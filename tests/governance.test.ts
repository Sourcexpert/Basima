import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { authorize, can, capabilitiesFor, ROLES, STEP_UP_REQUIRED, REASON_REQUIRED, type Viewer } from '../lib/auth/rbac';
import { normaliseKenyanMsisdn, darajaTimestamp, describeResultCode, parseCallback, buildStkPassword } from '../lib/payments/mpesa-format';
import { verifyOffline, type OfflineCheck } from '../lib/evidence/offline-verify';
import { canonicalize, sha256 } from '../lib/crypto/hash';

function viewer(role: Viewer['role'], extra: Partial<Viewer> = {}): Viewer {
  return {
    userId: 'user_test', email: `${role}@agree-e.com`, displayName: 'Test Operator',
    role, capabilities: capabilitiesFor(role), stepUpVerifiedAt: new Date().toISOString(),
    mfaEnabled: true, ...extra,
  };
}

/**
 * Privilege-boundary tests. The product's central claim to a law firm is that
 * support staff cannot read a contract and that no role can touch a credential
 * silently — so those refusals are asserted, not assumed.
 */
describe('role capabilities', () => {
  test('support cannot move money or touch credentials beyond recovery', () => {
    assert.equal(can('support', 'password.reset_link'), true);
    assert.equal(can('support', 'password.force_reset'), true);
    assert.equal(can('support', 'billing.refund'), false);
    assert.equal(can('support', 'billing.plans.manage'), false);
    assert.equal(can('support', 'password.temp_issue'), false);
    assert.equal(can('support', 'users.role_change'), false);
  });

  test('billing cannot touch credentials and cannot read agreement content', () => {
    assert.equal(can('billing', 'billing.refund'), true);
    assert.equal(can('billing', 'password.reset_link'), false);
    assert.equal(can('billing', 'password.force_reset'), false);
    assert.equal(can('billing', 'sessions.revoke'), false);
    assert.equal(can('billing', 'agreements.content.read.privileged'), false);
  });

  test('admin status does NOT grant contract-reading rights (guide §5)', () => {
    assert.equal(can('admin', 'users.read'), true);
    assert.equal(can('admin', 'billing.subscriptions.manage'), true);
    assert.equal(can('admin', 'agreements.metadata.read'), true);
    assert.equal(can('admin', 'agreements.content.read.privileged'), false);
    assert.equal(can('owner', 'agreements.content.read.privileged'), false);
  });

  test('only security can read agreement content, and only through the logged workflow', () => {
    assert.equal(can('security', 'agreements.content.read.privileged'), true);
    assert.equal(can('security', 'billing.refund'), false);
    assert.equal(can('counsel', 'agreements.content.read.privileged'), false);
    assert.equal(can('counsel', 'users.read'), false);
  });

  test('no role anywhere can read or set a plaintext password', () => {
    for (const role of ROLES) {
      const caps = capabilitiesFor(role);
      assert.equal(caps.some((c) => /plaintext_password|set_password/.test(c)), false, `${role} must not hold a password-read capability`);
    }
  });
});

describe('authorize()', () => {
  test('denies by default when there is no viewer', () => {
    const result = authorize(null, 'users.read');
    assert.equal(result.allowed, false);
    if (!result.allowed) assert.equal(result.status, 401);
  });

  test('refuses a capability the role does not hold', () => {
    const result = authorize(viewer('support'), 'billing.refund', { reason: 'Customer asked for money back immediately.' });
    assert.equal(result.allowed, false);
    if (!result.allowed) {
      assert.equal(result.status, 403);
      assert.match(result.error, /billing\.refund/);
    }
  });

  test('demands step-up for sensitive actions even when the role is correct', () => {
    const stale = viewer('security', { stepUpVerifiedAt: new Date(Date.now() - 60 * 60_000).toISOString() });
    const result = authorize(stale, 'agreements.content.read.privileged', { reason: 'Incident triage, ticket SEC-2291.' });
    assert.equal(result.allowed, false);
    if (!result.allowed) assert.equal(result.requiresStepUp, true);

    const fresh = authorize(viewer('security'), 'agreements.content.read.privileged', { reason: 'Incident triage, ticket SEC-2291.' });
    assert.equal(fresh.allowed, true);
  });

  test('demands a substantive written reason where policy requires one', () => {
    const short = authorize(viewer('admin'), 'password.force_reset', { reason: 'oops' });
    assert.equal(short.allowed, false);
    if (!short.allowed) assert.equal(short.requiresReason, true);

    const ok = authorize(viewer('admin'), 'password.force_reset', {
      reason: 'Credential-stuffing detected; owner confirmed by phone before we require a reset.',
    });
    assert.equal(ok.allowed, true);
  });

  test('step-up and reason guards cover the operations that deserve them', () => {
    for (const cap of ['password.temp_issue', 'users.role_change', 'sessions.revoke', 'billing.refund', 'agreements.content.read.privileged'] as const) {
      assert.equal(STEP_UP_REQUIRED.has(cap), true, `${cap} should require step-up`);
    }
    for (const cap of ['password.temp_issue', 'billing.refund', 'agreements.content.read.privileged'] as const) {
      assert.equal(REASON_REQUIRED.has(cap), true, `${cap} should require a written reason`);
    }
  });
});

/** Daraja formatting: a wrong MSISDN is a failed collection, so it is pinned. */
describe('M-PESA helpers', () => {
  test('normalises every Kenyan format customers actually type', () => {
    assert.equal(normaliseKenyanMsisdn('0712 345 678'), '254712345678');
    assert.equal(normaliseKenyanMsisdn('+254 712 345 678'), '254712345678');
    assert.equal(normaliseKenyanMsisdn('254712345678'), '254712345678');
    assert.equal(normaliseKenyanMsisdn('00254712345678'), '254712345678');
    assert.equal(normaliseKenyanMsisdn('0110000000'), '254110000000');
    assert.equal(normaliseKenyanMsisdn('712345678'), '254712345678');
  });

  test('rejects numbers Daraja cannot accept', () => {
    assert.equal(normaliseKenyanMsisdn('0812345678'), null);
    assert.equal(normaliseKenyanMsisdn('+2338012345678'), null);
    assert.equal(normaliseKenyanMsisdn('not a number'), null);
    assert.equal(normaliseKenyanMsisdn('12345'), null);
  });

  test('timestamp is EAT (UTC+3) in YYYYMMDDHHmmss', () => {
    const t = darajaTimestamp(new Date('2026-10-05T06:20:00.000Z'));
    assert.equal(t, '20261005092000');
    assert.match(t, /^\d{14}$/);
  });

  test('STK password is base64(shortcode + passkey + timestamp)', () => {
    const pass = buildStkPassword('174379', 'bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919', '20160216165627');
    assert.equal(
      pass,
      Buffer.from('174379bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c91920160216165627').toString('base64'),
    );
  });

  test('result codes are translated into plain language for operators', () => {
    assert.match(describeResultCode(1032, 'Request cancelled by user'), /cancelled/i);
    assert.match(describeResultCode(1, 'The balance is insufficient'), /[Ii]nsufficient/);
    assert.match(describeResultCode(2001, 'Wrong PIN'), /PIN/);
    assert.match(describeResultCode(0, 'The service request is processed successfully'), /completed/i);
  });

  test('a successful callback yields a receipt and an explanation', () => {
    const parsed = parseCallback({
      Body: {
        stkCallback: {
          MerchantRequestID: '29115-34620561-1',
          CheckoutRequestID: 'ws_CO_191220191020363925',
          ResultCode: 0,
          ResultDesc: 'The service request is processed successfully.',
          CallbackMetadata: {
            Item: [
              { Name: 'Amount', Value: 1 },
              { Name: 'MpesaReceiptNumber', Value: 'NLJ7RT61SV' },
              { Name: 'TransactionDate', Value: 20191101102115 },
              { Name: 'PhoneNumber', Value: 254708374149 },
            ],
          },
        },
      },
    });
    assert.equal(parsed?.succeeded, true);
    assert.equal(parsed?.receipt, 'NLJ7RT61SV');
    assert.equal(parsed?.amount, 1);
    assert.match(parsed!.explanation, /completed/i);
  });

  test('a cancelled callback is surfaced as a failure with the customer-facing reason', () => {
    const parsed = parseCallback({
      Body: {
        stkCallback: {
          MerchantRequestID: 'm-1', CheckoutRequestID: 'ws_CO_1', ResultCode: 1032,
          ResultDesc: 'Request cancelled by user',
        },
      },
    });
    assert.equal(parsed?.succeeded, false);
    assert.equal(parsed?.receipt, null);
    assert.match(parsed!.explanation, /cancelled/i);
  });
});

/**
 * Offline evidence verification — the property a court-facing export depends on:
 * a package must be verifiable without our servers, without our database and
 * without trusting our UI.
 */
describe('offline evidence package verification', () => {
  function makePackage(): { manifest: Record<string, unknown>; events: unknown[]; documentBytes: string } {
    const docBytes = 'the agreement text, byte for byte';
    const documentHash = sha256(docBytes);
    let last: string | null = null;
    const events = [
      ['agreement.created', { title: 'Loan' }],
      ['agreement.version_created', { version: 1 }],
      ['party.signed', { signature_method: 'otp_confirmed_intent' }],
      ['stamp.issued', { version: 1 }],
    ].map(([eventType, metadata], i) => {
      const id = `evt_${i}`;
      const occurredAt = new Date(Date.UTC(2026, 0, 2, 9, 0, i)).toISOString();
      const payload = canonicalize({
        id, agreement_id: 'agr_1', actor_id: 'user_1', event_type: eventType, object_id: 'agr_1',
        occurred_at: occurredAt, ip_hash: null, metadata,
      });
      const eventHash = sha256(`${last ?? 'GENESIS'}\n${payload}`);
      const row = {
        id, agreement_id: 'agr_1', actor_id: 'user_1', event_type: eventType, object_id: 'agr_1',
        occurred_at: occurredAt, ip_hash: null, metadata, previous_hash: last, event_hash: eventHash,
      };
      last = eventHash;
      return row;
    });
    return {
      manifest: {
        format: 'agree-e-evidence-package', version: '1.0', agreement_id: 'agr_1',
        document_hash_algorithm: 'SHA-256', document_hash: documentHash, event_chain_root: last,
      },
      events,
      documentBytes: docBytes,
    };
  }

  test('a well-formed package verifies and states exactly what was checked', () => {
    const pkg = makePackage();
    const result = verifyOffline(pkg.manifest, pkg.events, pkg.documentBytes);
    assert.equal(result.documentIntegrity, true);
    assert.equal(result.chainIntegrity, true);
    assert.equal(result.requiredEventsPresent, true);
    assert.equal(result.ok, true);
    assert.deepEqual(
      result.findings.map((f: OfflineCheck) => f.name),
      ['document_digest', 'chain_links', 'chain_root', 'required_events'],
    );
    assert.ok(result.statements.some((s: string) => /Document integrity verified/.test(s)));
  });

  test('a single altered byte in the document fails the digest check', () => {
    const pkg = makePackage();
    const result = verifyOffline(pkg.manifest, pkg.events, `${pkg.documentBytes} (edited)`);
    assert.equal(result.documentIntegrity, false);
    assert.equal(result.ok, false);
    assert.match(result.statements.join(' '), /NOT verified/);
  });

  test('an edited event fails the chain check at the right link', () => {
    const pkg = makePackage();
    const events = pkg.events.map((e, i) =>
      i === 1 ? { ...(e as Record<string, unknown>), metadata: { version: 2 } } : e,
    );
    const result = verifyOffline(pkg.manifest, events, pkg.documentBytes);
    assert.equal(result.chainIntegrity, false);
    assert.equal(result.failingIndex, 1);
  });

  test('a missing signing event is reported even when the chain is intact', () => {
    const pkg = makePackage();
    const withoutSignature = pkg.events.filter((e) => (e as { event_type: string }).event_type !== 'party.signed');
    const result = verifyOffline(pkg.manifest, withoutSignature, pkg.documentBytes);
    assert.equal(result.chainIntegrity, false); // removing an event breaks links
    assert.equal(result.requiredEventsPresent, false);
  });

  test('the verifier never converts technical findings into a legal conclusion', () => {
    const pkg = makePackage();
    const result = verifyOffline(pkg.manifest, pkg.events, pkg.documentBytes);
    const text = result.statements.join(' ');
    assert.equal(/legally valid|court admissible|court-admissible/i.test(text), false);
  });
});
