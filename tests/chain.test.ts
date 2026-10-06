import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { canonicalize, sha256 } from '../lib/crypto/hash';
import {
  appendToChain, canonicalEventPayload, computeEventHash, verifyChain,
  type AuditEventRecord,
} from '../lib/audit/chain';
import { computeAdminActionHash, verifyAdminChain } from '../lib/audit/admin-chain';

/**
 * Evidence-ledger tests. Build Guide §20 requires, before production:
 *   • hash verification: "deliberately modify a copied package and confirm
 *     verification fails at the correct event";
 *   • replay/idempotency: duplicate sign requests do not create conflicting states;
 *   • race conditions: concurrent signers produce one consistent transition.
 * The chain-level half of those requirements is asserted here.
 */

function buildChain(): AuditEventRecord[] {
  const steps: Array<[string, string | null, Record<string, unknown>]> = [
    ['agreement.created', 'user_owner', { title: 'Loan agreement', type: 'loan' }],
    ['agreement.version_created', 'user_owner', { version: 1, sha256: sha256('v1'), bytes: 84_112 }],
    ['party.identity_verified', 'user_party', { assurance_level: 'email_otp_plus_id_document' }],
    ['party.signed', 'user_party', { version: 2, signature_method: 'otp_confirmed_intent' }],
    ['party.signed', 'user_owner', { version: 2, signature_method: 'otp_confirmed_intent' }],
    ['stamp.issued', null, { version: 2 }],
  ];
  let last: AuditEventRecord | null = null;
  return steps.map(([eventType, actorId, metadata], i) => {
    const event = appendToChain(last, {
      id: `evt_${i}`,
      agreementId: 'agr_1',
      actorId,
      eventType,
      objectId: 'agr_1',
      occurredAt: new Date(Date.UTC(2026, 0, 1, 9, 0, i)).toISOString(),
      ipHash: sha256(`ip-${i}`).slice(0, 32),
      userAgent: 'test-agent',
      metadata,
    });
    last = event;
    return event;
  });
}

describe('canonical serialization', () => {
  test('key order does not change the digest', () => {
    const a = { b: 2, a: 1, nested: { z: true, y: null } };
    const b = { nested: { y: null, z: true }, a: 1, b: 2 };
    assert.equal(canonicalize(a), canonicalize(b));
    assert.equal(sha256(canonicalize(a)), sha256(canonicalize(b)));
  });

  test('undefined is dropped and dates are normalised, so formatting cannot break hashes', () => {
    const withUndefined = { a: 1, b: undefined as unknown };
    assert.equal(canonicalize(withUndefined), '{"a":1}');
    assert.equal(
      canonicalize({ at: new Date('2026-01-01T00:00:00.000Z') }),
      '{"at":"2026-01-01T00:00:00.000Z"}',
    );
  });

  test('nested arrays keep order (order is meaningful) but object keys are sorted', () => {
    assert.equal(canonicalize([{ b: 1, a: 2 }]), '[{"a":2,"b":1}]');
    assert.notEqual(canonicalize({ x: [1, 2] }), canonicalize({ x: [2, 1] }));
  });
});

describe('evidence chain', () => {
  test('a freshly built chain verifies and reports every link', () => {
    const chain = buildChain();
    const result = verifyChain(chain);
    assert.equal(result.valid, true);
    assert.equal(result.checkedEvents, chain.length);
    assert.equal(result.root, chain[0].eventHash);
    assert.equal(result.head, chain[chain.length - 1].eventHash);
    assert.equal(result.firstFailure, null);
  });

  test('the first event commits to GENESIS, later events commit to their predecessor', () => {
    const chain = buildChain();
    assert.equal(chain[0].previousHash, null);
    for (let i = 1; i < chain.length; i += 1) {
      assert.equal(chain[i].previousHash, chain[i - 1].eventHash);
    }
    // The first link commits to GENESIS rather than to a sibling event.
    assert.equal(chain[0].eventHash, computeEventHash(null, canonicalEventPayload(chain[0])));
  });

  test('tampering with metadata fails at the correct event, not silently', () => {
    const chain = buildChain();
    const tampered = chain.map((e, i) =>
      i === 2 ? { ...e, metadata: { assurance_level: 'email_otp_only' } } : e,
    );
    const result = verifyChain(tampered);
    assert.equal(result.valid, false);
    assert.equal(result.firstFailure?.index, 2);
    assert.equal(result.firstFailure?.reason, 'digest_mismatch');
    assert.match(result.firstFailure!.detail, /canonical payload hashes to/);
  });

  test('tampering with an actor or a timestamp is also detected', () => {
    const chain = buildChain();
    const actorSwap = chain.map((e, i) => (i === 3 ? { ...e, actorId: 'user_attacker' } : e));
    assert.equal(verifyChain(actorSwap).firstFailure?.reason, 'digest_mismatch');

    const timeShift = chain.map((e, i) => (i === 1 ? { ...e, occurredAt: new Date('2020-01-01').toISOString() } : e));
    const result = verifyChain(timeShift);
    assert.equal(result.valid, false);
    // Reordered timestamps are caught as an ordering error before digest checks.
    assert.equal(result.firstFailure?.reason, 'ordering_error');
  });

  test('removing an event breaks the link at the next one', () => {
    const chain = buildChain();
    const withHole = [...chain.slice(0, 3), ...chain.slice(4)];
    const result = verifyChain(withHole);
    assert.equal(result.valid, false);
    assert.equal(result.firstFailure?.index, 3);
    assert.equal(result.firstFailure?.reason, 'broken_link');
  });

  test('re-hashing a forged event does not repair the chain (it breaks the next link)', () => {
    const chain = buildChain();
    const forged = { ...chain[2], metadata: { assurance_level: 'email_otp_only' } };
    forged.eventHash = computeEventHash(forged.previousHash, canonicalEventPayload(forged));
    const attempt = [...chain.slice(0, 2), forged, ...chain.slice(3)];
    const result = verifyChain(attempt);
    assert.equal(result.valid, false);
    assert.equal(result.firstFailure?.index, 3);
    assert.equal(result.firstFailure?.reason, 'broken_link');
  });

  test('replaying the same sign event twice is detectable by the chain, not by hope', () => {
    // Idempotency is enforced in the signer; this asserts the ledger property
    // that a duplicated event is visible rather than silently absorbed.
    const chain = buildChain();
    const duplicated = [chain[0], chain[1], chain[2], { ...chain[3], id: 'evt_3_replay' }, ...chain.slice(3)];
    const result = verifyChain(duplicated);
    assert.equal(result.valid, false);
    assert.ok(['broken_link', 'digest_mismatch', 'ordering_error'].includes(result.firstFailure!.reason));
  });

  test('an empty chain is reported as unverifiable, never as valid', () => {
    const result = verifyChain([]);
    assert.equal(result.valid, false);
    assert.equal(result.firstFailure?.reason, 'empty_chain');
  });
});

describe('admin action ledger', () => {
  const base = {
    adminId: 'user_002', adminEmail: 'brian.otieno@agree-e.com', adminRole: 'admin',
    action: 'password.reset_link_issued', targetType: 'user', targetId: 'user_019',
    targetLabel: 'Tabitha Mueni', reason: 'Customer lost their device; identity confirmed by callback.',
    status: 'succeeded' as const, stepUp: false, ipHash: null, userAgent: 'console',
    occurredAt: new Date('2026-10-05T09:00:00.000Z').toISOString(), metadata: {},
  };

  test('actions chain and verify', () => {
    const first = { ...base, id: 'adm_1' };
    const h1 = computeAdminActionHash(null, first);
    const second = { ...base, id: 'adm_2', action: 'sessions.revoked', previousHash: h1, eventHash: '' };
    const h2 = computeAdminActionHash(h1, second);
    const rows = [
      { ...second, eventHash: h2, previousHash: h1 },
      { ...first, eventHash: h1, previousHash: null },
    ];
    const result = verifyAdminChain(rows);
    assert.equal(result.valid, true);
  });

  test('editing the justification of a recorded action is detected', () => {
    const first = { ...base, id: 'adm_1' };
    const h1 = computeAdminActionHash(null, first);
    const edited = { ...first, reason: 'Testing.', eventHash: h1, previousHash: null };
    const result = verifyAdminChain([edited]);
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'digest_mismatch');
  });
});

describe('hashing helpers', () => {
  test('sha256 matches published test vectors', () => {
    assert.equal(sha256('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    assert.equal(sha256(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });
});
