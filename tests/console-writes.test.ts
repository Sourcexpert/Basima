import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  changeRole, forcePasswordReset, issuePasswordResetLink, revokeSessions, setLocked, setMfaRequirement,
  setSuspended,
} from '../lib/services/users';
import { archivePlan, changeSubscription, refundPayment } from '../lib/services/billing';
import { store } from '../lib/data/store';
import { verifyAdminChain } from '../lib/audit/admin-chain';
import { capabilitiesFor, type Role, type Viewer } from '../lib/auth/rbac';

/**
 * The console's *write* path, driven for real.
 *
 * Why this file exists: the console's type-checks and its read-only pages were
 * green, and the signing walkthrough exercised the party side, but nothing had
 * ever executed an operator action end to end. The first time one was, it failed
 * — the credential schemas demanded uuids while the seeded dataset uses ids like
 * `user_020`, so every password/subscription button in the demo console refused
 * with "Invalid uuid". A green build and a green unit-test suite can both be
 * true while a whole surface is dead, and the only way to know is to call it.
 *
 * So: real services, real store, seeded operators, no mocks. Each test states the
 * refusals and the permission boundary as well as the happy path, and the last
 * one verifies the admin ledger those actions wrote.
 */

const OPERATOR = {
  owner: { id: 'user_001', email: 'amina.wanjiru@agree-e.com' },
  admin: { id: 'user_002', email: 'brian.otieno@agree-e.com' },
  support: { id: 'user_003', email: 'cynthia.mwikali@agree-e.com' },
  security: { id: 'user_004', email: 'daniel.kariuki@agree-e.com' },
  billing: { id: 'user_005', email: 'esther.nekesa@agree-e.com' },
} as const satisfies Record<string, { id: string; email: string }>;

/** A signed-in operator with fresh step-up, which the sensitive actions require. */
function viewer(role: Role): Viewer {
  const who = OPERATOR[role as keyof typeof OPERATOR] ?? OPERATOR.admin;
  return {
    userId: who.id,
    email: who.email,
    displayName: `${role} operator`,
    role,
    capabilities: capabilitiesFor(role),
    stepUpVerifiedAt: new Date().toISOString(),
    mfaEnabled: true,
  };
}

const ctx = (role: Role) => ({
  viewer: viewer(role),
  ipHash: 'ip-hash-fixture',
  userAgent: 'node-test',
});

const REASON = 'Customer called the support line and identity was confirmed by call-back.';
const TARGET = 'user_018'; // active customer account, no console role

describe('console write path — credentials', () => {
  test('a support operator can issue a link but never sees it in email mode', async () => {
    const emailed = await issuePasswordResetLink(ctx('support'), {
      userId: TARGET,
      delivery: 'email',
      reason: REASON,
      idempotencyKey: 'cw-reset-email-1',
    });

    assert.equal(emailed.ok, true, emailed.ok ? '' : emailed.error);
    assert.equal(emailed.ok && emailed.data.delivered, true);
    // The claim the whole product rests on: the person who hands out access
    // cannot use it. In email mode the link goes to the mailbox and nowhere else.
    assert.equal(emailed.ok ? emailed.data.link : 'x', undefined);

    const copy = await issuePasswordResetLink(ctx('support'), {
      userId: TARGET,
      delivery: 'copy',
      reason: REASON,
      idempotencyKey: 'cw-reset-copy-1',
    });
    assert.equal(copy.ok, true, copy.ok ? '' : copy.error);
    assert.ok(copy.ok && copy.data.link, 'support-call mode returns the link once, for reading out');
  });

  test('a reset link cannot be issued without a real justification', async () => {
    const thin = await issuePasswordResetLink(ctx('support'), {
      userId: TARGET, delivery: 'email', reason: 'called', idempotencyKey: 'cw-reset-thin-1',
    });
    assert.equal(thin.ok, false);
    assert.match(thin.ok ? '' : thin.error!, /at least 12 characters/);
  });

  test('force reset sets the flag, revokes sessions and is recorded with the reason', async () => {
    const before = (await store().listSessions(TARGET)).length;

    const result = await forcePasswordReset(ctx('support'), {
      userId: TARGET,
      requireMfa: true,
      revokeSessions: true,
      reason: 'Device reported lost; the account must not be usable with the old password.',
      idempotencyKey: 'cw-force-reset-1',
    });

    assert.equal(result.ok, true, result.ok ? '' : result.error);
    const profile = await store().getUser(TARGET);
    assert.equal(profile?.forcePasswordReset, true);
    assert.equal(profile?.mfaRequired, true);
    assert.equal(result.ok ? result.data.revokedSessions : -1, before, 'every session it found was revoked');
    assert.equal((await store().listSessions(TARGET)).length, 0);
  });

  test('revoking sessions twice is idempotent, not an error', async () => {
    const again = await revokeSessions(ctx('security'), {
      userId: TARGET, scope: 'global', reason: 'Second sweep after the device report was confirmed.',
      idempotencyKey: 'cw-revoke-1',
    });
    assert.equal(again.ok, true, again.ok ? '' : again.error);
    assert.equal(again.ok ? again.data.revoked : -1, 0);
  });

  test('locking needs the suspend capability; unlocking is deliberately easier', async () => {
    // Locking is the riskier direction, so it is gated. Undoing a lock is a
    // support-safety action: a role that can read users may undo one, because
    // stranding a customer behind a mistaken lock is its own harm.
    const refused = await setLocked(ctx('support'), {
      userId: TARGET, action: 'lock', reason: 'Repeated failed sign-ins followed by a suspicious reset request.',
      idempotencyKey: 'cw-lock-refused',
    });
    assert.equal(refused.ok, false);
    assert.match(refused.ok ? '' : refused.error!, /users\.suspend/);

    const locked = await setLocked(ctx('admin'), {
      userId: TARGET, action: 'lock', reason: 'Repeated failed sign-ins followed by a suspicious reset request.',
      idempotencyKey: 'cw-lock-1',
    });
    assert.equal(locked.ok, true, locked.ok ? '' : locked.error);
    assert.equal((await store().getUser(TARGET))?.status, 'locked');

    const unlocked = await setLocked(ctx('support'), {
      userId: TARGET, action: 'unlock', reason: 'Account holder re-verified by call-back and given a new link.',
      idempotencyKey: 'cw-unlock-1',
    });
    assert.equal(unlocked.ok, true, unlocked.ok ? '' : unlocked.error);
    assert.equal((await store().getUser(TARGET))?.status, 'active');

    const unexplained = await setLocked(ctx('admin'), {
      userId: TARGET, action: 'lock', reason: 'asdf', idempotencyKey: 'cw-lock-2',
    });
    assert.equal(unexplained.ok, false);
  });

  test('a suspension is separate from a lock, and reinstatement is explicit', async () => {
    const suspended = await setSuspended(ctx('admin'), {
      userId: TARGET, suspend: true, reason: 'Billing dispute escalated to the operations lead for review.',
      idempotencyKey: 'cw-suspend-1',
    });
    assert.equal(suspended.ok, true, suspended.ok ? '' : suspended.error);
    assert.equal((await store().getUser(TARGET))?.status, 'suspended');

    const reinstated = await setSuspended(ctx('admin'), {
      userId: TARGET, suspend: false, reason: 'Dispute resolved; subscription is current again this morning.',
      idempotencyKey: 'cw-suspend-2',
    });
    assert.equal(reinstated.ok, true, reinstated.ok ? '' : reinstated.error);
    assert.equal((await store().getUser(TARGET))?.status, 'active');
  });

  test('MFA is required by a role that holds mfa.manage, and support cannot', async () => {
    const refused = await setMfaRequirement(ctx('support'), {
      userId: TARGET, required: true, reason: 'Account holds executed agreements; second factor now required.',
      idempotencyKey: 'cw-mfa-refused',
    });
    assert.equal(refused.ok, false);
    assert.match(refused.ok ? '' : refused.error!, /mfa\.manage/);

    const mfa = await setMfaRequirement(ctx('security'), {
      userId: TARGET, required: true, reason: 'Account holds executed agreements; second factor now required.',
      idempotencyKey: 'cw-mfa-1',
    });
    assert.equal(mfa.ok, true, mfa.ok ? '' : mfa.error);
    assert.equal((await store().getUser(TARGET))?.mfaRequired, true);
  });

  test('only an owner or admin may change what an account is allowed to do', async () => {
    const before = await store().getUser(TARGET);
    assert.ok(before);

    const refused = await changeRole(ctx('support'), {
      userId: TARGET, role: 'support', reason: 'Promoting a helpful customer to help answer their own tickets.',
      idempotencyKey: 'cw-role-1',
    });
    assert.equal(refused.ok, false);
    assert.match(refused.ok ? '' : refused.error!, /users\.role_change/);

    const allowed = await changeRole(ctx('owner'), {
      userId: TARGET, role: 'support', reason: 'Joining the support rota after reference checks were completed.',
      idempotencyKey: 'cw-role-2',
    });
    assert.equal(allowed.ok, true, allowed.ok ? '' : allowed.error);
    assert.equal((await store().getUser(TARGET))?.role, 'support');

    // Leave the dataset as it was found.
    await store().patchUser(TARGET, { role: before!.role });
    assert.equal((await store().getUser(TARGET))?.role, before!.role);
  });
});

describe('console write path — billing', () => {
  test('a billing operator moves a subscription and the change is recorded', async () => {
    const result = await changeSubscription(ctx('billing'), {
      subscriptionId: 'sub_002',
      action: 'change_plan',
      planId: 'plan_practice_m',
      effective: 'period_end',
      reason: 'Customer outgrew the personal plan and agreed the practice rate on the call.',
      idempotencyKey: 'cw-sub-1',
    });
    assert.equal(result.ok, true, result.ok ? '' : result.error);
    assert.equal(result.ok ? result.data.planCode : 'x', 'practice_monthly');
  });

  test('support cannot touch subscriptions at all', async () => {
    const refused = await changeSubscription(ctx('support'), {
      subscriptionId: 'sub_002',
      action: 'cancel',
      effective: 'immediately',
      reason: 'Customer sounded annoyed and asked us to just cancel the thing.',
      idempotencyKey: 'cw-sub-2',
    });
    assert.equal(refused.ok, false);
    assert.match(refused.ok ? '' : refused.error!, /billing\.subscriptions\.manage/);
  });

  test('archiving a plan hides it from new sales without deleting its history', async () => {
    const before = (await store().listPlans(true)).length;
    const archived = await archivePlan(ctx('billing'), {
      planId: 'plan_legacy_starter',
      reason: 'Legacy pricing withdrawn from sale; existing subscribers keep their rate.',
    });
    assert.equal(archived.ok, true, archived.ok ? '' : archived.error);
    assert.equal((await store().listPlans(true)).length, before, 'archiving is not deletion');
    assert.equal((await store().listPlans(false)).some((p) => p.id === 'plan_legacy_starter'), false);
  });

  test('a refund needs a second person, and refuses when the approver is the requester', async () => {
    const someoneElse = await refundPayment(ctx('billing'), {
      paymentId: 'pay_001',
      amountMinor: 100_000,
      reason: 'Double charge on the September invoice, confirmed against the provider statement.',
      supervisorEmail: 'amina.wanjiru@agree-e.com',
      idempotencyKey: 'cw-refund-1',
    });
    assert.equal(someoneElse.ok, true, someoneElse.ok ? '' : someoneElse.error);
    assert.equal(someoneElse.ok ? someoneElse.data.refunded : -1, 100_000);

    const selfApproved = await refundPayment(ctx('owner'), {
      paymentId: 'pay_002',
      amountMinor: 100_000,
      reason: 'Approving my own refund because the customer is waiting and I am on duty.',
      supervisorEmail: 'amina.wanjiru@agree-e.com',
      idempotencyKey: 'cw-refund-2',
    });
    assert.equal(selfApproved.ok, false);
    assert.match(selfApproved.ok ? '' : selfApproved.error!, /second person|supervisor|different/i);
  });

  test('customer service cannot move money', async () => {
    const refused = await refundPayment(ctx('support'), {
      paymentId: 'pay_004',
      amountMinor: 50_000,
      reason: 'Customer asked for a goodwill refund for the outage last week.',
      supervisorEmail: 'amina.wanjiru@agree-e.com',
      idempotencyKey: 'cw-refund-3',
    });
    assert.equal(refused.ok, false);
    assert.match(refused.ok ? '' : refused.error!, /billing\.refund/);
  });
});

describe('console write path — the ledger it leaves behind', () => {
  test('every operator action is chained, justified and attributable', async () => {
    const actions = await store().listAdminActions({ limit: 500 });
    const verification = verifyAdminChain(actions);
    assert.equal(verification.valid, true, verification.detail);

    // Every row in the ledger — seeded and written by this run — carries a real
    // reason and a named operator. An unexplained privileged action is not an
    // acceptable record, and the schema says so (reason is NOT NULL, length ≥ 12).
    for (const action of actions.slice(0, 40)) {
      assert.ok(action.reason.trim().length >= 12, `${action.action} was recorded without a real reason`);
      assert.ok(action.adminEmail.includes('@'), `${action.action} was recorded without an operator`);
      assert.equal(action.eventHash.length, 64);
    }

    const recorded = new Set(actions.map((a) => a.action));
    for (const expected of [
      'password.reset_link_issued',
      'password.force_reset_required',
      'sessions.revoked',
      'mfa.requirement_changed',
      'user.role_changed',
      'plan.archived',
      'payment.refund_issued',
    ]) {
      assert.ok(recorded.has(expected), `${expected} should be visible in the admin ledger`);
    }
  });

  test('the evidence chain is untouched by any of it', async () => {
    // A credential or billing action must never appear inside an agreement's
    // timeline: those chains prove what happened to a contract, and nothing else.
    const events = await store().listAuditEvents({ limit: 500 });
    const leaked = events.filter((e) =>
      ['password', 'session', 'role', 'refund', 'subscription', 'mfa'].some((needle) =>
        e.eventType.toLowerCase().includes(needle),
      ),
    );
    assert.deepEqual(leaked.map((e) => e.eventType), []);
  });
});
