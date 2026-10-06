import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { completeRecovery, hashRecoveryToken, inspectRecoveryToken, issueRecoveryToken } from '../lib/services/password-recovery';
import { issuePasswordResetLink } from '../lib/services/users';
import { store } from '../lib/data/store';
import { hashIp } from '../lib/crypto/hash';
import { capabilitiesFor, type Viewer } from '../lib/auth/rbac';
import { DEMO_SESSIONS, DEMO_USERS } from '../lib/data/demo-db';

/**
 * Password recovery, tested against the real service layer and the real store.
 *
 * The console has always been able to *ask* for a reset; these tests hold the
 * line on what happens next. Four claims must not be taken on trust:
 *
 *   1. the raw token is never stored — only its digest — so an operator cannot
 *      read a recovery link back out of the database and use it;
 *   2. a token is single-use and expiring, and completing a reset closes every
 *      other outstanding link for that account;
 *   3. a successful reset revokes sessions and clears a forced reset, so the old
 *      credential and any live session both stop working;
 *   4. the recovery is recorded as a security event, with the operator who
 *      issued it named — an untraceable credential change is not acceptable.
 *
 * This file deliberately imports modules that are `server-only`. It runs under
 * `tsx --conditions=react-server --test` (see package.json), which resolves that
 * marker the way the Next.js server does.
 */

/**
 * Chosen from the seed rather than typed by hand: an account that is active *and*
 * has live sessions, so "the reset revoked something" is a claim the test can
 * actually falsify. (Declared, not inferred — if the fixture stops containing
 * such an account, this file fails loudly instead of passing vacuously.)
 */
const ACCOUNT = (() => {
  const withSessions = new Set(DEMO_SESSIONS.map((s) => s.userId));
  const candidate = DEMO_USERS.find((u) => withSessions.has(u.id) && u.status === 'active');
  if (!candidate) throw new Error('fixture: no active seeded account has sessions');
  return candidate.id;
})();

function operator(role: Viewer['role'] = 'support'): Viewer {
  return {
    userId: 'user_003',
    email: 'operator@agre-e.com',
    displayName: 'Test Operator',
    role,
    capabilities: capabilitiesFor(role),
    stepUpVerifiedAt: new Date().toISOString(),
    mfaEnabled: true,
  };
}

const ctx = { viewer: operator(), ipHash: hashIp('203.0.113.9', 'test-pepper'), userAgent: 'node-test' };

describe('password recovery', () => {
  test('the console issues a real, single-use link and stores only its digest', async () => {
    const result = await issuePasswordResetLink(ctx, {
      userId: ACCOUNT,
      delivery: 'copy',
      reason: 'Credential recovery requested on a support call; identity confirmed by call-back.',
      idempotencyKey: 'idem-recovery-1',
    });

    assert.equal(result.ok, true, result.ok ? '' : result.error);
    const link = result.ok ? result.data.link : undefined;
    assert.ok(link, 'copy delivery must return the link to the operator once');
    assert.match(link!, /\/auth\/confirm\?token=/);

    const raw = decodeURIComponent(new URL(link!).searchParams.get('token')!);
    const stored = await store().listPasswordRecoveries(ACCOUNT);
    assert.equal(stored.length, 1);

    const record = stored[0];
    assert.equal(record.tokenHash, hashRecoveryToken(raw), 'the digest is what is stored');
    assert.notEqual(record.tokenHash, raw, 'the raw token is never stored');
    assert.ok(
      !stored.some((r) => r.tokenHash.includes(raw.slice(0, 12))),
      'no column may carry the raw token, even partially',
    );
    assert.equal(record.issuedBy, ctx.viewer.userId, 'the issuing operator is named on the record');
    assert.equal(record.consumedAt, null);
    assert.ok(new Date(record.expiresAt).getTime() > Date.now(), 'links start out usable');

    // And a fresh read of the record cannot reconstruct the link.
    assert.equal(JSON.stringify(record).includes(raw), false);
  });

  test('an inspection tells the truth about a token without spending it', async () => {
    const issued = await issueRecoveryToken({
      userId: ACCOUNT, issuedBy: 'user_003', delivery: 'copy',
      reason: null, ipHash: null, userAgent: null,
    });

    const first = await inspectRecoveryToken(decodeURIComponent(new URL(issued.link).searchParams.get('token')!));
    assert.equal(first.state, 'valid');
    const again = await inspectRecoveryToken(decodeURIComponent(new URL(issued.link).searchParams.get('token')!));
    assert.equal(again.state, 'valid', 'inspecting must not consume: mail scanners open links too');

    assert.equal((await inspectRecoveryToken('not-a-real-token-but-long-enough')).state, 'unknown');
    assert.equal((await inspectRecoveryToken('')).state, 'unknown');
    assert.equal((await inspectRecoveryToken(undefined)).state, 'unknown');
  });

  test('a weak or mismatched password is refused and the link survives the attempt', async () => {
    const issued = await issueRecoveryToken({
      userId: ACCOUNT, issuedBy: 'user_003', delivery: 'copy',
      reason: null, ipHash: null, userAgent: null,
    });
    const raw = decodeURIComponent(new URL(issued.link).searchParams.get('token')!);
    const meta = { ipHash: null, userAgent: null };

    const weak = await completeRecovery(raw, { newPassword: 'short1A', confirmPassword: 'short1A' }, meta);
    assert.equal(weak.ok, false);
    assert.match(weak.ok ? '' : weak.error!, /at least 12 characters/);

    const noCase = await completeRecovery(raw, { newPassword: 'alllowercase123', confirmPassword: 'alllowercase123' }, meta);
    assert.equal(noCase.ok, false);
    assert.match(noCase.ok ? '' : noCase.error!, /upper case/i);

    const mismatch = await completeRecovery(raw, { newPassword: 'CorrectHorse123', confirmPassword: 'CorrectHorse124' }, meta);
    assert.equal(mismatch.ok, false);
    assert.match(mismatch.ok ? '' : mismatch.error!, /do not match/);

    // A failed attempt is not a lockout: the holder can fix the typo and retry.
    const state = await inspectRecoveryToken(raw);
    assert.equal(state.state, 'valid');
  });

  test('completing a reset spends the link, closes its siblings and revokes sessions', async () => {
    const first = await issueRecoveryToken({
      userId: ACCOUNT, issuedBy: 'user_003', delivery: 'email',
      reason: null, ipHash: null, userAgent: null,
    });
    const second = await issueRecoveryToken({
      userId: ACCOUNT, issuedBy: 'user_003', delivery: 'copy',
      reason: null, ipHash: null, userAgent: null,
    });
    const rawFirst = decodeURIComponent(new URL(first.link).searchParams.get('token')!);
    const rawSecond = decodeURIComponent(new URL(second.link).searchParams.get('token')!);

    // The account is forced into a reset first, so we can prove the flag clears.
    await store().patchUser(ACCOUNT, { forcePasswordReset: true });
    assert.equal((await store().getUser(ACCOUNT))?.forcePasswordReset, true);

    // A live session must exist for the revocation count to mean anything.
    const before = await store().listSessions(ACCOUNT);
    assert.ok(before.length >= 1, 'fixture: this account has seeded sessions');

    const done = await completeRecovery(rawSecond, {
      newPassword: 'Harbour-Lantern-42', confirmPassword: 'Harbour-Lantern-42',
    }, { ipHash: hashIp('203.0.113.9', 'test-pepper'), userAgent: 'node-test' });

    assert.equal(done.ok, true, done.ok ? '' : done.error);

    const profile = await store().getUser(ACCOUNT);
    assert.equal(profile?.forcePasswordReset, false, 'the forced reset is cleared by completing one');
    assert.ok(profile?.passwordChangedAt, 'the change is stamped on the profile');

    // Every session gone, and both links — used or not — are dead.
    assert.equal((await store().listSessions(ACCOUNT)).length, 0, 'a reset must sign out every existing session');
    assert.equal((await inspectRecoveryToken(rawSecond)).state, 'used');
    assert.equal((await inspectRecoveryToken(rawFirst)).state, 'used', 'the other outstanding link dies with it');

    // The event is on the security log, naming the operator and what was revoked.
    const events = await store().listSecurityEvents({ limit: 50 });
    const event = events.find((e) => e.type === 'password_recovery_completed' && e.userId === ACCOUNT);
    assert.ok(event, 'completion must be recorded as a security event');
    assert.equal(event!.severity, 'notice');
    assert.match(event!.detail, /Issued by operator user_003/);
  });

  test('a replay of a spent token is refused with the reason, not a generic failure', async () => {
    const issued = await issueRecoveryToken({
      userId: ACCOUNT, issuedBy: null, delivery: 'copy',
      reason: null, ipHash: null, userAgent: null,
    });
    const raw = decodeURIComponent(new URL(issued.link).searchParams.get('token')!);
    const meta = { ipHash: null, userAgent: null };

    const first = await completeRecovery(raw, { newPassword: 'Quiet-Harbour-42x', confirmPassword: 'Quiet-Harbour-42x' }, meta);
    assert.equal(first.ok, true, first.ok ? '' : first.error);

    const replay = await completeRecovery(raw, { newPassword: 'Attacker-Chosen-99', confirmPassword: 'Attacker-Chosen-99' }, meta);
    assert.equal(replay.ok, false);
    assert.match(replay.ok ? '' : replay.error!, /already been used/);
  });

  test('an expired token is refused, in terms the holder can act on', async () => {
    // Rather than wait the hour out, insert an aged request directly — the same
    // row shape the issuer writes, with `issued_at`/`expires_at` in the past.
    const raw = 'expired-test-token-abcdefghijklmnopqrstuvwxyz';
    const aged = new Date(Date.now() - 61 * 60_000).toISOString();
    await store().appendPasswordRecovery({
      id: 'prr_expired_fixture', userId: ACCOUNT, tokenHash: hashRecoveryToken(raw),
      issuedBy: 'user_003', delivery: 'email', reason: null, issuedAt: aged, expiresAt: aged,
      consumedAt: null, ipHash: null, userAgent: null,
    });

    const inspected = await inspectRecoveryToken(raw);
    assert.equal(inspected.state, 'expired');

    const attempt = await completeRecovery(raw, {
      newPassword: 'Quiet-Harbour-42x', confirmPassword: 'Quiet-Harbour-42x',
    }, { ipHash: null, userAgent: null });
    assert.equal(attempt.ok, false);
    assert.match(attempt.ok ? '' : attempt.error!, /expired/);
    assert.match(attempt.ok ? '' : attempt.error!, /60 minutes/, 'the holder is told the lifetime, so they know a fresh link will work');
  });

  test('the account status is enforced: a locked account cannot be recovered into', async () => {
    // user_020 is seeded locked — a real operator action, visible in the console.
    // A recovery link must not be a way around a lock an operator applied.
    const locked = DEMO_USERS.find((u) => u.id === 'user_020' && u.status === 'locked');
    assert.ok(locked, 'fixture: user_020 is seeded locked');

    const issued = await issueRecoveryToken({
      userId: locked!.id, issuedBy: 'user_003', delivery: 'copy',
      reason: null, ipHash: null, userAgent: null,
    });
    const raw = decodeURIComponent(new URL(issued.link).searchParams.get('token')!);

    const inspected = await inspectRecoveryToken(raw);
    assert.equal(inspected.state, 'blocked');
    assert.equal(inspected.account?.status, 'locked');

    const attempt = await completeRecovery(raw, {
      newPassword: 'Quiet-Harbour-42x', confirmPassword: 'Quiet-Harbour-42x',
    }, { ipHash: null, userAgent: null });
    assert.equal(attempt.ok, false);
    assert.match(attempt.ok ? '' : attempt.error!, /locked or suspended/);

    // And the link itself is not burned by the refusal, so support can unlock and
    // the same email still works — refusing is not the same as destroying.
    assert.equal((await inspectRecoveryToken(raw)).state, 'blocked');
  });
});
