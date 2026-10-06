import 'server-only';
import { newId } from '@/lib/data/types';
import type { PasswordRecoveryRequest, Profile } from '@/lib/data/types';
import { randomToken, sha256 } from '@/lib/crypto/hash';
import { env, supabaseConfigured } from '@/lib/env';
import { store } from '@/lib/data/store';
import { revokeSessionsFor } from '@/lib/auth/session-revoke';
import { requireAdminClient } from '@/lib/supabase/admin';
import { formatZodError, passwordRecoverySchema, type ActionResult } from '@/lib/validation/user-schemas';

/**
 * Password recovery, end to end.
 *
 * The console could always *send* a recovery link; this module is what makes the
 * link actually land somewhere and do something, without ever handing a
 * credential to the person who issued it. The rules:
 *
 *   1. The operator who issues the link never sees a password. They cause a
 *      token to exist; the account holder is the only one who can spend it.
 *   2. Only a digest of the token is stored (`tokenHash`), so a database dump,
 *      a console screen, or a curious engineer yields nothing reusable. The raw
 *      token exists in the link and in the holder's browser, then nowhere.
 *   3. A token is single-use and expires in {@link RECOVERY_TOKEN_TTL_MINUTES}
 *      minutes. Completing a reset also consumes every other outstanding link
 *      for that account, so an older email that is still sitting in an inbox
 *      cannot be used to regain access after the fact.
 *   4. A successful reset revokes every session. A password change that leaves
 *      an attacker's live session working has protected nothing.
 *   5. Every attempt is recorded — completion as a security event, and the
 *      issuance (in the console path) in the admin ledger. Failed attempts keep
 *      the token alive so a mistyped confirmation is not a lockout, but the
 *      response says plainly what happened.
 *
 * Brute force is not a realistic attack on a 32-byte token, which is why there
 * is no attempt counter here; the guard that matters is that the token is never
 * disclosed and never reusable.
 */

export const RECOVERY_TOKEN_TTL_MINUTES = 60;

/**
 * Domain-separated digest. The `agree-e:recovery:` prefix means a token digest
 * computed here can never collide with the same value hashed for another
 * purpose elsewhere in the product.
 */
export function hashRecoveryToken(rawToken: string): string {
  return sha256(`agree-e:recovery:${rawToken.trim()}`);
}

export interface IssuedRecovery {
  requestId: string;
  /** Returned to the issuer once. Never persisted, never logged. */
  link: string;
  expiresAt: string;
}

/**
 * Create a single-use recovery request and return the one-and-only copy of the
 * link. `issuedBy` is the operator when the console causes it, or null for a
 * future self-service flow where nobody privileged is involved.
 */
export async function issueRecoveryToken(input: {
  userId: string;
  issuedBy: string | null;
  delivery: 'email' | 'copy';
  reason: string | null;
  ipHash: string | null;
  userAgent: string | null;
}): Promise<IssuedRecovery> {
  const raw = randomToken(32);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + RECOVERY_TOKEN_TTL_MINUTES * 60_000).toISOString();

  const request: PasswordRecoveryRequest = {
    id: newId('prr'),
    userId: input.userId,
    tokenHash: hashRecoveryToken(raw),
    issuedBy: input.issuedBy,
    delivery: input.delivery,
    reason: input.reason,
    issuedAt: now.toISOString(),
    expiresAt,
    consumedAt: null,
    ipHash: input.ipHash,
    userAgent: input.userAgent,
  };
  await store().appendPasswordRecovery(request);

  // The link goes to /auth/confirm, which is the single place that decides what
  // a link of this shape means; from there the holder is sent to the form.
  return {
    requestId: request.id,
    link: `${env.appUrl}/auth/confirm?token=${encodeURIComponent(raw)}&type=recovery`,
    expiresAt,
  };
}

export type RecoveryTokenState =
  | { state: 'valid'; request: PasswordRecoveryRequest; account: Profile }
  | { state: 'unknown' | 'expired' | 'used' | 'blocked'; request: PasswordRecoveryRequest | null; account: Profile | null };

/** Read a token's state without spending it. Safe to call on every page render. */
export async function inspectRecoveryToken(rawToken: string | undefined | null): Promise<RecoveryTokenState> {
  if (!rawToken || rawToken.trim().length < 16) return { state: 'unknown', request: null, account: null };

  const request = await store().findPasswordRecoveryByTokenHash(hashRecoveryToken(rawToken));
  if (!request) return { state: 'unknown', request: null, account: null };

  const account = await store().getUser(request.userId);
  if (request.consumedAt) return { state: 'used', request, account };
  if (new Date(request.expiresAt).getTime() <= Date.now()) return { state: 'expired', request, account };
  // A deleted account, and an account an operator has deliberately locked or
  // suspended, are both "not right now" — but they are not the same thing, and
  // the page must not imply the link was wrong when the account is the reason.
  if (!account) return { state: 'unknown', request, account: null };
  if (account.status !== 'active') return { state: 'blocked', request, account };

  return { state: 'valid', request, account };
}

export interface RecoveryOutcome {
  userId: string;
  email: string;
  sessionsRevoked: number;
  /** True when a real auth provider stored the new password. */
  passwordStored: boolean;
}

/**
 * Spend a recovery token and set a new password.
 *
 * Order matters: validate → change the credential → revoke sessions → clear the
 * forced-reset flag → consume the token (and its siblings) → record. If the
 * provider call fails, nothing else happens and the link still works, so the
 * account holder can retry instead of being stranded.
 */
export async function completeRecovery(
  rawToken: string,
  input: unknown,
  meta: { ipHash: string | null; userAgent: string | null },
): Promise<ActionResult<RecoveryOutcome>> {
  const parsed = passwordRecoverySchema.safeParse({
    token: rawToken,
    ...(typeof input === 'object' && input !== null ? input : {}),
  });
  if (!parsed.success) return { ok: false, error: formatZodError(parsed.error), code: 'validation' };

  const inspected = await inspectRecoveryToken(parsed.data.token);
  if (inspected.state !== 'valid') {
    return { ok: false, error: recoveryStateMessage(inspected.state), code: 'forbidden' };
  }
  const { account, request } = inspected;

  let passwordStored = false;
  if (supabaseConfigured) {
    try {
      const admin = requireAdminClient('auth.admin.updateUserById');
      const { error } = await admin.auth.admin.updateUserById(account.id, {
        password: parsed.data.newPassword,
        app_metadata: {
          force_password_reset: false,
          password_changed_at: new Date().toISOString(),
          password_changed_via: 'recovery_link',
        },
      });
      if (error) return { ok: false, error: `Could not set the new password: ${error.message}`, code: 'provider_error' };
      passwordStored = true;
    } catch (e) {
      return {
        ok: false,
        code: 'provider_error',
        error: e instanceof Error ? e.message : 'Could not set the new password.',
      };
    }
  }

  const now = new Date().toISOString();
  const sessionsRevoked = await revokeSessionsFor(account.id, 'global');
  await store().patchUser(account.id, { passwordChangedAt: now, forcePasswordReset: false });
  const consumed = await store().consumePasswordRecoveries(account.id, now);

  await store().appendSecurityEvent({
    id: newId('sec'),
    userId: account.id,
    type: 'password_recovery_completed',
    severity: 'notice',
    detail:
      `Recovery link completed for ${account.email}; ${sessionsRevoked} session(s) revoked, ` +
      `${consumed} outstanding link(s) closed. Issued by ${request.issuedBy ? `operator ${request.issuedBy}` : 'self-service'}.` +
      (passwordStored ? '' : ' Demo build: no password is stored, the credential change is recorded as simulated.'),
    ipHash: meta.ipHash,
    occurredAt: now,
  });

  return {
    ok: true,
    data: { userId: account.id, email: account.email, sessionsRevoked, passwordStored },
    message: passwordStored
      ? 'Your new password is set, and every other session on your account has been signed out.'
      : 'Recorded. This demo build stores no passwords, so nothing was changed on a real credential — the recovery itself (token spent, sessions revoked, audit event written) is real.',
  };
}

/**
 * What the account holder is told. Each state is named for what actually
 * happened, because "invalid link" is the least useful thing you can say to
 * someone who is already locked out.
 */
export function recoveryStateMessage(state: RecoveryTokenState['state']): string {
  switch (state) {
    case 'expired':
      return `This recovery link has expired (links last ${RECOVERY_TOKEN_TTL_MINUTES} minutes). Ask for a new one — the old link is now useless to everyone, including whoever asked for it.`;
    case 'used':
      return 'This recovery link has already been used. If that was not you, every session has been signed out and you should contact support immediately.';
    case 'blocked':
      return 'This account is locked or suspended, so a recovery link cannot be used on it. Contact support.';
    default:
      return 'This recovery link is not valid. It may have been mistyped, truncated by an email client, or superseded by a newer link.';
  }
}
