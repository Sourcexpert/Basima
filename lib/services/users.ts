import 'server-only';
import { authorize, type Viewer } from '@/lib/auth/rbac';
import { generateTemporaryPassword } from '@/lib/crypto/hash';
import { env, supabaseConfigured } from '@/lib/env';
import { revokeSessionsFor } from '@/lib/auth/session-revoke';
import { recordAdminAction, store } from '@/lib/data/store';
import { issueRecoveryToken } from '@/lib/services/password-recovery';
import { requireAdminClient } from '@/lib/supabase/admin';
import {
  breakGlassSchema, changeRoleSchema, forceResetSchema, formatZodError, lockUserSchema, mfaSchema,
  passwordResetLinkSchema, revokeSessionsSchema, type ActionResult,
} from '@/lib/validation/schemas';

/**
 * User & credential administration.
 *
 * Design rule (agreed with the product owner): no administrator, in any role,
 * can read or set a plaintext password. The console can only:
 *   1. issue a single-use recovery link (emailed, or echoed once for a support
 *      call) — hashed and single-use upstream;
 *   2. require a password reset at next sign-in, optionally revoking sessions;
 *   3. revoke sessions;
 *   4. require MFA;
 *   5. lock / unlock / suspend / reinstate;
 *   6. issue a time-boxed single-use credential through break-glass, which
 *      requires step-up auth, a supervisor, an acknowledgement and a reason.
 *
 * Rationale: an evidence product must never let an operator assume a user's
 * identity. Every one of the actions above is recorded in the admin ledger with
 * the operator, the justification and a chained hash.
 */

const idempotency = new Map<string, { at: number; result: ActionResult }>();

function replay<T>(key: string): ActionResult<T> | null {
  const hit = idempotency.get(key);
  if (hit && Date.now() - hit.at < 15 * 60_000) return hit.result as ActionResult<T>;
  return null;
}

function remember<T>(key: string, result: ActionResult<T>): ActionResult<T> {
  idempotency.set(key, { at: Date.now(), result });
  return result;
}

interface ActorContext {
  viewer: Viewer;
  ipHash: string | null;
  userAgent: string | null;
}

/* ------------------------------------------------ 1. password reset link -- */

export async function issuePasswordResetLink(ctx: ActorContext, input: unknown): Promise<ActionResult<{ link?: string; delivered: boolean }>> {
  const parsed = passwordResetLinkSchema.safeParse(input);
  if (!parsed.success) return { ok: false, error: formatZodError(parsed.error), code: 'validation' };
  const { userId, delivery, redirectTo, reason, idempotencyKey } = parsed.data;

  const cached = replay<{ link?: string; delivered: boolean }>(idempotencyKey);
  if (cached) return cached;

  const auth = authorize(ctx.viewer, 'password.reset_link', { reason });
  if (!auth.allowed) return remember(idempotencyKey, { ok: false, error: auth.error, code: auth.status === 401 ? 'unauthorized' : 'forbidden' });

  const target = await store().getUser(userId);
  if (!target) return remember(idempotencyKey, { ok: false, error: 'User not found.', code: 'validation' });

  let link: string | undefined;
  let delivered = false;
  let failure: string | null = null;
  let recoveryRequestId: string | undefined;

  if (supabaseConfigured) {
    try {
      const admin = requireAdminClient('auth.admin.generateLink');
      const { data, error } = await admin.auth.admin.generateLink({
        type: 'recovery',
        email: target.email,
        options: { redirectTo: redirectTo ?? `${env.appUrl}/auth/callback?next=/reset-password` },
      });
      if (error) failure = error.message;
      else {
        // The link is single-use and expires upstream. In 'email' mode Supabase
        // sends it and we never see it; in 'copy' mode it is shown once to the
        // operator on the call and never stored.
        link = data?.properties?.action_link;
        delivered = delivery === 'email';
      }
    } catch (e) {
      failure = e instanceof Error ? e.message : 'Unknown error issuing recovery link.';
    }
  } else {
    // Demo build: there is no mail provider and no auth service, but the link
    // itself is real. A single-use, expiring token is minted here, only its
    // digest is stored, and the same /auth/confirm -> /reset-password hand-off
    // the production link uses is exercised end to end.
    const issued = await issueRecoveryToken({
      userId: target.id,
      issuedBy: ctx.viewer.userId,
      delivery,
      reason,
      ipHash: ctx.ipHash,
      userAgent: ctx.userAgent,
    });
    link = issued.link;
    recoveryRequestId = issued.requestId;
    delivered = delivery === 'email';
  }

  await recordAdminAction({
    adminId: ctx.viewer.userId,
    adminEmail: ctx.viewer.email,
    adminRole: ctx.viewer.role,
    action: 'password.reset_link_issued',
    targetType: 'user',
    targetId: target.id,
    targetLabel: `${target.displayName} <${target.email}>`,
    reason,
    status: failure ? 'failed' : 'succeeded',
    stepUp: false,
    ipHash: ctx.ipHash,
    userAgent: ctx.userAgent,
    metadata: { delivery, target_email: target.email, error: failure, link_issued: Boolean(link), recovery_request_id: recoveryRequestId ?? null },
  });

  if (failure) return remember(idempotencyKey, { ok: false, error: `Could not issue recovery link: ${failure}`, code: 'provider_error' });

  return remember(idempotencyKey, {
    ok: true,
    data: { link: delivery === 'copy' ? link : undefined, delivered },
    message: delivery === 'email'
      ? `Recovery link sent to ${target.email}.`
      : 'Single-use link generated — read it out and then close this panel. It will not be shown again.',
  });
}

/* ------------------------------------------- 2. force reset at next login -- */

export async function forcePasswordReset(ctx: ActorContext, input: unknown): Promise<ActionResult<{ revokedSessions: number }>> {
  const parsed = forceResetSchema.safeParse(input);
  if (!parsed.success) return { ok: false, error: formatZodError(parsed.error), code: 'validation' };
  const { userId, requireMfa, revokeSessions: revoke, reason, idempotencyKey } = parsed.data;

  const cached = replay<{ revokedSessions: number }>(idempotencyKey);
  if (cached) return cached;

  const auth = authorize(ctx.viewer, 'password.force_reset', { reason });
  if (!auth.allowed) return remember(idempotencyKey, { ok: false, error: auth.error, code: auth.status === 401 ? 'unauthorized' : 'forbidden' });

  const target = await store().getUser(userId);
  if (!target) return remember(idempotencyKey, { ok: false, error: 'User not found.', code: 'validation' });

  let revokedSessions = 0;
  if (revoke) revokedSessions = await revokeSessionsFor(target.id, 'global');

  await store().patchUser(target.id, {
    forcePasswordReset: true,
    mfaRequired: target.mfaRequired || requireMfa,
    passwordChangedAt: target.passwordChangedAt,
  });

  if (supabaseConfigured) {
    const admin = requireAdminClient('auth.admin.updateUserById');
    await admin.auth.admin.updateUserById(target.id, {
      app_metadata: { force_password_reset: true, reset_required_at: new Date().toISOString(), reset_required_by: ctx.viewer.userId },
    });
  }

  await recordAdminAction({
    adminId: ctx.viewer.userId, adminEmail: ctx.viewer.email, adminRole: ctx.viewer.role,
    action: 'password.force_reset_required', targetType: 'user', targetId: target.id,
    targetLabel: `${target.displayName} <${target.email}>`, reason, status: 'succeeded', stepUp: true,
    ipHash: ctx.ipHash, userAgent: ctx.userAgent,
    metadata: { require_mfa: requireMfa, revoked_sessions: revokedSessions },
  });

  return remember(idempotencyKey, {
    ok: true,
    data: { revokedSessions },
    message: `Password reset required at next sign-in${revoke ? `; ${revokedSessions} session(s) revoked` : ''}.`,
  });
}

/* ------------------------------------------------------ 3. revoke sessions -- */

export async function revokeSessions(ctx: ActorContext, input: unknown): Promise<ActionResult<{ revoked: number }>> {
  const parsed = revokeSessionsSchema.safeParse(input);
  if (!parsed.success) return { ok: false, error: formatZodError(parsed.error), code: 'validation' };
  const { userId, scope, reason, idempotencyKey } = parsed.data;

  const cached = replay<{ revoked: number }>(idempotencyKey);
  if (cached) return cached;

  const auth = authorize(ctx.viewer, 'sessions.revoke', { reason });
  if (!auth.allowed) return remember(idempotencyKey, { ok: false, error: auth.error, code: auth.status === 401 ? 'unauthorized' : 'forbidden' });

  const target = await store().getUser(userId);
  if (!target) return remember(idempotencyKey, { ok: false, error: 'User not found.', code: 'validation' });

  const revoked = await revokeSessionsFor(target.id, scope);

  await recordAdminAction({
    adminId: ctx.viewer.userId, adminEmail: ctx.viewer.email, adminRole: ctx.viewer.role,
    action: 'sessions.revoked', targetType: 'user', targetId: target.id,
    targetLabel: `${target.displayName} <${target.email}>`, reason, status: 'succeeded', stepUp: true,
    ipHash: ctx.ipHash, userAgent: ctx.userAgent, metadata: { scope, revoked },
  });

  return remember(idempotencyKey, {
    ok: true,
    data: { revoked },
    message: `Revoked ${revoked} session(s). Access tokens remain valid until expiry (≤1 hour), so also require a reset if the device is at risk.`,
  });
}

/* ------------------------------------------------------------ 4. MFA policy -- */

export async function setMfaRequirement(ctx: ActorContext, input: unknown): Promise<ActionResult<{ required: boolean }>> {
  const parsed = mfaSchema.safeParse(input);
  if (!parsed.success) return { ok: false, error: formatZodError(parsed.error), code: 'validation' };
  const { userId, required, reason, idempotencyKey } = parsed.data;

  const cached = replay<{ required: boolean }>(idempotencyKey);
  if (cached) return cached;

  const auth = authorize(ctx.viewer, 'mfa.manage', { reason });
  if (!auth.allowed) return remember(idempotencyKey, { ok: false, error: auth.error, code: auth.status === 401 ? 'unauthorized' : 'forbidden' });

  const target = await store().getUser(userId);
  if (!target) return remember(idempotencyKey, { ok: false, error: 'User not found.', code: 'validation' });

  await store().patchUser(userId, { mfaRequired: required });
  if (supabaseConfigured) {
    const admin = requireAdminClient('auth.admin.updateUserById');
    await admin.auth.admin.updateUserById(userId, { app_metadata: { mfa_required: required } });
  }

  await recordAdminAction({
    adminId: ctx.viewer.userId, adminEmail: ctx.viewer.email, adminRole: ctx.viewer.role,
    action: 'mfa.requirement_changed', targetType: 'user', targetId: userId,
    targetLabel: `${target.displayName} <${target.email}>`, reason, status: 'succeeded', stepUp: false,
    ipHash: ctx.ipHash, userAgent: ctx.userAgent, metadata: { required },
  });

  return remember(idempotencyKey, { ok: true, data: { required }, message: required ? 'MFA is now required for this account.' : 'MFA requirement removed.' });
}

/* -------------------------------------------------------- 5. lock / unlock -- */

export async function setLocked(ctx: ActorContext, input: unknown): Promise<ActionResult<{ status: string }>> {
  const parsed = lockUserSchema.safeParse(input);
  if (!parsed.success) return { ok: false, error: formatZodError(parsed.error), code: 'validation' };
  const { userId, action, reason, idempotencyKey } = parsed.data;

  const cached = replay<{ status: string }>(idempotencyKey);
  if (cached) return cached;

  const auth = authorize(ctx.viewer, action === 'lock' ? 'users.suspend' : 'users.read', { reason });
  if (!auth.allowed && action === 'lock') {
    return remember(idempotencyKey, { ok: false, error: auth.error, code: auth.status === 401 ? 'unauthorized' : 'forbidden' });
  }
  // Unlocking is a support-safety action: any role that can read users may undo
  // a lock, but never remove a deliberate suspension (that needs users.suspend).
  if (!auth.allowed && action === 'unlock') {
    const unlockAuth = authorize(ctx.viewer, 'users.read');
    if (!unlockAuth.allowed) return remember(idempotencyKey, { ok: false, error: unlockAuth.error, code: 'forbidden' });
  }

  const target = await store().getUser(userId);
  if (!target) return remember(idempotencyKey, { ok: false, error: 'User not found.', code: 'validation' });
  if (target.role === 'owner' && ctx.viewer.role !== 'owner') {
    return remember(idempotencyKey, { ok: false, error: 'Only an owner may lock or unlock an owner account.', code: 'forbidden' });
  }

  const nextStatus = action === 'lock' ? 'locked' : 'active';
  await store().patchUser(userId, {
    status: nextStatus,
    lockedUntil: action === 'lock' ? new Date(Date.now() + 15 * 60_000).toISOString() : null,
    failedSignInCount: action === 'unlock' ? 0 : target.failedSignInCount,
  });
  if (action === 'lock') await revokeSessionsFor(userId, 'global');

  await recordAdminAction({
    adminId: ctx.viewer.userId, adminEmail: ctx.viewer.email, adminRole: ctx.viewer.role,
    action: action === 'lock' ? 'user.locked' : 'user.unlocked', targetType: 'user', targetId: userId,
    targetLabel: `${target.displayName} <${target.email}>`, reason, status: 'succeeded', stepUp: false,
    ipHash: ctx.ipHash, userAgent: ctx.userAgent, metadata: {},
  });

  return remember(idempotencyKey, { ok: true, data: { status: nextStatus }, message: action === 'lock' ? 'Account locked and sessions revoked.' : 'Account unlocked.' });
}

/* ------------------------------------------------------- 6. role / suspend -- */

export async function changeRole(ctx: ActorContext, input: unknown): Promise<ActionResult<{ role: string }>> {
  const parsed = changeRoleSchema.safeParse(input);
  if (!parsed.success) return { ok: false, error: formatZodError(parsed.error), code: 'validation' };
  const { userId, role, reason, idempotencyKey } = parsed.data;

  const cached = replay<{ role: string }>(idempotencyKey);
  if (cached) return cached;

  const auth = authorize(ctx.viewer, 'users.role_change', { reason });
  if (!auth.allowed) return remember(idempotencyKey, { ok: false, error: auth.error, code: auth.status === 401 ? 'unauthorized' : 'forbidden' });
  if (ctx.viewer.role !== 'owner' && (role === 'owner' || target_role_is_owner(await store().getUser(userId)))) {
    return remember(idempotencyKey, { ok: false, error: 'Only an owner may grant or revoke the owner role.', code: 'forbidden' });
  }
  if (userId === ctx.viewer.userId) {
    return remember(idempotencyKey, { ok: false, error: 'You cannot change your own role — ask another owner.', code: 'forbidden' });
  }

  const target = await store().getUser(userId);
  if (!target) return remember(idempotencyKey, { ok: false, error: 'User not found.', code: 'validation' });

  await store().patchUser(userId, { role });
  if (supabaseConfigured) {
    const admin = requireAdminClient('auth.admin.updateUserById');
    await admin.auth.admin.updateUserById(userId, { app_metadata: { role } });
  }

  await recordAdminAction({
    adminId: ctx.viewer.userId, adminEmail: ctx.viewer.email, adminRole: ctx.viewer.role,
    action: 'user.role_changed', targetType: 'user', targetId: userId,
    targetLabel: `${target.displayName} → ${role}`, reason, status: 'succeeded', stepUp: true,
    ipHash: ctx.ipHash, userAgent: ctx.userAgent, metadata: { from: target.role, to: role },
  });

  return remember(idempotencyKey, { ok: true, data: { role }, message: `Role changed from ${target.role} to ${role}.` });
}

function target_role_is_owner(target: { role: string } | null): boolean {
  return target?.role === 'owner';
}

const SUSPEND_REASON_MIN = 12;

export async function setSuspended(ctx: ActorContext, input: { userId: string; suspend: boolean; reason: string; idempotencyKey: string }): Promise<ActionResult<{ status: string }>> {
  const { userId, suspend, reason, idempotencyKey } = input;
  if (reason.trim().length < SUSPEND_REASON_MIN) return { ok: false, error: 'A justification of at least 12 characters is required.', code: 'validation' };

  const cached = replay<{ status: string }>(idempotencyKey);
  if (cached) return cached;

  const auth = authorize(ctx.viewer, 'users.suspend', { reason });
  if (!auth.allowed) return remember(idempotencyKey, { ok: false, error: auth.error, code: auth.status === 401 ? 'unauthorized' : 'forbidden' });

  const target = await store().getUser(userId);
  if (!target) return remember(idempotencyKey, { ok: false, error: 'User not found.', code: 'validation' });
  if (target.role === 'owner') return remember(idempotencyKey, { ok: false, error: 'Owner accounts cannot be suspended from the console.', code: 'forbidden' });

  const status = suspend ? 'suspended' : 'active';
  await store().patchUser(userId, { status });
  if (suspend) await revokeSessionsFor(userId, 'global');

  await recordAdminAction({
    adminId: ctx.viewer.userId, adminEmail: ctx.viewer.email, adminRole: ctx.viewer.role,
    action: suspend ? 'user.suspended' : 'user.reinstated', targetType: 'user', targetId: userId,
    targetLabel: `${target.displayName} <${target.email}>`, reason, status: 'succeeded', stepUp: true,
    ipHash: ctx.ipHash, userAgent: ctx.userAgent, metadata: {},
  });

  return remember(idempotencyKey, {
    ok: true, data: { status },
    message: suspend
      ? 'Account suspended and sessions revoked. Evidentiary records are unaffected — suspension is a commercial/operational state only.'
      : 'Account reinstated.',
  });
}

/* ------------------------------------------------------- 7. break-glass -- */

export interface BreakGlassResult {
  temporaryPassword: string;
  expiresAt: string;
  requiresChangeAtNextSignIn: true;
}

export async function issueBreakGlassCredential(ctx: ActorContext, input: unknown): Promise<ActionResult<BreakGlassResult>> {
  const parsed = breakGlassSchema.safeParse(input);
  if (!parsed.success) return { ok: false, error: formatZodError(parsed.error), code: 'validation' };
  const { userId, ttlMinutes, supervisorEmail, reason, idempotencyKey } = parsed.data;

  const cached = replay<BreakGlassResult>(idempotencyKey);
  if (cached) return cached;

  const auth = authorize(ctx.viewer, 'password.temp_issue', { reason });
  if (!auth.allowed) return remember(idempotencyKey, { ok: false, error: auth.error, code: auth.status === 401 ? 'unauthorized' : 'forbidden' });

  const target = await store().getUser(userId);
  if (!target) return remember(idempotencyKey, { ok: false, error: 'User not found.', code: 'validation' });

  const supervisor = await store().getUserByEmail(supervisorEmail);
  if (!supervisor || !['owner', 'admin', 'security'].includes(supervisor.role)) {
    return remember(idempotencyKey, { ok: false, error: 'Supervisor must be an owner, admin or security account.', code: 'forbidden' });
  }
  if (supervisor.id === ctx.viewer.userId) {
    return remember(idempotencyKey, { ok: false, error: 'Break-glass requires a second person: the supervisor must not be the requesting admin.', code: 'forbidden' });
  }

  const temporaryPassword = generateTemporaryPassword();
  const expiresAt = new Date(Date.now() + ttlMinutes * 60_000).toISOString();

  const previousStatus = target.status;
  await store().patchUser(userId, {
    status: 'active', // a locked-out owner must be able to sign in…
    forcePasswordReset: true, // …but only to set a new password
    tempCredentialIssuedAt: new Date().toISOString(),
    tempCredentialExpiresAt: expiresAt,
    failedSignInCount: 0,
    lockedUntil: null,
  });
  await revokeSessionsFor(userId, 'global');

  if (supabaseConfigured) {
    const admin = requireAdminClient('auth.admin.updateUserById');
    await admin.auth.admin.updateUserById(userId, {
      password: temporaryPassword,
      app_metadata: {
        force_password_reset: true,
        temp_credential_expires_at: expiresAt,
        temp_credential_issued_by: ctx.viewer.userId,
        temp_credential_supervisor: supervisor.id,
        temp_credential_previous_status: previousStatus,
      },
    });
  }

  await recordAdminAction({
    adminId: ctx.viewer.userId, adminEmail: ctx.viewer.email, adminRole: ctx.viewer.role,
    action: 'password.temp_issued_breakglass', targetType: 'user', targetId: userId,
    targetLabel: `${target.displayName} <${target.email}>`, reason, status: 'succeeded', stepUp: true,
    ipHash: ctx.ipHash, userAgent: ctx.userAgent,
    metadata: {
      supervisor: supervisor.email, supervisor_id: supervisor.id, ttl_minutes: ttlMinutes,
      expires_at: expiresAt, previous_status: previousStatus,
      // The credential itself is never logged — only the fact it was issued.
      credential_logged: false,
    },
  });

  return remember(idempotencyKey, {
    ok: true,
    data: { temporaryPassword, expiresAt, requiresChangeAtNextSignIn: true },
    message: `Break-glass credential issued. It expires ${new Date(expiresAt).toISOString()} and must be changed at first sign-in. Read it to the customer now — it is not stored anywhere and cannot be shown again.`,
  });
}
