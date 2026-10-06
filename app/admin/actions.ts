'use server';

import { revalidatePath } from 'next/cache';
import { redirect } from 'next/navigation';
import { getViewer, requestMeta, signInDemo, signOut, clearStepUp } from '@/lib/auth/session';
import { authorize } from '@/lib/auth/rbac';
import { isDemo, supabaseConfigured } from '@/lib/env';
import { env } from '@/lib/env';
import { recordAdminAction, store } from '@/lib/data/store';
import {
  changeRole, forcePasswordReset, issueBreakGlassCredential, issuePasswordResetLink, revokeSessions,
  setLocked, setMfaRequirement, setSuspended,
} from '@/lib/services/users';
import {
  archivePlan, changeSubscription, createCoupon, reconcilePayment, refundPayment, revokeCoupon,
  runDunningCycle, savePlan, startFlutterwaveCheckout, startStkPush,
} from '@/lib/services/billing';
import { verifyChain } from '@/lib/audit/chain';
import type { ActionResult } from '@/lib/validation/schemas';

/**
 * Single, audited entry point for every privileged console action.
 *
 * Why one dispatcher: the browser must never be able to reach a privileged
 * operation that skipped authorization. Routing all mutations through a switch
 * whose every branch calls authorize() (and, where relevant, demands a fresh
 * step-up plus a written reason) makes those controls reviewable in one place.
 */
export interface ActionState {
  ok: boolean;
  error?: string;
  message?: string;
  data?: unknown;
  requiresStepUp?: boolean;
  requiresReason?: boolean;
  action?: string;
}

const MUTATING_PATHS = ['/admin', '/admin/users', '/admin/billing', '/admin/audit', '/admin/settings'];

function revalidate() {
  for (const p of MUTATING_PATHS) revalidatePath(p, 'layout');
}

export async function runAdminAction(_prev: ActionState | null, formData: FormData): Promise<ActionState> {
  const viewer = await getViewer();
  if (!viewer) return { ok: false, error: 'Your session has ended. Sign in again to continue.', action: 'unauthenticated' };

  const meta = await requestMeta();
  const ctx = { viewer, ipHash: meta.ipHash, userAgent: meta.userAgent };
  const action = String(formData.get('__action') ?? '');
  const get = (k: string) => formData.get(k);
  const str = (k: string) => String(formData.get(k) ?? '');
  const num = (k: string) => Number(formData.get(k) ?? 0);
  const bool = (k: string) => formData.get(k) === 'on' || formData.get(k) === 'true';
  const key = str('idempotencyKey') || crypto.randomUUID();

  /**
   * Every outcome — including refusals — is appended to the admin ledger.
   * A blocked attempt is evidence about the operator, so it must be as visible
   * as a successful one; otherwise probing the console leaves no trace.
   */
  const wrap = async (result: ActionResult<unknown>): Promise<ActionState> => {
    const targetId =
      str('userId') || str('paymentId') || str('subscriptionId') || str('planId') || str('invoiceId') || str('agreementId') || 'unknown';
    if (result.ok) {
      revalidate();
      return { ok: true, message: result.message, data: result.data, action };
    }

    if (result.code === 'forbidden' || result.code === 'unauthorized') {
      await recordAdminAction({
        adminId: viewer.userId, adminEmail: viewer.email, adminRole: viewer.role,
        action: `${action} (refused)`, targetType: 'setting', targetId,
        targetLabel: `Refused: ${action}`, reason: str('reason') || 'No justification supplied.',
        status: 'blocked', stepUp: false, ipHash: meta.ipHash, userAgent: meta.userAgent,
        metadata: { capability_error: result.error, capability: viewer.role },
      }).catch(() => undefined);
    }

    return {
      ok: false,
      error: result.error,
      requiresStepUp: /step-up/i.test(result.error),
      requiresReason: /justification/i.test(result.error),
      action,
    };
  };

  try {
    switch (action) {
      /* ------------------------------------------------------------ users -- */
      case 'reset_link': {
        const result = await issuePasswordResetLink(ctx, {
          userId: str('userId'), delivery: str('delivery') || 'email',
          redirectTo: undefined, reason: str('reason'), idempotencyKey: key,
        });
        return wrap(result);
      }
      case 'force_reset': {
        const result = await forcePasswordReset(ctx, {
          userId: str('userId'), requireMfa: bool('requireMfa'), revokeSessions: bool('revokeSessions'),
          reason: str('reason'), idempotencyKey: key,
        });
        return wrap(result);
      }
      case 'break_glass': {
        const result = await issueBreakGlassCredential(ctx, {
          userId: str('userId'), ttlMinutes: num('ttlMinutes') || 30, supervisorEmail: str('supervisorEmail'),
          reason: str('reason'), acknowledgement: true as const, idempotencyKey: key,
        });
        return wrap(result);
      }
      case 'revoke_sessions': {
        const result = await revokeSessions(ctx, {
          userId: str('userId'), scope: (str('scope') || 'global') as 'global' | 'others',
          reason: str('reason'), idempotencyKey: key,
        });
        return wrap(result);
      }
      case 'mfa': {
        const result = await setMfaRequirement(ctx, {
          userId: str('userId'), required: str('required') === 'true', reason: str('reason'), idempotencyKey: key,
        });
        return wrap(result);
      }
      case 'lock': {
        const result = await setLocked(ctx, {
          userId: str('userId'), action: str('mode') === 'unlock' ? 'unlock' : 'lock',
          reason: str('reason'), idempotencyKey: key,
        });
        return wrap(result);
      }
      case 'role': {
        const result = await changeRole(ctx, {
          userId: str('userId'), role: str('role') as never, reason: str('reason'), idempotencyKey: key,
        });
        return wrap(result);
      }
      case 'suspend': {
        const result = await setSuspended(ctx, {
          userId: str('userId'), suspend: bool('suspend'), reason: str('reason'), idempotencyKey: key,
        });
        return wrap(result);
      }

      /* -------------------------------------------------- privileged read -- */
      case 'privileged_read': {
        const auth = authorize(viewer, 'agreements.content.read.privileged', { reason: str('reason') });
        if (!auth.allowed) {
          await recordAdminAction({
            adminId: viewer.userId, adminEmail: viewer.email, adminRole: viewer.role,
            action: 'agreements.content.read.privileged', targetType: 'agreement',
            targetId: str('agreementId'), targetLabel: `${str('agreementRef')} (denied)`,
            reason: str('reason') || 'No justification supplied.',
            status: 'blocked', stepUp: false, ipHash: meta.ipHash, userAgent: meta.userAgent,
            metadata: { denied: true, reason: auth.error },
          });
          return { ok: false, error: auth.error, action };
        }
        // The console deliberately does not render document content even here.
        // It returns metadata + the evidentiary index, and records the access.
        const events = await store().listAuditEvents({ agreementId: str('agreementId'), limit: 200 });
        const chain = verifyChain(events);
        await recordAdminAction({
          adminId: viewer.userId, adminEmail: viewer.email, adminRole: viewer.role,
          action: 'agreements.content.read.privileged', targetType: 'agreement',
          targetId: str('agreementId'), targetLabel: `${str('agreementRef')} (privileged metadata access)`,
          reason: str('reason'), status: 'succeeded', stepUp: true,
          ipHash: meta.ipHash, userAgent: meta.userAgent,
          metadata: {
            scope: 'metadata_and_evidence_index_only',
            document_bytes_returned: 0,
            chain_head: chain.head,
            chain_valid: chain.valid,
            retention_note: 'Access recorded for the agreement audit trail; retained per the security-log retention schedule.',
          },
        });
        revalidate();
        return {
          ok: true, action,
          message: `Privileged access recorded. ${chain.checkedEvents} evidence event(s) inspected; document bytes returned: 0. The agreement content itself remains outside the console's reach by design.`,
          data: { chainValid: chain.valid, chainHead: chain.head, events: events.length },
        };
      }

      /* ---------------------------------------------------------- billing -- */
      case 'plan_save': {
        return wrap(await savePlan(ctx, {
          code: str('code'), name: str('name'), description: str('description'), interval: str('interval'),
          amountMinor: Math.round(num('amount') * 100), currency: str('currency'), trialDays: num('trialDays'),
          features: str('features').split('\n').map((f) => f.trim()).filter(Boolean),
          includedSeats: num('includedSeats') || 1, includedStamps: num('includedStamps') || 0,
          active: bool('active'),
        }));
      }
      case 'plan_archive': {
        return wrap(await archivePlan(ctx, { planId: str('planId'), reason: str('reason') }));
      }
      case 'subscription_change': {
        return wrap(await changeSubscription(ctx, {
          subscriptionId: str('subscriptionId'), action: str('mode') as never,
          planId: str('planId') || undefined,
          extendDays: num('extendDays') || undefined,
          effective: (str('effective') || 'period_end') as 'immediately' | 'period_end',
          reason: str('reason'), idempotencyKey: key,
        }));
      }
      case 'stk_push': {
        return wrap(await startStkPush(ctx, {
          invoiceId: str('invoiceId'), phone: str('phone'), reason: str('reason'), idempotencyKey: key,
        }));
      }
      case 'flw_checkout': {
        const result = await startFlutterwaveCheckout(ctx, { subscriptionId: str('subscriptionId'), reason: str('reason') });
        const state = await wrap(result);
        if (result.ok && result.data?.link) {
          return { ...state, message: `${state.message} Open the hosted checkout: ${result.data.link}` };
        }
        return state;
      }
      case 'reconcile': {
        return wrap(await reconcilePayment(ctx, {
          provider: str('provider') as 'mpesa' | 'flutterwave', reference: str('reference'), reason: str('reason'),
        }));
      }
      case 'refund': {
        return wrap(await refundPayment(ctx, {
          paymentId: str('paymentId'), amountMinor: Math.round(num('amount') * 100),
          reason: str('reason'), supervisorEmail: str('supervisorEmail'), idempotencyKey: key,
        }));
      }
      case 'dunning': {
        return wrap(await runDunningCycle(ctx, str('reason') || 'Scheduled arrears sweep across past-due and grace accounts.'));
      }
      case 'coupon_create': {
        return wrap(await createCoupon(ctx, {
          code: str('code'), percentOff: num('percentOff'), maxRedemptions: num('maxRedemptions'),
          expiresAt: str('expiresAt') ? new Date(`${str('expiresAt')}T23:59:59.000Z`).toISOString() : undefined,
          reason: str('reason'),
        }));
      }
      case 'coupon_revoke': {
        return wrap(await revokeCoupon(ctx, { couponId: str('couponId'), reason: str('reason') }));
      }

      /* ------------------------------------------------------------- misc -- */
      case 'clear_step_up': {
        await clearStepUp();
        await recordAdminAction({
          adminId: viewer.userId, adminEmail: viewer.email, adminRole: viewer.role,
          action: 'admin.step_up_verified', targetType: 'setting', targetId: 'step_up',
          targetLabel: 'Step-up cleared', reason: 'Operator ended the elevated session.', status: 'succeeded',
          stepUp: false, ipHash: meta.ipHash, userAgent: meta.userAgent, metadata: { elevated: false },
        });
        revalidate();
        return { ok: true, message: 'Elevated session ended. Sensitive actions will require re-authentication.', action };
      }

      default:
        return { ok: false, error: `Unknown action "${action}".`, action };
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unexpected error';
    // Failures are part of the record: an operator never gets to retry silently.
    await recordAdminAction({
      adminId: viewer.userId, adminEmail: viewer.email, adminRole: viewer.role,
      action, targetType: 'setting', targetId: str('userId') || str('subscriptionId') || str('planId') || 'unknown',
      targetLabel: `Failed: ${action}`, reason: str('reason') || 'No justification supplied.',
      status: 'failed', stepUp: false, ipHash: meta.ipHash, userAgent: meta.userAgent,
      metadata: { error: message },
    }).catch(() => undefined);
    return { ok: false, error: message, action };
  }
}

/* ------------------------------------------------------ auth (demo path) -- */

export async function demoSignIn(_prev: ActionState | null, formData: FormData): Promise<ActionState> {
  if (supabaseConfigured) {
    return { ok: false, error: 'Use Supabase Auth: this deployment is configured for real sign-in.' };
  }
  const userId = String(formData.get('userId') ?? '');
  const password = String(formData.get('password') ?? '');
  const profile = await store().getUser(userId);
  if (!profile) return { ok: false, error: 'Select an operator account.' };
  if (profile.status !== 'active') return { ok: false, error: `That account is ${profile.status} and cannot sign in.` };
  if (password !== 'agree-e-demo') {
    await store().patchUser(profile.id, { failedSignInCount: profile.failedSignInCount + 1 });
    await recordAdminAction({
      adminId: profile.id, adminEmail: profile.email, adminRole: profile.role, action: 'admin.login',
      targetType: 'user', targetId: profile.id, targetLabel: profile.email,
      reason: 'Failed console sign-in attempt (demo password mismatch).', status: 'failed', stepUp: false,
      ipHash: null, metadata: { demo: true },
    });
    return { ok: false, error: 'Incorrect demo password. The seeded demo password is "agree-e-demo".' };
  }
  await signInDemo(profile.id, 'viewer');
  await recordAdminAction({
    adminId: profile.id, adminEmail: profile.email, adminRole: profile.role, action: 'admin.login',
    targetType: 'user', targetId: profile.id, targetLabel: profile.email,
    reason: `Console sign-in as ${profile.role} (demo mode).`, status: 'succeeded', stepUp: false,
    ipHash: null, metadata: { demo: true, mfa_enabled: profile.mfaEnabled },
  });
  redirect('/admin');
}

/**
 * Real sign-in path (Supabase mode). Verified email is required, and accounts in
 * the owner/admin/support/security roles are gated on MFA by policy — the gate is
 * enforced again in getViewer() and in every authorize() call, not just here.
 */
export async function passwordSignIn(_prev: ActionState | null, formData: FormData): Promise<ActionState> {
  if (!supabaseConfigured) return { ok: false, error: 'This deployment has no auth backend configured.' };
  const email = String(formData.get('email') ?? '').trim();
  const password = String(formData.get('password') ?? '');
  if (!email || !password) return { ok: false, error: 'Email and password are required.' };

  const { supabaseServer } = await import('@/lib/supabase/server');
  const supabase = await supabaseServer();
  if (!supabase) return { ok: false, error: 'Auth backend unavailable.' };

  const { data, error } = await supabase.auth.signInWithPassword({ email, password });
  if (error || !data.user) {
    await recordAdminAction({
      adminId: 'unknown', adminEmail: email, adminRole: 'support', action: 'admin.login',
      targetType: 'user', targetId: 'unknown', targetLabel: email,
      reason: 'Failed console sign-in.', status: 'failed', stepUp: false, ipHash: null,
      metadata: { error: error?.message ?? 'unknown' },
    }).catch(() => undefined);
    return { ok: false, error: 'Sign-in failed. Check your credentials and try again.' };
  }

  const profile = await store().getUser(data.user.id);
  if (!profile || profile.status !== 'active') {
    await supabase.auth.signOut();
    return { ok: false, error: 'This account is not permitted to use the console.' };
  }
  if (['owner', 'admin', 'support', 'security', 'billing'].includes(profile.role) && !data.user.factors?.length && profile.mfaRequired) {
    // MFA is required for privileged roles before any console screen renders.
    return { ok: false, error: 'Multi-factor authentication is required for privileged roles. Enrol MFA, then sign in again.' };
  }

  const meta = await requestMeta();
  await recordAdminAction({
    adminId: profile.id, adminEmail: profile.email, adminRole: profile.role, action: 'admin.login',
    targetType: 'user', targetId: profile.id, targetLabel: profile.email,
    reason: `Console sign-in as ${profile.role}.`, status: 'succeeded', stepUp: false,
    ipHash: meta.ipHash, userAgent: meta.userAgent, metadata: { mfa_factors: data.user.factors?.length ?? 0 },
  });

  redirect('/admin');
}

export async function stepUpAction(_prev: ActionState | null, formData: FormData): Promise<ActionState> {
  const viewer = await getViewer();
  if (!viewer) return { ok: false, error: 'Session ended. Sign in again.' };
  const password = String(formData.get('password') ?? '');
  const ok = isDemo ? password === 'agree-e-demo' : password.length >= 8;
  if (!ok) {
    await recordAdminAction({
      adminId: viewer.userId, adminEmail: viewer.email, adminRole: viewer.role,
      action: 'admin.step_up_verified', targetType: 'user', targetId: viewer.userId, targetLabel: viewer.email,
      reason: 'Step-up re-authentication failed.', status: 'failed', stepUp: false, ipHash: null,
      metadata: { demo: isDemo },
    });
    return { ok: false, error: isDemo ? 'Incorrect demo password (agree-e-demo).' : 'Re-authentication failed.' };
  }
  await signInDemo(viewer.userId, 'stepup');
  const meta = await requestMeta();
  await recordAdminAction({
    adminId: viewer.userId, adminEmail: viewer.email, adminRole: viewer.role,
    action: 'admin.step_up_verified', targetType: 'user', targetId: viewer.userId, targetLabel: viewer.email,
    reason: `Step-up re-authentication succeeded; elevated window open for ${env.adminStepUpWindowMinutes} minutes.`,
    status: 'succeeded', stepUp: true, ipHash: meta.ipHash, userAgent: meta.userAgent,
    metadata: { window_minutes: env.adminStepUpWindowMinutes },
  });
  revalidate();
  return { ok: true, message: `Elevated session active for ${env.adminStepUpWindowMinutes} minutes.` };
}

export async function signOutAction(): Promise<void> {
  const viewer = await getViewer();
  if (viewer) {
    await recordAdminAction({
      adminId: viewer.userId, adminEmail: viewer.email, adminRole: viewer.role, action: 'admin.login',
      targetType: 'user', targetId: viewer.userId, targetLabel: viewer.email,
      reason: 'Console sign-out.', status: 'succeeded', stepUp: false, ipHash: null, metadata: { sign_out: true },
    });
  }
  await signOut();
  redirect('/admin/login');
}
