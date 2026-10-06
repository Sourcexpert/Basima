'use server';

import { revalidatePath } from 'next/cache';
import { redirect } from 'next/navigation';
import { getUserViewer, signInUser, signOutUser, userRequestMeta } from '@/lib/auth/user-auth';
import { isDemo, supabaseConfigured } from '@/lib/env';
import { store } from '@/lib/data/store';
import {
  acceptInvitation, addVersion, buildEvidencePackage, createAgreement, fileDataRequest,
  inviteParty, revokeAgreement, signAgreement,
} from '@/lib/services/agreements';
import { startOwnStkPush } from '@/lib/services/user-billing';
import { formatZodError, selfPasswordSchema, userPaymentSchema } from '@/lib/validation/user-schemas';
import type { ActionResult } from '@/lib/validation/schemas';

/**
 * The user workspace's single mutation surface, mirroring the console's
 * dispatcher: every branch resolves the viewer server-side, then delegates to a
 * service that re-checks the person's relationship to *this* agreement.
 * A signed-in session is never, by itself, authorization.
 */
export interface UserActionState {
  ok: boolean;
  error?: string;
  message?: string;
  data?: unknown;
  action?: string;
}

const PATHS = ['/app', '/app/agreements', '/app/evidence', '/app/billing', '/app/settings'];

function revalidate() {
  for (const p of PATHS) revalidatePath(p, 'layout');
}

export async function runUserAction(_prev: UserActionState | null, formData: FormData): Promise<UserActionState> {
  const viewer = await getUserViewer();
  if (!viewer) return { ok: false, error: 'Your session has ended. Sign in again.', action: 'unauthenticated' };

  const meta = await userRequestMeta();
  const ctx = {
    viewer: { userId: viewer.userId, email: viewer.email, displayName: viewer.displayName },
    ipHash: meta.ipHash,
    userAgent: meta.userAgent,
  };

  const action = String(formData.get('__action') ?? '');
  const str = (k: string) => String(formData.get(k) ?? '');
  const bool = (k: string) => formData.get(k) === 'on' || formData.get(k) === 'true';
  const num = (k: string) => Number(formData.get(k) ?? 0);
  const key = str('idempotencyKey') || crypto.randomUUID();

  const wrap = (result: ActionResult<unknown>): UserActionState => {
    if (result.ok) {
      revalidate();
      return { ok: true, message: result.message, data: result.data, action };
    }
    return { ok: false, error: result.error, action };
  };

  switch (action) {
    case 'create_agreement':
      return wrap(await createAgreement(ctx, {
        title: str('title'), agreementType: str('agreementType'),
        documentText: str('documentText'), idempotencyKey: key,
      }));

    case 'add_version':
      return wrap(await addVersion(ctx, {
        agreementId: str('agreementId'), documentText: str('documentText'),
        note: str('note'), idempotencyKey: key,
      }));

    case 'invite_party':
      return wrap(await inviteParty(ctx, {
        agreementId: str('agreementId'), email: str('email'), displayName: str('displayName'),
        partyRole: str('partyRole'), signingRequired: bool('signingRequired') ? true : str('signingRequired') !== 'false',
        signingOrder: num('signingOrder') || 1, idempotencyKey: key,
      }));

    case 'accept_invitation':
      return wrap(await acceptInvitation(ctx, { agreementId: str('agreementId') }));

    case 'sign':
      return wrap(await signAgreement(ctx, {
        agreementId: str('agreementId'), versionId: str('versionId'),
        disclosureVersion: str('disclosureVersion'), confirmName: str('confirmName'),
        otp: str('otp') || undefined, confirmIntent: true as const, idempotencyKey: key,
      }));

    case 'revoke':
      return wrap(await revokeAgreement(ctx, {
        agreementId: str('agreementId'), reason: str('reason'), idempotencyKey: key,
      }));

    case 'generate_package':
      return wrap(await buildEvidencePackage(ctx, str('agreementId')));

    case 'data_request':
      return wrap(await fileDataRequest(ctx, { type: str('type'), detail: str('detail') }));

    case 'pay_invoice': {
      // NOTE: intentionally not the console's billing service. A customer holds
      // no operator capability; the shared part is the provider client.
      return wrap(await startOwnStkPush(
        { viewer: { userId: viewer.userId, email: viewer.email }, ipHash: meta.ipHash, userAgent: meta.userAgent },
        { invoiceId: str('invoiceId'), phone: str('phone'), idempotencyKey: key },
      ));
    }

    case 'change_password': {
      const parsed = selfPasswordSchema.safeParse({
        currentPassword: str('currentPassword'), newPassword: str('newPassword'), confirmPassword: str('confirmPassword'),
      });
      if (!parsed.success) return { ok: false, error: formatZodError(parsed.error), action };

      if (isDemo) {
        await store().patchUser(viewer.userId, { passwordChangedAt: new Date().toISOString(), forcePasswordReset: false });
        revalidate();
        return {
          ok: true, action,
          message: 'Password changed and every other session for your account has been signed out. This demo build does not store passwords, so record the change as simulated.',
        };
      }
      const { supabaseServer } = await import('@/lib/supabase/server');
      const supabase = await supabaseServer();
      const { error: verifyError } = await supabase!.auth.signInWithPassword({ email: viewer.email, password: parsed.data.currentPassword });
      if (verifyError) return { ok: false, error: 'Your current password is not correct.', action };
      const { error } = await supabase!.auth.updateUser({ password: parsed.data.newPassword });
      if (error) return { ok: false, error: error.message, action };
      await store().patchUser(viewer.userId, { passwordChangedAt: new Date().toISOString(), forcePasswordReset: false });
      revalidate();
      return { ok: true, action, message: 'Password changed. Other sessions have been signed out.' };
    }

    default:
      return { ok: false, error: `Unknown action "${action}".`, action };
  }
}

/* ------------------------------------------------------------- user auth --- */

export async function demoUserSignIn(_prev: UserActionState | null, formData: FormData): Promise<UserActionState> {
  if (supabaseConfigured) return { ok: false, error: 'This deployment uses Supabase Auth.' };
  const email = String(formData.get('email') ?? '').trim();
  const password = String(formData.get('password') ?? '');
  const profile = await store().getUserByEmail(email);
  if (!profile || !['counsel'].includes(profile.role)) {
    return { ok: false, error: 'No customer account matches that email in this demo dataset.' };
  }
  if (['suspended', 'locked', 'deactivated'].includes(profile.status)) {
    return { ok: false, error: `That account is ${profile.status}. Sign-in is unavailable.` };
  }
  if (password !== 'agree-e-demo') {
    return { ok: false, error: 'Incorrect demo password. It is "agree-e-demo".' };
  }
  await signInUser(profile.id);
  redirect('/app');
}

export async function userSignIn(_prev: UserActionState | null, formData: FormData): Promise<UserActionState> {
  if (!supabaseConfigured) return { ok: false, error: 'This deployment has no auth backend configured.' };
  const email = String(formData.get('email') ?? '').trim();
  const password = String(formData.get('password') ?? '');
  const { supabaseServer } = await import('@/lib/supabase/server');
  const supabase = await supabaseServer();
  const { data, error } = await supabase!.auth.signInWithPassword({ email, password });
  if (error || !data.user) return { ok: false, error: 'Sign-in failed. Check your email and password.' };

  const profile = await store().getUser(data.user.id);
  if (profile?.forcePasswordReset) redirect('/app/reset-password');
  if (!profile || ['suspended', 'locked', 'deactivated'].includes(profile.status)) {
    await supabase!.auth.signOut();
    return { ok: false, error: 'This account cannot sign in. Contact support if you believe this is wrong.' };
  }
  redirect('/app');
}

export async function userSignOut(): Promise<void> {
  await signOutUser();
  redirect('/app/login');
}
