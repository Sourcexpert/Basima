'use server';

import { headers } from 'next/headers';
import { completeRecovery } from '@/lib/services/password-recovery';
import { hashIp } from '@/lib/crypto/hash';
import { env } from '@/lib/env';
import type { ActionResult } from '@/lib/validation/schemas';

/**
 * The one mutation on this surface.
 *
 * Note what is *absent*: no viewer, no session, no capability check. That is not
 * an oversight — the person using this form has lost their credential, so the
 * token in the link is the entire authorization. The service therefore does the
 * work the missing session would otherwise do: it re-reads the token, checks it
 * is unconsumed and unexpired, checks the account is still active, and consumes
 * it exactly once.
 */
export interface ResetState {
  ok: boolean;
  error?: string;
  message?: string;
}

export async function completeRecoveryAction(_prev: ResetState | null, formData: FormData): Promise<ResetState> {
  const h = await headers();
  const ip = h.get('x-forwarded-for')?.split(',')[0]?.trim() || h.get('x-real-ip') || null;
  const meta = { ipHash: hashIp(ip, env.ipHashPepper), userAgent: h.get('user-agent') };

  const result: ActionResult<unknown> = await completeRecovery(String(formData.get('token') ?? ''), {
    newPassword: String(formData.get('newPassword') ?? ''),
    confirmPassword: String(formData.get('confirmPassword') ?? ''),
  }, meta);

  return result.ok
    ? { ok: true, message: result.message }
    : { ok: false, error: result.error };
}
