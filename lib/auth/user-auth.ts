import 'server-only';
import { cookies, headers } from 'next/headers';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { env, supabaseConfigured } from '@/lib/env';
import { hashIp } from '@/lib/crypto/hash';
import { supabaseServer } from '@/lib/supabase/server';
import { store } from '@/lib/data/store';
import type { Profile } from '@/lib/data/types';

/**
 * The user workspace identity: a *customer*, not a console operator.
 *
 * It is a separate cookie and a separate session carrier from the admin console
 * on purpose. A person can be signed in to their own agreements without holding
 * any console capability, and console roles are checked elsewhere entirely —
 * the two trust boundaries never share a session.
 */
const USER_COOKIE = 'agree_e_user';

function secret(): string {
  // Same single server-side signing key as the console; production requires it.
  return env.ipHashPepper;
}

function sign(payload: string): string {
  return createHmac('sha256', secret()).update(payload).digest('base64url');
}

function encode(value: object): string {
  const body = Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
  return `${body}.${sign(body)}`;
}

function decode<T>(token: string | undefined): T | null {
  if (!token) return null;
  const [body, mac] = token.split('.');
  if (!body || !mac) return null;
  const expected = sign(body);
  const a = Buffer.from(mac);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  try {
    return JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) as T;
  } catch {
    return null;
  }
}

export interface UserViewer {
  userId: string;
  email: string;
  displayName: string;
  organisation: string | null;
  mfaEnabled: boolean;
  mode: 'demo' | 'supabase';
}

export async function getUserViewer(): Promise<UserViewer | null> {
  if (supabaseConfigured) {
    const supabase = await supabaseServer();
    if (!supabase) return null;
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return null;
    const profile = await store().getUser(user.id);
    if (!profile || ['suspended', 'locked', 'deactivated'].includes(profile.status)) return null;
    if (profile.forcePasswordReset) return null; // must change the password first
    return {
      userId: profile.id, email: profile.email, displayName: profile.displayName,
      organisation: profile.organisation, mfaEnabled: profile.mfaEnabled, mode: 'supabase',
    };
  }

  const raw = decode<{ userId: string; issuedAt: string }>(
    (await cookies()).get(USER_COOKIE)?.value,
  );

  let profile: Profile | null = null;
  if (raw) profile = await store().getUser(raw.userId);

  /**
   * Demo convenience: AGREE_E_USER_AUTOLOGIN=<email|id> lands a walkthrough or
   * screenshot session straight in a customer account. Refused outright when
   * Supabase is configured, so it can never be a production bypass.
   */
  if (!profile && process.env.AGREE_E_USER_AUTOLOGIN) {
    const wanted = process.env.AGREE_E_USER_AUTOLOGIN.trim();
    profile = (await store().getUserByEmail(wanted)) ?? (await store().getUser(wanted));
  }

  if (!profile) return null;
  if (['suspended', 'locked', 'deactivated'].includes(profile.status)) return null;
  if (profile.forcePasswordReset) return null;

  return {
    userId: profile.id, email: profile.email, displayName: profile.displayName,
    organisation: profile.organisation, mfaEnabled: profile.mfaEnabled, mode: 'demo',
  };
}

export async function signInUser(userId: string): Promise<void> {
  if (supabaseConfigured) throw new Error('Use Supabase Auth: this deployment is configured for real sign-in.');
  const jar = await cookies();
  jar.set(USER_COOKIE, encode({ userId, issuedAt: new Date().toISOString() }), {
    httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax',
    path: '/', maxAge: 7 * 24 * 3600,
  });
}

export async function signOutUser(): Promise<void> {
  const jar = await cookies();
  jar.delete(USER_COOKIE);
  if (supabaseConfigured) {
    const supabase = await supabaseServer();
    await supabase?.auth.signOut();
  }
}

export async function userRequestMeta(): Promise<{ ipHash: string | null; userAgent: string | null }> {
  const h = await headers();
  const ip = h.get('x-forwarded-for')?.split(',')[0]?.trim() || h.get('x-real-ip') || null;
  return { ipHash: hashIp(ip, env.ipHashPepper), userAgent: h.get('user-agent') };
}

/** Password strength/label used by the self-service change form. */
export function passwordStrength(pw: string): { score: 0 | 1 | 2 | 3 | 4; label: string } {
  let score = 0;
  if (pw.length >= 12) score += 1;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score += 1;
  if (/[0-9]/.test(pw)) score += 1;
  if (/[^A-Za-z0-9]/.test(pw) || pw.length >= 18) score += 1;
  const labels = ['Very weak', 'Weak', 'Reasonable', 'Strong', 'Very strong'];
  return { score: score as 0 | 1 | 2 | 3 | 4, label: labels[score] };
}
