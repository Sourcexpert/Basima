import 'server-only';
import { cookies, headers } from 'next/headers';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { capabilitiesFor, type Viewer } from '@/lib/auth/rbac';
import { env, isDemo, supabaseConfigured } from '@/lib/env';
import { hashIp } from '@/lib/crypto/hash';
import { supabaseServer } from '@/lib/supabase/server';
import { store } from '@/lib/data/store';

/**
 * Console session resolution.
 *
 * Production path: the Supabase session cookie is resolved server-side, the
 * profile is loaded, and the role is taken from the database — never from a
 * client-supplied value. Demo path: an HMAC-signed cookie selects one of the
 * seeded staff identities so the authorization model can be exercised locally.
 * The demo path is refused outright when Supabase is configured.
 */
const VIEWER_COOKIE = 'agree_e_console';
const STEPUP_COOKIE = 'agree_e_step_up';

function secret(): string {
  // Reuses the IP pepper so there is exactly one server-side signing key to
  // rotate; production requires it to be set (see lib/env.ts).
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

interface DemoViewerCookie { userId: string; issuedAt: string }

export async function getViewer(): Promise<Viewer | null> {
  const jar = await cookies();

  if (supabaseConfigured) {
    const supabase = await supabaseServer();
    if (!supabase) return null;
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return null;
    const { data: profile } = await supabase.from('profiles').select('*').eq('id', user.id).maybeSingle();
    if (!profile || profile.status !== 'active') return null;
    if (!['owner', 'admin', 'support', 'security', 'billing', 'counsel'].includes(profile.role)) return null;
    const stepUp = decode<{ at: string }>(jar.get(STEPUP_COOKIE)?.value);
    return {
      userId: user.id,
      email: profile.email,
      displayName: profile.display_name,
      role: profile.role,
      capabilities: capabilitiesFor(profile.role, profile.extra_capabilities ?? []),
      stepUpVerifiedAt: stepUp?.at ?? null,
      mfaEnabled: Boolean(profile.mfa_enabled),
    };
  }

  // ---- demo path (never active when Supabase is configured) ----
  const raw = decode<DemoViewerCookie>(jar.get(VIEWER_COOKIE)?.value);

  /**
   * Demo convenience for screenshots, walkthroughs and automated checks:
   * AGREE_E_AUTOLOGIN=<email|id> signs a seeded operator in without the cookie.
   * It only exists on the demo path (which requires an unconfigured backend),
   * and it is refused if Supabase credentials are present — see the branch above.
   */
  if (!raw && process.env.AGREE_E_AUTOLOGIN) {
    const wanted = process.env.AGREE_E_AUTOLOGIN.trim();
    const byEmail = await store().getUserByEmail(wanted);
    const profile = byEmail ?? (await store().getUser(wanted));
    if (profile && profile.status === 'active') {
      const stepUp = decode<{ at: string }>(jar.get(STEPUP_COOKIE)?.value);
      return {
        userId: profile.id,
        email: profile.email,
        displayName: profile.displayName,
        role: profile.role,
        capabilities: capabilitiesFor(profile.role, profile.extraCapabilities),
        stepUpVerifiedAt: stepUp?.at ?? null,
        mfaEnabled: profile.mfaEnabled,
      };
    }
  }

  if (!raw) return null;
  const profile = await store().getUser(raw.userId);
  if (!profile || profile.status !== 'active') return null;
  if (!['owner', 'admin', 'support', 'security', 'billing', 'counsel'].includes(profile.role)) return null;
  const stepUp = decode<{ at: string }>(jar.get(STEPUP_COOKIE)?.value);
  return {
    userId: profile.id,
    email: profile.email,
    displayName: profile.displayName,
    role: profile.role,
    capabilities: capabilitiesFor(profile.role, profile.extraCapabilities),
    stepUpVerifiedAt: stepUp?.at ?? null,
    mfaEnabled: profile.mfaEnabled,
  };
}

export async function signInDemo(userId: string, scope: 'viewer' | 'stepup' = 'viewer'): Promise<void> {
  if (supabaseConfigured) throw new Error('Demo sign-in is unavailable when Supabase is configured.');
  const jar = await cookies();
  const opts = {
    httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax' as const,
    path: '/', maxAge: scope === 'viewer' ? env.sessionAbsoluteHours * 3600 : 900,
  };
  if (scope === 'viewer') jar.set(VIEWER_COOKIE, encode({ userId, issuedAt: new Date().toISOString() }), opts);
  else jar.set(STEPUP_COOKIE, encode({ at: new Date().toISOString() }), opts);
}

export async function signOut(): Promise<void> {
  const jar = await cookies();
  jar.delete(VIEWER_COOKIE);
  jar.delete(STEPUP_COOKIE);
  if (supabaseConfigured) {
    const supabase = await supabaseServer();
    await supabase?.auth.signOut();
  }
}

export async function clearStepUp(): Promise<void> {
  (await cookies()).delete(STEPUP_COOKIE);
}

export async function requestMeta(): Promise<{ ipHash: string | null; userAgent: string | null }> {
  const h = await headers();
  const ip =
    h.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    h.get('x-real-ip') ||
    null;
  return { ipHash: hashIp(ip, env.ipHashPepper), userAgent: h.get('user-agent') };
}

export function stepUpFresh(viewer: Viewer): boolean {
  if (!viewer.stepUpVerifiedAt) return false;
  return Date.now() - new Date(viewer.stepUpVerifiedAt).getTime() < env.adminStepUpWindowMinutes * 60_000;
}

export function stepUpExpiresInMinutes(viewer: Viewer): number {
  if (!viewer.stepUpVerifiedAt) return 0;
  const elapsed = (Date.now() - new Date(viewer.stepUpVerifiedAt).getTime()) / 60_000;
  return Math.max(0, Math.round(env.adminStepUpWindowMinutes - elapsed));
}

export const authMode = isDemo ? 'demo' : 'supabase';
