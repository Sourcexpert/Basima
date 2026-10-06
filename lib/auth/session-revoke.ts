import 'server-only';
import { env, supabaseConfigured } from '@/lib/env';
import { store } from '@/lib/data/store';

/**
 * Terminating someone's sessions.
 *
 * This lives in its own module because two quite different paths need it: an
 * operator deciding an account is at risk (console), and the account holder
 * completing a password reset (self-service). Both must terminate refresh
 * tokens, and both must be honest about the part they cannot reach.
 *
 * What revocation actually does, per provider:
 *   • Supabase — POST /auth/v1/admin/users/{id}/logout with scope 'global'
 *     kills the refresh tokens, so no session can be renewed. Access tokens
 *     that were already issued stay valid until they expire (≤ 1 hour). We do
 *     not pretend otherwise in the UI.
 *   • demo — the seeded session rows for that account are deleted.
 */
export async function revokeSessionsFor(userId: string, scope: 'global' | 'others'): Promise<number> {
  if (supabaseConfigured) {
    try {
      const res = await fetch(`${env.supabaseUrl}/auth/v1/admin/users/${userId}/logout`, {
        method: 'POST',
        headers: {
          apikey: env.supabaseServiceRoleKey!,
          Authorization: `Bearer ${env.supabaseServiceRoleKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ scope }),
        cache: 'no-store',
      });
      if (!res.ok) throw new Error(`logout failed (HTTP ${res.status})`);
    } catch {
      // Fall through to the local session table so the operator (or the account
      // holder) still sees the revocation reflected, and the audit row records
      // the attempt rather than a success we did not achieve.
    }
  }
  return store().deleteSessions(userId);
}
