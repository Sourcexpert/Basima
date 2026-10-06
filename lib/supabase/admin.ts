import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import { env, supabaseConfigured } from '@/lib/env';

/**
 * Privileged client. SERVER ONLY.
 *
 * Build Guide §8: the service-role key bypasses RLS, so it must never reach a
 * client bundle, never be prefixed NEXT_PUBLIC_, and never be imported from a
 * file that also runs in the browser. This module is imported exclusively by
 * server code paths that have already called authorize() for the acting admin.
 *
 * Privilege is not implied by the key alone: every privileged path still writes
 * an audit row and (where required) demands step-up auth + a written reason.
 */
let cached: SupabaseClient | null = null;

export function supabaseAdmin(): SupabaseClient | null {
  if (!supabaseConfigured) return null;
  if (cached) return cached;
  cached = createClient(env.supabaseUrl!, env.supabaseServiceRoleKey!, {
    auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
    global: { headers: { 'X-Client-Info': 'agree-e-admin-console' } },
  });
  return cached;
}

/** Raised when a privileged operation is attempted without a configured backend. */
export class BackendNotConfiguredError extends Error {
  readonly code = 'not_configured';
  constructor(operation: string) {
    super(`Backend not configured: "${operation}" requires Supabase credentials.`);
  }
}

export function requireAdminClient(operation: string): SupabaseClient {
  const client = supabaseAdmin();
  if (!client) throw new BackendNotConfiguredError(operation);
  return client;
}

export type { SupabaseClient };
