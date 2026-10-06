import 'server-only';
import { isDemo } from '@/lib/env';
import { store, supabaseStore } from './store';

/**
 * The store as the *signed-in customer*.
 *
 * In demo mode this is the seeded in-memory store, same as everywhere else.
 *
 * With Supabase configured it returns a store bound to the request's
 * authenticated client (anon key + the user's cookies), so Row Level Security
 * applies to every read the user workspace performs. That matters for the rows
 * where an application bug would be a data breach rather than a bad screen:
 * document content, evidence packages, and anyone else's agreement.
 *
 * Writes are the other half of this seam and are deliberately not routed here:
 * the append-only ledger is written through SECURITY DEFINER functions
 * (`append_audit_event`, `record_signature_event`, `accept_invitation` in
 * migration 0003) so that hashing, stamping and the completion decision happen
 * server-side inside one transaction, never in a browser-controlled path.
 * Until the Supabase write path is switched to those RPCs, the TypeScript
 * service layer performs the same steps against the service-role client and
 * every one of them begins with an explicit authorisation check.
 */
export async function userStore() {
  if (isDemo) return store();
  const { supabaseServer } = await import('@/lib/supabase/server');
  const client = await supabaseServer();
  return supabaseStore(client);
}
