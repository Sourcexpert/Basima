import { NextResponse, type NextRequest } from 'next/server';
import { supabaseConfigured } from '@/lib/env';
import { supabaseServer } from '@/lib/supabase/server';

export const dynamic = 'force-dynamic';

/**
 * Redirect with a relative Location header. Building an absolute URL from
 * request.url breaks when the server listens on 0.0.0.0 (the dev and start
 * scripts do): the browser would be sent to http://0.0.0.0:3000, which it
 * cannot open. A relative Location keeps the browser on the host it used.
 */
function redirectTo(path: string) {
  return new NextResponse(null, { status: 307, headers: { Location: path } });
}

/**
 * Supabase's redirect target (`…/auth/callback?code=…`).
 *
 * Supabase Auth verifies the one-time link itself and sends the browser here
 * with an authorization code. The code is exchanged for a session on the
 * server, so the session cookie is set httpOnly and never passes through client
 * JavaScript. Only after that does the holder reach the reset form.
 */
export async function GET(request: NextRequest) {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const next = url.searchParams.get('next');

  if (url.searchParams.get('error_description') || !code) {
    return redirectTo('/reset-password?state=incomplete');
  }
  if (!supabaseConfigured) {
    return redirectTo('/reset-password?state=unconfigured');
  }

  /*
   * Honest note for the production seam: Supabase's PKCE flow expects the code
   * verifier cookie to have been written by the client that started the flow.
   * This build has no browser-side Supabase client, so on a live project either
   * middleware must mint that verifier, or the project should be configured for
   * the token-hash flow and post to /auth/confirm instead. The demo path — and
   * the `?token=` hand-off — is what `npm run walkthrough` exercises.
   */
  const supabase = await supabaseServer();
  const { error } = await supabase!.auth.exchangeCodeForSession(code);
  if (error) {
    return redirectTo('/reset-password?state=incomplete');
  }

  // `//host` and `/\host` start with '/' but browsers treat them as another origin.
  const destination = next && /^\/(?![/\\])/.test(next) ? next : '/reset-password';
  return redirectTo(destination);
}
