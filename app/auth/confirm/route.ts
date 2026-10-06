import { NextResponse, type NextRequest } from 'next/server';

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
 * The recovery-link landing point.
 *
 * A link of the shape `/auth/confirm?token=…&type=recovery` is the *only*
 * credential in a password reset, so this route does nothing clever: it hands
 * the token to the reset page and lets that page inspect it. It deliberately
 * does not consume or validate the token here — a mail scanner, a link
 * preview-bot or a curious colleague forwarding the mail must not be able to
 * burn someone's reset link, and they cannot, because a GET only moves the
 * token from the URL to the form.
 */
export async function GET(request: NextRequest) {
  const url = new URL(request.url);
  const token = url.searchParams.get('token');
  const type = url.searchParams.get('type') ?? 'recovery';

  if (!token) {
    return redirectTo('/reset-password?state=incomplete');
  }

  // Invitations use the same one-time-link mechanism but land on sign-in.
  if (type === 'invite') {
    return redirectTo('/app/login?invited=1');
  }

  return redirectTo(`/reset-password?token=${encodeURIComponent(token)}`);
}
