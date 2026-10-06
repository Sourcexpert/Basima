import Link from 'next/link';
import { inspectRecoveryToken, recoveryStateMessage, RECOVERY_TOKEN_TTL_MINUTES } from '@/lib/services/password-recovery';
import { isDemo } from '@/lib/env';
import { Badge, Callout, Card, KV, PageHead } from '@/components/ui';
import { ResetForm } from './reset-form';

export const dynamic = 'force-dynamic';

/**
 * Where a recovery link lands, and what it will and will not do.
 *
 * The page is deliberately outside `/app`: someone who cannot sign in must not
 * first be bounced to a sign-in page. It reads the token, states clearly what
 * state the link is in, and only then offers a form. Nothing about the account
 * is shown until the token is proven valid — an expired or reused link reveals
 * no name, no email, no existence.
 */
export default async function ResetPasswordPage({
  searchParams,
}: {
  searchParams: Promise<{ token?: string; state?: string }>;
}) {
  const params = await searchParams;
  const token = params.token;

  const inspected = token ? await inspectRecoveryToken(token) : null;
  const valid = inspected?.state === 'valid' ? inspected : null;

  return (
    <div className="auth-wrap">
      <PageHead
        title={valid ? 'Choose a new password' : 'Password recovery'}
        lede={
          valid
            ? 'You are here because a single-use recovery link was issued for this account. Setting a new password is the only thing this link can do.'
            : 'This page opens from a recovery link sent to the email address on an account. Nothing here can be done without one — by design.'
        }
      />

      <div className="split">
        <Card title={valid ? 'Set a new password' : 'Open your recovery link'}>
          {valid ? (
            <ResetForm token={token!} email={valid.account.email} />
          ) : (
            <>
              {inspected ? (
                <div className="callout danger">
                  <strong>This link cannot be used.</strong> {recoveryStateMessage(inspected.state)}
                </div>
              ) : (
                <div className="callout">
                  <strong>No link in this address.</strong> Recovery links look like{' '}
                  <span className="mono">/auth/confirm?token=…&amp;type=recovery</span>. If your mail client split the
                  link across two lines, copy the whole thing.
                </div>
              )}

              <div className="btn-row" style={{ marginTop: 14 }}>
                <Link className="btn primary" href="/app/login">Back to sign-in</Link>
              </div>

              <KV
                rows={[
                  ['Link lifetime', `${RECOVERY_TOKEN_TTL_MINUTES} minutes`],
                  ['Uses allowed', 'one, ever'],
                  ['Stored by agre-e', 'a one-way digest of the token — never the token itself'],
                  ['Who can see your password', 'nobody, in any role'],
                ]}
              />
            </>
          )}
        </Card>

        <div>
          <Card title="How to get a link">
            <ol className="sub" style={{ margin: 0, paddingLeft: 18 }}>
              <li>
                Ask for one. Support can issue a recovery link after confirming who you are — they will send it to the
                email address already on the account, never to an address you dictate in the conversation.
              </li>
              <li>
                The link arrives with a {RECOVERY_TOKEN_TTL_MINUTES}-minute life. Opening it does not spend it: only
                submitting the form does, so a mail scanner or a forwarded copy cannot lock you out.
              </li>
              <li>
                Setting a new password signs out every other session on the account.
              </li>
            </ol>
            <Callout tone="accent">
              <strong>Why we cannot simply reset it for you.</strong> An operator who can set your password can sign in
              as you, and could then sign as you. agre-e is a record of who did what, so no role here has that power —
              not support, not billing, not the engineering team. {isDemo && 'This demo build stores no passwords at all, so the credential step is recorded as simulated while the rest of the recovery is real.'}
            </Callout>
          </Card>

          <Card title="What this link is not" tight>
            <ul className="sub" style={{ margin: 0, paddingLeft: 18 }}>
              <li>It is not proof of identity — it proves control of the mailbox the link was sent to.</li>
              <li>It does not unlock any agreement. Being able to sign in is not the same as being a party to a record, which is checked separately on every page.</li>
              <li>It does not work twice, and it does not work after you have set a new password.</li>
            </ul>
            <div className="tiny" style={{ marginTop: 10 }}>
              Security events from this flow are visible to our security role as events — <Badge tone="info">no content</Badge>{' '}
              — and to nobody as a readable log of your activity.
            </div>
          </Card>
        </div>
      </div>

      <p className="tiny" style={{ marginTop: 14 }}>
        agre-e is a record-keeping system for agreements. It is not a law firm and does not provide legal advice. See{' '}
        <Link href="/" style={{ color: 'var(--accent)' }}>the overview</Link> for what we do and do not claim.
      </p>
    </div>
  );
}
