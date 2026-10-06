import { redirect } from 'next/navigation';
import Link from 'next/link';
import { getUserViewer } from '@/lib/auth/user-auth';
import { userStore } from '@/lib/data/user-store';
import { isDemo } from '@/lib/env';
import { USER_WORKSPACE_OWNER } from '@/lib/data/user-demo-db';
import { LoginForm } from './login-form';
import { Badge, Callout, Card, PageHead, Table } from '@/components/ui';

export const dynamic = 'force-dynamic';

export default async function LoginPage() {
  const viewer = await getUserViewer();
  if (viewer) redirect('/app');

  const s = await userStore();
  const demoAccounts = isDemo ? await demoSignInCandidates() : [];

  return (
    <div className="auth-wrap">
      <PageHead
        title="Sign in to agre-e"
        lede="Your agreements, signatures and evidence records live behind this door. There is no shared link and no guest access: an invitation is tied to the email address it was sent to."
      />

      <div className="split">
        <Card title="Sign in">
          <LoginForm demo={isDemo} />
        </Card>

        <div>
          {isDemo && (
            <Card
              title="Demo accounts"
              subtitle="This build runs on seeded data with no Supabase project attached. Any of these accounts can sign in; the password is shown once so you can walk the whole flow."
            >
              <Table head={['Account', 'Role on the records', 'Email']}>
                {demoAccounts.map((a) => (
                  <tr key={a.id}>
                    <td className="tiny">{a.displayName}</td>
                    <td className="tiny">{a.role}</td>
                    <td className="tiny mono">{a.email}</td>
                  </tr>
                ))}
              </Table>
              <Callout tone="accent">
                <strong>Password:</strong> <span className="mono">agree-e-demo</span>
                <div style={{ marginTop: 6 }}>
                  Sign in as{' '}
                  {demoAccounts[0] ? <>{demoAccounts[0].displayName} (<span className="mono">{demoAccounts[0].email}</span>)</> : 'any account'}{' '}
                  to see the owner&rsquo;s view, then as another party to see what a signer is shown — including the
                  signing order that stops them signing out of turn.
                </div>
              </Callout>
            </Card>
          )}

          <Card title="What happens at sign-in">
            <ul className="sub" style={{ margin: 0, paddingLeft: 18 }}>
              <li>You are authenticated as a <em>customer</em>. This door gives no access to the operator console, and operator credentials give no access to your agreements.</li>
              <li>Signing in does not reveal any agreement. Each screen re-checks whether you are the owner or an invited party on that specific record.</li>
              <li>If your account is suspended, locked or required to change its password, sign-in stops here — deliberately, rather than half-working.</li>
            </ul>
            <div className="callout" style={{ marginTop: 10 }}>
              <strong>Forgotten your password?</strong> We email a single-use reset link to the address on the account. Nobody — including our support team — can read or set your password for you; {isDemo ? 'this demo build stores no passwords at all, so the credential step is simulated while the rest of the recovery is real.' : 'the reset link is the only route.'}{' '}
              Holding a link? <Link href="/reset-password" style={{ color: 'var(--accent)' }}>Open the reset form</Link>.
            </div>
          </Card>

          <Card tight title="Operating the console instead?">
            <p className="sub" style={{ margin: 0 }}>
              The administrative console is a separate surface with its own session and its own capabilities:{' '}
              <Link href="/admin/login" style={{ color: 'var(--accent)' }}>/admin/login</Link>. Being an operator there
              grants you no access to any contract, and being a customer here grants you no operator capability. The
              separation is enforced server-side, not by which URL you know. <Badge tone="info">§5</Badge>
            </p>
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

/**
 * Demo-only convenience list. It deliberately shows *why* each account exists in
 * the dataset (owner, required signer, invitee who has not accepted), so a
 * walkthrough can demonstrate the authorisation rules rather than describe them.
 */
async function demoSignInCandidates() {
  const s = await userStore();
  const owner = await s.getUser(USER_WORKSPACE_OWNER);
  const agreements = owner ? await s.listAgreementsForUser(owner.id) : [];
  const out: Array<{ id: string; displayName: string; email: string; role: string }> = [];
  const seen = new Set<string>();

  if (owner) {
    out.push({ id: owner.id, displayName: owner.displayName, email: owner.email, role: 'Owner of the working drafts' });
    seen.add(owner.id);
  }

  for (const agreement of agreements) {
    for (const party of await s.listParties(agreement.id)) {
      if (!party.userId || seen.has(party.userId)) continue;
      const profile = await s.getUser(party.userId);
      if (!profile) continue;
      seen.add(party.userId);
      const state =
        party.status === 'invited' ? 'Invited — has not accepted yet'
          : party.signingRequired ? `Required signer (order ${party.signingOrder})`
            : 'Notified party, no signature required';
      out.push({ id: profile.id, displayName: profile.displayName, email: profile.email, role: state });
      if (out.length >= 6) return out;
    }
  }
  return out;
}
