import { redirect } from 'next/navigation';
import Link from 'next/link';
import { authMode, getViewer } from '@/lib/auth/session';
import { store } from '@/lib/data/store';
import { SignInForm } from './sign-in-form';

export const dynamic = 'force-dynamic';

export default async function LoginPage() {
  const viewer = await getViewer();
  if (viewer) redirect('/admin');

  const operators = authMode === 'demo'
    ? (await store().listUsers({ limit: 200 })).filter(
        (u) => ['owner', 'admin', 'support', 'security', 'billing'].includes(u.role),
      )
    : [];

  return (
    <div style={{ minHeight: '100vh', display: 'grid', placeItems: 'center', padding: 22 }}>
      <div style={{ width: 'min(940px, 100%)', display: 'grid', gridTemplateColumns: 'minmax(0,1fr) minmax(0,1fr)', gap: 22, alignItems: 'start' }}>
        <div>
          <div className="brand" style={{ padding: 0, marginBottom: 14 }}>
            <div className="brand-mark">ae</div>
            <div>
              <div className="brand-name">agre-e</div>
              <div className="brand-sub">Admin console</div>
            </div>
          </div>
          <h1 style={{ fontSize: 24 }}>Operations, billing and security console</h1>
          <p className="lede" style={{ marginTop: 8 }}>
            This surface manages accounts, credentials, subscriptions and security policy for agre-e.
            It is separated, by design, from agreement content: an administrator here cannot read a
            user&rsquo;s contract unless a security-role operator runs an explicit, logged privileged-access
            workflow with a written reason.
          </p>

          <div className="callout accent" style={{ marginTop: 16 }}>
            <strong>Trust boundaries enforced on this surface.</strong>
            <ul style={{ margin: '7px 0 0', paddingLeft: 18 }}>
              <li>Least privilege per role — support cannot move money, billing cannot touch credentials.</li>
              <li>Step-up re-authentication + written justification for sensitive actions.</li>
              <li>Append-only admin ledger: operator, target, reason, timestamp, chained hash.</li>
              <li>No administrator can read or set another person&rsquo;s plaintext password.</li>
            </ul>
          </div>

          <p className="tiny" style={{ marginTop: 16 }}>
            Public site: <Link href="/" style={{ color: 'var(--accent)' }}>www.agre-e.com</Link> · Counsel
            workspace: counsel.agre-e.com · User workspace: app.agre-e.com
          </p>
        </div>

        <SignInForm
          mode={authMode}
          operators={operators.map((o) => ({
            id: o.id, name: o.displayName, email: o.email, role: o.role,
            mfa: o.mfaEnabled, status: o.status,
          }))}
        />
      </div>
    </div>
  );
}
