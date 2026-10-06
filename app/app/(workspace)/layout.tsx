import Link from 'next/link';
import { redirect } from 'next/navigation';
import { getUserViewer } from '@/lib/auth/user-auth';
import { userStore } from '@/lib/data/user-store';
import { UserNav } from '@/components/user-nav';
import { nextActionFor } from '@/lib/auth/user-access';
import { Callout } from '@/components/ui';

export const dynamic = 'force-dynamic';

export default async function UserLayout({ children }: { children: React.ReactNode }) {
  const viewer = await getUserViewer();
  if (!viewer) redirect('/app/login');

  const s = await userStore();
  const [agreements, packages, invoices] = await Promise.all([
    s.listAgreementsForUser(viewer.userId, viewer.email),
    s.listPackages(),
    s.listInvoices({ limit: 500 }),
  ]);

  // "What needs me?" — computed once for the shell so the count is consistent
  // everywhere, and so the dashboard and the nav cannot disagree.
  const actionable: Array<{ id: string; ref: string; title: string; label: string; href: string }> = [];
  for (const agreement of agreements) {
    const [parties, signatureEvents, documents] = await Promise.all([
      s.listParties(agreement.id),
      s.listSignatureEvents(agreement.id),
      s.listDocuments(agreement.id),
    ]);
    const current = documents.find((d) => d.versionNumber === agreement.currentVersion) ?? null;
    const next = nextActionFor(viewer.userId, {
      agreement, parties, signatureEvents, currentVersion: current, viewerEmail: viewer.email,
    });
    if (next && ['Accept invitation', 'Sign now'].includes(next.label)) {
      actionable.push({ id: agreement.id, ref: agreement.ref, title: agreement.title, label: next.label, href: next.href });
    }
  }

  const openInvoices = invoices.filter((i) => i.userId === viewer.userId && i.status === 'open');

  return (
    <div className="shell">
      <UserNav
        viewer={{ displayName: viewer.displayName, email: viewer.email, organisation: viewer.organisation, mfaEnabled: viewer.mfaEnabled }}
        counts={{
          agreements: agreements.length,
          actionable: actionable.length,
          packages: packages.length,
          openInvoices: openInvoices.length,
        }}
        actionable={actionable}
        mode={viewer.mode}
      />
      <div className="main">
        <header className="topbar">
          <Link className="crumb" href="/app">agre-e · your agreements</Link>
          <span className="spacer" />
          <span className="chip" title="Integrity and evidence-chain checks are recomputed on every view, never cached.">
            Evidence chain: live
          </span>
          {openInvoices.length > 0 && (
            <Link className="chip" href="/app/billing" style={{ borderColor: 'var(--warn)', color: 'var(--warn)' }}>
              {openInvoices.length} invoice{openInvoices.length > 1 ? 's' : ''} awaiting payment
            </Link>
          )}
          {viewer.mode === 'demo' && <span className="pill-demo">DEMO</span>}
        </header>
        <main className="content">
          {actionable.length > 0 && (
            <Callout tone="warn">
              <strong>{actionable.length} agreement{actionable.length > 1 ? 's need' : ' needs'} you.</strong>{' '}
              {actionable.slice(0, 3).map((a) => (
                <span key={a.id}>
                  <Link href={a.href} style={{ color: 'var(--accent)' }}>{a.ref}</Link> — {a.label.toLowerCase()}{a !== actionable[Math.min(actionable.length, 3) - 1] ? ', ' : ''}
                </span>
              ))}
              {actionable.length > 3 ? ` and ${actionable.length - 3} more.` : '.'}
            </Callout>
          )}
          {children}
        </main>
      </div>
    </div>
  );
}
