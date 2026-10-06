import { redirect } from 'next/navigation';
import { getViewer, stepUpExpiresInMinutes, stepUpFresh, authMode } from '@/lib/auth/session';
import { Sidebar, type NavGroup } from '@/components/nav';
import { can, roleLabel } from '@/lib/auth/rbac';
import { store } from '@/lib/data/store';

export const dynamic = 'force-dynamic';

export default async function AdminLayout({ children }: { children: React.ReactNode }) {
  const viewer = await getViewer();
  if (!viewer) redirect('/admin/login');

  const [users, subscriptions, payments, security] = await Promise.all([
    can(viewer.role, 'users.read') ? store().listUsers({ limit: 1000 }) : Promise.resolve([]),
    can(viewer.role, 'billing.read') ? store().listSubscriptions({ limit: 1000 }) : Promise.resolve([]),
    can(viewer.role, 'billing.read') ? store().listPayments({ status: 'failed', limit: 1000 }) : Promise.resolve([]),
    can(viewer.role, 'audit.security.read') ? store().listSecurityEvents({ limit: 200 }) : Promise.resolve([]),
  ]);

  const groups: NavGroup[] = [
    {
      title: 'Operations',
      items: [
        { href: '/admin', label: 'Overview', capability: 'console.access' },
        { href: '/admin/users', label: 'Users & access', capability: 'users.read', count: users.length || undefined },
      ],
    },
    {
      title: 'Commercial',
      items: [
        { href: '/admin/billing', label: 'Subscriptions', capability: 'billing.read', count: subscriptions.length || undefined },
        { href: '/admin/billing/plans', label: 'Plans & pricing', capability: 'billing.read' },
        { href: '/admin/billing/payments', label: 'Payments & invoices', capability: 'billing.read', count: payments.length || undefined },
        { href: '/admin/billing/coupons', label: 'Coupons & dunning', capability: 'billing.read' },
      ],
    },
    {
      title: 'Assurance',
      items: [
        { href: '/admin/audit', label: 'Audit & evidence', capability: 'audit.admin.read' },
        { href: '/admin/security', label: 'Security events', capability: 'audit.security.read', count: security.filter((s) => s.severity === 'critical').length || undefined },
        { href: '/admin/settings', label: 'Roles & policy', capability: 'settings.manage' },
      ],
    },
  ];

  return (
    <div className="shell">
      <Sidebar
        groups={groups}
        capabilities={viewer.capabilities}
        viewer={{ displayName: viewer.displayName, email: viewer.email, role: roleLabel(viewer.role) }}
        mode={authMode}
        stepUpFresh={stepUpFresh(viewer)}
        stepUpExpiresInMinutes={stepUpExpiresInMinutes(viewer)}
      />
      <div className="main">
        <header className="topbar">
          <span className="crumb">agre-e · console · {roleLabel(viewer.role)}</span>
          <span className="spacer" />
          <span className="chip" title="Every privileged action on this screen is written to an append-only ledger.">
            Audit ledger: active
          </span>
          {authMode === 'demo' && <span className="pill-demo">DEMO</span>}
        </header>
        <main className="content">{children}</main>
      </div>
    </div>
  );
}
