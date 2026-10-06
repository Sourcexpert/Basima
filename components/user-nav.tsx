'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { userSignOut } from '@/app/app/actions';
import { Badge } from '@/components/ui';

export interface ActionableItem {
  id: string;
  ref: string;
  title: string;
  label: string;
  href: string;
}

export function UserNav({
  viewer, counts, actionable, mode,
}: {
  viewer: { displayName: string; email: string; organisation: string | null; mfaEnabled: boolean };
  counts: { agreements: number; actionable: number; packages: number; openInvoices: number };
  actionable: ActionableItem[];
  mode: 'demo' | 'supabase';
}) {
  const pathname = usePathname();

  const items = [
    { href: '/app', label: 'Home', badge: undefined },
    { href: '/app/agreements', label: 'My agreements', badge: counts.agreements || undefined },
    { href: '/app/evidence', label: 'Evidence packages', badge: counts.packages || undefined },
    { href: '/app/verify', label: 'Verify a chain', badge: undefined },
    { href: '/app/billing', label: 'Billing', badge: counts.openInvoices || undefined },
    { href: '/app/settings', label: 'Settings & privacy', badge: undefined },
  ];

  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-mark">ae</div>
        <div>
          <div className="brand-name">agre-e</div>
          <div className="brand-sub">Your workspace</div>
        </div>
      </div>

      {mode === 'demo' && (
        <div style={{ padding: '0 8px 12px' }}>
          <span className="pill-demo" title="No Supabase credentials detected; running on the seeded demo dataset.">DEMO DATA</span>
        </div>
      )}

      <div className="card tight" style={{ padding: 10, marginBottom: 12 }}>
        <div className="tiny" style={{ letterSpacing: '0.08em' }}>SIGNED IN AS</div>
        <div style={{ fontWeight: 620, marginTop: 3 }}>{viewer.displayName}</div>
        <div className="tiny" style={{ wordBreak: 'break-all' }}>{viewer.email}</div>
        {viewer.organisation && <div className="tiny" style={{ marginTop: 2 }}>{viewer.organisation}</div>}
        <div style={{ marginTop: 8, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          {viewer.mfaEnabled ? <Badge tone="ok">MFA on</Badge> : <Badge tone="warn">MFA off</Badge>}
        </div>
      </div>

      {counts.actionable > 0 && (
        <div style={{ marginBottom: 14 }}>
          <div className="nav-group-title" style={{ paddingLeft: 10 }}>Needs you now</div>
          {actionable.slice(0, 4).map((a) => (
            <Link key={a.id} href={a.href} className="nav-link" style={{ alignItems: 'flex-start' }}>
              <span className="dot" style={{ marginTop: 6, background: 'var(--warn)' }} />
              <span>
                <span style={{ display: 'block', fontWeight: 600, fontSize: 12.5 }}>{a.label}</span>
                <span className="tiny" style={{ display: 'block' }}>{a.ref}</span>
              </span>
            </Link>
          ))}
        </div>
      )}

      <nav>
        {items.map((item) => {
          const active = item.href === '/app' ? pathname === '/app' : pathname.startsWith(item.href);
          return (
            <Link key={item.href} href={item.href} className="nav-link" data-active={active}>
              <span className="dot" />
              {item.label}
              {typeof item.badge === 'number' && <span className="nav-count">{item.badge}</span>}
            </Link>
          );
        })}
      </nav>

      <div className="nav-group">
        <div className="nav-group-title">Not available to you</div>
        <span className="nav-link nav-locked" title="Operator functions are on a separate surface with separate authorisation. Being a customer never grants console access.">
          <span className="dot" /> Operator console
        </span>
      </div>

      <form action={userSignOut} style={{ marginTop: 18, padding: '0 4px' }}>
        <button type="submit" className="btn sm ghost" style={{ width: '100%' }}>Sign out</button>
      </form>
    </aside>
  );
}
