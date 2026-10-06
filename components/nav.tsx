'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useState } from 'react';
import { signOutAction } from '@/app/admin/actions';
import { StepUpControl } from '@/components/action-form';
import type { Capability } from '@/lib/auth/rbac';

export interface NavItem {
  href: string;
  label: string;
  capability: Capability;
  count?: number;
}

export interface NavGroup {
  title: string;
  items: NavItem[];
}

/**
 * Sidebar. Items are rendered only when the viewer's role holds the matching
 * capability — and each page re-checks it server-side. Hiding a link is a UX
 * affordance, never the control (Build Guide §8: "Browser-side hiding is not
 * authorization").
 */
export function Sidebar({
  groups, capabilities, viewer, mode, stepUpFresh, stepUpExpiresInMinutes,
}: {
  groups: NavGroup[];
  capabilities: Capability[];
  viewer: { displayName: string; email: string; role: string };
  mode: 'demo' | 'supabase';
  stepUpFresh: boolean;
  stepUpExpiresInMinutes: number;
}) {
  const pathname = usePathname();
  const [menuOpen, setMenuOpen] = useState(false);

  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-mark">ae</div>
        <div>
          <div className="brand-name">agre-e</div>
          <div className="brand-sub">Admin console</div>
        </div>
      </div>

      {mode === 'demo' && (
        <div style={{ padding: '0 8px 12px' }}>
          <span className="pill-demo" title="No Supabase credentials detected. Running on the seeded demo dataset.">DEMO DATA</span>
        </div>
      )}

      <div className="card tight" style={{ padding: 10, marginBottom: 14 }}>
        <div className="tiny" style={{ letterSpacing: '0.08em' }}>SIGNED IN AS</div>
        <div style={{ fontWeight: 620, marginTop: 3 }}>{viewer.displayName}</div>
        <div className="tiny" style={{ wordBreak: 'break-all' }}>{viewer.email}</div>
        <div style={{ marginTop: 8, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          <span className="chip">{viewer.role}</span>
          <button
            type="button"
            className="chip"
            onClick={() => { setMenuOpen(true); (document.getElementById('nav-session') as HTMLDialogElement | null)?.showModal(); }}
            style={{ cursor: 'pointer' }}
          >
            Session
          </button>
        </div>
      </div>

      <StepUpControl fresh={stepUpFresh} expiresInMinutes={stepUpExpiresInMinutes} mode={mode} />

      <nav style={{ marginTop: 16 }}>
        {groups.map((group) => {
          const visible = group.items.filter((i) => capabilities.includes(i.capability));
          if (visible.length === 0) return null;
          return (
            <div className="nav-group" key={group.title}>
              <div className="nav-group-title">{group.title}</div>
              {visible.map((item) => {
                const active = pathname === item.href || (item.href !== '/admin' && pathname.startsWith(item.href));
                return (
                  <Link key={item.href} href={item.href} className="nav-link" data-active={active}>
                    <span className="dot" />
                    {item.label}
                    {typeof item.count === 'number' && <span className="nav-count">{item.count}</span>}
                  </Link>
                );
              })}
            </div>
          );
        })}

        <div className="nav-group">
          <div className="nav-group-title">Boundary</div>
          <span className="nav-link nav-locked" title="Agreement content is reachable only through the privileged-access workflow, never by admin status alone.">
            <span className="dot" /> Agreements (content)
          </span>
          <span className="nav-link nav-locked" title="Admin status does not grant contract-reading rights.">
            <span className="dot" /> 🔒 Not granted by admin role
          </span>
        </div>
      </nav>

      <form action={signOutAction} style={{ marginTop: 18, padding: '0 4px' }}>
        <button type="submit" className="btn sm ghost" style={{ width: '100%' }}>Sign out</button>
      </form>

      {menuOpen && (
        <dialog id="nav-session" className="modal" onClose={() => setMenuOpen(false)}>
          <div className="modal-head">
            <h2>Session</h2>
            <div className="sub" style={{ marginTop: 4 }}>
              Console sessions are absolute-limited and step-up verification expires independently.
            </div>
          </div>
          <div className="modal-body">
            <dl className="kv">
              <dt>Operator</dt><dd>{viewer.email}</dd>
              <dt>Role</dt><dd>{viewer.role}</dd>
              <dt>Backend</dt><dd>{mode === 'supabase' ? 'Supabase Auth + RLS' : 'Demo dataset (no backend configured)'}</dd>
              <dt>Step-up</dt><dd>{stepUpFresh ? `Active, ~${stepUpExpiresInMinutes} min remaining` : 'Not elevated'}</dd>
            </dl>
          </div>
          <div className="modal-foot">
            <button type="button" className="btn ghost" onClick={() => { (document.getElementById('nav-session') as HTMLDialogElement | null)?.close(); setMenuOpen(false); }}>Close</button>
          </div>
        </dialog>
      )}
    </aside>
  );
}

/** Compact confirmation of the role model on every screen that acts on people. */
export function CapabilityRibbon({ capabilities }: { capabilities: Capability[] }) {
  const shown = capabilities.slice(0, 6);
  return (
    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
      {shown.map((c) => <span className="chip" key={c}>{c}</span>)}
      {capabilities.length > shown.length && <span className="chip">+{capabilities.length - shown.length} more</span>}
    </div>
  );
}
