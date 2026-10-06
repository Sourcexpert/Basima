import Link from 'next/link';

/**
 * Presentational primitives shared by every console screen.
 * No client-side state here on purpose: these render on the server, and the
 * console fetches nothing from the browser.
 */

export function Card({
  title, subtitle, actions, children, tight, className = '',
}: {
  title?: React.ReactNode; subtitle?: React.ReactNode; actions?: React.ReactNode;
  children?: React.ReactNode; tight?: boolean; className?: string;
}) {
  return (
    <section className={`card${tight ? ' tight' : ''} ${className}`}>
      {(title || actions) && (
        <header className="card-head">
          <div>
            {title && <h3>{title}</h3>}
            {subtitle && <div className="tiny" style={{ marginTop: 2 }}>{subtitle}</div>}
          </div>
          <div className="spacer" />
          {actions}
        </header>
      )}
      {children}
    </section>
  );
}

export function Stat({ label, value, meta, tone }: { label: string; value: React.ReactNode; meta?: React.ReactNode; tone?: 'ok' | 'warn' | 'danger' | 'accent' }) {
  return (
    <div className="card tight">
      <div className="stat-label">{label}</div>
      <div className="stat-value" style={tone ? { color: `var(--${tone === 'accent' ? 'accent' : tone})` } : undefined}>{value}</div>
      {meta && <div className="stat-meta">{meta}</div>}
    </div>
  );
}

type BadgeTone = 'ok' | 'warn' | 'danger' | 'info' | 'neutral' | 'accent';

export function Badge({ tone = 'neutral', children }: { tone?: BadgeTone; children: React.ReactNode }) {
  return <span className={`badge ${tone}`}>{children}</span>;
}

const STATUS_TONES: Record<string, BadgeTone> = {
  active: 'ok', completed: 'ok', succeeded: 'ok', paid: 'ok', verified: 'ok', trialing: 'info',
  invited: 'info', pending: 'info', initiated: 'info', draft: 'neutral', awaiting_parties: 'warn',
  awaiting_signatures: 'warn', past_due: 'warn', grace: 'warn', paused: 'warn', open: 'warn',
  locked: 'danger', suspended: 'danger', failed: 'danger', revoked: 'danger', expired: 'danger',
  cancelled: 'neutral', deactivated: 'neutral', refunded: 'info', reversed: 'warn', uncollectible: 'danger',
};

export function StatusBadge({ status }: { status: string }) {
  const tone = STATUS_TONES[status] ?? 'neutral';
  return <Badge tone={tone}>{status.replace(/_/g, ' ')}</Badge>;
}

export function Callout({ tone = 'info', children }: { tone?: 'info' | 'warn' | 'danger' | 'ok' | 'accent'; children: React.ReactNode }) {
  return <div className={`callout${tone === 'info' ? '' : ` ${tone}`}`}>{children}</div>;
}

export function Table({ head, children, empty }: { head: React.ReactNode[]; children?: React.ReactNode; empty?: string }) {
  const hasRows = Array.isArray(children) ? children.length > 0 : Boolean(children);
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>{head.map((h, i) => <th key={i}>{h}</th>)}</tr>
        </thead>
        <tbody>{hasRows ? children : <tr><td className="empty" colSpan={head.length}>{empty ?? 'Nothing to show.'}</td></tr>}</tbody>
      </table>
    </div>
  );
}

export function KV({ rows }: { rows: Array<[React.ReactNode, React.ReactNode]> }) {
  return (
    <dl className="kv">
      {rows.map(([k, v], i) => (
        <div key={i} style={{ display: 'contents' }}>
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Hash({ value, chars = 20 }: { value: string | null | undefined; chars?: number }) {
  if (!value) return <span className="tiny">—</span>;
  const short = value.length > chars ? `${value.slice(0, chars)}…` : value;
  return <span className="hash" title={value}>{short}</span>;
}

export function PageHead({ title, lede, actions }: { title: string; lede?: React.ReactNode; actions?: React.ReactNode }) {
  return (
    <div className="page-head">
      <div>
        <h1>{title}</h1>
        {lede && <p className="lede">{lede}</p>}
      </div>
      <div className="spacer" />
      {actions && <div className="btn-row">{actions}</div>}
    </div>
  );
}

export function DemoNote({ detail }: { detail: string }) {
  return (
    <Callout tone="warn">
      <strong>Demo dataset.</strong> {detail}
    </Callout>
  );
}

export function money(amountMinor: number, currency = 'KES'): string {
  const value = amountMinor / 100;
  const formatted = value.toLocaleString('en-KE', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  return `${currency} ${formatted}`;
}

export function moneyCompact(amountMinor: number, currency = 'KES'): string {
  const value = amountMinor / 100;
  if (value >= 1_000_000) return `${currency} ${(value / 1_000_000).toFixed(2)}M`;
  if (value >= 1_000) return `${currency} ${(value / 1_000).toFixed(1)}K`;
  return `${currency} ${value.toFixed(0)}`;
}

export function when(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleString('en-GB', {
    day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'UTC',
  });
}

export function day(iso: string | null | undefined): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', timeZone: 'UTC' });
}

export function relative(iso: string | null | undefined, from = Date.now()): string {
  if (!iso) return '—';
  const diff = from - new Date(iso).getTime();
  const mins = Math.round(diff / 60_000);
  if (Math.abs(mins) < 60) return mins <= 0 ? `in ${Math.abs(mins)}m` : `${mins}m ago`;
  const hours = Math.round(mins / 60);
  if (Math.abs(hours) < 36) return hours <= 0 ? `in ${Math.abs(hours)}h` : `${hours}h ago`;
  const days = Math.round(hours / 24);
  return days <= 0 ? `in ${Math.abs(days)}d` : `${days}d ago`;
}

export function TabLink({ href, active, children, count }: { href: string; active: boolean; children: React.ReactNode; count?: number }) {
  return (
    <Link href={href} className="tab" data-active={active} style={{ display: 'inline-flex', gap: 7, alignItems: 'center' }}>
      {children}
      {typeof count === 'number' && <span className="nav-count">{count}</span>}
    </Link>
  );
}

export function Initials({ name }: { name: string }) {
  const parts = name.replace(/[^A-Za-z\s]/g, '').trim().split(/\s+/).slice(0, 2);
  const text = parts.map((p) => p[0]).join('').toUpperCase() || '?';
  return (
    <span
      style={{
        display: 'inline-grid', placeItems: 'center', width: 28, height: 28, borderRadius: 8,
        background: 'rgba(94,234,212,0.14)', color: 'var(--accent)', fontWeight: 700, fontSize: 11.5,
      }}
    >
      {text}
    </span>
  );
}
