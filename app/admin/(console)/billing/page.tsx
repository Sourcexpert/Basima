import Link from 'next/link';
import { redirect } from 'next/navigation';
import { getViewer } from '@/lib/auth/session';
import { can } from '@/lib/auth/capabilities';
import { store } from '@/lib/data/store';
import { ActionButton } from '@/components/action-form';
import { FilterBar } from '@/components/action-form';
import { Badge, Callout, Card, PageHead, Stat, StatusBadge, Table, money, moneyCompact, day, relative, when } from '@/components/ui';

export const dynamic = 'force-dynamic';

const DEMO_NOW = new Date('2026-10-05T09:20:00.000Z').getTime();
const STATUSES = ['trialing', 'active', 'past_due', 'grace', 'paused', 'cancelled', 'expired'] as const;

export default async function SubscriptionsPage({
  searchParams,
}: {
  searchParams: Promise<{ q?: string; status?: string }>;
}) {
  const viewer = await getViewer();
  if (!viewer) redirect('/admin/login');
  if (!can(viewer.role, 'billing.read')) redirect('/admin');

  const params = await searchParams;
  const [snapshot, subs, plans] = await Promise.all([
    store().snapshot(),
    store().listSubscriptions({ limit: 1000 }),
    store().listPlans(true),
  ]);

  const rows = subs.filter(
    (s) =>
      (!params.status || s.status === params.status) &&
      (!params.q ||
        [s.userEmail, s.userName, s.planName, s.planCode].join(' ').toLowerCase().includes(params.q.toLowerCase())),
  );

  const canManage = can(viewer.role, 'billing.subscriptions.manage');

  return (
    <>
      <PageHead
        title="Subscriptions"
        lede="Commercial lifecycle: plans, trials, arrears, pauses and cancellations. Payment state and evidentiary state are deliberately separate — nothing on this screen can alter an agreement, a stamp or an audit event."
        actions={
          <>
            {can(viewer.role, 'billing.subscriptions.manage') && (
              <ActionButton
                label="Run dunning sweep"
                size="md"
                spec={{
                  action: 'dunning',
                  title: 'Run the arrears sweep',
                  intro: <>Advances every past-due account one step: reminder (cycles 1–2), grace with 7 days of read/export access but no new stamps (cycle 3), then capability pause (cycle 4). No agreement, stamp, package or audit event is touched at any step.</>,
                  reasonRequired: true,
                  reasonPlaceholder: 'e.g. Scheduled Monday sweep across all past-due accounts; no manual overrides this cycle.',
                  confirmLabel: 'Run sweep',
                }}
              />
            )}
            <Link className="btn sm" href="/admin/billing/plans">Plans &amp; pricing</Link>
            <Link className="btn sm" href="/admin/billing/payments">Payments</Link>
          </>
        }
      />

      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        <Stat label="MRR" value={moneyCompact(snapshot.billing.mrrMinor)} tone="accent" meta={`ARR ${moneyCompact(snapshot.billing.arrMinor)}`} />
        <Stat label="Active subscriptions" value={snapshot.billing.activeSubscriptions} meta={`${snapshot.billing.trialing} trialing`} />
        <Stat label="Past due / grace" value={snapshot.billing.pastDue} tone={snapshot.billing.pastDue ? 'warn' : undefined} meta={`${snapshot.billing.failedPayments7d} failed payment(s) in 7 days`} />
        <Stat label="Collected · 30 days" value={moneyCompact(snapshot.billing.collectedThisMonthMinor)} meta={`Refunded ${moneyCompact(snapshot.billing.refundedThisMonthMinor)}`} />
      </div>

      <Callout tone="accent">
        <strong>How arrears behave.</strong> A customer in arrears keeps read and export access to everything already
        produced, including stamps and evidence packages. Only <em>new</em> value-producing actions (issuing a new stamp)
        are gated, and downgrading or cancelling never withdraws access to records already created under a paid plan.
        That is what makes an evidence product defensible when a billing dispute later becomes a legal dispute.
      </Callout>

      <div className="section-title">
        <h2>Book of business</h2>
        <div className="spacer" />
        <span className="tiny">{rows.length} of {subs.length} shown</span>
      </div>

      <FilterBar
        basePath="/admin/billing"
        values={params}
        filters={[
          { name: 'q', label: 'Search', type: 'text', placeholder: 'customer or plan' },
          { name: 'status', label: 'Status', type: 'select', options: STATUSES.map((s) => ({ value: s, label: s.replace('_', ' ') })) },
        ]}
      />

      <div style={{ marginTop: 14 }}>
        <Table head={['Customer', 'Plan', 'Status', 'Period', 'Amount', 'Rail', 'Dunning', '']} empty="No subscriptions match those filters.">
          {rows.map((s) => (
            <tr key={s.id}>
              <td>
                <div style={{ fontWeight: 560 }}>{s.userName}</div>
                <div className="tiny">{s.userEmail}</div>
              </td>
              <td className="tiny nowrap">
                {s.planName}
                <div className="tiny mono">{s.planCode}</div>
              </td>
              <td>
                <StatusBadge status={s.status} />
                {s.cancelAtPeriodEnd && <div className="tiny" style={{ marginTop: 3 }}>ends {day(s.currentPeriodEnd)}</div>}
                {s.pausedAt && <div className="tiny" style={{ marginTop: 3 }}>paused {relative(s.pausedAt, DEMO_NOW)}</div>}
              </td>
              <td className="tiny nowrap">
                {day(s.currentPeriodStart)} → {day(s.currentPeriodEnd)}
                {s.trialEndsAt && <div className="tiny">trial ends {day(s.trialEndsAt)}</div>}
                {s.graceEndsAt && <div className="tiny" style={{ color: 'var(--warn)' }}>grace until {day(s.graceEndsAt)}</div>}
              </td>
              <td className="nowrap">{money(s.amountMinor, s.currency)}<div className="tiny">{s.seats} seat(s)</div></td>
              <td className="tiny nowrap">{s.provider === 'mpesa' ? 'M-PESA' : 'Flutterwave'}</td>
              <td className="tiny nowrap">
                {s.dunningAttempts ? <Badge tone={s.dunningAttempts >= 3 ? 'danger' : 'warn'}>{s.dunningAttempts}/4</Badge> : <span className="tiny">—</span>}
              </td>
              <td className="nowrap">
                {canManage ? (
                  <ActionButton
                    label="Manage"
                    spec={{
                      action: 'subscription_change',
                      title: `Manage ${s.userName} — ${s.planName}`,
                      intro: <>Changes take effect at the period boundary unless you choose otherwise, so a customer is never surprised mid-cycle. Cancelling keeps every existing record readable and exportable.</>,
                      hidden: { subscriptionId: s.id },
                      fields: [
                        {
                          name: 'mode', label: 'Action', type: 'select', required: true, defaultValue: 'change_plan',
                          options: [
                            { value: 'change_plan', label: 'Change plan' },
                            { value: 'cancel', label: 'Cancel subscription' },
                            { value: 'pause', label: 'Pause (no new stamps)' },
                            { value: 'resume', label: 'Resume to active' },
                            { value: 'extend_trial', label: 'Extend trial' },
                          ],
                        },
                        {
                          name: 'planId', label: 'Target plan (for change / new invoice)', type: 'select', defaultValue: s.planId,
                          options: plans.filter((p) => !p.archivedAt).map((p) => ({ value: p.id, label: `${p.name} — ${money(p.amountMinor, p.currency)} / ${p.interval}` })),
                        },
                        {
                          name: 'effective', label: 'Effective', type: 'select', defaultValue: 'period_end',
                          options: [
                            { value: 'period_end', label: 'At end of current period (recommended)' },
                            { value: 'immediately', label: 'Immediately (prorate)' },
                          ],
                        },
                        { name: 'extendDays', label: 'Trial extension (days)', type: 'number', min: 1, max: 90, defaultValue: 14 },
                      ],
                      reasonPlaceholder: 'e.g. Customer upgraded after onboarding call; agreed to the higher tier starting next cycle.',
                      confirmLabel: 'Apply change',
                      intent: 'primary',
                    }}
                  />
                ) : <span className="tiny">read-only role</span>}
              </td>
            </tr>
          ))}
        </Table>
      </div>

      <div className="grid cols-2" style={{ marginTop: 18 }}>
        <Card title="Plans in catalogue" subtitle="Pricing decisions are versioned in the admin ledger; existing subscribers keep the price they signed at until renewal.">
          <Table head={['Plan', 'Price', 'Interval', 'Subs', 'MRR contribution']}>
            {plans.map((p) => (
              <tr key={p.id}>
                <td className="tiny">
                  <Link href="/admin/billing/plans" style={{ color: 'var(--text)', fontWeight: 560 }}>{p.name}</Link>
                  <div className="tiny mono">{p.code}</div>
                </td>
                <td className="nowrap">{money(p.amountMinor, p.currency)}</td>
                <td className="tiny">{p.interval}</td>
                <td className="num">{p.subscribers ?? 0}</td>
                <td className="nowrap">{moneyCompact(p.mrrMinor ?? 0, p.currency)}</td>
              </tr>
            ))}
          </Table>
        </Card>

        <Card title="Collection rules in force" subtitle="What the console will and will not attempt automatically.">
          <div className="callout">
            <strong>Settlement.</strong> STK pushes and hosted checkouts are never marked paid from a redirect or an
            unverified webhook. Each settlement needs an authentic callback and an independent provider re-query matching
            status, amount, currency and reference.
          </div>
          <div className="callout warn">
            <strong>Manual settlement.</strong> If a rail is unconfigured, the console refuses to fabricate a payment and
            tells the operator to reconcile in the provider dashboard instead. It records who decided that, and why.
          </div>
          <div className="callout ok">
            <strong>Refunds.</strong> Require step-up, a supervisor, a written reason and a settled payment. The ledger
            entry states explicitly that a refund has no evidentiary effect.
          </div>
          <div className="callout accent">
            <strong>Last sweep.</strong> Dunning advances one step per cycle, four cycles maximum, and is fully described
            in the ledger so a customer complaint can be reconstructed months later.
          </div>
        </Card>
      </div>

      <p className="tiny" style={{ marginTop: 14 }}>
        Snapshot generated {when(new Date(DEMO_NOW).toISOString())} UTC. Figures are computed from stored subscription,
        invoice and payment rows on each request — no cached dashboard aggregate.
      </p>
    </>
  );
}
