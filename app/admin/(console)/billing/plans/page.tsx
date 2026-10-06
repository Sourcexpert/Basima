import { redirect } from 'next/navigation';
import { getViewer } from '@/lib/auth/session';
import { can } from '@/lib/auth/capabilities';
import { store } from '@/lib/data/store';
import { ActionButton } from '@/components/action-form';
import { Badge, Callout, Card, PageHead, Table, day, money, moneyCompact } from '@/components/ui';

export const dynamic = 'force-dynamic';

export default async function PlansPage() {
  const viewer = await getViewer();
  if (!viewer) redirect('/admin/login');
  if (!can(viewer.role, 'billing.read')) redirect('/admin');

  const plans = await store().listPlans(true);
  const canManage = can(viewer.role, 'billing.plans.manage');
  const live = plans.filter((p) => !p.archivedAt);
  const archived = plans.filter((p) => p.archivedAt);

  const totalMrr = plans.reduce((sum, p) => sum + (p.mrrMinor ?? 0), 0);
  const totalSubs = plans.reduce((sum, p) => sum + (p.subscribers ?? 0), 0);

  return (
    <>
      <PageHead
        title="Plans & pricing"
        lede="The commercial catalogue. Every create, edit and archive decision is written to the admin ledger with the before/after price, so a pricing dispute can be reconstructed exactly."
      />

      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        <div className="card tight"><div className="stat-label">Live plans</div><div className="stat-value">{live.length}</div></div>
        <div className="card tight"><div className="stat-label">Archived</div><div className="stat-value" style={{ color: 'var(--muted)' }}>{archived.length}</div></div>
        <div className="card tight"><div className="stat-label">Subscribers</div><div className="stat-value">{totalSubs}</div></div>
        <div className="card tight"><div className="stat-label">MRR contribution</div><div className="stat-value" style={{ color: 'var(--accent)' }}>{moneyCompact(totalMrr)}</div></div>
      </div>

      <Callout tone="warn">
        <strong>Pricing changes do not rewrite history.</strong> Editing a plan changes what <em>new</em> subscribers pay
        and what existing subscribers pay from their next renewal. No existing invoice, payment or subscription row is
        retroactively altered — the ledger keeps the price that was in force when each customer signed.
      </Callout>

      <div className="section-title">
        <h2>Live catalogue</h2>
        <div className="spacer" />
        {canManage && (
          <ActionButton
            label="Create plan"
            size="md"
            spec={{
              action: 'plan_save',
              title: 'Create a plan',
              intro: <>The code is the stable identifier used by subscriptions, invoices and the ledger. Choose it carefully; it cannot be reused for a different meaning later.</>,
              fields: [
                { name: 'code', label: 'Plan code', type: 'text', required: true, placeholder: 'practice_monthly' },
                { name: 'name', label: 'Display name', type: 'text', required: true, placeholder: 'Advocate Practice' },
                { name: 'description', label: 'Description', type: 'text', span: 2 },
                {
                  name: 'interval', label: 'Interval', type: 'select', required: true, defaultValue: 'monthly',
                  options: [{ value: 'monthly', label: 'Monthly' }, { value: 'annual', label: 'Annual' }],
                },
                {
                  name: 'currency', label: 'Currency', type: 'select', required: true, defaultValue: 'KES',
                  options: [{ value: 'KES', label: 'KES — Kenyan shilling' }, { value: 'USD', label: 'USD' }, { value: 'NGN', label: 'NGN' }],
                },
                { name: 'amount', label: 'Amount (major units)', type: 'number', required: true, min: 0, step: '0.01', defaultValue: 4500, help: 'Enter 4500 for KES 4,500. Stored in minor units to avoid float drift.' },
                { name: 'trialDays', label: 'Trial days', type: 'number', min: 0, max: 90, defaultValue: 14 },
                { name: 'includedSeats', label: 'Included seats', type: 'number', min: 1, defaultValue: 1 },
                { name: 'includedStamps', label: 'Included stamps / period', type: 'number', min: 0, defaultValue: 10 },
                { name: 'features', label: 'Features (one per line)', type: 'textarea', span: 2, placeholder: '40 stamps / month\nCounsel workspace\nAudit export' },
                { name: 'active', label: 'Available for new subscriptions', type: 'checkbox', defaultValue: true },
              ],
              reasonPlaceholder: 'e.g. New advocate tier agreed after pricing review; approved by the commercial owner.',
              confirmLabel: 'Create plan',
              intent: 'primary',
            }}
          />
        )}
      </div>

      <Table head={['Plan', 'Price', 'Trial', 'Includes', 'Subscribers', 'MRR', 'State', '']}>
        {plans.map((p) => (
          <tr key={p.id}>
            <td>
              <div style={{ fontWeight: 560 }}>{p.name}</div>
              <div className="tiny mono">{p.code}</div>
              <div className="tiny" style={{ maxWidth: 320 }}>{p.description}</div>
            </td>
            <td className="nowrap">
              {money(p.amountMinor, p.currency)}
              <div className="tiny">per {p.interval === 'monthly' ? 'month' : 'year'}</div>
            </td>
            <td className="tiny nowrap">{p.trialDays ? `${p.trialDays} days` : '—'}</td>
            <td className="tiny">
              {p.includedSeats} seat(s) · {p.includedStamps} stamp(s)
              {p.features.length > 0 && <div className="tiny" style={{ maxWidth: 260 }}>{p.features.slice(0, 3).join(' · ')}{p.features.length > 3 ? ' …' : ''}</div>}
            </td>
            <td className="num">{p.subscribers ?? 0}</td>
            <td className="nowrap">{moneyCompact(p.mrrMinor ?? 0, p.currency)}</td>
            <td>
              {p.archivedAt ? <Badge tone="neutral">archived {day(p.archivedAt)}</Badge> : p.active ? <Badge tone="ok">live</Badge> : <Badge tone="warn">closed to new</Badge>}
            </td>
            <td className="nowrap">
              {canManage ? (
                <>
                  <ActionButton
                    label="Edit"
                    spec={{
                      action: 'plan_save',
                      title: `Edit ${p.name}`,
                      intro: <>Existing subscribers keep the current price until their next renewal, then move to the new price. If you need existing customers to stay put, keep this plan and create a new one instead.</>,
                      fields: [
                        { name: 'code', label: 'Plan code', type: 'text', required: true, defaultValue: p.code, help: 'Immutable in practice — changing it would orphan existing subscriptions.' },
                        { name: 'name', label: 'Display name', type: 'text', required: true, defaultValue: p.name },
                        { name: 'description', label: 'Description', type: 'text', span: 2, defaultValue: p.description },
                        { name: 'interval', label: 'Interval', type: 'select', required: true, defaultValue: p.interval, options: [{ value: 'monthly', label: 'Monthly' }, { value: 'annual', label: 'Annual' }] },
                        { name: 'currency', label: 'Currency', type: 'select', required: true, defaultValue: p.currency, options: [{ value: 'KES', label: 'KES' }, { value: 'USD', label: 'USD' }, { value: 'NGN', label: 'NGN' }] },
                        { name: 'amount', label: 'Amount (major units)', type: 'number', required: true, min: 0, step: '0.01', defaultValue: p.amountMinor / 100 },
                        { name: 'trialDays', label: 'Trial days', type: 'number', min: 0, max: 90, defaultValue: p.trialDays },
                        { name: 'includedSeats', label: 'Included seats', type: 'number', min: 1, defaultValue: p.includedSeats },
                        { name: 'includedStamps', label: 'Included stamps', type: 'number', min: 0, defaultValue: p.includedStamps },
                        { name: 'features', label: 'Features (one per line)', type: 'textarea', span: 2, defaultValue: p.features.join('\n') },
                        { name: 'active', label: 'Available for new subscriptions', type: 'checkbox', defaultValue: p.active },
                      ],
                      reasonPlaceholder: 'e.g. FY2027 price review: KES 4,500 → KES 4,950 to cover increased verification costs.',
                      confirmLabel: 'Save plan',
                    }}
                  />
                  {!p.archivedAt && (
                    <span style={{ marginLeft: 6 }}>
                      <ActionButton
                        label="Archive"
                        spec={{
                          action: 'plan_archive',
                          title: `Archive ${p.name}`,
                          intro: <>Archiving closes the plan to new subscribers. Existing subscribers keep access at their current price — nothing is migrated automatically, so no customer loses evidence access without notice.</>,
                          hidden: { planId: p.id },
                          reasonPlaceholder: 'e.g. Superseded by the Firm tier; retain for the 8 existing subscribers until they migrate voluntarily.',
                          confirmLabel: 'Archive plan',
                          intent: 'danger',
                        }}
                      />
                    </span>
                  )}
                </>
              ) : <span className="tiny">read-only role</span>}
            </td>
          </tr>
        ))}
      </Table>

      {archived.length > 0 && (
        <Card title="Archived plans" subtitle="Kept indefinitely: they are referenced by live subscriptions, invoices and historical ledger entries.">
          <Table head={['Plan', 'Archived', 'Subscribers retained', 'Price held']}>
            {archived.map((p) => (
              <tr key={p.id}>
                <td className="tiny">{p.name}<div className="tiny mono">{p.code}</div></td>
                <td className="tiny nowrap">{day(p.archivedAt)}</td>
                <td className="num">{p.subscribers ?? 0}</td>
                <td className="nowrap">{money(p.amountMinor, p.currency)}</td>
              </tr>
            ))}
          </Table>
        </Card>
      )}
    </>
  );
}
