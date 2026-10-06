import { redirect } from 'next/navigation';
import { getViewer } from '@/lib/auth/session';
import { can } from '@/lib/auth/capabilities';
import { store } from '@/lib/data/store';
import { ActionButton } from '@/components/action-form';
import { Badge, Callout, Card, PageHead, StatusBadge, Table, day, money, relative } from '@/components/ui';

export const dynamic = 'force-dynamic';

const DEMO_NOW = new Date('2026-10-05T09:20:00.000Z').getTime();

export default async function CouponsPage() {
  const viewer = await getViewer();
  if (!viewer) redirect('/admin/login');
  if (!can(viewer.role, 'billing.read')) redirect('/admin');

  const [coupons, subs] = await Promise.all([store().listCoupons(), store().listSubscriptions({ limit: 1000 })]);
  const canManage = can(viewer.role, 'billing.plans.manage');

  const pastDue = subs.filter((s) => ['past_due', 'grace'].includes(s.status));
  const dunningHistory = (await store().listAdminActions({ limit: 500 })).filter((a) => a.action === 'dunning.retry_scheduled');

  return (
    <>
      <PageHead
        title="Coupons & dunning"
        lede="Discount instruments and the arrears ladder. Both are recorded in the ledger, including the commercial reasoning, so a later dispute can be reconstructed."
        actions={<a className="btn sm ghost" href="/admin/billing">← Subscriptions</a>}
      />

      <div className="grid cols-2">
        <Card
          title="Coupons"
          subtitle="Percentage-only discounts. Fixed-amount discounts are deliberately unsupported: they hide effective price changes and are hard to reconcile across currencies."
          actions={canManage ? (
            <ActionButton
              label="Create coupon"
              spec={{
                action: 'coupon_create',
                title: 'Create a coupon',
                intro: <>Codes are case-insensitive and stored uppercase. Redemption counts cap automatically; when the cap is reached the code stops applying without needing revocation.</>,
                fields: [
                  { name: 'code', label: 'Code', type: 'text', required: true, placeholder: 'LSK2026' },
                  { name: 'percentOff', label: 'Percent off', type: 'number', required: true, min: 1, max: 100, defaultValue: 15 },
                  { name: 'maxRedemptions', label: 'Maximum redemptions', type: 'number', required: true, min: 1, defaultValue: 200 },
                  { name: 'expiresAt', label: 'Expires (optional)', type: 'date' },
                ],
                reasonPlaceholder: 'e.g. Law Society conference code; approved as a 15% acquisition discount for Q4.',
                confirmLabel: 'Create coupon',
                intent: 'primary',
              }}
            />
          ) : undefined}
        >
          <Table head={['Code', 'Discount', 'Redemptions', 'Expires', 'State', '']}>
            {coupons.map((c) => (
              <tr key={c.id}>
                <td className="mono">{c.code}</td>
                <td className="nowrap">{c.percentOff}%</td>
                <td className="num">{c.redemptions} / {c.maxRedemptions}</td>
                <td className="tiny nowrap">{c.expiresAt ? day(c.expiresAt) : '—'}</td>
                <td>
                  {!c.active ? <Badge tone="neutral">revoked</Badge>
                    : c.redemptions >= c.maxRedemptions ? <Badge tone="warn">cap reached</Badge>
                    : c.expiresAt && new Date(c.expiresAt).getTime() < DEMO_NOW ? <Badge tone="warn">expired</Badge>
                    : <Badge tone="ok">active</Badge>}
                </td>
                <td className="nowrap">
                  {canManage && c.active && (
                    <ActionButton
                      label="Revoke"
                      spec={{
                        action: 'coupon_revoke',
                        title: `Revoke ${c.code}`,
                        intro: <>Revocation stops new redemptions. Subscriptions already discounted keep their discount until renewal — retroactively repricing a paying customer is not something the console will do silently.</>,
                        hidden: { couponId: c.id },
                        reasonPlaceholder: 'e.g. Campaign closed early after target volume reached.',
                        confirmLabel: 'Revoke coupon',
                        intent: 'danger',
                      }}
                    />
                  )}
                </td>
              </tr>
            ))}
          </Table>
          <div className="callout accent" style={{ marginTop: 12 }}>
            <strong>Coupon abuse controls.</strong> Codes are checked at redemption against cap, expiry and active state,
            and every application is attributed to a subscription row. Codes are not secrets — they are treated as
            pricing instruments, so leaking one is a commercial problem, not a security incident.
          </div>
        </Card>

        <Card
          title="Arrears ladder"
          subtitle="Four cycles, one step each, fully described in the ledger."
          actions={<span className="chip">{pastDue.length} in arrears</span>}
        >
          <Table head={['Cycle', 'Action', 'Customer impact', 'Evidence impact']}>
            <tr>
              <td className="nowrap">1–2</td>
              <td className="tiny">Reminder + retry prompt</td>
              <td className="tiny">None — full access, new stamps still permitted</td>
              <td className="tiny"><Badge tone="ok">none</Badge></td>
            </tr>
            <tr>
              <td className="nowrap">3</td>
              <td className="tiny">Grace period, 7 days</td>
              <td className="tiny">New stamps paused; read, verify and export unaffected</td>
              <td className="tiny"><Badge tone="ok">none</Badge></td>
            </tr>
            <tr>
              <td className="nowrap">4</td>
              <td className="tiny">Capability pause</td>
              <td className="tiny">No new agreements or stamps; all existing records readable and exportable</td>
              <td className="tiny"><Badge tone="ok">none</Badge></td>
            </tr>
            <tr>
              <td className="nowrap">—</td>
              <td className="tiny">Write-off / manual review</td>
              <td className="tiny">Handled commercially outside the console</td>
              <td className="tiny"><Badge tone="ok">none</Badge></td>
            </tr>
          </Table>

          <div className="section-title" style={{ marginTop: 18 }}>
            <h3>Accounts in arrears</h3>
          </div>
          <Table head={['Customer', 'Plan', 'Status', 'Attempts', 'Period ended']} empty="No accounts in arrears.">
            {pastDue.map((s) => (
              <tr key={s.id}>
                <td className="tiny">{s.userEmail}</td>
                <td className="tiny">{s.planName}</td>
                <td><StatusBadge status={s.status} /></td>
                <td className="num">{s.dunningAttempts}/4</td>
                <td className="tiny nowrap">{day(s.currentPeriodEnd)} <span className="tiny">({relative(s.currentPeriodEnd, DEMO_NOW)})</span></td>
              </tr>
            ))}
          </Table>

          <div className="section-title" style={{ marginTop: 18 }}>
            <h3>Recent sweeps</h3>
          </div>
          {dunningHistory.length === 0 ? (
            <p className="sub" style={{ margin: 0 }}>No sweeps recorded in this dataset yet — run one from the Subscriptions screen.</p>
          ) : (
            <Table head={['When', 'Operator', 'Scope', 'Outcome']}>
              {dunningHistory.slice(0, 6).map((a) => {
                const md = a.metadata as { evaluated?: number; reminders?: number; moved_to_grace?: number; paused?: number };
                return (
                  <tr key={a.id}>
                    <td className="tiny nowrap">{day(a.occurredAt)}</td>
                    <td className="tiny">{a.adminEmail}</td>
                    <td className="num">{md.evaluated ?? 0}</td>
                    <td className="tiny">
                      {md.reminders ?? 0} reminder(s) · {md.moved_to_grace ?? 0} to grace · {md.paused ?? 0} paused
                    </td>
                  </tr>
                );
              })}
            </Table>
          )}

          <Callout tone="warn">
            <strong>Deliberate asymmetry.</strong> Collection can pause a capability; it can never revoke a record.
            A stamped agreement that later becomes evidence in a dispute remains readable and exportable even if the
            customer never pays again — that asymmetry is a product commitment, documented here so support does not
            have to invent it under pressure (see also {money(0)} balances, which we never write off automatically).
          </Callout>
        </Card>
      </div>
    </>
  );
}
