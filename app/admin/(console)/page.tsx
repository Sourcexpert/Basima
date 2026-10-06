import Link from 'next/link';
import { getViewer, authMode } from '@/lib/auth/session';
import { can } from '@/lib/auth/rbac';
import { store } from '@/lib/data/store';
import { verifyChain } from '@/lib/audit/chain';
import { verifyAdminChain } from '@/lib/audit/admin-chain';
import { DEMO_TAMPERED_AGREEMENT } from '@/lib/data/demo-db';
import { Badge, Callout, Card, Hash, KV, PageHead, StatusBadge, Stat, Table, money, moneyCompact, relative, when } from '@/components/ui';

export const dynamic = 'force-dynamic';

const DEMO_NOW = new Date('2026-10-05T09:20:00.000Z').getTime();

export default async function OverviewPage() {
  const viewer = await getViewer();
  if (!viewer) return null;

  const [snapshot, allAudit, adminActions, security] = await Promise.all([
    store().snapshot(),
    store().listAuditEvents({ limit: 400 }),
    store().listAdminActions({ limit: 200 }),
    can(viewer.role, 'audit.security.read') ? store().listSecurityEvents({ limit: 100 }) : Promise.resolve([]),
  ]);

  const adminChain = verifyAdminChain(adminActions);
  const chains = Array.from(new Set(allAudit.map((e) => e.agreementId).filter(Boolean))) as string[];
  const chainResults = chains.map((id) => ({
    id,
    result: verifyChain(allAudit.filter((e) => e.agreementId === id)),
  }));
  const broken = chainResults.filter((c) => !c.result.valid);

  const alerts: Array<{ tone: 'danger' | 'warn' | 'info'; title: string; detail: React.ReactNode; href?: string }> = [];

  if (snapshot.users.privilegedWithoutMfa > 0) {
    alerts.push({
      tone: 'danger',
      title: `${snapshot.users.privilegedWithoutMfa} privileged operator account(s) without MFA`,
      detail: <>The security baseline requires MFA for admin and counsel roles. Require enrolment from <Link href="/admin/users?role=support" style={{ color: 'var(--accent)' }}>Users &amp; access</Link>, or remove the role.</>,
    });
  }
  if (broken.length > 0) {
    alerts.push({
      tone: 'danger',
      title: `${broken.length} evidence chain(s) fail verification`,
      detail: <>At least one agreement&rsquo;s append-only ledger no longer recomputes to its recorded digests. Open <Link href="/admin/audit" style={{ color: 'var(--accent)' }}>Audit &amp; evidence</Link> to see the exact failing link before anyone treats that record as intact.</>,
    });
  }
  if (!snapshot.paymentHealth.mpesaConfigured) {
    alerts.push({
      tone: 'warn',
      title: 'M-PESA Daraja credentials are not configured',
      detail: <>STK push will return <span className="mono">not_configured</span> rather than pretending to charge. Add the Daraja keys to enable mobile-money collection.</>,
    });
  }
  if (!snapshot.paymentHealth.flutterwaveConfigured) {
    alerts.push({
      tone: 'warn',
      title: 'Flutterwave keys are not configured',
      detail: <>Card, bank transfer and USSD collection stay disabled until <span className="mono">FLW_SECRET_KEY</span> and <span className="mono">FLW_SECRET_HASH</span> are present. The webhook rejects unsigned traffic either way.</>,
    });
  }
  if (snapshot.billing.pastDue > 0) {
    alerts.push({
      tone: 'info',
      title: `${snapshot.billing.pastDue} subscription(s) past due or in grace`,
      detail: <>Arrears gate new value-producing actions only. Evidence already produced stays readable and exportable — payment state never touches the evidence ledger.</>,
    });
  }

  return (
    <>
      <PageHead
        title="Overview"
        lede={`Operational, commercial and security posture at a glance. Reference time ${when(new Date(DEMO_NOW).toISOString())} UTC${authMode === 'demo' ? ' · demo dataset' : ''}.`}
        actions={
          <>
            <Link className="btn sm" href="/admin/users">Users &amp; access</Link>
            <Link className="btn sm" href="/admin/billing">Subscriptions</Link>
            <Link className="btn sm primary" href="/admin/audit">Verify a chain</Link>
          </>
        }
      />

      {alerts.length > 0 && (
        <div className="grid" style={{ marginBottom: 18 }}>
          {alerts.map((a, i) => (
            <Callout key={i} tone={a.tone === 'warn' ? 'warn' : a.tone === 'danger' ? 'danger' : 'info'}>
              <strong>{a.title}.</strong> {a.detail}
            </Callout>
          ))}
        </div>
      )}

      <div className="grid cols-4">
        <Stat
          label="Unique accounts"
          value={snapshot.users.total}
          meta={<>{snapshot.users.active} active · {snapshot.users.pendingInvites} invited · {snapshot.users.locked} locked</>}
        />
        <Stat
          label="MRR (running)"
          value={moneyCompact(snapshot.billing.mrrMinor)}
          meta={<>ARR {moneyCompact(snapshot.billing.arrMinor)} · {snapshot.billing.activeSubscriptions} paying</>}
          tone="accent"
        />
        <Stat
          label="Collected · 30 days"
          value={moneyCompact(snapshot.billing.collectedThisMonthMinor)}
          meta={<>{snapshot.billing.failedPayments7d} failed payment(s) in 7 days · refunded {moneyCompact(snapshot.billing.refundedThisMonthMinor)}</>}
        />
        <Stat
          label="Stamps issued · 30 days"
          value={snapshot.evidence.stampsIssued30d}
          meta={<>{snapshot.evidence.completed} of {snapshot.evidence.agreementsTotal} agreements completed</>}
        />
      </div>

      <div className="split" style={{ marginTop: 16 }}>
        <div>
          <Card
            title="Payment collection health"
            subtitle="Collection is verified twice: signed callback/webhook, then an independent provider re-query before anything is settled."
          >
            <Table
              head={['Rail', 'Status', 'Coverage', 'Observation']}
              empty="No payment rails configured."
            >
              <tr>
                <td className="nowrap"><strong>M-PESA (Daraja)</strong><div className="tiny">Lipa na M-PESA STK push · C2B</div></td>
                <td><Badge tone={snapshot.paymentHealth.mpesaConfigured ? 'ok' : 'warn'}>{snapshot.paymentHealth.mpesaConfigured ? 'configured' : 'not configured'}</Badge></td>
                <td className="tiny nowrap">KEN &middot; KES</td>
                <td className="tiny">
                  {snapshot.paymentHealth.lastStkPushAt ? `Last prompt ${relative(snapshot.paymentHealth.lastStkPushAt, DEMO_NOW)}. ` : ''}
                  {snapshot.paymentHealth.stkSuccessRate !== null
                    ? `Completion rate ${(snapshot.paymentHealth.stkSuccessRate * 100).toFixed(0)}% (failures are mostly customer-cancelled, code 1032).`
                    : 'No prompts issued yet.'}
                </td>
              </tr>
              <tr>
                <td className="nowrap"><strong>Flutterwave</strong><div className="tiny">Card · bank transfer · USSD · mobile money</div></td>
                <td><Badge tone={snapshot.paymentHealth.flutterwaveConfigured ? 'ok' : 'warn'}>{snapshot.paymentHealth.flutterwaveConfigured ? 'configured' : 'not configured'}</Badge></td>
                <td className="tiny nowrap">Multi-currency</td>
                <td className="tiny">
                  Webhook signature required (<span className="mono">verif-hash</span>); unsigned POSTs are discarded and logged.
                  {snapshot.paymentHealth.webhookLastReceivedAt ? ` Last signed event ${relative(snapshot.paymentHealth.webhookLastReceivedAt, DEMO_NOW)}.` : ''}
                </td>
              </tr>
            </Table>
            <div className="callout" style={{ marginTop: 12 }}>
              <strong>Settlement rule.</strong> A payment is only marked settled when (1) the callback or webhook is
              authentic, (2) it matches a transaction we initiated, and (3) a server-side re-query confirms status,
              amount, currency and reference. The redirect URL a customer returns with is never trusted.
            </div>
          </Card>

          <div className="section-title">
            <h2>Recent privileged activity</h2>
            <div className="spacer" />
            <Link className="btn sm ghost" href="/admin/audit">Open ledger</Link>
          </div>
          <Card tight>
            <div className="timeline">
              {snapshot.recentAdminActions.map((a) => (
                <div className="timeline-item" key={a.id}>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                    <strong>{a.action.replace(/_/g, ' ')}</strong>
                    <Badge tone={a.status === 'succeeded' ? 'ok' : a.status === 'blocked' ? 'danger' : 'warn'}>{a.status}</Badge>
                    {a.stepUp && <span className="chip">step-up</span>}
                    <span className="tiny">{when(a.occurredAt)} · {a.adminEmail} ({a.adminRole})</span>
                  </div>
                  <div className="sub" style={{ marginTop: 3 }}>{a.targetLabel} — {a.reason}</div>
                  <div className="tiny" style={{ marginTop: 3 }}>chain {a.previousHash ? <Hash value={a.previousHash} chars={10} /> : 'GENESIS'} → <Hash value={a.eventHash} chars={12} /></div>
                </div>
              ))}
            </div>
            <div className="callout ok" style={{ marginTop: 10 }}>
              <strong>Admin ledger integrity:</strong>{' '}
              {adminChain.valid ? `${adminActions.length} actions verified — every action commits to the previous action's hash.` : adminChain.detail}
            </div>
          </Card>
        </div>

        <div>
          <Card title="Security posture" subtitle="Support, security and admin boundaries as currently configured.">
            <KV
              rows={[
                ['Privileged accounts', `${snapshot.users.privilegedWithoutMfa} without MFA of ${snapshot.users.total - 2} operators`],
                ['Failed admin sign-ins (24h)', String(snapshot.security.failedAdminSignins24h)],
                ['Privileged agreement access (30d)', String(snapshot.security.privilegedAccesses30d)],
                ['Critical security events', <Badge key="c" tone={snapshot.security.openIncidents ? 'danger' : 'ok'}>{snapshot.security.openIncidents} open</Badge>],
                ['Evidence events (24h)', String(snapshot.security.auditEvents24h)],
                ['Session policy', 'absolute 12h · step-up 15 min'],
                ['Password policy', 'no operator may read or set a plaintext password'],
              ]}
            />
            {!can(viewer.role, 'audit.security.read') && (
              <div className="callout warn" style={{ marginTop: 12 }}>
                Your role ({viewer.role}) does not hold <span className="mono">audit.security.read</span>, so the
                security-event register is hidden here and blocked at the server if requested directly.
              </div>
            )}
          </Card>

          <Card
            title="Evidence chain monitor"
            subtitle="Recomputed from stored events, never from a cached summary."
            className=""
          >
            <div className="grid cols-2" style={{ gap: 10 }}>
              <div className="card tight">
                <div className="stat-label">Chains verified</div>
                <div className="stat-value" style={{ color: 'var(--ok)' }}>{chainResults.length - broken.length}</div>
              </div>
              <div className="card tight">
                <div className="stat-label">Chains failing</div>
                <div className="stat-value" style={{ color: broken.length ? 'var(--danger)' : 'var(--muted)' }}>{broken.length}</div>
              </div>
            </div>
            {broken.map((b) => (
              <div className="callout danger" key={b.id} style={{ marginTop: 10 }}>
                <strong>{b.id}</strong> — {b.result.firstFailure?.detail}
                {authMode === 'demo' && b.id === DEMO_TAMPERED_AGREEMENT && (
                  <div className="tiny" style={{ marginTop: 4 }}>
                    Seeded example: a verification-detail field was altered after hashing, exactly the case the guide
                    asks you to test before production.
                  </div>
                )}
              </div>
            ))}
            <div style={{ marginTop: 12 }}>
              <Link className="btn sm" href="/admin/audit">Open verify-chain workspace</Link>
            </div>
          </Card>

          <Card title="Billing posture">
            <KV
              rows={[
                ['Active', String(snapshot.billing.activeSubscriptions)],
                ['Trialing', String(snapshot.billing.trialing)],
                ['Past due / grace', <StatusBadge key="s" status={snapshot.billing.pastDue ? 'past_due' : 'active'} />],
                ['Cancelled · 30d', String(snapshot.billing.cancelledThisMonth)],
                ['Collected · 30d', money(snapshot.billing.collectedThisMonthMinor)],
              ]}
            />
            <div className="callout accent" style={{ marginTop: 12 }}>
              <strong>Commercial vs evidentiary.</strong> Billing state can pause new stamps, but it can never
              delete, amend or hide an agreement, a stamp, an evidence package or an audit event. That separation is
              a product guarantee, not a setting.
            </div>
          </Card>

          {can(viewer.role, 'audit.security.read') && security.length > 0 && (
            <Card title="Latest security events">
              <div className="timeline">
                {security.slice(0, 5).map((s) => (
                  <div className={`timeline-item${s.severity === 'critical' ? ' bad' : ''}`} key={s.id}>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                      <strong>{s.type.replace(/_/g, ' ')}</strong>
                      <Badge tone={s.severity === 'critical' ? 'danger' : s.severity === 'warning' ? 'warn' : 'info'}>{s.severity}</Badge>
                    </div>
                    <div className="sub" style={{ marginTop: 3 }}>{s.detail}</div>
                  </div>
                ))}
              </div>
              <div style={{ marginTop: 10 }}>
                <Link className="btn sm ghost" href="/admin/security">Security register</Link>
              </div>
            </Card>
          )}
        </div>
      </div>
    </>
  );
}
