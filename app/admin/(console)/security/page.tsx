import { redirect } from 'next/navigation';
import { getViewer } from '@/lib/auth/session';
import { can } from '@/lib/auth/capabilities';
import { store } from '@/lib/data/store';
import { Callout, Card, Hash, PageHead, Stat, Table, Badge, relative, when } from '@/components/ui';

export const dynamic = 'force-dynamic';

const DEMO_NOW = new Date('2026-10-05T09:20:00.000Z').getTime();

const SEVERITY_TONE = { info: 'info', notice: 'info', warning: 'warn', critical: 'danger' } as const;

export default async function SecurityPage() {
  const viewer = await getViewer();
  if (!viewer) redirect('/admin/login');
  if (!can(viewer.role, 'audit.security.read')) {
    return (
      <>
        <PageHead title="Security events" lede="Incident register and privileged-access record." />
        <Callout tone="danger">
          Your role (<span className="mono">{viewer.role}</span>) does not hold <span className="mono">audit.security.read</span>.
          Security telemetry can reveal investigative posture, so it is restricted separately from the admin ledger.
        </Callout>
      </>
    );
  }

  const [events, actions, users] = await Promise.all([
    store().listSecurityEvents({ limit: 300 }),
    store().listAdminActions({ limit: 500 }),
    store().listUsers({ limit: 1000 }),
  ]);

  const privilegedReads = actions.filter((a) => a.action === 'agreements.content.read.privileged');
  const breakGlass = actions.filter((a) => a.action === 'password.temp_issued_breakglass');
  const critical = events.filter((e) => e.severity === 'critical');

  return (
    <>
      <PageHead
        title="Security events"
        lede="Telemetry that security owns: authentication abuse, credential operations, privileged access, webhook and callback integrity. Read access is restricted by capability, and reading this screen is itself a logged action."
      />

      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        <Stat label="Critical events" value={critical.length} tone={critical.length ? 'danger' : 'ok'} meta="Open for triage" />
        <Stat label="Privileged agreement reads" value={privilegedReads.length} meta="Last 30 days, all attributed" />
        <Stat label="Break-glass issuances" value={breakGlass.length} meta="Each with a named supervisor" />
        <Stat label="Operators without MFA" value={users.filter((u) => !u.mfaEnabled && ['owner', 'admin', 'support', 'security', 'billing'].includes(u.role) && u.status === 'active').length} tone="warn" meta="Baseline requires MFA for privileged roles" />
      </div>

      <div className="split">
        <div>
          <div className="section-title"><h2>Register</h2></div>
          <Table head={['When', 'Event', 'Severity', 'Detail', 'Source']} empty="No security events.">
            {events.map((e) => (
              <tr key={e.id}>
                <td className="tiny nowrap">
                  {when(e.occurredAt)}
                  <div className="tiny">{relative(e.occurredAt, DEMO_NOW)}</div>
                </td>
                <td className="nowrap mono tiny">{e.type}</td>
                <td><Badge tone={SEVERITY_TONE[e.severity]}>{e.severity}</Badge></td>
                <td className="tiny" style={{ maxWidth: 420 }}>{e.detail}</td>
                <td className="tiny">
                  {e.userId ? users.find((u) => u.id === e.userId)?.email ?? e.userId : 'unattributed'}
                  <div className="tiny"><Hash value={e.ipHash} chars={10} /></div>
                </td>
              </tr>
            ))}
          </Table>

          <Callout tone="accent">
            <strong>IP handling.</strong> The console never stores a raw client address. Events carry a keyed digest so the
            same client can be correlated across attempts without retaining personal data — the <span className="mono">ip_hash</span>{' '}
            column in the evidence ledger exists for the same reason.
          </Callout>
        </div>

        <div>
          <Card title="Privileged agreement access" subtitle="Every instance of the one workflow that crosses the contract-content boundary.">
            {privilegedReads.length === 0 ? (
              <p className="sub" style={{ margin: 0 }}>No privileged accesses recorded.</p>
            ) : (
              <div className="timeline">
                {privilegedReads.map((a) => (
                  <div className={`timeline-item${a.status === 'succeeded' ? ' good' : ' bad'}`} key={a.id}>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                      <strong>{a.targetLabel}</strong>
                      <Badge tone={a.status === 'succeeded' ? 'ok' : 'danger'}>{a.status}</Badge>
                    </div>
                    <div className="sub" style={{ marginTop: 3 }}>{a.reason}</div>
                    <div className="tiny" style={{ marginTop: 3 }}>{a.adminEmail} · {when(a.occurredAt)}</div>
                  </div>
                ))}
              </div>
            )}
            <div className="callout warn" style={{ marginTop: 12 }}>
              <strong>Boundary.</strong> Admin status alone never grants contract reading. The only path is{' '}
              <span className="mono">agreements.content.read.privileged</span>, held by the security role, gated on step-up and a
              written reason, logged here and on the agreement&rsquo;s own evidence trail, and returning an evidence index rather
              than document bytes.
            </div>
          </Card>

          <Card title="Break-glass register" subtitle="Temporary credentials are the highest-risk operation in the console.">
            {breakGlass.length === 0 ? (
              <p className="sub" style={{ margin: 0 }}>No break-glass issuances recorded.</p>
            ) : (
              <Table head={['When', 'Subject', 'Approver', 'TTL']}>
                {breakGlass.map((a) => {
                  const md = a.metadata as { supervisor?: string; ttl_minutes?: number };
                  return (
                    <tr key={a.id}>
                      <td className="tiny nowrap">{when(a.occurredAt)}</td>
                      <td className="tiny">{a.targetLabel}</td>
                      <td className="tiny">{md.supervisor ?? '—'}</td>
                      <td className="tiny nowrap">{md.ttl_minutes ?? '—'} min</td>
                    </tr>
                  );
                })}
              </Table>
            )}
            <div className="callout ok" style={{ marginTop: 12 }}>
              <strong>By construction.</strong> The credential itself is never written to the ledger, never logged and never
              retrievable after the dialog closes — only the fact that one was issued, by whom, for whom, with whose approval,
              for how long, and why.
            </div>
          </Card>
        </div>
      </div>
    </>
  );
}
