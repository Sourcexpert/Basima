import Link from 'next/link';
import { redirect } from 'next/navigation';
import { getViewer } from '@/lib/auth/session';
import { can } from '@/lib/auth/capabilities';
import { store } from '@/lib/data/store';
import { describeVerification, verifyChain } from '@/lib/audit/chain';
import { verifyAdminChain } from '@/lib/audit/admin-chain';
import { ActionButton } from '@/components/action-form';
import { FilterBar } from '@/components/action-form';
import { Badge, Callout, Card, Hash, KV, PageHead, Stat, Table, TabLink, day, relative, when } from '@/components/ui';

export const dynamic = 'force-dynamic';

const DEMO_NOW = new Date('2026-10-05T09:20:00.000Z').getTime();

export default async function AuditPage({
  searchParams,
}: {
  searchParams: Promise<{ tab?: string; q?: string; agreement?: string }>;
}) {
  const viewer = await getViewer();
  if (!viewer) redirect('/admin/login');
  if (!can(viewer.role, 'audit.admin.read')) {
    return (
      <>
        <PageHead title="Audit & evidence" lede="Append-only ledgers." />
        <Callout tone="danger">
          Your role (<span className="mono">{viewer.role}</span>) does not hold <span className="mono">audit.admin.read</span>.
          The admin ledger contains operator behaviour, so it is restricted in both directions: operators are not exempt from
          being recorded, and not every operator may read the record.
        </Callout>
      </>
    );
  }

  const params = await searchParams;
  const tab = params.tab ?? 'evidence';

  const [events, actions, agreements, security] = await Promise.all([
    store().listAuditEvents({ limit: 500 }),
    store().listAdminActions({ limit: 300 }),
    store().listAgreements({ limit: 500 }),
    can(viewer.role, 'audit.security.read') ? store().listSecurityEvents({ limit: 200 }) : Promise.resolve([]),
  ]);

  const agreementIds = Array.from(new Set(events.map((e) => e.agreementId).filter(Boolean))) as string[];
  const chainResults = agreementIds.map((id) => ({
    id,
    agreement: agreements.find((a) => a.id === id),
    result: verifyChain(events.filter((e) => e.agreementId === id)),
  }));
  const failing = chainResults.filter((c) => !c.result.valid);
  const adminChain = verifyAdminChain(actions);

  const selectedId = params.agreement ?? chainResults[0]?.id ?? null;
  const selected = chainResults.find((c) => c.id === selectedId) ?? chainResults[0];
  const selectedEvents = selected ? events.filter((e) => e.agreementId === selected.id) : [];

  const filteredActions = actions.filter(
    (a) => !params.q || [a.action, a.adminEmail, a.targetLabel, a.reason].join(' ').toLowerCase().includes(params.q.toLowerCase()),
  );

  return (
    <>
      <PageHead
        title="Audit & evidence"
        lede="Two separate append-only ledgers. The evidence ledger records what happened to an agreement; the admin ledger records what operators did. They are never mixed, because an operational action must not appear inside an agreement's evidence timeline."
      />

      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        <Stat label="Evidence events" value={events.length} meta={`across ${agreementIds.length} agreement chain(s)`} />
        <Stat label="Chains verified" value={chainResults.length - failing.length} tone="ok" meta={`${failing.length} failing`} />
        <Stat label="Admin actions" value={actions.length} tone={adminChain.valid ? 'ok' : 'danger'} meta={adminChain.valid ? 'ledger intact' : 'LEDGER MISMATCH'} />
        <Stat label="Security events" value={security.length || '—'} meta={can(viewer.role, 'audit.security.read') ? `${security.filter((s) => s.severity === 'critical').length} critical` : 'not in your role'} />
      </div>

      <div className="tabs">
        <TabLink href="/admin/audit?tab=evidence" active={tab === 'evidence'}>Evidence ledger</TabLink>
        <TabLink href="/admin/audit?tab=verify" active={tab === 'verify'}>Verify chain</TabLink>
        <TabLink href="/admin/audit?tab=admin" active={tab === 'admin'} count={actions.length}>Admin ledger</TabLink>
        <TabLink href="/admin/audit?tab=agreements" active={tab === 'agreements'}>Agreement index</TabLink>
      </div>

      {tab === 'evidence' && (
        <>
          <Callout tone="accent">
            <strong>How to read this ledger.</strong> Each event commits to the previous event&rsquo;s hash. Changing anything
            about an earlier canonical event — a timestamp, an actor, a metadata field — breaks every link after it, which is
            why this is described as <em>tamper-evident</em> and never as tamper-proof or blockchain-based. Hashing and
            timestamping happen server-side and, in production, inside a database function so no application code path can
            write an unchained row.
          </Callout>

          <div className="section-title"><h2>Chains</h2></div>
          <Table head={['Agreement', 'Events', 'Root → head', 'Verification', '']} empty="No evidence events on record.">
            {chainResults.map((c) => (
              <tr key={c.id}>
                <td>
                  <div style={{ fontWeight: 560 }}>{c.agreement?.ref ?? c.id}</div>
                  <div className="tiny">{c.agreement?.title ?? '—'}</div>
                </td>
                <td className="num">{c.result.checkedEvents}</td>
                <td className="tiny">
                  <Hash value={c.result.root} chars={14} /> → <Hash value={c.result.head} chars={14} />
                </td>
                <td>
                  {c.result.valid
                    ? <Badge tone="ok">verified</Badge>
                    : <Badge tone="danger">failed at event {c.result.firstFailure?.index}</Badge>}
                </td>
                <td className="nowrap"><Link className="btn sm" href={`/admin/audit?tab=verify&agreement=${c.id}`}>Inspect</Link></td>
              </tr>
            ))}
          </Table>

          <div className="section-title"><h2>Latest events</h2></div>
          <Table head={['When', 'Event', 'Agreement', 'Actor', 'Metadata', 'Hash']}>
            {[...events].reverse().slice(0, 25).map((e) => (
              <tr key={e.id}>
                <td className="tiny nowrap">{when(e.occurredAt)}</td>
                <td className="nowrap"><span className="mono tiny">{e.eventType}</span></td>
                <td className="tiny">{agreements.find((a) => a.id === e.agreementId)?.ref ?? '—'}</td>
                <td className="tiny">{e.actorId ?? <span className="tiny">system</span>}</td>
                <td className="tiny" style={{ maxWidth: 320 }}>
                  <span className="mono" style={{ fontSize: 11 }}>{JSON.stringify(e.metadata).slice(0, 110)}{JSON.stringify(e.metadata).length > 110 ? '…' : ''}</span>
                </td>
                <td><Hash value={e.eventHash} chars={12} /></td>
              </tr>
            ))}
          </Table>
        </>
      )}

      {tab === 'verify' && selected && (
        <div className="split">
          <div>
            <Card
              title={`Verification — ${selected.agreement?.ref ?? selected.id}`}
              subtitle={`${selected.agreement?.title ?? ''} · ${selected.result.checkedEvents} event(s) recomputed from stored rows`}
              actions={
                <ActionButton
                  label="Run privileged access"
                  spec={{
                    action: 'privileged_read',
                    title: 'Privileged agreement access',
                    intro: <>Reading agreement content is not a right of admin status. This workflow is limited to the security role, requires a fresh step-up, demands a written reason, and is recorded against the agreement&rsquo;s own evidence trail as well as the admin ledger. Even then, the console returns the evidence index — not document bytes.</>,
                    hidden: { agreementId: selected.id, agreementRef: selected.agreement?.ref ?? selected.id },
                    stepUpHint: true,
                    reasonPlaceholder: 'e.g. Security incident triage on this agreement; counsel approved access. Ticket SEC-2291.',
                    confirmLabel: 'Record access and continue',
                    intent: 'danger',
                  }}
                  disabled={!can(viewer.role, 'agreements.content.read.privileged')}
                  disabledReason="Only the security role holds agreements.content.read.privileged."
                />
              }
            >
              <div className={`callout ${selected.result.valid ? 'ok' : 'danger'}`}>
                {selected.result.valid ? (
                  <ul style={{ margin: 0, paddingLeft: 18 }}>
                    {describeVerification(selected.result).map((line, i) => <li key={i}>{line}</li>)}
                  </ul>
                ) : (
                  <>
                    <strong>Verification failed.</strong> {selected.result.firstFailure?.detail}
                    <div style={{ marginTop: 6 }}>
                      Legal treatment is determined by the applicable process or court, not by this screen. Escalate to the
                      security owner and to counsel before this record is relied upon.
                    </div>
                  </>
                )}
              </div>

              <div className="section-title"><h2>Link-by-link checks</h2></div>
              <Table head={['#', 'Event', 'previous_hash → event_hash', 'Check']}>
                {selectedEvents.map((e, i) => {
                  const check = selected.result.checks[i];
                  return (
                    <tr key={e.id}>
                      <td className="num">{i + 1}</td>
                      <td className="tiny nowrap"><span className="mono">{e.eventType}</span><div className="tiny">{when(e.occurredAt)}</div></td>
                      <td className="tiny">
                        <Hash value={e.previousHash ?? 'GENESIS'} chars={12} /> → <Hash value={e.eventHash} chars={12} />
                      </td>
                      <td>
                        {check?.ok
                          ? <Badge tone="ok">link verified</Badge>
                          : <Badge tone="danger">{check?.reason ?? 'not reached'}</Badge>}
                        {check && !check.ok && <div className="tiny" style={{ marginTop: 3, maxWidth: 300 }}>{check.detail}</div>}
                      </td>
                    </tr>
                  );
                })}
              </Table>

              <Callout tone="warn">
                <strong>What this verification does and does not claim.</strong> It proves the stored events recompute to
                their recorded digests and that the links are unbroken. It says nothing about identity, consent or legal
                effect on its own, and the certificate workspace exists precisely so a lawyer assesses those separately.
              </Callout>
            </Card>
          </div>

          <div>
            <Card title="Chain facts">
              <KV
                rows={[
                  ['Agreement', selected.agreement?.ref ?? selected.id],
                  ['Status', selected.agreement?.status ?? '—'],
                  ['Current version', `v${selected.agreement?.currentVersion ?? '—'}`],
                  ['Document SHA-256', <Hash key="h" value={selected.agreement?.documentHash ?? null} chars={26} />],
                  ['Chain root', <Hash key="r" value={selected.result.root} chars={26} />],
                  ['Chain head', <Hash key="hd" value={selected.result.head} chars={26} />],
                  ['Events checked', String(selected.result.checkedEvents)],
                  ['Stamp issued', selected.agreement?.stampIssuedAt ? when(selected.agreement.stampIssuedAt) : 'not stamped'],
                ]}
              />
              <div className="callout danger" style={{ marginTop: 12 }}>
                <strong>The ledger is append-only.</strong> There is no console control anywhere in this product that edits,
                redacts or deletes an evidence event. Amendments create new versions and new events; an executed version is
                frozen.
              </div>
            </Card>

            <Card title="Select a chain">
              <Table head={['Agreement', 'State', '']}>
                {chainResults.map((c) => (
                  <tr key={c.id}>
                    <td className="tiny">{c.agreement?.ref ?? c.id}<div className="tiny">{c.agreement?.title?.slice(0, 46)}</div></td>
                    <td>{c.result.valid ? <Badge tone="ok">ok</Badge> : <Badge tone="danger">failed</Badge>}</td>
                    <td className="nowrap"><Link className="btn sm ghost" href={`/admin/audit?tab=verify&agreement=${c.id}`}>Open</Link></td>
                  </tr>
                ))}
              </Table>
            </Card>
          </div>
        </div>
      )}

      {tab === 'admin' && (
        <>
          <div className={`callout ${adminChain.valid ? 'ok' : 'danger'}`}>
            <strong>Admin ledger:</strong> {adminChain.valid
              ? `${actions.length} operator actions verified. Each action commits to the previous action's hash, so removing or altering one is detectable.`
              : adminChain.detail}
          </div>

          <div className="section-title">
            <h2>Operator actions</h2>
            <div className="spacer" />
          </div>

          <FilterBar basePath="/admin/audit" values={params} filters={[{ name: 'q', label: 'Search', type: 'text', placeholder: 'action, operator, target, reason' }]} />
          <input type="hidden" name="tab" value="admin" />

          <div style={{ marginTop: 14 }}>
            <Table head={['When', 'Operator', 'Action', 'Target', 'Justification', 'State', 'Chain']} empty="No operator actions match.">
              {filteredActions.map((a) => (
                <tr key={a.id}>
                  <td className="tiny nowrap">{when(a.occurredAt)}<div className="tiny">{relative(a.occurredAt, DEMO_NOW)}</div></td>
                  <td className="tiny">
                    {a.adminEmail}
                    <div className="tiny"><span className="chip">{a.adminRole}</span></div>
                  </td>
                  <td className="nowrap">
                    <span className="mono tiny">{a.action}</span>
                    {a.stepUp && <div className="tiny">step-up verified</div>}
                  </td>
                  <td className="tiny" style={{ maxWidth: 210 }}>{a.targetLabel}</td>
                  <td className="tiny" style={{ maxWidth: 340 }}>{a.reason}</td>
                  <td><Badge tone={a.status === 'succeeded' ? 'ok' : a.status === 'blocked' ? 'danger' : 'warn'}>{a.status}</Badge></td>
                  <td className="tiny"><Hash value={a.eventHash} chars={10} /></td>
                </tr>
              ))}
            </Table>
          </div>

          <Callout tone="accent">
            <strong>Refusals are recorded too.</strong> When an operator attempts something their role does not hold, the
            attempt is appended with status <span className="mono">blocked</span>. Probing the console therefore leaves a
            trail, which is the point of running the console as a separate trust boundary.
          </Callout>
        </>
      )}

      {tab === 'agreements' && (
        <>
          <Callout tone="warn">
            <strong>Metadata only.</strong> This index carries no contract text, no party identity material and no document
            bytes. It exists so operations can answer &ldquo;is this record intact, and who touched it?&rdquo; without granting
            anyone the ability to read what two parties agreed.
          </Callout>
          <div className="section-title"><h2>Agreement index</h2></div>
          <Table head={['Reference', 'Title', 'Type', 'Owner', 'State', 'Version', 'Document SHA-256', 'Stamp']}>
            {agreements.map((a) => (
              <tr key={a.id}>
                <td className="mono tiny">{a.ref}</td>
                <td className="tiny" style={{ maxWidth: 300 }}>{a.title}</td>
                <td className="tiny nowrap">{a.agreementType}</td>
                <td className="tiny">{a.ownerEmail}</td>
                <td className="tiny"><Badge tone={a.status === 'completed' ? 'ok' : a.status === 'revoked' ? 'danger' : 'warn'}>{a.status.replace(/_/g, ' ')}</Badge></td>
                <td className="num">v{a.currentVersion}</td>
                <td><Hash value={a.documentHash} chars={16} /></td>
                <td className="tiny nowrap">{a.stampIssuedAt ? day(a.stampIssuedAt) : '—'}</td>
              </tr>
            ))}
          </Table>
        </>
      )}
    </>
  );
}
