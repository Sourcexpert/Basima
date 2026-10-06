import Link from 'next/link';
import { notFound, redirect } from 'next/navigation';
import { getUserViewer } from '@/lib/auth/user-auth';
import { userStore } from '@/lib/data/user-store';
import { accessLevel, canPerform, evaluateCompletion, requiredParties } from '@/lib/auth/user-access';
import { verifyChain, describeVerification } from '@/lib/audit/chain';
import { UserActionButton } from '@/components/user-action-form';
import {
  Badge, Callout, Card, Hash, KV, PageHead, StatusBadge, Table, TabLink, day, when, relative,
} from '@/components/ui';

export const dynamic = 'force-dynamic';

const DEMO_NOW = new Date('2026-10-05T09:20:00.000Z').getTime();

const EVENT_LABELS: Record<string, string> = {
  'agreement.created': 'Agreement created',
  'agreement.version_created': 'New version written',
  'agreement.party_invited': 'Party invited',
  'agreement.completion_evaluated': 'Completion evaluated',
  'agreement.revoked': 'Agreement revoked',
  'party.identity_verified': 'Party identity verified',
  'party.consent_recorded': 'Consent recorded',
  'party.signed': 'Party signed',
  'party.signature_refused': 'Signature refused (blocked)',
  'integrity.check_failed': 'Integrity check failed (signing blocked)',
  'stamp.issued': 'Stamp issued — version frozen',
  'evidence.package_generated': 'Evidence package generated',
};

export default async function AgreementPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ tab?: string; v?: string }>;
}) {
  const viewer = await getUserViewer();
  if (!viewer) redirect('/app/login');

  const { id } = await params;
  const sp = await searchParams;
  const s = await userStore();

  const agreement = await s.getAgreementSummary(id);
  if (!agreement) notFound();

  const [parties, signatureEvents, documents, events, consents, requests, packages] = await Promise.all([
    s.listParties(id),
    s.listSignatureEvents(id),
    s.listDocuments(id),
    s.listAuditEvents({ agreementId: id, limit: 1000 }),
    s.listConsents(id),
    s.listSignatureRequests(id),
    s.listPackages(id),
  ]);

  const subjBase = { agreement, parties, signatureEvents, viewerEmail: viewer.email };
  const access = accessLevel(viewer.userId, subjBase);

  // Deny by default: a signed-in stranger gets nothing, not an empty screen.
  if (access.level === 'none') {
    return (
      <>
        <PageHead title="Not available" lede="This agreement is not shared with your account." />
        <Callout tone="danger">
          You are not the owner or an invited party on this agreement. If you were expecting an invitation, ask the
          owner to check the email address they used — invitations are tied to a specific address and cannot be
          transferred by forwarding a link.
        </Callout>
        <div style={{ marginTop: 14 }}><Link className="btn sm" href="/app/agreements">← My agreements</Link></div>
      </>
    );
  }

  const current = documents.find((d) => d.versionNumber === agreement.currentVersion) ?? documents[documents.length - 1] ?? null;
  const viewing = (sp.v ? documents.find((d) => d.id === sp.v) : null) ?? current;
  const tab = sp.tab ?? 'document';

  const completion = current ? evaluateCompletion(parties, signatureEvents, current.id) : null;
  const myParty = access.party;
  const signDecision = canPerform(viewer.userId, { ...subjBase, version: current, currentVersion: current }, 'sign');
  const editDecision = canPerform(viewer.userId, subjBase, 'edit');
  const inviteDecision = canPerform(viewer.userId, subjBase, 'invite');
  const revokeDecision = canPerform(viewer.userId, subjBase, 'revoke');
  const exportDecision = canPerform(viewer.userId, subjBase, 'export');
  const acceptDecision = myParty?.status === 'invited';
  const alreadySigned = myParty && current
    ? signatureEvents.some((e) => e.partyId === myParty.id && e.versionId === current.id && e.outcome === 'signed')
    : false;

  const chain = verifyChain(events);
  const frozen = documents.filter((d) => d.frozenAt);
  const isOwner = agreement.ownerId === viewer.userId;

  return (
    <>
      <PageHead
        title={agreement.title}
        lede={
          <span>
            <span className="mono">{agreement.ref}</span> · {agreement.agreementType} · created {when(agreement.createdAt)}
            {agreement.stampIssuedAt ? ` · stamped ${day(agreement.stampIssuedAt)}` : ''}
          </span>
        }
        actions={
          <>
            <Link className="btn sm ghost" href="/app/agreements">← All agreements</Link>
            {signDecision.allowed && !alreadySigned && (
              <Link className="btn sm primary" href={`/app/agreements/${id}/sign`}>Review &amp; sign</Link>
            )}
          </>
        }
      />

      <div style={{ display: 'flex', gap: 7, flexWrap: 'wrap', marginBottom: 14 }}>
        <StatusBadge status={agreement.status} />
        {isOwner ? <Badge tone="accent">you own this</Badge> : myParty ? <Badge tone="info">you are {myParty.partyRole}</Badge> : null}
        {myParty?.signingRequired && !alreadySigned && agreement.status !== 'completed' && <Badge tone="warn">your signature is required</Badge>}
        {alreadySigned && <Badge tone="ok">you have signed</Badge>}
        {agreement.status === 'completed' && <Badge tone="ok">frozen &amp; stamped</Badge>}
        {agreement.status === 'revoked' && <Badge tone="danger">revoked</Badge>}
      </div>

      {acceptDecision && (
        <Callout tone="warn">
          <strong>You have been invited to this agreement.</strong> Accepting records that you received the invitation and
          confirmed your email. It does <em>not</em> sign anything — you will review the document and sign separately.
          <div style={{ marginTop: 10 }}>
            <UserActionButton
              label="Accept invitation"
              variant="primary"
              spec={{
                action: 'accept_invitation',
                title: 'Accept the invitation',
                hidden: { agreementId: id },
                intro: <>This records an <span className="mono">invitation accepted</span> and an identity-verification event at
                  the level actually performed (verified email). It does not create a signature and does not bind you to anything.</>,
                confirmLabel: 'Accept invitation',
                disclaimer: <div className="callout"><strong>Next step after this:</strong> read the document carefully. Nothing is final until you sign a specific version.</div>,
              }}
            />
          </div>
        </Callout>
      )}

      {signDecision.allowed && !alreadySigned && (
        <Callout tone="accent">
          <strong>Your signature is needed on version {current?.versionNumber}.</strong> Read it, then sign the exact
          version shown — the signature is bound to that text and its hash, not to &ldquo;the agreement&rdquo; in general.
          <div style={{ marginTop: 10 }}>
            <Link className="btn primary" href={`/app/agreements/${id}/sign`}>Review &amp; sign version {current?.versionNumber}</Link>
          </div>
        </Callout>
      )}

      {!signDecision.allowed && myParty?.signingRequired && !alreadySigned && signDecision.reason && (
        <Callout tone="warn"><strong>You cannot sign yet.</strong> {signDecision.reason}</Callout>
      )}

      <div className="tabs">
        <TabLink href={`/app/agreements/${id}?tab=document`} active={tab === 'document'}>Document</TabLink>
        <TabLink href={`/app/agreements/${id}?tab=parties`} active={tab === 'parties'} count={parties.length}>Parties</TabLink>
        <TabLink href={`/app/agreements/${id}?tab=timeline`} active={tab === 'timeline'} count={events.length}>Evidence timeline</TabLink>
        <TabLink href={`/app/agreements/${id}?tab=versions`} active={tab === 'versions'} count={documents.length}>Versions</TabLink>
        <TabLink href={`/app/agreements/${id}?tab=integrity`} active={tab === 'integrity'}>Integrity</TabLink>
      </div>

      <div className="split">
        <div>
          {tab === 'document' && viewing && (
            <Card
              title={`Version ${viewing.versionNumber}${viewing.frozenAt ? ' — frozen' : ''}`}
              subtitle={
                <>
                  SHA-256 <Hash value={viewing.sha256} chars={32} /> · {viewing.byteSize.toLocaleString()} bytes.
                  {viewing.id !== current?.id && ' This is a superseded version, shown for reference only.'}
                </>
              }
              actions={
                documents.length > 1 ? (
                  <form method="get" style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                    <input type="hidden" name="tab" value="document" />
                    <select name="v" defaultValue={viewing.id} style={{ width: 'auto' }}>
                      {documents.map((d) => <option key={d.id} value={d.id}>Version {d.versionNumber}{d.frozenAt ? ' (frozen)' : ''}</option>)}
                    </select>
                    <button className="btn sm" type="submit">View</button>
                  </form>
                ) : undefined
              }
            >
              {viewing.id !== current?.id && (
                <Callout tone="warn">
                  You are reading version {viewing.versionNumber}, which has been superseded by version {current?.versionNumber}.
                  Nothing can be signed on this version any more — that is deliberate, so a signature can never be attached to
                  text the other side has already changed.
                </Callout>
              )}
              <pre
                style={{
                  marginTop: 12, padding: 16, background: 'var(--ink)', border: '1px solid var(--line)',
                  borderRadius: 10, whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                  maxHeight: 560, overflowY: 'auto', fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
                  fontSize: 12.5, lineHeight: 1.6,
                }}
              >
                {viewing.body ?? 'Document content is stored in private object storage and served only through an authenticated, expiring link.'}
              </pre>
            </Card>
          )}

          {tab === 'parties' && (
            <Card
              title="Parties and signing order"
              subtitle="Signatures are collected in order, so a later signer cannot commit before an earlier one has had the chance to review."
            >
              <Table head={['Order', 'Party', 'Role', 'Signing', 'Identity assurance', 'Status', 'Signed']}>
                {parties.map((p) => {
                  const signedAt = signatureEvents.find((e) => e.partyId === p.id && e.outcome === 'signed')?.occurredAt ?? null;
                  return (
                    <tr key={p.id}>
                      <td className="num">{p.signingOrder}</td>
                      <td>
                        {p.displayName}
                        <div className="tiny">{p.email}</div>
                        {p.userId === viewer.userId && <div className="tiny" style={{ color: 'var(--accent)' }}>that's you</div>}
                      </td>
                      <td className="tiny nowrap"><span className="chip">{p.partyRole}</span></td>
                      <td className="tiny">{p.signingRequired ? <Badge tone="warn">required</Badge> : <Badge tone="neutral">not required</Badge>}</td>
                      <td className="tiny">
                        {p.assuranceLevel
                          ? <>{p.assuranceLevel.replace(/_/g, ' ')}<div className="tiny">{p.identityVerifiedAt ? `verified ${day(p.identityVerifiedAt)}` : ''}</div></>
                          : <span className="tiny">not yet verified</span>}
                      </td>
                      <td><Badge tone={p.status === 'accepted' ? 'ok' : p.status === 'declined' ? 'danger' : 'info'}>{p.status}</Badge></td>
                      <td className="tiny nowrap">{signedAt ? `${day(signedAt)} (${relative(signedAt, DEMO_NOW)})` : '—'}</td>
                    </tr>
                  );
                })}
              </Table>

              {completion && (
                <div className="callout accent" style={{ marginTop: 12 }}>
                  <strong>Completion rule.</strong> {completion.signed.size} of {completion.required.length} required signature(s)
                  recorded on version {current?.versionNumber}. The version freezes and the stamp issues only when every required
                  signer has signed <em>and</em> nobody required has declined.
                  {completion.declined.length > 0 && <div style={{ marginTop: 6 }}>Declined: {completion.declined.map((p) => p.partyRole).join(', ')} — completion is blocked until this is resolved.</div>}
                </div>
              )}

              {inviteDecision.allowed && (
                <div style={{ marginTop: 14 }}>
                  <UserActionButton
                    label="Invite another party"
                    variant="primary"
                    spec={{
                      action: 'invite_party',
                      title: 'Invite a party',
                      hidden: { agreementId: id },
                      intro: <>Invitations are tied to the email address you enter. In production an email with a single-use link is sent; in this demo build nothing is emailed.</>,
                      fields: [
                        { name: 'displayName', label: 'Full name', type: 'text', required: true, placeholder: 'Grace Achieng' },
                        { name: 'email', label: 'Email address', type: 'email', required: true, placeholder: 'grace@example.com', help: 'This address is what binds the invitation to a person. Check it carefully.' },
                        { name: 'partyRole', label: 'Role on this agreement', type: 'text', required: true, placeholder: 'supplier', help: 'e.g. lender, borrower, landlord, tenant, buyer, guarantor. This appears on the evidence timeline.' },
                        {
                          name: 'signingRequired', label: 'Signature required', type: 'select', required: true, defaultValue: 'true',
                          options: [{ value: 'true', label: 'Yes — must sign before completion' }, { value: 'false', label: 'No — notified only' }],
                        },
                        { name: 'signingOrder', label: 'Signing order', type: 'number', required: true, min: 1, max: 20, defaultValue: (parties.length + 1), help: 'Lower numbers sign first.' },
                      ],
                      confirmLabel: 'Send invitation',
                      disclaimer: <div className="callout"><strong>What the invitee sees:</strong> the document, the parties, who has signed, and an evidence timeline. They do not see your other agreements.</div>,
                    }}
                  />
                </div>
              )}
            </Card>
          )}

          {tab === 'timeline' && (
            <Card
              title="Evidence timeline"
              subtitle="Append-only. Each entry commits to the hash of the one before it, so an edit anywhere is detectable."
            >
              <div className="timeline">
                {events.map((e, i) => {
                  const check = chain.checks[i];
                  const bad = check && !check.ok;
                  return (
                    <div className={`timeline-item${bad ? ' bad' : ' good'}`} key={e.id}>
                      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                        <strong>{EVENT_LABELS[e.eventType] ?? e.eventType}</strong>
                        <Badge tone={bad ? 'danger' : e.eventType.includes('refused') || e.eventType.includes('failed') ? 'warn' : 'ok'}>
                          {String(i + 1).padStart(2, '0')}
                        </Badge>
                        <span className="tiny">{when(e.occurredAt)}</span>
                      </div>
                      <div className="tiny" style={{ marginTop: 4 }}>
                        {Object.entries(e.metadata).filter(([k]) => !['note'].includes(k)).slice(0, 5).map(([k, v]) => (
                          <span key={k} style={{ marginRight: 10 }}>
                            <span style={{ color: 'var(--muted-2)' }}>{k}:</span> {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                          </span>
                        ))}
                      </div>
                      <div className="tiny" style={{ marginTop: 4 }}>
                        {e.previousHash ? <Hash value={e.previousHash} chars={14} /> : 'GENESIS'} → <Hash value={e.eventHash} chars={14} />
                      </div>
                      {('note' in e.metadata) && <div className="sub" style={{ marginTop: 3 }}>{String((e.metadata as { note?: string }).note)}</div>}
                    </div>
                  );
                })}
              </div>
            </Card>
          )}

          {tab === 'versions' && (
            <Card
              title="Version history"
              subtitle="Nothing is ever overwritten. If you need a change after signing, it becomes a new agreement or an amendment version — never a silent edit."
            >
              <Table head={['Version', 'Written', 'SHA-256', 'State', 'Signatures on this version', '']}>
                {[...documents].reverse().map((d) => {
                  const signedHere = signatureEvents.filter((e) => e.versionId === d.id && e.outcome === 'signed').length;
                  return (
                    <tr key={d.id}>
                      <td className="num">v{d.versionNumber}{d.id === current?.id && <div className="tiny">current</div>}</td>
                      <td className="tiny nowrap">{day(d.createdAt)}</td>
                      <td><Hash value={d.sha256} chars={18} /></td>
                      <td>{d.frozenAt ? <Badge tone="ok">frozen</Badge> : d.id === current?.id ? <Badge tone="info">open</Badge> : <Badge tone="neutral">superseded</Badge>}</td>
                      <td className="num">{signedHere}</td>
                      <td className="nowrap">
                        <Link className="btn sm ghost" href={`/app/agreements/${id}?tab=document&v=${d.id}`}>Read</Link>
                        {d.frozenAt && <span style={{ marginLeft: 6 }}><Link className="btn sm" href={`/app/evidence?agreement=${id}`}>Package</Link></span>}
                      </td>
                    </tr>
                  );
                })}
              </Table>
            </Card>
          )}

          {tab === 'integrity' && (
            <Card
              title="Integrity of this record"
              subtitle="Recomputed from the stored events each time you open this page. Never a cached badge."
            >
              <div className={`callout ${chain.valid ? 'ok' : 'danger'}`}>
                {chain.valid ? (
                  <ul style={{ margin: 0, paddingLeft: 18 }}>
                    {describeVerification(chain).map((line, i) => <li key={i}>{line}</li>)}
                  </ul>
                ) : (
                  <>
                    <strong>Verification failed.</strong> {chain.firstFailure?.detail}
                    <div style={{ marginTop: 6 }}>
                      Do not rely on this record until it has been investigated. Contact support quoting {agreement.ref},
                      and avoid deleting anything on your side.
                    </div>
                  </>
                )}
              </div>

              <div className="section-title"><h2>Checks performed</h2></div>
              <Table head={['#', 'Event', 'Check']}>
                {chain.checks.map((c) => (
                  <tr key={c.eventId ?? c.index}>
                    <td className="num">{c.index + 1}</td>
                    <td className="tiny mono">{events[c.index]?.eventType ?? '—'}</td>
                    <td className="tiny">
                      {c.ok ? <Badge tone="ok">link verified</Badge> : <Badge tone="danger">{c.reason}</Badge>}
                      <div className="tiny" style={{ marginTop: 2 }}>{c.detail}</div>
                    </td>
                  </tr>
                ))}
              </Table>

              <Callout tone="warn">
                <strong>What this proves, precisely.</strong> That the stored events recompute to their recorded digests and
                that the links between them are unbroken. It does not on its own prove who a person was, whether they had
                capacity, or whether the agreement has any legal effect. Those are different questions, answered by different
                evidence — our identity and consent records, and ultimately a court.
              </Callout>
            </Card>
          )}
        </div>

        <div>
          <Card title="At a glance">
            <KV
              rows={[
                ['Reference', <span className="mono" key="r">{agreement.ref}</span>],
                ['Status', <StatusBadge key="s" status={agreement.status} />],
                ['Current version', `v${agreement.currentVersion} of ${documents.length}`],
                ['Document SHA-256', <Hash key="h" value={current?.sha256 ?? null} chars={22} />],
                ['Chain head', <Hash key="c" value={chain.head} chars={22} />],
                ['Events', String(events.length)],
                ['Required signers', String(requiredParties(parties).length)],
                ['Signed', String(completion?.signed.size ?? 0)],
                ['Stamp issued', agreement.stampIssuedAt ? when(agreement.stampIssuedAt) : 'not yet'],
                ['Frozen versions', String(frozen.length)],
              ]}
            />
          </Card>

          {agreement.status === 'completed' && (
            <Card title="Evidence package" subtitle="Hand this to anyone who needs to check the record — they do not need an agre-e account.">
              {exportDecision.allowed ? (
                <>
                  <div className="callout ok">
                    {packages.length > 0
                      ? 'A package exists for this agreement. Downloading it again returns the same files — the package is derived from the chain, not regenerated with a new timestamp.'
                      : 'No package yet for this agreement. Generate one now: it contains the frozen document, the full event chain, the signature records and the verification result.'}
                  </div>
                  <div className="btn-row" style={{ marginTop: 12 }}>
                    <UserActionButton
                      label={packages.length > 0 ? 'Re-generate (idempotent)' : 'Generate package'}
                      spec={{ action: 'generate_package', title: 'Generate the evidence package', hidden: { agreementId: id }, confirmLabel: 'Generate' }}
                    />
                    <Link className="btn sm" href={`/app/evidence?agreement=${id}`}>Open package</Link>
                    <a className="btn sm" href={`/api/evidence/${id}`}>Download .zip</a>
                  </div>
                </>
              ) : (
                <p className="sub" style={{ margin: 0 }}>{exportDecision.reason}</p>
              )}
            </Card>
          )}

          {isOwner && (editDecision.allowed || revokeDecision.allowed) && (
            <Card title="Owner actions" subtitle="All of these append events. None of them delete anything.">
              <div className="btn-row">
                {editDecision.allowed && (
                  <UserActionButton
                    label="Write a new version"
                    variant="primary"
                    spec={{
                      action: 'add_version',
                      title: 'Write a new version',
                      hidden: { agreementId: id },
                      intro: <>The current version stays exactly as it is. This creates version {(current?.versionNumber ?? 0) + 1} with its own hash, and every unsigned party must sign that version instead.</>,
                      fields: [
                        { name: 'documentText', label: 'Full text of the new version', type: 'textarea', required: true, rows: 16, defaultValue: current?.body ?? '' },
                        { name: 'note', label: 'Why the change was needed', type: 'text', placeholder: 'e.g. delivery window extended by seven days at the supplier’s request', help: 'This note is stored on the timeline. Write it for the person reading the record in two years.' },
                      ],
                      confirmLabel: 'Create new version',
                      disclaimer: <div className="callout warn"><strong>Signed already?</strong> Any existing signatures apply to the previous version. Changing the text after someone has signed does not move their signature — it invalidates it for the new version, and that is visible to everyone.</div>,
                    }}
                  />
                )}
                {revokeDecision.allowed && (
                  <UserActionButton
                    label="Revoke agreement"
                    variant="danger"
                    spec={{
                      action: 'revoke',
                      title: 'Revoke this agreement',
                      hidden: { agreementId: id },
                      intro: <>Revocation withdraws the agreement from further action. Everything already recorded — drafts, versions, invites, any signatures — is retained unaltered. A later dispute may well need to know what was proposed and withdrawn.</>,
                      fields: [{ name: 'reason', label: 'Reason for revocation', type: 'textarea', required: true, placeholder: 'e.g. Commercial terms could not be agreed; the parties are proceeding on a different structure.' }],
                      acknowledgement: 'I understand this does not delete the record, and that anything already signed remains on file.',
                      confirmLabel: 'Revoke agreement',
                      intent: 'danger',
                    }}
                  />
                )}
              </div>
            </Card>
          )}

          <Card title="Who is on this record">
            <Table head={['Party', 'Role', 'Signature']}>
              {parties.map((p) => {
                const signed = signatureEvents.find((e) => e.partyId === p.id && e.outcome === 'signed');
                return (
                  <tr key={p.id}>
                    <td className="tiny">{p.displayName}{p.userId === viewer.userId && <span className="tiny"> (you)</span>}</td>
                    <td className="tiny">{p.partyRole}</td>
                    <td className="tiny">
                      {p.status === 'declined' ? <Badge tone="danger">declined</Badge>
                        : signed ? <Badge tone="ok">signed {day(signed.occurredAt)}</Badge>
                          : p.signingRequired ? <Badge tone="warn">awaiting</Badge> : <Badge tone="neutral">not required</Badge>}
                    </td>
                  </tr>
                );
              })}
            </Table>
            {consents.length > 0 && (
              <div className="tiny" style={{ marginTop: 10 }}>
                {consents.length} consent record(s) captured against disclosure version{' '}
                <span className="mono">{consents[0].disclosureVersion}</span>. Consent scope is recorded per event, not assumed.
              </div>
            )}
          </Card>

          {requests.length > 0 && (
            <Card title="Signature requests" subtitle="What each party has been asked to sign, and whether that request is still live.">
              <Table head={['Party', 'Version', 'State']}>
                {requests.map((r) => {
                  const party = parties.find((p) => p.id === r.partyId);
                  const version = documents.find((d) => d.id === r.versionId);
                  return (
                    <tr key={r.id}>
                      <td className="tiny">{party?.displayName ?? '—'}</td>
                      <td className="tiny">v{version?.versionNumber ?? '—'}</td>
                      <td className="tiny">
                        <Badge tone={r.status === 'signed' ? 'ok' : r.status === 'expired' ? 'neutral' : 'warn'}>{r.status}</Badge>
                      </td>
                    </tr>
                  );
                })}
              </Table>
            </Card>
          )}
        </div>
      </div>
    </>
  );
}
