import Link from 'next/link';
import { notFound, redirect } from 'next/navigation';
import { getUserViewer } from '@/lib/auth/user-auth';
import { userStore } from '@/lib/data/user-store';
import { accessLevel, canPerform, requiredParties, signingBlockers } from '@/lib/auth/user-access';
import { CURRENT_DISCLOSURE } from '@/lib/data/user-demo-db';
import { SignForm } from './sign-form';
import { Badge, Callout, Card, Hash, KV, PageHead, StatusBadge, Table, day } from '@/components/ui';

export const dynamic = 'force-dynamic';

export default async function SignPage({ params }: { params: Promise<{ id: string }> }) {
  const viewer = await getUserViewer();
  if (!viewer) redirect('/app/login');

  const { id } = await params;
  const s = await userStore();
  const agreement = await s.getAgreementSummary(id);
  if (!agreement) notFound();

  const [parties, signatureEvents, documents] = await Promise.all([
    s.listParties(id),
    s.listSignatureEvents(id),
    s.listDocuments(id),
  ]);

  const access = accessLevel(viewer.userId, { agreement, parties, signatureEvents, viewerEmail: viewer.email });
  const myParty = access.party;
  if (!myParty && agreement.ownerId !== viewer.userId) {
    return (
      <>
        <PageHead title="Not available" lede="You are not a party to this agreement." />
        <Callout tone="danger">Only an invited party with a signing requirement can sign this agreement.</Callout>
        <div style={{ marginTop: 14 }}><Link className="btn sm" href="/app/agreements">← My agreements</Link></div>
      </>
    );
  }

  const current = documents.find((d) => d.versionNumber === agreement.currentVersion) ?? null;
  const decision = canPerform(
    viewer.userId,
    { agreement, parties, signatureEvents, version: current, currentVersion: current, viewerEmail: viewer.email },
    'sign',
  );
  const alreadySigned = myParty && current
    ? signatureEvents.some((e) => e.partyId === myParty.id && e.versionId === current.id && e.outcome === 'signed')
    : false;
  const blockers = current && myParty ? signingBlockers(parties, signatureEvents, current.id, myParty) : [];

  if (!decision.allowed || alreadySigned) {
    return (
      <>
        <PageHead title="Signing unavailable" lede={agreement.title} />
        <Callout tone={alreadySigned ? 'ok' : 'warn'}>
          <strong>{alreadySigned ? 'You have already signed this version.' : 'You cannot sign at the moment.'}</strong>{' '}
          {alreadySigned
            ? 'Your signature is on the record. Signing again would not create a second event — duplicate submissions are recognised and ignored.'
            : decision.allowed ? '' : decision.reason}
        </Callout>
        {blockers.length > 0 && (
          <Callout tone="warn">
            <strong>Signing order.</strong> This agreement is signed in sequence. Still awaited before you:{' '}
            {blockers.map((b) => `${b.partyRole} (order ${b.signingOrder})`).join(', ')}.
          </Callout>
        )}
        <div style={{ marginTop: 14 }}>
          <Link className="btn sm" href={`/app/agreements/${id}`}>← Back to the agreement</Link>
        </div>
      </>
    );
  }

  const party = myParty!;
  const required = requiredParties(parties);
  const signedCount = current ? signatureEvents.filter((e) => e.versionId === current.id && e.outcome === 'signed').length : 0;

  return (
    <>
      <PageHead
        title="Review and sign"
        lede={
          <span>
            {agreement.title} · <span className="mono">{agreement.ref}</span> · version {current?.versionNumber}
          </span>
        }
        actions={<Link className="btn sm ghost" href={`/app/agreements/${id}`}>Cancel</Link>}
      />

      <Callout tone="accent">
        <strong>Read before you sign.</strong> Your signature will be bound to the exact text below and to its SHA-256
        digest. If anyone changes a single character afterwards, verification fails at that point and your signature can
        be shown to belong to the earlier text — which protects you as much as it protects the other side.
      </Callout>

      <div className="split">
        <div>
          <Card
            title={`The document you are about to sign — version ${current?.versionNumber}`}
            subtitle={<>SHA-256 <Hash value={current?.sha256 ?? null} chars={40} /> · {current?.byteSize.toLocaleString()} bytes</>}
          >
            <pre
              style={{
                padding: 16, background: 'var(--ink)', border: '1px solid var(--line)', borderRadius: 10,
                whiteSpace: 'pre-wrap', wordBreak: 'break-word', maxHeight: 460, overflowY: 'auto',
                fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', fontSize: 12.5, lineHeight: 1.6, margin: 0,
              }}
            >
              {current?.body ?? 'Document content is served through an authenticated, expiring link.'}
            </pre>
          </Card>

          <SignForm
            agreementId={id}
            versionId={current!.id}
            versionNumber={current!.versionNumber}
            documentHash={current!.sha256}
            disclosureVersion={CURRENT_DISCLOSURE}
            partyDisplayName={party.displayName}
            partyRole={party.partyRole}
            remainingAfterYou={required.length - signedCount - 1}
          />
        </div>

        <div>
          <Card title="Who else is on this agreement">
            <Table head={['Order', 'Party', 'Role', 'Signature']}>
              {required.map((p) => {
                const signed = signatureEvents.some((e) => e.partyId === p.id && e.versionId === current?.id && e.outcome === 'signed');
                return (
                  <tr key={p.id}>
                    <td className="num">{p.signingOrder}</td>
                    <td className="tiny">
                      {p.displayName}
                      {p.id === party.id && <div className="tiny" style={{ color: 'var(--accent)' }}>that's you</div>}
                    </td>
                    <td className="tiny"><span className="chip">{p.partyRole}</span></td>
                    <td className="tiny">
                      {signed ? <Badge tone="ok">signed</Badge> : p.id === party.id ? <Badge tone="warn">signing now</Badge> : <Badge tone="neutral">awaiting</Badge>}
                    </td>
                  </tr>
                );
              })}
            </Table>
          </Card>

          <Card title="Your signing record will contain">
            <KV
              rows={[
                ['Your party role', party.partyRole],
                ['Identity assurance', party.assuranceLevel?.replace(/_/g, ' ') ?? 'not verified'],
                ['Verified on', party.identityVerifiedAt ? day(party.identityVerifiedAt) : '—'],
                ['Method', 'one-time code + typed name + confirmed intent'],
                ['Consent version', CURRENT_DISCLOSURE],
                ['Server timestamp', 'recorded when you confirm, in UTC'],
                ['What is NOT stored', 'no ID document copy, no raw IP address'],
              ]}
            />
          </Card>

          <Card tight title="What happens straight after you sign">
            <ol className="sub" style={{ margin: 0, paddingLeft: 18 }}>
              <li>A consent record is written against the disclosure version shown to you.</li>
              <li>A signature event is bound to version {current?.versionNumber} and its document digest.</li>
              <li>An evidence event is appended to the chain — it cannot be altered later, by anyone, including us.</li>
              <li>
                {required.length - signedCount <= 1
                  ? 'Because you are the last required signer, the version freezes, the stamp is issued and the evidence package is generated.'
                  : `${required.length - signedCount - 1} more signature(s) are needed before the version freezes and the package is issued.`}
              </li>
            </ol>
          </Card>

          <Card tight title="If something looks wrong">
            <p className="sub" style={{ margin: 0 }}>
              Do not sign. Contact the other party, or reach our support team — but note that our staff cannot read your
              agreement content, so they will help you with the process rather than the substance of the text. If you
              believe someone is pressuring you into signing, that is a matter for your own advocate, not for us.
            </p>
          </Card>
        </div>
      </div>
    </>
  );
}
