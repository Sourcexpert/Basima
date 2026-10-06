import Link from 'next/link';
import { redirect } from 'next/navigation';
import { getUserViewer } from '@/lib/auth/user-auth';
import { userStore } from '@/lib/data/user-store';
import { accessLevel, evaluateCompletion, nextActionFor } from '@/lib/auth/user-access';
import { Badge, Card, PageHead, StatusBadge, Table, TabLink, day, relative } from '@/components/ui';

export const dynamic = 'force-dynamic';

const DEMO_NOW = new Date('2026-10-05T09:20:00.000Z').getTime();
const FILTERS = ['all', 'draft', 'awaiting_parties', 'awaiting_signatures', 'completed', 'revoked'] as const;

export default async function AgreementsPage({
  searchParams,
}: {
  searchParams: Promise<{ status?: string }>;
}) {
  const viewer = await getUserViewer();
  if (!viewer) redirect('/app/login');

  const params = await searchParams;
  const filter = (FILTERS.includes((params.status ?? 'all') as typeof FILTERS[number]) ? params.status : 'all') ?? 'all';

  const s = await userStore();
  const all = await s.listAgreementsForUser(viewer.userId, viewer.email);
  const rows = await Promise.all(
    all.map(async (agreement) => {
      const [parties, signatureEvents, documents] = await Promise.all([
        s.listParties(agreement.id),
        s.listSignatureEvents(agreement.id),
        s.listDocuments(agreement.id),
      ]);
      const current = documents.find((d) => d.versionNumber === agreement.currentVersion) ?? null;
      return {
        agreement, parties, documents, current,
        completion: current ? evaluateCompletion(parties, signatureEvents, current.id) : null,
        next: nextActionFor(viewer.userId, { agreement, parties, signatureEvents, currentVersion: current, viewerEmail: viewer.email }),
        mine: accessLevel(viewer.userId, { agreement, parties, signatureEvents, viewerEmail: viewer.email }).party,
      };
    }),
  );

  const filtered = filter === 'all' ? rows : rows.filter((r) => r.agreement.status === filter);
  const count = (status: string) => (status === 'all' ? rows.length : rows.filter((r) => r.agreement.status === status).length);

  return (
    <>
      <PageHead
        title="My agreements"
        lede="Every agreement you own or are a party to, with the exact version currently in play. Earlier versions are never deleted: they stay on the record and the timeline shows why each one was superseded."
        actions={<Link className="btn sm primary" href="/app/agreements/new">New agreement</Link>}
      />

      <div className="tabs">
        {FILTERS.map((f) => (
          <TabLink key={f} href={`/app/agreements?status=${f}`} active={filter === f} count={count(f)}>
            {f === 'all' ? 'All' : f.replace(/_/g, ' ')}
          </TabLink>
        ))}
      </div>

      <Card>
        <Table head={['Agreement', 'Your role', 'Status', 'Version', 'Signatures', 'Next step', '']} empty="Nothing in this filter.">
          {filtered.map((r) => (
            <tr key={r.agreement.id}>
              <td>
                <Link href={`/app/agreements/${r.agreement.id}`} style={{ fontWeight: 560 }}>{r.agreement.title}</Link>
                <div className="tiny mono">{r.agreement.ref}</div>
                <div className="tiny">created {day(r.agreement.createdAt)} ({relative(r.agreement.createdAt, DEMO_NOW)})</div>
              </td>
              <td className="tiny">
                {r.agreement.ownerId === viewer.userId
                  ? <Badge tone="accent">owner</Badge>
                  : r.mine
                    ? <><Badge tone="info">{r.mine.partyRole}</Badge>{r.mine.signingRequired && <div className="tiny">signature required</div>}</>
                    : <span className="tiny">counterparty</span>}
              </td>
              <td>
                <StatusBadge status={r.agreement.status} />
                {r.agreement.stampIssuedAt && <div className="tiny" style={{ marginTop: 3 }}>stamped {day(r.agreement.stampIssuedAt)}</div>}
              </td>
              <td className="num">
                v{r.agreement.currentVersion}
                <div className="tiny">{r.documents.length} version{r.documents.length === 1 ? '' : 's'} on record</div>
              </td>
              <td className="tiny nowrap">
                {r.completion ? `${r.completion.signed.size}/${r.completion.required.length}` : '—'}
                {r.completion && r.completion.pending.length > 0 && (
                  <div className="tiny">awaiting {r.completion.pending.map((p) => p.partyRole).join(', ')}</div>
                )}
                {r.completion && r.completion.declined.length > 0 && (
                  <div className="tiny" style={{ color: 'var(--danger)' }}>declined: {r.completion.declined.map((p) => p.partyRole).join(', ')}</div>
                )}
              </td>
              <td className="tiny">{r.next ? r.next.label : '—'}</td>
              <td className="nowrap"><Link className="btn sm" href={`/app/agreements/${r.agreement.id}`}>Open</Link></td>
            </tr>
          ))}
        </Table>
      </Card>

      <div style={{ marginTop: 16 }} className="grid cols-3">
        <Card tight title="Why versions matter">
          <p className="sub" style={{ margin: 0 }}>
            If you change a term after someone has seen the text, we do not quietly update the document. We write a new
            version, keep the old one untouched, and ask the signers to sign the new one. Anyone reading the record later
            can see exactly which text each signature was placed on.
          </p>
        </Card>
        <Card tight title="What a status means">
          <p className="sub" style={{ margin: 0 }}>
            <strong>Draft</strong> — you are still preparing it. <strong>Awaiting parties</strong> — invitations are out.
            {' '}<strong>Awaiting signatures</strong> — at least one required signer has signed; others have not.
            {' '}<strong>Completed</strong> — the version is frozen, stamped and exportable.
            {' '}<strong>Revoked</strong> — withdrawn, but retained unaltered.
          </p>
        </Card>
        <Card tight title="Who can see this">
          <p className="sub" style={{ margin: 0 }}>
            Only the owner and invited parties, and only because they are on the agreement. Our own support staff cannot
            read your agreement content — they can see that a record exists and whether its chain verifies, which is why
            a support agent will ask you for details rather than quoting your contract back to you.
          </p>
        </Card>
      </div>
    </>
  );
}
