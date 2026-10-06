import Link from 'next/link';
import { redirect } from 'next/navigation';
import { getUserViewer } from '@/lib/auth/user-auth';
import { userStore } from '@/lib/data/user-store';
import { canPerform, evaluateCompletion, nextActionFor } from '@/lib/auth/user-access';
import { verifyChain } from '@/lib/audit/chain';
import {
  Badge, Callout, Card, Hash, PageHead, Stat, StatusBadge, Table, money, relative, when,
} from '@/components/ui';

export const dynamic = 'force-dynamic';

const DEMO_NOW = new Date('2026-10-05T09:20:00.000Z').getTime();

export default async function UserHome() {
  const viewer = await getUserViewer();
  if (!viewer) redirect('/app/login');

  const s = await userStore();
  const agreements = await s.listAgreementsForUser(viewer.userId, viewer.email);

  const rows = await Promise.all(
    agreements.map(async (agreement) => {
      const [parties, signatureEvents, documents] = await Promise.all([
        s.listParties(agreement.id),
        s.listSignatureEvents(agreement.id),
        s.listDocuments(agreement.id),
      ]);
      const current = documents.find((d) => d.versionNumber === agreement.currentVersion) ?? null;
      const completion = current ? evaluateCompletion(parties, signatureEvents, current.id) : null;
      return {
        agreement,
        parties,
        signatureEvents,
        documents,
        current,
        completion,
        next: nextActionFor(viewer.userId, { agreement, parties, signatureEvents, currentVersion: current, viewerEmail: viewer.email }),
        canSign: canPerform(viewer.userId, { agreement, parties, signatureEvents, currentVersion: current, version: current, viewerEmail: viewer.email }, 'sign'),
      };
    }),
  );

  const actionable = rows.filter((r) => r.next && ['Accept invitation', 'Sign now'].includes(r.next.label));
  const active = rows.filter((r) => ['draft', 'awaiting_parties', 'awaiting_signatures'].includes(r.agreement.status));
  const completed = rows.filter((r) => r.agreement.status === 'completed');

  // Integrity is recomputed, not summarised: the number on this page is the
  // number of chains that actually recompute correctly right now.
  const checks = await Promise.all(
    completed.map(async (r) => ({
      id: r.agreement.id,
      ref: r.agreement.ref,
      result: verifyChain(await s.listAuditEvents({ agreementId: r.agreement.id, limit: 1000 })),
    })),
  );
  const verified = checks.filter((c) => c.result.valid).length;
  const failing = checks.filter((c) => !c.result.valid);

  const invoices = (await s.listInvoices({ limit: 500 })).filter((i) => i.userId === viewer.userId);
  const openInvoices = invoices.filter((i) => i.status === 'open');
  const subscription = (await s.listSubscriptions({ limit: 500 })).find((x) => x.userId === viewer.userId) ?? null;

  return (
    <>
      <PageHead
        title={`Good to see you, ${viewer.displayName.split(' ')[0]}`}
        lede="Your agreements, what needs your attention, and the integrity of your records — all computed fresh on every visit."
        actions={
          <>
            <Link className="btn sm" href="/app/verify">Verify a chain</Link>
            <Link className="btn sm primary" href="/app/agreements/new">New agreement</Link>
          </>
        }
      />

      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        <Stat
          label="Agreements you're party to"
          value={rows.length}
          meta={`${active.length} in progress · ${completed.length} completed`}
        />
        <Stat
          label="Needs your action"
          value={actionable.length}
          tone={actionable.length ? 'warn' : 'ok'}
          meta={actionable.length ? actionable.map((a) => a.agreement.ref).slice(0, 2).join(', ') : 'Nothing waiting on you'}
        />
        <Stat
          label="Chains verified"
          value={`${verified}/${checks.length || 0}`}
          tone={failing.length ? 'danger' : 'ok'}
          meta={failing.length ? `${failing.length} failing — investigate` : 'Recomputed just now'}
        />
        <Stat
          label="Billing"
          value={openInvoices.length ? `${openInvoices.length} due` : 'Clear'}
          tone={openInvoices.length ? 'warn' : 'ok'}
          meta={subscription ? `${subscription.planName} · ${subscription.status.replace('_', ' ')}` : 'No subscription'}
        />
      </div>

      {actionable.length > 0 && (
        <Card
          title="Waiting on you"
          subtitle="Nothing here is a notification you can dismiss: each item is a step only you can complete."
        >
          <Table head={['Agreement', 'What you need to do', 'Why it matters', '']}>
            {actionable.map((r) => (
              <tr key={r.agreement.id}>
                <td>
                  <div style={{ fontWeight: 560 }}>{r.agreement.title}</div>
                  <div className="tiny mono">{r.agreement.ref}</div>
                </td>
                <td><Badge tone="warn">{r.next?.label}</Badge></td>
                <td className="tiny" style={{ maxWidth: 420 }}>
                  {r.next?.label === 'Accept invitation'
                    ? 'Accepting records that you received the invitation and confirmed your email — it does not sign anything.'
                    : r.canSign.allowed && 'note' in r.canSign && r.canSign.note === 'duplicate'
                      ? 'Your signature is already recorded.'
                      : 'You are a required signer. Until you sign, the version cannot be frozen and no evidence package can be issued.'}
                </td>
                <td className="nowrap"><Link className="btn sm primary" href={r.next?.href ?? '#'}>Open</Link></td>
              </tr>
            ))}
          </Table>
        </Card>
      )}

      <div className="split" style={{ marginTop: 16 }}>
        <div>
          <Card
            title="Your agreements"
            subtitle="Versions are immutable. When something changes, a new version is created and every signer is asked to sign that one."
            actions={<Link className="btn sm ghost" href="/app/agreements">See all</Link>}
          >
            <Table head={['Agreement', 'Status', 'Version', 'Signatures', 'Last event', '']} empty="You have no agreements yet.">
              {rows.slice(0, 6).map((r) => {
                const lastEvent = r.agreement.stampIssuedAt ?? r.agreement.createdAt;
                return (
                  <tr key={r.agreement.id}>
                    <td>
                      <Link href={`/app/agreements/${r.agreement.id}`} style={{ fontWeight: 560 }}>{r.agreement.title}</Link>
                      <div className="tiny mono">{r.agreement.ref} · {r.agreement.agreementType}</div>
                    </td>
                    <td><StatusBadge status={r.agreement.status} /></td>
                    <td className="num">v{r.agreement.currentVersion}</td>
                    <td className="tiny nowrap">
                      {r.completion
                        ? `${r.completion.signed.size}/${r.completion.required.length} signed`
                        : '—'}
                      {r.completion && r.completion.pending.length > 0 && (
                        <div className="tiny">awaiting {r.completion.pending.map((p) => p.partyRole).join(', ')}</div>
                      )}
                    </td>
                    <td className="tiny nowrap">{relative(lastEvent, DEMO_NOW)}</td>
                    <td className="nowrap">
                      <Link className="btn sm" href={`/app/agreements/${r.agreement.id}`}>
                        {r.canSign.allowed && r.canSign.note !== 'duplicate' ? 'Review & sign' : 'View'}
                      </Link>
                    </td>
                  </tr>
                );
              })}
            </Table>
          </Card>

          <Card
            title="What this product does — and what it does not"
            subtitle="Stated plainly, because you may need to explain it to someone else."
          >
            <div className="callout ok">
              <strong>What we do.</strong> We keep an unalterable record of what was agreed, who agreed to it, on
              which exact version, and when — and we give you a package you can hand to someone else, including a
              court, that verifies without our help.
            </div>
            <div className="callout warn">
              <strong>What we do not do.</strong> We do not give legal advice, we do not decide whether an agreement
              is legally valid, and we cannot make an unenforceable contract enforceable. An integrity check proves
              the record has not changed; it does not by itself prove anything else.
            </div>
            <div className="callout">
              <strong>Your identity data.</strong> We record <em>that</em> your identity was verified and at what
              level — we do not keep a copy of your ID document, and we never store your raw IP address.
            </div>
          </Card>
        </div>

        <div>
          {failing.length > 0 && (
            <Card title="Integrity problem — read this first">
              {failing.map((f) => (
                <div className="callout danger" key={f.id}>
                  <strong>{f.ref}</strong> failed verification: {f.result.firstFailure?.detail}
                  <div style={{ marginTop: 6 }}>
                    Do not rely on this record until it has been investigated. Contact support with the reference above.
                  </div>
                </div>
              ))}
            </Card>
          )}

          <Card title="Your records" subtitle="Everything below can be exported and verified independently of this website.">
            <Table head={['Record', 'Count', '']}>
              <tr>
                <td className="tiny">Completed agreements (frozen versions)</td>
                <td className="num">{completed.length}</td>
                <td className="nowrap"><Link className="btn sm ghost" href="/app/evidence">Open</Link></td>
              </tr>
              <tr>
                <td className="tiny">Evidence events across your agreements</td>
                <td className="num">{rows.reduce((n, r) => n + r.signatureEvents.length, 0)} signatures</td>
                <td className="nowrap"><Link className="btn sm ghost" href="/app/verify">Verify</Link></td>
              </tr>
              <tr>
                <td className="tiny">Open invoices</td>
                <td className="num">{openInvoices.length}</td>
                <td className="nowrap"><Link className="btn sm ghost" href="/app/billing">Billing</Link></td>
              </tr>
            </Table>
          </Card>

          <Card title="Latest activity" subtitle="The same events a counterparty would see in an evidence package.">
            <div className="timeline">
              {rows
                .flatMap((r) => r.signatureEvents.map((e) => ({ ...e, ref: r.agreement.ref, title: r.agreement.title })))
                .sort((a, b) => b.occurredAt.localeCompare(a.occurredAt))
                .slice(0, 6)
                .map((e) => (
                  <div className="timeline-item good" key={e.id}>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                      <strong>{e.outcome === 'signed' ? 'Signature recorded' : e.outcome}</strong>
                      <Badge tone="ok">{e.signatureMethod.replace(/_/g, ' ')}</Badge>
                    </div>
                    <div className="sub" style={{ marginTop: 3 }}>{e.title}</div>
                    <div className="tiny" style={{ marginTop: 2 }}>
                      {when(e.occurredAt)} · {e.ref} · digest <Hash value={e.ipHash} chars={10} />
                    </div>
                  </div>
                ))}
              {rows.every((r) => r.signatureEvents.length === 0) && (
                <div className="tiny">No signing activity yet.</div>
              )}
            </div>
          </Card>
        </div>
      </div>

      <div style={{ marginTop: 16 }}>
        <Callout tone="accent">
          <strong>Want to check our work?</strong> Open <Link href="/app/verify" style={{ color: 'var(--accent)' }}>Verify a chain</Link>,
          edit one character of any timeline entry, and watch verification fail at that exact link. That is the whole
          point: we would rather you trust the arithmetic than our word.
        </Callout>
      </div>
    </>
  );
}
