import { redirect } from 'next/navigation';
import { getUserViewer } from '@/lib/auth/user-auth';
import { userStore } from '@/lib/data/user-store';
import { verifyChain } from '@/lib/audit/chain';
import { VerifyWorkbench } from './workbench';
import { Card, PageHead, Table, Badge, Hash, Callout, day } from '@/components/ui';

export const dynamic = 'force-dynamic';

export default async function VerifyPage({
  searchParams,
}: {
  searchParams: Promise<{ agreement?: string }>;
}) {
  const viewer = await getUserViewer();
  if (!viewer) redirect('/app/login');

  const sp = await searchParams;
  const s = await userStore();
  const myAgreements = await s.listAgreementsForUser(viewer.userId, viewer.email);

  const rows = await Promise.all(
    myAgreements.map(async (a) => {
      const events = await s.listAuditEvents({ agreementId: a.id, limit: 1000 });
      const result = verifyChain(events);
      return { agreement: a, events, result };
    }),
  );
  const focus = sp.agreement ? rows.find((r) => r.agreement.id === sp.agreement) ?? null : null;

  return (
    <>
      <PageHead
        title="Verify a chain"
        lede="Two things you can check without trusting us: paste a package's contents and this page recomputes every digest in your own browser, or read the live verification state of each of your agreements below."
      />

      <VerifyWorkbench
        initial={focus ? { agreementRef: focus.agreement.ref, events: focus.events } : null}
        options={rows.map((r) => ({ id: r.agreement.id, ref: r.agreement.ref, title: r.agreement.title }))}
        demo={myAgreements.map((a) => ({ id: a.id, ref: a.ref, title: a.title }))}
      />

      <Card
        title="Live state of your chains"
        subtitle="Computed server-side from the stored events on this request. A page that caches a green tick is worthless, so nothing here is cached."
      >
        <Table head={['Agreement', 'Events', 'Chain head', 'Result', '']}>
          {rows.map((r) => (
            <tr key={r.agreement.id}>
              <td>
                <div style={{ fontWeight: 560 }}>{r.agreement.title}</div>
                <div className="tiny mono">{r.agreement.ref}</div>
              </td>
              <td className="num">
                {r.events.length}
                <div className="tiny">{r.events.length ? `first ${day(r.events[0].occurredAt)}` : ''}</div>
              </td>
              <td><Hash value={r.result.head} chars={22} /></td>
              <td className="tiny">
                {r.result.valid
                  ? <Badge tone="ok">verified</Badge>
                  : <><Badge tone="danger">failed at #{r.result.firstFailure?.index}</Badge><div className="tiny">{r.result.firstFailure?.reason}</div></>}
              </td>
              <td className="nowrap"><a className="btn sm ghost" href={`/app/verify?agreement=${r.agreement.id}`}>Load</a></td>
            </tr>
          ))}
        </Table>
      </Card>

      <div style={{ marginTop: 16 }} className="grid cols-2">
        <Card title="What the check does, exactly">
          <ol className="sub" style={{ margin: 0, paddingLeft: 18 }}>
            <li>Takes each stored event and recomputes its digest from its canonical fields.</li>
            <li>Compares that digest to the digest recorded for the event.</li>
            <li>Checks the event&rsquo;s <span className="mono">previousHash</span> equals the previous event&rsquo;s recorded digest — the link.</li>
            <li>Reports the first index at which either check fails, and stops there.</li>
          </ol>
          <Callout tone="accent">
            Change one character anywhere in the timeline and step 1 or 2 fails at that event, and step 3 fails on the one
            after it. That is what tamper-evident means — we cannot hide an edit, and neither could anyone who got into our
            database.
          </Callout>
        </Card>
        <Card title="What it cannot tell you">
          <ul className="sub" style={{ margin: 0, paddingLeft: 18 }}>
            <li>Whether the person who signed had authority to bind a company — that is a documents question.</li>
            <li>Whether the signer was under duress, or lacked capacity.</li>
            <li>Whether the agreement is lawful, fair or enforceable.</li>
            <li>Whether the text itself is a good agreement. Ours records what you agreed; it does not judge it.</li>
          </ul>
          <div className="callout warn" style={{ marginTop: 10 }}>
            A verified chain proves the record is intact. It is evidence about the record, not a verdict about the deal.
          </div>
        </Card>
      </div>
    </>
  );
}
