import Link from 'next/link';
import { redirect } from 'next/navigation';
import { getUserViewer } from '@/lib/auth/user-auth';
import { userStore } from '@/lib/data/user-store';
import { paymentRails, isDemo } from '@/lib/env';
import { UserActionButton } from '@/components/user-action-form';
import { Badge, Callout, Card, KV, PageHead, Stat, StatusBadge, Table, day, money } from '@/components/ui';

export const dynamic = 'force-dynamic';

export default async function UserBillingPage() {
  const viewer = await getUserViewer();
  if (!viewer) redirect('/app/login');

  const s = await userStore();
  const [invoices, payments, subscription, profile] = await Promise.all([
    s.listInvoices({ limit: 500 }),
    s.listPayments({ limit: 500 }),
    s.listSubscriptions({ limit: 500 }),
    s.getUser(viewer.userId),
  ]);
  const mine = invoices.filter((i) => i.userId === viewer.userId);
  const myPayments = payments.filter((p) => mine.some((i) => i.id === p.invoiceId));
  const sub = subscription.find((x) => x.userId === viewer.userId) ?? null;
  const open = mine.filter((i) => i.status === 'open');
  const plan = sub ? await s.getPlan(sub.planId) : null;

  const rails = paymentRails();
  const attemptsFor = (invoiceId: string) => myPayments.filter((p) => p.invoiceId === invoiceId).length;
  // Settlement reference comes from the payment record (written by the webhook),
  // never from a field on the invoice — invoices do not carry provider data.
  const receiptFor = (invoiceId: string) => {
    const settled = myPayments.find((p) => p.invoiceId === invoiceId && p.status === 'succeeded');
    return settled?.mpesaReceipt ?? settled?.providerRef ?? '';
  };

  return (
    <>
      <PageHead
        title="Billing"
        lede="Your plan, your invoices and what happens if a payment does not go through. Payment state never touches your agreements — arrears can stop you starting new work, and nothing else."
      />

      <div className="grid cols-3" style={{ marginBottom: 16 }}>
        <Stat label="Plan" value={sub?.planName ?? 'None'} meta={sub ? <StatusBadge status={sub.status} /> : 'No subscription on this account'} />
        <Stat
          label="Outstanding"
          value={open.length ? money(open.reduce((n, i) => n + i.amountMinor, 0), open[0].currency) : 'Clear'}
          tone={open.length ? 'warn' : 'ok'}
          meta={open.length ? `${open.length} invoice(s) open` : 'Nothing due'}
        />
        <Stat
          label="Repayment method"
          value={<span style={{ fontSize: 15 }}>M-PESA</span>}
          meta="Card and bank transfer are handled by Flutterwave"
        />
      </div>

      {open.length > 0 && (
        <Card
          title="Invoices to pay"
          subtitle="Paying by M-PESA sends a prompt to your phone. Nothing is marked paid until the network confirms it — an accepted prompt is not a completed payment."
        >
          <Table head={['Invoice', 'Issued', 'Due', 'Amount', 'State', 'Pay']}>
            {open.map((inv) => (
              <tr key={inv.id}>
                <td className="tiny mono">{inv.number}</td>
                <td className="tiny nowrap">{day(inv.issuedAt)}</td>
                <td className="tiny nowrap">{day(inv.dueAt)}</td>
                <td className="num">{money(inv.amountMinor, inv.currency)}</td>
                <td>
                  <StatusBadge status={inv.status} />
                  {attemptsFor(inv.id) > 0 && (
                    <div className="tiny">{attemptsFor(inv.id)} attempt(s); the balance is unchanged</div>
                  )}
                </td>
                <td className="nowrap">
                  {rails.mpesa.configured ? (
                    <UserActionButton
                      label="Pay with M-PESA"
                      variant="primary"
                      spec={{
                        action: 'pay_invoice',
                        title: `Pay ${money(inv.amountMinor, inv.currency)} with M-PESA`,
                        hidden: { invoiceId: inv.id },
                        intro: <>Enter the M-PESA number to send the prompt to. You will approve it on your handset with your M-PESA PIN — we never see your PIN.</>,
                        fields: [
                          { name: 'phone', label: 'M-PESA number', type: 'tel', required: true, placeholder: '0712 345 678', help: 'Formats accepted: 07…, 01…, +254…, 254…. The prompt goes to this number.' },
                        ],
                        confirmLabel: 'Send payment prompt',
                        disclaimer: <div className="callout"><strong>What happens next:</strong> a prompt arrives on your handset. Approve it there. This page shows <span className="mono">initiated</span> until the network calls us back with the receipt — a timed-out prompt is not a charge, and we will not record one as paid.</div>,
                      }}
                    />
                  ) : (
                    <span className="tiny">M-PESA is not configured on this deployment. Contact support for a payment link.</span>
                  )}
                </td>
              </tr>
            ))}
          </Table>
          {isDemo && (
            <Callout tone="warn">
              <strong>Demo build.</strong> No payment rails have credentials here: pressing pay returns
              <span className="mono"> not_configured</span> rather than pretending a payment occurred. In production this
              button starts a real Daraja STK push and the invoice is settled only by the signed callback.
            </Callout>
          )}
        </Card>
      )}

      <div className="split">
        <div>
          <Card title="Invoice history" subtitle="Invoices are immutable records. A correction is a credit note, never an edit.">
            <Table head={['Invoice', 'Issued', 'Amount', 'State', 'Paid']} empty="No invoices yet.">
              {[...mine].reverse().map((inv) => (
                <tr key={inv.id}>
                  <td className="tiny mono">{inv.number}</td>
                  <td className="tiny nowrap">{day(inv.issuedAt)}</td>
                  <td className="num">{money(inv.amountMinor, inv.currency)}</td>
                  <td><StatusBadge status={inv.status} /></td>
                  <td className="tiny nowrap">
                    {inv.paidAt ? (
                      <>
                        {day(inv.paidAt)}
                        <div className="tiny mono">{receiptFor(inv.id)}</div>
                      </>
                    ) : '—'}
                  </td>
                </tr>
              ))}
            </Table>
          </Card>

          <Card title="Payment attempts" subtitle="Every attempt, including the ones that failed. A failure is never hidden from you.">
            <Table head={['When', 'Amount', 'Rail', 'Provider reference', 'Outcome']} empty="No payment attempts recorded.">
              {[...myPayments].reverse().map((p) => (
                <tr key={p.id}>
                  <td className="tiny nowrap">{day(p.createdAt)}</td>
                  <td className="num">{money(p.amountMinor, p.currency)}</td>
                  <td className="tiny">{p.provider}</td>
                  <td className="tiny mono">{p.providerRef ?? '—'}</td>
                  <td className="tiny">
                    <StatusBadge status={p.status} />
                    {p.failureReason && <div className="tiny">{p.failureReason}</div>}
                  </td>
                </tr>
              ))}
            </Table>
          </Card>
        </div>

        <div>
          <Card title="Your plan">
            {plan ? (
              <KV
                rows={[
                  ['Plan', plan.name],
                  ['Price', `${money(plan.amountMinor, plan.currency)} / ${plan.interval}`],
                  ['Status', <StatusBadge key="s" status={sub!.status} />],
                  ['Current period ends', sub!.currentPeriodEnd ? day(sub!.currentPeriodEnd) : '—'],
                  ['Renews', sub!.cancelAtPeriodEnd ? 'No — cancels at period end' : 'Yes, automatically'],
                ]}
              />
            ) : (
              <p className="sub" style={{ margin: 0 }}>No subscription attached to your account yet.</p>
            )}
            <div className="callout accent" style={{ marginTop: 10 }}>
              <strong>Cancelling is real, not a maze.</strong> Cancelling stops future charges immediately and keeps your
              completed agreements and evidence packages downloadable for as long as the law requires us to hold them.
            </div>
          </Card>

          <Card title="If a payment fails" subtitle="Published so you can plan around it rather than be surprised by it.">
            <ol className="sub" style={{ margin: 0, paddingLeft: 18 }}>
              <li>Day 0 — payment fails. We record the failure and keep your account fully working.</li>
              <li>Day 1 and day 3 — we retry and email you. Nothing is suspended.</li>
              <li>Day 7 — the account moves to <span className="mono">past due</span>. Existing agreements stay fully accessible; signing, viewing and exporting are never blocked.</li>
              <li>Day 14 — new agreements cannot be created and new signing invitations cannot be sent until the balance clears.</li>
              <li>Day 30 — the account is suspended. Your records remain intact, exportable and verifiable.</li>
            </ol>
            <Callout tone="ok">
              <strong>Your completed agreements are never held hostage.</strong> Arrears gate starting new work. They do not,
              and will not, gate access to evidence of what you have already agreed — that would make the record worthless
              exactly when you most need it.
            </Callout>
          </Card>

          <Card title="Money and records are separate systems">
            <p className="sub" style={{ margin: 0 }}>
              Your payment state has no path into the evidence ledger. A failed payment does not create an event on any
              agreement chain, and paying an invoice does not alter one. If you ever see a billing event inside an evidence
              package, that is a defect — report it, because the two systems are meant to be incapable of influencing each
              other.
            </p>
          </Card>
        </div>
      </div>
    </>
  );
}
