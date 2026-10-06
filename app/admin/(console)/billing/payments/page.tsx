import { redirect } from 'next/navigation';
import { getViewer } from '@/lib/auth/session';
import { can } from '@/lib/auth/capabilities';
import { store } from '@/lib/data/store';
import { ActionButton } from '@/components/action-form';
import { FilterBar } from '@/components/action-form';
import { Badge, Callout, Card, Hash, PageHead, Stat, StatusBadge, Table, day, money, moneyCompact, when } from '@/components/ui';

export const dynamic = 'force-dynamic';

const STATUSES = ['initiated', 'pending', 'succeeded', 'failed', 'refunded', 'reversed'] as const;

export default async function PaymentsPage({
  searchParams,
}: {
  searchParams: Promise<{ q?: string; status?: string; provider?: string }>;
}) {
  const viewer = await getViewer();
  if (!viewer) redirect('/admin/login');
  if (!can(viewer.role, 'billing.read')) redirect('/admin');

  const params = await searchParams;
  const [payments, invoices, subs, snapshot] = await Promise.all([
    store().listPayments({ limit: 1000 }),
    store().listInvoices({ limit: 1000 }),
    store().listSubscriptions({ limit: 1000 }),
    store().snapshot(),
  ]);

  const canCollect = can(viewer.role, 'billing.payments.manage');
  const canRefund = can(viewer.role, 'billing.refund');

  const filtered = payments.filter(
    (p) =>
      (!params.status || p.status === params.status) &&
      (!params.provider || p.provider === params.provider) &&
      (!params.q ||
        [p.reference, p.userEmail, p.mpesaReceipt ?? '', p.providerRef ?? ''].join(' ').toLowerCase().includes(params.q.toLowerCase())),
  );

  const openInvoices = invoices.filter((i) => i.status === 'open');
  const failed = payments.filter((p) => p.status === 'failed');

  return (
    <>
      <PageHead
        title="Payments & invoices"
        lede="Reconciliation for M-PESA (Daraja) and Flutterwave. Nothing here can change whether an evidentiary event occurred — the ledger footer on each action says so explicitly."
        actions={<a className="btn sm ghost" href="/admin/billing">← Subscriptions</a>}
      />

      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        <Stat label="Settled · 30 days" value={moneyCompact(snapshot.billing.collectedThisMonthMinor)} meta={`${payments.filter((p) => p.status === 'succeeded').length} successful payments on record`} tone="accent" />
        <Stat label="Awaiting settlement" value={payments.filter((p) => p.status === 'pending' || p.status === 'initiated').length} meta="Prompt sent, customer has not confirmed" />
        <Stat label="Failed · last 7 days" value={snapshot.billing.failedPayments7d} tone={snapshot.billing.failedPayments7d ? 'warn' : undefined} meta="Mostly customer-cancelled (1032) and low balance (1)" />
        <Stat label="Open invoices" value={openInvoices.length} meta={`${money(openInvoices.reduce((s, i) => s + i.amountMinor, 0), 'KES')} outstanding`} />
      </div>

      <Callout tone="danger">
        <strong>Why the console refuses to &ldquo;just mark it paid&rdquo;.</strong> A settlement is the one place where a
        UI convenience could create a real loss. Every settlement path here requires an authentic provider callback whose
        reference matches a transaction we initiated, followed by an independent provider re-query that matches status,
        amount, currency and reference. If a rail is unconfigured, the console says so rather than inventing a success.
      </Callout>

      <div className="section-title">
        <h2>Transactions</h2>
        <div className="spacer" />
        <span className="tiny">{filtered.length} of {payments.length}</span>
      </div>

      <FilterBar
        basePath="/admin/billing/payments"
        values={params}
        filters={[
          { name: 'q', label: 'Search', type: 'text', placeholder: 'reference, receipt, email' },
          { name: 'status', label: 'Status', type: 'select', options: STATUSES.map((s) => ({ value: s, label: s })) },
          { name: 'provider', label: 'Rail', type: 'select', options: [{ value: 'mpesa', label: 'M-PESA' }, { value: 'flutterwave', label: 'Flutterwave' }] },
        ]}
      />

      <div style={{ marginTop: 14 }}>
        <Table head={['Reference', 'Customer', 'Rail', 'Amount', 'Status', 'Provider reference', 'Created', '']} empty="No payments match those filters.">
          {filtered.map((p) => (
            <tr key={p.id}>
              <td className="nowrap">
                <div className="mono">{p.reference}</div>
                {p.refundedMinor > 0 && <div className="tiny">refunded {money(p.refundedMinor, p.currency)}</div>}
              </td>
              <td className="tiny">
                {p.userEmail}
                {p.invoiceId && <div className="tiny">invoice {invoices.find((i) => i.id === p.invoiceId)?.number ?? '—'}</div>}
              </td>
              <td className="tiny nowrap">
                {p.provider === 'mpesa' ? 'M-PESA' : 'Flutterwave'}
                <div className="tiny">{p.method.replace(/_/g, ' ')}</div>
              </td>
              <td className="nowrap">{money(p.amountMinor, p.currency)}</td>
              <td>
                <StatusBadge status={p.status} />
                {p.failureReason && <div className="tiny" style={{ marginTop: 3, maxWidth: 260 }}>{p.failureReason}</div>}
                {p.reconciledBy && <div className="tiny" style={{ marginTop: 3 }}>reconciled by {p.reconciledBy}</div>}
              </td>
              <td className="tiny">
                {p.mpesaReceipt && <div>receipt <span className="mono">{p.mpesaReceipt}</span></div>}
                {p.providerRef && <div className="tiny">ref <Hash value={p.providerRef} chars={18} /></div>}
              </td>
              <td className="tiny nowrap">{when(p.createdAt)}</td>
              <td className="nowrap">
                <div className="btn-row">
                  {canCollect && p.status !== 'succeeded' && p.status !== 'refunded' && (
                    <ActionButton
                      label="Re-verify"
                      spec={{
                        action: 'reconcile',
                        title: `Re-verify ${p.reference}`,
                        intro: <>Queries the provider directly. For M-PESA this calls the STK query endpoint; for Flutterwave it calls <span className="mono">/v3/transactions/{'{id}'}/verify</span> and requires all four checks to pass before settling.</>,
                        hidden: { provider: p.provider, reference: p.reference },
                        reasonPlaceholder: 'e.g. Customer says they paid and forwarded the SMS; verifying before applying credit.',
                        confirmLabel: 'Query provider',
                      }}
                    />
                  )}
                  {canRefund && p.status === 'succeeded' && (
                    <ActionButton
                      label="Refund"
                      spec={{
                        action: 'refund',
                        title: `Refund ${p.reference}`,
                        intro: <>Requires a second person's approval. Flutterwave refunds are initiated against the provider API; M-PESA reversals must be raised with Safaricom Support and are recorded here for reconciliation. A refund has no effect on any agreement, stamp or audit event.</>,
                        hidden: { paymentId: p.id },
                        stepUpHint: true,
                        fields: [
                          { name: 'amount', label: 'Amount (major units)', type: 'number', required: true, min: 0.01, step: '0.01', defaultValue: ((p.amountMinor - p.refundedMinor) / 100).toFixed(2), help: `Remaining refundable: ${money(p.amountMinor - p.refundedMinor, p.currency)}` },
                          { name: 'supervisorEmail', label: 'Approving supervisor', type: 'text', required: true, placeholder: 'brian.otieno@agree-e.com' },
                        ],
                        reasonPlaceholder: 'e.g. Duplicate M-PESA charge confirmed on reconciliation; customer notified by email.',
                        acknowledgement: 'I confirm this refund is commercially justified and that it does not alter any evidentiary record.',
                        confirmLabel: 'Issue refund',
                        intent: 'danger',
                      }}
                    />
                  )}
                  {!canCollect && !canRefund && <span className="tiny">read-only role</span>}
                </div>
              </td>
            </tr>
          ))}
        </Table>
      </div>

      <div className="grid cols-2" style={{ marginTop: 18 }}>
        <Card
          title="Collect from a customer (M-PESA STK push)"
          subtitle="Sends a prompt to the customer's handset against an open invoice."
        >
          {openInvoices.length === 0 ? (
            <p className="sub" style={{ margin: 0 }}>No open invoices to collect against.</p>
          ) : (
            <Table head={['Invoice', 'Customer', 'Amount', 'Due', '']}>
              {openInvoices.slice(0, 8).map((inv) => (
                <tr key={inv.id}>
                  <td className="mono tiny">{inv.number}</td>
                  <td className="tiny">{inv.userEmail}<div className="tiny">{subs.find((s) => s.id === inv.subscriptionId)?.planName ?? ''}</div></td>
                  <td className="nowrap">{money(inv.amountMinor, inv.currency)}</td>
                  <td className="tiny nowrap">{day(inv.dueAt)}</td>
                  <td className="nowrap">
                    {canCollect ? (
                      <ActionButton
                        label="Send prompt"
                        spec={{
                          action: 'stk_push',
                          title: `STK push for ${inv.number}`,
                          intro: <>The customer receives a prompt to authorise {money(inv.amountMinor, inv.currency)} from their M-PESA balance. {snapshot.paymentHealth.mpesaConfigured ? '' : 'M-PESA is not configured on this deployment, so this will report not_configured rather than pretend to charge.'}</>,
                          hidden: { invoiceId: inv.id },
                          fields: [{ name: 'phone', label: 'Customer M-PESA number', type: 'tel', required: true, placeholder: '0712 345 678', help: 'Normalised to 2547XXXXXXXX before it reaches Daraja. Account reference is derived from the invoice number (12-character limit).' }],
                          reasonPlaceholder: 'e.g. Customer requested a prompt during the support call; invoice past due by 9 days.',
                          confirmLabel: 'Send STK push',
                          intent: 'primary',
                        }}
                      />
                    ) : <span className="tiny">read-only role</span>}
                  </td>
                </tr>
              ))}
            </Table>
          )}
          <div className="callout" style={{ marginTop: 12 }}>
            <strong>What happens next.</strong> Daraja posts the result to <span className="mono">/api/webhooks/mpesa</span>.
            That handler rejects callbacks without the secret token, quarantines a CheckoutRequestID it never issued, and
            records the outcome — success or failure — in the admin ledger. Result codes are translated into plain
            language (1032 = customer cancelled, 1 = insufficient balance, 1037 = timed out).
          </div>
        </Card>

        <Card title="Invoice register" subtitle="Issued for subscription periods; never renumbered or edited after payment.">
          <Table head={['Invoice', 'Customer', 'Amount', 'Status', 'Issued', 'Paid']}>
            {invoices.slice(0, 12).map((inv) => (
              <tr key={inv.id}>
                <td className="mono tiny">{inv.number}</td>
                <td className="tiny">{inv.userEmail}</td>
                <td className="nowrap">{money(inv.amountMinor, inv.currency)}</td>
                <td><StatusBadge status={inv.status} /></td>
                <td className="tiny nowrap">{day(inv.issuedAt)}</td>
                <td className="tiny nowrap">{inv.paidAt ? day(inv.paidAt) : '—'}</td>
              </tr>
            ))}
          </Table>
        </Card>
      </div>

      {failed.length > 0 && (
        <Card title="Recurring failure patterns" subtitle="Failure taxonomy is stored, not inferred, so dunning can be tuned without guessing.">
          <div className="grid cols-3">
            {summariseFailures(failed).map((row) => (
              <div className="card tight" key={row.reason}>
                <div className="stat-label">{row.count} occurrence(s)</div>
                <div className="sub" style={{ marginTop: 4 }}>{row.reason}</div>
              </div>
            ))}
          </div>
          <div className="callout warn" style={{ marginTop: 12 }}>
            <strong>Dunning is conservative.</strong> Reminders at cycles 1–2, grace (read and export only) at cycle 3,
            capability pause at cycle 4. A customer in arrears never loses access to evidence they already paid to create
            — that record may be needed in court precisely when their business is struggling.
          </div>
        </Card>
      )}
    </>
  );
}

function summariseFailures(payments: Array<{ failureReason: string | null }>) {
  const counts = new Map<string, number>();
  for (const p of payments) {
    const reason = p.failureReason ?? 'Unclassified failure';
    counts.set(reason, (counts.get(reason) ?? 0) + 1);
  }
  return Array.from(counts.entries())
    .map(([reason, count]) => ({ reason, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 6);
}
