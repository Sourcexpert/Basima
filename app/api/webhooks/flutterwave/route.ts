import { NextResponse } from 'next/server';
import { parseWebhook, verifyWebhookSignature, verifyTransaction } from '@/lib/payments/flutterwave';
import { recordAdminAction, store } from '@/lib/data/store';
import { hashIp } from '@/lib/crypto/hash';
import { env } from '@/lib/env';

/**
 * Flutterwave webhook.
 *
 * Order of operations matters and is deliberate:
 *   1. Verify `verif-hash` against our configured secret hash — otherwise 401 and
 *      a security event. Anyone can POST here, so an unverified body is noise.
 *   2. Match the event to a payment we created (by tx_ref).
 *   3. Re-verify server-side with GET /v3/transactions/{id}/verify and require all
 *      four checks (status, amount, currency, tx_ref) before settling. Webhooks
 *      can arrive out of order or be replayed, so the provider API — not the
 *      webhook — is the source of truth.
 *   4. Respond 200 quickly; work is short and idempotent.
 */
export async function POST(request: Request) {
  const signature = request.headers.get('verif-hash');
  const ipHash = hashIp(request.headers.get('x-forwarded-for')?.split(',')[0] ?? null, env.ipHashPepper);

  if (!verifyWebhookSignature(signature)) {
    await recordAdminAction({
      adminId: 'system',
      adminEmail: 'system@agree-e.com',
      adminRole: 'security',
      action: 'payment.reconciled',
      targetType: 'payment',
      targetId: 'flutterwave-webhook',
      targetLabel: 'Unsigned Flutterwave webhook',
      reason: 'Rejected: verif-hash header missing or does not match the configured secret hash.',
      status: 'blocked',
      stepUp: false,
      ipHash,
      metadata: { rejected: true, reason: 'invalid_verif_hash', header_present: Boolean(signature) },
    });
    return new NextResponse('Unauthorized', { status: 401 });
  }

  let payload: unknown;
  try {
    payload = await request.json();
  } catch {
    return new NextResponse('Malformed payload', { status: 400 });
  }

  const event = parseWebhook(payload);
  if (!event) return new NextResponse('Unrecognised event', { status: 400 });

  // Acknowledge first — provider retries aggressively on slow responses.
  const response = NextResponse.json({ status: 'received' });

  if (event.kind === 'charge') {
    const payments = await store().listPayments({ limit: 1000 });
    const payment = payments.find((p) => p.reference === event.txRef || p.providerRef === String(event.id));

    if (!payment) {
      await recordAdminAction({
        adminId: 'system',
        adminEmail: 'system@agree-e.com',
        adminRole: 'billing',
        action: 'payment.reconciled',
        targetType: 'payment',
        targetId: event.txRef || String(event.id),
        targetLabel: `Unmatched webhook ${event.txRef}`,
        reason: 'Webhook signature valid but no matching payment record; quarantined for reconciliation.',
        status: 'blocked',
        stepUp: false,
        ipHash,
        metadata: { provider: 'flutterwave', event: event.event, tx_ref: event.txRef, flw_id: event.id },
      });
      return response;
    }

    const verified = await verifyTransaction(event.id, {
      amountMinor: payment.amountMinor,
      currency: payment.currency,
      txRef: payment.reference,
    });

    if (verified.ok) {
      await store().patchPayment(payment.id, {
        status: 'succeeded',
        providerRef: String(event.id),
        failureReason: null,
      });
      if (payment.invoiceId) {
        const invoice = await store().getInvoice(payment.invoiceId);
        if (invoice && invoice.status !== 'paid') {
          await store().patchInvoice(invoice.id, { status: 'paid', paidAt: new Date().toISOString() });
          const sub = await store().getSubscription(invoice.subscriptionId);
          if (sub) {
            const start = new Date();
            const end = new Date(start);
            if (sub.planCode.endsWith('annual')) end.setUTCFullYear(end.getUTCFullYear() + 1);
            else end.setUTCDate(end.getUTCDate() + 30);
            await store().patchSubscription(sub.id, {
              status: 'active', currentPeriodStart: start.toISOString(), currentPeriodEnd: end.toISOString(),
              dunningAttempts: 0, graceEndsAt: null, cancelAtPeriodEnd: false,
            });
          }
        }
      }
    } else {
      await store().patchPayment(payment.id, {
        status: verified.status === 'failed' ? 'failed' : payment.status,
        providerRef: String(event.id),
        failureReason: verified.reason,
      });
    }

    await recordAdminAction({
      adminId: 'system',
      adminEmail: 'system@agree-e.com',
      adminRole: 'billing',
      action: 'payment.reconciled',
      targetType: 'payment',
      targetId: payment.id,
      targetLabel: payment.reference,
      reason: verified.reason,
      status: verified.ok ? 'succeeded' : 'failed',
      stepUp: false,
      ipHash,
      metadata: {
        source: 'flutterwave_webhook',
        event: event.event,
        flw_id: event.id,
        checks: verified.checks,
        amount_minor: verified.amountMinor,
        payment_type: verified.paymentType,
        evidentiary_effect: 'none',
      },
    });
  } else if (event.kind === 'refund') {
    await recordAdminAction({
      adminId: 'system',
      adminEmail: 'system@agree-e.com',
      adminRole: 'billing',
      action: 'payment.refund_issued',
      targetType: 'payment',
      targetId: event.txRef || String(event.id),
      targetLabel: `Refund webhook ${event.txRef}`,
      reason: `Provider confirmed refund with status "${event.status}".`,
      status: event.status === 'completed' ? 'succeeded' : 'failed',
      stepUp: false,
      ipHash,
      metadata: { source: 'flutterwave_webhook', event: event.event, amount_minor: event.amountMinor },
    });
  } else {
    await recordAdminAction({
      adminId: 'system',
      adminEmail: 'system@agree-e.com',
      adminRole: 'billing',
      action: 'payment.reconciled',
      targetType: 'payment',
      targetId: event.txRef || String(event.id),
      targetLabel: `Webhook ${event.event}`,
      reason: 'Signed webhook of an unhandled type was recorded without side effects.',
      status: 'succeeded',
      stepUp: false,
      ipHash,
      metadata: { source: 'flutterwave_webhook', event: event.event },
    });
  }

  return response;
}
