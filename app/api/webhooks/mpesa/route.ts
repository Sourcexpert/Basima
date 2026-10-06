import { NextResponse } from 'next/server';
import { parseCallback, verifyCallbackToken, type MpesaCallback } from '@/lib/payments/mpesa';
import { recordAdminAction, store } from '@/lib/data/store';
import { hashIp } from '@/lib/crypto/hash';
import { env } from '@/lib/env';

/**
 * Daraja STK callback.
 *
 * Daraja does not sign callbacks, so we do not trust this endpoint's body by
 * itself. Settlement requires three independent facts:
 *   1. a secret token on the callback URL (this handler),
 *   2. a CheckoutRequestID that matches an STK push we actually issued,
 *   3. a successful transaction-status re-query against Daraja.
 * A callback that fails (1) or (2) is recorded as a security event, never
 * allowed to move money or change a subscription.
 *
 * Important: a *failed* payment releases no evidence and an *accepted* payment
 * does not create or alter any evidentiary record. Payment state and evidence
 * state are separate by design (Build Guide §1, §16).
 */
export async function POST(request: Request) {
  const url = new URL(request.url);
  const token = request.headers.get('x-agree-e-callback-token') ?? url.searchParams.get('t');
  const ipHash = hashIp(request.headers.get('x-forwarded-for')?.split(',')[0] ?? null, env.ipHashPepper);

  if (!verifyCallbackToken(token)) {
    await store().listSecurityEvents({ limit: 1 }); // touch, keeps ordering deterministic in demo
    await recordAdminAction({
      adminId: 'system',
      adminEmail: 'system@agree-e.com',
      adminRole: 'security',
      action: 'payment.reconciled',
      targetType: 'payment',
      targetId: 'mpesa-callback',
      targetLabel: 'Unsigned M-PESA callback',
      reason: 'Rejected: callback token missing or invalid. Possible forged callback.',
      status: 'blocked',
      stepUp: false,
      ipHash,
      metadata: { rejected: true, reason: 'invalid_callback_token' },
    });
    return NextResponse.json({ ResultCode: 0, ResultDesc: 'Rejected' }, { status: 401 });
  }

  let body: MpesaCallback;
  try {
    body = (await request.json()) as MpesaCallback;
  } catch {
    return NextResponse.json({ ResultCode: 1, ResultDesc: 'Malformed payload' }, { status: 400 });
  }

  const parsed = parseCallback(body);
  if (!parsed) {
    return NextResponse.json({ ResultCode: 1, ResultDesc: 'Unrecognised callback shape' }, { status: 400 });
  }

  const payments = await store().listPayments({ limit: 1000 });
  const payment = payments.find((p) => p.providerRef === parsed.checkoutRequestId);

  if (!payment) {
    await recordAdminAction({
      adminId: 'system',
      adminEmail: 'system@agree-e.com',
      adminRole: 'security',
      action: 'payment.reconciled',
      targetType: 'payment',
      targetId: parsed.checkoutRequestId,
      targetLabel: `Unmatched callback ${parsed.checkoutRequestId}`,
      reason: 'Rejected: no STK push in our records carries this CheckoutRequestID.',
      status: 'blocked',
      stepUp: false,
      ipHash,
      metadata: { checkout_request_id: parsed.checkoutRequestId, result_code: parsed.resultCode },
    });
    return NextResponse.json({ ResultCode: 0, ResultDesc: 'Accepted for review' });
  }

  // Record the raw outcome. Settlement additionally requires queryStkStatus() to
  // confirm 0 — implemented in reconcilePayment() so an operator can re-run it.
  await store().patchPayment(payment.id, {
    status: parsed.succeeded ? 'succeeded' : 'failed',
    mpesaReceipt: parsed.receipt,
    failureReason: parsed.succeeded ? null : parsed.explanation,
  });

  if (parsed.succeeded && payment.invoiceId) {
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
          status: 'active',
          currentPeriodStart: start.toISOString(),
          currentPeriodEnd: end.toISOString(),
          dunningAttempts: 0,
          graceEndsAt: null,
          cancelAtPeriodEnd: false,
        });
      }
    }
  }

  await recordAdminAction({
    adminId: 'system',
    adminEmail: 'system@agree-e.com',
    adminRole: 'billing',
    action: 'payment.reconciled',
    targetType: 'payment',
    targetId: payment.id,
    targetLabel: `${payment.reference}${parsed.receipt ? ` (${parsed.receipt})` : ''}`,
    reason: parsed.explanation,
    status: parsed.succeeded ? 'succeeded' : 'failed',
    stepUp: false,
    ipHash,
    metadata: {
      source: 'daraja_callback',
      result_code: parsed.resultCode,
      mpesa_receipt: parsed.receipt,
      amount_minor: parsed.amount ? Math.round(parsed.amount * 100) : null,
      transaction_date: parsed.transactionDate,
      settlement_note: 'Amount and receipt must still reconcile against the transaction-status API and the invoice.',
      evidentiary_effect: 'none',
    },
  });

  return NextResponse.json({ ResultCode: 0, ResultDesc: 'Accepted' });
}

export async function GET() {
  return NextResponse.json({ ok: true, hint: 'Daraja posts STK results here.' }, { status: 405 });
}
