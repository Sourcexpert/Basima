import 'server-only';
import { store } from '@/lib/data/store';
import { initiateStkPush } from '@/lib/payments/mpesa';
import { sha256 } from '@/lib/crypto/hash';
import { newId, type Payment } from '@/lib/data/types';
import { formatZodError, userPaymentSchema } from '@/lib/validation/user-schemas';
import type { ActionResult } from '@/lib/validation/schemas';

/**
 * Customer-initiated payments.
 *
 * Deliberately NOT routed through `lib/services/billing.ts`: that module is the
 * console's, and every one of its entry points begins with an operator
 * capability check. A customer paying their own invoice holds no console
 * capability, and inventing one for them would soften exactly the boundary the
 * console exists to hold.
 *
 * What *is* shared is the provider client (`initiateStkPush`), so the Daraja
 * contract — password construction, timestamp, reference limits, result-code
 * mapping — is implemented once.
 *
 * The same rule applies on both surfaces: a payment is never recorded as settled
 * here. Settlement happens only in the webhook, after the callback is
 * authenticated and the transaction is re-queried with Daraja.
 */
export interface UserPaymentInput {
  invoiceId: string;
  phone: string;
  idempotencyKey: string;
}

export async function startOwnStkPush(
  ctx: { viewer: { userId: string; email: string }; ipHash: string | null; userAgent: string | null },
  input: unknown,
): Promise<ActionResult<{ paymentId: string; checkoutRequestId: string | null }>> {
  const parsed = userPaymentSchema.safeParse(input);
  if (!parsed.success) return { ok: false, error: formatZodError(parsed.error), code: 'validation' };

  const invoice = await store().getInvoice(parsed.data.invoiceId);
  if (!invoice) return { ok: false, error: 'That invoice does not exist.', code: 'validation' };
  if (invoice.userId !== ctx.viewer.userId) {
    // Ownership is checked here, not inferred from the form field.
    return { ok: false, error: 'That invoice does not belong to your account.', code: 'forbidden' };
  }
  if (invoice.status === 'paid') return { ok: false, error: 'That invoice is already paid.', code: 'conflict' };

  // Idempotency: an impatient double-tap must not send two prompts.
  const recent = (await store().listPayments({ limit: 200 })).find(
    (p) => p.invoiceId === invoice.id && p.status === 'pending' && Date.now() - new Date(p.createdAt).getTime() < 120_000,
  );
  if (recent) {
    return {
      ok: false,
      code: 'conflict',
      error: `A payment prompt was already sent for this invoice ${Math.round((Date.now() - new Date(recent.createdAt).getTime()) / 1000)} seconds ago. Enter your PIN on your phone, or wait two minutes and try again.`,
    };
  }

  const phone = parsed.data.phone.replace(/^0/, '254').replace(/^\+/, '');
  const payment: Payment = {
    id: newId('pay'),
    reference: `PAY-${sha256(`${invoice.id}:${Date.now()}`).slice(0, 8).toUpperCase()}`,
    invoiceId: invoice.id,
    userId: invoice.userId,
    userEmail: invoice.userEmail,
    provider: 'mpesa',
    method: 'mpesa_stk',
    amountMinor: invoice.amountMinor,
    currency: invoice.currency,
    status: 'initiated',
    providerRef: null,
    mpesaReceipt: null,
    failureReason: null,
    reconciledBy: null,
    refundedMinor: 0,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  await store().appendPayment(payment);

  const result = await initiateStkPush({
    phone,
    amountKes: Math.round(invoice.amountMinor / 100),
    accountReference: invoice.number.replace(/[^A-Za-z0-9]/g, '').slice(-12),
    description: 'agree subscription',
  });

  if (!result.ok) {
    await store().patchPayment(payment.id, { status: 'failed', failureReason: result.error ?? 'STK push rejected.' });
    return {
      ok: false,
      code: result.configured ? 'provider_error' : 'not_configured',
      error: result.configured
        ? `M-PESA rejected the request: ${result.error}`
        : 'M-PESA is not configured on this deployment, so no payment was started and nothing was charged. Use the bank details on your invoice, or contact support.',
    };
  }

  await store().patchPayment(payment.id, { status: 'pending', providerRef: result.checkoutRequestId ?? null });

  return {
    ok: true,
    data: { paymentId: payment.id, checkoutRequestId: result.checkoutRequestId ?? null },
    message: `A payment prompt has been sent to ${phone}. Approve it on your handset with your M-PESA PIN. This invoice stays open until the network confirms the payment to us — an approved prompt that times out is not a payment, and we will not record it as one.`,
  };
}
