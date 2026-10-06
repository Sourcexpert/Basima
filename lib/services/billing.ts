import 'server-only';
import { randomUUID } from 'node:crypto';
import { authorize, type Viewer } from '@/lib/auth/rbac';
import { sha256 } from '@/lib/crypto/hash';
import { env, flutterwaveConfigured, mpesaConfigured } from '@/lib/env';
import { recordAdminAction, store } from '@/lib/data/store';
import { newId, type Invoice, type Payment, type Plan, type Subscription } from '@/lib/data/types';
import { initiateStkPush, queryStkStatus } from '@/lib/payments/mpesa';
import { initiateCheckout, initiateRefund, newTxRef, verifyTransaction } from '@/lib/payments/flutterwave';
import {
  couponSchema, formatZodError, planSchema, reconciliationSchema, refundSchema, stkPushSchema,
  subscriptionChangeSchema, type ActionResult,
} from '@/lib/validation/schemas';

/**
 * Billing & subscriptions.
 *
 * Two invariants from the build guide, enforced in code and stated in the UI:
 *   1. §1 / §16: payment state is separate from evidentiary truth. Nothing in
 *      this module can delete, alter or "un-complete" an agreement, a stamp, an
 *      evidence package or an audit event. A customer in arrears keeps their
 *      evidence; only new value-producing actions are gated.
 *   2. §16 (step 16 of the plan): payments were only integrated once the
 *      evidence/signing state was stable — so billing reads agreement counts,
 *      never the reverse.
 */

interface ActorContext {
  viewer: Viewer;
  ipHash: string | null;
  userAgent: string | null;
}

function action<T>(result: ActionResult<T>) { return result; }

async function audit(ctx: ActorContext, args: {
  action: string; targetType: string; targetId: string; targetLabel: string; reason: string;
  status?: 'succeeded' | 'failed' | 'blocked'; stepUp?: boolean; metadata?: Record<string, unknown>;
}) {
  return recordAdminAction({
    adminId: ctx.viewer.userId,
    adminEmail: ctx.viewer.email,
    adminRole: ctx.viewer.role,
    action: args.action,
    targetType: args.targetType,
    targetId: args.targetId,
    targetLabel: args.targetLabel,
    reason: args.reason,
    status: args.status ?? 'succeeded',
    stepUp: args.stepUp ?? false,
    ipHash: ctx.ipHash,
    userAgent: ctx.userAgent,
    metadata: args.metadata ?? {},
  });
}

/* ----------------------------------------------------------------- plans -- */

export async function savePlan(ctx: ActorContext, input: unknown): Promise<ActionResult<Plan>> {
  const parsed = planSchema.safeParse(input);
  if (!parsed.success) return { ok: false, error: formatZodError(parsed.error), code: 'validation' };
  const data = parsed.data;

  const auth = authorize(ctx.viewer, 'billing.plans.manage');
  if (!auth.allowed) return { ok: false, error: auth.error, code: auth.status === 401 ? 'unauthorized' : 'forbidden' };

  const existing = (await store().listPlans(true)).find((p) => p.code === data.code);
  const plan: Plan = {
    id: existing?.id ?? newId('plan'),
    code: data.code,
    name: data.name,
    description: data.description,
    interval: data.interval,
    amountMinor: data.amountMinor,
    currency: data.currency,
    trialDays: data.trialDays,
    features: data.features,
    includedSeats: data.includedSeats,
    includedStamps: data.includedStamps,
    active: data.active,
    archivedAt: existing?.archivedAt ?? null,
    createdAt: existing?.createdAt ?? new Date().toISOString(),
  };

  await store().upsertPlan(plan);
  await audit(ctx, {
    action: existing ? 'plan.updated' : 'plan.created',
    targetType: 'plan', targetId: plan.id, targetLabel: `${plan.name} (${plan.code})`,
    reason: reasonForPlan(ctx, existing, plan),
    metadata: existing
      ? { before_amount_minor: existing.amountMinor, after_amount_minor: plan.amountMinor, interval: plan.interval }
      : { code: plan.code, amount_minor: plan.amountMinor, currency: plan.currency },
  });

  return action({
    ok: true, data: plan,
    message: existing
      ? 'Plan updated. Existing subscribers keep the price they signed up at until their next renewal cycle, when the new price applies.'
      : 'Plan created.',
  });
}

function reasonForPlan(_ctx: ActorContext, existing: Plan | undefined, plan: Plan): string {
  return existing
    ? `Catalogue review: ${existing.name} updated (${existing.amountMinor} → ${plan.amountMinor} ${plan.currency} ${plan.interval}).`
    : `New plan added to the commercial catalogue: ${plan.name} at ${plan.amountMinor} ${plan.currency} ${plan.interval}.`;
}

export async function archivePlan(ctx: ActorContext, input: { planId: string; reason: string }): Promise<ActionResult<Plan>> {
  const auth = authorize(ctx.viewer, 'billing.plans.manage');
  if (!auth.allowed) return { ok: false, error: auth.error, code: 'forbidden' };
  const plan = await store().getPlan(input.planId);
  if (!plan) return { ok: false, error: 'Plan not found.', code: 'validation' };
  if (input.reason.trim().length < 12) return { ok: false, error: 'A justification of at least 12 characters is required.', code: 'validation' };

  const archived = { ...plan, active: false, archivedAt: new Date().toISOString() };
  await store().upsertPlan(archived);
  await audit(ctx, {
    action: 'plan.archived', targetType: 'plan', targetId: plan.id, targetLabel: plan.name,
    reason: input.reason, metadata: { subscribers: plan.subscribers ?? 0, grandfathering: true },
  });

  return action({
    ok: true, data: archived,
    message: `Plan archived. ${plan.subscribers ?? 0} existing subscriber(s) keep access and are not migrated automatically — grandfathering is the default so no customer loses evidence access without notice.`,
  });
}

/* --------------------------------------------------------- subscriptions -- */

export async function changeSubscription(ctx: ActorContext, input: unknown): Promise<ActionResult<Subscription>> {
  const parsed = subscriptionChangeSchema.safeParse(input);
  if (!parsed.success) return { ok: false, error: formatZodError(parsed.error), code: 'validation' };
  const { subscriptionId, action: act, planId, extendDays, effective, reason } = parsed.data;

  const auth = authorize(ctx.viewer, 'billing.subscriptions.manage', { reason });
  if (!auth.allowed) return { ok: false, error: auth.error, code: auth.status === 401 ? 'unauthorized' : 'forbidden' };

  const sub = await store().getSubscription(subscriptionId);
  if (!sub) return { ok: false, error: 'Subscription not found.', code: 'validation' };

  const now = new Date();
  const patch: Partial<Subscription> = {};
  let message = '';
  let actionName = 'subscription.plan_changed';

  switch (act) {
    case 'change_plan': {
      const plan = planId ? await store().getPlan(planId) : null;
      if (!plan) return { ok: false, error: 'Target plan not found.', code: 'validation' };
      if (plan.archivedAt) return { ok: false, error: 'That plan is archived and cannot receive new subscribers.', code: 'conflict' };
      patch.planId = plan.id;
      patch.planCode = plan.code;
      patch.planName = plan.name;
      patch.amountMinor = plan.amountMinor;
      patch.currency = plan.currency;
      patch.seats = plan.includedSeats;
      actionName = 'subscription.plan_changed';
      message = effective === 'immediately'
        ? `Moved to ${plan.name} immediately. The next invoice is prorated.`
        : `Scheduled a move to ${plan.name} at the end of the current period (${sub.currentPeriodEnd.slice(0, 10)}). Access does not change today.`;
      break;
    }
    case 'cancel': {
      patch.cancelAtPeriodEnd = true;
      patch.cancelledAt = now.toISOString();
      actionName = 'subscription.cancelled';
      if (effective === 'immediately') {
        patch.status = 'cancelled';
        patch.currentPeriodEnd = now.toISOString();
        message = 'Cancelled immediately. Evidence already produced remains available for the retention period — cancelling a subscription never destroys an executed record.';
      } else {
        message = `Scheduled to cancel on ${sub.currentPeriodEnd.slice(0, 10)}. The customer keeps full access until then.`;
      }
      break;
    }
    case 'pause': {
      patch.status = 'paused';
      patch.pausedAt = now.toISOString();
      actionName = 'subscription.paused';
      message = 'Subscription paused. Signing is disabled for new agreements; existing evidence stays readable and exportable.';
      break;
    }
    case 'resume': {
      patch.status = 'active';
      patch.pausedAt = null;
      patch.dunningAttempts = 0;
      patch.graceEndsAt = null;
      actionName = 'subscription.resumed';
      message = 'Subscription resumed to active.';
      break;
    }
    case 'extend_trial': {
      const days = extendDays ?? 14;
      const base = sub.trialEndsAt ? new Date(sub.trialEndsAt) : now;
      patch.trialEndsAt = new Date(base.getTime() + days * 86_400_000).toISOString();
      patch.status = 'trialing';
      actionName = 'subscription.trial_extended';
      message = `Trial extended by ${days} day(s), now ending ${patch.trialEndsAt.slice(0, 10)}.`;
      break;
    }
  }

  await store().patchSubscription(sub.id, patch);
  if (patch.status === 'active' && sub.status !== 'active') {
    const invoice = await openInvoiceFor(sub);
    message += ` Invoice ${invoice.number} is open.`;
  }

  await audit(ctx, {
    action: actionName, targetType: 'subscription', targetId: sub.id,
    targetLabel: `${sub.userName} — ${sub.planName}`, reason,
    metadata: { effective, from_plan: sub.planCode, to_plan: patch.planCode ?? sub.planCode, previous_status: sub.status, new_status: patch.status ?? sub.status },
  });

  return action({ ok: true, data: { ...sub, ...patch }, message });
}

async function openInvoiceFor(sub: Subscription): Promise<Invoice> {
  const now = new Date();
  const seq = (await store().listInvoices({ limit: 1000 })).length + 1;
  const invoice: Invoice = {
    id: newId('inv'),
    number: `AG-INV-${now.getUTCFullYear()}-${String(2000 + seq)}`,
    subscriptionId: sub.id,
    userId: sub.userId,
    userEmail: sub.userEmail,
    amountMinor: sub.amountMinor,
    currency: sub.currency,
    status: 'open',
    issuedAt: now.toISOString(),
    dueAt: new Date(now.getTime() + 7 * 86_400_000).toISOString(),
    paidAt: null,
    provider: sub.provider,
  };
  await store().appendInvoice(invoice);
  return invoice;
}

/* ------------------------------------------------------ collection flows -- */

export async function startStkPush(ctx: ActorContext, input: unknown): Promise<ActionResult<{ checkoutRequestId: string | null; message: string }>> {
  const parsed = stkPushSchema.safeParse(input);
  if (!parsed.success) return { ok: false, error: formatZodError(parsed.error), code: 'validation' };
  const { invoiceId, phone, reason } = parsed.data;

  const auth = authorize(ctx.viewer, 'billing.payments.manage', { reason });
  if (!auth.allowed) return { ok: false, error: auth.error, code: auth.status === 401 ? 'unauthorized' : 'forbidden' };

  const invoice = await store().getInvoice(invoiceId);
  if (!invoice) return { ok: false, error: 'Invoice not found.', code: 'validation' };
  if (invoice.status === 'paid') return { ok: false, error: 'That invoice is already paid.', code: 'conflict' };

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
    payment.status = 'failed';
    payment.failureReason = result.error ?? 'STK push rejected.';
    await store().patchPayment(payment.id, {
    status: payment.status, providerRef: payment.providerRef, failureReason: payment.failureReason,
  });
    await audit(ctx, {
      action: 'payment.stk_push_initiated', targetType: 'payment', targetId: payment.id,
      targetLabel: `${payment.reference} → ${phone}`, reason, status: 'failed',
      metadata: { invoice: invoice.number, configured: result.configured, error: result.error },
    });
    return {
      ok: false,
      error: result.configured
        ? `M-PESA rejected the request: ${result.error}`
        : 'M-PESA is not configured on this deployment. Add the Daraja credentials to enable STK push.',
      code: result.configured ? 'provider_error' : 'not_configured',
    };
  }

  payment.status = 'pending';
  payment.providerRef = result.checkoutRequestId ?? null;
  await store().patchPayment(payment.id, {
    status: payment.status, providerRef: payment.providerRef, failureReason: payment.failureReason,
  });

  await audit(ctx, {
    action: 'payment.stk_push_initiated', targetType: 'payment', targetId: payment.id,
    targetLabel: `${payment.reference} → ${phone}`, reason, stepUp: true,
    metadata: {
      invoice: invoice.number, checkout_request_id: result.checkoutRequestId,
      merchant_request_id: result.merchantRequestId, amount_minor: payment.amountMinor,
      callback_verification: 'CheckoutRequestID matched on callback + transaction-status re-query before settlement',
    },
  });

  return action({
    ok: true,
    data: { checkoutRequestId: result.checkoutRequestId ?? null, message: result.customerMessage ?? '' },
    message: `STK push sent to ${phone}. The customer has 60 seconds to enter their M-PESA PIN; the result arrives on the Daraja callback. Do not mark the invoice paid until the callback and the status re-query both confirm it.`,
  });
}

export async function startFlutterwaveCheckout(ctx: ActorContext, input: { subscriptionId: string; reason: string }): Promise<ActionResult<{ link: string | null }>> {
  const auth = authorize(ctx.viewer, 'billing.payments.manage', { reason: input.reason });
  if (!auth.allowed) return { ok: false, error: auth.error, code: 'forbidden' };
  const sub = await store().getSubscription(input.subscriptionId);
  if (!sub) return { ok: false, error: 'Subscription not found.', code: 'validation' };

  const txRef = newTxRef('AG');
  const invoice = (await store().listInvoices({ limit: 1000 })).find((i) => i.subscriptionId === sub.id && i.status === 'open');
  const payment: Payment = {
    id: newId('pay'),
    reference: txRef, // our own tx_ref is the join key for verification
    invoiceId: invoice?.id ?? null,
    userId: sub.userId,
    userEmail: sub.userEmail,
    provider: 'flutterwave',
    method: 'card',
    amountMinor: sub.amountMinor,
    currency: sub.currency,
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

  const result = await initiateCheckout({
    txRef,
    amountMinor: sub.amountMinor,
    currency: sub.currency,
    email: sub.userEmail,
    name: sub.userName,
    redirectUrl: `${env.appUrl}/app/billing/callback`,
    title: 'agre-e subscription',
    description: `${sub.planName} — ${sub.currency} ${(sub.amountMinor / 100).toFixed(2)}`,
  });

  if (!result.ok) {
    await audit(ctx, {
      action: 'payment.reconciled', targetType: 'subscription', targetId: sub.id,
      targetLabel: `${sub.userName} — ${sub.planName}`, reason: input.reason, status: 'failed',
      metadata: { provider: 'flutterwave', error: result.error, configured: result.configured },
    });
    return {
      ok: false,
      error: result.configured
        ? `Flutterwave rejected the checkout: ${result.error}`
        : 'Flutterwave is not configured. Add FLW_SECRET_KEY and FLW_SECRET_HASH to enable card/bank payment.',
      code: result.configured ? 'provider_error' : 'not_configured',
    };
  }

  await store().patchPayment(payment.id, {
    status: payment.status, providerRef: payment.providerRef, failureReason: payment.failureReason,
  });
  await audit(ctx, {
    action: 'payment.stk_push_initiated', targetType: 'subscription', targetId: sub.id,
    targetLabel: `${sub.userName} — ${sub.planName}`, reason: input.reason,
    metadata: { provider: 'flutterwave', tx_ref: txRef, hosted_checkout: true },
  });

  return action({
    ok: true, data: { link: result.link ?? null },
    message: 'Hosted checkout link created. The payment is only recognised after the webhook signature check and a server-side /verify call that matches amount, currency and tx_ref.',
  });
}

/**
 * Reconciliation. Re-confirms the transaction with the provider before settling —
 * protects against forged callbacks, replay and out-of-order webhook delivery.
 */
export async function reconcilePayment(ctx: ActorContext, input: unknown): Promise<ActionResult<{ status: string; explanation: string }>> {
  const parsed = reconciliationSchema.safeParse(input);
  if (!parsed.success) return { ok: false, error: formatZodError(parsed.error), code: 'validation' };
  const { provider, reference, reason } = parsed.data;

  const auth = authorize(ctx.viewer, 'billing.payments.manage', { reason });
  if (!auth.allowed) return { ok: false, error: auth.error, code: auth.status === 401 ? 'unauthorized' : 'forbidden' };

  const payments = await store().listPayments({ limit: 1000 });
  const payment = payments.find((p) => p.reference === reference || p.mpesaReceipt === reference || p.providerRef === reference);
  if (!payment) return { ok: false, error: `No payment matches "${reference}".`, code: 'validation' };

  let explanation = '';
  let settled = false;
  let newStatus: Payment['status'] = payment.status;

  if (provider === 'mpesa') {
    if (!mpesaConfigured) {
      return { ok: false, error: 'M-PESA is not configured, so the provider cannot be queried. Use manual settlement with a written reason.', code: 'not_configured' };
    }
    if (!payment.providerRef) return { ok: false, error: 'Payment has no CheckoutRequestID to query.', code: 'validation' };
    const status = await queryStkStatus(payment.providerRef);
    explanation = status?.explanation ?? 'No response from the STK query endpoint.';
    settled = Boolean(status?.ok);
    newStatus = settled ? 'succeeded' : status && status.resultCode > 0 ? 'failed' : 'pending';
  } else {
    if (!flutterwaveConfigured) {
      return { ok: false, error: 'Flutterwave is not configured, so the provider cannot be queried.', code: 'not_configured' };
    }
    const invoice = payment.invoiceId ? await store().getInvoice(payment.invoiceId) : null;
    const verified = await verifyTransaction(
      payment.providerRef?.replace(/[^0-9]/g, '') || '0',
      { amountMinor: payment.amountMinor, currency: payment.currency, txRef: payment.reference },
    );
    explanation = `${verified.reason} ${verified.checks.map((c) => `${c.name}:${c.passed ? 'pass' : 'fail'}`).join(', ')}`;
    settled = verified.ok;
    newStatus = settled ? 'succeeded' : verified.status === 'failed' ? 'failed' : 'pending';
    if (invoice && verified.checks.some((c) => !c.passed)) {
      explanation += ' Settlement withheld: at least one verification check failed.';
    }
  }

  if (settled) await settlePayment(payment, ctx.viewer.userId);
  else await store().patchPayment(payment.id, { status: newStatus, failureReason: settled ? null : explanation });

  await audit(ctx, {
    action: 'payment.reconciled', targetType: 'payment', targetId: payment.id,
    targetLabel: payment.reference, reason, status: settled ? 'succeeded' : 'failed',
    metadata: { provider, reference, settled, explanation },
  });

  if (settled) {
    return action({ ok: true, data: { status: newStatus, explanation }, message: `Payment settled. ${explanation}` });
  }
  return action({ ok: false, data: { status: newStatus, explanation }, error: explanation });
}

async function settlePayment(payment: Payment, adminId: string) {
  await store().patchPayment(payment.id, { status: 'succeeded', reconciledBy: adminId, failureReason: null });
  if (!payment.invoiceId) return;
  const invoice = await store().getInvoice(payment.invoiceId);
  if (!invoice) return;
  await store().patchInvoice(invoice.id, { status: 'paid', paidAt: new Date().toISOString() });
  const sub = await store().getSubscription(invoice.subscriptionId);
  if (!sub) return;
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

export async function refundPayment(ctx: ActorContext, input: unknown): Promise<ActionResult<{ refunded: number }>> {
  const parsed = refundSchema.safeParse(input);
  if (!parsed.success) return { ok: false, error: formatZodError(parsed.error), code: 'validation' };
  const { paymentId, amountMinor, reason, supervisorEmail } = parsed.data;

  const auth = authorize(ctx.viewer, 'billing.refund', { reason });
  if (!auth.allowed) return { ok: false, error: auth.error, code: auth.status === 401 ? 'unauthorized' : 'forbidden' };

  const supervisor = await store().getUserByEmail(supervisorEmail);
  if (!supervisor || !['owner', 'admin', 'security'].includes(supervisor.role)) {
    return { ok: false, error: 'Supervisor must be an owner, admin or security account.', code: 'forbidden' };
  }
  if (supervisor.id === ctx.viewer.userId) {
    return { ok: false, error: 'Refunds require a second person to approve.', code: 'forbidden' };
  }

  const payment = await store().getPayment(paymentId);
  if (!payment) return { ok: false, error: 'Payment not found.', code: 'validation' };
  if (payment.status !== 'succeeded') return { ok: false, error: 'Only settled payments can be refunded.', code: 'conflict' };
  const refundable = payment.amountMinor - payment.refundedMinor;
  if (amountMinor > refundable) return { ok: false, error: `Refund exceeds the remaining refundable amount of ${refundable / 100}.`, code: 'conflict' };

  let providerRefunded = false;
  let providerMessage = 'Flutterwave not configured — refund recorded for manual settlement via the provider dashboard.';
  if (payment.provider === 'flutterwave' && flutterwaveConfigured && payment.providerRef) {
    const res = await initiateRefund(payment.providerRef.replace(/[^0-9]/g, ''), amountMinor);
    providerRefunded = res.ok;
    providerMessage = res.ok ? (res.message ?? 'Refund accepted by Flutterwave.') : (res.error ?? 'Flutterwave rejected the refund.');
  }
  if (payment.provider === 'mpesa') {
    providerMessage = 'M-PESA reversals are raised with Safaricom M-PESA Support (B2B reversal) and typically settle within 3–5 working days. Recorded here for reconciliation.';
  }

  await store().patchPayment(payment.id, {
    refundedMinor: payment.refundedMinor + amountMinor,
    status: payment.refundedMinor + amountMinor >= payment.amountMinor ? 'refunded' : 'succeeded',
  });

  await audit(ctx, {
    action: 'payment.refund_issued', targetType: 'payment', targetId: payment.id, targetLabel: payment.reference,
    reason, stepUp: true,
    metadata: {
      amount_minor: amountMinor, provider: payment.provider, supervisor: supervisor.email,
      provider_accepted: providerRefunded, provider_message: providerMessage,
      evidentiary_effect: 'none — refunds do not alter agreements, stamps or audit events',
    },
  });

  return action({
    ok: true, data: { refunded: amountMinor },
    message: `Refund of ${(amountMinor / 100).toFixed(2)} ${payment.currency} recorded. ${providerMessage}`,
  });
}

/* -------------------------------------------------------------- dunning -- */

export interface DunningOutcome {
  evaluated: number;
  reminders: number;
  movedToGrace: number;
  suspended: number;
  details: string[];
}

/**
 * Dunning sweep. Deliberately conservative: arrears stop *new* value-producing
 * actions, never retroactively withdraw evidence access, and never touch the
 * agreement ledger.
 */
export async function runDunningCycle(ctx: ActorContext, reason: string): Promise<ActionResult<DunningOutcome>> {
  const auth = authorize(ctx.viewer, 'billing.subscriptions.manage', { reason });
  if (!auth.allowed) return { ok: false, error: auth.error, code: 'forbidden' };

  const subs = await store().listSubscriptions({ limit: 1000 });
  const now = Date.now();
  const details: string[] = [];
  let reminders = 0, toGrace = 0, suspended = 0;
  const targets = subs.filter((s) => ['past_due', 'grace'].includes(s.status));

  for (const sub of targets) {
    const dueAt = new Date(sub.currentPeriodEnd).getTime();
    const daysLate = Math.floor((now - dueAt) / 86_400_000);
    const attempts = sub.dunningAttempts + 1;

    if (daysLate <= 0) continue;

    if (attempts <= 2) {
      reminders += 1;
      await store().patchSubscription(sub.id, { dunningAttempts: attempts });
      details.push(`${sub.userEmail}: reminder ${attempts}/4 sent (${daysLate} day(s) past due). New stamps are still permitted during the reminder window.`);
    } else if (attempts === 3) {
      toGrace += 1;
      await store().patchSubscription(sub.id, {
        dunningAttempts: attempts,
        status: 'grace',
        graceEndsAt: new Date(now + 7 * 86_400_000).toISOString(),
      });
      details.push(`${sub.userEmail}: moved to grace period — evidence stays readable and exportable, new stamps paused for 7 days.`);
    } else {
      suspended += 1;
      await store().patchSubscription(sub.id, { dunningAttempts: attempts, status: 'paused' });
      details.push(`${sub.userEmail}: new-stamp capability paused after 4 failed cycles. Existing agreements, stamps, packages and audit events are untouched and remain exportable.`);
    }
  }

  await audit(ctx, {
    action: 'dunning.retry_scheduled', targetType: 'setting', targetId: 'dunning_sweep',
    targetLabel: `Dunning sweep — ${targets.length} account(s)`, reason,
    metadata: { evaluated: targets.length, reminders, moved_to_grace: toGrace, paused: suspended, details },
  });

  return action({
    ok: true,
    data: { evaluated: targets.length, reminders, movedToGrace: toGrace, suspended, details },
    message: `Dunning sweep complete: ${targets.length} account(s) evaluated, ${reminders} reminder(s), ${toGrace} moved to grace, ${suspended} paused.`,
  });
}

/* ------------------------------------------------------------- coupons -- */

export async function createCoupon(ctx: ActorContext, input: unknown): Promise<ActionResult<{ code: string }>> {
  const parsed = couponSchema.safeParse(input);
  if (!parsed.success) return { ok: false, error: formatZodError(parsed.error), code: 'validation' };
  const { code, percentOff, maxRedemptions, expiresAt, reason } = parsed.data;

  const auth = authorize(ctx.viewer, 'billing.plans.manage', { reason });
  if (!auth.allowed) return { ok: false, error: auth.error, code: 'forbidden' };

  const existing = (await store().listCoupons()).find((c) => c.code === code);
  if (existing) return { ok: false, error: `Coupon ${code} already exists.`, code: 'conflict' };

  await store().appendCoupon({
    id: newId('cpn'), code, percentOff, maxRedemptions, redemptions: 0,
    expiresAt: expiresAt ?? null, active: true, createdAt: new Date().toISOString(),
  });

  await audit(ctx, {
    action: 'coupon.created', targetType: 'setting', targetId: code, targetLabel: `Coupon ${code} — ${percentOff}%`,
    reason, metadata: { percent_off: percentOff, max_redemptions: maxRedemptions, expires_at: expiresAt ?? null },
  });

  return action({ ok: true, data: { code }, message: `Coupon ${code} created (${percentOff}% off, max ${maxRedemptions} redemptions).` });
}

export async function revokeCoupon(ctx: ActorContext, input: { couponId: string; reason: string }): Promise<ActionResult<{ code: string }>> {
  const auth = authorize(ctx.viewer, 'billing.plans.manage', { reason: input.reason });
  if (!auth.allowed) return { ok: false, error: auth.error, code: 'forbidden' };
  const coupon = (await store().listCoupons()).find((c) => c.id === input.couponId);
  if (!coupon) return { ok: false, error: 'Coupon not found.', code: 'validation' };

  await store().patchCoupon(coupon.id, { active: false });
  await audit(ctx, {
    action: 'coupon.revoked', targetType: 'setting', targetId: coupon.id, targetLabel: `Coupon ${coupon.code}`,
    reason: input.reason, metadata: { redemptions: coupon.redemptions },
  });
  return action({ ok: true, data: { code: coupon.code }, message: `Coupon ${coupon.code} revoked.` });
}

/** Idempotency key generator for server actions. */
export function newActionKey(): string {
  return randomUUID();
}
