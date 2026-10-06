import 'server-only';
import { env, flutterwaveConfigured } from '@/lib/env';
import { randomToken, safeEqual } from '@/lib/crypto/hash';

/**
 * Flutterwave v3 — cards, bank transfer, USSD and mobile money.
 *
 * Verified contract:
 *   • Initiate checkout: POST https://api.flutterwave.com/v3/payments with
 *     tx_ref, amount, currency, redirect_url, customer, customizations. Response
 *     carries data.link for the hosted checkout.
 *   • Verify: GET /v3/transactions/{id}/verify with Bearer secret key. Four
 *     checks are mandatory before delivering value: status === 'successful',
 *     amount, currency and tx_ref all match what we expected.
 *   • Webhooks: Flutterwave sends the configured secret hash verbatim in the
 *     `verif-hash` header. Requests whose header is missing or wrong are
 *     discarded with 401 — and recorded as a security event.
 */

const API = 'https://api.flutterwave.com/v3';

export interface CheckoutResult {
  ok: boolean;
  configured: boolean;
  link?: string;
  txRef?: string;
  error?: string;
}

export function newTxRef(prefix = 'AG'): string {
  // Unique, non-guessable, and tied back to our own records — never trust the
  // reference the customer returns in the redirect.
  return `${prefix}-${Date.now().toString(36).toUpperCase()}-${randomToken(6).toUpperCase()}`;
}

export async function initiateCheckout(args: {
  txRef: string; amountMinor: number; currency: string; email: string; name: string; phone?: string | null;
  redirectUrl: string; title?: string; description?: string;
}): Promise<CheckoutResult> {
  if (!flutterwaveConfigured) {
    return { ok: false, configured: false, error: 'Flutterwave is not configured. Set FLW_SECRET_KEY and FLW_SECRET_HASH.' };
  }
  const res = await fetch(`${API}/payments`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${env.flutterwave.secretKey}`, 'Content-Type': 'application/json' },
    cache: 'no-store',
    body: JSON.stringify({
      tx_ref: args.txRef,
      amount: (args.amountMinor / 100).toFixed(2),
      currency: args.currency,
      redirect_url: args.redirectUrl,
      payment_options: 'card,banktransfer,ussd,mobilemoney',
      customer: { email: args.email, name: args.name, phonenumber: args.phone ?? undefined },
      customizations: {
        title: args.title ?? 'agre-e',
        description: args.description ?? 'Subscription payment',
      },
    }),
  });
  const json = (await res.json().catch(() => ({}))) as { status?: string; message?: string; data?: { link?: string } };
  if (!res.ok || json.status !== 'success' || !json.data?.link) {
    return { ok: false, configured: true, error: json.message ?? `Checkout init failed (HTTP ${res.status}).` };
  }
  return { ok: true, configured: true, link: json.data.link, txRef: args.txRef };
}

export interface VerifiedTransaction {
  ok: boolean;
  configured: boolean;
  found: boolean;
  status: string;
  amountMinor: number | null;
  currency: string | null;
  txRef: string | null;
  flwId: number | null;
  paymentType: string | null;
  reason: string;
  checks: Array<{ name: string; passed: boolean; detail: string }>;
}

/**
 * Server-side verification. The redirect URL is attacker-controllable, so we
 * never mark a payment paid from browser-supplied status — only from this call.
 */
export async function verifyTransaction(transactionId: string | number, expected: {
  amountMinor: number; currency: string; txRef: string;
}): Promise<VerifiedTransaction> {
  const base: VerifiedTransaction = {
    ok: false, configured: flutterwaveConfigured, found: false, status: 'unknown',
    amountMinor: null, currency: null, txRef: null, flwId: null, paymentType: null,
    reason: 'Not verified.', checks: [],
  };
  if (!flutterwaveConfigured) return { ...base, reason: 'Flutterwave is not configured.' };

  const res = await fetch(`${API}/transactions/${transactionId}/verify`, {
    headers: { Authorization: `Bearer ${env.flutterwave.secretKey}` },
    cache: 'no-store',
  });
  const json = (await res.json().catch(() => ({}))) as {
    status?: string; message?: string;
    data?: { id: number; status: string; amount: number; currency: string; tx_ref: string; payment_type?: string };
  };
  if (!res.ok || !json.data) return { ...base, reason: json.message ?? `Verification failed (HTTP ${res.status}).` };

  const d = json.data;
  const amountMinor = Math.round(Number(d.amount) * 100);
  const checks = [
    { name: 'status', passed: d.status === 'successful', detail: `Provider status "${d.status}".` },
    { name: 'amount', passed: amountMinor === expected.amountMinor, detail: `Expected ${expected.amountMinor / 100}, provider reported ${d.amount}.` },
    { name: 'currency', passed: d.currency === expected.currency, detail: `Expected ${expected.currency}, provider reported ${d.currency}.` },
    { name: 'tx_ref', passed: d.tx_ref === expected.txRef, detail: `Expected ${expected.txRef}, provider reported ${d.tx_ref}.` },
  ];
  const ok = checks.every((c) => c.passed);
  return {
    ok, configured: true, found: true, status: d.status, amountMinor, currency: d.currency, txRef: d.tx_ref,
    flwId: d.id, paymentType: d.payment_type ?? null,
    reason: ok ? 'All four verification checks passed.' : 'Verification checks failed — payment must not be marked settled.',
    checks,
  };
}

/** Webhook authenticity: the configured secret hash is echoed in `verif-hash`. */
export function verifyWebhookSignature(headerValue: string | null): boolean {
  if (!env.flutterwave.secretHash) return false;
  if (!headerValue) return false;
  return safeEqual(headerValue, env.flutterwave.secretHash);
}

export type FlwWebhookEvent =
  | { kind: 'charge'; event: string; id: number; txRef: string; status: string; amountMinor: number; currency: string | null; paymentType: string | null; customerEmail: string | null }
  | { kind: 'refund'; event: string; id: number; txRef: string; status: string; amountMinor: number | null; currency: string | null; paymentType: null; customerEmail: string | null }
  | { kind: 'other'; event: string; id: number; txRef: string; status: string; amountMinor: null; currency: string | null; paymentType: null; customerEmail: string | null };

export function parseWebhook(payload: unknown): FlwWebhookEvent | null {
  if (!payload || typeof payload !== 'object') return null;
  /* eslint-disable @typescript-eslint/no-explicit-any */
  const p = payload as any;
  const event = String(p.event ?? '');
  const data = p.data ?? {};
  if (!event) return null;
  const common = {
    event,
    id: Number(data.id ?? 0),
    txRef: String(data.tx_ref ?? data.txRef ?? ''),
    status: String(data.status ?? ''),
    currency: data.currency ? String(data.currency) : null,
    customerEmail: data.customer?.email ? String(data.customer.email) : null,
  };
  if (event.startsWith('charge')) {
    return { kind: 'charge', ...common, amountMinor: Math.round(Number(data.amount ?? 0) * 100), paymentType: data.payment_type ? String(data.payment_type) : null };
  }
  if (event.startsWith('refund')) {
    return { kind: 'refund', ...common, amountMinor: data.amount ? Math.round(Number(data.amount) * 100) : null, paymentType: null };
  }
  return { kind: 'other', ...common, amountMinor: null, paymentType: null };
}

/** Refunds are a privileged, supervisor-approved operation void of evidentiary effect. */
export async function initiateRefund(transactionId: string | number, amountMinor: number) {
  if (!flutterwaveConfigured) return { ok: false, configured: false, error: 'Flutterwave is not configured.' };
  const res = await fetch(`${API}/transactions/${transactionId}/refund`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${env.flutterwave.secretKey}`, 'Content-Type': 'application/json' },
    cache: 'no-store',
    body: JSON.stringify({ amount: (amountMinor / 100).toFixed(2) }),
  });
  const json = (await res.json().catch(() => ({}))) as { status?: string; message?: string };
  if (!res.ok || json.status !== 'success') return { ok: false, configured: true, error: json.message ?? `Refund failed (HTTP ${res.status}).` };
  return { ok: true, configured: true, message: json.message ?? 'Refund queued with provider.' };
}
