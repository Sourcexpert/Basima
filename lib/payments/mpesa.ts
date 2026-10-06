import 'server-only';
import { env, mpesaConfigured } from '@/lib/env';
import {
  buildStkPassword, clampReference, darajaTimestamp, describeResultCode, normaliseKenyanMsisdn,
  parseCallback, type MpesaCallback,
} from '@/lib/payments/mpesa-format';

/**
 * M-PESA Daraja — Lipa na M-PESA Online (STK Push) + callback handling.
 *
 * Verified against the Daraja contract:
 *   • OAuth: GET {base}/oauth/v1/generate?grant_type=client_credentials with Basic
 *     auth of consumerKey:consumerSecret. Token lifetime 3600s.
 *   • STK:   POST {base}/mpesa/stkpush/v1/processrequest with BusinessShortCode,
 *     Password = base64(ShortCode + Passkey + Timestamp), Timestamp = YYYYMMDDHHmmss
 *     in EAT, TransactionType CustomerPayBillOnline, PartyA = PartyB =
 *     2547XXXXXXXX, CallBackURL, AccountReference (≤12 chars), TransactionDesc (≤13).
 *   • Result: ResultCode 0 = success, with MpesaReceiptNumber in CallbackMetadata.
 *
 * Formatting/parsing live in ./mpesa-format.ts so they can be unit-tested without
 * a server-only import. Credentials never leave this module (Build Guide §8, §17).
 */
export { buildStkPassword, darajaTimestamp, describeResultCode, normaliseKenyanMsisdn, parseCallback };
export type { MpesaCallback };

const BASE = env.mpesa.env === 'production'
  ? 'https://api.safaricom.co.ke'
  : 'https://sandbox.safaricom.co.ke';

export interface StkPushResult {
  ok: boolean;
  merchantRequestId?: string;
  checkoutRequestId?: string;
  customerMessage?: string;
  responseCode?: string;
  error?: string;
  configured: boolean;
}

/** Token caching: one hour of validity, refreshed 60 seconds early. */
let tokenCache: { token: string; expiresAt: number } | null = null;

export async function mpesaAccessToken(): Promise<string | null> {
  if (!mpesaConfigured) return null;
  if (tokenCache && tokenCache.expiresAt > Date.now()) return tokenCache.token;

  const auth = Buffer.from(`${env.mpesa.consumerKey}:${env.mpesa.consumerSecret}`).toString('base64');
  const res = await fetch(`${BASE}/oauth/v1/generate?grant_type=client_credentials`, {
    headers: { Authorization: `Basic ${auth}`, Accept: 'application/json' },
    cache: 'no-store',
  });
  if (!res.ok) throw new Error(`Daraja OAuth failed with HTTP ${res.status}`);
  const json = (await res.json()) as { access_token: string; expires_in?: string };
  tokenCache = {
    token: json.access_token,
    expiresAt: Date.now() + (Number(json.expires_in ?? 3599) - 60) * 1000,
  };
  return tokenCache.token;
}

/** Builds the exact request body Daraja expects, respecting its field limits. */
export function buildStkRequest(args: {
  phone: string; amountKes: number; accountReference: string; description: string;
  callbackUrl: string; timestamp: string; shortcode: string; passkey: string;
}) {
  return {
    BusinessShortCode: args.shortcode,
    Password: buildStkPassword(args.shortcode, args.passkey, args.timestamp),
    Timestamp: args.timestamp,
    TransactionType: 'CustomerPayBillOnline' as const,
    Amount: Math.round(args.amountKes),           // whole shillings only
    PartyA: args.phone,
    PartyB: args.shortcode,
    PhoneNumber: args.phone,
    CallBackURL: args.callbackUrl,
    AccountReference: clampReference(args.accountReference, 12),
    TransactionDesc: clampReference(args.description, 13),
  };
}

export async function initiateStkPush(args: {
  phone: string; amountKes: number; accountReference: string; description?: string;
}): Promise<StkPushResult> {
  if (!mpesaConfigured) {
    return {
      ok: false, configured: false,
      error: 'M-PESA is not configured. Set MPESA_CONSUMER_KEY, MPESA_CONSUMER_SECRET, MPESA_SHORTCODE, MPESA_PASSKEY and MPESA_CALLBACK_URL.',
    };
  }
  const msisdn = normaliseKenyanMsisdn(args.phone);
  if (!msisdn) return { ok: false, configured: true, error: 'Phone number is not a valid Kenyan MSISDN.' };
  if (args.amountKes < 1) return { ok: false, configured: true, error: 'Amount must be at least KES 1 (whole shillings).' };

  const token = await mpesaAccessToken();
  if (!token) return { ok: false, configured: false, error: 'Could not obtain a Daraja access token.' };

  const timestamp = darajaTimestamp();
  const body = buildStkRequest({
    phone: msisdn,
    amountKes: args.amountKes,
    accountReference: args.accountReference,
    description: args.description ?? 'agre-e subscriptn',
    callbackUrl: env.mpesa.callbackUrl!,
    timestamp,
    shortcode: env.mpesa.shortcode!,
    passkey: env.mpesa.passkey!,
  });

  const res = await fetch(`${BASE}/mpesa/stkpush/v1/processrequest`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    cache: 'no-store',
  });

  const json = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (!res.ok || String(json.ResponseCode ?? '') !== '0') {
    return {
      ok: false, configured: true,
      responseCode: String(json.ResponseCode ?? res.status),
      error: String(json.errorMessage ?? json.ResponseDescription ?? `STK push failed (HTTP ${res.status}).`),
    };
  }
  return {
    ok: true, configured: true,
    merchantRequestId: String(json.MerchantRequestID ?? ''),
    checkoutRequestId: String(json.CheckoutRequestID ?? ''),
    customerMessage: String(json.CustomerMessage ?? ''),
    responseCode: String(json.ResponseCode ?? '0'),
  };
}

/**
 * Daraja does not sign callbacks with an HMAC, so authenticity is established by
 * (a) a secret token on the callback URL, (b) matching the callback's
 * CheckoutRequestID against an STK push we actually issued, and (c) re-confirming
 * through the Transaction Status API before value is delivered. Anything that
 * does not match is quarantined and recorded, never trusted.
 */
export function verifyCallbackToken(headerValue: string | null): boolean {
  if (!env.mpesa.callbackToken) return process.env.NODE_ENV !== 'production';
  if (!headerValue) return false;
  return headerValue === env.mpesa.callbackToken;
}

export async function queryStkStatus(checkoutRequestId: string) {
  if (!mpesaConfigured) return null;
  const token = await mpesaAccessToken();
  if (!token) return null;
  const timestamp = darajaTimestamp();
  const shortcode = env.mpesa.shortcode!;
  const password = buildStkPassword(shortcode, env.mpesa.passkey!, timestamp);

  const res = await fetch(`${BASE}/mpesa/stkpushquery/v1/query`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      BusinessShortCode: shortcode, Password: password, Timestamp: timestamp, CheckoutRequestID: checkoutRequestId,
    }),
    cache: 'no-store',
  });
  const json = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  const code = Number(json.ResultCode ?? -1);
  return {
    ok: res.ok && code === 0,
    resultCode: code,
    resultDesc: String(json.ResultDesc ?? ''),
    explanation: code >= 0
      ? describeResultCode(code, String(json.ResultDesc ?? ''))
      : 'No result yet — the customer may not have responded to the prompt.',
  };
}
