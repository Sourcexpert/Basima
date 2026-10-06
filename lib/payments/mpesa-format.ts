/**
 * Pure M-PESA Daraja formatting/parsing helpers — no server-only imports, no
 * environment reads, so they can be unit-tested directly by the Node test runner.
 * lib/payments/mpesa.ts re-exports these and adds the network calls.
 */

export interface MpesaCallbackMetadataItem { Name: string; Value?: string | number }

export interface MpesaCallback {
  Body: {
    stkCallback: {
      MerchantRequestID: string;
      CheckoutRequestID: string;
      ResultCode: number;
      ResultDesc: string;
      CallbackMetadata?: { Item: MpesaCallbackMetadataItem[] };
    };
  };
}

/**
 * Normalises Kenyan MSISDNs to the 254 7XXXXXXXX / 254 1XXXXXXXX form Daraja
 * requires. Accepts 07…, 01…, +254…, 254…, and 00254….
 */
export function normaliseKenyanMsisdn(input: string): string | null {
  const digits = (input ?? '').replace(/[^0-9]/g, '');
  if (/^254[17]\d{8}$/.test(digits)) return digits;
  if (/^0[17]\d{8}$/.test(digits)) return `254${digits.slice(1)}`;
  if (/^[17]\d{8}$/.test(digits)) return `254${digits}`;
  if (/^00254[17]\d{8}$/.test(digits)) return digits.slice(2);
  return null;
}

/** YYYYMMDDHHmmss in EAT (Africa/Nairobi, UTC+3, no daylight saving). */
export function darajaTimestamp(d = new Date()): string {
  const eat = new Date(d.getTime() + 3 * 3_600_000);
  return eat.toISOString().replace(/[-:TZ.]/g, '').slice(0, 14);
}

/** Password = base64(Shortcode + Passkey + Timestamp). */
export function buildStkPassword(shortcode: string, passkey: string, timestamp: string): string {
  return Buffer.from(`${shortcode}${passkey}${timestamp}`).toString('base64');
}

/** ResultCode -> precise operator-facing explanation. */
export function describeResultCode(code: number, desc: string): string {
  const map: Record<number, string> = {
    0: 'Payment completed.',
    1: 'Insufficient M-PESA balance.',
    1032: 'Customer cancelled the request on their handset.',
    1037: 'No response from the customer — the prompt timed out before PIN entry.',
    2001: 'Wrong M-PESA PIN entered; retries exhausted.',
    1001: 'Unable to complete: another transaction is in progress on this number.',
    1019: 'Transaction expired.',
    1025: 'Request rejected by M-PESA. Repeat after a short while.',
    9999: 'Request failed at the M-PESA service. Treat as unresolved and reconcile.',
  };
  return map[code] ?? `${desc} (ResultCode ${code})`;
}

/** Parses a Daraja STK callback into a shape the console can act on safely. */
export function parseCallback(body: MpesaCallback) {
  const cb = body?.Body?.stkCallback;
  if (!cb) return null;
  const items = cb.CallbackMetadata?.Item ?? [];
  const get = (name: string) => items.find((i) => i.Name === name)?.Value;
  return {
    merchantRequestId: cb.MerchantRequestID,
    checkoutRequestId: cb.CheckoutRequestID,
    resultCode: cb.ResultCode,
    resultDesc: cb.ResultDesc,
    amount: get('Amount') !== undefined ? Number(get('Amount')) : null,
    receipt: (get('MpesaReceiptNumber') as string | undefined) ?? null,
    transactionDate: (get('TransactionDate') as string | undefined) ?? null,
    phone: (get('PhoneNumber') as string | undefined) ?? null,
    succeeded: cb.ResultCode === 0,
    explanation: describeResultCode(cb.ResultCode, cb.ResultDesc),
  };
}

/** Daraja caps these two fields; truncating here beats a rejected request. */
export function clampReference(value: string, length = 12): string {
  return value.slice(0, length);
}
