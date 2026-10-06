import crypto from 'node:crypto';

/**
 * SHA-256 helper (Build Guide §10).
 * Cryptographic hash answers one question: "does this data produce the expected
 * digest?" Run this on the server / inside Postgres only — never trust a digest
 * computed by the browser.
 */
export function sha256(data: string): string {
  return crypto.createHash('sha256').update(data, 'utf8').digest('hex');
}

export function sha256Hex(data: Buffer | Uint8Array | string): string {
  return crypto
    .createHash('sha256')
    .update(typeof data === 'string' ? Buffer.from(data, 'utf8') : data)
    .digest('hex');
}

/**
 * Deterministic canonical serialization.
 *
 * §9 of the guide is explicit: insignificant JSON formatting differences must not
 * be able to produce inconsistent hashes. So we sort keys, drop undefined, and
 * normalise numbers/dates before the payload is ever hashed.
 */
export function canonicalize(value: unknown): string {
  return JSON.stringify(normalize(value));
}

function normalize(value: unknown): unknown {
  if (value === null) return null;
  if (value instanceof Date) return value.toISOString();
  if (Array.isArray(value)) return value.map(normalize);
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const v = (value as Record<string, unknown>)[key];
      if (v === undefined) continue;
      out[key] = normalize(v);
    }
    return out;
  }
  if (typeof value === 'number' && !Number.isFinite(value)) return String(value);
  return value;
}

/**
 * One-way IP pseudonymisation (Build Guide §9 `ip_hash`).
 * We never store raw IP addresses on the evidence ledger — we store a keyed
 * digest so the same client can be correlated without retaining personal data.
 */
export function hashIp(ip: string | null | undefined, pepper: string): string | null {
  if (!ip) return null;
  const salt = pepper || 'agree-e-dev-pepper';
  return crypto.createHmac('sha256', salt).update(ip.trim()).digest('hex').slice(0, 32);
}

/** Deterministic human-readable identifier, e.g. AG-9F2C8A / PAY-4A19C2. */
export function publicRef(prefix: string, seed: string, length = 6): string {
  return `${prefix}-${sha256(seed).slice(0, length).toUpperCase()}`;
}

/** Timing-safe string comparison for webhook signatures / tokens. */
export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

/** Cryptographically strong opaque token (idempotency keys, CSRF, temp invites). */
export function randomToken(bytes = 32): string {
  return crypto.randomBytes(bytes).toString('base64url');
}

/**
 * Generates a high-entropy temporary secret when an admin uses the
 * break-glass workflow. Never displayed twice, never stored in plaintext,
 * never logged (it is written to auth.users by Supabase, hashed).
 */
export function generateTemporaryPassword(): string {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  const bytes = crypto.randomBytes(24);
  let out = '';
  for (const b of bytes) out += alphabet[b % alphabet.length];
  return `${out.slice(0, 4)}-${out.slice(4, 12)}-${out.slice(12, 20)}-${out.slice(20, 24)}`;
}
