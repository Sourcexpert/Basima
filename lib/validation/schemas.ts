import { z } from 'zod';

/**
 * Strict input handling (Build Guide §17). Every privileged action validates its
 * payload on the server before anything touches the database or a provider API.
 */

export const uuidSchema = z.string().uuid();

/**
 * A row identifier.
 *
 * Production ids are uuids. The seeded demo dataset uses readable ids
 * (`user_020`, `plan_practice_m`, `pay_9f2c8a`) so a walkthrough can name the
 * record it is talking about — and the console is fully operable on that dataset
 * with no backend attached, which is the whole point of it.
 *
 * Accepting both here is not a weakening: an id is never an authorization
 * control. Every service loads the row by that id and then authorizes against
 * the loaded record, so a well-formed string that names something the caller may
 * not touch is refused a step later, with a reason. What the format check buys is
 * rejection of garbage before any query runs.
 */
export const recordIdSchema = z
  .string()
  .trim()
  .min(3, 'Missing identifier')
  .max(64, 'Identifier is too long')
  .regex(/^[A-Za-z0-9][A-Za-z0-9_-]*$/, 'Malformed identifier');

/** Server-side IP pseudonymisation means we validate, never trust, the header. */
export const ipSchema = z
  .string()
  .max(64)
  .regex(/^[0-9a-fA-F.:]+$/, 'Invalid address format')
  .nullable()
  .optional();

export const reasonSchema = z
  .string()
  .trim()
  .min(12, 'Justification must be at least 12 characters')
  .max(600, 'Justification is too long (600 characters max)');

export const passwordResetLinkSchema = z.object({
  userId: recordIdSchema,
  /** 'email' sends a recovery link; 'copy' returns a single-use link for support calls. */
  delivery: z.enum(['email', 'copy']).default('email'),
  redirectTo: z.string().url().optional(),
  reason: reasonSchema,
  idempotencyKey: z.string().min(8).max(128),
});

export const forceResetSchema = z.object({
  userId: recordIdSchema,
  /** User must set a new password at next sign-in. */
  requireMfa: z.boolean().default(false),
  revokeSessions: z.boolean().default(true),
  reason: reasonSchema,
  idempotencyKey: z.string().min(8).max(128),
});

export const breakGlassSchema = z.object({
  userId: recordIdSchema,
  ttlMinutes: z.number().int().min(5).max(120).default(30),
  supervisorEmail: z.string().email(),
  reason: reasonSchema,
  acknowledgement: z.literal(true, {
    errorMap: () => ({ message: 'You must acknowledge the break-glass conditions.' }),
  }),
  idempotencyKey: z.string().min(8).max(128),
});

export const revokeSessionsSchema = z.object({
  userId: recordIdSchema,
  scope: z.enum(['global', 'others']).default('global'),
  reason: reasonSchema,
  idempotencyKey: z.string().min(8).max(128),
});

export const lockUserSchema = z.object({
  userId: recordIdSchema,
  action: z.enum(['lock', 'unlock']),
  reason: reasonSchema,
  idempotencyKey: z.string().min(8).max(128),
});

export const changeRoleSchema = z.object({
  userId: recordIdSchema,
  role: z.enum(['owner', 'admin', 'support', 'security', 'billing', 'counsel']),
  reason: reasonSchema,
  idempotencyKey: z.string().min(8).max(128),
});

export const mfaSchema = z.object({
  userId: recordIdSchema,
  required: z.boolean(),
  reason: reasonSchema,
  idempotencyKey: z.string().min(8).max(128),
});

/* ------------------------------- billing ---------------------------------- */

export const planSchema = z.object({
  code: z.string().trim().min(2).max(40).regex(/^[a-z0-9_]+$/, 'Use lowercase letters, numbers and underscores'),
  name: z.string().trim().min(2).max(80),
  description: z.string().trim().max(400).default(''),
  interval: z.enum(['monthly', 'annual']),
  amountMinor: z.number().int().min(0).max(100_000_000),
  currency: z.enum(['KES', 'USD', 'NGN']),
  trialDays: z.number().int().min(0).max(90).default(14),
  features: z.array(z.string().trim().min(1).max(120)).max(20).default([]),
  includedSeats: z.number().int().min(1).max(500).default(1),
  includedStamps: z.number().int().min(0).max(10_000).default(10),
  active: z.boolean().default(true),
});

export const subscriptionChangeSchema = z.object({
  subscriptionId: recordIdSchema,
  action: z.enum(['change_plan', 'cancel', 'pause', 'resume', 'extend_trial']),
  planId: z.string().min(1).optional(),
  extendDays: z.number().int().min(1).max(90).optional(),
  effective: z.enum(['immediately', 'period_end']).default('period_end'),
  reason: reasonSchema,
  idempotencyKey: z.string().min(8).max(128),
});

export const refundSchema = z.object({
  paymentId: recordIdSchema,
  amountMinor: z.number().int().min(1),
  reason: reasonSchema,
  supervisorEmail: z.string().email(),
  idempotencyKey: z.string().min(8).max(128),
});

export const reconciliationSchema = z.object({
  provider: z.enum(['mpesa', 'flutterwave']),
  reference: z.string().min(3).max(120),
  reason: reasonSchema,
});

export const stkPushSchema = z.object({
  invoiceId: recordIdSchema,
  phone: z
    .string()
    .transform((v) => v.replace(/[^0-9]/g, ''))
    .refine((v) => /^(0[17]\d{8}|254[17]\d{8})$/.test(v), 'Enter a Kenyan number as 07XXXXXXXX or 2547XXXXXXXX'),
  reason: reasonSchema,
  idempotencyKey: z.string().min(8).max(128),
});

export const couponSchema = z.object({
  code: z.string().trim().toUpperCase().min(3).max(24).regex(/^[A-Z0-9_-]+$/, 'Use letters, numbers, dash or underscore'),
  percentOff: z.number().int().min(1).max(100),
  maxRedemptions: z.number().int().min(1).max(100_000),
  expiresAt: z.string().datetime().optional(),
  reason: reasonSchema,
});

export const settingsSchema = z.object({
  key: z.string().trim().min(2).max(80),
  value: z.union([z.string(), z.number(), z.boolean()]),
  reason: reasonSchema,
});

/* ------------------------------- helpers ---------------------------------- */

export function formatZodError(error: z.ZodError): string {
  return error.issues.map((i) => `${i.path.join('.') || 'input'}: ${i.message}`).join('; ');
}

export type ActionResult<T = unknown> =
  | { ok: true; data: T; message?: string }
  | { ok: false; error: string; data?: T; code?: 'unauthorized' | 'forbidden' | 'validation' | 'not_configured' | 'provider_error' | 'conflict' };
