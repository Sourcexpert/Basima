import { z } from 'zod';
import { formatZodError } from './schemas';

export { formatZodError };
export type { ActionResult } from './schemas';

/** Strict input handling for the user workspace, mirroring the console's rules. */

export const agreementTypeSchema = z.enum([
  'loan', 'tenancy', 'services', 'supply', 'sale', 'employment', 'settlement',
  'distribution', 'corporate', 'lease', 'other',
]);

export const createAgreementSchema = z.object({
  title: z.string().trim().min(8, 'Give the agreement a descriptive title').max(180),
  agreementType: agreementTypeSchema,
  documentText: z.string().trim().min(40, 'The draft needs some substance before it can be versioned').max(200_000),
  idempotencyKey: z.string().min(8).max(128),
});

export const addVersionSchema = z.object({
  agreementId: z.string().min(3),
  documentText: z.string().trim().min(40).max(200_000),
  note: z.string().trim().max(300).default(''),
  idempotencyKey: z.string().min(8).max(128),
});

export const invitePartySchema = z.object({
  agreementId: z.string().min(3),
  email: z.string().email('Enter a valid email address'),
  displayName: z.string().trim().min(2).max(120),
  partyRole: z.string().trim().min(2).max(40),
  signingRequired: z.boolean().default(true),
  signingOrder: z.number().int().min(1).max(20).default(1),
  idempotencyKey: z.string().min(8).max(128),
});

export const signSchema = z.object({
  agreementId: z.string().min(3),
  versionId: z.string().min(3),
  disclosureVersion: z.string().min(3).max(64),
  /** Typed by the signer: their own name, matched against the party record. */
  confirmName: z.string().trim().min(2).max(120),
  /** One-time code step. Demo mode accepts the code shown on screen. */
  otp: z.string().trim().min(4).max(8).optional(),
  confirmIntent: z.literal(true, {
    errorMap: () => ({ message: 'You must confirm that you intend to sign this exact version.' }),
  }),
  idempotencyKey: z.string().min(8).max(128),
});

export const revokeSchema = z.object({
  agreementId: z.string().min(3),
  reason: z.string().trim().min(12, 'Explain why, in at least 12 characters').max(600),
  idempotencyKey: z.string().min(8).max(128),
});

export const acceptInvitationSchema = z.object({
  agreementId: z.string().min(3),
});

export const dataRequestSchema = z.object({
  type: z.enum(['access', 'correction', 'deletion', 'restriction', 'portability']),
  detail: z.string().trim().min(12, 'Describe what you are asking for').max(1000),
});

export const userPaymentSchema = z.object({
  invoiceId: z.string().min(3),
  phone: z
    .string()
    .transform((v) => v.replace(/[^0-9]/g, ''))
    .refine((v) => /^(0[17]\d{8}|254[17]\d{8})$/.test(v), 'Enter your M-PESA number as 07XXXXXXXX or 2547XXXXXXXX'),
  idempotencyKey: z.string().min(8).max(128),
});

export const selfPasswordSchema = z
  .object({
    currentPassword: z.string().min(8, 'Enter your current password'),
    newPassword: z
      .string()
      .min(12, 'Use at least 12 characters')
      .refine((v) => /[A-Z]/.test(v) && /[a-z]/.test(v) && /[0-9]/.test(v), 'Mix upper case, lower case and numbers'),
    confirmPassword: z.string(),
  })
  .refine((v) => v.newPassword === v.confirmPassword, {
    message: 'The two new passwords do not match',
    path: ['confirmPassword'],
  });

/**
 * The recovery form. There is no "current password" field — by definition the
 * person filling this in does not have it. The token in the link is the only
 * credential, so it is validated server-side, single-use, and short-lived.
 *
 * Mirror of `selfPasswordSchema`'s strength rule, expressed once as a predicate
 * so the server rule and the hint shown in the form cannot drift apart.
 */
export function passwordPolicyFailure(password: string): string | null {
  if (password.length < 12) return 'Use at least 12 characters';
  if (!/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/[0-9]/.test(password)) {
    return 'Mix upper case, lower case and numbers';
  }
  return null;
}

export const passwordRecoverySchema = z
  .object({
    token: z.string().trim().min(16, 'This recovery link is incomplete').max(512),
    newPassword: z.string().min(12, 'Use at least 12 characters').refine(
      (v) => passwordPolicyFailure(v) === null,
      'Mix upper case, lower case and numbers',
    ),
    confirmPassword: z.string(),
  })
  .refine((v) => v.newPassword === v.confirmPassword, {
    message: 'The two new passwords do not match',
    path: ['confirmPassword'],
  });

export type CreateAgreementInput = z.infer<typeof createAgreementSchema>;
export type SignInput = z.infer<typeof signSchema>;
