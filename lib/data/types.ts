import { randomUUID } from 'node:crypto';
import type { Capability, Role } from '@/lib/auth/rbac';
import type { AuditEventRecord } from '@/lib/audit/chain';

/* ------------------------------------------------------------------ users -- */

export type UserStatus = 'active' | 'invited' | 'suspended' | 'locked' | 'deactivated';
export type PlanCode = 'free' | 'personal' | 'practice' | 'firm' | 'enterprise';

export interface Profile {
  id: string;
  email: string;
  displayName: string;
  role: Role;
  status: UserStatus;
  phone: string | null;
  country: string;
  organisation: string | null;
  createdAt: string;
  lastSignInAt: string | null;
  emailVerified: boolean;
  mfaEnabled: boolean;
  mfaRequired: boolean;
  forcePasswordReset: boolean;
  passwordChangedAt: string | null;
  failedSignInCount: number;
  lockedUntil: string | null;
  /** Set when a break-glass temporary credential was issued. */
  tempCredentialIssuedAt: string | null;
  tempCredentialExpiresAt: string | null;
  agreementsOwned: number;
  /** Admin-console capabilities beyond the role default. */
  extraCapabilities: Capability[];
}

export interface UserSession {
  id: string;
  userId: string;
  ipHash: string;
  userAgent: string;
  createdAt: string;
  lastSeenAt: string;
  expiresAt: string;
  current: boolean;
  mfaSatisfied: boolean;
}

export interface SecurityEventRecord {
  id: string;
  userId: string | null;
  type: string;
  severity: 'info' | 'notice' | 'warning' | 'critical';
  detail: string;
  ipHash: string | null;
  occurredAt: string;
}

/* ------------------------------------------------------- password recovery -- */

/**
 * A single-use recovery request.
 *
 * The raw token exists in exactly two places: the link handed to the account
 * holder, and their browser. The stored record keeps only `tokenHash`, so no
 * database read — and therefore no console screen — can yield a credential.
 * `issuedBy` records which operator caused the link to exist; a future
 * self-service ("forgot password") flow leaves it null, because nobody
 * privileged was involved.
 */
export interface PasswordRecoveryRequest {
  id: string;
  userId: string;
  tokenHash: string;
  issuedBy: string | null;
  delivery: 'email' | 'copy';
  reason: string | null;
  issuedAt: string;
  expiresAt: string;
  consumedAt: string | null;
  ipHash: string | null;
  userAgent: string | null;
}

/* ---------------------------------------------------------------- billing -- */

export type SubscriptionStatus =
  | 'trialing' | 'active' | 'past_due' | 'grace' | 'paused' | 'cancelled' | 'expired';

export type PaymentProvider = 'mpesa' | 'flutterwave';

export interface Plan {
  id: string;
  code: PlanCode | string;
  name: string;
  description: string;
  interval: 'monthly' | 'annual';
  amountMinor: number;
  currency: 'KES' | 'USD' | 'NGN';
  trialDays: number;
  features: string[];
  includedSeats: number;
  includedStamps: number;
  active: boolean;
  archivedAt: string | null;
  createdAt: string;
  /** Commercial only — never an input to any evidentiary decision. */
  subscribers?: number;
  mrrMinor?: number;
}

export interface Subscription {
  id: string;
  userId: string;
  userEmail: string;
  userName: string;
  planId: string;
  planCode: string;
  planName: string;
  status: SubscriptionStatus;
  startedAt: string;
  currentPeriodStart: string;
  currentPeriodEnd: string;
  trialEndsAt: string | null;
  cancelAtPeriodEnd: boolean;
  cancelledAt: string | null;
  pausedAt: string | null;
  seats: number;
  amountMinor: number;
  currency: string;
  provider: PaymentProvider;
  /** Recovery state so a payment outage can never be mistaken for lost evidence. */
  dunningAttempts: number;
  graceEndsAt: string | null;
}

export interface Invoice {
  id: string;
  number: string;
  subscriptionId: string;
  userId: string;
  userEmail: string;
  amountMinor: number;
  currency: string;
  status: 'draft' | 'open' | 'paid' | 'void' | 'uncollectible';
  issuedAt: string;
  dueAt: string;
  paidAt: string | null;
  provider: PaymentProvider;
}

export interface Payment {
  id: string;
  reference: string;
  invoiceId: string | null;
  userId: string;
  userEmail: string;
  provider: PaymentProvider;
  method: 'mpesa_stk' | 'mpesa_c2b' | 'card' | 'bank_transfer' | 'ussd' | 'manual';
  amountMinor: number;
  currency: string;
  status: 'initiated' | 'pending' | 'succeeded' | 'failed' | 'reversed' | 'refunded';
  providerRef: string | null;
  mpesaReceipt: string | null;
  failureReason: string | null;
  reconciledBy: string | null;
  refundedMinor: number;
  createdAt: string;
  updatedAt: string;
}

/* -------------------------------------------------------------- agreements -- */

/**
 * Metadata only. The console never receives agreement content or party identity
 * material unless a security-role admin runs the privileged access workflow
 * (Build Guide §5).
 */
export interface AgreementSummary {
  id: string;
  ref: string;
  title: string;
  agreementType: string;
  ownerId: string;
  ownerEmail: string;
  status: 'draft' | 'awaiting_parties' | 'awaiting_signatures' | 'completed' | 'revoked';
  currentVersion: number;
  documentHash: string | null;
  partiesCount: number;
  requiredSigners: number;
  completedSigners: number;
  stampIssuedAt: string | null;
  chainHead: string | null;
  createdAt: string;
  completedAt: string | null;
}

/* ------------------------------------------------- user workspace (parties) -- */

/**
 * User-side entities. The owner and the invited parties act on these through the
 * user workspace; the console never sees document bodies or consent payloads.
 */
export interface AgreementDocument {
  id: string;
  agreementId: string;
  versionNumber: number;
  storagePath: string;
  sha256: string;
  byteSize: number;
  createdBy: string;
  createdAt: string;
  /** Set when the agreement completes. A frozen version can never be edited. */
  frozenAt: string | null;
  /** Demo mode only: the document body, as its owner would see it. */
  body?: string;
}

export type PartyStatus = 'invited' | 'accepted' | 'declined' | 'removed';

export interface AgreementParty {
  id: string;
  agreementId: string;
  userId: string | null;
  displayName: string;
  email: string;
  partyRole: string;
  signingRequired: boolean;
  signingOrder: number;
  status: PartyStatus;
  invitationSentAt: string | null;
  invitationAcceptedAt: string | null;
  /** Set through identity_verifications; a reference, never a document copy. */
  assuranceLevel: string | null;
  identityVerifiedAt: string | null;
}

export interface SignatureRequest {
  id: string;
  agreementId: string;
  versionId: string;
  partyId: string;
  requestedBy: string | null;
  status: 'requested' | 'viewed' | 'signed' | 'declined' | 'expired';
  requestedAt: string;
  expiresAt: string | null;
}

export interface SignatureEvent {
  id: string;
  agreementId: string;
  versionId: string;
  partyId: string;
  actorId: string | null;
  signatureMethod: string;
  outcome: 'signed' | 'declined' | 'failed';
  consentId: string | null;
  occurredAt: string;
  ipHash: string | null;
  userAgent: string | null;
}

export interface ConsentRecord {
  id: string;
  agreementId: string;
  userId: string;
  disclosureVersion: string;
  scope: string;
  acceptedAt: string;
  ipHash: string | null;
}

export interface EvidencePackageRecord {
  id: string;
  agreementId: string;
  versionId: string;
  format: string;
  packageVersion: string;
  documentHash: string;
  chainRoot: string;
  eventCount: number;
  createdAt: string;
  createdBy: string | null;
  verification: {
    ok: boolean;
    documentIntegrity: boolean;
    chainIntegrity: boolean;
    requiredEventsPresent: boolean;
    findings: Array<{ name: string; passed: boolean; detail: string }>;
    statements: string[];
  };
}

export interface PackageFile {
  name: string;
  content: string;
  mime: string;
}

/** Data-subject workflow (Kenya DPA): filed by the user, tracked openly. */
export interface DataSubjectRequest {
  id: string;
  userId: string;
  type: 'access' | 'correction' | 'deletion' | 'restriction' | 'portability';
  detail: string;
  status: 'received' | 'in_review' | 'fulfilled' | 'refused';
  submittedAt: string;
  dueAt: string;
  resolvedAt: string | null;
  resolutionNote: string | null;
}

/* ------------------------------------------------------------------ audit -- */

export interface AdminActionRecord {
  id: string;
  adminId: string;
  adminEmail: string;
  adminRole: Role;
  action: string;
  targetType: 'user' | 'plan' | 'subscription' | 'payment' | 'invoice' | 'setting' | 'agreement';
  targetId: string;
  targetLabel: string;
  reason: string;
  status: 'succeeded' | 'failed' | 'blocked';
  stepUp: boolean;
  ipHash: string | null;
  userAgent: string | null;
  previousHash: string | null;
  eventHash: string;
  occurredAt: string;
  metadata: Record<string, unknown>;
}

export interface Coupon {
  id: string;
  code: string;
  percentOff: number;
  maxRedemptions: number;
  redemptions: number;
  expiresAt: string | null;
  active: boolean;
  createdAt: string;
}

/* -------------------------------------------------------------- container -- */

export interface OperationsSnapshot {
  generatedAt: string;
  mode: 'supabase' | 'demo';
  users: {
    total: number;
    active: number;
    suspended: number;
    withoutMfa: number;
    privilegedWithoutMfa: number;
    pendingInvites: number;
    locked: number;
  };
  billing: {
    currency: string;
    mrrMinor: number;
    arrMinor: number;
    activeSubscriptions: number;
    trialing: number;
    pastDue: number;
    cancelledThisMonth: number;
    collectedThisMonthMinor: number;
    failedPayments7d: number;
    refundedThisMonthMinor: number;
  };
  evidence: {
    agreementsTotal: number;
    completed: number;
    stampsIssued30d: number;
    chainIntegrity: { verified: number; failed: number; lastCheckedAt: string | null };
  };
  security: {
    openIncidents: number;
    failedAdminSignins24h: number;
    privilegedAccesses30d: number;
    auditEvents24h: number;
  };
  paymentHealth: {
    mpesaConfigured: boolean;
    flutterwaveConfigured: boolean;
    lastStkPushAt: string | null;
    stkSuccessRate: number | null;
    webhookLastReceivedAt: string | null;
  };
  recentAudit: AuditEventRecord[];
  recentAdminActions: AdminActionRecord[];
}

export function newId(prefix = 'id'): string {
  return `${prefix}_${randomUUID()}`;
}
