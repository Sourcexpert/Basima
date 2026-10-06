import { appendToChain, type AuditEventRecord as ChainEvent } from '@/lib/audit/chain';
import { computeAdminActionHash } from '@/lib/audit/admin-chain';
import type { Role } from '@/lib/auth/rbac';
import { sha256 } from '@/lib/crypto/hash';
import type {
  AdminActionRecord, AgreementSummary, Coupon, Invoice, Payment, Plan, Profile,
  SecurityEventRecord, Subscription, UserSession,
} from '@/lib/data/types';

/**
 * Seeded in-memory dataset used when no Supabase project is configured.
 *
 * It exists so the console, its authorization paths and its audit ledger can be
 * exercised end-to-end without credentials. It is NOT a security boundary — in
 * production the same reads/writes go through Supabase with RLS enforced.
 *
 * All timestamps are derived from a fixed anchor so server render and client
 * hydration agree, and so the seeded audit chains hash identically every boot.
 */
const DEMO_NOW = new Date('2026-10-05T09:20:00.000Z').getTime();

function days(n: number): number { return DEMO_NOW - n * 86_400_000; }
function hours(n: number): number { return DEMO_NOW - n * 3_600_000; }
function weeks(n: number): number { return days(n * 7); }
function iso(ms: number): string { return new Date(ms).toISOString(); }

/** Deterministic PRNG so the seed is identical on every boot. */
function mulberry32(seed: number) {
  let a = seed;
  return () => {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4_294_967_296;
  };
}
const rnd = mulberry32(20261005);
const pick = <T,>(arr: readonly T[]): T => arr[Math.floor(rnd() * arr.length)];

/* ------------------------------------------------------------------ plans -- */

export const DEMO_PLANS: Plan[] = [
  {
    id: 'plan_free', code: 'free', name: 'Free', interval: 'monthly', amountMinor: 0, currency: 'KES',
    description: 'Trial the evidence workflow on a single agreement.',
    trialDays: 0, includedSeats: 1, includedStamps: 1,
    features: ['1 agreement', '1 stamp', 'Verify chain', 'Community support'],
    active: true, archivedAt: null, createdAt: iso(weeks(60)),
  },
  {
    id: 'plan_personal_m', code: 'personal_monthly', name: 'Personal', interval: 'monthly', amountMinor: 150_000, currency: 'KES',
    description: 'For individuals who need a defensible record of one-to-one agreements.',
    trialDays: 14, includedSeats: 1, includedStamps: 10,
    features: ['10 stamps / month', '2 party seats', 'Evidence package export', 'Email support'],
    active: true, archivedAt: null, createdAt: iso(weeks(48)),
  },
  {
    id: 'plan_personal_y', code: 'personal_annual', name: 'Personal (annual)', interval: 'annual', amountMinor: 1_500_000, currency: 'KES',
    description: 'Personal, billed yearly — two months free.',
    trialDays: 14, includedSeats: 1, includedStamps: 120,
    features: ['120 stamps / year', '2 party seats', 'Evidence package export', 'Priority email support'],
    active: true, archivedAt: null, createdAt: iso(weeks(48)),
  },
  {
    id: 'plan_practice_m', code: 'practice_monthly', name: 'Advocate Practice', interval: 'monthly', amountMinor: 450_000, currency: 'KES',
    description: 'For solo advocates managing client matters and certificate drafts.',
    trialDays: 14, includedSeats: 3, includedStamps: 40,
    features: ['40 stamps / month', 'Counsel workspace', 'Certificate draft workspace', 'Matter sharing controls', 'Audit export'],
    active: true, archivedAt: null, createdAt: iso(weeks(40)),
  },
  {
    id: 'plan_firm_m', code: 'firm_monthly', name: 'Firm', interval: 'monthly', amountMinor: 1_800_000, currency: 'KES',
    description: 'For law firms with multiple advocates and shared matters.',
    trialDays: 14, includedSeats: 10, includedStamps: 150,
    features: ['150 stamps / month', '10 advocate seats', 'Organisation tenancy', 'SSO-ready', 'Named onboarding', 'Audit export'],
    active: true, archivedAt: null, createdAt: iso(weeks(36)),
  },
  {
    id: 'plan_firm_y', code: 'firm_annual', name: 'Firm (annual)', interval: 'annual', amountMinor: 18_000_000, currency: 'KES',
    description: 'Firm plan billed yearly.',
    trialDays: 14, includedSeats: 10, includedStamps: 1_800,
    features: ['1,800 stamps / year', '10 advocate seats', 'Organisation tenancy', 'Named onboarding'],
    active: true, archivedAt: null, createdAt: iso(weeks(36)),
  },
  {
    id: 'plan_legacy_starter', code: 'legacy_starter', name: 'Starter (legacy)', interval: 'monthly', amountMinor: 90_000, currency: 'KES',
    description: 'Grandfathered plan. Closed to new sign-ups, honours existing subscribers.',
    trialDays: 0, includedSeats: 1, includedStamps: 5,
    features: ['5 stamps / month', 'Email support'],
    active: false, archivedAt: iso(weeks(6)), createdAt: iso(weeks(70)),
  },
];

/* ------------------------------------------------------------------ users -- */

const SEED_USERS: Array<Pick<Profile, 'displayName' | 'email' | 'role' | 'status' | 'organisation' | 'country'> & {
  daysAgo: number; mfa: boolean; verified?: boolean; phone?: string; suspendedReason?: string;
}> = [
  { displayName: 'Amina Wanjiru', email: 'amina.wanjiru@agree-e.com', role: 'owner', status: 'active', organisation: 'agre-e', country: 'KE', daysAgo: 420, mfa: true, phone: '+254711000101' },
  { displayName: 'Brian Otieno', email: 'brian.otieno@agree-e.com', role: 'admin', status: 'active', organisation: 'agre-e', country: 'KE', daysAgo: 300, mfa: true },
  { displayName: 'Cynthia Mwikali', email: 'cynthia.mwikali@agree-e.com', role: 'support', status: 'active', organisation: 'agre-e', country: 'KE', daysAgo: 240, mfa: false },
  { displayName: 'Daniel Kariuki', email: 'daniel.kariuki@agree-e.com', role: 'security', status: 'active', organisation: 'agre-e', country: 'KE', daysAgo: 260, mfa: true },
  { displayName: 'Esther Nekesa', email: 'esther.nekesa@agree-e.com', role: 'billing', status: 'active', organisation: 'agre-e', country: 'KE', daysAgo: 180, mfa: false },
  { displayName: 'Adv. Felix Muthama', email: 'f.muthama@muthamaadvocates.co.ke', role: 'counsel', status: 'active', organisation: 'Muthama & Associates Advocates', country: 'KE', daysAgo: 150, mfa: true },
  { displayName: 'Grace Achieng', email: 'grace.achieng@gmail.com', role: 'counsel', status: 'active', organisation: null, country: 'KE', daysAgo: 90, mfa: false },
  { displayName: 'Hakim Odhiambo', email: 'hakim.odhiambo@outlook.com', role: 'counsel', status: 'active', organisation: null, country: 'KE', daysAgo: 75, mfa: false },
  { displayName: 'Irene Chebet', email: 'irene.chebet@kilimanjaro-law.co.tz', role: 'counsel', status: 'active', organisation: 'Kilimanjaro Law Chambers', country: 'TZ', daysAgo: 60, mfa: true },
  { displayName: 'Joseph Kimani', email: 'jkimani@kimaniassociates.co.ke', role: 'counsel', status: 'active', organisation: 'Kimani & Associates', country: 'KE', daysAgo: 140, mfa: true },
  { displayName: 'Kevin Mwangi', email: 'kevin.mwangi@agriease.co.ke', role: 'counsel', status: 'active', organisation: 'AgriEase Ltd', country: 'KE', daysAgo: 52, mfa: false },
  { displayName: 'Lydia Wairimu', email: 'lydia.wairimu@wananchi.co.ke', role: 'counsel', status: 'active', organisation: null, country: 'KE', daysAgo: 45, mfa: true },
  { displayName: 'Moses Kiplagat', email: 'moses.kiplagat@gmail.com', role: 'counsel', status: 'active', organisation: null, country: 'KE', daysAgo: 40, mfa: false },
  { displayName: 'Nancy Atieno', email: 'nancy.atieno@safarihomes.co.ke', role: 'counsel', status: 'active', organisation: 'Safari Homes Properties', country: 'KE', daysAgo: 38, mfa: true },
  { displayName: 'Oscar Bundi', email: 'oscar.bundi@lenderfirst.co.ke', role: 'counsel', status: 'active', organisation: 'LenderFirst Credit', country: 'KE', daysAgo: 33, mfa: false },
  { displayName: 'Purity Njeri', email: 'purity.njeri@ngaaadvocates.co.ke', role: 'counsel', status: 'active', organisation: 'Ngaa Advocates LLP', country: 'KE', daysAgo: 30, mfa: true },
  { displayName: 'Quinter Adhiambo', email: 'quinter.adhiambo@gmail.com', role: 'counsel', status: 'invited', organisation: null, country: 'KE', daysAgo: 4, mfa: false },
  { displayName: 'Rashid Juma', email: 'rashid.juma@coastalholdings.co.ke', role: 'counsel', status: 'invited', organisation: 'Coastal Holdings', country: 'KE', daysAgo: 2, mfa: false },
  { displayName: 'Samuel Njoroge', email: 'samuel.njoroge@mail.com', role: 'counsel', status: 'suspended', organisation: null, country: 'KE', daysAgo: 120, mfa: false, suspendedReason: 'Repeated failed payment reconciliation after 3 dunning cycles.' },
  { displayName: 'Tabitha Mueni', email: 'tabitha.mueni@kasuku.ke', role: 'counsel', status: 'locked', organisation: 'Kasuku Traders', country: 'KE', daysAgo: 26, mfa: false },
  { displayName: 'Umar Suleiman', email: 'umar.suleiman@lagosfintrust.ng', role: 'counsel', status: 'active', organisation: 'Lagos FinTrust', country: 'NG', daysAgo: 22, mfa: true, phone: '+2348012345678' },
  { displayName: 'Violet Nyambura', email: 'violet.nyambura@eastafricarealty.co.ke', role: 'counsel', status: 'active', organisation: 'East Africa Realty', country: 'KE', daysAgo: 18, mfa: false },
  { displayName: 'Wilfred Barasa', email: 'wilfred.barasa@bcsadvocates.co.ke', role: 'counsel', status: 'active', organisation: 'Barasa Court Services', country: 'KE', daysAgo: 12, mfa: false },
  { displayName: 'Yusuf Abdi', email: 'yusuf.abdi@hornsolutions.so', role: 'counsel', status: 'deactivated', organisation: 'Horn Solutions', country: 'SO', daysAgo: 95, mfa: false, suspendedReason: 'Account closed at customer request (data retained per retention schedule).' },
];

export const DEMO_USERS: Profile[] = SEED_USERS.map((u, i) => {
  const id = `user_${String(i + 1).padStart(3, '0')}`;
  const suspended = u.status === 'suspended';
  const locked = u.status === 'locked';
  return {
    id,
    email: u.email,
    displayName: u.displayName,
    role: u.role as Role,
    status: u.status,
    phone: u.phone ?? null,
    country: u.country,
    organisation: u.organisation,
    createdAt: iso(days(u.daysAgo)),
    lastSignInAt: u.status === 'invited' ? null : iso(hours(i % 40)),
    emailVerified: u.verified ?? u.status !== 'invited',
    mfaEnabled: u.mfa,
    // Privileged console roles are policy-bound to MFA (Build Guide §17).
    mfaRequired: ['owner', 'admin', 'support', 'security', 'billing'].includes(u.role),
    forcePasswordReset: false,
    passwordChangedAt: u.status === 'invited' ? null : iso(days(30 + i)),
    failedSignInCount: suspended ? 5 : locked ? 9 : 0,
    lockedUntil: locked ? iso(hours(6)) : null,
    tempCredentialIssuedAt: null,
    tempCredentialExpiresAt: null,
    agreementsOwned: u.role === 'counsel' ? Math.floor(rnd() * 24) + 1 : 0,
    extraCapabilities: [],
  };
});

/* ---------------------------------------------------------- subscriptions -- */

const SUB_LAYOUT: Array<{ userId: string; planId: string; status: Subscription['status']; provider: Subscription['provider']; periodDay: number }> = [
  { userId: 'user_006', planId: 'plan_practice_m', status: 'active', provider: 'mpesa', periodDay: 12 },
  { userId: 'user_007', planId: 'plan_personal_m', status: 'active', provider: 'mpesa', periodDay: 5 },
  { userId: 'user_008', planId: 'plan_personal_m', status: 'past_due', provider: 'mpesa', periodDay: 20 },
  { userId: 'user_009', planId: 'plan_practice_m', status: 'active', provider: 'flutterwave', periodDay: 8 },
  { userId: 'user_010', planId: 'plan_firm_m', status: 'active', provider: 'flutterwave', periodDay: 15 },
  { userId: 'user_011', planId: 'plan_practice_m', status: 'active', provider: 'mpesa', periodDay: 22 },
  { userId: 'user_012', planId: 'plan_personal_y', status: 'active', provider: 'flutterwave', periodDay: 30 },
  { userId: 'user_013', planId: 'plan_personal_m', status: 'trialing', provider: 'mpesa', periodDay: 3 },
  { userId: 'user_014', planId: 'plan_firm_m', status: 'active', provider: 'flutterwave', periodDay: 9 },
  { userId: 'user_015', planId: 'plan_practice_m', status: 'grace', provider: 'mpesa', periodDay: 26 },
  { userId: 'user_016', planId: 'plan_personal_m', status: 'active', provider: 'mpesa', periodDay: 14 },
  { userId: 'user_019', planId: 'plan_legacy_starter', status: 'cancelled', provider: 'mpesa', periodDay: 28 },
  { userId: 'user_021', planId: 'plan_firm_m', status: 'active', provider: 'flutterwave', periodDay: 11 },
  { userId: 'user_022', planId: 'plan_practice_m', status: 'paused', provider: 'mpesa', periodDay: 18 },
  { userId: 'user_023', planId: 'plan_personal_m', status: 'expired', provider: 'mpesa', periodDay: 40 },
  { userId: 'user_024', planId: 'plan_personal_m', status: 'past_due', provider: 'mpesa', periodDay: 6 },
];

export const DEMO_SUBSCRIPTIONS: Subscription[] = SUB_LAYOUT.map((row, i) => {
  const user = DEMO_USERS.find((u) => u.id === row.userId)!;
  const plan = DEMO_PLANS.find((p) => p.id === row.planId)!;
  const periodStart = days(row.periodDay);
  const periodEnd = row.planId.endsWith('_y') ? days(row.periodDay - 365) : days(row.periodDay - 30);
  const provider: Subscription['provider'] = row.provider;
  return {
    id: `sub_${String(i + 1).padStart(3, '0')}`,
    userId: user.id,
    userEmail: user.email,
    userName: user.displayName,
    planId: plan.id,
    planCode: plan.code,
    planName: plan.name,
    status: row.status,
    startedAt: iso(days(row.periodDay + 200 - i * 5)),
    currentPeriodStart: iso(periodStart),
    currentPeriodEnd: iso(periodEnd),
    trialEndsAt: row.status === 'trialing' ? iso(days(row.periodDay - 14)) : null,
    cancelAtPeriodEnd: row.status === 'cancelled',
    cancelledAt: row.status === 'cancelled' ? iso(days(row.periodDay - 2)) : null,
    pausedAt: row.status === 'paused' ? iso(days(row.periodDay - 4)) : null,
    seats: plan.includedSeats,
    amountMinor: plan.amountMinor,
    currency: plan.currency,
    provider,
    dunningAttempts: row.status === 'past_due' ? 2 : row.status === 'grace' ? 3 : 0,
    graceEndsAt: row.status === 'grace' ? iso(days(row.periodDay - 37)) : null,
  };
});

/* ------------------------------------------------- invoices and payments -- */

export const DEMO_INVOICES: Invoice[] = DEMO_SUBSCRIPTIONS.flatMap((sub, i) => {
  const cycles = sub.status === 'expired' || sub.status === 'cancelled' ? 2 : 3;
  return Array.from({ length: cycles }, (_, c) => {
    const issued = days(sub.planCode.endsWith('annual') ? (c + 1) * 365 : (c + 1) * 30);
    const number = `AG-INV-2026-${String(1000 + i * 10 + c)}`;
    const isCurrent = c === 0;
    const paid = !(isCurrent && ['past_due', 'grace', 'expired'].includes(sub.status));
    return {
      id: `inv_${sub.id}_${c}`,
      number,
      subscriptionId: sub.id,
      userId: sub.userId,
      userEmail: sub.userEmail,
      amountMinor: sub.amountMinor,
      currency: sub.currency,
      status: paid ? 'paid' : isCurrent ? 'open' : 'uncollectible',
      issuedAt: iso(issued),
      dueAt: iso(issued + 7 * 86_400_000),
      paidAt: paid ? iso(issued + (rnd() < 0.6 ? 1 : 3) * 86_400_000) : null,
      provider: sub.provider,
    } satisfies Invoice;
  });
});

const MPESA_RECEIPTS = ['RJK4X7T21Q', 'QGH7Y2M94L', 'SKL9P4D73M', 'TBW2N8K41R', 'RKT6M3V88P', 'OJX5C1Z27N', 'VCB8L6T52W', 'NDQ3F9H16J'];
const FAILURES: Array<{ reason: string; code: string }> = [
  { reason: 'Request cancelled by user (ResultCode 1032)', code: '1032' },
  { reason: 'Insufficient M-PESA balance (ResultCode 1)', code: '1' },
  { reason: 'Transaction timed out before PIN entry (ResultCode 1037)', code: '1037' },
  { reason: 'Wrong PIN entered, retries exhausted (ResultCode 2001)', code: '2001' },
];

export const DEMO_PAYMENTS: Payment[] = (() => {
  const out: Payment[] = [];
  DEMO_INVOICES.forEach((inv, i) => {
    const paidOk = inv.status === 'paid';
    const rolled = rnd();
    const status: Payment['status'] = paidOk && rolled < 0.94 ? 'succeeded' : inv.status === 'paid' ? 'refunded' : rolled < 0.45 ? 'failed' : rolled < 0.8 ? 'pending' : 'initiated';
    const failure = status === 'failed' ? pick(FAILURES) : null;
    const useMpesa = inv.provider === 'mpesa';
    const created = inv.paidAt ? new Date(inv.paidAt).getTime() - 120_000 : new Date(inv.dueAt).getTime() - 3_600_000;
    out.push({
      id: `pay_${String(i + 1).padStart(3, '0')}`,
      reference: `PAY-${sha256(inv.id).slice(0, 8).toUpperCase()}`,
      invoiceId: inv.id,
      userId: inv.userId,
      userEmail: inv.userEmail,
      provider: inv.provider,
      method: useMpesa ? (rnd() < 0.85 ? 'mpesa_stk' : 'mpesa_c2b') : pick(['card', 'bank_transfer', 'ussd'] as const),
      amountMinor: inv.amountMinor,
      currency: inv.currency,
      status,
      providerRef: useMpesa ? `ws_CO_${String(20_261_005_000_000 + i * 337)}` : `FLW-${4_100_000 + i * 913}`,
      mpesaReceipt: useMpesa && status === 'succeeded' ? MPESA_RECEIPTS[i % MPESA_RECEIPTS.length] : null,
      failureReason: failure?.reason ?? null,
      reconciledBy: null,
      refundedMinor: status === 'refunded' ? inv.amountMinor : 0,
      createdAt: iso(created),
      updatedAt: iso(created + 90_000),
    });
  });
  return out;
})();

/* ------------------------------------------------------------- agreements -- */

const AGREEMENT_TITLES: Array<{ title: string; type: string; owner: string }> = [
  { title: 'Loan agreement — KES 250,000 working capital', type: 'loan', owner: 'user_007' },
  { title: 'Tenancy agreement — Kilimani 2-bedroom', type: 'tenancy', owner: 'user_008' },
  { title: 'Supply agreement — hardware, 12-month term', type: 'supply', owner: 'user_011' },
  { title: 'Founder services agreement — 18-month vesting', type: 'services', owner: 'user_012' },
  { title: 'Loan agreement — KES 1,200,000 asset finance', type: 'loan', owner: 'user_014' },
  { title: 'Land sale agreement — Ngong Road plot', type: 'sale', owner: 'user_015' },
  { title: 'Consultancy agreement — 6-month engagement', type: 'services', owner: 'user_016' },
  { title: 'Shareholders agreement — seed round', type: 'corporate', owner: 'user_021' },
  { title: 'Vehicle sale agreement — Toyota Hilux', type: 'sale', owner: 'user_022' },
  { title: 'Employment contract — senior associate', type: 'employment', owner: 'user_010' },
  { title: 'Settlement agreement — invoice dispute', type: 'settlement', owner: 'user_019' },
  { title: 'Loan agreement — KES 80,000 emergency facility', type: 'loan', owner: 'user_023' },
  { title: 'Distribution agreement — East Africa territory', type: 'distribution', owner: 'user_006' },
  { title: 'Tenancy agreement — Westlands office suite', type: 'tenancy', owner: 'user_009' },
  { title: 'Co-founders agreement — product studio', type: 'corporate', owner: 'user_013' },
  { title: 'Equipment lease — solar installation', type: 'lease', owner: 'user_024' },
  { title: 'Loan agreement — KES 500,000 (draft)', type: 'loan', owner: 'user_020' },
  { title: 'Services agreement — retainer (awaiting parties)', type: 'services', owner: 'user_018' },
];

export const DEMO_AGREEMENTS: AgreementSummary[] = AGREEMENT_TITLES.map((a, i) => {
  const owner = DEMO_USERS.find((u) => u.id === a.owner)!;
  const status: AgreementSummary['status'] =
    i % 9 === 0 ? 'draft' : i % 7 === 0 ? 'awaiting_parties' : i % 5 === 0 ? 'awaiting_signatures' : i % 13 === 0 ? 'revoked' : 'completed';
  const requiredSigners = (i % 3) + 2;
  const completedSigners = status === 'completed' ? requiredSigners : Math.min(requiredSigners - 1, i % requiredSigners);
  const created = days(20 + i * 11);
  const completed = status === 'completed' ? created + 3 * 86_400_000 : null;
  return {
    id: `agr_${String(i + 1).padStart(3, '0')}`,
    ref: `AG-${sha256(`agreement-${i}`).slice(0, 6).toUpperCase()}`,
    title: a.title,
    agreementType: a.type,
    ownerId: owner.id,
    ownerEmail: owner.email,
    status,
    currentVersion: status === 'draft' ? 1 : (i % 4) + 1,
    documentHash: status === 'draft' ? null : sha256(`${a.title}:v${(i % 4) + 1}:${i}`),
    partiesCount: requiredSigners + (i % 2),
    requiredSigners,
    completedSigners,
    stampIssuedAt: completed ? iso(completed) : null,
    chainHead: completed ? sha256(`chain-head-${i}`) : null,
    createdAt: iso(created),
    completedAt: completed ? iso(completed) : null,
  };
});

/* --------------------------------------------------- audit + admin ledger -- */

/**
 * Two real chains are seeded so the Verify-chain workspace has genuine,
 * recomputable links — and one deliberately broken chain demonstrates what a
 * failed verification looks like (see DEMO_TAMPERED_AGREEMENT).
 */
function buildChain(agreementId: string, startMs: number, steps: Array<[string, string | null, Record<string, unknown>]>): ChainEvent[] {
  let last: ChainEvent | null = null;
  return steps.map(([eventType, actorId, metadata], idx) => {
    const event = appendToChain(last, {
      id: `evt_${agreementId}_${idx}`,
      agreementId,
      actorId,
      eventType,
      objectId: agreementId,
      occurredAt: iso(startMs + idx * 137_000),
      ipHash: sha256(`${agreementId}-ip-${idx}`).slice(0, 32),
      userAgent: 'Mozilla/5.0 (Linux; Android 14) agree-e/1.0',
      metadata,
    });
    last = event;
    return event;
  });
}

export const DEMO_TAMPERED_AGREEMENT = 'agr_011';

export const DEMO_AUDIT_EVENTS: ChainEvent[] = [
  ...buildChain('agr_001', days(4), [
    ['agreement.created', 'user_007', { title: 'Loan agreement — KES 250,000 working capital', type: 'loan' }],
    ['agreement.version_created', 'user_007', { version: 1, sha256: sha256('agr_001:v1'), bytes: 84_112 }],
    ['agreement.party_invited', 'user_007', { party_role: 'lender', invitation_channel: 'email' }],
    ['party.identity_verified', 'user_020', { assurance_level: 'email_otp_plus_id_document', provider: 'internal' }],
    ['party.consent_recorded', 'user_020', { disclosure_version: 'consent-2026-08-v3', scope: 'sign_and_evidence' }],
    ['party.signed', 'user_020', { version: 2, agreement_version_id: 'agv_001_2', signature_method: 'otp_confirmed_intent' }],
    ['party.signed', 'user_007', { version: 2, agreement_version_id: 'agv_001_2', signature_method: 'otp_confirmed_intent' }],
    ['agreement.completion_evaluated', null, { required: 2, completed: 2, satisfied: true }],
    ['stamp.issued', null, { version: 2, document_sha256: sha256('agr_001:v2'), chain_head: 'pending' }],
    ['evidence.package_generated', null, { format: 'agree-e-evidence-package', version: '1.0', files: 6 }],
  ]),
  ...buildChain('agr_002', days(9), [
    ['agreement.created', 'user_008', { title: 'Tenancy agreement — Kilimani 2-bedroom', type: 'tenancy' }],
    ['agreement.version_created', 'user_008', { version: 1, sha256: sha256('agr_002:v1'), bytes: 91_204 }],
    ['agreement.party_invited', 'user_008', { party_role: 'tenant', invitation_channel: 'sms' }],
    ['party.identity_verified', 'user_017', { assurance_level: 'phone_otp', provider: 'internal' }],
    ['party.consent_recorded', 'user_017', { disclosure_version: 'consent-2026-08-v3', scope: 'sign_and_evidence' }],
    ['party.signed', 'user_017', { version: 1, agreement_version_id: 'agv_002_1', signature_method: 'otp_confirmed_intent' }],
    ['agreement.completion_evaluated', null, { required: 2, completed: 1, satisfied: false }],
  ]),
  ...buildChain('agr_003', days(14), [
    ['agreement.created', 'user_007', { title: 'Loan agreement — KES 1,200,000 asset finance', type: 'loan' }],
    ['agreement.version_created', 'user_007', { version: 1, sha256: sha256('agr_003:v1'), bytes: 120_884 }],
    ['party.identity_verified', 'user_014', { assurance_level: 'email_otp_plus_id_document', provider: 'internal' }],
    ['party.signed', 'user_014', { version: 3, agreement_version_id: 'agv_003_3', signature_method: 'otp_confirmed_intent' }],
    ['party.signed', 'user_007', { version: 3, agreement_version_id: 'agv_003_3', signature_method: 'otp_confirmed_intent' }],
    ['stamp.issued', null, { version: 3, document_sha256: sha256('agr_003:v3') }],
  ]),
  // agr_011: a chain that has been tampered with AFTER hashing. The demo keeps
  // the corrupted row so the Verify-chain workspace can show what a real
  // failure looks like (Build Guide §20: "deliberately modify a copied package
  // and confirm verification fails at the correct event").
  ...(() => {
    const chain = buildChain('agr_011', days(21), [
      ['agreement.created', 'user_019', { title: 'Settlement agreement — invoice dispute', type: 'settlement' }],
      ['agreement.version_created', 'user_019', { version: 1, sha256: sha256('agr_011:v1'), bytes: 66_441 }],
      ['party.identity_verified', 'user_020', { assurance_level: 'email_otp_plus_id_document', provider: 'internal' }],
      ['party.signed', 'user_020', { version: 1, agreement_version_id: 'agv_011_1', signature_method: 'otp_confirmed_intent' }],
      ['stamp.issued', null, { version: 1, document_sha256: sha256('agr_011:v1') }],
    ]);
    const target = chain[2];
    return [
      chain[0], chain[1],
      { ...target, metadata: { ...target.metadata, assurance_level: 'email_otp_only' } }, // silently downgraded
      chain[3], chain[4],
    ];
  })(),
];

export const DEMO_ADMIN_ACTIONS: AdminActionRecord[] = (() => {
  const rows: Array<[string, string, string, string, string, AdminActionRecord['status'], number]> = [
    ['admin.login', 'user_002', 'user', 'user_002', 'Brian Otieno', 'succeeded', 1],
    ['admin.step_up_verified', 'user_002', 'user', 'user_002', 'Brian Otieno', 'succeeded', 1],
    ['password.reset_link_issued', 'user_003', 'user', 'user_020', 'Samuel Njoroge', 'succeeded', 5],
    ['sessions.revoked', 'user_004', 'user', 'user_019', 'Tabitha Mueni', 'succeeded', 8],
    ['billing.subscription.plan_changed', 'user_002', 'subscription', 'sub_014', 'Advocate Practice → Firm', 'succeeded', 26],
    ['billing.payment.reconciled', 'user_005', 'payment', 'pay_012', 'PAY-8C31A2F0', 'succeeded', 30],
    ['plan.updated', 'user_001', 'plan', 'plan_firm_m', 'Firm — price change', 'succeeded', 32],
    ['password.temp_issued_breakglass', 'user_002', 'user', 'user_023', 'Wilfred Barasa', 'succeeded', 51],
    ['user.locked', 'user_004', 'user', 'user_020', 'Tabitha Mueni', 'succeeded', 54],
    ['agreements.content.read.privileged', 'user_004', 'agreement', 'agr_011', 'AG-9F12AB (privileged read)', 'succeeded', 60],
    ['user.role_changed', 'user_001', 'user', 'user_005', 'Esther Nekesa → Billing', 'succeeded', 72],
    ['password.force_reset_required', 'user_003', 'user', 'user_022', 'Violet Nyambura', 'succeeded', 80],
    ['billing.refund_issued', 'user_005', 'payment', 'pay_019', 'PAY-2E77B109', 'succeeded', 120],
    ['mfa.requirement_changed', 'user_004', 'user', 'user_018', 'Rashid Juma — MFA required', 'succeeded', 140],
    ['admin.exported_user_list', 'user_002', 'setting', 'export', 'users.csv (1,284 rows)', 'succeeded', 168],
    ['user.suspended', 'user_002', 'user', 'user_020', 'Samuel Njoroge', 'succeeded', 200],
    ['password.reset_link_issued', 'user_003', 'user', 'user_017', 'Quinter Adhiambo', 'failed', 210],
  ];
  let previousHash: string | null = null;
  const out = rows.map(([action, adminId, targetType, targetId, targetLabel, status, hoursAgo], idx) => {
    const admin = DEMO_USERS.find((u) => u.id === adminId)!;
    const base: Omit<AdminActionRecord, 'previousHash' | 'eventHash'> = {
      id: `adm_${String(idx + 1).padStart(3, '0')}`,
      adminId,
      adminEmail: admin.email,
      adminRole: admin.role,
      action,
      targetType: targetType as AdminActionRecord['targetType'],
      targetId,
      targetLabel,
      reason: indexReason(action),
      status,
      stepUp: action !== 'admin.login' && action !== 'admin.exported_user_list',
      ipHash: sha256(`admin-ip-${idx}`).slice(0, 32),
      userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) agree-e-console/1.0',
      occurredAt: iso(hours(hoursAgo)),
      metadata: {},
    };
    const link = previousHash;
    const eventHash = computeAdminActionHash(link, base);
    previousHash = eventHash;
    return { ...base, previousHash: link, eventHash };
  });
  return out.reverse();
})();

function indexReason(action: string): string {
  const map: Record<string, string> = {
    'admin.login': 'Console authentication.',
    'admin.step_up_verified': 'Step-up verification for privileged session.',
    'password.reset_link_issued': 'Customer called support after losing device; identity confirmed via registered phone call-back.',
    'sessions.revoked': 'Suspected session theft reported by account owner.',
    'password.temp_issued_breakglass': 'Account owner locked out during live signing session; supervisor approved break-glass after video identity check.',
    'user.locked': 'Automated lock after 9 failed sign-in attempts; verified with owner.',
    'user.suspended': 'Suspension after repeated reconciliation failures and chargeback risk review.',
    'billing.refund_issued': 'Duplicate M-PESA charge confirmed on reconciliation; customer notified.',
    'agreements.content.read.privileged': 'Security incident triage: suspected credential stuffing on this agreement; counsel-approved access.',
    'plan.updated': 'Annual price review approved for FY2027 catalogue.',
  };
  return map[action] ?? 'Operational action recorded with justification.';
}

/* ------------------------------------------------------- security events -- */

export const DEMO_SECURITY_EVENTS: SecurityEventRecord[] = [
  ['credential_stuffing_suspected', 'critical', 'Burst of 412 sign-in attempts across 68 accounts from 3 IP ranges.', 2],
  ['failed_admin_signin', 'warning', '5 failed console sign-ins for brian.otieno@agree-e.com; challenged with MFA and step-up.', 6],
  ['mfa_disabled', 'notice', 'MFA disabled for support role account cynthia.mwikali@agree-e.com — policy violation, remediation due.', 22],
  ['session_revoked', 'info', 'Sessions revoked for user_019 by Daniel Kariuki after owner report.', 8],
  ['break_glass_used', 'warning', 'Break-glass temporary credential issued for user_023; expires in 30 minutes.', 51],
  ['rate_limit_triggered', 'notice', 'WAF rate limit engaged on /api/verify after 60 requests/minute.', 30],
  ['privileged_access', 'notice', 'Privileged agreement metadata read for agr_011 by security role.', 60],
  ['password_reset_completed', 'info', 'Self-service recovery completed for user_020 after admin-issued link.', 5],
  ['impossible_travel', 'warning', 'Sign-in from Mombasa 40 minutes after Nairobi session start; challenge issued.', 96],
  ['api_key_rejected', 'info', 'M-PESA OAuth token rejected; consumer secret rotated.', 120],
  ['webhook_signature_invalid', 'critical', 'Unsigned POST to /api/webhooks/flutterwave discarded (401).', 140],
  ['data_export_requested', 'info', 'Data-subject access request logged under DPA workflow; fulfilment due in 30 days.', 160],
  ['retention_job_run', 'info', 'Retention sweep archived 184 draft objects older than 24 months.', 180],
  ['dpa_breach_register_updated', 'notice', 'Breach register entry closed after ODPC notification window assessed.', 240],
].map((row, i) => {
  const [type, severity, detail, hoursAgo] = row as [string, SecurityEventRecord['severity'], string, number];
  return {
    id: `sec_${String(i + 1).padStart(3, '0')}`,
    userId: type.includes('admin') ? 'user_002' : i % 3 === 0 ? 'user_020' : i % 3 === 1 ? 'user_019' : null,
    type,
    severity,
    detail,
    ipHash: sha256(`sec-ip-${i}`).slice(0, 32),
    occurredAt: iso(hours(hoursAgo)),
  };
});

/* ----------------------------------------------------------------- coupons -- */

export const DEMO_COUPONS: Coupon[] = [
  { id: 'cpn_001', code: 'LSK2026', percentOff: 25, maxRedemptions: 500, redemptions: 138, expiresAt: iso(days(-120)), active: true, createdAt: iso(weeks(20)) },
  { id: 'cpn_002', code: 'EARLYBIRD', percentOff: 40, maxRedemptions: 100, redemptions: 100, expiresAt: iso(days(30)), active: false, createdAt: iso(weeks(40)) },
  { id: 'cpn_003', code: 'FIRMFIRST', percentOff: 15, maxRedemptions: 200, redemptions: 41, expiresAt: iso(days(-60)), active: true, createdAt: iso(weeks(12)) },
];

export const DEMO_SESSIONS: UserSession[] = DEMO_USERS.filter((u) => u.status === 'active').slice(0, 12).flatMap((u, i) =>
  Array.from({ length: (i % 3) + 1 }, (_, s) => ({
    id: `ses_${u.id}_${s}`,
    userId: u.id,
    ipHash: sha256(`session-${u.id}-${s}`).slice(0, 32),
    userAgent: s === 0 ? 'Chrome 141 · macOS 15.4' : s === 1 ? 'agree-e Android 1.0 · Pixel 8' : 'Safari 19 · iOS 19.1',
    createdAt: iso(hours(2 + i * 3 + s)),
    lastSeenAt: iso(hours(s) ),
    expiresAt: iso(hours(-10 + s)),
    current: false,
    mfaSatisfied: u.mfaEnabled,
  })),
);

export const DEMO_ANCHOR = DEMO_NOW;
export { DEMO_NOW };
