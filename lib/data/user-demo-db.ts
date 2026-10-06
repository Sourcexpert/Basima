import { appendToChain, type AuditEventRecord } from '@/lib/audit/chain';
import { buildPackage } from '@/lib/evidence/package';
import { sha256 } from '@/lib/crypto/hash';
import { DEMO_NOW, DEMO_AGREEMENTS, DEMO_USERS } from '@/lib/data/demo-db';
import type {
  AgreementDocument, AgreementParty, AgreementSummary, ConsentRecord, DataSubjectRequest,
  EvidencePackageRecord, SignatureEvent, SignatureRequest,
} from '@/lib/data/types';

/**
 * User-workspace seed.
 *
 * Shares the same agreement ids, profiles and audit ledger as the admin console,
 * so a signing performed in the user workspace is immediately visible in the
 * console's evidence view — the two rooms of the guide's §21 briefing, over one
 * record. Timestamps are derived from the same fixed anchor so server render and
 * client hydration agree and seeded chains hash identically on every boot.
 */
const DAY = 86_400_000;
const days = (n: number) => DEMO_NOW - n * DAY;
const hours = (n: number) => DEMO_NOW - n * 3_600_000;
const iso = (ms: number) => new Date(ms).toISOString();

const user = (id: string) => DEMO_USERS.find((u) => u.id === id)!;

export const USER_WORKSPACE_OWNER = 'user_011'; // Kevin Mwangi — AgriEase Ltd

/* -------------------------------------------------------------- documents -- */

const SUPPLY_AGREEMENT_V3 = `SUPPLY AGREEMENT
Reference: AG-SUPPLY-2026-114 · Version 3 (executed)

BETWEEN
  AgriEase Ltd, of Kilimani, Nairobi (the "Buyer"), and
  Ngaa General Supplies Ltd, of Industrial Area, Nairobi (the "Supplier").

1. GOODS AND TERM
1.1 The Supplier shall supply irrigation fittings, drip lines and pump assemblies
    as itemised in Schedule A, in accordance with the specifications in Schedule B.
1.2 The term is twelve (12) months from the date of signature, renewable by written
    agreement of both parties not less than thirty (30) days before expiry.

2. DELIVERY
2.1 Delivery shall be made to the Buyer's warehouse in Industrial Area within
    fourteen (14) days of each written order.
2.2 Risk passes on delivery; title passes on payment in full.

3. PRICE AND PAYMENT
3.1 Prices are fixed for the first six (6) months and reviewed thereafter in writing.
3.2 Payment is due within thirty (30) days of a valid tax invoice.
3.3 Late payment attracts interest at two per centum (2%) per month on the
    outstanding balance, calculated daily.

4. QUALITY AND WARRANTY
4.1 All goods must conform to KS EN standards as applicable.
4.2 The Supplier warrants goods against defect for twelve (12) months from delivery.

5. VARIATION
5.1 No variation of this agreement is effective unless recorded as a new version
    within the agre-e system and signed by both parties. Earlier versions remain
    part of the record and are not amended.

6. GOVERNING LAW
6.1 This agreement is governed by the laws of Kenya and the parties submit to the
    exclusive jurisdiction of the courts of Kenya.

Executed by the parties whose signatures appear in the accompanying evidence chain.`;

const SUPPLY_AGREEMENT_V2 = `SUPPLY AGREEMENT
Reference: AG-SUPPLY-2026-114 · Version 2

BETWEEN
  AgriEase Ltd, of Kilimani, Nairobi (the "Buyer"), and
  Ngaa General Supplies Ltd, of Industrial Area, Nairobi (the "Supplier").

1. GOODS AND TERM
1.1 The Supplier shall supply irrigation fittings, drip lines and pump assemblies
    as itemised in Schedule A, in accordance with the specifications in Schedule B.
1.2 The term is twelve (12) months from the date of signature.

2. DELIVERY
2.1 Delivery shall be made to the Buyer's warehouse in Industrial Area within
    fourteen (14) days of each written order.

3. PRICE AND PAYMENT
3.1 Prices are fixed for the first six (6) months and reviewed thereafter in writing.
3.2 Payment is due within thirty (30) days of a valid tax invoice.

4. QUALITY AND WARRANTY
4.1 All goods must conform to KS EN standards as applicable.
4.2 The Supplier warrants goods against defect for six (6) months from delivery.

5. VARIATION
5.1 No variation of this agreement is effective unless recorded as a new version
    within the agre-e system and signed by both parties.

6. GOVERNING LAW
6.1 This agreement is governed by the laws of Kenya.`;

const SUPPLY_AGREEMENT_V1 = `SUPPLY AGREEMENT (draft)
Reference: AG-SUPPLY-2026-114 · Version 1

BETWEEN AgriEase Ltd (the "Buyer") and the Supplier named in Schedule 1.

1. GOODS AND TERM
1.1 The Supplier shall supply irrigation fittings and pump assemblies per Schedule A
    for a term of twelve (12) months.

2. DELIVERY
2.1 Delivery to the Buyer's warehouse within fourteen (14) days of each order.

3. PRICE AND PAYMENT
3.1 Prices fixed for six (6) months; payment due within thirty (30) days of invoice.

4. GOVERNING LAW
4.1 The laws of Kenya apply.

[Version 1 — superseded. Retained unaltered as part of the agreement record.]`;

const RETAINER_V2 = `SERVICES AGREEMENT — DISTRIBUTION RETAINER
Reference: AG-RETAINER-2026-041 · Version 2

BETWEEN
  Muthama & Associates Advocates (the "Firm"), and
  AgriEase Ltd (the "Client").

1. SCOPE
1.1 The Firm shall provide distribution, agency and regulatory advisory services in
    respect of the Client's East Africa territory expansion, as detailed in Schedule 1.
1.2 The engagement runs for six (6) months from the commencement date, with two
    optional renewals of three (3) months each by written notice.

2. FEES
2.1 A monthly retainer of Kenya Shillings Four Hundred and Fifty Thousand
    (KES 450,000) exclusive of disbursements and VAT.
2.2 Invoices are payable within fourteen (14) days of receipt.

3. CONFIDENTIALITY
3.1 Each party shall keep confidential all commercial information received from the
    other and shall not disclose it save as required by law or with written consent.

4. INTELLECTUAL PROPERTY
4.1 Deliverables prepared under this engagement vest in the Client on payment.

5. TERMINATION
5.1 Either party may terminate on thirty (30) days' written notice.
5.2 Termination does not affect the evidentiary record of actions already completed.

6. GOVERNING LAW AND DISPUTES
6.1 The laws of Kenya govern. The parties shall attempt good-faith negotiation for
    fourteen (14) days before commencing any proceedings.

Executed in counterpart. This version supersedes Version 1 in full; Version 1 remains
unaltered on the record.`;

const LOAN_DRAFT_V1 = `LOAN AGREEMENT (DRAFT — NOT YET EXECUTED)
Reference: AG-LOAN-2026-207 · Version 1

LENDER:  AgriEase Ltd
BORROWER: [to be inserted]

1. PRINCIPAL AND PURPOSE
1.1 The Lender shall advance Kenya Shillings Five Hundred Thousand (KES 500,000)
    for the purchase of a maize milling unit.

2. REPAYMENT
2.1 Repayable in twelve (12) equal monthly instalments of KES 45,833 commencing
    thirty (30) days after drawdown.

3. SECURITY
3.1 [Security to be agreed — chattel mortgage over the unit under consideration.]

4. DEFAULT
4.1 On default the entire balance becomes immediately payable.

NOTE: This is a working draft. No party has been invited and nothing has been signed.
       Do not rely on it as an executed instrument.`;

const WAREHOUSE_TENANCY_V1 = `TENANCY AGREEMENT (DRAFT — AWAITING PARTIES)
Reference: AG-TENANCY-2026-233 · Version 1

LANDLORD: AgriEase Ltd
TENANT: [invitation issued]

1. PREMISES
1.1 A warehouse unit of 450 square metres at Industrial Area, Nairobi, as edged red
    on the plan annexed.

2. TERM AND RENT
2.1 Term of twenty-four (24) months at Kenya Shillings One Hundred and Eighty
    Thousand (KES 180,000) per month, payable monthly in advance.
2.2 Deposit equivalent to three (3) months' rent, refundable within thirty (30) days
    of vacant possession.

3. REPAIRS AND INSURANCE
3.1 The Tenant keeps the interior in good repair; the Landlord insures the structure.

4. GOVERNING LAW
4.1 The laws of Kenya apply.

NOTE: Invitations issued; no signature recorded.`;

const EMPLOYMENT_REVOKED_V1 = `EMPLOYMENT CONTRACT (REVOKED)
Reference: AG-EMPLOY-2026-118 · Version 1

EMPLOYER: AgriEase Ltd
EMPLOYEE: [name withheld from this demonstration dataset]

1. POSITION AND TERM
1.1 Field Agronomist, fixed term of twenty-four (24) months, probation of three (3)
    months.

2. REMUNERATION
2.1 Kenya Shillings One Hundred and Ten Thousand (KES 110,000) per month, subject
    to statutory deductions.

STATUS: This contract was revoked by the owner before completion, following the
        candidate's withdrawal. The record is retained unaltered; nothing was
        deleted. The revocation event and its reason form part of the chain.`;

export const USER_DOCUMENTS: AgreementDocument[] = [
  {
    id: 'agv_023_2', agreementId: 'agr_023', versionNumber: 2, storagePath: 'agreements/agr_023/v2.txt',
    sha256: sha256(SUPPLY_AGREEMENT_V2), byteSize: SUPPLY_AGREEMENT_V2.length, createdBy: 'user_011',
    createdAt: iso(days(90)), frozenAt: null, body: SUPPLY_AGREEMENT_V2,
  },
  {
    id: 'agv_023_1', agreementId: 'agr_023', versionNumber: 1, storagePath: 'agreements/agr_023/v1.txt',
    sha256: sha256(SUPPLY_AGREEMENT_V1), byteSize: SUPPLY_AGREEMENT_V1.length, createdBy: 'user_011',
    createdAt: iso(days(96)), frozenAt: null, body: SUPPLY_AGREEMENT_V1,
  },
  {
    id: 'agv_023_3', agreementId: 'agr_023', versionNumber: 3, storagePath: 'agreements/agr_023/v3.txt',
    sha256: sha256(SUPPLY_AGREEMENT_V3), byteSize: SUPPLY_AGREEMENT_V3.length, createdBy: 'user_011',
    createdAt: iso(days(84)), frozenAt: iso(days(82)), body: SUPPLY_AGREEMENT_V3,
  },
  {
    id: 'agv_019_1', agreementId: 'agr_019', versionNumber: 1, storagePath: 'agreements/agr_019/v1.txt',
    sha256: sha256(RETAINER_V2.replace('Version 2', 'Version 1')), byteSize: 1_204, createdBy: 'user_006',
    createdAt: iso(days(21)), frozenAt: null, body: RETAINER_V2.replace('Version 2', 'Version 1'),
  },
  {
    id: 'agv_019_2', agreementId: 'agr_019', versionNumber: 2, storagePath: 'agreements/agr_019/v2.txt',
    sha256: sha256(RETAINER_V2), byteSize: RETAINER_V2.length, createdBy: 'user_006',
    createdAt: iso(days(14)), frozenAt: null, body: RETAINER_V2,
  },
  {
    id: 'agv_020_1', agreementId: 'agr_020', versionNumber: 1, storagePath: 'agreements/agr_020/v1.txt',
    sha256: sha256(LOAN_DRAFT_V1), byteSize: LOAN_DRAFT_V1.length, createdBy: 'user_011',
    createdAt: iso(days(3)), frozenAt: null, body: LOAN_DRAFT_V1,
  },
  {
    id: 'agv_021_1', agreementId: 'agr_021', versionNumber: 1, storagePath: 'agreements/agr_021/v1.txt',
    sha256: sha256(WAREHOUSE_TENANCY_V1), byteSize: WAREHOUSE_TENANCY_V1.length, createdBy: 'user_011',
    createdAt: iso(days(6)), frozenAt: null, body: WAREHOUSE_TENANCY_V1,
  },
  {
    id: 'agv_022_1', agreementId: 'agr_022', versionNumber: 1, storagePath: 'agreements/agr_022/v1.txt',
    sha256: sha256(EMPLOYMENT_REVOKED_V1), byteSize: EMPLOYMENT_REVOKED_V1.length, createdBy: 'user_011',
    createdAt: iso(days(40)), frozenAt: null, body: EMPLOYMENT_REVOKED_V1,
  },
];

/* ---------------------------------------------------------------- parties -- */

function party(args: {
  id: string; agreementId: string; userKey: string | null; displayName: string; email: string;
  partyRole: string; signingRequired: boolean; order: number;
  status: AgreementParty['status']; invitedDaysAgo: number | null; acceptedDaysAgo: number | null;
  assurance?: string | null; verifiedDaysAgo?: number | null;
}): AgreementParty {
  return {
    id: args.id,
    agreementId: args.agreementId,
    userId: args.userKey,
    displayName: args.displayName,
    email: args.email,
    partyRole: args.partyRole,
    signingRequired: args.signingRequired,
    signingOrder: args.order,
    status: args.status,
    invitationSentAt: args.invitedDaysAgo === null ? null : iso(days(args.invitedDaysAgo)),
    invitationAcceptedAt: args.acceptedDaysAgo === null ? null : iso(days(args.acceptedDaysAgo)),
    assuranceLevel: args.assurance ?? null,
    identityVerifiedAt: args.verifiedDaysAgo == null ? null : iso(days(args.verifiedDaysAgo)),
  };
}

const kevin = user('user_011');
const felix = user('user_006');
const grace = user('user_007');
const joseph = user('user_010');
const purity = user('user_016');
const quinter = user('user_017');

export const USER_PARTIES: AgreementParty[] = [
  // agr_023 — completed: every required signer has signed.
  party({ id: 'pty_023_1', agreementId: 'agr_023', userKey: kevin.id, displayName: kevin.displayName, email: kevin.email, partyRole: 'buyer', signingRequired: true, order: 1, status: 'accepted', invitedDaysAgo: 92, acceptedDaysAgo: 91, assurance: 'email_otp_plus_id_document', verifiedDaysAgo: 90 }),
  party({ id: 'pty_023_2', agreementId: 'agr_023', userKey: grace.id, displayName: grace.displayName, email: grace.email, partyRole: 'supplier', signingRequired: true, order: 2, status: 'accepted', invitedDaysAgo: 92, acceptedDaysAgo: 90, assurance: 'email_otp_plus_id_document', verifiedDaysAgo: 89 }),
  party({ id: 'pty_023_3', agreementId: 'agr_023', userKey: purity.id, displayName: purity.displayName, email: purity.email, partyRole: 'financier', signingRequired: true, order: 3, status: 'accepted', invitedDaysAgo: 91, acceptedDaysAgo: 88, assurance: 'email_otp', verifiedDaysAgo: 87 }),
  party({ id: 'pty_023_4', agreementId: 'agr_023', userKey: joseph.id, displayName: joseph.displayName, email: joseph.email, partyRole: 'guarantor', signingRequired: true, order: 4, status: 'accepted', invitedDaysAgo: 91, acceptedDaysAgo: 86, assurance: 'email_otp', verifiedDaysAgo: 85 }),

  // agr_019 — awaiting signatures: the counterparty has signed; Kevin has not.
  party({ id: 'pty_019_1', agreementId: 'agr_019', userKey: felix.id, displayName: felix.displayName, email: felix.email, partyRole: 'firm', signingRequired: true, order: 1, status: 'accepted', invitedDaysAgo: 21, acceptedDaysAgo: 20, assurance: 'email_otp_plus_id_document', verifiedDaysAgo: 19 }),
  party({ id: 'pty_019_2', agreementId: 'agr_019', userKey: kevin.id, displayName: kevin.displayName, email: kevin.email, partyRole: 'client', signingRequired: true, order: 2, status: 'accepted', invitedDaysAgo: 21, acceptedDaysAgo: 18, assurance: 'email_otp_plus_id_document', verifiedDaysAgo: 17 }),

  // agr_021 — awaiting parties: invitation issued, not yet accepted.
  party({ id: 'pty_021_1', agreementId: 'agr_021', userKey: null, displayName: 'Warehouse tenant (invited)', email: quinter.email, partyRole: 'tenant', signingRequired: true, order: 1, status: 'invited', invitedDaysAgo: 5, acceptedDaysAgo: null }),

  // agr_022 — revoked before completion.
  party({ id: 'pty_022_1', agreementId: 'agr_022', userKey: kevin.id, displayName: kevin.displayName, email: kevin.email, partyRole: 'employer', signingRequired: true, order: 1, status: 'accepted', invitedDaysAgo: 39, acceptedDaysAgo: 38, assurance: 'email_otp', verifiedDaysAgo: 37 }),
  party({ id: 'pty_022_2', agreementId: 'agr_022', userKey: null, displayName: 'Candidate (withdrew)', email: 'candidate.agronomist@example.com', partyRole: 'employee', signingRequired: true, order: 2, status: 'declined', invitedDaysAgo: 39, acceptedDaysAgo: null, assurance: 'email_otp', verifiedDaysAgo: 36 }),
];

/* ------------------------------------------- signature requests and events -- */

export const USER_SIGNATURE_REQUESTS: SignatureRequest[] = [
  { id: 'srq_023_1', agreementId: 'agr_023', versionId: 'agv_023_3', partyId: 'pty_023_1', requestedBy: kevin.id, status: 'signed', requestedAt: iso(days(84)), expiresAt: iso(days(54)) },
  { id: 'srq_023_2', agreementId: 'agr_023', versionId: 'agv_023_3', partyId: 'pty_023_2', requestedBy: kevin.id, status: 'signed', requestedAt: iso(days(84)), expiresAt: iso(days(54)) },
  { id: 'srq_023_3', agreementId: 'agr_023', versionId: 'agv_023_3', partyId: 'pty_023_3', requestedBy: kevin.id, status: 'signed', requestedAt: iso(days(84)), expiresAt: iso(days(54)) },
  { id: 'srq_023_4', agreementId: 'agr_023', versionId: 'agv_023_3', partyId: 'pty_023_4', requestedBy: kevin.id, status: 'signed', requestedAt: iso(days(84)), expiresAt: iso(days(54)) },
  { id: 'srq_019_1', agreementId: 'agr_019', versionId: 'agv_019_2', partyId: 'pty_019_1', requestedBy: felix.id, status: 'signed', requestedAt: iso(days(14)), expiresAt: iso(days(14 - 30)) },
  { id: 'srq_019_2', agreementId: 'agr_019', versionId: 'agv_019_2', partyId: 'pty_019_2', requestedBy: felix.id, status: 'viewed', requestedAt: iso(days(14)), expiresAt: iso(days(14 - 30)) },

  { id: 'srq_021_1', agreementId: 'agr_021', versionId: 'agv_021_1', partyId: 'pty_021_1', requestedBy: kevin.id, status: 'requested', requestedAt: iso(days(5)), expiresAt: iso(days(-25)) },
];

export const USER_SIGNATURE_EVENTS: SignatureEvent[] = [
  { id: 'sev_023_1', agreementId: 'agr_023', versionId: 'agv_023_3', partyId: 'pty_023_1', actorId: kevin.id, signatureMethod: 'otp_confirmed_intent', outcome: 'signed', consentId: 'cns_023_1', occurredAt: iso(days(83)), ipHash: sha256('sev-023-1').slice(0, 32), userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) agree-e/1.0' },
  { id: 'sev_023_2', agreementId: 'agr_023', versionId: 'agv_023_3', partyId: 'pty_023_2', actorId: grace.id, signatureMethod: 'otp_confirmed_intent', outcome: 'signed', consentId: 'cns_023_2', occurredAt: iso(days(83) + 5_400_000), ipHash: sha256('sev-023-2').slice(0, 32), userAgent: 'Mozilla/5.0 (Linux; Android 14) agree-e/1.0' },
  { id: 'sev_023_3', agreementId: 'agr_023', versionId: 'agv_023_3', partyId: 'pty_023_3', actorId: purity.id, signatureMethod: 'otp_confirmed_intent', outcome: 'signed', consentId: 'cns_023_3', occurredAt: iso(days(82)), ipHash: sha256('sev-023-3').slice(0, 32), userAgent: 'Mozilla/5.0 (Windows NT 10.0) agree-e/1.0' },
  { id: 'sev_023_4', agreementId: 'agr_023', versionId: 'agv_023_3', partyId: 'pty_023_4', actorId: joseph.id, signatureMethod: 'otp_confirmed_intent', outcome: 'signed', consentId: 'cns_023_4', occurredAt: iso(days(82) + 2_400_000), ipHash: sha256('sev-023-4').slice(0, 32), userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 19_0) agree-e/1.0' },
  { id: 'sev_019_1', agreementId: 'agr_019', versionId: 'agv_019_2', partyId: 'pty_019_1', actorId: felix.id, signatureMethod: 'otp_confirmed_intent', outcome: 'signed', consentId: 'cns_019_1', occurredAt: iso(days(13)), ipHash: sha256('sev-019-1').slice(0, 32), userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) agree-e/1.0' },
];

export const USER_CONSENTS: ConsentRecord[] = [
  { id: 'cns_023_1', agreementId: 'agr_023', userId: kevin.id, disclosureVersion: 'consent-2026-08-v3', scope: 'sign_and_evidence', acceptedAt: iso(days(83)), ipHash: sha256('cns-023-1').slice(0, 32) },
  { id: 'cns_023_2', agreementId: 'agr_023', userId: grace.id, disclosureVersion: 'consent-2026-08-v3', scope: 'sign_and_evidence', acceptedAt: iso(days(83) + 5_400_000), ipHash: sha256('cns-023-2').slice(0, 32) },
  { id: 'cns_023_3', agreementId: 'agr_023', userId: purity.id, disclosureVersion: 'consent-2026-08-v3', scope: 'sign_and_evidence', acceptedAt: iso(days(82)), ipHash: sha256('cns-023-3').slice(0, 32) },
  { id: 'cns_023_4', agreementId: 'agr_023', userId: joseph.id, disclosureVersion: 'consent-2026-08-v3', scope: 'sign_and_evidence', acceptedAt: iso(days(82) + 2_400_000), ipHash: sha256('cns-023-4').slice(0, 32) },
  { id: 'cns_019_1', agreementId: 'agr_019', userId: felix.id, disclosureVersion: 'consent-2026-08-v3', scope: 'sign_and_evidence', acceptedAt: iso(days(13)), ipHash: sha256('cns-019-1').slice(0, 32) },
];

/* -------------------------------------------- additional agreement records -- */

function ref(seed: string) {
  return `AG-${sha256(seed).slice(0, 6).toUpperCase()}`;
}

export const USER_AGREEMENTS: AgreementSummary[] = [
  {
    id: 'agr_023', ref: ref('supply-2026-114'), title: 'Supply agreement — irrigation fittings and drip lines',
    agreementType: 'supply', ownerId: kevin.id, ownerEmail: kevin.email, status: 'completed',
    currentVersion: 3, documentHash: sha256(SUPPLY_AGREEMENT_V3), partiesCount: 4, requiredSigners: 4, completedSigners: 4,
    stampIssuedAt: iso(days(82) + 3_600_000), chainHead: null, createdAt: iso(days(96)), completedAt: iso(days(82) + 3_600_000),
  },
  {
    id: 'agr_019', ref: ref('retainer-2026-041'), title: 'Services agreement — distribution retainer',
    agreementType: 'services', ownerId: felix.id, ownerEmail: felix.email, status: 'awaiting_signatures',
    currentVersion: 2, documentHash: sha256(RETAINER_V2), partiesCount: 2, requiredSigners: 2, completedSigners: 1,
    stampIssuedAt: null, chainHead: null, createdAt: iso(days(21)), completedAt: null,
  },
  {
    id: 'agr_020', ref: ref('loan-2026-207'), title: 'Loan agreement — KES 500,000 equipment finance',
    agreementType: 'loan', ownerId: kevin.id, ownerEmail: kevin.email, status: 'draft',
    currentVersion: 1, documentHash: sha256(LOAN_DRAFT_V1), partiesCount: 0, requiredSigners: 0, completedSigners: 0,
    stampIssuedAt: null, chainHead: null, createdAt: iso(days(3)), completedAt: null,
  },
  {
    id: 'agr_021', ref: ref('tenancy-2026-233'), title: 'Tenancy agreement — Industrial Area warehouse',
    agreementType: 'tenancy', ownerId: kevin.id, ownerEmail: kevin.email, status: 'awaiting_parties',
    currentVersion: 1, documentHash: sha256(WAREHOUSE_TENANCY_V1), partiesCount: 1, requiredSigners: 1, completedSigners: 0,
    stampIssuedAt: null, chainHead: null, createdAt: iso(days(6)), completedAt: null,
  },
  {
    id: 'agr_022', ref: ref('employ-2026-118'), title: 'Employment contract — field agronomist (revoked)',
    agreementType: 'employment', ownerId: kevin.id, ownerEmail: kevin.email, status: 'revoked',
    currentVersion: 1, documentHash: sha256(EMPLOYMENT_REVOKED_V1), partiesCount: 2, requiredSigners: 2, completedSigners: 0,
    stampIssuedAt: null, chainHead: null, createdAt: iso(days(40)), completedAt: null,
  },
];

/* ------------------------------------------------------- evidence chains -- */

function buildChain(
  agreementId: string,
  startMs: number,
  steps: Array<[string, string | null, Record<string, unknown>]>,
): AuditEventRecord[] {
  let last: AuditEventRecord | null = null;
  return steps.map(([eventType, actorId, metadata], idx) => {
    const event = appendToChain(last, {
      id: `evt_${agreementId}_${idx}`,
      agreementId,
      actorId,
      eventType,
      objectId: agreementId,
      occurredAt: iso(startMs + idx * 131_000),
      ipHash: sha256(`${agreementId}-ip-${idx}`).slice(0, 32),
      userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) agree-e/1.0',
      metadata,
    });
    last = event;
    return event;
  });
}


/**
 * Same construction as buildChain, but with explicit timestamps so a long-lived
 * agreement's events line up with its signature records instead of being squeezed
 * into a few minutes of clock.
 */
/** n evenly spaced instants between two points in time. */
function span(fromMs: number, toMs: number, count: number): number[] {
  if (count <= 1) return [fromMs];
  const step = (toMs - fromMs) / (count - 1);
  return Array.from({ length: count }, (_, i) => Math.round(fromMs + i * step));
}

function buildChainAt(
  agreementId: string,
  times: number[],
  steps: Array<[string, string | null, Record<string, unknown>]>,
): AuditEventRecord[] {
  let last: AuditEventRecord | null = null;
  return steps.map(([eventType, actorId, metadata], idx) => {
    const event = appendToChain(last, {
      id: `evt_${agreementId}_${idx}`,
      agreementId,
      actorId,
      eventType,
      objectId: agreementId,
      occurredAt: iso(times[Math.min(idx, times.length - 1)]),
      ipHash: sha256(`${agreementId}-ip-${idx}`).slice(0, 32),
      userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) agree-e/1.0',
      metadata,
    });
    last = event;
    return event;
  });
}

export const USER_AUDIT_EVENTS: AuditEventRecord[] = [
  // agr_019 — in flight, counterparty has signed, awaiting the client.
  ...buildChain('agr_019', days(21), [
    ['agreement.created', felix.id, { title: 'Services agreement — distribution retainer', type: 'services' }],
    ['agreement.version_created', felix.id, { version: 1, sha256: sha256(RETAINER_V2.replace('Version 2', 'Version 1')), note: 'Initial draft shared for comment.' }],
    ['agreement.party_invited', felix.id, { party_role: 'client', invitation_channel: 'email', signing_order: 2 }],
    ['agreement.version_created', felix.id, { version: 2, sha256: sha256(RETAINER_V2), note: 'Fee clause 2.2 amended to fourteen (14) days; supersedes version 1.' }],
    ['agreement.party_invited', felix.id, { party_role: 'firm', invitation_channel: 'email', signing_order: 1 }],
    ['party.identity_verified', felix.id, { assurance_level: 'email_otp_plus_id_document', provider: 'internal' }],
    ['party.consent_recorded', felix.id, { disclosure_version: 'consent-2026-08-v3', scope: 'sign_and_evidence' }],
    ['party.signed', felix.id, { version: 2, agreement_version_id: 'agv_019_2', signature_method: 'otp_confirmed_intent', signature_event_id: 'sev_019_1' }],
    ['agreement.completion_evaluated', null, { required: 2, completed: 1, satisfied: false, pending_party_roles: ['client'] }],
  ]),
  // agr_023 — the executed supply agreement: four required signatures, a frozen
  // version, a stamp and an exported package. This is the record a counterparty
  // disputes two years from now, so it is seeded in full.
  ...buildChainAt('agr_023', span(days(96), days(82) + 7_200_000, 18), [
    ['agreement.created', kevin.id, { title: 'Supply agreement — irrigation fittings and drip lines', type: 'supply', reference: 'AG-SUPPLY-2026-114' }],
    ['agreement.version_created', kevin.id, { version: 1, agreement_version_id: 'agv_023_1', sha256: sha256(SUPPLY_AGREEMENT_V1), note: 'Initial draft prepared from the standard supply terms.' }],
    ['agreement.party_invited', kevin.id, { party_role: 'supplier', invitation_channel: 'email', signing_required: true, signing_order: 2 }],
    ['agreement.version_created', kevin.id, { version: 2, agreement_version_id: 'agv_023_2', sha256: sha256(SUPPLY_AGREEMENT_V2), note: 'Payment terms moved from 45 to 30 days at the supplier’s request; supersedes version 1.', supersedes_version: 1 }],
    ['agreement.party_invited', kevin.id, { party_role: 'financier', invitation_channel: 'email', signing_required: true, signing_order: 3 }],
    ['agreement.version_created', kevin.id, { version: 3, agreement_version_id: 'agv_023_3', sha256: sha256(SUPPLY_AGREEMENT_V3), note: 'Warranty period extended to twelve months and late-payment interest added; final text issued for signature.', supersedes_version: 2 }],
    ['party.identity_verified', kevin.id, { party_role: 'buyer', assurance_level: 'email_otp_plus_id_document', provider: 'internal', note: 'Level reflects the check actually performed; no document copy retained.' }],
    ['party.identity_verified', grace.id, { party_role: 'supplier', assurance_level: 'email_otp_plus_id_document', provider: 'internal' }],
    ['party.identity_verified', purity.id, { party_role: 'financier', assurance_level: 'email_otp', provider: 'internal' }],
    ['party.identity_verified', joseph.id, { party_role: 'guarantor', assurance_level: 'email_otp', provider: 'internal' }],
    ['party.consent_recorded', kevin.id, { party_role: 'buyer', disclosure_version: 'consent-2026-08-v3', scope: 'sign_and_evidence' }],
    ['party.signed', kevin.id, { party_role: 'buyer', version: 3, agreement_version_id: 'agv_023_3', signature_method: 'otp_confirmed_intent', signature_event_id: 'sev_023_1', document_sha256: sha256(SUPPLY_AGREEMENT_V3) }],
    ['party.signed', grace.id, { party_role: 'supplier', version: 3, agreement_version_id: 'agv_023_3', signature_method: 'otp_confirmed_intent', signature_event_id: 'sev_023_2' }],
    ['party.signed', purity.id, { party_role: 'financier', version: 3, agreement_version_id: 'agv_023_3', signature_method: 'otp_confirmed_intent', signature_event_id: 'sev_023_3' }],
    ['party.signed', joseph.id, { party_role: 'guarantor', version: 3, agreement_version_id: 'agv_023_3', signature_method: 'otp_confirmed_intent', signature_event_id: 'sev_023_4' }],
    ['agreement.completion_evaluated', null, { version: 3, required: 4, completed: 4, satisfied: true, pending_party_roles: [] }],
    ['stamp.issued', null, { version: 3, agreement_version_id: 'agv_023_3', document_sha256: sha256(SUPPLY_AGREEMENT_V3), required_signers: 4, signed_signers: 4, definition: 'frozen version + required party actions complete + integrity digest + evidence-chain record' }],
    ['evidence.package_generated', kevin.id, { format: 'agree-e-evidence-package', package_version: '1.0', version: 3, files: 6, verification_ok: true }],
  ]),
  // agr_020 — draft under preparation.
  ...buildChain('agr_020', days(3), [
    ['agreement.created', kevin.id, { title: 'Loan agreement — KES 500,000 equipment finance', type: 'loan' }],
    ['agreement.version_created', kevin.id, { version: 1, sha256: sha256(LOAN_DRAFT_V1), note: 'Working draft; security clause still open.' }],
  ]),
  // agr_021 — invitations issued, nobody has signed.
  ...buildChain('agr_021', days(6), [
    ['agreement.created', kevin.id, { title: 'Tenancy agreement — Industrial Area warehouse', type: 'tenancy' }],
    ['agreement.version_created', kevin.id, { version: 1, sha256: sha256(WAREHOUSE_TENANCY_V1) }],
    ['agreement.party_invited', kevin.id, { party_role: 'tenant', invitation_channel: 'email', signing_order: 1 }],
    ['agreement.completion_evaluated', null, { required: 1, completed: 0, satisfied: false, pending_party_roles: ['tenant'] }],
  ]),
  // agr_022 — revoked before completion; the record is retained unaltered.
  ...buildChain('agr_022', days(40), [
    ['agreement.created', kevin.id, { title: 'Employment contract — field agronomist', type: 'employment' }],
    ['agreement.version_created', kevin.id, { version: 1, sha256: sha256(EMPLOYMENT_REVOKED_V1) }],
    ['agreement.party_invited', kevin.id, { party_role: 'employee', invitation_channel: 'email' }],
    ['agreement.revoked', kevin.id, { reason: 'Candidate withdrew before signature; hiring decision reversed.', versions_frozen: 0, records_deleted: 0 }],
  ]),
];

export const USER_DATA_REQUESTS: DataSubjectRequest[] = [];

/* ------------------------------------------------------------ packages ---- */

/**
 * The package for the executed supply agreement, assembled with the same builder
 * the export route uses — so the console, the workspace and the download all
 * describe one artefact rather than three approximations of it.
 */
function seedPackages(): EvidencePackageRecord[] {
  const agreement = USER_AGREEMENTS.find((a) => a.id === 'agr_023');
  const version = USER_DOCUMENTS.find((d) => d.id === 'agv_023_3');
  if (!agreement || !version) return [];
  const allEvents = USER_AUDIT_EVENTS.filter((e) => e.agreementId === 'agr_023');
  // The package describes the chain as it stood when it was assembled: the
  // export itself is appended afterwards (a copy being taken is part of the
  // record), so the package's root is the last event before that.
  const events = allEvents.filter((e) => e.eventType !== 'evidence.package_generated');

  // The agreement's chain head is the newest event, including the export.
  const head = allEvents[allEvents.length - 1];
  if (head) agreement.chainHead = head.eventHash;

  const bundle = buildPackage({
    agreement,
    version,
    parties: USER_PARTIES.filter((p) => p.agreementId === 'agr_023'),
    events,
    signatureEvents: USER_SIGNATURE_EVENTS.filter((e) => e.agreementId === 'agr_023'),
    consents: USER_CONSENTS.filter((c) => c.agreementId === 'agr_023'),
    generatedBy: { userId: kevin.id, email: kevin.email, displayName: kevin.displayName },
    generatedAt: iso(days(82) + 7_200_000),
    documentFile: { name: 'document.txt', mime: 'text/plain' },
  });

  return [{
    id: 'epk_023_1',
    agreementId: agreement.id,
    versionId: version.id,
    format: 'agree-e-evidence-package',
    packageVersion: '1.0',
    documentHash: version.sha256,
    chainRoot: bundle.chainRoot,
    eventCount: events.length,
    createdAt: iso(days(82) + 7_200_000),
    createdBy: kevin.id,
    verification: {
      ok: bundle.verification.ok,
      documentIntegrity: bundle.verification.documentIntegrity,
      chainIntegrity: bundle.verification.chainIntegrity,
      requiredEventsPresent: bundle.verification.requiredEventsPresent,
      findings: bundle.verification.findings.map((f) => ({ name: f.name, passed: f.passed, detail: f.detail })),
      statements: bundle.verification.statements,
    },
  }];
}

export const USER_PACKAGES: EvidencePackageRecord[] = seedPackages();

/** The two disclosure versions this product has used, newest last. */
export const DISCLOSURE_VERSIONS = ['consent-2026-08-v3'] as const;
export const CURRENT_DISCLOSURE = DISCLOSURE_VERSIONS[DISCLOSURE_VERSIONS.length - 1];

export const ALL_DEMO_AGREEMENTS: AgreementSummary[] = [...DEMO_AGREEMENTS, ...USER_AGREEMENTS];
export { hours as userHours, days as userDays };
