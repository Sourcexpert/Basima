import 'server-only';
import { randomUUID } from 'node:crypto';
import { computeAdminActionHash, type AdminActionLike } from '@/lib/audit/admin-chain';
import { appendToChain, type AuditEventRecord } from '@/lib/audit/chain';
import { sha256 } from '@/lib/crypto/hash';
import { isDemo } from '@/lib/env';
import type { Role } from '@/lib/auth/rbac';
import { supabaseAdmin } from '@/lib/supabase/admin';
import {
  DEMO_ADMIN_ACTIONS, DEMO_AGREEMENTS, DEMO_AUDIT_EVENTS, DEMO_COUPONS, DEMO_INVOICES,
  DEMO_PAYMENTS, DEMO_PLANS, DEMO_SECURITY_EVENTS, DEMO_SESSIONS, DEMO_SUBSCRIPTIONS, DEMO_USERS,
  DEMO_NOW,
} from '@/lib/data/demo-db';
import {
  ALL_DEMO_AGREEMENTS, USER_AGREEMENTS, USER_AUDIT_EVENTS, USER_CONSENTS, USER_DATA_REQUESTS,
  USER_DOCUMENTS, USER_PACKAGES, USER_PARTIES, USER_SIGNATURE_EVENTS, USER_SIGNATURE_REQUESTS,
} from '@/lib/data/user-demo-db';
import type {
  AdminActionRecord, AgreementDocument, AgreementParty, AgreementSummary, ConsentRecord, Coupon,
  DataSubjectRequest, EvidencePackageRecord, Invoice, OperationsSnapshot, Payment, Plan, Profile,
  PasswordRecoveryRequest, SecurityEventRecord, SignatureEvent, SignatureRequest, Subscription,
  UserSession,
} from '@/lib/data/types';

/**
 * Data access for the console.
 *
 * Both backends implement the same interface so every page, action and test is
 * expressed once. The Supabase backend is the production path (RLS still applies
 * to user-facing clients; this service-role path is reserved for console
 * operations and always writes an audit row). The demo backend keeps the console
 * fully operable — and fully clickable — without credentials.
 */
export interface ListOptions {
  q?: string;
  limit?: number;
  offset?: number;
}

export interface Store {
  readonly mode: 'supabase' | 'demo';
  listUsers(o?: ListOptions & { role?: Role; status?: Profile['status'] }): Promise<Profile[]>;
  getUser(id: string): Promise<Profile | null>;
  getUserByEmail(email: string): Promise<Profile | null>;
  upsertUser(p: Profile): Promise<void>;
  patchUser(id: string, patch: Partial<Profile>): Promise<void>;
  listSessions(userId?: string): Promise<UserSession[]>;
  deleteSessions(userId: string): Promise<number>;

  /* ----------------------------------------------- credential recovery -- */

  /**
   * Password recovery is append-only plus a consume stamp. Note what is *not*
   * here: no method returns a token. Only the digest is stored, so the raw
   * credential cannot be read back out of the database by anyone — operator,
   * support agent, or the account holder after the fact.
   */
  listPasswordRecoveries(userId?: string): Promise<PasswordRecoveryRequest[]>;
  appendPasswordRecovery(r: PasswordRecoveryRequest): Promise<void>;
  findPasswordRecoveryByTokenHash(tokenHash: string): Promise<PasswordRecoveryRequest | null>;
  /** Marks every outstanding request for the user consumed; returns how many. */
  consumePasswordRecoveries(userId: string, at: string): Promise<number>;
  listPlans(includeArchived?: boolean): Promise<Plan[]>;
  getPlan(id: string): Promise<Plan | null>;
  upsertPlan(p: Plan): Promise<void>;
  listSubscriptions(o?: ListOptions & { status?: Subscription['status'] }): Promise<Subscription[]>;
  getSubscription(id: string): Promise<Subscription | null>;
  patchSubscription(id: string, patch: Partial<Subscription>): Promise<void>;
  listInvoices(o?: ListOptions): Promise<Invoice[]>;
  getInvoice(id: string): Promise<Invoice | null>;
  appendInvoice(i: Invoice): Promise<void>;
  patchInvoice(id: string, patch: Partial<Invoice>): Promise<void>;
  listPayments(o?: ListOptions & { status?: Payment['status']; provider?: Payment['provider'] }): Promise<Payment[]>;
  getPayment(id: string): Promise<Payment | null>;
  appendPayment(p: Payment): Promise<void>;
  patchPayment(id: string, patch: Partial<Payment>): Promise<void>;
  listAgreements(o?: ListOptions & { status?: AgreementSummary['status'] }): Promise<AgreementSummary[]>;
  listAuditEvents(o?: { agreementId?: string; limit?: number }): Promise<AuditEventRecord[]>;
  appendAuditEvent(e: AuditEventRecord): Promise<void>;
  listAdminActions(o?: ListOptions): Promise<AdminActionRecord[]>;
  appendAdminAction(a: AdminActionRecord): Promise<void>;
  listSecurityEvents(o?: ListOptions): Promise<SecurityEventRecord[]>;
  appendSecurityEvent(e: SecurityEventRecord): Promise<void>;
  listCoupons(): Promise<Coupon[]>;
  appendCoupon(c: Coupon): Promise<void>;
  patchCoupon(id: string, patch: Partial<Coupon>): Promise<void>;
  /* ------------------------------------------------- user workspace (parties) -- */

  listAgreementsForUser(userId: string, email?: string | null): Promise<AgreementSummary[]>;
  getAgreementSummary(id: string): Promise<AgreementSummary | null>;
  appendAgreement(a: AgreementSummary): Promise<void>;
  patchAgreement(id: string, patch: Partial<AgreementSummary>): Promise<void>;

  listDocuments(agreementId: string): Promise<AgreementDocument[]>;
  getDocument(versionId: string): Promise<AgreementDocument | null>;
  appendDocument(d: AgreementDocument): Promise<void>;
  freezeVersion(versionId: string): Promise<void>;

  listParties(agreementId: string): Promise<AgreementParty[]>;
  appendParty(p: AgreementParty): Promise<void>;
  patchParty(id: string, patch: Partial<AgreementParty>): Promise<void>;

  listSignatureRequests(agreementId?: string): Promise<SignatureRequest[]>;
  appendSignatureRequest(r: SignatureRequest): Promise<void>;
  patchSignatureRequest(id: string, patch: Partial<SignatureRequest>): Promise<void>;

  listSignatureEvents(agreementId?: string): Promise<SignatureEvent[]>;
  appendSignatureEvent(e: SignatureEvent): Promise<void>;

  listConsents(agreementId?: string): Promise<ConsentRecord[]>;
  appendConsent(c: ConsentRecord): Promise<void>;

  listPackages(agreementId?: string): Promise<EvidencePackageRecord[]>;
  getPackage(id: string): Promise<EvidencePackageRecord | null>;
  appendPackage(p: EvidencePackageRecord): Promise<void>;

  listDataRequests(userId?: string): Promise<DataSubjectRequest[]>;
  appendDataRequest(r: DataSubjectRequest): Promise<void>;
  patchDataRequest(id: string, patch: Partial<DataSubjectRequest>): Promise<void>;

  snapshot(): Promise<OperationsSnapshot>;
}

/* ------------------------------------------------------------------ utils -- */

function matches(haystack: string[], q?: string): boolean {
  if (!q) return true;
  const needle = q.trim().toLowerCase();
  if (!needle) return true;
  return haystack.some((h) => (h ?? '').toLowerCase().includes(needle));
}

function page<T>(rows: T[], o?: ListOptions): T[] {
  const offset = o?.offset ?? 0;
  const limit = o?.limit ?? 500;
  return rows.slice(offset, offset + limit);
}

/* ------------------------------------------------------------ demo backend -- */

class DemoStore implements Store {
  readonly mode = 'demo' as const;

  private users: Profile[] = DEMO_USERS.map((u) => ({ ...u }));
  private sessions: UserSession[] = DEMO_SESSIONS.map((s) => ({ ...s }));
  private plans: Plan[] = DEMO_PLANS.map((p) => ({ ...p }));
  private subscriptions: Subscription[] = DEMO_SUBSCRIPTIONS.map((s) => ({ ...s }));
  private invoices: Invoice[] = DEMO_INVOICES.map((i) => ({ ...i }));
  private payments: Payment[] = DEMO_PAYMENTS.map((p) => ({ ...p }));
  // The user workspace and the console share one dataset in demo mode, so a
  // signing performed as a party shows up immediately in the console's evidence
  // view. In Supabase mode both surfaces read the same tables.
  private agreements: AgreementSummary[] = ALL_DEMO_AGREEMENTS.map((a) => ({ ...a }));
  private audit: AuditEventRecord[] = [...DEMO_AUDIT_EVENTS, ...USER_AUDIT_EVENTS].map((e) => ({ ...e }));
  private documents: AgreementDocument[] = USER_DOCUMENTS.map((d) => ({ ...d }));
  private parties: AgreementParty[] = USER_PARTIES.map((p) => ({ ...p }));
  private signatureRequests: SignatureRequest[] = USER_SIGNATURE_REQUESTS.map((r) => ({ ...r }));
  private signatureEvents: SignatureEvent[] = USER_SIGNATURE_EVENTS.map((e) => ({ ...e }));
  private consents: ConsentRecord[] = USER_CONSENTS.map((c) => ({ ...c }));
  private packages: EvidencePackageRecord[] = USER_PACKAGES.map((p) => ({ ...p }));
  private dataRequests: DataSubjectRequest[] = USER_DATA_REQUESTS.map((r) => ({ ...r }));
  private adminActions: AdminActionRecord[] = DEMO_ADMIN_ACTIONS.map((a) => ({ ...a }));
  private security: SecurityEventRecord[] = DEMO_SECURITY_EVENTS.map((s) => ({ ...s }));
  private passwordRecoveries: PasswordRecoveryRequest[] = [];
  private coupons: Coupon[] = DEMO_COUPONS.map((c) => ({ ...c }));

  async listUsers(o: ListOptions & { role?: Role; status?: Profile['status'] } = {}) {
    return page(
      this.users.filter(
        (u) =>
          (!o.role || u.role === o.role) &&
          (!o.status || u.status === o.status) &&
          matches([u.displayName, u.email, u.organisation ?? '', u.country], o.q),
      ).sort((a, b) => a.displayName.localeCompare(b.displayName)),
      o,
    );
  }
  async getUser(id: string) { return this.users.find((u) => u.id === id) ?? null; }
  async getUserByEmail(email: string) {
    return this.users.find((u) => u.email.toLowerCase() === email.toLowerCase()) ?? null;
  }
  async upsertUser(p: Profile) {
    const i = this.users.findIndex((u) => u.id === p.id);
    if (i >= 0) this.users[i] = { ...p };
    else this.users.push({ ...p });
  }
  async patchUser(id: string, patch: Partial<Profile>) {
    const i = this.users.findIndex((u) => u.id === id);
    if (i >= 0) this.users[i] = { ...this.users[i], ...patch };
  }
  async listSessions(userId?: string) {
    return this.sessions.filter((s) => !userId || s.userId === userId).sort((a, b) => b.lastSeenAt.localeCompare(a.lastSeenAt));
  }
  async deleteSessions(userId: string) {
    const before = this.sessions.length;
    this.sessions = this.sessions.filter((s) => s.userId !== userId);
    return before - this.sessions.length;
  }

  async listPasswordRecoveries(userId?: string) {
    return this.passwordRecoveries
      .filter((r) => !userId || r.userId === userId)
      .sort((a, b) => b.issuedAt.localeCompare(a.issuedAt))
      .map((r) => ({ ...r }));
  }
  async appendPasswordRecovery(r: PasswordRecoveryRequest) {
    this.passwordRecoveries.unshift({ ...r });
  }
  async findPasswordRecoveryByTokenHash(tokenHash: string) {
    const hit = this.passwordRecoveries.find((r) => r.tokenHash === tokenHash);
    return hit ? { ...hit } : null;
  }
  async consumePasswordRecoveries(userId: string, at: string) {
    let consumed = 0;
    this.passwordRecoveries = this.passwordRecoveries.map((r) => {
      if (r.userId !== userId || r.consumedAt) return r;
      consumed += 1;
      return { ...r, consumedAt: at };
    });
    return consumed;
  }
  async listPlans(includeArchived = true) {
    const plans = includeArchived ? this.plans : this.plans.filter((p) => !p.archivedAt && p.active);
    return plans.map((p) => {
      const subs = this.subscriptions.filter((s) => s.planId === p.id && ['active', 'trialing', 'past_due', 'grace'].includes(s.status));
      const monthly = p.interval === 'annual' ? Math.round(p.amountMinor / 12) : p.amountMinor;
      return { ...p, subscribers: subs.length, mrrMinor: subs.reduce((sum, s) => sum + (s.status === 'trialing' ? 0 : monthly), 0) };
    });
  }
  async getPlan(id: string) { return this.plans.find((p) => p.id === id) ?? null; }
  async upsertPlan(p: Plan) {
    const i = this.plans.findIndex((x) => x.id === p.id);
    if (i >= 0) this.plans[i] = { ...p };
    else this.plans.push({ ...p });
  }
  async listSubscriptions(o: ListOptions & { status?: Subscription['status'] } = {}) {
    return page(
      this.subscriptions
        .filter((s) => (!o.status || s.status === o.status) && matches([s.userEmail, s.userName, s.planName, s.planCode], o.q))
        .sort((a, b) => b.currentPeriodEnd.localeCompare(a.currentPeriodEnd)),
      o,
    );
  }
  async getSubscription(id: string) { return this.subscriptions.find((s) => s.id === id) ?? null; }
  async patchSubscription(id: string, patch: Partial<Subscription>) {
    const i = this.subscriptions.findIndex((s) => s.id === id);
    if (i >= 0) this.subscriptions[i] = { ...this.subscriptions[i], ...patch };
  }
  async listInvoices(o: ListOptions = {}) {
    return page(
      this.invoices
        .filter((i) => matches([i.number, i.userEmail], o.q))
        .sort((a, b) => b.issuedAt.localeCompare(a.issuedAt)),
      o,
    );
  }
  async getInvoice(id: string) { return this.invoices.find((i) => i.id === id) ?? null; }
  async appendInvoice(i: Invoice) { this.invoices.push({ ...i }); }
  async patchInvoice(id: string, patch: Partial<Invoice>) {
    const i = this.invoices.findIndex((x) => x.id === id);
    if (i >= 0) this.invoices[i] = { ...this.invoices[i], ...patch };
  }
  async listPayments(o: ListOptions & { status?: Payment['status']; provider?: Payment['provider'] } = {}) {
    return page(
      this.payments
        .filter(
          (p) =>
            (!o.status || p.status === o.status) &&
            (!o.provider || p.provider === o.provider) &&
            matches([p.reference, p.userEmail, p.mpesaReceipt ?? '', p.providerRef ?? ''], o.q),
        )
        .sort((a, b) => b.createdAt.localeCompare(a.createdAt)),
      o,
    );
  }
  async getPayment(id: string) { return this.payments.find((p) => p.id === id) ?? null; }
  async appendPayment(p: Payment) { this.payments.unshift({ ...p }); }
  async patchPayment(id: string, patch: Partial<Payment>) {
    const i = this.payments.findIndex((p) => p.id === id);
    if (i >= 0) this.payments[i] = { ...this.payments[i], ...patch, updatedAt: new Date(DEMO_NOW).toISOString() };
  }
  async listAgreements(o: ListOptions & { status?: AgreementSummary['status'] } = {}) {
    return page(
      this.agreements
        .filter((a) => (!o.status || a.status === o.status) && matches([a.ref, a.title, a.ownerEmail, a.agreementType], o.q))
        .sort((a, b) => b.createdAt.localeCompare(a.createdAt)),
      o,
    );
  }
  async listAuditEvents(o: { agreementId?: string; limit?: number } = {}) {
    const rows = o.agreementId ? this.audit.filter((e) => e.agreementId === o.agreementId) : this.audit;
    return rows.slice(0, o.limit ?? 200);
  }
  async appendAuditEvent(e: AuditEventRecord) { this.audit.push({ ...e }); }
  async listAdminActions(o: ListOptions = {}) {
    return page(
      this.adminActions.filter((a) => matches([a.action, a.adminEmail, a.targetLabel, a.reason], o.q)),
      o,
    );
  }
  async appendAdminAction(a: AdminActionRecord) { this.adminActions.unshift({ ...a }); }
  async listSecurityEvents(o: ListOptions = {}) {
    return page(this.security.filter((s) => matches([s.type, s.detail], o.q)), o);
  }
  async appendSecurityEvent(e: SecurityEventRecord) { this.security.unshift({ ...e }); }
  async listCoupons() { return this.coupons.map((c) => ({ ...c })); }
  async appendCoupon(c: Coupon) { this.coupons.unshift({ ...c }); }
  async patchCoupon(id: string, patch: Partial<Coupon>) {
    const i = this.coupons.findIndex((c) => c.id === id);
    if (i >= 0) this.coupons[i] = { ...this.coupons[i], ...patch };
  }

  /* ------------------------------------------------- user workspace (parties) -- */

  async listAgreementsForUser(userId: string, email?: string | null) {
    // Two ways to be a party: an accepted invitation (user_id is set) or an
    // invitation addressed to your email that you have not accepted yet. The
    // second must be visible, or the invitation could never be accepted.
    const wanted = email?.trim().toLowerCase() ?? null;
    const partyAgreementIds = new Set(
      this.parties
        .filter(
          (p) =>
            p.status !== 'removed' &&
            (p.userId === userId || (!p.userId && wanted !== null && p.email.trim().toLowerCase() === wanted)),
        )
        .map((p) => p.agreementId),
    );
    return this.agreements
      .filter((a) => a.ownerId === userId || partyAgreementIds.has(a.id))
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }
  async getAgreementSummary(id: string) { return this.agreements.find((a) => a.id === id) ?? null; }
  async appendAgreement(a: AgreementSummary) { this.agreements.unshift({ ...a }); }
  async patchAgreement(id: string, patch: Partial<AgreementSummary>) {
    const i = this.agreements.findIndex((a) => a.id === id);
    if (i >= 0) this.agreements[i] = { ...this.agreements[i], ...patch };
  }

  async listDocuments(agreementId: string) {
    return this.documents.filter((d) => d.agreementId === agreementId).sort((a, b) => a.versionNumber - b.versionNumber);
  }
  async getDocument(versionId: string) { return this.documents.find((d) => d.id === versionId) ?? null; }
  async appendDocument(d: AgreementDocument) { this.documents.push({ ...d }); }
  async freezeVersion(versionId: string) {
    const i = this.documents.findIndex((d) => d.id === versionId);
    // Freezing is one-way: an executed version is never un-frozen.
    if (i >= 0 && !this.documents[i].frozenAt) this.documents[i] = { ...this.documents[i], frozenAt: new Date().toISOString() };
  }

  async listParties(agreementId: string) {
    return this.parties.filter((p) => p.agreementId === agreementId).sort((a, b) => a.signingOrder - b.signingOrder);
  }
  async appendParty(p: AgreementParty) { this.parties.push({ ...p }); }
  async patchParty(id: string, patch: Partial<AgreementParty>) {
    const i = this.parties.findIndex((p) => p.id === id);
    if (i >= 0) this.parties[i] = { ...this.parties[i], ...patch };
  }

  async listSignatureRequests(agreementId?: string) {
    return this.signatureRequests.filter((r) => !agreementId || r.agreementId === agreementId);
  }
  async appendSignatureRequest(r: SignatureRequest) { this.signatureRequests.push({ ...r }); }
  async patchSignatureRequest(id: string, patch: Partial<SignatureRequest>) {
    const i = this.signatureRequests.findIndex((r) => r.id === id);
    if (i >= 0) this.signatureRequests[i] = { ...this.signatureRequests[i], ...patch };
  }

  async listSignatureEvents(agreementId?: string) {
    return this.signatureEvents.filter((e) => !agreementId || e.agreementId === agreementId);
  }
  async appendSignatureEvent(e: SignatureEvent) { this.signatureEvents.push({ ...e }); }

  async listConsents(agreementId?: string) {
    return this.consents.filter((c) => !agreementId || c.agreementId === agreementId);
  }
  async appendConsent(c: ConsentRecord) { this.consents.push({ ...c }); }

  async listPackages(agreementId?: string) {
    return this.packages.filter((p) => !agreementId || p.agreementId === agreementId);
  }
  async getPackage(id: string) { return this.packages.find((p) => p.id === id) ?? null; }
  async appendPackage(p: EvidencePackageRecord) { this.packages.push({ ...p }); }

  async listDataRequests(userId?: string) {
    return this.dataRequests.filter((r) => !userId || r.userId === userId);
  }
  async appendDataRequest(r: DataSubjectRequest) { this.dataRequests.unshift({ ...r }); }
  async patchDataRequest(id: string, patch: Partial<DataSubjectRequest>) {
    const i = this.dataRequests.findIndex((r) => r.id === id);
    if (i >= 0) this.dataRequests[i] = { ...this.dataRequests[i], ...patch };
  }

  async snapshot(): Promise<OperationsSnapshot> {
    const now = DEMO_NOW;
    const monthStart = now - 30 * 86_400_000;
    const privileged = this.users.filter((u) => ['owner', 'admin', 'support', 'security', 'billing'].includes(u.role));
    const activeSubs = this.subscriptions.filter((s) => ['active', 'past_due', 'grace'].includes(s.status));
    const mrr = activeSubs.reduce((sum, s) => {
      const monthly = s.planCode.endsWith('annual') ? Math.round(s.amountMinor / 12) : s.amountMinor;
      return sum + (s.status === 'grace' ? Math.round(monthly * 0.5) : monthly);
    }, 0);
    const collected = this.payments
      .filter((p) => p.status === 'succeeded' && new Date(p.createdAt).getTime() >= monthStart)
      .reduce((s, p) => s + p.amountMinor, 0);
    const failed7d = this.payments.filter(
      (p) => p.status === 'failed' && new Date(p.createdAt).getTime() >= now - 7 * 86_400_000,
    ).length;
    const stkPushes = this.payments.filter((p) => p.method === 'mpesa_stk');
    const stkDone = stkPushes.filter((p) => p.status === 'succeeded').length;

    return {
      generatedAt: new Date(now).toISOString(),
      mode: 'demo',
      users: {
        total: this.users.length,
        active: this.users.filter((u) => u.status === 'active').length,
        suspended: this.users.filter((u) => u.status === 'suspended').length,
        withoutMfa: this.users.filter((u) => !u.mfaEnabled).length,
        privilegedWithoutMfa: privileged.filter((u) => !u.mfaEnabled && u.status === 'active').length,
        pendingInvites: this.users.filter((u) => u.status === 'invited').length,
        locked: this.users.filter((u) => u.status === 'locked').length,
      },
      billing: {
        currency: 'KES',
        mrrMinor: mrr,
        arrMinor: mrr * 12,
        activeSubscriptions: activeSubs.length,
        trialing: this.subscriptions.filter((s) => s.status === 'trialing').length,
        pastDue: this.subscriptions.filter((s) => ['past_due', 'grace'].includes(s.status)).length,
        cancelledThisMonth: this.subscriptions.filter((s) => s.cancelledAt && new Date(s.cancelledAt).getTime() >= monthStart).length,
        collectedThisMonthMinor: collected,
        failedPayments7d: failed7d,
        refundedThisMonthMinor: this.payments
          .filter((p) => p.refundedMinor > 0 && new Date(p.updatedAt).getTime() >= monthStart)
          .reduce((s, p) => s + p.refundedMinor, 0),
      },
      evidence: {
        agreementsTotal: this.agreements.length,
        completed: this.agreements.filter((a) => a.status === 'completed').length,
        stampsIssued30d: this.agreements.filter((a) => a.stampIssuedAt && new Date(a.stampIssuedAt).getTime() >= monthStart).length,
        chainIntegrity: { verified: 2, failed: 1, lastCheckedAt: new Date(DEMO_NOW - 3_600_000).toISOString() },
      },
      security: {
        openIncidents: this.security.filter((s) => s.severity === 'critical').length,
        failedAdminSignins24h: 5,
        privilegedAccesses30d: this.adminActions.filter((a) => a.action === 'agreements.content.read.privileged').length,
        auditEvents24h: this.audit.filter((e) => new Date(e.occurredAt).getTime() >= now - 86_400_000).length,
      },
      paymentHealth: {
        mpesaConfigured: false,
        flutterwaveConfigured: false,
        lastStkPushAt: stkPushes[0]?.createdAt ?? null,
        stkSuccessRate: stkPushes.length ? stkDone / stkPushes.length : null,
        webhookLastReceivedAt: new Date(DEMO_NOW - 5_400_000).toISOString(),
      },
      recentAudit: this.audit.slice(-6).reverse(),
      recentAdminActions: this.adminActions.slice(0, 6),
    };
  }
}

/* -------------------------------------------------------- supabase backend -- */

/* eslint-disable @typescript-eslint/no-explicit-any */
function mapProfile(r: any): Profile {
  return {
    id: r.id,
    email: r.email,
    displayName: r.display_name,
    role: r.role,
    status: r.status,
    phone: r.phone,
    country: r.country,
    organisation: r.organisation,
    createdAt: r.created_at,
    lastSignInAt: r.last_sign_in_at,
    emailVerified: r.email_verified,
    mfaEnabled: r.mfa_enabled,
    mfaRequired: r.mfa_required,
    forcePasswordReset: r.force_password_reset,
    passwordChangedAt: r.password_changed_at,
    failedSignInCount: r.failed_sign_in_count ?? 0,
    lockedUntil: r.locked_until,
    tempCredentialIssuedAt: r.temp_credential_issued_at,
    tempCredentialExpiresAt: r.temp_credential_expires_at,
    agreementsOwned: r.agreements_owned ?? 0,
    extraCapabilities: r.extra_capabilities ?? [],
  };
}

function profileToRow(p: Partial<Profile>): Record<string, unknown> {
  const map: Record<string, string> = {
    displayName: 'display_name', lastSignInAt: 'last_sign_in_at', emailVerified: 'email_verified',
    mfaEnabled: 'mfa_enabled', mfaRequired: 'mfa_required', forcePasswordReset: 'force_password_reset',
    passwordChangedAt: 'password_changed_at', failedSignInCount: 'failed_sign_in_count',
    lockedUntil: 'locked_until', tempCredentialIssuedAt: 'temp_credential_issued_at',
    tempCredentialExpiresAt: 'temp_credential_expires_at', extraCapabilities: 'extra_capabilities',
  };
  const row: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(p)) row[map[k] ?? k] = v;
  return row;
}

class SupabaseStore implements Store {
  readonly mode = 'supabase' as const;

  /**
   * `injected` is how the user workspace runs *as the user*: pass the request's
   * authenticated client and RLS binds every statement. The console and the
   * ledger writer use the service-role client, which is why privilege is
   * checked in code (authorize()) and recorded in the admin chain.
   */
  constructor(private readonly injected?: unknown | null) {}

  private db() {
    const client = (this.injected as ReturnType<typeof supabaseAdmin>) ?? supabaseAdmin();
    if (!client) throw new Error('Supabase not configured');
    return client;
  }

  async listUsers(o: ListOptions & { role?: Role; status?: Profile['status'] } = {}) {
    let q = this.db().from('profiles').select('*').order('display_name').limit(o.limit ?? 500);
    if (o.role) q = q.eq('role', o.role);
    if (o.status) q = q.eq('status', o.status);
    if (o.q) q = q.or(`display_name.ilike.%${o.q}%,email.ilike.%${o.q}%,organisation.ilike.%${o.q}%`);
    const { data, error } = await q;
    if (error) throw error;
    return (data ?? []).map(mapProfile);
  }
  async getUser(id: string) {
    const { data } = await this.db().from('profiles').select('*').eq('id', id).maybeSingle();
    return data ? mapProfile(data) : null;
  }
  async getUserByEmail(email: string) {
    const { data } = await this.db().from('profiles').select('*').ilike('email', email).maybeSingle();
    return data ? mapProfile(data) : null;
  }
  async upsertUser(p: Profile) {
    const { error } = await this.db().from('profiles').upsert({ id: p.id, email: p.email, ...profileToRow(p) });
    if (error) throw error;
  }
  async patchUser(id: string, patch: Partial<Profile>) {
    const { error } = await this.db().from('profiles').update(profileToRow(patch)).eq('id', id);
    if (error) throw error;
  }
  async listSessions(userId?: string) {
    let q = this.db().from('user_sessions').select('*').order('last_seen_at', { ascending: false }).limit(500);
    if (userId) q = q.eq('user_id', userId);
    const { data, error } = await q;
    if (error) throw error;
    return (data ?? []).map((r: any): UserSession => ({
      id: r.id, userId: r.user_id, ipHash: r.ip_hash, userAgent: r.user_agent, createdAt: r.created_at,
      lastSeenAt: r.last_seen_at, expiresAt: r.expires_at, current: false, mfaSatisfied: r.mfa_satisfied,
    }));
  }
  async deleteSessions(userId: string) {
    const { data, error } = await this.db().from('user_sessions').delete().eq('user_id', userId).select('id');
    if (error) throw error;
    return data?.length ?? 0;
  }

  async listPasswordRecoveries(userId?: string) {
    let q = this.db().from('password_recovery_requests').select('*').order('issued_at', { ascending: false });
    if (userId) q = q.eq('user_id', userId);
    const { data, error } = await q;
    if (error) throw error;
    return (data ?? []).map((r: any): PasswordRecoveryRequest => ({
      id: r.id, userId: r.user_id, tokenHash: r.token_hash, issuedBy: r.issued_by,
      delivery: r.delivery, reason: r.reason, issuedAt: r.issued_at, expiresAt: r.expires_at,
      consumedAt: r.consumed_at, ipHash: r.ip_hash, userAgent: r.user_agent,
    }));
  }
  async appendPasswordRecovery(r: PasswordRecoveryRequest) {
    const { error } = await this.db().from('password_recovery_requests').insert({
      id: r.id, user_id: r.userId, token_hash: r.tokenHash, issued_by: r.issuedBy,
      delivery: r.delivery, reason: r.reason, issued_at: r.issuedAt, expires_at: r.expiresAt,
      ip_hash: r.ipHash, user_agent: r.userAgent,
    });
    if (error) throw error;
  }
  async findPasswordRecoveryByTokenHash(tokenHash: string) {
    const { data, error } = await this.db().from('password_recovery_requests')
      .select('*').eq('token_hash', tokenHash).maybeSingle();
    if (error) throw error;
    if (!data) return null;
    return {
      id: data.id, userId: data.user_id, tokenHash: data.token_hash, issuedBy: data.issued_by,
      delivery: data.delivery, reason: data.reason, issuedAt: data.issued_at,
      expiresAt: data.expires_at, consumedAt: data.consumed_at,
      ipHash: data.ip_hash, userAgent: data.user_agent,
    } as PasswordRecoveryRequest;
  }
  async consumePasswordRecoveries(userId: string, at: string) {
    const { data, error } = await this.db().from('password_recovery_requests')
      .update({ consumed_at: at }).eq('user_id', userId).is('consumed_at', null).select('id');
    if (error) throw error;
    return (data ?? []).length;
  }
  async listPlans(includeArchived = true) {
    let q = this.db().from('plans').select('*').order('amount_minor');
    if (!includeArchived) q = q.is('archived_at', null).eq('active', true);
    const { data, error } = await q;
    if (error) throw error;
    return (data ?? []).map((r: any): Plan => ({
      id: r.id, code: r.code, name: r.name, description: r.description ?? '', interval: r.interval,
      amountMinor: r.amount_minor, currency: r.currency, trialDays: r.trial_days, features: r.features ?? [],
      includedSeats: r.included_seats, includedStamps: r.included_stamps, active: r.active,
      archivedAt: r.archived_at, createdAt: r.created_at,
    }));
  }
  async getPlan(id: string) {
    const { data } = await this.db().from('plans').select('*').eq('id', id).maybeSingle();
    if (!data) return null;
    return (await this.listPlans()).find((p) => p.id === data.id) ?? null;
  }
  async upsertPlan(p: Plan) {
    const { error } = await this.db().from('plans').upsert({
      id: p.id, code: p.code, name: p.name, description: p.description, interval: p.interval,
      amount_minor: p.amountMinor, currency: p.currency, trial_days: p.trialDays, features: p.features,
      included_seats: p.includedSeats, included_stamps: p.includedStamps, active: p.active, archived_at: p.archivedAt,
    });
    if (error) throw error;
  }
  async listSubscriptions(o: ListOptions & { status?: Subscription['status'] } = {}) {
    let q = this.db().from('subscriptions').select('*, plan:plans(*), profile:profiles(*)')
      .order('current_period_end', { ascending: false }).limit(o.limit ?? 500);
    if (o.status) q = q.eq('status', o.status);
    const { data, error } = await q;
    if (error) throw error;
    return (data ?? [])
      .filter((r: any) => matches([r.profile?.email ?? '', r.profile?.display_name ?? '', r.plan?.name ?? ''], o.q))
      .map((r: any): Subscription => ({
        id: r.id, userId: r.user_id, userEmail: r.profile?.email ?? '', userName: r.profile?.display_name ?? '',
        planId: r.plan_id, planCode: r.plan?.code ?? '', planName: r.plan?.name ?? '', status: r.status,
        startedAt: r.started_at, currentPeriodStart: r.current_period_start, currentPeriodEnd: r.current_period_end,
        trialEndsAt: r.trial_ends_at, cancelAtPeriodEnd: r.cancel_at_period_end, cancelledAt: r.cancelled_at,
        pausedAt: r.paused_at, seats: r.seats, amountMinor: r.amount_minor, currency: r.currency,
        provider: r.provider, dunningAttempts: r.dunning_attempts ?? 0, graceEndsAt: r.grace_ends_at,
      }));
  }
  async getSubscription(id: string) {
    const { data } = await this.db().from('subscriptions').select('*').eq('id', id).maybeSingle();
    if (!data) return null;
    return (await this.listSubscriptions({ limit: 1000 })).find((s) => s.id === id) ?? null;
  }
  async patchSubscription(id: string, patch: Partial<Subscription>) {
    const map: Record<string, string> = {
      planId: 'plan_id', planCode: 'plan_code', planName: 'plan_name', currentPeriodStart: 'current_period_start',
      currentPeriodEnd: 'current_period_end', trialEndsAt: 'trial_ends_at', cancelAtPeriodEnd: 'cancel_at_period_end',
      cancelledAt: 'cancelled_at', pausedAt: 'paused_at', amountMinor: 'amount_minor', dunningAttempts: 'dunning_attempts',
      graceEndsAt: 'grace_ends_at', startedAt: 'started_at',
    };
    const row: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(patch)) row[map[k] ?? k] = v;
    const { error } = await this.db().from('subscriptions').update(row).eq('id', id);
    if (error) throw error;
  }
  async listInvoices(o: ListOptions = {}) {
    let q = this.db().from('invoices').select('*, profile:profiles(email)').order('issued_at', { ascending: false }).limit(o.limit ?? 500);
    if (o.q) q = q.ilike('number', `%${o.q}%`);
    const { data, error } = await q;
    if (error) throw error;
    return (data ?? []).map((r: any): Invoice => ({
      id: r.id, number: r.number, subscriptionId: r.subscription_id, userId: r.user_id,
      userEmail: r.profile?.email ?? '', amountMinor: r.amount_minor, currency: r.currency, status: r.status,
      issuedAt: r.issued_at, dueAt: r.due_at, paidAt: r.paid_at, provider: r.provider,
    }));
  }
  async getInvoice(id: string) {
    const { data } = await this.db().from('invoices').select('*, profile:profiles(email)').eq('id', id).maybeSingle();
    if (!data) return null;
    return {
      id: data.id, number: data.number, subscriptionId: data.subscription_id, userId: data.user_id,
      userEmail: data.profile?.email ?? '', amountMinor: data.amount_minor, currency: data.currency,
      status: data.status, issuedAt: data.issued_at, dueAt: data.due_at, paidAt: data.paid_at, provider: data.provider,
    } as Invoice;
  }
  async appendInvoice(i: Invoice) {
    const { error } = await this.db().from('invoices').insert({
      id: i.id, number: i.number, subscription_id: i.subscriptionId, user_id: i.userId,
      amount_minor: i.amountMinor, currency: i.currency, status: i.status,
      issued_at: i.issuedAt, due_at: i.dueAt, paid_at: i.paidAt, provider: i.provider,
    });
    if (error) throw error;
  }
  async patchInvoice(id: string, patch: Partial<Invoice>) {
    const map: Record<string, string> = { paidAt: 'paid_at', amountMinor: 'amount_minor' };
    const row: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(patch)) row[map[k] ?? k] = v;
    const { error } = await this.db().from('invoices').update(row).eq('id', id);
    if (error) throw error;
  }
  async listPayments(o: ListOptions & { status?: Payment['status']; provider?: Payment['provider'] } = {}) {
    let q = this.db().from('payments').select('*, profile:profiles(email)').order('created_at', { ascending: false }).limit(o.limit ?? 500);
    if (o.status) q = q.eq('status', o.status);
    if (o.provider) q = q.eq('provider', o.provider);
    const { data, error } = await q;
    if (error) throw error;
    return (data ?? [])
      .filter((r: any) => matches([r.reference, r.mpesa_receipt ?? '', r.provider_ref ?? ''], o.q))
      .map((r: any): Payment => ({
        id: r.id, reference: r.reference, invoiceId: r.invoice_id, userId: r.user_id, userEmail: r.profile?.email ?? '',
        provider: r.provider, method: r.method, amountMinor: r.amount_minor, currency: r.currency, status: r.status,
        providerRef: r.provider_ref, mpesaReceipt: r.mpesa_receipt, failureReason: r.failure_reason,
        reconciledBy: r.reconciled_by, refundedMinor: r.refunded_minor ?? 0, createdAt: r.created_at, updatedAt: r.updated_at,
      }));
  }
  async getPayment(id: string) {
    const { data } = await this.db().from('payments').select('*, profile:profiles(email)').eq('id', id).maybeSingle();
    if (!data) return null;
    return {
      id: data.id, reference: data.reference, invoiceId: data.invoice_id, userId: data.user_id,
      userEmail: data.profile?.email ?? '', provider: data.provider, method: data.method,
      amountMinor: data.amount_minor, currency: data.currency, status: data.status, providerRef: data.provider_ref,
      mpesaReceipt: data.mpesa_receipt, failureReason: data.failure_reason, reconciledBy: data.reconciled_by,
      refundedMinor: data.refunded_minor ?? 0, createdAt: data.created_at, updatedAt: data.updated_at,
    } as Payment;
  }
  async appendPayment(p: Payment) {
    const { error } = await this.db().from('payments').insert({
      id: p.id, reference: p.reference, invoice_id: p.invoiceId, user_id: p.userId, provider: p.provider,
      method: p.method, amount_minor: p.amountMinor, currency: p.currency, status: p.status,
      provider_ref: p.providerRef, mpesa_receipt: p.mpesaReceipt, failure_reason: p.failureReason,
      reconciled_by: p.reconciledBy, refunded_minor: p.refundedMinor,
    });
    if (error) throw error;
  }
  async patchPayment(id: string, patch: Partial<Payment>) {
    const map: Record<string, string> = {
      invoiceId: 'invoice_id', providerRef: 'provider_ref', mpesaReceipt: 'mpesa_receipt',
      failureReason: 'failure_reason', reconciledBy: 'reconciled_by', refundedMinor: 'refunded_minor',
      amountMinor: 'amount_minor', updatedAt: 'updated_at',
    };
    const row: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(patch)) row[map[k] ?? k] = v;
    const { error } = await this.db().from('payments').update(row).eq('id', id);
    if (error) throw error;
  }
  async listAgreements(o: ListOptions & { status?: AgreementSummary['status'] } = {}) {
    // Metadata only — no document content, no party identity material.
    let q = this.db().from('admin_agreement_index').select('*').order('created_at', { ascending: false }).limit(o.limit ?? 500);
    if (o.status) q = q.eq('status', o.status);
    const { data, error } = await q;
    if (error) throw error;
    const rows = (data ?? []).filter((r: any) => matches([r.ref, r.title, r.owner_email, r.agreement_type], o.q));
    return rows.map((r: any): AgreementSummary => ({
      id: r.id, ref: r.ref, title: r.title, agreementType: r.agreement_type, ownerId: r.owner_id,
      ownerEmail: r.owner_email, status: r.status, currentVersion: r.current_version, documentHash: r.document_hash,
      partiesCount: r.parties_count, requiredSigners: r.required_signers, completedSigners: r.completed_signers,
      stampIssuedAt: r.stamp_issued_at, chainHead: r.chain_head, createdAt: r.created_at, completedAt: r.completed_at,
    }));
  }
  async listAuditEvents(o: { agreementId?: string; limit?: number } = {}) {
    let q = this.db().from('audit_events').select('*').order('occurred_at').limit(o.limit ?? 200);
    if (o.agreementId) q = q.eq('agreement_id', o.agreementId);
    const { data, error } = await q;
    if (error) throw error;
    return (data ?? []).map((r: any): AuditEventRecord => ({
      id: r.id, agreementId: r.agreement_id, actorId: r.actor_id, eventType: r.event_type, objectId: r.object_id,
      occurredAt: r.occurred_at, ipHash: r.ip_hash, userAgent: r.user_agent, metadata: r.metadata ?? {},
      previousHash: r.previous_hash, eventHash: r.event_hash,
    }));
  }
  async appendAuditEvent(e: AuditEventRecord) {
    // The database owns hashing in production (RPC append_audit_event); this
    // insert path exists so server-side code can chain a pre-computed event.
    const { error } = await this.db().from('audit_events').insert({
      id: e.id, agreement_id: e.agreementId, actor_id: e.actorId, event_type: e.eventType, object_id: e.objectId,
      occurred_at: e.occurredAt, ip_hash: e.ipHash, user_agent: e.userAgent, metadata: e.metadata,
      previous_hash: e.previousHash, event_hash: e.eventHash,
    });
    if (error) throw error;
  }
  async listAdminActions(o: ListOptions = {}) {
    let q = this.db().from('admin_actions').select('*').order('occurred_at', { ascending: false }).limit(o.limit ?? 200);
    if (o.q) q = q.or(`action.ilike.%${o.q}%,target_label.ilike.%${o.q}%,reason.ilike.%${o.q}%`);
    const { data, error } = await q;
    if (error) throw error;
    return (data ?? []).map((r: any): AdminActionRecord => ({
      id: r.id, adminId: r.admin_id, adminEmail: r.admin_email, adminRole: r.admin_role, action: r.action,
      targetType: r.target_type, targetId: r.target_id, targetLabel: r.target_label, reason: r.reason,
      status: r.status, stepUp: r.step_up, ipHash: r.ip_hash, userAgent: r.user_agent,
      previousHash: r.previous_hash, eventHash: r.event_hash, occurredAt: r.occurred_at, metadata: r.metadata ?? {},
    }));
  }
  async appendAdminAction(a: AdminActionRecord) {
    const { error } = await this.db().from('admin_actions').insert({
      id: a.id, admin_id: a.adminId, admin_email: a.adminEmail, admin_role: a.adminRole, action: a.action,
      target_type: a.targetType, target_id: a.targetId, target_label: a.targetLabel, reason: a.reason,
      status: a.status, step_up: a.stepUp, ip_hash: a.ipHash, user_agent: a.userAgent,
      previous_hash: a.previousHash, event_hash: a.eventHash, occurred_at: a.occurredAt, metadata: a.metadata,
    });
    if (error) throw error;
  }
  async listSecurityEvents(o: ListOptions = {}) {
    const { data, error } = await this.db().from('security_events').select('*')
      .order('occurred_at', { ascending: false }).limit(o.limit ?? 200);
    if (error) throw error;
    return (data ?? [])
      .filter((r: any) => matches([r.type, r.detail], o.q))
      .map((r: any): SecurityEventRecord => ({
        id: r.id, userId: r.user_id, type: r.type, severity: r.severity, detail: r.detail,
        ipHash: r.ip_hash, occurredAt: r.occurred_at,
      }));
  }
  async appendSecurityEvent(e: SecurityEventRecord) {
    const { error } = await this.db().from('security_events').insert({
      user_id: e.userId, type: e.type, severity: e.severity, detail: e.detail,
      ip_hash: e.ipHash, occurred_at: e.occurredAt,
    });
    if (error) throw error;
  }
  async listCoupons() {
    const { data, error } = await this.db().from('coupons').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    return (data ?? []).map((r: any): Coupon => ({
      id: r.id, code: r.code, percentOff: r.percent_off, maxRedemptions: r.max_redemptions,
      redemptions: r.redemptions ?? 0, expiresAt: r.expires_at, active: r.active, createdAt: r.created_at,
    }));
  }
  async appendCoupon(c: Coupon) {
    const { error } = await this.db().from('coupons').insert({
      id: c.id, code: c.code, percent_off: c.percentOff, max_redemptions: c.maxRedemptions,
      redemptions: c.redemptions, expires_at: c.expiresAt, active: c.active,
    });
    if (error) throw error;
  }
  async patchCoupon(id: string, patch: Partial<Coupon>) {
    const map: Record<string, string> = { percentOff: 'percent_off', maxRedemptions: 'max_redemptions', expiresAt: 'expires_at' };
    const row: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(patch)) row[map[k] ?? k] = v;
    const { error } = await this.db().from('coupons').update(row).eq('id', id);
    if (error) throw error;
  }

  /* ------------------------------------------------- user workspace (parties) -- */

  private mapAgreementIndex(r: any): AgreementSummary {
    return {
      id: r.id, ref: r.ref, title: r.title, agreementType: r.agreement_type, ownerId: r.owner_id,
      ownerEmail: r.owner_email, status: r.status, currentVersion: r.current_version,
      documentHash: r.document_hash, partiesCount: r.parties_count, requiredSigners: r.required_signers,
      completedSigners: r.completed_signers, stampIssuedAt: r.stamp_issued_at, chainHead: r.chain_head,
      createdAt: r.created_at, completedAt: r.completed_at,
    };
  }

  async listAgreementsForUser(userId: string, email?: string | null) {
    // Membership is resolved through agreement_parties, so being invited to a
    // matter is what grants read access — not knowing an agreement id. An
    // invitation that has not yet been accepted is matched on email instead
    // (the RLS policy in migration 0003 allows exactly this and nothing more).
    const wanted = email?.trim().toLowerCase() ?? null;
    const { data: memberships } = await this.db()
      .from('agreement_parties')
      .select('agreement_id')
      .or(wanted ? `user_id.eq.${userId},invited_email.eq.${wanted}` : `user_id.eq.${userId}`);
    const ids = Array.from(new Set((memberships ?? []).map((m: any) => m.agreement_id as string)));
    const filter = ids.length ? `owner_id.eq.${userId},id.in.(${ids.join(',')})` : `owner_id.eq.${userId}`;
    const { data, error } = await this.db()
      .from('admin_agreement_index').select('*').or(filter).order('created_at', { ascending: false });
    if (error) throw error;
    return (data ?? []).map((r: any) => this.mapAgreementIndex(r));
  }
  async getAgreementSummary(id: string) {
    const { data } = await this.db().from('admin_agreement_index').select('*').eq('id', id).maybeSingle();
    return data ? this.mapAgreementIndex(data) : null;
  }
  async appendAgreement(a: AgreementSummary) {
    const { error } = await this.db().from('agreements').insert({
      id: a.id, ref: a.ref, owner_id: a.ownerId, title: a.title, agreement_type: a.agreementType, status: a.status,
    });
    if (error) throw error;
  }
  async patchAgreement(id: string, patch: Partial<AgreementSummary>) {
    const map: Record<string, string> = { completedAt: 'completed_at' };
    const row: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(patch)) {
      if (k === 'documentHash' || k === 'chainHead' || k === 'currentVersion') continue; // derived
      row[map[k] ?? k] = v;
    }
    const { error } = await this.db().from('agreements').update(row).eq('id', id);
    if (error) throw error;
  }

  async listDocuments(agreementId: string) {
    const { data, error } = await this.db().from('agreement_versions').select('*')
      .eq('agreement_id', agreementId).order('version_number');
    if (error) throw error;
    return (data ?? []).map((r: any): AgreementDocument => ({
      id: r.id, agreementId: r.agreement_id, versionNumber: r.version_number, storagePath: r.storage_path,
      sha256: r.sha256, byteSize: Number(r.byte_size ?? 0), createdBy: r.created_by, createdAt: r.created_at,
      frozenAt: r.frozen_at,
    }));
  }
  async getDocument(versionId: string) {
    const { data } = await this.db().from('agreement_versions').select('*').eq('id', versionId).maybeSingle();
    if (!data) return null;
    return {
      id: data.id, agreementId: data.agreement_id, versionNumber: data.version_number,
      storagePath: data.storage_path, sha256: data.sha256, byteSize: Number(data.byte_size ?? 0),
      createdBy: data.created_by, createdAt: data.created_at, frozenAt: data.frozen_at,
    } as AgreementDocument;
  }
  async appendDocument(d: AgreementDocument) {
    const { error } = await this.db().from('agreement_versions').insert({
      id: d.id, agreement_id: d.agreementId, version_number: d.versionNumber, storage_path: d.storagePath,
      sha256: d.sha256, byte_size: d.byteSize, created_by: d.createdBy,
    });
    if (error) throw error;
  }
  async freezeVersion(versionId: string) {
    // The trigger in 0001 blocks any later change to a frozen row.
    const { error } = await this.db().from('agreement_versions')
      .update({ frozen_at: new Date().toISOString() }).eq('id', versionId).is('frozen_at', null);
    if (error) throw error;
  }

  async listParties(agreementId: string) {
    const { data, error } = await this.db().from('agreement_parties').select('*')
      .eq('agreement_id', agreementId).order('signing_order');
    if (error) throw error;
    return (data ?? []).map((r: any): AgreementParty => ({
      id: r.id, agreementId: r.agreement_id, userId: r.user_id, displayName: r.display_name ?? '',
      email: r.email ?? r.invitation_email ?? '', partyRole: r.party_role, signingRequired: r.signing_required,
      signingOrder: r.signing_order, status: r.status,
      invitationSentAt: r.invitation_sent_at, invitationAcceptedAt: r.invitation_accepted_at,
      assuranceLevel: r.assurance_level ?? null, identityVerifiedAt: r.identity_verified_at ?? null,
    }));
  }
  async appendParty(p: AgreementParty) {
    const { error } = await this.db().from('agreement_parties').insert({
      id: p.id, agreement_id: p.agreementId, user_id: p.userId, display_name: p.displayName,
      email: p.email, party_role: p.partyRole, signing_required: p.signingRequired,
      signing_order: p.signingOrder, status: p.status, invitation_email: p.email,
      invitation_sent_at: p.invitationSentAt, invitation_accepted_at: p.invitationAcceptedAt,
      assurance_level: p.assuranceLevel, identity_verified_at: p.identityVerifiedAt,
    });
    if (error) throw error;
  }
  async patchParty(id: string, patch: Partial<AgreementParty>) {
    const map: Record<string, string> = {
      signingRequired: 'signing_required', signingOrder: 'signing_order', invitationSentAt: 'invitation_sent_at',
      invitationAcceptedAt: 'invitation_accepted_at', assuranceLevel: 'assurance_level',
      identityVerifiedAt: 'identity_verified_at',
    };
    const row: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(patch)) row[map[k] ?? k] = v;
    const { error } = await this.db().from('agreement_parties').update(row).eq('id', id);
    if (error) throw error;
  }

  async listSignatureRequests(agreementId?: string) {
    let q = this.db().from('signature_requests').select('*').limit(1000);
    if (agreementId) q = q.eq('agreement_id', agreementId);
    const { data, error } = await q;
    if (error) throw error;
    return (data ?? []).map((r: any): SignatureRequest => ({
      id: r.id, agreementId: r.agreement_id, versionId: r.agreement_version_id, partyId: r.party_id,
      requestedBy: r.requested_by, status: r.status, requestedAt: r.requested_at, expiresAt: r.expires_at,
    }));
  }
  async appendSignatureRequest(r: SignatureRequest) {
    const { error } = await this.db().from('signature_requests').insert({
      id: r.id, agreement_id: r.agreementId, agreement_version_id: r.versionId, party_id: r.partyId,
      requested_by: r.requestedBy, status: r.status, requested_at: r.requestedAt, expires_at: r.expiresAt,
    });
    if (error) throw error;
  }
  async patchSignatureRequest(id: string, patch: Partial<SignatureRequest>) {
    const map: Record<string, string> = { versionId: 'agreement_version_id', partyId: 'party_id' };
    const row: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(patch)) row[map[k] ?? k] = v;
    const { error } = await this.db().from('signature_requests').update(row).eq('id', id);
    if (error) throw error;
  }

  async listSignatureEvents(agreementId?: string) {
    let q = this.db().from('signature_events').select('*').order('occurred_at').limit(1000);
    if (agreementId) q = q.eq('agreement_id', agreementId);
    const { data, error } = await q;
    if (error) throw error;
    return (data ?? []).map((r: any): SignatureEvent => ({
      id: r.id, agreementId: r.agreement_id, versionId: r.agreement_version_id, partyId: r.party_id,
      actorId: r.actor_id, signatureMethod: r.signature_method, outcome: r.outcome, consentId: r.consent_id,
      occurredAt: r.occurred_at, ipHash: r.ip_hash, userAgent: r.user_agent,
    }));
  }
  async appendSignatureEvent(e: SignatureEvent) {
    const { error } = await this.db().from('signature_events').insert({
      id: e.id, agreement_id: e.agreementId, agreement_version_id: e.versionId, party_id: e.partyId,
      actor_id: e.actorId, signature_method: e.signatureMethod, outcome: e.outcome,
      consent_id: e.consentId, occurred_at: e.occurredAt, ip_hash: e.ipHash, user_agent: e.userAgent,
    });
    if (error) throw error;
  }

  async listConsents(agreementId?: string) {
    let q = this.db().from('consents').select('*').limit(1000);
    if (agreementId) q = q.eq('agreement_id', agreementId);
    const { data, error } = await q;
    if (error) throw error;
    return (data ?? []).map((r: any): ConsentRecord => ({
      id: r.id, agreementId: r.agreement_id, userId: r.user_id, disclosureVersion: r.disclosure_version,
      scope: r.scope, acceptedAt: r.accepted_at, ipHash: r.ip_hash,
    }));
  }
  async appendConsent(c: ConsentRecord) {
    const { error } = await this.db().from('consents').insert({
      id: c.id, agreement_id: c.agreementId, user_id: c.userId, disclosure_version: c.disclosureVersion,
      scope: c.scope, accepted_at: c.acceptedAt, ip_hash: c.ipHash,
    });
    if (error) throw error;
  }

  async listPackages(agreementId?: string) {
    let q = this.db().from('evidence_packages').select('*').order('created_at', { ascending: false });
    if (agreementId) q = q.eq('agreement_id', agreementId);
    const { data, error } = await q;
    if (error) throw error;
    return (data ?? []).map((r: any): EvidencePackageRecord => ({
      id: r.id, agreementId: r.agreement_id, versionId: r.agreement_version_id, format: r.format,
      packageVersion: r.package_version, documentHash: r.document_hash, chainRoot: r.chain_root,
      eventCount: r.event_count, createdAt: r.created_at, createdBy: r.created_by, verification: r.verification,
    }));
  }
  async getPackage(id: string) {
    const { data } = await this.db().from('evidence_packages').select('*').eq('id', id).maybeSingle();
    if (!data) return null;
    return {
      id: data.id, agreementId: data.agreement_id, versionId: data.agreement_version_id, format: data.format,
      packageVersion: data.package_version, documentHash: data.document_hash, chainRoot: data.chain_root,
      eventCount: data.event_count, createdAt: data.created_at, createdBy: data.created_by,
      verification: data.verification,
    } as EvidencePackageRecord;
  }
  async appendPackage(p: EvidencePackageRecord) {
    const { error } = await this.db().from('evidence_packages').insert({
      id: p.id, agreement_id: p.agreementId, agreement_version_id: p.versionId, format: p.format,
      package_version: p.packageVersion, document_hash: p.documentHash, chain_root: p.chainRoot,
      event_count: p.eventCount, created_by: p.createdBy, verification: p.verification,
    });
    if (error) throw error;
  }

  async listDataRequests(userId?: string) {
    let q = this.db().from('data_subject_requests').select('*').order('submitted_at', { ascending: false });
    if (userId) q = q.eq('user_id', userId);
    const { data, error } = await q;
    if (error) throw error;
    return (data ?? []).map((r: any): DataSubjectRequest => ({
      id: r.id, userId: r.user_id, type: r.type, detail: r.detail, status: r.status,
      submittedAt: r.submitted_at, dueAt: r.due_at, resolvedAt: r.resolved_at, resolutionNote: r.resolution_note,
    }));
  }
  async appendDataRequest(r: DataSubjectRequest) {
    const { error } = await this.db().from('data_subject_requests').insert({
      id: r.id, user_id: r.userId, type: r.type, detail: r.detail, status: r.status,
      submitted_at: r.submittedAt, due_at: r.dueAt,
    });
    if (error) throw error;
  }
  async patchDataRequest(id: string, patch: Partial<DataSubjectRequest>) {
    const map: Record<string, string> = { resolvedAt: 'resolved_at', resolutionNote: 'resolution_note' };
    const row: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(patch)) row[map[k] ?? k] = v;
    const { error } = await this.db().from('data_subject_requests').update(row).eq('id', id);
    if (error) throw error;
  }

  async snapshot(): Promise<OperationsSnapshot> {
    const [users, subs, payments, agreements, security, adminActions, audit] = await Promise.all([
      this.listUsers({ limit: 2000 }), this.listSubscriptions({ limit: 2000 }), this.listPayments({ limit: 2000 }),
      this.listAgreements({ limit: 2000 }), this.listSecurityEvents({ limit: 500 }), this.listAdminActions({ limit: 500 }),
      this.listAuditEvents({ limit: 500 }),
    ]);
    const now = Date.now();
    const monthAgo = now - 30 * 86_400_000;
    const privileged = users.filter((u) => ['owner', 'admin', 'support', 'security', 'billing'].includes(u.role));
    const activeSubs = subs.filter((s) => ['active', 'past_due', 'grace'].includes(s.status));
    const mrr = activeSubs.reduce((sum, s) => {
      const monthly = s.planCode.endsWith('annual') || s.currency === 'USD' ? Math.round(s.amountMinor / 12) : s.amountMinor;
      return sum + monthly;
    }, 0);
    const stk = payments.filter((p) => p.method === 'mpesa_stk');

    return {
      generatedAt: new Date().toISOString(),
      mode: 'supabase',
      users: {
        total: users.length,
        active: users.filter((u) => u.status === 'active').length,
        suspended: users.filter((u) => u.status === 'suspended').length,
        withoutMfa: users.filter((u) => !u.mfaEnabled).length,
        privilegedWithoutMfa: privileged.filter((u) => !u.mfaEnabled && u.status === 'active').length,
        pendingInvites: users.filter((u) => u.status === 'invited').length,
        locked: users.filter((u) => u.status === 'locked').length,
      },
      billing: {
        currency: 'KES',
        mrrMinor: mrr,
        arrMinor: mrr * 12,
        activeSubscriptions: activeSubs.length,
        trialing: subs.filter((s) => s.status === 'trialing').length,
        pastDue: subs.filter((s) => ['past_due', 'grace'].includes(s.status)).length,
        cancelledThisMonth: subs.filter((s) => s.cancelledAt && new Date(s.cancelledAt).getTime() >= monthAgo).length,
        collectedThisMonthMinor: payments
          .filter((p) => p.status === 'succeeded' && new Date(p.createdAt).getTime() >= monthAgo)
          .reduce((s, p) => s + p.amountMinor, 0),
        failedPayments7d: payments.filter((p) => p.status === 'failed' && new Date(p.createdAt).getTime() >= now - 7 * 86_400_000).length,
        refundedThisMonthMinor: payments.filter((p) => p.refundedMinor > 0).reduce((s, p) => s + p.refundedMinor, 0),
      },
      evidence: {
        agreementsTotal: agreements.length,
        completed: agreements.filter((a) => a.status === 'completed').length,
        stampsIssued30d: agreements.filter((a) => a.stampIssuedAt && new Date(a.stampIssuedAt).getTime() >= monthAgo).length,
        chainIntegrity: { verified: agreements.filter((a) => a.chainHead).length, failed: 0, lastCheckedAt: null },
      },
      security: {
        openIncidents: security.filter((s) => s.severity === 'critical').length,
        failedAdminSignins24h: security.filter((s) => s.type === 'failed_admin_signin' && new Date(s.occurredAt).getTime() >= now - 86_400_000).length,
        privilegedAccesses30d: adminActions.filter((a) => a.action === 'agreements.content.read.privileged').length,
        auditEvents24h: audit.filter((e) => new Date(e.occurredAt).getTime() >= now - 86_400_000).length,
      },
      paymentHealth: {
        mpesaConfigured: Boolean(process.env.MPESA_CONSUMER_KEY),
        flutterwaveConfigured: Boolean(process.env.FLW_SECRET_KEY),
        lastStkPushAt: stk[0]?.createdAt ?? null,
        stkSuccessRate: stk.length ? stk.filter((p) => p.status === 'succeeded').length / stk.length : null,
        webhookLastReceivedAt: null,
      },
      recentAudit: audit.slice(-6).reverse(),
      recentAdminActions: adminActions.slice(0, 6),
    };
  }
}

/* ------------------------------------------------------------- singleton -- */

declare global {
  // eslint-disable-next-line no-var
  var __agreeEStore: Store | undefined;
}

/**
 * A Supabase-backed store bound to a specific client. Passing the request's
 * authenticated client makes RLS apply; passing nothing uses the service role.
 */
export function supabaseStore(client?: unknown | null): Store {
  return new SupabaseStore(client ?? null);
}

export function store(): Store {
  if (!globalThis.__agreeEStore) globalThis.__agreeEStore = isDemo ? new DemoStore() : new SupabaseStore();
  return globalThis.__agreeEStore;
}

/**
 * Append an admin action to the admin ledger with a correctly chained hash.
 * Called by every privileged operation, successful or not.
 */
export async function recordAdminAction(
  input: Omit<AdminActionLike, 'id' | 'ipHash' | 'occurredAt' | 'metadata'> & {
    id?: string; ipHash?: string | null; occurredAt?: string; metadata?: Record<string, unknown>;
  },
): Promise<AdminActionRecord> {
  const s = store();
  const previous = await s.listAdminActions({ limit: 1 });
  const previousHash = previous[0]?.eventHash ?? null;
  const base: AdminActionLike = {
    ...input,
    id: input.id ?? `adm_${randomUUID()}`,
    ipHash: input.ipHash ?? null,
    userAgent: input.userAgent ?? null,
    occurredAt: input.occurredAt ?? new Date().toISOString(),
    metadata: input.metadata ?? {},
  };
  const eventHash = computeAdminActionHash(previousHash, base);
  const row: AdminActionRecord = {
    ...base,
    userAgent: base.userAgent ?? null,
    adminRole: base.adminRole as Role,
    targetType: base.targetType as AdminActionRecord['targetType'],
    previousHash,
    eventHash,
  };
  await s.appendAdminAction(row);
  return row;
}

/** Append an agreement-scoped evidence event, extending that agreement's chain. */
export async function appendAgreementEvent(input: {
  agreementId: string; actorId: string | null; eventType: string; objectId?: string | null;
  metadata?: Record<string, unknown>; ipHash?: string | null; userAgent?: string | null;
}): Promise<AuditEventRecord> {
  const s = store();
  const existing = await s.listAuditEvents({ agreementId: input.agreementId, limit: 1000 });
  const last = existing.length ? existing[existing.length - 1] : null;
  const event = appendToChain(last, {
    id: `evt_${sha256(`${input.agreementId}:${Date.now()}:${Math.random()}`).slice(0, 24)}`,
    agreementId: input.agreementId,
    actorId: input.actorId,
    eventType: input.eventType,
    objectId: input.objectId ?? input.agreementId,
    occurredAt: new Date().toISOString(),
    ipHash: input.ipHash ?? null,
    userAgent: input.userAgent ?? null,
    metadata: input.metadata ?? {},
  });
  await s.appendAuditEvent(event);
  return event;
}
