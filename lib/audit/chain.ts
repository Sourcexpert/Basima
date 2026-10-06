import { canonicalize, sha256 } from '../crypto/hash';

/**
 * The append-only audit ledger (Build Guide §9).
 *
 * E1 [agreement created] hash=A...
 *   |  E2 [party verified] previous=A... hash=B...
 *   |  E3 [party signed]   previous=B... hash=C...
 *   `> E4 [stamp issued]   previous=C... hash=D...
 *
 * Each event commits to the previous event hash. Mutating an earlier canonical
 * event therefore breaks verification of every subsequent link — that is what
 * makes the chain tamper-"evident" (not tamper-proof, and never "blockchain").
 *
 * Hashing and timestamping must happen server-side / in Postgres. This module is
 * the single implementation used by the API routes, the RPC fallback and tests.
 */

export const CHAIN_GENESIS = 'GENESIS';

export type AuditEventType =
  | 'agreement.created'
  | 'agreement.version_created'
  | 'agreement.party_invited'
  | 'party.identity_verified'
  | 'party.consent_recorded'
  | 'party.signed'
  | 'agreement.completion_evaluated'
  | 'stamp.issued'
  | 'evidence.package_generated'
  | 'evidence.certificate_attested'
  | 'agreement.revoked';

export type AdminActionType =
  | 'admin.login'
  | 'admin.step_up_verified'
  | 'admin.exported_user_list'
  | 'password.reset_link_issued'
  | 'password.force_reset_required'
  | 'password.temp_issued_breakglass'
  | 'sessions.revoked'
  | 'mfa.requirement_changed'
  | 'user.locked'
  | 'user.unlocked'
  | 'user.role_changed'
  | 'user.invited'
  | 'user.suspended'
  | 'user.reinstated'
  | 'plan.created'
  | 'plan.updated'
  | 'plan.archived'
  | 'subscription.created'
  | 'subscription.plan_changed'
  | 'subscription.cancelled'
  | 'subscription.paused'
  | 'subscription.resumed'
  | 'subscription.trial_extended'
  | 'payment.stk_push_initiated'
  | 'payment.reconciled'
  | 'payment.refund_issued'
  | 'dunning.retry_scheduled'
  | 'coupon.created'
  | 'coupon.revoked'
  | 'settings.updated';

export interface AuditEventInput {
  agreementId?: string | null;
  /** Actor is nullable by design: system/webhook events have no human actor. */
  actorId?: string | null;
  eventType: AuditEventType | AdminActionType | string;
  objectId?: string | null;
  occurredAt?: string;
  ipHash?: string | null;
  userAgent?: string | null;
  metadata?: Record<string, unknown>;
}

export interface AuditEventRecord extends Required<Pick<AuditEventInput, 'eventType'>> {
  id: string;
  agreementId: string | null;
  actorId: string | null;
  objectId: string | null;
  occurredAt: string;
  ipHash: string | null;
  userAgent: string | null;
  metadata: Record<string, unknown>;
  previousHash: string | null;
  eventHash: string;
}

/**
 * Canonical payload for an event. Field order is fixed here and re-sorted inside
 * canonicalize(), so a re-implementation on another platform can reproduce it.
 */
export function canonicalEventPayload(e: {
  id: string;
  agreementId: string | null;
  actorId: string | null;
  eventType: string;
  objectId: string | null;
  occurredAt: string;
  ipHash: string | null;
  metadata: Record<string, unknown>;
}): string {
  return canonicalize({
    id: e.id,
    agreement_id: e.agreementId,
    actor_id: e.actorId,
    event_type: e.eventType,
    object_id: e.objectId,
    occurred_at: e.occurredAt,
    ip_hash: e.ipHash,
    metadata: e.metadata ?? {},
  });
}

/** event_hash = SHA256(previous_hash || canonical_json(payload)) */
export function computeEventHash(previousHash: string | null, payload: string): string {
  return sha256(`${previousHash ?? CHAIN_GENESIS}\n${payload}`);
}

export function appendToChain(
  previous: { eventHash: string } | null,
  event: Omit<AuditEventRecord, 'previousHash' | 'eventHash'>,
): AuditEventRecord {
  const previousHash = previous?.eventHash ?? null;
  const eventHash = computeEventHash(previousHash, canonicalEventPayload(event));
  return { ...event, previousHash, eventHash };
}

export type ChainCheck = {
  ok: boolean;
  index: number;
  total: number;
  eventId: string | null;
  reason:
    | 'ok'
    | 'broken_link'
    | 'digest_mismatch'
    | 'ordering_error'
    | 'empty_chain';
  detail: string;
};

export type ChainVerification = {
  valid: boolean;
  checkedEvents: number;
  head: string | null;
  root: string | null;
  firstFailure: ChainCheck | null;
  checks: ChainCheck[];
};

/**
 * Verify chain workflow (Build Guide §14), step 4-6 of the pipeline:
 * reconstruct canonical events -> verify each previous_hash link -> verify event
 * digests. Returns precise technical findings; it deliberately does NOT return a
 * legal conclusion.
 */
export function verifyChain(events: AuditEventRecord[]): ChainVerification {
  const checks: ChainCheck[] = [];
  let previous: AuditEventRecord | null = null;

  if (events.length === 0) {
    return {
      valid: false,
      checkedEvents: 0,
      head: null,
      root: null,
      firstFailure: {
        ok: false, index: -1, total: 0, eventId: null,
        reason: 'empty_chain', detail: 'No events supplied for verification.',
      },
      checks,
    };
  }

  for (let i = 0; i < events.length; i += 1) {
    const event = events[i];
    const expectedPrevious = previous ? previous.eventHash : null;

    // 1. ordering: occurred_at must be non-decreasing
    if (previous && new Date(event.occurredAt) < new Date(previous.occurredAt)) {
      checks.push({
        ok: false, index: i, total: events.length, eventId: event.id,
        reason: 'ordering_error',
        detail: `Event ${i} is timestamped before event ${i - 1}.`,
      });
      break;
    }

    // 2. link: event.previous_hash must equal the hash of the prior event
    if (event.previousHash !== expectedPrevious) {
      checks.push({
        ok: false, index: i, total: events.length, eventId: event.id,
        reason: 'broken_link',
        detail: `Event ${i} commits to "${event.previousHash ?? 'GENESIS'}" but the preceding link is "${expectedPrevious ?? 'GENESIS'}".`,
      });
      break;
    }

    // 3. digest: recompute and compare
    const recomputed = computeEventHash(event.previousHash, canonicalEventPayload(event));
    if (recomputed !== event.eventHash) {
      checks.push({
        ok: false, index: i, total: events.length, eventId: event.id,
        reason: 'digest_mismatch',
        detail: `Event ${i} records digest ${event.eventHash.slice(0, 16)}… but the canonical payload hashes to ${recomputed.slice(0, 16)}….`,
      });
      break;
    }

    checks.push({
      ok: true, index: i, total: events.length, eventId: event.id,
      reason: 'ok', detail: `Link ${i + 1} verified.`,
    });
    previous = event;
  }

  const firstFailure = checks.find((c) => !c.ok) ?? null;
  return {
    valid: !firstFailure,
    checkedEvents: checks.filter((c) => c.ok).length,
    head: events[events.length - 1]?.eventHash ?? null,
    root: events[0]?.eventHash ?? null,
    firstFailure,
    checks,
  };
}

/** User-facing string that states what was verified — never a legal conclusion. */
export function describeVerification(v: ChainVerification): string[] {
  if (!v.valid) {
    const f = v.firstFailure;
    return [
      'Evidence-chain integrity NOT verified.',
      f ? `${f.detail}` : 'A chain link could not be verified.',
      'Do not treat this record as intact without investigation and counsel review.',
    ];
  }
  return [
    'Document integrity verified.',
    'Evidence-chain integrity verified.',
    'Required signing events recorded.',
    'No broken chain links detected.',
  ];
}
