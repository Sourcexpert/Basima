import { canonicalize, sha256 } from '../crypto/hash';
import { CHAIN_GENESIS } from './chain';

/**
 * The admin-action ledger is a *separate* append-only chain from the agreement
 * evidence chain (Build Guide §6: security_events / admin_actions). Mixing them
 * would let an operational action (e.g. a password reset) appear inside an
 * agreement's evidence timeline, which would confuse what that timeline proves.
 *
 * Structural typing is used deliberately so this module has no dependency on the
 * domain types (avoids an import cycle with lib/data/types.ts).
 */
export interface AdminActionLike {
  id: string;
  adminId: string;
  adminEmail: string;
  adminRole: string;
  action: string;
  targetType: string;
  targetId: string;
  targetLabel: string;
  reason: string;
  status: 'succeeded' | 'failed' | 'blocked';
  stepUp: boolean;
  ipHash: string | null;
  userAgent?: string | null;
  occurredAt: string;
  metadata: Record<string, unknown>;
}

export function canonicalAdminPayload(a: AdminActionLike): string {
  return canonicalize({
    id: a.id,
    admin_id: a.adminId,
    admin_email: a.adminEmail,
    admin_role: a.adminRole,
    action: a.action,
    target_type: a.targetType,
    target_id: a.targetId,
    target_label: a.targetLabel,
    reason: a.reason,
    status: a.status,
    step_up: a.stepUp,
    ip_hash: a.ipHash,
    user_agent: a.userAgent ?? null,
    occurred_at: a.occurredAt,
    metadata: a.metadata ?? {},
  });
}

export function computeAdminActionHash(previousHash: string | null, a: AdminActionLike): string {
  return sha256(`${previousHash ?? CHAIN_GENESIS}\n${canonicalAdminPayload(a)}`);
}

export function verifyAdminChain(rows: Array<AdminActionLike & { previousHash: string | null; eventHash: string }>) {
  // Rows arrive newest-first from the UI; the chain is verified oldest-first.
  const ordered = [...rows].reverse();
  let previous: string | null = null;
  for (const [index, row] of ordered.entries()) {
    if (row.previousHash !== previous) {
      return { valid: false, index, reason: 'broken_link' as const, detail: `Admin action ${row.id} does not link to the preceding action.` };
    }
    if (computeAdminActionHash(previous, row) !== row.eventHash) {
      return { valid: false, index, reason: 'digest_mismatch' as const, detail: `Admin action ${row.id} has been altered after it was recorded.` };
    }
    previous = row.eventHash;
  }
  return { valid: true, index: -1, reason: 'ok' as const, detail: `${ordered.length} admin actions verified.` };
}
