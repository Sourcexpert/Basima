import { canonicalize, sha256 } from '../crypto/hash';

/**
 * Offline evidence-package verification (Build Guide §13 and §14).
 *
 * Purpose: a counterparty, an advocate, an arbitrator or a court clerk must be
 * able to check an exported evidence package without access to agre-e, our
 * database, our API or our UI. Everything needed is inside the package.
 *
 * The verifier deliberately:
 *   • returns precise technical findings, not a legal conclusion;
 *   • reports *which* link failed, so a failure can be investigated rather than
 *     simply disbelieved;
 *   • treats the manifest as untrusted input (it is checked against recomputed
 *     values, never used as the source of truth).
 *
 * This module has no server-only imports and no environment reads: it is the same
 * code that can be shipped in a standalone verification tool.
 */

export interface OfflineCheck {
  name: 'document_digest' | 'chain_links' | 'chain_root' | 'required_events';
  passed: boolean;
  detail: string;
}

export interface OfflineVerification {
  ok: boolean;
  documentIntegrity: boolean;
  chainIntegrity: boolean;
  requiredEventsPresent: boolean;
  failingIndex: number | null;
  findings: OfflineCheck[];
  /** Plain-language statements that say only what was technically verified. */
  statements: string[];
}

/** Events that must be present for a package to describe a completed agreement. */
export const REQUIRED_EVENT_TYPES = [
  'agreement.created',
  'agreement.version_created',
  'party.signed',
  'stamp.issued',
] as const;

interface PackageEvent {
  id: string;
  agreement_id?: string | null;
  actor_id?: string | null;
  event_type: string;
  object_id?: string | null;
  occurred_at: string;
  ip_hash?: string | null;
  metadata?: Record<string, unknown>;
  previous_hash: string | null;
  event_hash: string;
}

interface PackageManifest {
  format?: string;
  version?: string;
  agreement_id?: string;
  document_hash_algorithm?: string;
  document_hash?: string;
  event_chain_root?: string;
}

export function canonicalPackageEventPayload(e: PackageEvent): string {
  return canonicalize({
    id: e.id,
    agreement_id: e.agreement_id ?? null,
    actor_id: e.actor_id ?? null,
    event_type: e.event_type,
    object_id: e.object_id ?? null,
    occurred_at: e.occurred_at,
    ip_hash: e.ip_hash ?? null,
    metadata: e.metadata ?? {},
  });
}

export function verifyOffline(
  manifest: PackageManifest | null | undefined,
  events: unknown,
  documentBytes: string | Buffer | Uint8Array,
): OfflineVerification {
  const findings: OfflineCheck[] = [];
  const list: PackageEvent[] = Array.isArray(events) ? (events as PackageEvent[]) : [];

  // 1. Recalculate the document digest and compare with the manifest.
  const recomputedDocumentHash = sha256(
    typeof documentBytes === 'string' ? documentBytes : Buffer.from(documentBytes as Uint8Array).toString('utf8'),
  );
  const documentIntegrity = Boolean(manifest?.document_hash) && recomputedDocumentHash === manifest!.document_hash;
  findings.push({
    name: 'document_digest',
    passed: documentIntegrity,
    detail: documentIntegrity
      ? `Recomputed SHA-256 matches the manifest (${recomputedDocumentHash.slice(0, 16)}…).`
      : `Recomputed SHA-256 ${recomputedDocumentHash.slice(0, 16)}… does not match the manifest value ${String(manifest?.document_hash ?? 'missing').slice(0, 16)}….`,
  });

  // 2. Reconstruct canonical events and verify each previous_hash link + digest.
  let failingIndex: number | null = null;
  let previous: string | null = null;
  let chainIntegrity = list.length > 0;
  for (const [index, event] of list.entries()) {
    if (failingIndex !== null) break;
    if ((event.previous_hash ?? null) !== previous) {
      chainIntegrity = false;
      failingIndex = index;
      findings.push({
        name: 'chain_links',
        passed: false,
        detail: `Event ${index} commits to "${event.previous_hash ?? 'GENESIS'}" but the preceding link is "${previous ?? 'GENESIS'}" — an event may have been inserted, removed or reordered.`,
      });
      break;
    }
    const recomputed = sha256(`${previous ?? 'GENESIS'}\n${canonicalPackageEventPayload(event)}`);
    if (recomputed !== event.event_hash) {
      chainIntegrity = false;
      failingIndex = index;
      findings.push({
        name: 'chain_links',
        passed: false,
        detail: `Event ${index} (${event.event_type}) records digest ${String(event.event_hash).slice(0, 16)}… but the canonical event hashes to ${recomputed.slice(0, 16)}….`,
      });
      break;
    }
    previous = event.event_hash;
  }
  if (failingIndex === null) {
    findings.push({
      name: 'chain_links',
      passed: chainIntegrity,
      detail: chainIntegrity
        ? `${list.length} event(s) recomputed; every link and digest verified.`
        : 'No events were supplied, so the chain cannot be verified.',
    });
  }

  // 3. The chain root recorded in the manifest must equal the recomputed head.
  const chainRoot = list.length > 0 ? list[list.length - 1].event_hash : null;
  const rootMatches = Boolean(manifest?.event_chain_root) && chainRoot === manifest!.event_chain_root;
  findings.push({
    name: 'chain_root',
    passed: rootMatches,
    detail: rootMatches
      ? 'The recomputed chain head matches the manifest root.'
      : `The recomputed chain head ${chainRoot ? `${chainRoot.slice(0, 16)}…` : '(none)'} does not match the manifest root ${String(manifest?.event_chain_root ?? 'missing').slice(0, 16)}….`,
  });

  // 4. Required signing/completion events must be present in the package.
  const presentTypes = new Set(list.map((e) => e.event_type));
  const missing = REQUIRED_EVENT_TYPES.filter((t) => !presentTypes.has(t));
  const requiredEventsPresent = missing.length === 0;
  findings.push({
    name: 'required_events',
    passed: requiredEventsPresent,
    detail: requiredEventsPresent
      ? 'Required creation, version, signing and stamp events are present.'
      : `Missing required event type(s): ${missing.join(', ')}.`,
  });

  const ok = documentIntegrity && chainIntegrity && rootMatches && requiredEventsPresent && failingIndex === null;

  const statements = ok
    ? [
        'Document integrity verified.',
        'Evidence-chain integrity verified.',
        'Required signing events recorded.',
        'No broken chain links detected.',
      ]
    : [
        'Document integrity ' + (documentIntegrity ? 'verified.' : 'NOT verified.'),
        'Evidence-chain integrity ' + (chainIntegrity && failingIndex === null ? 'verified.' : 'NOT verified.'),
        requiredEventsPresent ? 'Required signing events recorded.' : 'Required signing events NOT all present.',
        failingIndex === null ? 'No broken chain links detected.' : `Broken chain link detected at event index ${failingIndex}.`,
        'Legal treatment is determined by the applicable process or court, not by this verification.',
      ];

  return { ok, documentIntegrity, chainIntegrity, requiredEventsPresent, failingIndex, findings, statements };
}
