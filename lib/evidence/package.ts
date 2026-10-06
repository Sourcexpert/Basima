import { sha256 } from '../crypto/hash';
import type { AuditEventRecord } from '../audit/chain';
import { verifyOffline, type OfflineVerification } from './offline-verify';
import type {
  AgreementDocument, AgreementParty, AgreementSummary, ConsentRecord, PackageFile, SignatureEvent,
} from '../data/types';

/**
 * Evidence-package construction (Build Guide §12–§14).
 *
 * Pure: given the stored records, produce the exact file set that a counterparty,
 * an advocate or a court clerk receives. The package is deliberately
 * self-describing and verifiable without agre-e — the manifest names the
 * algorithm, the digest, the chain root and the document file, and
 * verification.json records the result of an independent recomputation at the
 * moment of export.
 */

export const PACKAGE_FORMAT = 'agree-e-evidence-package';
export const PACKAGE_VERSION = '1.0';
export const VERIFIER_VERSION = '1.0.0';

export interface PackageInput {
  agreement: AgreementSummary;
  version: AgreementDocument;
  parties: AgreementParty[];
  events: AuditEventRecord[];
  signatureEvents: SignatureEvent[];
  consents: ConsentRecord[];
  generatedBy: { userId: string; email: string; displayName: string };
  generatedAt: string;
  /** Document file name and MIME; production packages carry the stored PDF. */
  documentFile?: { name: string; mime: string };
  /** Set by the caller when the stored object could not be read for a byte-level check. */
  documentBytesAvailable?: boolean;
}

export interface PackageBundle {
  manifest: Record<string, unknown>;
  files: PackageFile[];
  verification: OfflineVerification;
  chainRoot: string;
}

/** snake_case serialization of a stored event for the export/verification pair. */
export function toPackageEvent(e: AuditEventRecord) {
  return {
    id: e.id,
    agreement_id: e.agreementId,
    actor_id: e.actorId,
    event_type: e.eventType,
    object_id: e.objectId,
    occurred_at: e.occurredAt,
    ip_hash: e.ipHash,
    metadata: e.metadata ?? {},
    previous_hash: e.previousHash,
    event_hash: e.eventHash,
  };
}

export function buildPackage(input: PackageInput): PackageBundle {
  const {
    agreement, version, parties, events, signatureEvents, consents, generatedBy, generatedAt,
  } = input;

  const documentFile = input.documentFile ?? { name: 'document.txt', mime: 'text/plain' };
  const packageEvents = events.map(toPackageEvent);
  const chainRoot = events.length ? events[events.length - 1].eventHash : '';

  /**
   * Independent recomputation, at export time, over exactly the bytes that are
   * being written into the package. If a stored document no longer matches the
   * digest recorded at signing, the package says so instead of certifying it.
   */
  const storedBody = version.body ?? null;
  const digestRecheck = storedBody === null ? null : sha256(storedBody) === version.sha256;

  const verification = verifyOffline(
    {
      format: PACKAGE_FORMAT,
      version: PACKAGE_VERSION,
      agreement_id: agreement.id,
      document_hash_algorithm: 'SHA-256',
      document_hash: version.sha256,
      event_chain_root: chainRoot,
    },
    packageEvents,
    storedBody ?? '',
  );

  const signatures = signatureEvents.map((e) => {
    const party = parties.find((p) => p.id === e.partyId);
    const consent = consents.find((c) => c.id === e.consentId);
    return {
      signature_event_id: e.id,
      agreement_version_id: e.versionId,
      party_role: party?.partyRole ?? 'unknown',
      party_display_name: party?.displayName ?? null,
      party_email: party?.email ?? null,
      identity_assurance_level: party?.assuranceLevel ?? null,
      signature_method: e.signatureMethod,
      outcome: e.outcome,
      signed_at: e.occurredAt,
      consent: consent
        ? { disclosure_version: consent.disclosureVersion, scope: consent.scope, accepted_at: consent.acceptedAt }
        : null,
      // Stated explicitly so nobody reads more into the record than it supports.
      note: 'A signature record evidences that this actor confirmed intent on this exact version. Identity assurance is recorded separately.',
    };
  });

  const manifest: Record<string, unknown> = {
    format: PACKAGE_FORMAT,
    version: PACKAGE_VERSION,
    agreement_id: agreement.id,
    agreement_reference: agreement.ref,
    agreement_title: agreement.title,
    agreement_type: agreement.agreementType,
    agreement_status: agreement.status,
    agreement_version_id: version.id,
    agreement_version_number: version.versionNumber,
    document_file: documentFile.name,
    document_format: documentFile.mime,
    document_hash_algorithm: 'SHA-256',
    document_hash: version.sha256,
    document_bytes: version.byteSize,
    event_chain_root: chainRoot,
    event_count: events.length,
    signature_count: signatureEvents.filter((e) => e.outcome === 'signed').length,
    required_signers: parties.filter((p) => p.signingRequired).length,
    created_at: version.createdAt,
    frozen_at: version.frozenAt,
    completed_at: agreement.completedAt,
    stamp_issued_at: agreement.stampIssuedAt,
    generated_at: generatedAt,
    generated_by: { user_id: generatedBy.userId, email: generatedBy.email, display_name: generatedBy.displayName },
    contents: ['manifest.json', 'events.json', 'verification.json', 'signatures.json', 'certificate-data.json', documentFile.name],
    notes: [
      'This package is verifiable without access to agre-e: recompute the SHA-256 of the document file and rebuild the event chain from events.json.',
      'The evidence chain is tamper-evident, not tamper-proof. Verification detects alteration; it does not by itself establish legal effect.',
      'Legal treatment is determined by the applicable process or court.',
    ],
  };

  const certificateData: Record<string, unknown> = {
    // Section 15 workspace input: system identification, identifiers, timestamps,
    // digest, timeline and storage information, for a lawyer to assess.
    prepared_for: 'counsel_review',
    system_identification: {
      system_name: 'agre-e',
      system_role: 'Private agreement creation, signing and evidence preservation',
      environment: process.env.NODE_ENV ?? 'unknown',
      verifier_version: VERIFIER_VERSION,
    },
    agreement: {
      id: agreement.id,
      reference: agreement.ref,
      title: agreement.title,
      type: agreement.agreementType,
      owner_id: agreement.ownerId,
      status: agreement.status,
      created_at: agreement.createdAt,
      completed_at: agreement.completedAt,
      stamp_issued_at: agreement.stampIssuedAt,
    },
    version: {
      id: version.id,
      version_number: version.versionNumber,
      created_at: version.createdAt,
      frozen_at: version.frozenAt,
      storage_path: version.storagePath,
      sha256: version.sha256,
      byte_size: version.byteSize,
    },
    parties: parties.map((p) => ({
      party_id: p.id,
      party_role: p.partyRole,
      display_name: p.displayName,
      email: p.email,
      signing_required: p.signingRequired,
      signing_order: p.signingOrder,
      invitation_sent_at: p.invitationSentAt,
      invitation_accepted_at: p.invitationAcceptedAt,
      identity_assurance_level: p.assuranceLevel,
      identity_verified_at: p.identityVerifiedAt,
      status: p.status,
    })),
    timeline: events.map((e) => ({
      event_id: e.id,
      event_type: e.eventType,
      occurred_at: e.occurredAt,
      actor_id: e.actorId,
      event_hash: e.eventHash,
      previous_hash: e.previousHash,
    })),
    integrity_findings: {
      document_digest_recomputed_at_export: digestRecheck,
      document_digest_matches_stored: digestRecheck,
      chain_verified_at_export: verification.ok,
      chain_failing_index: verification.failingIndex,
      document_bytes_available: input.documentBytesAvailable ?? storedBody !== null,
    },
    declaration: {
      status: 'pending_counsel_approval',
      wording: null,
      note: 'The attestation wording, responsible signatory and procedure are to be determined by counsel. This file assembles inputs for that review; it is not itself a declaration.',
    },
    export_metadata: {
      generated_at: generatedAt,
      generated_by_user_id: generatedBy.userId,
      package_version: PACKAGE_VERSION,
      jurisdiction_note: 'Designed with Kenya Evidence Act (Cap. 80) ss.78A/106B and the Data Protection Act in mind. Counsel to confirm the claims made.',
    },
  };

  const files: PackageFile[] = [
    { name: 'manifest.json', mime: 'application/json', content: JSON.stringify(manifest, null, 2) },
    { name: 'events.json', mime: 'application/json', content: JSON.stringify({ format: PACKAGE_FORMAT, agreement_id: agreement.id, events: packageEvents }, null, 2) },
    {
      name: 'verification.json',
      mime: 'application/json',
      content: JSON.stringify(
        {
          format: PACKAGE_FORMAT,
          verifier_version: VERIFIER_VERSION,
          checked_at: generatedAt,
          result: {
            ok: verification.ok,
            document_integrity: verification.documentIntegrity,
            chain_integrity: verification.chainIntegrity,
            required_events_present: verification.requiredEventsPresent,
            failing_index: verification.failingIndex,
          },
          findings: verification.findings,
          statements: verification.statements,
          disclaimer: 'These are technical findings. Legal treatment is determined by the applicable process or court.',
        },
        null,
        2,
      ),
    },
    { name: 'signatures.json', mime: 'application/json', content: JSON.stringify({ format: PACKAGE_FORMAT, agreement_id: agreement.id, signatures }, null, 2) },
    { name: 'certificate-data.json', mime: 'application/json', content: JSON.stringify(certificateData, null, 2) },
  ];

  if (storedBody !== null) {
    files.push({ name: documentFile.name, mime: documentFile.mime, content: storedBody });
  }

  return { manifest, files, verification, chainRoot };
}

/** Deterministic file listing for the console/UI preview before download. */
export function describePackage(files: PackageFile[]): Array<{ name: string; bytes: number; mime: string }> {
  return files.map((f) => ({ name: f.name, bytes: Buffer.byteLength(f.content, 'utf8'), mime: f.mime }));
}
