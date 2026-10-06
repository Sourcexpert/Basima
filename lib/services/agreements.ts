import 'server-only';
import { appendAgreementEvent, store } from '@/lib/data/store';
import { canPerform, evaluateCompletion, nextActionFor, type AccessSubject } from '@/lib/auth/user-access';
import { buildPackage, type PackageBundle } from '@/lib/evidence/package';
import { sha256 } from '@/lib/crypto/hash';
import { env } from '@/lib/env';
import { newId, type AgreementDocument, type AgreementParty, type AgreementSummary } from '@/lib/data/types';
import {
  acceptInvitationSchema, addVersionSchema, createAgreementSchema, dataRequestSchema, formatZodError,
  invitePartySchema, revokeSchema, signSchema, type ActionResult,
} from '@/lib/validation/user-schemas';

/**
 * The agreement lifecycle, from the parties' side.
 *
 * Signing follows the exact order the build guide sets out (§11):
 *   invite -> authenticate -> authorize -> load exact version -> display agreement
 *   -> capture consent -> confirm signing action -> write signature event
 *   -> append audit event -> evaluate completion -> stamp.
 *
 * Two properties are enforced here rather than trusted:
 *   • an executed version is frozen and can never be edited (§7);
 *   • a duplicate sign request cannot create a second completion state (§20).
 */

export interface UserContext {
  viewer: { userId: string; email: string; displayName: string };
  ipHash: string | null;
  userAgent: string | null;
}

/**
 * Serialises work per agreement. Two parties clicking "sign" at the same moment
 * must produce one consistent completion transition, not two stamps. In Postgres
 * the equivalent guarantee is the advisory lock inside `record_signature_event()`
 * (migration 0003), so this mutex is the demo/local equivalent of the same
 * transaction boundary — not a substitute for it.
 */
const locks = new Map<string, Promise<unknown>>();
async function withAgreementLock<T>(agreementId: string, fn: () => Promise<T>): Promise<T> {
  const previous = locks.get(agreementId) ?? Promise.resolve();
  const run = previous.then(fn, fn);
  locks.set(
    agreementId,
    run.catch(() => undefined),
  );
  return run;
}

const replay = new Map<string, { at: number; result: ActionResult<unknown> }>();
function replayHit<T>(key: string): ActionResult<T> | null {
  const hit = replay.get(key);
  if (hit && Date.now() - hit.at < 15 * 60_000) return hit.result as ActionResult<T>;
  return null;
}
function replayStore<T>(key: string, result: ActionResult<T>): ActionResult<T> {
  replay.set(key, { at: Date.now(), result });
  return result;
}

async function subject(
  agreementId: string,
  viewerEmail?: string | null,
): Promise<{ agreement: AgreementSummary; subj: AccessSubject; documents: AgreementDocument[] } | null> {
  const s = store();
  const agreement = await s.getAgreementSummary(agreementId);
  if (!agreement) return null;
  const [parties, signatureEvents, documents] = await Promise.all([
    s.listParties(agreementId),
    s.listSignatureEvents(agreementId),
    s.listDocuments(agreementId),
  ]);
  const current = documents.find((d) => d.versionNumber === agreement.currentVersion) ?? documents[documents.length - 1] ?? null;
  return {
    agreement,
    documents,
    subj: { agreement, parties, signatureEvents, currentVersion: current, viewerEmail: viewerEmail ?? null },
  };
}

function ref(seed: string): string {
  return `AG-${sha256(seed).slice(0, 6).toUpperCase()}`;
}

/* ------------------------------------------------------------ create draft -- */

export async function createAgreement(ctx: UserContext, input: unknown): Promise<ActionResult<{ agreementId: string; ref: string; versionId: string }>> {
  const parsed = createAgreementSchema.safeParse(input);
  if (!parsed.success) return { ok: false, error: formatZodError(parsed.error), code: 'validation' };
  const { title, agreementType, documentText, idempotencyKey } = parsed.data;

  const cached = replayHit<{ agreementId: string; ref: string; versionId: string }>(idempotencyKey);
  if (cached) return cached;

  const s = store();
  const id = newId('agr');
  const reference = ref(`${ctx.viewer.userId}:${title}:${Date.now()}`);
  const now = new Date().toISOString();
  const digest = sha256(documentText);

  const agreement: AgreementSummary = {
    id, ref: reference, title, agreementType, ownerId: ctx.viewer.userId, ownerEmail: ctx.viewer.email,
    status: 'draft', currentVersion: 1, documentHash: digest, partiesCount: 0, requiredSigners: 0,
    completedSigners: 0, stampIssuedAt: null, chainHead: null, createdAt: now, completedAt: null,
  };
  await s.appendAgreement(agreement);

  const versionId = newId('agv');
  await s.appendDocument({
    id: versionId, agreementId: id, versionNumber: 1, storagePath: `agreements/${id}/v1.txt`,
    sha256: digest, byteSize: Buffer.byteLength(documentText, 'utf8'), createdBy: ctx.viewer.userId,
    createdAt: now, frozenAt: null, body: documentText,
  });

  await appendAgreementEvent({
    agreementId: id, actorId: ctx.viewer.userId, eventType: 'agreement.created',
    metadata: { title, type: agreementType, reference },
    ipHash: ctx.ipHash, userAgent: ctx.userAgent,
  });
  await appendAgreementEvent({
    agreementId: id, actorId: ctx.viewer.userId, eventType: 'agreement.version_created',
    metadata: { version: 1, agreement_version_id: versionId, sha256: digest, bytes: Buffer.byteLength(documentText, 'utf8') },
    ipHash: ctx.ipHash, userAgent: ctx.userAgent,
  });

  return replayStore(idempotencyKey, {
    ok: true,
    data: { agreementId: id, ref: reference, versionId },
    message: `Draft created as ${reference}. Version 1 is stored with its SHA-256 digest; it is immutable from the moment it is written.`,
  });
}

/* ---------------------------------------------------------- add a version -- */

export async function addVersion(ctx: UserContext, input: unknown): Promise<ActionResult<{ versionId: string; versionNumber: number; sha256: string }>> {
  const parsed = addVersionSchema.safeParse(input);
  if (!parsed.success) return { ok: false, error: formatZodError(parsed.error), code: 'validation' };
  const { agreementId, documentText, note, idempotencyKey } = parsed.data;

  const cached = replayHit<{ versionId: string; versionNumber: number; sha256: string }>(idempotencyKey);
  if (cached) return cached;

  return withAgreementLock(agreementId, async () => {
    const loaded = await subject(agreementId, ctx.viewer.email);
    if (!loaded) return replayStore(idempotencyKey, { ok: false, error: 'Agreement not found.', code: 'validation' as const });

    const decision = canPerform(ctx.viewer.userId, loaded.subj, 'add_version');
    if (!decision.allowed) return replayStore(idempotencyKey, { ok: false, error: decision.reason, code: 'forbidden' as const });

    const s = store();
    const documents = await s.listDocuments(agreementId);
    const nextNumber = Math.max(...documents.map((d) => d.versionNumber), 0) + 1;
    const versionId = newId('agv');
    const digest = sha256(documentText);
    const now = new Date().toISOString();

    await s.appendDocument({
      id: versionId, agreementId, versionNumber: nextNumber, storagePath: `agreements/${agreementId}/v${nextNumber}.txt`,
      sha256: digest, byteSize: Buffer.byteLength(documentText, 'utf8'), createdBy: ctx.viewer.userId,
      createdAt: now, frozenAt: null, body: documentText,
    });

    // Existing signature requests now point at superseded text, so they are
    // expired rather than silently re-pointed at the new version.
    const requests = await s.listSignatureRequests(agreementId);
    for (const request of requests.filter((r) => r.status !== 'signed' && r.versionId !== versionId)) {
      await s.patchSignatureRequest(request.id, { status: 'expired' });
    }
    for (const party of await s.listParties(agreementId)) {
      if (party.signingRequired && party.status !== 'removed') {
        await s.appendSignatureRequest({
          id: newId('srq'), agreementId, versionId, partyId: party.id, requestedBy: ctx.viewer.userId,
          status: 'requested', requestedAt: now, expiresAt: null,
        });
      }
    }

    await s.patchAgreement(agreementId, {
      currentVersion: nextNumber,
      documentHash: digest,
      status: loaded.agreement.status === 'draft' && loaded.subj.parties.length > 0 ? 'awaiting_signatures' : loaded.agreement.status,
    });

    await appendAgreementEvent({
      agreementId, actorId: ctx.viewer.userId, eventType: 'agreement.version_created',
      metadata: {
        version: nextNumber, agreement_version_id: versionId, sha256: digest,
        bytes: Buffer.byteLength(documentText, 'utf8'), note: note || undefined,
        supersedes_version: loaded.agreement.currentVersion,
        previous_version_preserved: true,
      },
      ipHash: ctx.ipHash, userAgent: ctx.userAgent,
    });

    return replayStore(idempotencyKey, {
      ok: true,
      data: { versionId, versionNumber: nextNumber, sha256: digest },
      message: `Version ${nextNumber} created and hashed. Version ${loaded.agreement.currentVersion} is unchanged and remains on the record; any unsigned party must sign version ${nextNumber}.`,
    });
  });
}

/* ----------------------------------------------------------- invite a party -- */

export async function inviteParty(ctx: UserContext, input: unknown): Promise<ActionResult<{ partyId: string }>> {
  const parsed = invitePartySchema.safeParse(input);
  if (!parsed.success) return { ok: false, error: formatZodError(parsed.error), code: 'validation' };
  const { agreementId, email, displayName, partyRole, signingRequired, signingOrder, idempotencyKey } = parsed.data;

  const cached = replayHit<{ partyId: string }>(idempotencyKey);
  if (cached) return cached;

  return withAgreementLock(agreementId, async () => {
    const loaded = await subject(agreementId, ctx.viewer.email);
    if (!loaded) return replayStore(idempotencyKey, { ok: false, error: 'Agreement not found.', code: 'validation' as const });

    const decision = canPerform(ctx.viewer.userId, loaded.subj, 'invite');
    if (!decision.allowed) return replayStore(idempotencyKey, { ok: false, error: decision.reason, code: 'forbidden' as const });

    const s = store();
    const existing = loaded.subj.parties.find((p) => p.email.toLowerCase() === email.toLowerCase() && p.status !== 'removed');
    if (existing) {
      return replayStore(idempotencyKey, { ok: false, error: `${email} is already a party on this agreement as ${existing.partyRole}.`, code: 'conflict' as const });
    }

    const account = await s.getUserByEmail(email);
    const current = loaded.documents.find((d) => d.versionNumber === loaded.agreement.currentVersion) ?? null;
    const now = new Date().toISOString();
    const partyId = newId('pty');

    const party: AgreementParty = {
      id: partyId, agreementId, userId: account?.id ?? null, displayName, email, partyRole,
      signingRequired, signingOrder, status: 'invited', invitationSentAt: now, invitationAcceptedAt: null,
      assuranceLevel: null, identityVerifiedAt: null,
    };
    await s.appendParty(party);

    if (signingRequired && current) {
      await s.appendSignatureRequest({
        id: newId('srq'), agreementId, versionId: current.id, partyId, requestedBy: ctx.viewer.userId,
        status: 'requested', requestedAt: now, expiresAt: null,
      });
    }

    const parties = [...loaded.subj.parties, party];
    await s.patchAgreement(agreementId, {
      partiesCount: parties.length,
      requiredSigners: parties.filter((p) => p.signingRequired).length,
      status: loaded.agreement.status === 'draft' ? 'awaiting_parties' : loaded.agreement.status,
    });

    await appendAgreementEvent({
      agreementId, actorId: ctx.viewer.userId, eventType: 'agreement.party_invited',
      metadata: {
        party_id: partyId, party_role: partyRole, signing_required: signingRequired,
        signing_order: signingOrder, invitation_channel: 'email', // demo: no email is sent
        version_to_sign: current?.versionNumber ?? null,
      },
      ipHash: ctx.ipHash, userAgent: ctx.userAgent,
    });

    return replayStore(idempotencyKey, {
      ok: true,
      data: { partyId },
      message: `${displayName} was invited as ${partyRole}${signingRequired ? ` and must sign version ${current?.versionNumber ?? 1}` : ' (no signature required)'}. The invitation and its terms are recorded in the chain.`,
    });
  });
}

/* -------------------------------------------------------- accept invitation -- */

export async function acceptInvitation(ctx: UserContext, input: unknown): Promise<ActionResult<{ partyId: string }>> {
  const parsed = acceptInvitationSchema.safeParse(input);
  if (!parsed.success) return { ok: false, error: formatZodError(parsed.error), code: 'validation' };
  const { agreementId } = parsed.data;

  return withAgreementLock(agreementId, async () => {
    const loaded = await subject(agreementId, ctx.viewer.email);
    if (!loaded) return { ok: false, error: 'Agreement not found.', code: 'validation' };

    // Invitations are addressed to an email address. Acceptance is the moment
    // the account is bound to the party row, and from then on the user id is
    // what authorises — the email is not consulted again.
    const party =
      loaded.subj.parties.find((p) => p.userId === ctx.viewer.userId && p.status !== 'removed') ??
      loaded.subj.parties.find(
        (p) => !p.userId && p.email.trim().toLowerCase() === ctx.viewer.email.trim().toLowerCase() && p.status !== 'removed',
      ) ??
      null;
    if (!party) return { ok: false, error: 'You are not an invited party on this agreement.', code: 'forbidden' };
    if (party.invitationAcceptedAt) return { ok: true, data: { partyId: party.id }, message: 'Invitation already accepted.' };

    const s = store();
    const now = new Date().toISOString();
    const account = await s.getUser(party.userId ?? ctx.viewer.userId);

    // Acceptance *is* the verification event: the person authenticated as the
    // account the invitation was addressed to. The level records how much was
    // checked (a verified email is stronger than an account that merely exists),
    // and the timestamp records that the check happened.
    const assurance = account?.emailVerified ? 'email_otp' : 'email';
    await s.patchParty(party.id, {
      userId: party.userId ?? ctx.viewer.userId,
      status: 'accepted', invitationAcceptedAt: now,
      assuranceLevel: assurance,
      identityVerifiedAt: now,
    });

    await appendAgreementEvent({
      agreementId, actorId: ctx.viewer.userId, eventType: 'party.identity_verified',
      metadata: {
        party_id: party.id, party_role: party.partyRole,
        invitation_bound_to_user_id: party.userId ?? ctx.viewer.userId,
        assurance_level: assurance,
        provider: 'internal',
        note: 'Assurance level reflects the verification actually performed; it is not an assertion of identity beyond that.',
      },
      ipHash: ctx.ipHash, userAgent: ctx.userAgent,
    });

    return {
      ok: true,
      data: { partyId: party.id },
      message: 'Invitation accepted. Review the agreement carefully, then sign the exact version shown to you.',
    };
  });
}

/* --------------------------------------------------------------- the sign --- */

export interface SignReceipt {
  signatureEventId: string;
  versionId: string;
  versionNumber: number;
  documentHash: string;
  signedAt: string;
  duplicate: boolean;
  completed: boolean;
  chainHead: string | null;
  stampIssuedAt: string | null;
  packageId: string | null;
  pending: Array<{ partyRole: string; displayName: string; signingOrder: number }>;
  statements: string[];
}

/**
 * The signing transaction. Nothing here trusts the browser: the version, the
 * document digest, the party's authority and the completion state are all
 * re-derived server-side from stored records.
 */
export async function signAgreement(ctx: UserContext, input: unknown): Promise<ActionResult<SignReceipt>> {
  const parsed = signSchema.safeParse(input);
  if (!parsed.success) return { ok: false, error: formatZodError(parsed.error), code: 'validation' };
  const { agreementId, versionId, disclosureVersion, confirmName, confirmIntent, idempotencyKey } = parsed.data;
  void confirmIntent;

  const cached = replayHit<SignReceipt>(idempotencyKey);
  if (cached) return cached;

  return withAgreementLock(agreementId, async () => {
    const s = store();
    const loaded = await subject(agreementId, ctx.viewer.email);
    if (!loaded) return replayStore(idempotencyKey, { ok: false, error: 'Agreement not found.', code: 'validation' as const });

    const version = loaded.documents.find((d) => d.id === versionId) ?? null;
    const subj: AccessSubject = { ...loaded.subj, version };
    const decision = canPerform(ctx.viewer.userId, subj, 'sign');

    if (!decision.allowed) {
      // Refusals on the *evidentiary* path are recorded too: an attempt to sign
      // a superseded version is exactly the kind of event a dispute turns on.
      await appendAgreementEvent({
        agreementId, actorId: ctx.viewer.userId, eventType: 'party.signature_refused',
        metadata: { reason: decision.reason, attempted_version_id: versionId, attempted_version_number: version?.versionNumber ?? null },
        ipHash: ctx.ipHash, userAgent: ctx.userAgent,
      }).catch(() => undefined);
      return replayStore(idempotencyKey, { ok: false, error: decision.reason, code: 'forbidden' as const });
    }

    const party =
      loaded.subj.parties.find((p) => p.userId === ctx.viewer.userId && p.status !== 'removed')!;

    // Idempotency: a resubmitted form must not produce a second signed event.
    const already = loaded.subj.signatureEvents.find(
      (e) => e.partyId === party.id && e.versionId === version!.id && e.outcome === 'signed',
    );
    if (already || decision.note === 'duplicate') {
      const completion = evaluateCompletion(loaded.subj.parties, loaded.subj.signatureEvents, version!.id);
      return replayStore(idempotencyKey, {
        ok: true,
        data: {
          signatureEventId: already?.id ?? 'existing', versionId: version!.id, versionNumber: version!.versionNumber,
          documentHash: version!.sha256, signedAt: already?.occurredAt ?? new Date().toISOString(), duplicate: true,
          completed: loaded.agreement.status === 'completed', chainHead: loaded.agreement.chainHead,
          stampIssuedAt: loaded.agreement.stampIssuedAt, packageId: null,
          pending: completion.pending.map((p) => ({ partyRole: p.partyRole, displayName: p.displayName, signingOrder: p.signingOrder })),
          statements: ['Your signature was already recorded on this version. Nothing was recorded twice.'],
        },
        message: 'Your signature on this version is already on the record — no duplicate event was created.',
      });
    }

    // The name typed by the signer must match the party record. This is a
    // deliberate intent check, not an identity check (that is separate).
    if (confirmName.trim().toLowerCase() !== party.displayName.trim().toLowerCase()) {
      return replayStore(idempotencyKey, {
        ok: false,
        error: `The name you typed does not match the party record for your account (${party.displayName}). Type your full name exactly as it should appear on the agreement.`,
        code: 'validation' as const,
      });
    }

    // Integrity check at the moment of signing: the bytes we are about to bind
    // the signature to must still hash to the digest recorded for this version.
    if (version!.body !== undefined && sha256(version!.body) !== version!.sha256) {
      await appendAgreementEvent({
        agreementId, actorId: ctx.viewer.userId, eventType: 'integrity.check_failed',
        metadata: {
          version_id: version!.id, expected_sha256: version!.sha256,
          recomputed_sha256: sha256(version!.body ?? ''), blocked: true,
        },
        ipHash: ctx.ipHash, userAgent: ctx.userAgent,
      });
      return replayStore(idempotencyKey, {
        ok: false,
        error: 'The stored document does not match its recorded digest, so signing has been blocked. Report this to support immediately — the record must be investigated before it is signed.',
        code: 'conflict' as const,
      });
    }

    const now = new Date().toISOString();
    const consentId = newId('cns');
    await s.appendConsent({
      id: consentId, agreementId, userId: ctx.viewer.userId, disclosureVersion,
      scope: 'sign_and_evidence', acceptedAt: now, ipHash: ctx.ipHash,
    });

    const signatureEventId = newId('sev');
    await s.appendSignatureEvent({
      id: signatureEventId, agreementId, versionId: version!.id, partyId: party.id,
      actorId: ctx.viewer.userId, signatureMethod: 'otp_confirmed_intent', outcome: 'signed',
      consentId, occurredAt: now, ipHash: ctx.ipHash, userAgent: ctx.userAgent,
    });

    const requests = await s.listSignatureRequests(agreementId);
    const request = requests.find((r) => r.partyId === party.id && r.versionId === version!.id);
    if (request) await s.patchSignatureRequest(request.id, { status: 'signed' });

    await appendAgreementEvent({
      agreementId, actorId: ctx.viewer.userId, eventType: 'party.consent_recorded',
      metadata: {
        party_id: party.id, party_role: party.partyRole, consent_id: consentId,
        disclosure_version: disclosureVersion, scope: 'sign_and_evidence',
      },
      ipHash: ctx.ipHash, userAgent: ctx.userAgent,
    });

    await appendAgreementEvent({
      agreementId, actorId: ctx.viewer.userId, eventType: 'party.signed',
      metadata: {
        party_id: party.id, party_role: party.partyRole, version: version!.versionNumber,
        agreement_version_id: version!.id, signature_method: 'otp_confirmed_intent',
        signature_event_id: signatureEventId, consent_id: consentId, document_sha256: version!.sha256,
      },
      ipHash: ctx.ipHash, userAgent: ctx.userAgent,
    });

    // ---------------------------------------------------- evaluate completion --
    const events = await s.listSignatureEvents(agreementId);
    const completion = evaluateCompletion(loaded.subj.parties, events, version!.id);

    await appendAgreementEvent({
      agreementId, actorId: null, eventType: 'agreement.completion_evaluated',
      metadata: {
        version: version!.versionNumber, required: completion.required.length,
        completed: completion.required.filter((p) => completion.signed.has(p.id)).length,
        satisfied: completion.complete,
        pending_party_roles: completion.pending.map((p) => p.partyRole),
        declined_party_roles: completion.declined.map((p) => p.partyRole),
      },
      ipHash: null, userAgent: null,
    });

    let stampIssuedAt: string | null = null;
    let packageId: string | null = null;
    let chainHead: string | null = null;

    if (completion.complete) {
      // Stamp = frozen version + completion of required actions + integrity
      // digest + an evidence-chain record. It is not a claim of legal validity.
      await s.freezeVersion(version!.id);
      const stampedAt = new Date().toISOString();
      await s.patchAgreement(agreementId, {
        status: 'completed', completedAt: stampedAt, stampIssuedAt: stampedAt,
        completedSigners: completion.required.length,
      });

      const stampEvent = await appendAgreementEvent({
        agreementId, actorId: null, eventType: 'stamp.issued',
        metadata: {
          version: version!.versionNumber, agreement_version_id: version!.id,
          document_sha256: version!.sha256, required_signers: completion.required.length,
          signed_signers: completion.required.length,
          definition: 'frozen version + required party actions complete + integrity digest + evidence-chain record',
        },
        ipHash: null, userAgent: null,
      });
      stampIssuedAt = stampedAt;
      chainHead = stampEvent.eventHash;

      const bundle = await buildEvidencePackage(ctx, agreementId);
      if (bundle.ok) packageId = bundle.data.packageId;
      const refreshed = await s.getAgreementSummary(agreementId);
      chainHead = refreshed?.chainHead ?? chainHead;
    } else {
      if (loaded.agreement.status !== 'awaiting_signatures') {
        await s.patchAgreement(agreementId, { status: 'awaiting_signatures' });
      }
      await s.patchAgreement(agreementId, { completedSigners: completion.signed.size });
    }

    const statements = completion.complete
      ? [
          'Your signature is recorded against this exact version.',
          'All required parties have now signed; the version has been frozen and stamped.',
          'An evidence package has been generated and can be verified independently.',
        ]
      : [
          'Your signature is recorded against this exact version.',
          `Still awaiting: ${completion.pending.map((p) => `${p.partyRole} (${p.displayName})`).join(', ')}.`,
          'The version is not frozen and no package is issued until every required party has signed.',
        ];

    return replayStore(idempotencyKey, {
      ok: true,
      data: {
        signatureEventId, versionId: version!.id, versionNumber: version!.versionNumber,
        documentHash: version!.sha256, signedAt: now, duplicate: false, completed: completion.complete,
        chainHead, stampIssuedAt, packageId,
        pending: completion.pending.map((p) => ({ partyRole: p.partyRole, displayName: p.displayName, signingOrder: p.signingOrder })),
        statements,
      },
      message: completion.complete
        ? 'Signed. All required signatures are in, the version is frozen and stamped, and the evidence package is ready.'
        : 'Signed. The agreement is not complete yet — the remaining parties have been recorded as still awaiting signature.',
    });
  });
}

/* ----------------------------------------------------------------- revoke --- */

export async function revokeAgreement(ctx: UserContext, input: unknown): Promise<ActionResult<{ agreementId: string }>> {
  const parsed = revokeSchema.safeParse(input);
  if (!parsed.success) return { ok: false, error: formatZodError(parsed.error), code: 'validation' };
  const { agreementId, reason, idempotencyKey } = parsed.data;

  const cached = replayHit<{ agreementId: string }>(idempotencyKey);
  if (cached) return cached;

  return withAgreementLock(agreementId, async () => {
    const loaded = await subject(agreementId, ctx.viewer.email);
    if (!loaded) return replayStore(idempotencyKey, { ok: false, error: 'Agreement not found.', code: 'validation' as const });

    const decision = canPerform(ctx.viewer.userId, loaded.subj, 'revoke');
    if (!decision.allowed) return replayStore(idempotencyKey, { ok: false, error: decision.reason, code: 'forbidden' as const });

    await store().patchAgreement(agreementId, { status: 'revoked' });
    await appendAgreementEvent({
      agreementId, actorId: ctx.viewer.userId, eventType: 'agreement.revoked',
      metadata: { reason, versions_frozen: 0, records_deleted: 0, note: 'Revocation appends an event; nothing is deleted or amended.' },
      ipHash: ctx.ipHash, userAgent: ctx.userAgent,
    });

    return replayStore(idempotencyKey, {
      ok: true,
      data: { agreementId },
      message: 'Revoked. The draft and its whole history are retained unaltered — a later dispute may need to know what was proposed.',
    });
  });
}

/* -------------------------------------------------------- evidence package -- */

export async function buildEvidencePackage(
  ctx: UserContext,
  agreementId: string,
): Promise<ActionResult<{ packageId: string; chainRoot: string; files: ReturnType<typeof describeFiles>; statements: string[]; ok2: boolean }>> {
  const s = store();
  const loaded = await subject(agreementId, ctx.viewer.email);
  if (!loaded) return { ok: false, error: 'Agreement not found.', code: 'validation' };

  const decision = canPerform(ctx.viewer.userId, loaded.subj, 'export');
  if (!decision.allowed) return { ok: false, error: decision.reason, code: 'forbidden' };

  const frozen = loaded.documents.find((d) => d.frozenAt) ?? loaded.documents[loaded.documents.length - 1];
  if (!frozen) return { ok: false, error: 'No document version is available to export.', code: 'conflict' };

  const [parties, events, signatureEvents, consents] = await Promise.all([
    s.listParties(agreementId),
    s.listAuditEvents({ agreementId, limit: 1000 }),
    s.listSignatureEvents(agreementId),
    s.listConsents(agreementId),
  ]);

  const bundle: PackageBundle = buildPackage({
    agreement: loaded.agreement,
    version: frozen,
    parties,
    events,
    signatureEvents,
    consents,
    generatedBy: ctx.viewer,
    generatedAt: new Date().toISOString(),
    documentFile: { name: 'document.txt', mime: 'text/plain' },
    documentBytesAvailable: frozen.body !== undefined,
  });

  // Idempotent: the same chain produces the same package, so re-generating
  // returns the existing record rather than polluting the table with copies.
  const existing = (await s.listPackages(agreementId)).find((p) => p.chainRoot === bundle.chainRoot);
  if (existing) {
    return {
      ok: true,
      data: {
        packageId: existing.id, chainRoot: existing.chainRoot,
        files: describeFiles(bundle.files), statements: existing.verification.statements, ok2: existing.verification.ok,
      },
      message: 'This agreement already has an evidence package for this chain; the existing one is returned unchanged.',
    };
  }

  const record = {
    id: newId('epk'), agreementId, versionId: frozen.id, format: 'agree-e-evidence-package',
    packageVersion: '1.0', documentHash: frozen.sha256, chainRoot: bundle.chainRoot,
    eventCount: events.length, createdAt: bundle.manifest.generated_at as string,
    createdBy: ctx.viewer.userId,
    verification: {
      ok: bundle.verification.ok,
      documentIntegrity: bundle.verification.documentIntegrity,
      chainIntegrity: bundle.verification.chainIntegrity,
      requiredEventsPresent: bundle.verification.requiredEventsPresent,
      findings: bundle.verification.findings,
      statements: bundle.verification.statements,
    },
  };
  await s.appendPackage(record);

  const exportEvent = await appendAgreementEvent({
    agreementId, actorId: ctx.viewer.userId, eventType: 'evidence.package_generated',
    metadata: {
      package_id: record.id, format: record.format, package_version: record.packageVersion,
      version: frozen.versionNumber, files: bundle.files.length, chain_root: bundle.chainRoot,
      verification_ok: bundle.verification.ok,
    },
    ipHash: ctx.ipHash, userAgent: ctx.userAgent,
  });
  // The export extends the chain, so the recorded head moves with it: the
  // package's root stays fixed at the state it described.
  await s.patchAgreement(agreementId, { chainHead: exportEvent.eventHash });

  return {
    ok: true,
    data: {
      packageId: record.id, chainRoot: bundle.chainRoot, files: describeFiles(bundle.files),
      statements: bundle.verification.statements, ok2: bundle.verification.ok,
    },
    message: bundle.verification.ok
      ? 'Evidence package generated. It contains the frozen document, the full event chain, the signature records and the verification result.'
      : 'Package generated, but verification did NOT pass. Do not rely on this record until the failing link has been investigated.',
  };
}

function describeFiles(files: Array<{ name: string; content: string; mime: string }>) {
  return files.map((f) => ({ name: f.name, bytes: Buffer.byteLength(f.content, 'utf8'), mime: f.mime }));
}

/** Files for download. The route zips exactly these. */
export async function packageFiles(ctx: UserContext, agreementId: string) {
  const s = store();
  const loaded = await subject(agreementId, ctx.viewer.email);
  if (!loaded) return { ok: false as const, error: 'Agreement not found.' };
  const decision = canPerform(ctx.viewer.userId, loaded.subj, 'export');
  if (!decision.allowed) return { ok: false as const, error: decision.reason };

  const frozen = loaded.documents.find((d) => d.frozenAt) ?? loaded.documents[loaded.documents.length - 1];
  if (!frozen) return { ok: false as const, error: 'No document version is available to export.' };

  const [parties, events, signatureEvents, consents] = await Promise.all([
    s.listParties(agreementId),
    s.listAuditEvents({ agreementId, limit: 1000 }),
    s.listSignatureEvents(agreementId),
    s.listConsents(agreementId),
  ]);

  const bundle = buildPackage({
    agreement: loaded.agreement, version: frozen, parties, events, signatureEvents, consents,
    generatedBy: ctx.viewer, generatedAt: new Date().toISOString(),
    documentFile: { name: 'document.txt', mime: 'text/plain' },
    documentBytesAvailable: frozen.body !== undefined,
  });

  return { ok: true as const, agreement: loaded.agreement, bundle };
}

/* --------------------------------------------------- data-subject requests -- */

export async function fileDataRequest(ctx: UserContext, input: unknown): Promise<ActionResult<{ requestId: string; dueAt: string }>> {
  const parsed = dataRequestSchema.safeParse(input);
  if (!parsed.success) return { ok: false, error: formatZodError(parsed.error), code: 'validation' };
  const { type, detail } = parsed.data;

  const now = new Date();
  const due = new Date(now.getTime() + 30 * 86_400_000);
  const id = newId('dsr');
  await store().appendDataRequest({
    id, userId: ctx.viewer.userId, type, detail, status: 'received',
    submittedAt: now.toISOString(), dueAt: due.toISOString(), resolvedAt: null, resolutionNote: null,
  });

  const explanations: Record<string, string> = {
    access: 'We will assemble the personal data we hold about you and the agreements you are party to.',
    correction: 'We will check the record and correct anything demonstrably inaccurate. Note that an executed agreement is immutable: a correction cannot rewrite what was signed, only annotate it.',
    deletion: 'We will assess what can be deleted. Executed agreements, stamps and audit events are retained as legal records — the request will be answered in writing explaining what was deleted and what must be kept, and why.',
    restriction: 'We will restrict processing of your data while the request is assessed.',
    portability: 'We will provide your data and your agreements in a machine-readable export.',
  };

  return {
    ok: true,
    data: { requestId: id, dueAt: due.toISOString() },
    message: `Request logged (${type}). ${explanations[type]} You will get a written response by ${due.toISOString().slice(0, 10)}.`,
  };
}

export { evaluateCompletion, nextActionFor };

/** Absolute URL helper for invitation links in production emails. */
export function invitationUrl(agreementId: string) {
  return `${env.appUrl}/app/agreements/${agreementId}`;
}
