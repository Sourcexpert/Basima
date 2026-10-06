import type { AgreementDocument, AgreementParty, SignatureEvent } from '@/lib/data/types';

/**
 * Authorization for the user workspace.
 *
 * The console's RBAC answers "may this operator do this?"; this module answers a
 * different question: "is this person a party to *this* agreement, and is the
 * action available on *this* version?" It is the same deny-by-default discipline
 * applied to the parties themselves, and it is a pure function so the rules can
 * be tested without a database.
 *
 * Deliberately no role can substitute for membership: being an administrator does
 * not make you a party (Build Guide §8).
 */

export type AgreementAction = 'view' | 'edit' | 'add_version' | 'invite' | 'revoke' | 'sign' | 'export';

export interface AccessSubject {
  agreement: { id: string; ownerId: string; status: string };
  parties: AgreementParty[];
  signatureEvents: SignatureEvent[];
  /** The version the action targets. For signing this must be the current one. */
  version?: Pick<AgreementDocument, 'id' | 'versionNumber' | 'frozenAt'> | null;
  /** Latest version of the agreement, used to reject signatures on superseded text. */
  currentVersion?: Pick<AgreementDocument, 'id' | 'versionNumber' | 'frozenAt'> | null;
  /**
   * The viewer's email address. An invitation is bound to an email address, not
   * to an account: until the invited person accepts, their party row has no
   * user_id, and matching on email is how they are recognised at all. Acceptance
   * binds the account, after which the id is the only thing consulted.
   */
  viewerEmail?: string | null;
}

export type AccessLevel = 'owner' | 'party' | 'none';

export type Decision =
  | { allowed: true; level: Exclude<AccessLevel, 'none'>; note?: string }
  | { allowed: false; reason: string };

export const EDITABLE_STATUSES = ['draft', 'awaiting_parties'] as const;
export const SIGNING_STATUSES = ['awaiting_parties', 'awaiting_signatures'] as const;

export function accessLevel(viewerId: string, subject: AccessSubject): { level: AccessLevel; party: AgreementParty | null } {
  const email = subject.viewerEmail?.trim().toLowerCase() ?? null;
  // Ownership and party membership are independent facts. An owner is often
  // also a named signer, so the party row is resolved either way — refusing to
  // look for it would leave an owner unable to sign their own agreement.
  const party =
    subject.parties.find((p) => p.userId === viewerId && p.status !== 'removed') ??
    subject.parties.find(
      (p) => !p.userId && email !== null && p.email.trim().toLowerCase() === email && p.status !== 'removed',
    ) ??
    null;

  if (subject.agreement.ownerId === viewerId) return { level: 'owner', party };
  return { level: party ? 'party' : 'none', party };
}

/**
 * Parties required to sign a given version, in signing order.
 * A declined party blocks completion, which is surfaced rather than hidden.
 */
export function requiredParties(parties: AgreementParty[], versionId?: string | null): AgreementParty[] {
  void versionId;
  return parties
    .filter((p) => p.signingRequired && p.status !== 'removed' && p.status !== 'declined')
    .sort((a, b) => a.signingOrder - b.signingOrder);
}

export function signedPartyIds(events: SignatureEvent[], versionId: string): Set<string> {
  return new Set(
    events.filter((e) => e.versionId === versionId && e.outcome === 'signed').map((e) => e.partyId),
  );
}

export interface CompletionEvaluation {
  complete: boolean;
  required: AgreementParty[];
  signed: Set<string>;
  pending: AgreementParty[];
  declined: AgreementParty[];
}

/**
 * Completion is evaluated from the stored signature events, not from a mutable
 * status flag — the same reason the audit ledger is append-only.
 */
export function evaluateCompletion(
  parties: AgreementParty[],
  events: SignatureEvent[],
  versionId: string,
): CompletionEvaluation {
  const required = requiredParties(parties, versionId);
  const signed = signedPartyIds(events, versionId);
  const pending = required.filter((p) => !signed.has(p.id));
  const declined = parties.filter((p) => p.signingRequired && p.status === 'declined');
  return { complete: required.length > 0 && pending.length === 0 && declined.length === 0, required, signed, pending, declined };
}

/** Signing order is enforced so a later signer cannot jump ahead of an earlier one. */
export function signingBlockers(
  parties: AgreementParty[],
  events: SignatureEvent[],
  versionId: string,
  party: AgreementParty,
): AgreementParty[] {
  const signed = signedPartyIds(events, versionId);
  return requiredParties(parties, versionId).filter(
    (p) => p.signingOrder < party.signingOrder && !signed.has(p.id),
  );
}

export function canPerform(viewerId: string, subject: AccessSubject, action: AgreementAction): Decision {
  const { level, party } = accessLevel(viewerId, subject);
  const status = subject.agreement.status;

  if (level === 'none') {
    return { allowed: false, reason: 'You are not the owner or an invited party on this agreement.' };
  }

  // Revoked and completed records are read-only for everyone, permanently.
  const immutable = status === 'completed' || status === 'revoked';

  switch (action) {
    case 'view':
      return { allowed: true, level };

    case 'edit':
      if (level !== 'owner') return { allowed: false, reason: 'Only the agreement owner may edit the working draft.' };
      if (immutable) {
        return {
          allowed: false,
          reason: status === 'completed'
            ? 'This agreement is complete. An executed version is frozen: record a change as a new agreement or an amendment version instead.'
            : 'This agreement is revoked and is retained read-only.',
        };
      }
      return { allowed: true, level };

    case 'add_version':
      if (level !== 'owner') return { allowed: false, reason: 'Only the agreement owner may create a new version.' };
      if (immutable) return { allowed: false, reason: 'Executed or revoked agreements cannot receive new versions.' };
      return {
        allowed: true,
        level,
        note: 'This creates an immutable version. Earlier versions remain on the record and are never overwritten.',
      };

    case 'invite':
      if (level !== 'owner') return { allowed: false, reason: 'Only the agreement owner may invite parties.' };
      if (immutable) return { allowed: false, reason: 'A completed or revoked agreement cannot take new parties.' };
      return { allowed: true, level };

    case 'revoke':
      if (level !== 'owner') return { allowed: false, reason: 'Only the agreement owner may revoke.' };
      if (status === 'revoked') return { allowed: false, reason: 'This agreement is already revoked.' };
      if (status === 'completed') {
        return { allowed: false, reason: 'A completed agreement cannot be revoked: the executed record stands.' };
      }
      return { allowed: true, level, note: 'Revocation appends an event. Nothing is deleted.' };

    case 'sign': {
      // Note: an owner who is not a party has nothing to sign — owning is not
      // signing. An owner who *is* named as a signer reaches the checks below.
      if (!party) {
        return { allowed: false, reason: 'Only an invited party with a signing requirement may sign this agreement.' };
      }
      if (!party.signingRequired) return { allowed: false, reason: 'Your role on this agreement does not require a signature.' };
      if (status === 'completed') return { allowed: false, reason: 'This agreement is already complete; your signature is on the record.' };
      if (status === 'revoked') return { allowed: false, reason: 'This agreement was revoked and can no longer be signed.' };
      if (status === 'draft') return { allowed: false, reason: 'The owner has not yet issued this agreement for signature.' };
      if (!party.invitationAcceptedAt) {
        return { allowed: false, reason: 'Accept the invitation before signing.' };
      }
      if (!subject.version) return { allowed: false, reason: 'No document version is available to sign.' };
      if (subject.currentVersion && subject.version.id !== subject.currentVersion.id) {
        return {
          allowed: false,
          reason: `You are looking at version ${subject.version.versionNumber}, but version ${subject.currentVersion.versionNumber} is current. Reload and sign the current version.`,
        };
      }
      if (party.identityVerifiedAt === null) {
        return { allowed: false, reason: 'Identity verification has not been completed for your party record.' };
      }
      const already = signedPartyIds(subject.signatureEvents, subject.version.id).has(party.id);
      if (already) return { allowed: true, level, note: 'duplicate' };
      const blockers = signingBlockers(subject.parties, subject.signatureEvents, subject.version.id, party);
      if (blockers.length > 0) {
        return {
          allowed: false,
          reason: `This agreement is signed in order. Awaiting ${blockers.map((b) => `${b.partyRole} (order ${b.signingOrder})`).join(', ')} before you can sign.`,
        };
      }
      return { allowed: true, level };
    }

    case 'export': {
      if (status !== 'completed') {
        return { allowed: false, reason: 'An evidence package is generated once the agreement is complete. Until then there is no frozen version to export.' };
      }
      return { allowed: true, level };
    }
  }
}

/**
 * What a party's own dashboard should show them: the single next thing to do.
 * Ordered by urgency so "what needs me?" is answered without reading a list.
 */
export function nextActionFor(viewerId: string, subject: AccessSubject): { label: string; href: string } | null {
  const { level, party } = accessLevel(viewerId, subject);
  const status = subject.agreement.status;
  const href = `/app/agreements/${subject.agreement.id}`;

  if (party && party.status === 'invited') return { label: 'Accept invitation', href };
  if (party && party.signingRequired && status !== 'completed' && status !== 'revoked') {
    const decision = canPerform(viewerId, subject, 'sign');
    if (decision.allowed && decision.note !== 'duplicate') return { label: 'Sign now', href: `${href}/sign` };
  }
  if (level === 'owner' && (status === 'draft' || status === 'awaiting_parties')) return { label: 'Prepare and invite', href };
  if (level === 'owner' && status === 'awaiting_signatures') return { label: 'Awaiting signatures', href };
  if (status === 'completed') return { label: 'View evidence package', href: '/app/evidence' };
  return null;
}
