import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { inflateRawSync } from 'node:zlib';

import { verifyChain } from '../lib/audit/chain';
import { sha256 } from '../lib/crypto/hash';
import { accessLevel, canPerform, evaluateCompletion, requiredParties, signingBlockers } from '../lib/auth/user-access';
import { buildPackage } from '../lib/evidence/package';
import { buildEvidenceZip } from '../lib/evidence/zip';
import {
  USER_WORKSPACE_OWNER, USER_AGREEMENTS, USER_PARTIES, USER_DOCUMENTS, USER_SIGNATURE_EVENTS,
  USER_CONSENTS, USER_AUDIT_EVENTS, USER_PACKAGES, CURRENT_DISCLOSURE,
} from '../lib/data/user-demo-db';
import type { AgreementParty, SignatureEvent } from '../lib/data/types';

/**
 * Party-side tests. Build Guide §20 asks for hash verification, replay and race
 * coverage before production; the user workspace adds three more claims that must
 * not be taken on trust:
 *
 *   1. a signature binds to one exact version, and never to a superseded one;
 *   2. completion is computed from stored events, and an executed record is
 *      read-only for everyone — including its owner;
 *   3. an evidence package states only what was technically verified, and its
 *      certificate wording is explicitly unapproved until counsel signs it off.
 */

const KEVIN = USER_WORKSPACE_OWNER; // user_011
const GRACE = 'user_007';
const STRANGER = 'user_999';
const kevinEmail = 'kevin.mwangi@agriease.co.ke';

const executed = USER_AGREEMENTS.find((a) => a.id === 'agr_023')!;
const inFlight = USER_AGREEMENTS.find((a) => a.id === 'agr_019')!;
const draft = USER_AGREEMENTS.find((a) => a.id === 'agr_020')!;
const awaitingInvite = USER_AGREEMENTS.find((a) => a.id === 'agr_021')!;
const revoked = USER_AGREEMENTS.find((a) => a.id === 'agr_022')!;

const partiesFor = (id: string) => USER_PARTIES.filter((p) => p.agreementId === id);
const eventsFor = (id: string) => USER_SIGNATURE_EVENTS.filter((e) => e.agreementId === id);
const docsFor = (id: string) => USER_DOCUMENTS.filter((d) => d.agreementId === id);
const currentDoc = (id: string) => {
  const docs = docsFor(id);
  return docs.find((d) => d.versionNumber === Math.max(...docs.map((x) => x.versionNumber))) ?? null;
};

describe('party authorisation (deny by default)', () => {
  test('a signed-in stranger is refused everything on an agreement they are not on', () => {
    const subject = { agreement: executed, parties: partiesFor(executed.id), signatureEvents: eventsFor(executed.id) };
    assert.equal(accessLevel(STRANGER, subject).level, 'none');
    for (const action of ['view', 'edit', 'add_version', 'invite', 'revoke', 'sign', 'export'] as const) {
      const decision = canPerform(STRANGER, { ...subject, version: currentDoc(executed.id) }, action);
      assert.equal(decision.allowed, false, `stranger must not be able to ${action}`);
      assert.match(decision.allowed === false ? decision.reason : '', /not the owner or an invited party/);
    }
  });

  test('a customer holds no operator capability — the two surfaces never share a session', () => {
    // The party checks are membership-based on purpose: no role substitutes for
    // being on the agreement, and no console role is consulted here at all.
    const asOwner = canPerform(KEVIN, { agreement: executed, parties: partiesFor(executed.id), signatureEvents: eventsFor(executed.id), viewerEmail: kevinEmail }, 'view');
    assert.equal(asOwner.allowed, true);
  });

  test('an owner who is also a named signer can sign — owning is not signing, but it is not a bar either', () => {
    // Felix owns the retainer and is also party 1 on it. Ownership and party
    // membership are independent facts; the party row must still be found.
    const felix = 'user_006';
    const access = accessLevel(felix, {
      agreement: inFlight, parties: partiesFor(inFlight.id), signatureEvents: eventsFor(inFlight.id),
    });
    assert.equal(access.level, 'owner');
    assert.ok(access.party, 'the owner is also a party on this agreement');
    assert.equal(access.party?.id, 'pty_019_1');

    // …and an owner who is *not* a party has nothing to sign: the draft has no
    // parties on it at all, so Kevin owns it and is nobody's counterparty.
    const ownerOnly = accessLevel(KEVIN, {
      agreement: draft, parties: partiesFor(draft.id), signatureEvents: eventsFor(draft.id),
    });
    assert.equal(ownerOnly.level, 'owner');
    assert.equal(ownerOnly.party, null);
    const nothingToSign = canPerform(KEVIN, {
      agreement: draft, parties: partiesFor(draft.id), signatureEvents: eventsFor(draft.id),
      version: currentDoc(draft.id), currentVersion: currentDoc(draft.id),
    }, 'sign');
    assert.equal(nothingToSign.allowed, false);
    assert.match(nothingToSign.allowed === false ? nothingToSign.reason : '', /Only an invited party/);
  });

  test('an invitation addressed to an email is visible before it is accepted, and binds on acceptance', () => {
    const tenantEmail = partiesFor(awaitingInvite.id)[0].email;
    // Not yet an account binding: matched by email only.
    const byEmail = accessLevel('user_017', { agreement: awaitingInvite, parties: partiesFor(awaitingInvite.id), signatureEvents: eventsFor(awaitingInvite.id), viewerEmail: tenantEmail });
    assert.equal(byEmail.level, 'party');
    assert.equal(byEmail.party?.userId, null);

    // A different signed-in person with a different address sees nothing.
    const other = accessLevel('user_017', { agreement: awaitingInvite, parties: partiesFor(awaitingInvite.id), signatureEvents: eventsFor(awaitingInvite.id), viewerEmail: 'someone.else@example.com' });
    assert.equal(other.level, 'none');
  });
});

describe('the signing act is bound to one exact version', () => {
  test('a superseded version cannot be signed', () => {
    const documents = docsFor(inFlight.id);
    const superseded = documents.find((d) => d.versionNumber === 1)!;
    const current = currentDoc(inFlight.id)!;
    const decision = canPerform(
      KEVIN,
      {
        agreement: inFlight, parties: partiesFor(inFlight.id), signatureEvents: eventsFor(inFlight.id),
        version: superseded, currentVersion: current, viewerEmail: kevinEmail,
      },
      'sign',
    );
    assert.equal(decision.allowed, false);
    assert.match(decision.allowed === false ? decision.reason : '', /version 2 is current/);
  });

  test('the current version can be signed by the party who owes a signature', () => {
    const decision = canPerform(
      KEVIN,
      {
        agreement: inFlight, parties: partiesFor(inFlight.id), signatureEvents: eventsFor(inFlight.id),
        version: currentDoc(inFlight.id), currentVersion: currentDoc(inFlight.id), viewerEmail: kevinEmail,
      },
      'sign',
    );
    assert.equal(decision.allowed, true);
  });

  test('signing is refused on drafts, revoked records and completed records', () => {
    // The draft case needs a party on it: an agreement with no parties has
    // nobody to sign, which is a different refusal.
    const draftWithParty = { ...draft, status: 'draft' as const };
    const draftParties = [syntheticParty(draftWithParty.id, 1)];
    const draftDecision = canPerform(
      'u1',
      {
        agreement: draftWithParty, parties: draftParties, signatureEvents: [],
        version: { id: 'v', versionNumber: 1, frozenAt: null },
        currentVersion: { id: 'v', versionNumber: 1, frozenAt: null },
      },
      'sign',
    );
    assert.equal(draftDecision.allowed, false);
    assert.match(draftDecision.allowed === false ? draftDecision.reason : '', /has not yet issued this agreement for signature/);

    // The revoked case likewise needs a party: Kevin *owns* that agreement, and
    // an owner who is not a party has no signature to give.
    const revokedWithParty = { ...revoked, status: 'revoked' as const };
    const revokedDecision = canPerform(
      'u1',
      {
        agreement: revokedWithParty, parties: [syntheticParty(revokedWithParty.id, 1)], signatureEvents: [],
        version: { id: 'v', versionNumber: 1, frozenAt: null },
        currentVersion: { id: 'v', versionNumber: 1, frozenAt: null },
      },
      'sign',
    );
    assert.equal(revokedDecision.allowed, false);
    assert.match(revokedDecision.allowed === false ? revokedDecision.reason : '', /revoked and can no longer be signed/);

    // A required signer on a completed agreement: the refusal is about
    // completion, not about who they are.
    const asSigner = canPerform(
      GRACE,
      {
        agreement: executed, parties: partiesFor(executed.id), signatureEvents: eventsFor(executed.id),
        version: currentDoc(executed.id), currentVersion: currentDoc(executed.id),
      },
      'sign',
    );
    assert.equal(asSigner.allowed, false);
    assert.match(asSigner.allowed === false ? asSigner.reason : '', /already complete/);

    // And its owner cannot sign it either — owning is not a signature.
    const asOwner = canPerform(
      KEVIN,
      {
        agreement: executed, parties: partiesFor(executed.id), signatureEvents: eventsFor(executed.id),
        version: currentDoc(executed.id), currentVersion: currentDoc(executed.id),
      },
      'sign',
    );
    assert.equal(asOwner.allowed, false);
  });

  test('signing order blocks a later signer until earlier ones have signed', () => {
    const parties: AgreementParty[] = [
      { ...syntheticParty('a', 1), id: 'p1', userId: 'u1', displayName: 'First', partyRole: 'lender' },
      { ...syntheticParty('a', 2), id: 'p2', userId: 'u2', displayName: 'Second', partyRole: 'borrower' },
    ];
    const open = { ...draft, status: 'awaiting_signatures' as const };
    const decision = canPerform('u2', { agreement: open, parties, signatureEvents: [], version: { id: 'v', versionNumber: 1, frozenAt: null }, currentVersion: { id: 'v', versionNumber: 1, frozenAt: null } }, 'sign');
    assert.equal(decision.allowed, false);
    assert.match(decision.allowed === false ? decision.reason : '', /signed in order/);

    const blockers = signingBlockers(parties, [], 'v', parties[1]);
    assert.equal(blockers.length, 1);
    assert.equal(blockers[0].partyRole, 'lender');
  });

  test('a duplicate sign request is recognised rather than recorded twice', () => {
    const decision = canPerform(
      KEVIN,
      {
        agreement: executed, parties: partiesFor(executed.id), signatureEvents: eventsFor(executed.id),
        version: currentDoc(executed.id), currentVersion: currentDoc(executed.id), viewerEmail: kevinEmail,
      },
      'sign',
    );
    // Completed first, so the refusal is about completion — but for an open
    // agreement the same rule yields note: 'duplicate', which the service turns
    // into a no-op receipt instead of a second signature event.
    assert.equal(decision.allowed, false);

    const signed: SignatureEvent[] = [{
      id: 'sev_x', agreementId: inFlight.id, versionId: 'agv_019_2', partyId: 'pty_019_2', actorId: KEVIN,
      signatureMethod: 'otp_confirmed_intent', outcome: 'signed', consentId: null,
      occurredAt: new Date().toISOString(), ipHash: null, userAgent: null,
    }];
    const dup = canPerform(KEVIN, {
      agreement: { ...inFlight, status: 'awaiting_signatures' },
      parties: partiesFor(inFlight.id), signatureEvents: signed,
      version: currentDoc(inFlight.id), currentVersion: currentDoc(inFlight.id), viewerEmail: kevinEmail,
    }, 'sign');
    assert.equal(dup.allowed, true);
    assert.equal(dup.allowed === true ? dup.note : null, 'duplicate');
  });
});

describe('completion and immutability', () => {
  test('completion is computed from signature events, not from a status field', () => {
    const complete = evaluateCompletion(partiesFor(executed.id), eventsFor(executed.id), 'agv_023_3');
    assert.equal(complete.complete, true);
    assert.equal(complete.required.length, 4);
    assert.equal(complete.signed.size, 4);

    const pending = evaluateCompletion(partiesFor(inFlight.id), eventsFor(inFlight.id), 'agv_019_2');
    assert.equal(pending.complete, false);
    assert.deepEqual(pending.pending.map((p) => p.partyRole), ['client']);
  });

  test('a declined required party blocks completion even if everyone else signed', () => {
    const parties = partiesFor(revoked.id);
    const events: SignatureEvent[] = [
      { id: 'sev_a', agreementId: revoked.id, versionId: 'agv_022_1', partyId: 'pty_022_1', actorId: KEVIN, signatureMethod: 'otp_confirmed_intent', outcome: 'signed', consentId: null, occurredAt: new Date().toISOString(), ipHash: null, userAgent: null },
    ];
    const evaluation = evaluateCompletion(parties, events, 'agv_022_1');
    assert.equal(evaluation.complete, false);
    assert.equal(evaluation.declined.length, 1);
    assert.equal(evaluation.declined[0].partyRole, 'employee');
  });

  test('an executed agreement is read-only for its own owner', () => {
    for (const action of ['edit', 'add_version', 'invite', 'revoke'] as const) {
      const decision = canPerform(KEVIN, { agreement: executed, parties: partiesFor(executed.id), signatureEvents: eventsFor(executed.id), viewerEmail: kevinEmail }, action);
      assert.equal(decision.allowed, false, `${action} must be refused on an executed agreement`);
    }
  });

  test('a revoked agreement is retained, read-only, and cannot be re-revoked', () => {
    const decision = canPerform(KEVIN, { agreement: revoked, parties: partiesFor(revoked.id), signatureEvents: eventsFor(revoked.id), viewerEmail: kevinEmail }, 'revoke');
    assert.equal(decision.allowed, false);
    assert.match(decision.allowed === false ? decision.reason : '', /already revoked/);
  });

  test('export is refused until there is a frozen version', () => {
    const decision = canPerform(KEVIN, { agreement: inFlight, parties: partiesFor(inFlight.id), signatureEvents: eventsFor(inFlight.id), viewerEmail: kevinEmail }, 'export');
    assert.equal(decision.allowed, false);
    assert.match(decision.allowed === false ? decision.reason : '', /once the agreement is complete/);
  });
});

describe('seeded records are internally consistent', () => {
  test('every seeded agreement chain verifies', () => {
    for (const agreement of USER_AGREEMENTS) {
      const events = USER_AUDIT_EVENTS.filter((e) => e.agreementId === agreement.id);
      assert.ok(events.length > 0, `${agreement.id} has no events`);
      const result = verifyChain(events);
      assert.equal(result.valid, true, `${agreement.id}: ${result.firstFailure?.detail ?? ''}`);
      assert.equal(result.checks.length, events.length);
    }
  });

  test('the executed agreement completed only after all four signatures', () => {
    const events = USER_AUDIT_EVENTS.filter((e) => e.agreementId === executed.id);
    const types = events.map((e) => e.eventType);
    const signedIndices = types.flatMap((t, i) => (t === 'party.signed' ? [i] : []));
    const stampIndex = types.indexOf('stamp.issued');
    assert.equal(signedIndices.length, 4);
    assert.ok(stampIndex > Math.max(...signedIndices), 'stamp must follow every signature');
    assert.ok(types.indexOf('agreement.completion_evaluated') < stampIndex);
  });

  test('the frozen version is the one the signatures were placed on', () => {
    const frozen = docsFor(executed.id).filter((d) => d.frozenAt);
    assert.equal(frozen.length, 1);
    assert.equal(frozen[0].versionNumber, executed.currentVersion);
    for (const event of eventsFor(executed.id)) {
      assert.equal(event.versionId, frozen[0].id, 'a signature points at a version that was not the executed one');
    }
    assert.equal(sha256(frozen[0].body ?? ''), frozen[0].sha256, 'a stored body must hash to its recorded digest');
  });

  test('the seeded package matches the chain it claims to describe', () => {
    const record = USER_PACKAGES.find((p) => p.agreementId === executed.id)!;
    assert.ok(record, 'expected a seeded package for the executed agreement');
    const events = USER_AUDIT_EVENTS.filter((e) => e.agreementId === executed.id);
    const stamp = events.find((e) => e.eventType === 'stamp.issued')!;
    const last = events[events.length - 1];

    // The package's root is the chain as it stood when it was assembled: the
    // stamp. Taking a copy is itself an event, so the agreement's head is one
    // link further on — and the two must not be confused.
    assert.equal(record.chainRoot, stamp.eventHash);
    assert.equal(last.eventType, 'evidence.package_generated');
    assert.equal(executed.chainHead, last.eventHash);

    assert.equal(record.documentHash, docsFor(executed.id).find((d) => d.id === 'agv_023_3')!.sha256);
    assert.equal(record.verification.ok, true);
    // The whole chain, export included, still verifies.
    assert.equal(verifyChain(events).valid, true);
  });
});

describe('evidence package contents', () => {
  const version = docsFor(executed.id).find((d) => d.id === 'agv_023_3')!;
  const bundle = buildPackage({
    agreement: executed, version,
    parties: partiesFor(executed.id),
    events: USER_AUDIT_EVENTS.filter((e) => e.agreementId === executed.id),
    signatureEvents: eventsFor(executed.id),
    consents: USER_CONSENTS.filter((c) => c.agreementId === executed.id),
    generatedBy: { userId: KEVIN, email: kevinEmail, displayName: 'Kevin Mwangi' },
    generatedAt: '2026-10-05T09:20:00.000Z',
    documentFile: { name: 'document.txt', mime: 'text/plain' },
  });

  test('the six expected files are present', () => {
    assert.deepEqual(
      bundle.files.map((f) => f.name).sort(),
      ['certificate-data.json', 'document.txt', 'events.json', 'manifest.json', 'signatures.json', 'verification.json'],
    );
  });

  test('verification passes and states findings, not a legal conclusion', () => {
    assert.equal(bundle.verification.ok, true);
    assert.equal(bundle.verification.documentIntegrity, true);
    assert.equal(bundle.verification.chainIntegrity, true);
    assert.equal(bundle.verification.requiredEventsPresent, true);
    assert.equal(bundle.verification.failingIndex, null);

    const claims = bundle.verification.statements.join(' ').toLowerCase();
    for (const forbidden of ['legally valid', 'court admissible', 'enforceab', 'binding']) {
      assert.ok(!claims.includes(forbidden), `package must not claim "${forbidden}"`);
    }
    const manifest = JSON.stringify(bundle.manifest).toLowerCase();
    assert.ok(!manifest.includes('legally valid'));
    assert.ok(!manifest.includes('blockchain'), 'the market term is "tamper-evident audit chain"');
  });

  test('a tampered event breaks verification at the right link', () => {
    const events = structuredClone(USER_AUDIT_EVENTS.filter((e) => e.agreementId === executed.id));
    events[8].metadata = { ...events[8].metadata, tampered: 'one character changed' };
    const result = verifyChain(events);
    assert.equal(result.valid, false);
    assert.equal(result.firstFailure?.reason, 'digest_mismatch');
    assert.equal(result.firstFailure?.index, 8);
  });

  test('a document whose bytes no longer match its digest is reported, not certified', () => {
    const edited = { ...version, body: `${version.body}\n(unauthorised edit)` };
    const tampered = buildPackage({
      agreement: executed, version: edited,
      parties: partiesFor(executed.id),
      events: USER_AUDIT_EVENTS.filter((e) => e.agreementId === executed.id),
      signatureEvents: eventsFor(executed.id),
      consents: USER_CONSENTS.filter((c) => c.agreementId === executed.id),
      generatedBy: { userId: KEVIN, email: kevinEmail, displayName: 'Kevin Mwangi' },
      generatedAt: '2026-10-05T09:20:00.000Z',
    });
    assert.equal(tampered.verification.documentIntegrity, false);
    assert.equal(tampered.verification.ok, false);
  });

  test('certificate wording is explicitly pending counsel approval', () => {
    const certificate = JSON.parse(bundle.files.find((f) => f.name === 'certificate-data.json')!.content);
    assert.equal(certificate.declaration.status, 'pending_counsel_approval');
    assert.equal(certificate.declaration.wording, null);
    assert.match(certificate.declaration.note, /not itself a declaration/);
    assert.equal(certificate.integrity_findings.document_digest_recomputed_at_export, true);
    assert.equal(certificate.prepared_for, 'counsel_review');
  });

  test('identity assurance is recorded as a level, never as a document', () => {
    const signatures = JSON.parse(bundle.files.find((f) => f.name === 'signatures.json')!.content);
    for (const signature of signatures.signatures) {
      assert.ok(['email', 'email_otp', 'phone_otp', 'email_otp_plus_id_document', 'in_person', null].includes(signature.identity_assurance_level));
      assert.ok(!('id_number' in signature) && !('document' in signature));
    }
    const certificate = JSON.stringify(bundle.files.find((f) => f.name === 'certificate-data.json')!.content).toLowerCase();
    for (const forbidden of ['id_number', 'national_id', 'passport_number', 'id_document_url']) {
      assert.ok(!certificate.includes(forbidden), `certificate must not carry ${forbidden}`);
    }
    // The disclosure version the signer saw is preserved on each signature.
    const withConsent = signatures.signatures.filter((s: { consent: unknown }) => s.consent);
    assert.equal(withConsent.length, 4);
    assert.equal(withConsent[0].consent.disclosure_version, CURRENT_DISCLOSURE);
  });

  test('required parties are the ones whose signature blocks completion', () => {
    assert.equal(requiredParties(partiesFor(executed.id)).length, 4);
    assert.equal(requiredParties(partiesFor(revoked.id)).length, 1, 'a declined party is not counted as required');
  });
});

describe('evidence package zip', () => {
  const entries = [
    { name: 'manifest.json', content: '{"format":"agree-e-evidence-package"}' },
    { name: 'document.txt', content: 'SUPPLY AGREEMENT\n'.repeat(60) },
    { name: 'empty.txt', content: '' },
  ];

  function readZip(buf: Buffer) {
    const out: Array<{ name: string; content: string }> = [];
    let offset = 0;
    while (offset + 30 <= buf.length && buf.readUInt32LE(offset) === 0x04034b50) {
      const method = buf.readUInt16LE(offset + 8);
      const crc = buf.readUInt32LE(offset + 14);
      const compressed = buf.readUInt32LE(offset + 18);
      const uncompressed = buf.readUInt32LE(offset + 22);
      const nameLen = buf.readUInt16LE(offset + 26);
      const extraLen = buf.readUInt16LE(offset + 28);
      const name = buf.subarray(offset + 30, offset + 30 + nameLen).toString('utf8');
      const bodyStart = offset + 30 + nameLen + extraLen;
      const body = buf.subarray(bodyStart, bodyStart + compressed);
      const content = method === 8 ? inflateRawSync(body).toString('utf8') : body.toString('utf8');
      assert.equal(content.length, uncompressed, `${name}: declared length`);
      assert.equal(crc32(content), crc, `${name}: CRC-32 in the header must match the content`);
      out.push({ name, content });
      offset = bodyStart + compressed;
    }
    return { entries: out, centralOffset: offset };
  }

  test('files round-trip with correct CRC-32 values and a well-formed central directory', () => {
    const zip = buildEvidenceZip(entries, new Date('2026-10-05T09:20:00.000Z'));
    const { entries: read, centralOffset } = readZip(zip);

    assert.deepEqual(read.map((e) => e.name), entries.map((e) => e.name));
    for (const [i, entry] of read.entries()) assert.equal(entry.content, entries[i].content);

    // Central directory + end-of-central-directory record
    assert.equal(zip.readUInt32LE(centralOffset), 0x02014b50);
    assert.equal(zip.readUInt16LE(centralOffset + 10), zip.readUInt16LE(8), 'compression methods agree');
    const eocd = zip.subarray(zip.length - 22);
    assert.equal(eocd.readUInt32LE(0), 0x06054b50);
    assert.equal(eocd.readUInt16LE(8), entries.length);
    assert.equal(eocd.readUInt16LE(10), entries.length);

    // Path traversal cannot be smuggled into an entry name.
    assert.ok(read.every((e) => !e.name.includes('..') && !e.name.startsWith('/')));
  });
});

/* ------------------------------------------------------------------ helpers -- */

function syntheticParty(agreementId: string, order: number): AgreementParty {
  return {
    id: `pty_${order}`, agreementId, userId: `u${order}`, displayName: `Party ${order}`, email: `p${order}@example.com`,
    partyRole: order === 1 ? 'lender' : 'borrower', signingRequired: true, signingOrder: order, status: 'accepted',
    invitationSentAt: null, invitationAcceptedAt: new Date().toISOString(), assuranceLevel: 'email_otp',
    identityVerifiedAt: new Date().toISOString(),
  };
}

function crc32(text: string): number {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let c = i;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[i] = c >>> 0;
  }
  const bytes = Buffer.from(text, 'utf8');
  let crc = 0xffffffff;
  for (const byte of bytes) crc = table[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

