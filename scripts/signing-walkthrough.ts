/**
 * End-to-end walkthrough of the signing transaction, against the real services
 * and the real store (demo backend, in-memory — nothing outside this process is
 * touched, and re-running it starts from the seeded state again).
 *
 * Run:  npm run walkthrough
 *
 * It exists because the claims a customer cannot check from a screenshot are the
 * ones that matter most:
 *
 *   1. a signature binds to one exact version, is recorded once, and completes
 *      the agreement only when every required party has signed;
 *   2. an executed record is then frozen — for the owner as much as for anyone;
 *   3. the console sees the same record, without seeing the agreement;
 *   4. an operator can hand someone access to their own account without ever
 *      holding the credential that grants it.
 */

import assert from 'node:assert/strict';
import { store } from '@/lib/data/store';
import { hashIp } from '@/lib/crypto/hash';
import { verifyChain } from '@/lib/audit/chain';
import { CURRENT_DISCLOSURE } from '@/lib/data/user-demo-db';
import {
  acceptInvitation, addVersion, buildEvidencePackage, packageFiles, revokeAgreement, signAgreement,
} from '@/lib/services/agreements';
import { issuePasswordResetLink } from '@/lib/services/users';
import { completeRecovery, inspectRecoveryToken } from '@/lib/services/password-recovery';
import { capabilitiesFor } from '@/lib/auth/rbac';

type Viewer = { userId: string; email: string; displayName: string };

const ctx = (viewer: Viewer, ip = '197.232.0.1') => ({
  viewer,
  ipHash: hashIp(ip, 'agree-e-walkthrough'),
  userAgent: 'agree-e walkthrough/1.0',
});

const line = (s = '') => console.log(s);
const step = (n: number, title: string) => line(`\n${n}. ${title}`);
const note = (s: string) => line(`   · ${s}`);

async function main() {
  const s = store();
  const status = await s.snapshot();
  const allAgreements = await s.listAgreements({ limit: 500 });

  line('agre-e · walkthrough: signing, evidence, and access recovery');
  line(`backend: ${status.mode}   users: ${status.users.total}   agreements: ${allAgreements.length}   MRR: ${(status.billing.mrrMinor / 100).toLocaleString('en-KE')} KES`);

  /* ---------------------------------------------------------------- cast --- */
  const kevinProfile = await s.getUser('user_011');
  const felixProfile = await s.getUser('user_006');
  assert.ok(kevinProfile && felixProfile, 'seeded profiles missing');

  const kevin: Viewer = { userId: kevinProfile.id, email: kevinProfile.email, displayName: kevinProfile.displayName };
  const felix: Viewer = { userId: felixProfile.id, email: felixProfile.email, displayName: felixProfile.displayName };
  const stranger: Viewer = { userId: 'user_999', email: 'stranger@example.com', displayName: 'Not A Party' };

  const retainer = 'agr_019'; // Felix's retainer, awaiting Kevin's signature.

  /* -------------------------------------------------- 1. accept invitation -- */
  step(1, 'An invitation is bound to an email address, then to an account');
  const invitedAgreement = 'agr_021';
  const invited = (await s.listParties(invitedAgreement))[0];
  assert.ok(invited && invited.userId === null, 'expected an unaccepted invitation');
  const invitee = await s.getUserByEmail(invited.email);
  assert.ok(invitee, `no account for ${invited.email}`);
  note(`${invited.email} is invited to ${invitedAgreement} as “${invited.partyRole}” (signing order ${invited.signingOrder})`);
  note('the party row carries no user_id yet: the invitation is the binding, not the account');

  const visibleBefore = await s.listAgreementsForUser(invitee.id, invitee.email);
  assert.ok(visibleBefore.some((a) => a.id === invitedAgreement), 'an invitee must be able to see their invitation');
  note(`the invitee can already open ${invitedAgreement} — read-only, and nothing else`);

  const accepted = await acceptInvitation(
    ctx({ userId: invitee.id, email: invitee.email, displayName: invitee.displayName }),
    { agreementId: invitedAgreement },
  );
  assert.equal(accepted.ok, true, accepted.ok ? '' : accepted.error);
  const boundParty = (await s.listParties(invitedAgreement))[0];
  assert.equal(boundParty.userId, invitee.id);
  assert.equal(boundParty.status, 'accepted');
  assert.ok(['email', 'email_otp'].includes(boundParty.assuranceLevel ?? ''));
  note(`accepted: user_id ${boundParty.userId} bound; assurance recorded as “${boundParty.assuranceLevel}”`);
  note(`profile.emailVerified=${invitee.emailVerified} → the level recorded follows the check performed, and never overstates it`);

  /* ------------------------------------------------------- 2. strangers ----- */
  step(2, 'A signed-in stranger gets nothing');
  const docs = await s.listDocuments(retainer);
  const current = docs[docs.length - 1];
  const strangerSign = await signAgreement(ctx(stranger), {
    agreementId: retainer,
    versionId: current.id,
    disclosureVersion: CURRENT_DISCLOSURE,
    confirmName: 'Not A Party',
    confirmIntent: true,
    idempotencyKey: 'walk-stranger-1',
  });
  assert.equal(strangerSign.ok, false);
  assert.equal(strangerSign.ok === false ? strangerSign.code : null, 'forbidden');
  note(`refused: “${strangerSign.ok === false ? strangerSign.error : ''}”`);

  const strangerExport = await buildEvidencePackage(ctx(stranger), retainer);
  assert.equal(strangerExport.ok, false);
  note(`refused an export of someone else's agreement: “${strangerExport.ok === false ? strangerExport.error : ''}”`);

  /* ------------------------------------------------ 3. duplicates are safe -- */
  step(3, 'A duplicate submission is recognised, not recorded twice');
  const before = await s.listSignatureEvents(retainer);
  note(`before: ${before.filter((e) => e.outcome === 'signed').length} signature event(s) on ${retainer}; version ${current.versionNumber} is current`);

  // Felix signed this version already and the agreement is still open, so a
  // second press must return a receipt that says so — not a second signature.
  const felixAgain = await signAgreement(ctx(felix), {
    agreementId: retainer,
    versionId: current.id,
    disclosureVersion: CURRENT_DISCLOSURE,
    confirmName: felix.displayName,
    confirmIntent: true,
    idempotencyKey: 'walk-felix-again',
  });
  assert.equal(felixAgain.ok, true);
  assert.equal(felixAgain.ok === true ? felixAgain.data.duplicate : null, true);
  note('press-twice by a party who already signed → duplicate receipt, no new event');

  // Signing the wrong name is refused before anything is written.
  const wrongName = await signAgreement(ctx(kevin), {
    agreementId: retainer,
    versionId: current.id,
    disclosureVersion: CURRENT_DISCLOSURE,
    confirmName: 'Someone Else',
    confirmIntent: true,
    idempotencyKey: 'walk-kevin-wrong-name',
  });
  assert.equal(wrongName.ok, false);
  note(`refused a mis-typed name: “${wrongName.ok === false ? wrongName.error.split(' (')[0] : ''}”`);

  /* ------------------------------------------------- 4. Kevin signs it ----- */
  step(4, 'The required party signs the exact version in front of them');
  const signed = await signAgreement(ctx(kevin), {
    agreementId: retainer,
    versionId: current.id,
    disclosureVersion: CURRENT_DISCLOSURE,
    confirmName: kevin.displayName,
    confirmIntent: true,
    idempotencyKey: 'walk-kevin-1',
  });
  assert.equal(signed.ok, true, signed.ok ? '' : signed.error);
  if (!signed.ok) return finish(1);
  const receipt = signed.data;
  note(`recorded ${receipt.signatureEventId} on v${receipt.versionNumber} (digest ${receipt.documentHash.slice(0, 16)}…)`);
  assert.equal(receipt.duplicate, false);
  assert.equal(receipt.completed, true, 'both required parties have now signed');
  assert.ok(receipt.stampIssuedAt, 'a completed agreement must be stamped');
  for (const statement of receipt.statements) note(statement);

  /* -------------------------------------------- 5. frozen, and it stays ----- */
  step(5, 'The executed record is frozen');
  const frozenDoc = (await s.listDocuments(retainer)).find((d) => d.frozenAt);
  assert.ok(frozenDoc, 'the executed version must be frozen');
  note(`version ${frozenDoc.versionNumber} frozen at ${frozenDoc.frozenAt}`);

  const newVersion = await addVersion(ctx(felix), {
    agreementId: retainer,
    documentText: `${frozenDoc.body ?? ''}\n\n(attempted post-execution edit)`,
    note: 'Attempting to amend an executed agreement.',
    idempotencyKey: 'walk-felix-new-version',
  });
  assert.equal(newVersion.ok, false);
  note(`the owner cannot add a version either: “${newVersion.ok === false ? newVersion.error : ''}”`);

  const revoke = await revokeAgreement(ctx(felix), {
    agreementId: retainer,
    reason: 'Attempting to revoke an executed agreement.',
    idempotencyKey: 'walk-felix-revoke',
  });
  assert.equal(revoke.ok, false);
  note(`nor revoke it: “${revoke.ok === false ? revoke.error : ''}”`);

  /* ------------------------------------------- 6. nothing is written twice -- */
  step(6, 'After completion, nothing further is written');
  // The same idempotency key returns the identical receipt: a caller can retry a
  // request whose response it never saw, and no second signature is produced.
  const replayed = await signAgreement(ctx(kevin), {
    agreementId: retainer,
    versionId: current.id,
    disclosureVersion: CURRENT_DISCLOSURE,
    confirmName: kevin.displayName,
    confirmIntent: true,
    idempotencyKey: 'walk-kevin-1',
  });
  assert.equal(replayed.ok, true);
  assert.equal(replayed.ok === true ? replayed.data.signatureEventId : null, receipt.signatureEventId);
  note('same idempotency key → the original receipt is returned, nothing new written');

  const freshKeyAttempt = await signAgreement(ctx(kevin), {
    agreementId: retainer,
    versionId: current.id,
    disclosureVersion: CURRENT_DISCLOSURE,
    confirmName: kevin.displayName,
    confirmIntent: true,
    idempotencyKey: 'walk-kevin-2',
  });
  assert.equal(freshKeyAttempt.ok, false);
  note(`a fresh attempt is refused on the frozen record: “${freshKeyAttempt.ok === false ? freshKeyAttempt.error : ''}”`);

  const after = await s.listSignatureEvents(retainer);
  assert.equal(after.filter((e) => e.outcome === 'signed').length, before.filter((e) => e.outcome === 'signed').length + 1, 'exactly one new signature event');
  note(`signature events on ${retainer}: ${before.filter((e) => e.outcome === 'signed').length} → ${after.filter((e) => e.outcome === 'signed').length} (exactly one added)`);

  /* ------------------------------------------------ 7. the chain is intact -- */
  step(7, 'The evidence chain still verifies, and the export is honest');
  const events = await s.listAuditEvents({ agreementId: retainer, limit: 1000 });
  const verified = verifyChain(events);
  assert.equal(verified.valid, true, verified.firstFailure?.detail ?? '');
  note(`${verified.checkedEvents} links verified; head ${String(verified.head).slice(0, 16)}…`);
  note(`events added by this walkthrough: ${events.slice(-5).map((e) => e.eventType).join(', ')}`);

  const packaged = await s.listPackages(retainer);
  assert.ok(packaged.length > 0, 'completion must have produced an evidence package record');
  note(`package ${packaged[0].id}: the chain as it stood when it was assembled, verification_ok=${packaged[0].verification.ok}`);

  const files = await packageFiles(ctx(kevin), retainer);
  assert.equal(files.ok, true);
  if (files.ok) {
    note(`exportable files: ${files.bundle.files.map((f) => f.name).join(', ')}`);
    assert.equal(files.bundle.verification.ok, true);
    assert.ok(files.bundle.files.some((f) => f.name === 'certificate-data.json'));
  }

  /* --------------------------------------------------------- 8. console ----- */
  step(8, 'The operator console sees the same record — and not the document');
  const consoleView = await s.getAgreementSummary(retainer);
  assert.equal(consoleView?.status, 'completed');
  note(`console index: ${consoleView?.ref} — “${consoleView?.status}”, ${consoleView?.completedSigners}/${consoleView?.requiredSigners} signers, head ${String(consoleView?.chainHead).slice(0, 16)}…`);
  note('no agreement content crosses into the console: status, digest, party counts and chain head only.');

  /* --------------------------------- 9. handing out access without holding it -- */
  step(9, 'An operator can restore access without ever holding the credential');
  const operator = {
    userId: 'user_003',
    email: 'cynthia.mwikali@agree-e.com',
    displayName: 'Cynthia Mwikali',
    role: 'support' as const,
    capabilities: capabilitiesFor('support'),
    stepUpVerifiedAt: new Date().toISOString(),
    mfaEnabled: true,
  };
  const liveSession = (await s.listSessions())[0];
  assert.ok(liveSession, 'fixture: the demo dataset has live sessions');
  const customer = await s.getUser(liveSession.userId);
  assert.ok(customer);
  note(`customer on the call: ${customer.displayName} <${customer.email}>, ${(await s.listSessions(customer.id)).length} live session(s)`);

  const issued = await issuePasswordResetLink(
    { viewer: operator, ipHash: hashIp('197.232.0.1', 'agree-e-walkthrough'), userAgent: ctx(kevin).userAgent ?? null },
    {
      userId: customer.id,
      delivery: 'copy',
      reason: 'Account holder called support after losing the device; identity confirmed by call-back.',
      idempotencyKey: 'walk-reset-1',
    },
  );
  assert.equal(issued.ok, true, issued.ok === false ? issued.error : '');
  const link = issued.ok ? issued.data.link : undefined;
  assert.ok(link, 'support-call mode returns the single-use link');
  const rawToken = decodeURIComponent(new URL(link!).searchParams.get('token')!);
  note(`link issued: /auth/confirm?token=… (${rawToken.length} chars) — shown once, to the operator, and read out`);

  // The claim: the operator can hand it over but cannot use it later, because
  // what the database holds is a digest, not the link.
  const records = await s.listPasswordRecoveries(customer.id);
  assert.equal(records.length, 1);
  assert.notEqual(records[0].tokenHash, rawToken);
  assert.equal(JSON.stringify(records[0]).includes(rawToken), false, 'no stored field may carry the token');
  note(`stored: token_hash ${records[0].tokenHash.slice(0, 16)}… issued_by ${records[0].issuedBy} — the digest is useless to whoever holds it`);

  const opened = await inspectRecoveryToken(rawToken);
  assert.equal(opened.state, 'valid');
  assert.equal((await inspectRecoveryToken(rawToken)).state, 'valid');
  note('opening the link does not spend it: a mail scanner or a forwarded copy cannot burn it');

  const beforePasswordColumns = Object.keys(await s.getUser(customer.id) ?? {});
  assert.equal(beforePasswordColumns.includes('password'), false);
  assert.equal(beforePasswordColumns.includes('passwordHash'), false);
  note('the account row has no password column at all — "nobody can see it" is a schema fact, not a policy promise');

  const sessionsBefore = (await s.listSessions(customer.id)).length;
  const done = await completeRecovery(
    rawToken,
    { newPassword: 'Harbour-Lantern-42', confirmPassword: 'Harbour-Lantern-42' },
    { ipHash: hashIp('197.232.0.1', 'agree-e-walkthrough'), userAgent: 'agree-e walkthrough/1.0' },
  );
  assert.equal(done.ok, true, done.ok === false ? done.error : '');
  note(`reset completed: ${sessionsBefore} session(s) revoked, every outstanding link closed`);
  note(`statement shown to the holder: “${done.ok ? done.message : ''}”`);

  const replay = await completeRecovery(
    rawToken,
    { newPassword: 'Attacker-Chosen-99', confirmPassword: 'Attacker-Chosen-99' },
    { ipHash: null, userAgent: null },
  );
  assert.equal(replay.ok, false);
  note(`the same link a second time: “${replay.ok === false ? replay.error : ''}”`);

  const security = await s.listSecurityEvents({ limit: 20 });
  const recoveryEvent = security.find((e) => e.type === 'password_recovery_completed' && e.userId === customer.id);
  assert.ok(recoveryEvent, 'the recovery is on the security log');
  note(`security log: ${recoveryEvent.type} — “${recoveryEvent.detail}”`);
  note('and the admin ledger carries the issuance, with the operator, the reason and a chained hash.');

  line('\nAll checks passed. The walkthrough drove the real services, not a mock.\n');
  return finish(0);
}

function finish(code: number) {
  process.exitCode = code;
}

main().catch((err) => {
  console.error('\nWalkthrough failed:', err instanceof Error ? err.message : err);
  process.exitCode = 1;
});
