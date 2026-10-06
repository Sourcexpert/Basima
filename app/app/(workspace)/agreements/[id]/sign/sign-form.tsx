'use client';

import { useActionState, useState } from 'react';
import Link from 'next/link';
import { runUserAction, type UserActionState } from '@/app/app/actions';
import { Badge, Hash, Table, when } from '@/components/ui';

/**
 * The signing transaction, as the signer experiences it.
 *
 * Steps are explicit and irreversible-by-design: review the exact version,
 * confirm identity with a one-time code, type your name, acknowledge the
 * disclosure, then sign. The server re-derives everything — this component is
 * convenience, never authority.
 */
export function SignForm({
  agreementId, versionId, versionNumber, documentHash, disclosureVersion, partyDisplayName, partyRole, remainingAfterYou,
}: {
  agreementId: string;
  versionId: string;
  versionNumber: number;
  documentHash: string;
  disclosureVersion: string;
  partyDisplayName: string;
  partyRole: string;
  remainingAfterYou: number;
}) {
  const [state, formAction, pending] = useActionState<UserActionState | null, FormData>(runUserAction, null);
  const [key] = useState(() => (typeof crypto !== 'undefined' && 'randomUUID' in crypto ? crypto.randomUUID() : `k_${Math.random()}`));
  const [step, setStep] = useState(1);
  const [name, setName] = useState('');
  const [otpSent, setOtpSent] = useState(false);
  const [otp, setOtp] = useState('');
  const [consent, setConsent] = useState(false);
  const [intent, setIntent] = useState(false);

  // Demo standing code. In production this is generated server-side, delivered
  // out-of-band (SMS/email), single-use and short-lived.
  const demoCode = '481902';
  const nameMatches = name.trim().toLowerCase() === partyDisplayName.trim().toLowerCase();
  const receipt = state?.ok ? (state.data as {
    signatureEventId: string; versionNumber: number; documentHash: string; signedAt: string;
    duplicate: boolean; completed: boolean; stampIssuedAt: string | null; packageId: string | null;
    chainHead: string | null; pending: Array<{ partyRole: string; displayName: string; signingOrder: number }>;
    statements: string[];
  }) : null;

  if (state?.ok && receipt) {
    return (
      <div className="card" style={{ marginTop: 16 }}>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
          <h2 style={{ margin: 0 }}>{receipt.duplicate ? 'Already signed' : 'Signed'}</h2>
          <Badge tone="ok">{receipt.duplicate ? 'no duplicate record created' : 'signature recorded'}</Badge>
          {receipt.completed && <Badge tone="accent">agreement complete</Badge>}
        </div>

        <div className="callout ok" style={{ marginTop: 12 }}>
          <ul style={{ margin: 0, paddingLeft: 18 }}>
            {receipt.statements.map((s, i) => <li key={i}>{s}</li>)}
          </ul>
        </div>

        <div className="section-title"><h3>Your signing record</h3></div>
        <Table head={['Field', 'Value']}>
          <tr><td className="tiny">Signature event</td><td className="tiny mono">{receipt.signatureEventId}</td></tr>
          <tr><td className="tiny">Agreement version</td><td className="tiny">v{receipt.versionNumber}</td></tr>
          <tr><td className="tiny">Document SHA-256</td><td className="tiny"><Hash value={receipt.documentHash} chars={44} /></td></tr>
          <tr><td className="tiny">Signed at</td><td className="tiny">{when(receipt.signedAt)}</td></tr>
          <tr><td className="tiny">Chain head after your event</td><td className="tiny"><Hash value={receipt.chainHead} chars={44} /></td></tr>
          <tr><td className="tiny">Disclosure version accepted</td><td className="tiny mono">{disclosureVersion}</td></tr>
          <tr><td className="tiny">Your party role</td><td className="tiny">{partyRole}</td></tr>
        </Table>

        {receipt.completed ? (
          <div className="callout ok" style={{ marginTop: 12 }}>
            <strong>Everything required is now in place.</strong> Version {receipt.versionNumber} has been frozen, the stamp was
            issued at {receipt.stampIssuedAt ? when(receipt.stampIssuedAt) : 'just now'}, and an evidence package has been generated.
            <div className="btn-row" style={{ marginTop: 10 }}>
              <Link className="btn sm primary" href={`/app/evidence?agreement=${agreementId}`}>Open the evidence package</Link>
              <a className="btn sm" href={`/api/evidence/${agreementId}`}>Download .zip</a>
            </div>
          </div>
        ) : (
          <div className="callout warn" style={{ marginTop: 12 }}>
            <strong>Not complete yet.</strong> Still awaiting:{' '}
            {receipt.pending.length > 0
              ? receipt.pending.map((p) => `${p.partyRole} (${p.displayName})`).join(', ')
              : 'no one — re-evaluating'}.
            The version is not frozen and no evidence package is issued until every required party has signed. You do not need to
            do anything further; you will see the record update when they sign.
          </div>
        )}

        <div className="btn-row" style={{ marginTop: 14 }}>
          <Link className="btn primary" href={`/app/agreements/${agreementId}`}>Back to the agreement</Link>
          <Link className="btn" href="/app/agreements">My agreements</Link>
        </div>
      </div>
    );
  }

  return (
    <div className="card" style={{ marginTop: 16 }}>
      <div className="card-head">
        <div>
          <h2>Sign version {versionNumber}</h2>
          <div className="tiny" style={{ marginTop: 3 }}>Three short steps. Nothing is recorded until you press sign at the end.</div>
        </div>
        <div className="spacer" />
        <span className="chip">Step {step} of 3</span>
      </div>

      <div className="bar" style={{ marginBottom: 16 }}><i style={{ width: `${(step / 3) * 100}%` }} /></div>

      <form action={formAction}>
        <input type="hidden" name="__action" value="sign" />
        <input type="hidden" name="idempotencyKey" value={key} />
        <input type="hidden" name="agreementId" value={agreementId} />
        <input type="hidden" name="versionId" value={versionId} />
        <input type="hidden" name="disclosureVersion" value={disclosureVersion} />
        <input type="hidden" name="confirmName" value={name} />
        <input type="hidden" name="otp" value={otp} />
        {consent && intent && <input type="hidden" name="confirmIntent" value="true" />}

        {step === 1 && (
          <>
            <h3>1. Confirm this is the version you intend to sign</h3>
            <p className="sub">
              The digest below is what your signature will be bound to. If it does not match the text above, stop and
              contact the other party.
            </p>
            <div className="scan">
              <div className="tiny">Version {versionNumber} · SHA-256</div>
              <div className="hash" style={{ marginTop: 4 }}>{documentHash}</div>
            </div>
            <div className="check" style={{ marginTop: 12 }}>
              <input
                type="checkbox"
                id="versionConfirmed"
                checked={consent}
                onChange={(e) => setConsent(e.target.checked)}
              />
              <label htmlFor="versionConfirmed">
                I have read version {versionNumber} in full and the digest shown here is the document I intend to sign.
              </label>
            </div>
            {!consent && <div className="tiny" style={{ marginTop: 8 }}>Tick the box to continue.</div>}
            <div className="btn-row" style={{ marginTop: 14, justifyContent: 'flex-end' }}>
              <button type="button" className="btn primary" disabled={!consent} onClick={() => setStep(2)}>Continue</button>
            </div>
          </>
        )}

        {step === 2 && (
          <>
            <h3>2. Confirm it is you</h3>
            <p className="sub">
              We send a one-time code before recording a signature, so a stolen session alone cannot sign. In production
              this arrives by SMS to your registered number; in this demonstration build the code is shown below.
            </p>

            {!otpSent ? (
              <button type="button" className="btn primary" onClick={() => setOtpSent(true)}>Send me a one-time code</button>
            ) : (
              <>
                <div className="callout accent">
                  <strong>Demo build:</strong> your code is <span className="mono" style={{ fontSize: 16 }}>{demoCode}</span>.
                  In production it would be delivered out-of-band, would expire in minutes, and would be single-use.
                </div>
                <div className="field">
                  <label htmlFor="otpInput">One-time code</label>
                  <input
                    id="otpInput" type="text" inputMode="numeric" maxLength={6} value={otp}
                    onChange={(e) => setOtp(e.target.value.replace(/[^0-9]/g, ''))} placeholder="6 digits"
                    style={{ maxWidth: 160, letterSpacing: '0.3em', fontSize: 18 }}
                  />
                  <span className="hint">Enter the code to confirm you are present at this device.</span>
                </div>
              </>
            )}

            <div className="btn-row" style={{ marginTop: 14, justifyContent: 'flex-end' }}>
              <button type="button" className="btn ghost" onClick={() => setStep(1)}>Back</button>
              <button
                type="button"
                className="btn primary"
                disabled={!otpSent || otp.length !== 6 || otp !== demoCode}
                onClick={() => setStep(3)}
              >
                Verify code
              </button>
            </div>
            {otpSent && otp.length === 6 && otp !== demoCode && (
              <div className="callout danger" style={{ marginTop: 10 }}>That code does not match. Check the value above.</div>
            )}
          </>
        )}

        {step === 3 && (
          <>
            <h3>3. Sign</h3>
            <p className="sub">
              Type your full name exactly as it appears on this agreement. This is the name that will be recorded next to
              your signature.
            </p>

            <div className="field">
              <label htmlFor="nameInput">Your full name as it should appear</label>
              <input
                id="nameInput" type="text" value={name} onChange={(e) => setName(e.target.value)}
                placeholder={partyDisplayName} autoComplete="name"
              />
              {name.length > 0 && !nameMatches && (
                <span className="hint" style={{ color: 'var(--warn)' }}>
                  This does not match the party record ({partyDisplayName}). Type it exactly, or ask the owner to correct
                  the party record first.
                </span>
              )}
              {nameMatches && <span className="hint" style={{ color: 'var(--ok)' }}>Matches the party record.</span>}
            </div>

            <div className="field">
              <label className="check">
                <input type="checkbox" checked={intent} onChange={(e) => setIntent(e.target.checked)} />
                <span>
                  I intend to sign this exact version ({versionNumber}) as <strong>{partyDisplayName}</strong>, in the role of{' '}
                  <strong>{partyRole}</strong>, and I understand that a record of this act — with a server timestamp, the
                  document digest and my consent — is appended to an evidence ledger that cannot be altered or deleted
                  afterwards, by me, by the other party or by agre-e.
                </span>
              </label>
            </div>

            <div className="callout warn">
              <strong>What this signature means — and does not.</strong> It evidences that you reviewed this version and
              confirmed your intention to be bound by it. It is not a claim by agre-e about your identity beyond the
              assurance level recorded, nor about the agreement&rsquo;s legal effect. If you are unsure of your obligations,
              take advice before signing.
              {remainingAfterYou > 0 && (
                <div style={{ marginTop: 6 }}>
                  After you sign, {remainingAfterYou} other required signature(s) still remain before the agreement is complete.
                </div>
              )}
            </div>

            <div className="btn-row" style={{ marginTop: 14, justifyContent: 'flex-end' }}>
              <button type="button" className="btn ghost" onClick={() => setStep(2)}>Back</button>
              <button
                type="submit"
                className="btn primary"
                disabled={pending || !nameMatches || !intent}
              >
                {pending ? 'Recording your signature…' : `Sign version ${versionNumber}`}
              </button>
            </div>
          </>
        )}

        {state && !state.ok && <div className="callout danger" style={{ marginTop: 12 }}><strong>Not recorded.</strong> {state.error}</div>}
      </form>
    </div>
  );
}
