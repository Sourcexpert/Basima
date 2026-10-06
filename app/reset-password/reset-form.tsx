'use client';

import Link from 'next/link';
import { useActionState, useState } from 'react';
import { completeRecoveryAction, type ResetState } from './actions';

/**
 * The reset form.
 *
 * There is no "current password" field, because the person filling this in does
 * not have one — that is the whole situation. The token rides in a hidden field
 * so it is posted, never printed, and disappears from the URL on submit.
 */
export function ResetForm({ token, email }: { token: string; email: string }) {
  const [state, formAction, pending] = useActionState<ResetState | null, FormData>(completeRecoveryAction, null);
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');

  if (state?.ok) {
    return (
      <>
        <div className="callout ok">
          <strong>Done.</strong> {state.message}
        </div>
        <div className="callout" style={{ marginTop: 12 }}>
          <strong>What was recorded.</strong> The link was spent (it now fails for everyone, including you), every other
          session on the account was signed out, and an event was written to the security log with the reason and the
          operator who issued the link. Nobody — operator, support agent or engineer — ever saw or set the password
          itself.
        </div>
        <div className="btn-row" style={{ marginTop: 14 }}>
          <Link className="btn primary" href="/app/login">Go to sign-in</Link>
        </div>
      </>
    );
  }

  const mismatch = confirm.length > 0 && password !== confirm;
  const policy = passwordPolicyNote(password);

  return (
    <form action={formAction}>
      <input type="hidden" name="token" value={token} />

      <p className="sub" style={{ marginTop: 0 }}>
        Setting a new password for <span className="mono">{email}</span>.
      </p>

      <div className="field">
        <label htmlFor="newPassword">New password *</label>
        <input
          id="newPassword" name="newPassword" type="password" required minLength={12}
          autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)}
        />
        <span className="hint">
          At least 12 characters, mixing upper case, lower case and numbers. Length beats symbolism — three unrelated
          words are stronger than one clever substitution.
        </span>
        {policy && <span className="hint" style={{ color: 'var(--warn, #d9a300)' }}>{policy}</span>}
      </div>

      <div className="field">
        <label htmlFor="confirmPassword">Repeat new password *</label>
        <input
          id="confirmPassword" name="confirmPassword" type="password" required minLength={12}
          autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)}
        />
        {mismatch && <span className="hint" style={{ color: 'var(--danger, #e5484d)' }}>The two entries do not match yet.</span>}
      </div>

      {state && !state.ok && <div className="callout danger"><strong>Not done.</strong> {state.error}</div>}

      <div className="btn-row" style={{ marginTop: 14, justifyContent: 'flex-end' }}>
        <Link className="btn ghost" href="/app/login">Cancel</Link>
        <button type="submit" className="btn primary" disabled={pending || mismatch || policy !== null || password.length === 0}>
          {pending ? 'Saving…' : 'Set new password and sign out everywhere'}
        </button>
      </div>
    </form>
  );
}

/** Same rule the server enforces, so the hint cannot drift from the validation. */
function passwordPolicyNote(password: string): string | null {
  if (password.length === 0) return null;
  if (password.length < 12) return `${12 - password.length} more character(s) needed.`;
  if (!/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/[0-9]/.test(password)) {
    return 'Add an upper-case letter, a lower-case letter and a number.';
  }
  return null;
}
