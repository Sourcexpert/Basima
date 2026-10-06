'use client';

import { useActionState, useState } from 'react';
import { demoSignIn, passwordSignIn, type ActionState } from '@/app/admin/actions';

interface Operator { id: string; name: string; email: string; role: string; mfa: boolean; status: string }

export function SignInForm({ mode, operators }: { mode: 'demo' | 'supabase'; operators: Operator[] }) {
  const action = mode === 'demo' ? demoSignIn : passwordSignIn;
  const [state, formAction, pending] = useActionState<ActionState | null, FormData>(action, null);
  const [selected, setSelected] = useState(operators[0]?.id ?? '');

  return (
    <div className="card">
      <h2>{mode === 'demo' ? 'Sign in (demo deployment)' : 'Sign in'}</h2>
      <div className="tiny" style={{ marginTop: 4, marginBottom: 14 }}>
        {mode === 'demo'
          ? 'No Supabase project is configured, so this deployment runs the console against the seeded dataset. Pick an operator to see how role-based capabilities change the console.'
          : 'Verified email required. Privileged roles must satisfy MFA before any console screen renders.'}
      </div>

      <form action={formAction}>
        {mode === 'demo' ? (
          <>
            <div className="field">
              <label htmlFor="userId">Operator account</label>
              <select id="userId" name="userId" value={selected} onChange={(e) => setSelected(e.target.value)}>
                {operators.map((o) => (
                  <option key={o.id} value={o.id}>
                    {o.name} — {o.role}{o.mfa ? ' · MFA on' : ' · MFA off'}
                  </option>
                ))}
              </select>
              <span className="hint">
                Sign in as <strong>Support</strong> and the billing controls disappear; sign in as <strong>Billing</strong> and the
                credential controls disappear. Sign in as <strong>Security</strong> and the privileged-access workflow becomes usable.
              </span>
            </div>
            <div className="field">
              <label htmlFor="password">Demo password</label>
              <input id="password" name="password" type="password" placeholder="agree-e-demo" required autoComplete="current-password" />
              <span className="hint">Seeded value: <span className="mono">agree-e-demo</span></span>
            </div>
          </>
        ) : (
          <>
            <div className="field">
              <label htmlFor="email">Work email</label>
              <input id="email" name="email" type="email" required autoComplete="username" />
            </div>
            <div className="field">
              <label htmlFor="password">Password</label>
              <input id="password" name="password" type="password" required autoComplete="current-password" />
            </div>
          </>
        )}

        {state && !state.ok && <div className="callout danger">{state.error}</div>}

        <button type="submit" className="btn primary" style={{ width: '100%', marginTop: 6 }} disabled={pending}>
          {pending ? 'Signing in…' : 'Sign in to console'}
        </button>
      </form>

      <div className="tiny" style={{ marginTop: 14, borderTop: '1px solid var(--line)', paddingTop: 12 }}>
        {mode === 'demo' ? (
          <>
            Sessions are absolute-limited to 12 hours and carried in a signed, httpOnly cookie. In production this
            form posts to Supabase Auth (verified email + MFA for privileged roles) and the role is read from
            <span className="mono"> profiles.role</span> server-side.
          </>
        ) : (
          <>Role comes from <span className="mono">profiles.role</span>. Every sign-in, success or failure, appends to the admin ledger.</>
        )}
      </div>
    </div>
  );
}
