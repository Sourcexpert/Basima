'use client';

import { useActionState } from 'react';
import { demoUserSignIn, userSignIn, type UserActionState } from '@/app/app/actions';

export function LoginForm({ demo }: { demo: boolean }) {
  const [state, formAction, pending] = useActionState<UserActionState | null, FormData>(
    demo ? demoUserSignIn : userSignIn,
    null,
  );

  return (
    <form action={formAction}>
      <div className="field">
        <label htmlFor="email">Email address</label>
        <input id="email" name="email" type="email" required autoComplete="email" placeholder="you@example.com" />
        <span className="hint">The address the invitation was sent to. Invitations cannot be transferred by forwarding a link.</span>
      </div>

      <div className="field">
        <label htmlFor="password">Password</label>
        <input id="password" name="password" type="password" required autoComplete="current-password" placeholder={demo ? 'agree-e-demo' : '••••••••••••'} />
        {demo && <span className="hint">Demo builds ship with the password <span className="mono">agree-e-demo</span>.</span>}
      </div>

      {state && !state.ok && <div className="callout danger"><strong>Not signed in.</strong> {state.error}</div>}

      <div className="btn-row" style={{ marginTop: 14 }}>
        <button type="submit" className="btn primary" disabled={pending}>
          {pending ? 'Signing in…' : 'Sign in'}
        </button>
      </div>

      <p className="tiny" style={{ marginTop: 12 }}>
        We do not use email links as a login mechanism: a link can be forwarded or intercepted, an authenticated session
        cannot. Resetting a forgotten password sends a single-use link that expires in 60 minutes.
      </p>
    </form>
  );
}
