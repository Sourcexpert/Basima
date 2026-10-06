'use client';

import { useActionState, useEffect, useRef, useState } from 'react';
import { runAdminAction, stepUpAction, type ActionState } from '@/app/admin/actions';

/**
 * The console's single mutation surface.
 *
 * Every privileged control is one of these: a button that opens a dialog with
 * the action's inputs, a mandatory justification where policy requires one, and
 * an explicit confirmation for irreversible or high-risk operations. The result
 * (including a one-time break-glass credential) renders inline exactly once.
 */
export interface FieldSpec {
  name: string;
  label: string;
  type: 'text' | 'email' | 'number' | 'tel' | 'date' | 'select' | 'textarea' | 'checkbox' | 'hidden';
  required?: boolean;
  placeholder?: string;
  help?: string;
  options?: Array<{ value: string; label: string }>;
  defaultValue?: string | number | boolean;
  min?: number;
  max?: number;
  step?: string;
  span?: 1 | 2;
}

export interface ActionSpec {
  /** Dispatcher key — see runAdminAction(). */
  action: string;
  title: string;
  /** Rendered at the top of the dialog; use it to state exactly what will happen. */
  intro?: React.ReactNode;
  fields?: FieldSpec[];
  /** Hidden inputs that pin the target (userId, planId, …). */
  hidden?: Record<string, string>;
  reasonLabel?: string;
  reasonPlaceholder?: string;
  reasonRequired?: boolean;
  /** Acknowledge checkbox text for high-risk operations. */
  acknowledgement?: string;
  confirmLabel?: string;
  intent?: 'primary' | 'default' | 'danger';
  stepUpHint?: boolean;
}

const initialState: ActionState | null = null;

export function ActionButton({
  spec, label, size = 'sm', disabled, disabledReason, icon,
}: {
  spec: ActionSpec;
  label: string;
  size?: 'sm' | 'md';
  disabled?: boolean;
  disabledReason?: string;
  icon?: React.ReactNode;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [open, setOpen] = useState(false);

  return (
    <>
      <button
        type="button"
        className={`btn ${spec.intent === 'primary' ? 'primary' : spec.intent === 'danger' ? 'danger' : ''} ${size === 'sm' ? 'sm' : ''}`}
        onClick={() => { setOpen(true); dialog.current?.showModal(); }}
        disabled={disabled}
        title={disabled ? disabledReason : undefined}
      >
        {icon}{label}
      </button>
      {open && (
        <dialog ref={dialog} className="modal" onClose={() => setOpen(false)}>
          <ActionForm spec={spec} onClose={() => { dialog.current?.close(); setOpen(false); }} />
        </dialog>
      )}
    </>
  );
}

function ActionForm({ spec, onClose }: { spec: ActionSpec; onClose: () => void }) {
  const [state, formAction, pending] = useActionState(runAdminAction, initialState);
  const [acked, setAcked] = useState(!spec.acknowledgement);
  const keyRef = useRef<string>('');

  if (!keyRef.current) {
    keyRef.current = typeof crypto !== 'undefined' && 'randomUUID' in crypto
      ? crypto.randomUUID()
      : `key_${Math.random().toString(36).slice(2)}`;
  }

  // Re-generate the idempotency key after a completed attempt so a deliberate
  // second action is a new intent, while a double-submit is not.
  const [attempt, setAttempt] = useState(0);
  const shown = useRef<string>('');
  useEffect(() => {
    if (state && state.action !== shown.current) {
      shown.current = state.action ?? '';
    }
  }, [state]);

  const done = state?.ok === true;
  const credential = (state?.data as { temporaryPassword?: string } | undefined)?.temporaryPassword;
  const link = (state?.data as { link?: string } | undefined)?.link;

  return (
    <form
      action={formAction}
      onSubmit={() => { setAttempt((a) => a + 1); }}
      key={attempt}
    >
      <div className="modal-head">
        <h2>{spec.title}</h2>
        {spec.intro && <div className="sub" style={{ marginTop: 5 }}>{spec.intro}</div>}
      </div>

      <div className="modal-body">
        <input type="hidden" name="__action" value={spec.action} />
        <input type="hidden" name="idempotencyKey" value={keyRef.current} />
        {Object.entries(spec.hidden ?? {}).map(([k, v]) => <input key={k} type="hidden" name={k} value={v} />)}

        {spec.stepUpHint && (
          <div className="callout accent" style={{ marginBottom: 12 }}>
            <strong>Elevated action.</strong> A fresh step-up verification within the last 15 minutes is required.
            If yours has lapsed, re-authenticate from the top bar — the attempt is still recorded either way.
          </div>
        )}

        {(spec.fields ?? []).map((f) => {
          if (f.type === 'hidden') {
            return <input key={f.name} type="hidden" name={f.name} value={String(f.defaultValue ?? '')} />;
          }
          if (f.type === 'checkbox') {
            return (
              <div className="field" key={f.name} style={{ gridColumn: f.span === 2 ? '1 / -1' : undefined }}>
                <label className="check">
                  <input type="checkbox" name={f.name} defaultChecked={Boolean(f.defaultValue)} />
                  <span>{f.label}{f.help && <span className="hint" style={{ display: 'block' }}>{f.help}</span>}</span>
                </label>
              </div>
            );
          }
          return (
            <div className="field" key={f.name} style={{ gridColumn: f.span === 2 ? '1 / -1' : undefined }}>
              <label htmlFor={f.name}>{f.label}{f.required && ' *'}</label>
              {f.type === 'select' ? (
                <select id={f.name} name={f.name} defaultValue={String(f.defaultValue ?? '')} required={f.required}>
                  {f.options?.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>
              ) : f.type === 'textarea' ? (
                <textarea id={f.name} name={f.name} placeholder={f.placeholder} defaultValue={String(f.defaultValue ?? '')} required={f.required} />
              ) : (
                <input
                  id={f.name}
                  name={f.name}
                  type={f.type}
                  placeholder={f.placeholder}
                  defaultValue={f.defaultValue === undefined ? undefined : String(f.defaultValue)}
                  required={f.required}
                  min={f.min}
                  max={f.max}
                  step={f.step}
                />
              )}
              {f.help && <span className="hint">{f.help}</span>}
            </div>
          );
        })}

        <div className="field">
          <label htmlFor="reason">{spec.reasonLabel ?? 'Justification'} {spec.reasonRequired !== false && '*'}</label>
          <textarea
            id="reason"
            name="reason"
            required={spec.reasonRequired !== false}
            placeholder={spec.reasonPlaceholder ?? 'Why is this action necessary? This text is written to the append-only admin ledger.'}
          />
          <span className="hint">
            Recorded in the admin ledger with your identity, the target, your role, a timestamp and a chained hash.
            Write it for a reviewer who will read it months from now.
          </span>
        </div>

        {spec.acknowledgement && (
          <div className="field">
            <label className="check">
              <input type="checkbox" required checked={acked} onChange={(e) => setAcked(e.target.checked)} />
              <span>{spec.acknowledgement}</span>
            </label>
          </div>
        )}

        {state && !state.ok && (
          <div className="callout danger" style={{ marginTop: 4 }}>
            <strong>Refused.</strong> {state.error}
            {state.requiresStepUp && <div style={{ marginTop: 6 }}>Re-authenticate from the top bar, then run the action again.</div>}
          </div>
        )}

        {done && (
          <div className="callout ok" style={{ marginTop: 4 }}>
            <strong className="result-ok">Recorded.</strong> {state?.message}
            {link && (
              <div className="scan" style={{ marginTop: 9 }}>
                <div className="tiny">Single-use link — shown once, never stored:</div>
                <div className="hash" style={{ marginTop: 4 }}>{link}</div>
              </div>
            )}
            {credential && (
              <div className="scan" style={{ marginTop: 9 }}>
                <div className="tiny">One-time break-glass credential — shown once, never stored, must be changed at first sign-in:</div>
                <div className="mono" style={{ fontSize: 16, marginTop: 6, letterSpacing: '0.06em', color: 'var(--warn)' }}>{credential}</div>
              </div>
            )}
          </div>
        )}
      </div>

      <div className="modal-foot">
        <button type="button" className="btn ghost" onClick={onClose}>Close</button>
        <button
          type="submit"
          className={`btn ${spec.intent === 'danger' ? 'danger' : 'primary'}`}
          disabled={pending || (Boolean(spec.acknowledgement) && !acked)}
        >
          {pending ? 'Working…' : spec.confirmLabel ?? 'Confirm'}
        </button>
      </div>
    </form>
  );
}

/** Step-up re-authentication control for the top bar. */
export function StepUpControl({ fresh, expiresInMinutes, mode }: { fresh: boolean; expiresInMinutes: number; mode: string }) {
  const [state, formAction, pending] = useActionState(stepUpAction, initialState);
  const dialog = useRef<HTMLDialogElement>(null);
  const [open, setOpen] = useState(false);

  return (
    <>
      <button
        type="button"
        className={`btn sm ${fresh ? '' : 'primary'}`}
        onClick={() => { setOpen(true); dialog.current?.showModal(); }}
        title={fresh ? `Elevated session expires in about ${expiresInMinutes} minutes` : 'Sensitive actions require a fresh verification'}
      >
        {fresh ? `Elevated · ${expiresInMinutes}m` : 'Step-up required'}
      </button>
      {open && (
        <dialog ref={dialog} className="modal" onClose={() => setOpen(false)}>
          <form action={formAction}>
            <div className="modal-head">
              <h2>Re-authenticate</h2>
              <div className="sub" style={{ marginTop: 5 }}>
                Sensitive operations (break-glass credentials, role changes, session revocation, refunds, privileged
                agreement access) require a fresh verification. Losing and regaining your session is not enough.
              </div>
            </div>
            <div className="modal-body">
              <div className="field">
                <label htmlFor="password">{mode === 'demo' ? 'Demo password' : 'Your account password'}</label>
                <input id="password" name="password" type="password" autoComplete="current-password" required />
                <span className="hint">
                  {mode === 'demo'
                    ? 'Demo deployment: the seeded password is agree-e-demo. In production this step is your real credential plus a TOTP challenge.'
                    : 'In production this step is accompanied by a TOTP challenge; the elevated window is 15 minutes.'}
                </span>
              </div>
              {state && !state.ok && <div className="callout danger">{state.error}</div>}
              {state?.ok && <div className="callout ok">{state.message}</div>}
            </div>
            <div className="modal-foot">
              <button type="button" className="btn ghost" onClick={() => { dialog.current?.close(); setOpen(false); }}>Close</button>
              <button type="submit" className="btn primary" disabled={pending}>{pending ? 'Verifying…' : 'Verify'}</button>
            </div>
          </form>
        </dialog>
      )}
    </>
  );
}

/** Small copy-to-clipboard affordance used for hashes and lockout links. */
export function CopyButton({ value, label = 'Copy' }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className="btn sm ghost"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setCopied(true);
          setTimeout(() => setCopied(false), 1600);
        } catch { /* clipboard blocked */ }
      }}
    >
      {copied ? 'Copied' : label}
    </button>
  );
}

/** Filter bar that writes to the URL so filters are shareable and auditable. */
export function FilterBar({ basePath, filters, values }: {
  basePath: string;
  filters: Array<{ name: string; label: string; type: 'text' | 'select'; options?: Array<{ value: string; label: string }>; placeholder?: string }>;
  values: Record<string, string | undefined>;
}) {
  return (
    <form className="searchbar" method="get" action={basePath}>
      {filters.map((f) => (
        <span key={f.name} style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
          <label className="tiny" htmlFor={f.name}>{f.label}</label>
          {f.type === 'select' ? (
            <select id={f.name} name={f.name} defaultValue={values[f.name] ?? ''}>
              <option value="">All</option>
              {f.options?.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          ) : (
            <input id={f.name} name={f.name} type="text" placeholder={f.placeholder} defaultValue={values[f.name] ?? ''} />
          )}
        </span>
      ))}
      <button type="submit" className="btn sm">Apply</button>
      <a className="btn sm ghost" href={basePath}>Reset</a>
    </form>
  );
}
