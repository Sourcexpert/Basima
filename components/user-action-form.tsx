'use client';

import { useActionState, useState } from 'react';
import { runUserAction, type UserActionState } from '@/app/app/actions';
import type { ActionResult } from '@/lib/validation/schemas';

/**
 * Shared form control for the user workspace. Mirrors the console's ActionForm,
 * but the dialogs are written in the customer's language rather than an
 * operator's: what will happen, what will not, and what it does not prove.
 */
export interface UserField {
  name: string;
  label: string;
  type: 'text' | 'email' | 'number' | 'tel' | 'select' | 'textarea' | 'checkbox';
  required?: boolean;
  placeholder?: string;
  help?: string;
  options?: Array<{ value: string; label: string }>;
  defaultValue?: string | number | boolean;
  min?: number;
  max?: number;
  step?: string;
  rows?: number;
}

export interface UserActionSpec {
  action: string;
  title: string;
  intro?: React.ReactNode;
  fields?: UserField[];
  hidden?: Record<string, string>;
  acknowledgement?: string;
  confirmLabel?: string;
  intent?: 'primary' | 'default' | 'danger';
  disclaimer?: React.ReactNode;
}

export function UserActionButton({
  spec, label, variant = 'sm', disabled, disabledReason,
}: {
  spec: UserActionSpec;
  label: string;
  variant?: 'sm' | 'md' | 'primary' | 'danger';
  disabled?: boolean;
  disabledReason?: string;
}) {
  const [open, setOpen] = useState(false);
  const className = [' btn',
    variant === 'primary' ? 'primary' : variant === 'danger' ? 'danger' : '',
    variant === 'md' || variant === 'primary' || variant === 'danger' ? '' : 'sm',
  ].join('');

  return (
    <>
      <button type="button" className={className.trim()} onClick={() => setOpen(true)} disabled={disabled} title={disabled ? disabledReason : undefined}>
        {label}
      </button>
      {open && (
        <div
          style={{
            position: 'fixed', inset: 0, background: 'rgba(4,7,13,0.72)', backdropFilter: 'blur(3px)',
            display: 'grid', placeItems: 'center', zIndex: 60, padding: 16,
          }}
          onClick={(e) => { if (e.target === e.currentTarget) setOpen(false); }}
        >
          <div className="card" style={{ width: 'min(620px, 96vw)', maxHeight: '90vh', overflowY: 'auto' }}>
            <UserActionForm spec={spec} onClose={() => setOpen(false)} />
          </div>
        </div>
      )}
    </>
  );
}

function UserActionForm({ spec, onClose }: { spec: UserActionSpec; onClose: () => void }) {
  const [state, formAction, pending] = useActionState<UserActionState | null, FormData>(runUserAction, null);
  const [acked, setAcked] = useState(!spec.acknowledgement);
  const key = useKey();
  const done = state?.ok === true;

  return (
    <form action={formAction}>
      <div style={{ marginBottom: 12 }}>
        <h2>{spec.title}</h2>
        {spec.intro && <div className="sub" style={{ marginTop: 6 }}>{spec.intro}</div>}
      </div>

      <input type="hidden" name="__action" value={spec.action} />
      <input type="hidden" name="idempotencyKey" value={key} />
      {Object.entries(spec.hidden ?? {}).map(([k, v]) => <input key={k} type="hidden" name={k} value={v} />)}

      {(spec.fields ?? []).map((f) => (
        <div className="field" key={f.name}>
          {f.type === 'checkbox' ? (
            <label className="check">
              <input type="checkbox" name={f.name} defaultChecked={Boolean(f.defaultValue)} />
              <span>{f.label}{f.help && <span className="hint" style={{ display: 'block' }}>{f.help}</span>}</span>
            </label>
          ) : (
            <>
              <label htmlFor={f.name}>{f.label}{f.required && ' *'}</label>
              {f.type === 'select' ? (
                <select id={f.name} name={f.name} defaultValue={String(f.defaultValue ?? '')} required={f.required}>
                  {f.options?.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>
              ) : f.type === 'textarea' ? (
                <textarea
                  id={f.name} name={f.name} placeholder={f.placeholder} required={f.required}
                  defaultValue={String(f.defaultValue ?? '')} style={{ minHeight: f.rows ? f.rows * 22 : undefined }}
                />
              ) : (
                <input
                  id={f.name} name={f.name} type={f.type} placeholder={f.placeholder} required={f.required}
                  defaultValue={f.defaultValue === undefined ? undefined : String(f.defaultValue)}
                  min={f.min} max={f.max} step={f.step}
                />
              )}
              {f.help && <span className="hint">{f.help}</span>}
            </>
          )}
        </div>
      ))}

      {spec.acknowledgement && (
        <div className="field">
          <label className="check">
            <input type="checkbox" required checked={acked} onChange={(e) => setAcked(e.target.checked)} />
            <span>{spec.acknowledgement}</span>
          </label>
        </div>
      )}

      {state && !state.ok && <div className="callout danger"><strong>Not done.</strong> {state.error}</div>}
      {done && <div className="callout ok"><strong>Done.</strong> {state?.message}</div>}

      {spec.disclaimer && <div style={{ marginTop: 10 }}>{spec.disclaimer}</div>}

      <div className="btn-row" style={{ marginTop: 14, justifyContent: 'flex-end' }}>
        <button type="button" className="btn ghost" onClick={onClose}>{done ? 'Close' : 'Cancel'}</button>
        {!done && (
          <button type="submit" className={`btn ${spec.intent === 'danger' ? 'danger' : 'primary'}`} disabled={pending || (Boolean(spec.acknowledgement) && !acked)}>
            {pending ? 'Working…' : spec.confirmLabel ?? 'Confirm'}
          </button>
        )}
      </div>
    </form>
  );
}

function useKey(): string {
  const [key] = useState(() =>
    typeof crypto !== 'undefined' && 'randomUUID' in crypto ? crypto.randomUUID() : `key_${Math.random().toString(36).slice(2)}`,
  );
  return key;
}

/** Inline result banner used by the sign page and settings forms. */
export function ResultBanner({ state, successTitle = 'Done' }: { state: UserActionState | null; successTitle?: string }) {
  if (!state) return null;
  if (state.ok) return <div className="callout ok"><strong>{successTitle}.</strong> {state.message}</div>;
  return <div className="callout danger"><strong>Not done.</strong> {state.error}</div>;
}

export type { ActionResult };
