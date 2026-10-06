'use client';

import { useActionState, useState } from 'react';
import { runUserAction, type UserActionState } from '@/app/app/actions';
import { ResultBanner } from '@/components/user-action-form';

const TYPES = [
  { value: 'loan', label: 'Loan' },
  { value: 'tenancy', label: 'Tenancy / lease' },
  { value: 'services', label: 'Services' },
  { value: 'supply', label: 'Supply of goods' },
  { value: 'sale', label: 'Sale of property or goods' },
  { value: 'employment', label: 'Employment' },
  { value: 'settlement', label: 'Settlement' },
  { value: 'distribution', label: 'Distribution / agency' },
  { value: 'corporate', label: 'Corporate (shareholders, founders)' },
  { value: 'other', label: 'Other' },
];

const TEMPLATE = `AGREEMENT

BETWEEN
  [Your full name or company name], of [address] (the "Party A"), and
  [Counterparty name], of [address] (the "Party B").

1. PURPOSE
1.1 [What is being agreed, in plain terms.]

2. TERM
2.1 This agreement takes effect on the date of the last signature and continues for [period].

3. PAYMENT
3.1 [Amount, currency, timing and method.]

4. OBLIGATIONS
4.1 Party A shall [obligations].
4.2 Party B shall [obligations].

5. CHANGES
5.1 No change to this agreement is effective unless recorded as a new version within agre-e and signed by both parties.

6. GOVERNING LAW
6.1 This agreement is governed by the laws of Kenya.

Executed by the parties whose signatures appear in the accompanying evidence record.`;

export function NewAgreementForm() {
  const [state, formAction, pending] = useActionState<UserActionState | null, FormData>(runUserAction, null);
  const [key] = useState(() => (typeof crypto !== 'undefined' && 'randomUUID' in crypto ? crypto.randomUUID() : `k_${Math.random()}`));
  const [text, setText] = useState(TEMPLATE);
  const bytes = new Blob([text]).size;

  const created = state?.ok ? (state.data as { agreementId?: string; ref?: string } | undefined) : undefined;

  return (
    <form action={formAction}>
      <input type="hidden" name="__action" value="create_agreement" />
      <input type="hidden" name="idempotencyKey" value={key} />

      <div className="field">
        <label htmlFor="title">Title</label>
        <input id="title" name="title" type="text" required placeholder="e.g. Supply agreement — irrigation fittings, 12 months" />
        <span className="hint">This is how the agreement appears in your list and in the evidence package. Make it recognisable a year from now.</span>
      </div>

      <div className="field">
        <label htmlFor="agreementType">Type</label>
        <select id="agreementType" name="agreementType" required defaultValue="services">
          {TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
        </select>
        <span className="hint">Used for organisation only. It does not change how the document is treated or which law applies.</span>
      </div>

      <div className="field">
        <label htmlFor="documentText">Document text</label>
        <textarea
          id="documentText"
          name="documentText"
          required
          value={text}
          onChange={(e) => setText(e.target.value)}
          style={{ minHeight: 380, fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', fontSize: 12.5 }}
        />
        <span className="hint">
          {bytes.toLocaleString()} bytes ·{' '}
          <button type="button" className="btn sm ghost" style={{ padding: '1px 6px' }} onClick={() => setText(TEMPLATE)}>
            reset to template
          </button>{' '}
          · <button type="button" className="btn sm ghost" style={{ padding: '1px 6px' }} onClick={() => setText('')}>clear</button>
        </span>
      </div>

      <ResultBanner state={state} successTitle="Draft created" />

      {created?.agreementId && (
        <div className="callout accent" style={{ marginTop: 12 }}>
          <strong>Next:</strong> invite the other party, then issue the agreement for signature. Guests reach the
          agreement through an invitation link tied to their email.
        </div>
      )}

      <div className="btn-row" style={{ marginTop: 12 }}>
        <button type="submit" className="btn primary" disabled={pending || text.trim().length < 40}>
          {pending ? 'Storing version 1…' : 'Create draft and hash version 1'}
        </button>
      </div>

      <p className="tiny" style={{ marginTop: 10 }}>
        By creating this draft you confirm you have the right to share this text with the parties you invite. Drafts are
        private to your account until you issue an invitation.
      </p>
    </form>
  );
}
