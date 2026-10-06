# agre-e · the product

An evidence-first private agreements platform, built as real Next.js 15 + Supabase
code rather than a mock-up, from the *Architecture & Security Build Guide*
(October 2026). Two surfaces, one record:

| Surface | Route root | Who it is for |
|---|---|---|
| **Operator console** | `/admin/*` | Support, billing, security and owner staff managing accounts, credentials, subscriptions, pricing and audit |
| **User workspace** | `/app/*` | The parties themselves: create drafts, invite counterparties, sign exact versions, pull evidence packages, manage their own data rights |

They share one dataset and **never share authority**. A signed-in customer holds no
operator capability; an operator role grants no access to any contract (§5).

---

## 1. What is here

### Operator console

| Area | Screen | What it does |
|---|---|---|
| Overview | `/admin` | Posture: users, MRR, collection, chain integrity, live alerts |
| Users & access | `/admin/users`, `/admin/users/[id]` | Credentials, sessions, roles, MFA, lock/suspend, break-glass |
| Subscriptions | `/admin/billing` | Book of business, plan changes, cancels, pauses, dunning sweep |
| Plans & pricing | `/admin/billing/plans` | Catalogue CRUD with grandfathering, archive-not-delete |
| Payments & invoices | `/admin/billing/payments` | M-PESA STK collection, Flutterwave checkout, reconciliation, refunds |
| Coupons & dunning | `/admin/billing/coupons` | Discount instruments, arrears ladder, sweep history |
| Audit & evidence | `/admin/audit` | Evidence ledgers, chain verification, admin ledger, agreement index |
| Security events | `/admin/security` | Incident register, privileged-access record, break-glass register |
| Roles & policy | `/admin/settings` | Full capability matrix, elevated-action policy, runtime config |

### User workspace

| Area | Screen | What it does |
|---|---|---|
| Home | `/app` | What needs you now, integrity of your own chains, plain-language limits |
| Agreements | `/app/agreements`, `/app/agreements/new` | List and filter by status; write a draft, hash it as version 1 |
| Agreement | `/app/agreements/[id]` | Document, parties and signing order, evidence timeline, version history, integrity report |
| Signing | `/app/agreements/[id]/sign` | Three-step signing: confirm the exact version, one-time code, typed name + intent, receipt |
| Evidence | `/app/evidence` | Packages, the six-file contents, how to check one yourself in three commands |
| Verify a chain | `/app/verify` | **Browser-side** verification: paste or load a chain, tamper with an event, watch it fail at that link |
| Billing | `/app/billing` | Plan, invoices, M-PESA payment, attempt history, the published arrears ladder |
| Settings & privacy | `/app/settings` | Password change, MFA, data-protection requests, consents, what we hold and what we do not |
| Recovery | `/reset-password` (+ `/auth/confirm`) | The other half of a password reset: a single-use link the holder spends themselves — sign-in is not required, because the point is that they cannot sign in |

### Supporting code

```
lib/auth/rbac.ts             console capability model + authorize() (deny by default)
lib/auth/user-access.ts      party model: membership, signing order, completion, read-only rules
lib/auth/user-auth.ts        customer session (separate cookie, separate trust boundary)
lib/auth/session-revoke.ts   terminating sessions, shared by the console and self-service reset
lib/audit/chain.ts           evidence chain: canonical payload, hashing, verification
lib/audit/admin-chain.ts     the separate append-only operator ledger
lib/crypto/hash.ts           SHA-256, deterministic canonical JSON, timing-safe compare
lib/evidence/package.ts      assembles the §12–14 package file set
lib/evidence/offline-verify.ts  verifies an exported package without any server
lib/evidence/zip.ts          dependency-free ZIP writer (store + deflate, own CRC-32)
lib/payments/mpesa.ts        Daraja: OAuth, STK push, status query, callback handling
lib/payments/mpesa-format.ts pure formatting/parsing (unit-tested)
lib/payments/flutterwave.ts  checkout, four-check verification, webhook signature, refunds
lib/services/users.ts        credential/session/MFA/role/suspension operations
lib/services/billing.ts      plans, subscription lifecycle, collection, dunning
lib/services/agreements.ts   the agreement lifecycle incl. the signing transaction
lib/services/user-billing.ts customer-initiated payments (never console-gated)
lib/services/password-recovery.ts  single-use recovery tokens: issue, inspect, spend
scripts/signing-walkthrough.ts  drives the real product paths end to end (9 steps, incl. recovery)
lib/data/store.ts            one interface; Supabase backend or seeded demo backend
lib/data/user-store.ts       the workspace's reads, RLS-bound when Supabase is configured
app/api/chain/[id]           chain export for the in-browser verifier
app/api/evidence/[id]        evidence package download (logged as an event)
app/api/webhooks/*           M-PESA callback + Flutterwave webhook, with rejection paths
supabase/migrations/0001     evidence core: agreements, versions, audit ledger, RLS
supabase/migrations/0002     admin console: commercial tables, admin ledger, RLS
supabase/migrations/0003     user workspace: packages, data rights, signing RPCs, RLS
supabase/migrations/0004     password recovery: single-use tokens, consume RPC, RLS
tests/                       84 tests: chains, governance, parties, packages, M-PESA, ZIP,
                             and the console's own write path (credentials + billing)
```

---

## 2. Run it

```bash
npm install
cp .env.example .env.local     # optional: leave Supabase blank to use demo data
npm run dev                    # http://localhost:3000
```

**Two honest modes, no third.**

- **Demo mode** (no Supabase credentials): both surfaces run against one seeded,
  fully mutable dataset — 24 accounts, 7 plans, 16 subscriptions, invoices, M-PESA
  and Flutterwave payments, an executed supply agreement with four signatures and a
  real evidence package, a retainer awaiting one signature, a draft, a tenancy
  waiting on an unaccepted invitation, a revoked employment contract, two verifiable
  console chains and one **deliberately tampered chain**. Every screen carries a
  `DEMO DATA` badge.
  - Console: any operator, password `agree-e-demo`.
  - Workspace: any listed customer account, password `agree-e-demo`.
  *Try it:* sign in to the console as **Cynthia (Support)** — billing and refund
  controls vanish; as **Esther (Billing)** — credential controls vanish; as
  **Daniel (Security)** — privileged agreement access appears. Then sign in to
  `/app` as **Kevin Mwangi** (owner and required signer on the retainer) and sign
  it: the console's evidence view reflects it immediately, because it is one record.
- **Supabase mode**: set the three Supabase variables and the app switches backend,
  enforces MFA for privileged roles, and reads roles from `profiles.role`. A
  production build with *no* credentials refuses to start rather than silently
  running on demo data.
- Optional walkthrough helpers (refused when Supabase is configured):
  `AGREE_E_AUTOLOGIN=amina.wanjiru@agree-e.com` for a console session,
  `AGREE_E_USER_AUTOLOGIN=user_011` for a workspace session.

```bash
npm run build && npm start     # production
npm test                       # 84 tests
npm run typecheck
npm run walkthrough            # drive the real paths: signing, evidence, recovery
```

### Seeing it run

```bash
npm run walkthrough
```

Nine steps against the real services and the seeded demo store (in memory, in its own
process), printing what happened at each one: an invitation bound to an email and
then to an account; a stranger refused a signature *and* an export; a duplicate
submission recognised instead of re-recorded; a mis-typed name refused; the signing
transaction completing the agreement, freezing the version, stamping it and
generating the package; the owner then unable to amend or revoke it; the chain still
verifying afterwards; the console reading the same record — status, digest, party
counts and chain head, no document; and finally an operator handing a locked-out
customer a recovery link, then being unable to use it themselves: the stored digest
is shown, the same link is shown failing on its second use, and the security event it
wrote is printed.

`npm test` covers the same ground where it can be asserted: the party-side rules, the
chains, the payment rails — and, in `tests/console-writes.test.ts`, the console's
*write* path, driven with seeded operators so that every permission boundary is
stated twice (as an allowed action and as a refusal).

### Database

Apply all three migrations to a fresh Supabase project (SQL editor, or
`supabase db push`). 0001 creates the evidence core with RLS, append-only triggers
and the database-side chain functions (`append_audit_event`, `verify_audit_chain`);
0002 adds the commercial tables, the admin ledger and `admin_agreement_index`
(metadata only); 0003 adds evidence packages, data-subject requests, the invitation
predicates, and the RPCs that make the signing act safe — `accept_invitation()`,
`record_signature_event()` (advisory lock, version/party/order re-derivation,
freeze + stamp on completion) and `record_evidence_package()`; 0004 adds
`password_recovery_requests` (digests only, RLS on with **no** policies, reachable
solely through `consume_recovery_token()` and the service role) — the table that lets
a recovery link be spent exactly once instead of being a promise in a UI.

**One seam to be explicit about.** In Supabase mode the *reads* of the user
workspace run through the authenticated client (`lib/data/user-store.ts`), so RLS
binds. The *writes* currently go through the service-role client from the
TypeScript service layer, where authorization is checked in code and every step is
an explicit, reviewed call. The equivalent SQL RPCs exist (0003) and are the
intended production path — hashing, stamping and completion decisions happening
inside Postgres in one transaction. Until that switch is made, RLS is defence in
depth rather than the sole boundary, and `lib/data/user-store.ts` says so in the
file rather than in a plan nobody reads.

---

## 3. Password management: the decision

**No administrator, in any role, can read or set another person's password.** The
console offers six operations and nothing else:

| Operation | Control | Why |
|---|---|---|
| Send recovery link | justification | Single-use, expiring, issued by Supabase; emailed or shown once for a support call |
| Force reset at next sign-in | justification | Flags the account; optionally revokes sessions and requires MFA |
| Revoke sessions | step-up + justification | Kills refresh tokens; the UI states plainly that live access tokens survive until expiry |
| Require MFA | justification | Policy-bound for owner/admin/support/security/billing |
| Lock / unlock | justification | Immediate, reversible; unlock never lifts a deliberate suspension |
| Break-glass credential | step-up + **second approver** + acknowledgement + reason | Time-boxed (5–120 min), single-use, forces a change at first sign-in |

The reasoning is product-critical, not stylistic: an evidence product cannot let an
operator assume a user's identity, or every signature on every agreement becomes
arguable. Enforced by omission — there is no capability to grant.

**The loop is closed on the customer's side, not just the console's.** A link minted
by *Send recovery link* is stored as a SHA-256 digest, so the operator who hands it
over cannot use it later, and neither can anyone who reads the database. Only the raw
token — in the link, in the holder's browser — can spend it. The rules are enforced in
`lib/services/password-recovery.ts` and, on a live Supabase project, by
`consume_recovery_token()` in migration 0004:

- opening the link does not spend it (a mail scanner or a forwarded copy cannot burn
  someone's reset), only submitting the form does;
- a token expires in 60 minutes and works once; completing *any* reset closes every
  other outstanding link for that account;
- a successful reset revokes every session — a password change that leaves an
  attacker's session alive has protected nothing;
- an operator-applied lock or suspension is honoured: a recovery link is not a way
  around a decision someone made deliberately;
- the failure the holder sees names what actually happened (expired / already used /
  account locked), because "invalid link" is the least useful thing to tell someone
  who is locked out;
- the completion is written to the security log with the operator who issued the link
  named, and the issuance is in the admin ledger with its reason and chained hash.

---

## 4. Security properties worth reviewing

1. **Deny by default.** Every privileged mutation goes through one dispatcher
   (`app/admin/actions.ts`) calling `authorize()`; every party-side action goes
   through `app/app/actions.ts` and then a service that re-derives membership from
   stored rows. Refusals are recorded — console refusals in the admin ledger with
   status `blocked`, an attempt to sign a superseded version on the agreement's own
   evidence chain.
2. **Admin status ≠ contract-reading rights** (guide §5). The only path to agreement
   data is `agreements.content.read.privileged`, held by `security` alone, gated on
   step-up and a written reason, returning the *index and metadata* — not document
   bytes. Support staff cannot read your agreement, which is why the workspace tells
   customers that support will ask them to read something out rather than quoting it.
3. **Two append-only ledgers, never merged.** Operational actions cannot be made to
   look like part of an agreement's evidentiary history. Both chains are hashed
   server-side; `BEFORE UPDATE/DELETE` triggers raise, so no code path can rewrite
   history.
4. **An owner is a party only if they are named as one.** Ownership and party
   membership are independent: an owner who is also a signer signs normally, and an
   owner who is not named has nothing to sign. Owning is not signing.
5. **A signature binds to one exact version.** The version id, the document digest,
   the party's authority and the completion state are all re-derived server-side at
   the moment of signing. Signing a superseded version is refused; a duplicate
   submission returns a "already recorded" receipt instead of a second event; a new
   version expires the outstanding requests rather than silently re-pointing them.
6. **Completion is computed, never asserted.** It is evaluated from stored signature
   events against the parties required for that version; a declined required party
   blocks it. On completion the version is frozen, stamped, and a package generated —
   and from that moment the record is read-only for everyone, including its owner.
7. **Canonical hashing, implemented twice and tested.** `canonical_event_payload`
   (SQL) and `canonicalEventPayload` (TypeScript) must agree; the verifier detects
   tampering at the correct event, including the "re-hash the forged event" attack.
   The browser verifier reimplements the same recipe so a customer can check a chain
   without trusting the server that served it.
8. **Conservative payment settlement.** M-PESA callbacks are rejected without the
   URL token, and a `CheckoutRequestID` we never issued is quarantined. Flutterwave
   webhooks require `verif-hash`; settlement re-queries the provider and demands
   status, amount, currency **and** `tx_ref` to match. Customer-initiated payments
   never fabricate settlement either: an approved prompt that times out is not a
   payment.
9. **Payment state is separate from evidentiary truth.** Nothing in billing can
   delete or amend an agreement, stamp, package or audit event. Arrears gate new
   value-producing actions only; read, sign and export always survive.
10. **Privacy by construction.** IP addresses are stored only as keyed digests. We
   record *that* identity was verified and at what level — never a copy of a
   document. Data-subject requests are filed by the user, answered in writing, and
   the code states plainly what a deletion request cannot reach.
12. **A green build is not evidence that a surface works.** Writing
    `tests/console-writes.test.ts` — the first test ever to *call* an operator action
    rather than inspect its inputs — found that every console credential and billing
    action was dead in demo mode: the schemas demanded a uuid while the seeded dataset
    uses readable ids (`user_020`, `plan_practice_m`), so "Send reset link" answered
    `Invalid uuid`. Types were clean, `tsc` was clean, the pages rendered and the
    suite was green — because nothing had ever pressed the button. The fix is
    `recordIdSchema` (uuids *or* seeded ids; the format is not an authorization
    control, authorization happens against the loaded row) plus a test that drives
    each action twice: once to see it succeed, once to see it refused for a role that
    should not hold it.
13. **Secret hygiene and headers.** The service-role key lives in server-only
    modules, never prefixed `NEXT_PUBLIC_`. `next.config.ts` sets HSTS, a strict CSP,
    `frame-ancestors 'none'`, `nosniff`, and `no-store` on console and API routes.

---

## 5. Payment rails

**M-PESA Daraja** (verified against the published contract): OAuth
`client_credentials` with Basic auth, 3600s tokens refreshed early; STK push at
`/mpesa/stkpush/v1/processrequest` with `Password = base64(Shortcode + Passkey +
Timestamp)`, EAT `YYYYMMDDHHmmss` timestamps, 12-character `AccountReference` and
13-character `TransactionDesc` limits enforced in code; result codes translated into
plain language (1032 cancelled, 1 insufficient balance, 1037 timeout, 2001 wrong
PIN); MSISDN normalisation accepts `07…`, `01…`, `+254…`, `254…`, `00254…`.

**Flutterwave v3**: hosted checkout via `/v3/payments`; verification via
`/v3/transactions/{id}/verify` with all four checks; webhook authenticity via the
`verif-hash` header compared with `timingSafeEqual`; refunds via
`/v3/transactions/{id}/refund`, restricted to the billing role with a second
approver.

Both rails are **off by default and honestly reported**: with no credentials the app
returns `not_configured` and says so on the customer's own billing page, rather than
fabricating a settlement.

---

## 6. Not built (deliberately)

- **Counsel and public surfaces.** The guide's `(public)` and `counsel/` routes are
  not included; the console's privileged access returns the metadata index.
- **Live Supabase project and the RPC write path.** Migrations are written to be
  applied; no project is provisioned, so both surfaces run on demo data. The
  Supabase write path (section 2, "one seam") is the first production task.
- **Provider sandbox credentials.** Sandbox keys are needed to exercise STK push and
  Flutterwave checkout end to end; without them those paths report `not_configured`.
- **Email and SMS delivery.** Invitations, one-time codes and reset links are
  modelled in the data and the UI; no mail or SMS provider is wired, so demo builds
  show the code on screen and say so. The recovery *link* itself is real — minted,
  digest-stored, single-use, expiring, and spent through `/auth/confirm` →
  `/reset-password` — but in demo mode it is read out rather than emailed, and the
  credential change is recorded as simulated (this build stores no passwords at all).
- **Self-service "forgot password".** Today a link is issued by an operator after
  identity confirmation, which is the flow the console was asked for. `issuedBy` is
  nullable precisely so the same table can carry a future self-service request where
  nobody privileged is involved.
- **DPIA, retention runbook, penetration test, counsel-approved certificate
  wording** (guide steps 14–15). Legal/organisational rather than code. The package's
  `certificate-data.json` therefore ships with `declaration.status:
  "pending_counsel_approval"` and `wording: null` — an explicit refusal to emit an
  unapproved attestation.
- A written operator guide (`docs/ADMIN_CONSOLE.md`).

## 7. Wording discipline

The UI states only what the technology verifies — *"Document integrity verified"*,
*"Evidence-chain integrity verified"*, *"No broken chain links detected"* — and never
*"legally valid"*, *"court admissible"* or *"blockchain secured"*, per §22 of the
guide. Both the offline verifier and the package builder assert this in tests, and
the workspace says it to customers in plain words on the home screen.
