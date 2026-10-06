-- ---------------------------------------------------------------------------
-- agre-e · 0002 · Admin management console (users, billing, audit)
--
-- Everything the console needs, plus the guarantees that make the console safe
-- to hand to support staff:
--   • admin_actions is a second append-only chain (operational != evidentiary)
--   • security_events / user_sessions for operational telemetry
--   • commercial tables (plans, subscriptions, invoices, payments, coupons)
--     that can never affect an evidentiary row
--   • admin_agreement_index: metadata-only view. This is the ONLY agreement
--     surface a console role can read, and it exposes no document content.
-- ---------------------------------------------------------------------------

create extension if not exists "pgcrypto";

-- ------------------------------------------------------------- commercial --
create table if not exists plans (
  id text primary key default ('plan_' || replace(gen_random_uuid()::text, '-', '')),
  code text not null unique,
  name text not null,
  description text not null default '',
  interval text not null check (interval in ('monthly','annual')),
  amount_minor bigint not null check (amount_minor >= 0),   -- minor units: no float drift
  currency text not null default 'KES' check (currency in ('KES','USD','NGN')),
  trial_days integer not null default 14 check (trial_days between 0 and 90),
  features jsonb not null default '[]'::jsonb,
  included_seats integer not null default 1,
  included_stamps integer not null default 10,
  active boolean not null default true,
  archived_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists subscriptions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete restrict,
  plan_id text not null references plans(id),
  status text not null default 'trialing'
    check (status in ('trialing','active','past_due','grace','paused','cancelled','expired')),
  started_at timestamptz not null default now(),
  current_period_start timestamptz not null default now(),
  current_period_end timestamptz not null,
  trial_ends_at timestamptz,
  cancel_at_period_end boolean not null default false,
  cancelled_at timestamptz,
  paused_at timestamptz,
  seats integer not null default 1,
  amount_minor bigint not null,
  currency text not null default 'KES',
  provider text not null default 'mpesa' check (provider in ('mpesa','flutterwave')),
  dunning_attempts integer not null default 0 check (dunning_attempts between 0 and 10),
  grace_ends_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists subscriptions_user_idx on subscriptions(user_id);
create index if not exists subscriptions_status_idx on subscriptions(status);

create table if not exists invoices (
  id uuid primary key default gen_random_uuid(),
  number text not null unique,
  subscription_id uuid references subscriptions(id) on delete set null,
  user_id uuid not null references auth.users(id) on delete restrict,
  amount_minor bigint not null check (amount_minor >= 0),
  currency text not null default 'KES',
  status text not null default 'open' check (status in ('draft','open','paid','void','uncollectible')),
  issued_at timestamptz not null default now(),
  due_at timestamptz not null,
  paid_at timestamptz,
  provider text not null default 'mpesa' check (provider in ('mpesa','flutterwave')),
  created_at timestamptz not null default now()
);

create index if not exists invoices_user_idx on invoices(user_id);
create index if not exists invoices_status_idx on invoices(status);

create table if not exists payments (
  id uuid primary key default gen_random_uuid(),
  reference text not null unique,
  invoice_id uuid references invoices(id) on delete set null,
  user_id uuid not null references auth.users(id) on delete restrict,
  provider text not null check (provider in ('mpesa','flutterwave')),
  method text not null check (method in ('mpesa_stk','mpesa_c2b','card','bank_transfer','ussd','manual')),
  amount_minor bigint not null check (amount_minor >= 0),
  currency text not null default 'KES',
  status text not null default 'initiated'
    check (status in ('initiated','pending','succeeded','failed','reversed','refunded')),
  provider_ref text,                 -- CheckoutRequestID (M-PESA) or Flutterwave id
  mpesa_receipt text,                -- e.g. RJK4X7T21Q
  failure_reason text,
  reconciled_by uuid references auth.users(id),
  refunded_minor bigint not null default 0 check (refunded_minor >= 0),
  -- Idempotency: a provider must not be able to settle the same intent twice.
  provider_event_id text unique,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint refunded_not_more_than_charged check (refunded_minor <= amount_minor)
);

create index if not exists payments_user_idx on payments(user_id);
create index if not exists payments_status_idx on payments(status);
create index if not exists payments_receipt_idx on payments(mpesa_receipt);

create table if not exists coupons (
  id uuid primary key default gen_random_uuid(),
  code text not null unique,
  percent_off integer not null check (percent_off between 1 and 100),
  max_redemptions integer not null check (max_redemptions > 0),
  redemptions integer not null default 0,
  expires_at timestamptz,
  active boolean not null default true,
  created_at timestamptz not null default now()
);

-- Payment state and evidentiary state are separate by construction: no trigger,
-- constraint or foreign key in this file reaches an evidentiary table, and the
-- only cross-reference is read-only (admin_agreement_index counts).

-- ------------------------------------------------------------- operations --
create table if not exists user_sessions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  ip_hash text,
  user_agent text,
  mfa_satisfied boolean not null default false,
  created_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  expires_at timestamptz not null
);

create index if not exists user_sessions_user_idx on user_sessions(user_id);

create table if not exists security_events (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete set null,
  type text not null,
  severity text not null check (severity in ('info','notice','warning','critical')),
  detail text not null,
  ip_hash text,
  occurred_at timestamptz not null default now()
);

create index if not exists security_events_severity_idx on security_events(severity, occurred_at desc);

-- Admin action ledger: a second append-only chain. Mirrors
-- lib/audit/admin-chain.ts. reason is NOT NULL because an unexplained privileged
-- action is not an acceptable record.
create table if not exists admin_actions (
  id uuid primary key default gen_random_uuid(),
  admin_id uuid references auth.users(id) on delete set null,
  admin_email citext not null,
  admin_role text not null,
  action text not null,
  target_type text not null check (target_type in ('user','plan','subscription','payment','invoice','setting','agreement')),
  target_id text not null,
  target_label text not null,
  reason text not null check (length(btrim(reason)) >= 12),
  status text not null check (status in ('succeeded','failed','blocked')),
  step_up boolean not null default false,
  ip_hash text,
  user_agent text,
  metadata jsonb not null default '{}'::jsonb,
  previous_hash text,
  event_hash text not null,
  occurred_at timestamptz not null default now()
);

create index if not exists admin_actions_time_idx on admin_actions(occurred_at desc);
create index if not exists admin_actions_target_idx on admin_actions(target_type, target_id);
create index if not exists admin_actions_admin_idx on admin_actions(admin_id, occurred_at desc);

create or replace function admin_actions_append_only()
returns trigger language plpgsql as $$
begin
  raise exception 'admin_actions is append-only: % is not permitted', tg_op
    using errcode = 'restrict_violation';
end $$;

drop trigger if exists admin_actions_no_update on admin_actions;
create trigger admin_actions_no_update before update on admin_actions
  for each row execute function admin_actions_append_only();
drop trigger if exists admin_actions_no_delete on admin_actions;
create trigger admin_actions_no_delete before delete on admin_actions
  for each row execute function admin_actions_append_only();

create or replace function canonical_admin_payload(
  p_id uuid, p_admin_id uuid, p_admin_email text, p_admin_role text, p_action text,
  p_target_type text, p_target_id text, p_target_label text, p_reason text,
  p_status text, p_step_up boolean, p_ip_hash text, p_user_agent text,
  p_occurred_at timestamptz, p_metadata jsonb
) returns text language sql immutable as $$
  select jsonb_build_object(
    'id', p_id,
    'admin_id', p_admin_id,
    'admin_email', p_admin_email,
    'admin_role', p_admin_role,
    'action', p_action,
    'target_type', p_target_type,
    'target_id', p_target_id,
    'target_label', p_target_label,
    'reason', p_reason,
    'status', p_status,
    'step_up', p_step_up,
    'ip_hash', p_ip_hash,
    'user_agent', p_user_agent,
    'occurred_at', to_char(p_occurred_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    'metadata', coalesce(p_metadata, '{}'::jsonb)
  )::text;
$$;

create or replace function append_admin_action(
  p_admin_id uuid, p_admin_email text, p_admin_role text, p_action text,
  p_target_type text, p_target_id text, p_target_label text, p_reason text,
  p_status text, p_step_up boolean, p_ip_hash text default null,
  p_user_agent text default null, p_metadata jsonb default '{}'::jsonb
) returns admin_actions
language plpgsql security definer set search_path = public as $$
declare
  v_id uuid := gen_random_uuid();
  v_occurred timestamptz := now();
  v_previous text;
  v_payload text;
  v_row admin_actions;
begin
  perform pg_advisory_xact_lock(hashtext('admin_actions_chain'));

  select event_hash into v_previous from admin_actions order by occurred_at desc, id desc limit 1;

  v_payload := canonical_admin_payload(v_id, p_admin_id, p_admin_email, p_admin_role, p_action,
    p_target_type, p_target_id, p_target_label, p_reason, p_status, p_step_up, p_ip_hash,
    p_user_agent, v_occurred, p_metadata);

  insert into admin_actions (id, admin_id, admin_email, admin_role, action, target_type, target_id,
    target_label, reason, status, step_up, ip_hash, user_agent, metadata, previous_hash, event_hash, occurred_at)
  values (v_id, p_admin_id, p_admin_email, p_admin_role, p_action, p_target_type, p_target_id,
    p_target_label, p_reason, p_status, p_step_up, p_ip_hash, p_user_agent,
    coalesce(p_metadata, '{}'::jsonb), v_previous,
    encode(digest(coalesce(v_previous,'GENESIS') || E'\n' || v_payload, 'sha256'), 'hex'), v_occurred)
  returning * into v_row;

  return v_row;
end $$;

revoke all on function append_admin_action(uuid, text, text, text, text, text, text, text, text, boolean, text, text, jsonb)
  from anon, authenticated;

-- Idempotency for privileged mutations: a double-submit must not create two
-- links, two refunds or two credentials.
create table if not exists idempotency_keys (
  key text primary key,
  action text not null,
  admin_id uuid,
  response jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '15 minutes')
);

-- Break-glass register. The credential itself is never stored here.
create table if not exists break_glass_grants (
  id uuid primary key default gen_random_uuid(),
  subject_user_id uuid not null references auth.users(id),
  requested_by uuid not null references auth.users(id),
  supervisor_id uuid not null references auth.users(id),
  reason text not null,
  ttl_minutes integer not null check (ttl_minutes between 5 and 120),
  expires_at timestamptz not null,
  consumed_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz not null default now(),
  constraint two_person_rule check (requested_by <> supervisor_id)
);

-- ------------------------------------------------------- metadata-only view --
-- The single agreement surface the console can read. No storage path, no
-- document body, no party identity material, no consent payloads. The view is
-- built so that a support operator physically cannot select contract text.
create or replace view admin_agreement_index as
select
  a.id,
  a.ref,
  a.title,
  a.agreement_type,
  a.owner_id,
  p.email          as owner_email,
  a.status,
  a.created_at,
  a.completed_at,
  v.version_number as current_version,
  v.sha256         as document_hash,
  (select count(*) from agreement_parties ap where ap.agreement_id = a.id) as parties_count,
  (select count(*) from agreement_parties ap where ap.agreement_id = a.id and ap.signing_required) as required_signers,
  (select count(*) from signature_events se where se.agreement_id = a.id and se.outcome = 'signed') as completed_signers,
  (select max(se.occurred_at) from signature_events se where se.agreement_id = a.id and se.outcome = 'signed') as last_signature_at,
  (select ae.event_hash from audit_events ae where ae.agreement_id = a.id order by ae.occurred_at desc limit 1) as chain_head,
  (select max(ae.occurred_at) from audit_events ae where ae.agreement_id = a.id and ae.event_type = 'stamp.issued') as stamp_issued_at
from agreements a
join profiles p on p.id = a.owner_id
left join lateral (
  select version_number, sha256 from agreement_versions av
  where av.agreement_id = a.id order by version_number desc limit 1
) v on true;

revoke all on admin_agreement_index from anon, authenticated;

-- Record a privileged read. Called only by the security role through the
-- server; the justification is mandatory.
create or replace function record_privileged_access(
  p_admin_id uuid, p_agreement_id uuid, p_reason text, p_scope text default 'metadata_and_evidence_index_only'
) returns void language plpgsql security definer set search_path = public as $$
declare v_label text;
begin
  select ref into v_label from agreements where id = p_agreement_id;
  perform append_admin_action(
    p_admin_id,
    (select email::text from profiles where id = p_admin_id),
    coalesce((select role from profiles where id = p_admin_id), 'security'),
    'agreements.content.read.privileged', 'agreement', p_agreement_id::text,
    coalesce(v_label, p_agreement_id::text) || ' (' || p_scope || ')',
    p_reason, 'succeeded', true, null, null,
    jsonb_build_object('scope', p_scope, 'document_bytes_returned', 0)
  );
  -- Also visible on the agreement's own evidence trail, so a party can be told
  -- that an operator inspected their record.
  perform append_audit_event(
    p_agreement_id, p_admin_id, 'admin.privileged_access', p_agreement_id,
    jsonb_build_object('scope', p_scope, 'document_bytes_returned', 0), null, null
  );
end $$;

revoke all on function record_privileged_access(uuid, uuid, text, text) from anon, authenticated;

-- ------------------------------------------------------ console-side RLS -----
alter table plans           enable row level security;
alter table subscriptions   enable row level security;
alter table invoices        enable row level security;
alter table payments        enable row level security;
alter table coupons         enable row level security;
alter table user_sessions   enable row level security;
alter table security_events enable row level security;
alter table admin_actions   enable row level security;
alter table idempotency_keys enable row level security;
alter table break_glass_grants enable row level security;

-- Customers may read their own commercial records and nothing else. No console
-- role gets a policy here at all: the console reads these tables through the
-- server-side service role, after authorize(), which is what makes every console
-- read reviewable in one place.
drop policy if exists "customer reads own subscription" on subscriptions;
create policy "customer reads own subscription" on subscriptions for select
  using (user_id = auth.uid());

drop policy if exists "customer reads own invoices" on invoices;
create policy "customer reads own invoices" on invoices for select
  using (user_id = auth.uid());

drop policy if exists "customer reads own payments" on payments;
create policy "customer reads own payments" on payments for select
  using (user_id = auth.uid());

drop policy if exists "customer reads own sessions" on user_sessions;
create policy "customer reads own sessions" on user_sessions for select
  using (user_id = auth.uid());

-- Explicitly deny the browser any reach into the operators' ledgers.
revoke all on admin_actions from anon, authenticated;
revoke all on security_events from anon, authenticated;
revoke all on idempotency_keys from anon, authenticated;
revoke all on break_glass_grants from anon, authenticated;
revoke all on plans from anon;
-- Plans are a public catalogue: the pricing page needs them.
grant select on plans to anon, authenticated;

-- Helpful operational views for the console (service role only).
create or replace view admin_billing_health as
select
  count(*) filter (where status in ('active','past_due','grace'))                    as active_subscriptions,
  count(*) filter (where status = 'trialing')                                        as trialing,
  count(*) filter (where status in ('past_due','grace'))                             as past_due,
  sum(amount_minor) filter (where status = 'active')                                 as mrr_minor,
  count(*) filter (where cancel_at_period_end)                                       as pending_cancellations
from subscriptions;

create or replace view admin_payment_health as
select
  count(*) filter (where method = 'mpesa_stk')                                        as stk_attempts,
  count(*) filter (where method = 'mpesa_stk' and status = 'succeeded')               as stk_completions,
  count(*) filter (where status = 'failed' and created_at > now() - interval '7 days') as failures_7d,
  sum(refunded_minor)                                                                 as refunded_minor,
  max(created_at)                                                                     as last_payment_at
from payments;

revoke all on admin_billing_health from anon, authenticated;
revoke all on admin_payment_health from anon, authenticated;

-- Retention helper. Data classes have different clocks (Build Guide §16):
-- security logs and payment records are kept for audit and tax reasons; draft
-- documents are the first thing to go; executed agreements follow the
-- customer's contractual retention.
create or replace function retention_sweep(p_dry_run boolean default true)
returns table (data_class text, candidate_rows bigint, policy_interval text)
language plpgsql security definer set search_path = public as $$
begin
  return query
  select 'audit_events'::text,
         (select count(*) from audit_events where occurred_at < now() - interval '7 years'),
         '7 years (evidentiary chain, never deleted earlier)'::text
  union all
  select 'admin_actions',
         (select count(*) from admin_actions where occurred_at < now() - interval '7 years'),
         '7 years (operator accountability)'::text
  union all
  select 'security_events',
         (select count(*) from security_events where occurred_at < now() - interval '24 months'),
         '24 months'::text
  union all
  select 'payments',
         (select count(*) from payments where created_at < now() - interval '7 years'),
         '7 years (tax and reconciliation)'::text
  union all
  select 'agreement_versions',
         (select count(*) from agreement_versions v join agreements a on a.id = v.agreement_id
           where a.status = 'draft' and v.created_at < now() - interval '24 months'),
         '24 months for drafts only; executed versions are retained'::text;

  if p_dry_run then
    raise notice 'retention_sweep was called in dry-run mode: no rows were removed.';
  end if;
end $$;

revoke all on function retention_sweep(boolean) from anon, authenticated;
