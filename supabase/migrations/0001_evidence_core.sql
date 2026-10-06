-- ---------------------------------------------------------------------------
-- agre-e · 0001 · Evidence core
--
-- Implements the append-only evidence model from the Architecture & Security
-- Build Guide (§6 data model, §7 SQL starter schema, §8 RLS, §9 audit ledger).
--
-- Two rules drive the shape of this file:
--   1. An executed version is never mutated. Amendments add rows.
--   2. Hashes and timestamps are produced by the database, not the application,
--      so no code path can write an unchained event.
-- ---------------------------------------------------------------------------

create extension if not exists "pgcrypto";
create extension if not exists "citext";

-- ---------------------------------------------------------------- profiles --
create table if not exists profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email citext not null unique,
  display_name text not null default '',
  role text not null default 'counsel'
    check (role in ('owner','admin','support','security','billing','counsel')),
  status text not null default 'active'
    check (status in ('active','invited','suspended','locked','deactivated')),
  phone text,
  country text not null default 'KE',
  organisation text,
  email_verified boolean not null default false,
  mfa_enabled boolean not null default false,
  mfa_required boolean not null default false,
  force_password_reset boolean not null default false,
  password_changed_at timestamptz,
  failed_sign_in_count integer not null default 0,
  locked_until timestamptz,
  temp_credential_issued_at timestamptz,
  temp_credential_expires_at timestamptz,
  extra_capabilities text[] not null default '{}',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists profiles_role_idx on profiles(role);
create index if not exists profiles_status_idx on profiles(status);

-- --------------------------------------------------------------- agreements --
create table if not exists agreements (
  id uuid primary key default gen_random_uuid(),
  ref text not null unique,
  owner_id uuid not null references auth.users(id),
  title text not null,
  agreement_type text not null,
  status text not null check (status in
    ('draft','awaiting_parties','awaiting_signatures','completed','revoked')),
  created_at timestamptz not null default now(),
  completed_at timestamptz,
  revoked_at timestamptz,
  revoke_reason text
);

create index if not exists agreements_owner_idx on agreements(owner_id);
create index if not exists agreements_status_idx on agreements(status);

create table if not exists agreement_versions (
  id uuid primary key default gen_random_uuid(),
  agreement_id uuid not null references agreements(id) on delete restrict,
  version_number integer not null,
  storage_path text not null,
  sha256 text not null,
  byte_size bigint,
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now(),
  frozen_at timestamptz,          -- set when the agreement completes
  unique (agreement_id, version_number)
);

-- An executed version is frozen. Nothing — not even the service role through
-- normal application paths — may edit its storage path or digest.
create or replace function prevent_frozen_version_change()
returns trigger language plpgsql as $$
begin
  if old.frozen_at is not null and (
       new.storage_path is distinct from old.storage_path
    or new.sha256       is distinct from old.sha256
    or new.version_number is distinct from old.version_number
    or new.agreement_id is distinct from old.agreement_id) then
    raise exception 'agreement_versions row % is frozen (executed version) and cannot be modified', old.id
      using errcode = 'restrict_violation';
  end if;
  if tg_op = 'DELETE' then
    if old.frozen_at is not null then
      raise exception 'executed version % cannot be deleted; amend it with a new version instead', old.id
        using errcode = 'restrict_violation';
    end if;
    return old;
  end if;
  return new;
end $$;

drop trigger if exists agreement_versions_immutable on agreement_versions;
create trigger agreement_versions_immutable
  before update or delete on agreement_versions
  for each row execute function prevent_frozen_version_change();

create table if not exists agreement_parties (
  id uuid primary key default gen_random_uuid(),
  agreement_id uuid not null references agreements(id) on delete cascade,
  user_id uuid references auth.users(id),
  party_role text not null,
  signing_required boolean not null default true,
  signing_order integer not null default 1,
  invitation_email citext,
  invitation_sent_at timestamptz,
  invitation_accepted_at timestamptz,
  created_at timestamptz not null default now(),
  unique (agreement_id, party_role, invitation_email)
);

create table if not exists identity_verifications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id),
  agreement_id uuid references agreements(id) on delete cascade,
  provider text not null default 'internal',
  -- Provider reference only. We deliberately do not copy ID documents or numbers.
  provider_reference text,
  assurance_level text not null
    check (assurance_level in ('email','email_otp','phone_otp','email_otp_plus_id_document','in_person')),
  status text not null default 'pending' check (status in ('pending','verified','failed','expired')),
  verified_at timestamptz,
  expires_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists signature_requests (
  id uuid primary key default gen_random_uuid(),
  agreement_id uuid not null references agreements(id) on delete cascade,
  agreement_version_id uuid not null references agreement_versions(id),
  party_id uuid not null references agreement_parties(id),
  requested_by uuid references auth.users(id),
  status text not null default 'requested' check (status in ('requested','viewed','signed','declined','expired')),
  requested_at timestamptz not null default now(),
  expires_at timestamptz
);

create table if not exists signature_events (
  id uuid primary key default gen_random_uuid(),
  signature_request_id uuid references signature_requests(id),
  agreement_id uuid not null references agreements(id) on delete cascade,
  agreement_version_id uuid not null references agreement_versions(id),
  party_id uuid references agreement_parties(id),
  actor_id uuid references auth.users(id),
  signature_method text not null default 'otp_confirmed_intent',
  outcome text not null check (outcome in ('signed','declined','failed')),
  consent_id uuid,
  occurred_at timestamptz not null default now(),
  ip_hash text,
  user_agent text
);

create table if not exists consents (
  id uuid primary key default gen_random_uuid(),
  agreement_id uuid references agreements(id) on delete cascade,
  user_id uuid not null references auth.users(id),
  disclosure_version text not null,
  scope text not null,
  accepted_at timestamptz not null default now(),
  ip_hash text
);

-- ------------------------------------------------------- audit event ledger --
create table if not exists audit_events (
  id uuid primary key default gen_random_uuid(),
  agreement_id uuid not null references agreements(id) on delete restrict,
  actor_id uuid references auth.users(id),
  event_type text not null,
  object_id uuid,
  occurred_at timestamptz not null default now(),
  ip_hash text,
  user_agent text,
  metadata jsonb not null default '{}'::jsonb,
  previous_hash text,
  event_hash text not null
);

create index if not exists audit_events_agreement_idx on audit_events(agreement_id, occurred_at);

-- Append-only at the storage layer: no UPDATE, no DELETE, for anyone.
create or replace function audit_events_append_only()
returns trigger language plpgsql as $$
begin
  raise exception 'audit_events is append-only: % is not permitted', tg_op
    using errcode = 'restrict_violation';
end $$;

drop trigger if exists audit_events_no_update on audit_events;
create trigger audit_events_no_update before update on audit_events
  for each row execute function audit_events_append_only();
drop trigger if exists audit_events_no_delete on audit_events;
create trigger audit_events_no_delete before delete on audit_events
  for each row execute function audit_events_append_only();

-- Deterministic canonical serialization. Mirrors lib/audit/chain.ts exactly:
-- sorted keys, snake_case field names, nulls preserved. Any change here must be
-- matched in the TypeScript verifier, or verification will disagree with the
-- database (tested in tests/chain.test.ts).
create or replace function canonical_event_payload(
  p_id uuid, p_agreement_id uuid, p_actor_id uuid, p_event_type text,
  p_object_id uuid, p_occurred_at timestamptz, p_ip_hash text, p_metadata jsonb
) returns text language sql immutable as $$
  select jsonb_build_object(
    'id', p_id,
    'agreement_id', p_agreement_id,
    'actor_id', p_actor_id,
    'event_type', p_event_type,
    'object_id', p_object_id,
    'occurred_at', to_char(p_occurred_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    'ip_hash', p_ip_hash,
    'metadata', coalesce(p_metadata, '{}'::jsonb)
  )::text;
$$;

create or replace function compute_event_hash(previous text, payload text)
returns text language sql immutable as $$
  select encode(digest(coalesce(previous, 'GENESIS') || E'\n' || payload, 'sha256'), 'hex');
$$;

create or replace function event_hash(previous text, payload text)
returns text language sql immutable as $$
  select encode(digest(coalesce(previous, 'GENESIS') || E'\n' || payload, 'sha256'), 'hex');
$$;

-- Append a chained event. Locks the agreement's chain head so two concurrent
-- writers cannot fork the ledger (Build Guide §20: "two parties signing
-- simultaneously result in one consistent completion transition").
create or replace function append_audit_event(
  p_agreement_id uuid,
  p_actor_id uuid,
  p_event_type text,
  p_object_id uuid default null,
  p_metadata jsonb default '{}'::jsonb,
  p_ip_hash text default null,
  p_user_agent text default null
) returns audit_events
language plpgsql security definer set search_path = public as $$
declare
  v_id uuid := gen_random_uuid();
  v_occurred timestamptz := now();
  v_previous text;
  v_payload text;
  v_hash text;
  v_row audit_events;
begin
  -- Serialise writers per agreement.
  perform pg_advisory_xact_lock(hashtext(p_agreement_id::text));

  select event_hash into v_previous
    from audit_events
   where agreement_id = p_agreement_id
   order by occurred_at desc, id desc
   limit 1;

  v_payload := canonical_event_payload(v_id, p_agreement_id, p_actor_id, p_event_type,
                                       p_object_id, v_occurred, p_ip_hash, p_metadata);
  v_hash := event_hash(v_previous, v_payload);

  insert into audit_events (id, agreement_id, actor_id, event_type, object_id, occurred_at,
                            ip_hash, user_agent, metadata, previous_hash, event_hash)
  values (v_id, p_agreement_id, p_actor_id, p_event_type, p_object_id, v_occurred,
          p_ip_hash, p_user_agent, coalesce(p_metadata, '{}'::jsonb), v_previous, v_hash)
  returning * into v_row;

  return v_row;
end $$;

revoke all on function append_audit_event(uuid, uuid, text, uuid, jsonb, text, text) from anon, authenticated;

-- Server-side verification, mirroring verifyChain() in lib/audit/chain.ts.
create or replace function verify_audit_chain(p_agreement_id uuid)
returns table (valid boolean, checked_events integer, failure_index integer, failure_reason text, detail text)
language plpgsql stable security definer set search_path = public as $$
declare
  r audit_events;
  v_previous text := null;
  v_index integer := 0;
  v_payload text;
  v_recomputed text;
begin
  for r in
    select * from audit_events where agreement_id = p_agreement_id order by occurred_at asc, id asc
  loop
    if r.previous_hash is distinct from v_previous then
      return query select false, v_index, v_index, 'broken_link',
        format('Event %s commits to %s but the preceding link is %s', v_index,
               coalesce(r.previous_hash,'GENESIS'), coalesce(v_previous,'GENESIS'));
      return;
    end if;

    v_payload := canonical_event_payload(r.id, r.agreement_id, r.actor_id, r.event_type,
                                         r.object_id, r.occurred_at, r.ip_hash, r.metadata);
    v_recomputed := event_hash(r.previous_hash, v_payload);
    if v_recomputed <> r.event_hash then
      return query select false, v_index, v_index, 'digest_mismatch',
        format('Event %s records digest %s but the canonical payload hashes to %s',
               v_index, left(r.event_hash,16), left(v_recomputed,16));
      return;
    end if;

    v_previous := r.event_hash;
    v_index := v_index + 1;
  end loop;

  return query select true, v_index, null::integer, 'ok'::text,
    format('%s events verified', v_index);
end $$;

-- --------------------------------------------------------------- RLS set-up --
alter table profiles              enable row level security;
alter table agreements            enable row level security;
alter table agreement_versions    enable row level security;
alter table agreement_parties     enable row level security;
alter table identity_verifications enable row level security;
alter table signature_requests    enable row level security;
alter table signature_events      enable row level security;
alter table consents              enable row level security;
alter table audit_events          enable row level security;

-- Helper: is the caller an active console operator with a given role?
create or replace function current_role_name()
returns text language sql stable security definer set search_path = public as $$
  select p.role from profiles p where p.id = auth.uid() and p.status = 'active';
$$;

create or replace function has_role(variadic roles text[])
returns boolean language sql stable security definer set search_path = public as $$
  select coalesce(current_role_name() = any(roles), false);
$$;

-- profiles: a person sees and edits only their own row. Console roles are read
-- through the server-side service-role path, never straight from the browser.
drop policy if exists "profile self read" on profiles;
create policy "profile self read" on profiles for select
  using (id = auth.uid());

drop policy if exists "profile self update" on profiles;
create policy "profile self update" on profiles for update
  using (id = auth.uid())
  with check (
    id = auth.uid()
    -- A user may not escalate their own role or status through the API.
    and role = (select p.role from profiles p where p.id = auth.uid())
    and status = (select p.status from profiles p where p.id = auth.uid())
  );

-- agreements: owner or an explicitly invited party (Build Guide §8).
drop policy if exists "party can read agreement" on agreements;
create policy "party can read agreement" on agreements for select
  using (
    owner_id = auth.uid()
    or exists (
      select 1 from agreement_parties p
      where p.agreement_id = agreements.id
        and p.user_id = auth.uid()
    )
  );

drop policy if exists "owner can create agreement" on agreements;
create policy "owner can create agreement" on agreements for insert
  with check (owner_id = auth.uid());

drop policy if exists "owner can update draft agreement" on agreements;
create policy "owner can update draft agreement" on agreements for update
  using (owner_id = auth.uid() and status in ('draft','awaiting_parties'))
  with check (owner_id = auth.uid());

drop policy if exists "agreement parties read" on agreement_parties;
create policy "agreement parties read" on agreement_parties for select
  using (
    user_id = auth.uid()
    or exists (select 1 from agreements a where a.id = agreement_parties.agreement_id and a.owner_id = auth.uid())
  );

drop policy if exists "version read for participants" on agreement_versions;
create policy "version read for participants" on agreement_versions for select
  using (
    exists (
      select 1 from agreements a
      where a.id = agreement_versions.agreement_id
        and (a.owner_id = auth.uid()
             or exists (select 1 from agreement_parties p
                        where p.agreement_id = a.id and p.user_id = auth.uid()))
    )
  );

drop policy if exists "audit read for participants" on audit_events;
create policy "audit read for participants" on audit_events for select
  using (
    exists (
      select 1 from agreements a
      where a.id = audit_events.agreement_id
        and (a.owner_id = auth.uid()
             or exists (select 1 from agreement_parties p
                        where p.agreement_id = a.id and p.user_id = auth.uid()))
    )
  );

-- Note deliberately absent: there is no INSERT/UPDATE/DELETE policy on
-- audit_events for authenticated users at all. Events are only written by
-- append_audit_event() (security definer, revoked from anon/authenticated) or by
-- the server-side service role. Nothing in the browser can forge a ledger row.

drop policy if exists "signature events read for participants" on signature_events;
create policy "signature events read for participants" on signature_events for select
  using (
    exists (
      select 1 from agreements a
      where a.id = signature_events.agreement_id
        and (a.owner_id = auth.uid()
             or exists (select 1 from agreement_parties p
                        where p.agreement_id = a.id and p.user_id = auth.uid()))
    )
  );

drop policy if exists "identity own rows" on identity_verifications;
create policy "identity own rows" on identity_verifications for select
  using (user_id = auth.uid());

drop policy if exists "consents own rows" on consents;
create policy "consents own rows" on consents for select
  using (user_id = auth.uid());
create policy "consents own insert" on consents for insert
  with check (user_id = auth.uid());

-- Counsel access to a matter must be granted explicitly, never implied by role.
create table if not exists matter_shares (
  id uuid primary key default gen_random_uuid(),
  agreement_id uuid not null references agreements(id) on delete cascade,
  counsel_id uuid not null references auth.users(id),
  granted_by uuid not null references auth.users(id),
  scope text not null default 'evidence_read' check (scope in ('evidence_read','certificate_draft')),
  granted_at timestamptz not null default now(),
  revoked_at timestamptz,
  unique (agreement_id, counsel_id)
);

alter table matter_shares enable row level security;

drop policy if exists "counsel sees own shares" on matter_shares;
create policy "counsel sees own shares" on matter_shares for select
  using (counsel_id = auth.uid() or granted_by = auth.uid());

-- Keep updated_at honest.
create or replace function touch_updated_at()
returns trigger language plpgsql as $$
begin
  new.updated_at := now();
  return new;
end $$;

drop trigger if exists profiles_touch on profiles;
create trigger profiles_touch before update on profiles
  for each row execute function touch_updated_at();

-- New auth user -> profile row. Role defaults to the least-privileged console
-- role; nothing here grants admin.
create or replace function handle_new_auth_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into profiles (id, email, display_name, country, email_verified)
  values (
    new.id,
    new.email,
    coalesce(new.raw_user_meta_data->>'full_name', split_part(new.email, '@', 1)),
    coalesce(new.raw_user_meta_data->>'country', 'KE'),
    new.email_confirmed_at is not null
  )
  on conflict (id) do nothing;
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function handle_new_auth_user();
