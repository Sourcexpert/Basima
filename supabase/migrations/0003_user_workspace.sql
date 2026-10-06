-- ---------------------------------------------------------------------------
-- agre-e · 0003 · User workspace: parties, signing, evidence packages, rights
--
-- 0001 created the evidentiary core (agreements, versions, parties, signature
-- requests/events, consents, append-only audit_events, RLS, verification RPC).
-- This migration finishes the *party* side of the product:
--
--   • evidence_packages — an export record keyed to the chain root, immutable
--   • data_subject_requests — the Kenya DPA workflow, filed by the user
--   • assurance columns on agreement_parties (a reference, never a document)
--   • an invitation that is visible to its invitee *before* acceptance, and
--     nothing else: the email is the binding, and `accept_invitation()` is the
--     single place where an account becomes a party
--   • record_signature_event() — the signing transaction, in one transaction,
--     with the completion decision and the stamp made server-side
--
-- Design rules restated here because SQL is where they are hardest to enforce:
--   * hashing and timestamping happen in Postgres, never in the browser;
--   * an executed version is frozen and cannot be edited or deleted;
--   * nothing on this path can read or write a password;
--   * the console's service role is *not* used by the user-facing reads — the
--     policies below bind the authenticated client, and the app additionally
--     authorises every action in code before it reaches any of this.
-- ---------------------------------------------------------------------------

-- ------------------------------------------------------------- package rows --
create table if not exists evidence_packages (
  id uuid primary key default gen_random_uuid(),
  agreement_id uuid not null references agreements(id) on delete restrict,
  agreement_version_id uuid not null references agreement_versions(id) on delete restrict,
  format text not null default 'agree-e-evidence-package',
  package_version text not null default '1.0',
  document_hash text not null,
  chain_root text not null,
  event_count integer not null default 0,
  verification_ok boolean not null default false,
  verification jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  created_by uuid references auth.users(id),
  -- One package per chain root: re-generating from the same chain returns the
  -- same artefact instead of accumulating look-alike copies.
  unique (agreement_id, chain_root)
);

create index if not exists evidence_packages_agreement_idx on evidence_packages(agreement_id);

create or replace function prevent_package_change()
returns trigger language plpgsql as $$
begin
  raise exception 'evidence_packages row % is an export record and cannot be changed', old.id
    using errcode = 'restrict_violation';
end $$;

drop trigger if exists evidence_packages_immutable on evidence_packages;
create trigger evidence_packages_immutable
  before update or delete on evidence_packages
  for each row execute function prevent_package_change();

-- --------------------------------------------------------- data-subject work --
create table if not exists data_subject_requests (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  request_type text not null check (request_type in ('access','correction','deletion','restriction','portability')),
  detail text not null,
  status text not null default 'received' check (status in ('received','in_review','fulfilled','refused')),
  submitted_at timestamptz not null default now(),
  due_at timestamptz not null default now() + interval '30 days',
  resolved_at timestamptz,
  resolution_note text
);

create index if not exists data_subject_requests_user_idx on data_subject_requests(user_id);

-- An executed agreement is a legal record: a deletion request cannot reach it.
-- Recorded as a comment because the constraint lives in the append-only ledger
-- and in the immutable-version trigger, not in this table.
comment on table data_subject_requests is
  'Filed by the data subject. Fulfilment may not delete executed agreements, stamps, or audit events; the response must state what was deleted and what was retained, and why.';

-- ------------------------------------------------- parties: assurance refs ----
alter table agreement_parties
  add column if not exists assurance_level text
    check (assurance_level is null or assurance_level in ('email','email_otp','phone_otp','email_otp_plus_id_document','in_person')),
  add column if not exists identity_verified_at timestamptz,
  add column if not exists display_name text,
  add column if not exists status text not null default 'invited'
    check (status in ('invited','accepted','declined','removed'));

comment on column agreement_parties.assurance_level is
  'Level of the identity check actually performed. The check itself lives in identity_verifications; no document copy is stored anywhere.';

create index if not exists agreement_parties_email_idx on agreement_parties(lower(invitation_email::text));
create index if not exists agreement_parties_user_idx on agreement_parties(user_id);

-- --------------------------------------------------------------- predicates --
-- A participant is the owner or a party whose invitation has been accepted.
create or replace function is_participant(p_agreement_id uuid, p_user_id uuid default auth.uid())
returns boolean language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from agreements a where a.id = p_agreement_id and a.owner_id = p_user_id
  ) or exists (
    select 1 from agreement_parties p
    where p.agreement_id = p_agreement_id
      and p.status <> 'removed'
      and (p.user_id = p_user_id
           or (p.user_id is null and lower(p.invitation_email::text) = lower(coalesce(auth.email(), ''))))
  );
$$;

-- An invitee may read the agreement they were invited to *before* accepting,
-- and nothing more than that.
create or replace function is_invitee(p_agreement_id uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from agreement_parties p
    where p.agreement_id = p_agreement_id
      and p.user_id is null
      and p.status = 'invited'
      and lower(p.invitation_email::text) = lower(coalesce(auth.email(), ''))
  );
$$;

-- --------------------------------------------------------------- RLS: read --
drop policy if exists "invitee may read invitation" on agreements;
create policy "invitee may read invitation" on agreements for select
  using (is_invitee(id));

drop policy if exists "participant may read package" on evidence_packages;
create policy "participant may read package" on evidence_packages for select
  using (is_participant(agreement_id));

-- Packages are written by the service path only (record_evidence_package).
drop policy if exists "participant may create package" on evidence_packages;
-- deliberately no insert policy for authenticated users

-- ------------------------------------------------------- RLS: data requests --
drop policy if exists "own data requests read" on data_subject_requests;
create policy "own data requests read" on data_subject_requests for select
  using (user_id = auth.uid());

drop policy if exists "own data requests insert" on data_subject_requests;
create policy "own data requests insert" on data_subject_requests for insert
  with check (
    user_id = auth.uid()
    -- A requester cannot pre-mark their own request as fulfilled, and cannot
    -- set their own deadline.
    and status = 'received'
    and resolved_at is null
    and due_at between now() + interval '25 days' and now() + interval '35 days'
  );

-- Status changes are made by the operator console under a security role, and
-- are audited in the admin chain — not by the requester.
drop policy if exists "own data requests update" on data_subject_requests;

-- ------------------------------------------------------------ accept a party --
create or replace function accept_invitation(
  p_agreement_id uuid,
  p_ip_hash text default null,
  p_user_agent text default null
) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_party agreement_parties;
  v_email text := lower(coalesce(auth.email(), ''));
  v_verified timestamptz := now();
begin
  if auth.uid() is null then
    return jsonb_build_object('ok', false, 'error', 'authentication_required');
  end if;

  perform pg_advisory_xact_lock(hashtext(p_agreement_id::text));

  select * into v_party
    from agreement_parties
   where agreement_id = p_agreement_id
     and status <> 'removed'
     and (user_id = auth.uid() or (user_id is null and lower(invitation_email::text) = v_email))
   order by (user_id = auth.uid()) desc
   limit 1;

  if v_party.id is null then
    return jsonb_build_object('ok', false, 'error', 'not_an_invited_party');
  end if;

  if v_party.invitation_accepted_at is not null then
    return jsonb_build_object('ok', true, 'party_id', v_party.id, 'already_accepted', true);
  end if;

  -- The moment the account is bound to the party row. From here on the user id
  -- authorises; the email address is not consulted again.
  update agreement_parties
     set user_id = coalesce(v_party.user_id, auth.uid()),
         status = 'accepted',
         invitation_accepted_at = v_verified,
         assurance_level = 'email_otp',
         identity_verified_at = v_verified
   where id = v_party.id;

  insert into identity_verifications (user_id, agreement_id, provider, assurance_level, status, verified_at)
  values (auth.uid(), p_agreement_id, 'internal', 'email_otp', 'verified', v_verified);

  perform append_audit_event(
    p_agreement_id, auth.uid(), 'party.identity_verified', v_party.id,
    jsonb_build_object(
      'party_role', v_party.party_role,
      'assurance_level', 'email_otp',
      'provider', 'internal',
      'invitation_bound_to_user_id', auth.uid(),
      'note', 'Assurance reflects the check actually performed, not an assertion of identity beyond it.'
    ),
    p_ip_hash, p_user_agent
  );

  perform append_audit_event(
    p_agreement_id, auth.uid(), 'agreement.invitation_accepted', v_party.id,
    jsonb_build_object('party_role', v_party.party_role),
    p_ip_hash, p_user_agent
  );

  return jsonb_build_object('ok', true, 'party_id', v_party.id, 'assurance_level', 'email_otp');
end $$;

revoke all on function accept_invitation(uuid, text, text) from anon;
grant execute on function accept_invitation(uuid, text, text) to authenticated;

-- ------------------------------------------------------- the signing act ----
create or replace function record_signature_event(
  p_agreement_id uuid,
  p_agreement_version_id uuid,
  p_disclosure_version text,
  p_signature_method text default 'otp_confirmed_intent',
  p_ip_hash text default null,
  p_user_agent text default null
) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_agreement agreements;
  v_version agreement_versions;
  v_current agreement_versions;
  v_party agreement_parties;
  v_consent uuid := gen_random_uuid();
  v_event uuid := gen_random_uuid();
  v_existing signature_events;
  v_required integer;
  v_signed integer;
  v_earlier_missing integer;
  v_stamp timestamptz;
  v_chain_root text;
  v_package uuid;
begin
  if auth.uid() is null then
    return jsonb_build_object('ok', false, 'error', 'authentication_required');
  end if;

  -- One signer at a time per agreement, so two people signing at the same
  -- instant cannot both observe "one signature missing" and both stamp.
  perform pg_advisory_xact_lock(hashtext(p_agreement_id::text));

  select * into v_agreement from agreements where id = p_agreement_id;
  if v_agreement.id is null then
    return jsonb_build_object('ok', false, 'error', 'agreement_not_found');
  end if;

  if v_agreement.status in ('completed','revoked') then
    return jsonb_build_object('ok', false, 'error', 'agreement_immutable', 'status', v_agreement.status);
  end if;

  select * into v_version from agreement_versions
   where id = p_agreement_version_id and agreement_id = p_agreement_id;
  if v_version.id is null then
    return jsonb_build_object('ok', false, 'error', 'version_not_found');
  end if;

  select * into v_current from agreement_versions
   where agreement_id = p_agreement_id order by version_number desc limit 1;
  if v_current.id is distinct from v_version.id then
    -- A signature must never attach to text the other side has already replaced.
    return jsonb_build_object('ok', false, 'error', 'superseded_version',
                              'current_version_number', v_current.version_number);
  end if;

  select * into v_party from agreement_parties
   where agreement_id = p_agreement_id
     and status = 'accepted'
     and user_id = auth.uid()
   limit 1;
  if v_party.id is null then
    return jsonb_build_object('ok', false, 'error', 'not_a_party');
  end if;
  if not v_party.signing_required then
    return jsonb_build_object('ok', false, 'error', 'signature_not_required');
  end if;
  if v_party.identity_verified_at is null then
    return jsonb_build_object('ok', false, 'error', 'identity_not_verified');
  end if;

  -- Signing order: an earlier required signer who has not signed blocks this one.
  select count(*) into v_earlier_missing
    from agreement_parties p
   where p.agreement_id = p_agreement_id
     and p.signing_required
     and p.status = 'accepted'
     and p.signing_order < v_party.signing_order
     and not exists (
       select 1 from signature_events e
        where e.party_id = p.id and e.agreement_version_id = v_version.id and e.outcome = 'signed'
     );
  if v_earlier_missing > 0 then
    return jsonb_build_object('ok', false, 'error', 'signing_order_not_reached', 'blockers', v_earlier_missing);
  end if;

  select * into v_existing from signature_events
   where agreement_version_id = v_version.id and party_id = v_party.id and outcome = 'signed'
   limit 1;
  if v_existing.id is not null then
    return jsonb_build_object('ok', true, 'duplicate', true, 'signature_event_id', v_existing.id,
                              'completed', v_agreement.status = 'completed');
  end if;

  insert into consents (id, agreement_id, user_id, disclosure_version, scope, ip_hash)
  values (v_consent, p_agreement_id, auth.uid(), p_disclosure_version, 'sign_and_evidence', p_ip_hash);

  insert into signature_events (id, agreement_id, agreement_version_id, party_id, actor_id,
                                signature_method, outcome, consent_id, ip_hash, user_agent)
  values (v_event, p_agreement_id, v_version.id, v_party.id, auth.uid(),
          p_signature_method, 'signed', v_consent, p_ip_hash, p_user_agent);

  update signature_requests
     set status = 'signed'
   where agreement_id = p_agreement_id and agreement_version_id = v_version.id and party_id = v_party.id;

  perform append_audit_event(
    p_agreement_id, auth.uid(), 'party.consent_recorded', v_party.id,
    jsonb_build_object('consent_id', v_consent, 'disclosure_version', p_disclosure_version,
                       'scope', 'sign_and_evidence', 'party_role', v_party.party_role),
    p_ip_hash, p_user_agent
  );

  perform append_audit_event(
    p_agreement_id, auth.uid(), 'party.signed', v_party.id,
    jsonb_build_object(
      'party_role', v_party.party_role,
      'version', v_version.version_number,
      'agreement_version_id', v_version.id,
      'signature_method', p_signature_method,
      'signature_event_id', v_event,
      'consent_id', v_consent,
      'document_sha256', v_version.sha256
    ),
    p_ip_hash, p_user_agent
  );

  select count(*) into v_required from agreement_parties
   where agreement_id = p_agreement_id and signing_required and status = 'accepted';

  select count(*) into v_signed from signature_events e
    join agreement_parties p on p.id = e.party_id
   where e.agreement_version_id = v_version.id and e.outcome = 'signed'
     and p.signing_required and p.status = 'accepted';

  perform append_audit_event(
    p_agreement_id, null, 'agreement.completion_evaluated', null,
    jsonb_build_object('version', v_version.version_number, 'required', v_required,
                       'completed', v_signed, 'satisfied', v_signed >= v_required),
    null, null
  );

  if v_signed >= v_required then
    -- Freeze the executed version, stamp it, and record the package that a
    -- counterparty will be handed. Not a claim of legal validity: the stamp
    -- records that this version, these signatures and this chain are intact.
    update agreement_versions set frozen_at = now()
     where id = v_version.id and frozen_at is null;

    update agreements
       set status = 'completed', completed_at = now()
     where id = p_agreement_id;

    v_stamp := now();
    perform append_audit_event(
      p_agreement_id, null, 'stamp.issued', null,
      jsonb_build_object(
        'version', v_version.version_number,
        'agreement_version_id', v_version.id,
        'document_sha256', v_version.sha256,
        'required_signers', v_required,
        'signed_signers', v_signed,
        'definition', 'frozen version + required party actions complete + integrity digest + evidence-chain record'
      ),
      null, null
    );

    select event_hash into v_chain_root from audit_events
     where agreement_id = p_agreement_id order by occurred_at desc, id desc limit 1;

    insert into evidence_packages (agreement_id, agreement_version_id, document_hash, chain_root,
                                   event_count, verification_ok, created_by)
    values (p_agreement_id, v_version.id, v_version.sha256, v_chain_root,
            (select count(*) from audit_events where agreement_id = p_agreement_id),
            true, auth.uid())
    on conflict (agreement_id, chain_root) do nothing
    returning id into v_package;

    perform append_audit_event(
      p_agreement_id, auth.uid(), 'evidence.package_generated', null,
      jsonb_build_object('package_id', v_package, 'format', 'agree-e-evidence-package',
                         'package_version', '1.0', 'version', v_version.version_number,
                         'chain_root', v_chain_root),
      p_ip_hash, p_user_agent
    );
  else
    update agreements set status = 'awaiting_signatures' where id = p_agreement_id and status <> 'awaiting_signatures';
  end if;

  return jsonb_build_object(
    'ok', true,
    'duplicate', false,
    'signature_event_id', v_event,
    'consent_id', v_consent,
    'version', v_version.version_number,
    'document_sha256', v_version.sha256,
    'required_signers', v_required,
    'signed_signers', v_signed,
    'completed', v_signed >= v_required,
    'stamp_issued_at', v_stamp,
    'package_id', v_package
  );
end $$;

revoke all on function record_signature_event(uuid, uuid, text, text, text, text) from anon;
grant execute on function record_signature_event(uuid, uuid, text, text, text, text) to authenticated;

-- --------------------------------------------------------- record an export --
create or replace function record_evidence_package(
  p_agreement_id uuid,
  p_agreement_version_id uuid,
  p_chain_root text,
  p_event_count integer,
  p_verification jsonb
) returns uuid
language plpgsql security definer set search_path = public as $$
declare
  v_id uuid;
  v_hash text;
begin
  if not is_participant(p_agreement_id) then
    raise exception 'not a participant on agreement %', p_agreement_id using errcode = 'insufficient_privilege';
  end if;

  select sha256 into v_hash from agreement_versions where id = p_agreement_version_id;
  if v_hash is null then
    raise exception 'version % not found for agreement %', p_agreement_version_id, p_agreement_id;
  end if;

  insert into evidence_packages (agreement_id, agreement_version_id, document_hash, chain_root,
                                 event_count, verification_ok, verification, created_by)
  values (p_agreement_id, p_agreement_version_id, v_hash, p_chain_root,
          p_event_count, coalesce((p_verification->>'ok')::boolean, false), p_verification, auth.uid())
  on conflict (agreement_id, chain_root) do update set verification = excluded.verification
  returning id into v_id;

  return v_id;
end $$;

revoke all on function record_evidence_package(uuid, uuid, text, integer, jsonb) from anon;
grant execute on function record_evidence_package(uuid, uuid, text, integer, jsonb) to authenticated;

-- --------------------------------------------------------- grants / hygiene --
revoke all on table evidence_packages from anon;
revoke all on table data_subject_requests from anon;
grant select on table evidence_packages to authenticated;
grant select, insert on table data_subject_requests to authenticated;
-- No update/delete grants: package rows are immutable and a data-subject
-- request's progression is recorded by the console's audited path, not by the
-- requester and not by a direct table write.

comment on function record_signature_event(uuid, uuid, text, text, text, text) is
  'The signing transaction. Locks the agreement, re-derives the version, party, signing order and completion state from stored rows, writes the consent and signature events, freezes and stamps on completion, and appends every step to the audit chain. Returns findings, never a legal conclusion.';
