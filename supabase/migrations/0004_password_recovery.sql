-- ---------------------------------------------------------------------------
-- agre-e · 0004 · Password recovery: tokens, single use, and the ledger trail
--
-- 0002 gave the console the *ability to ask* for a password reset. This
-- migration gives the product somewhere for that request to live and a way for
-- the account holder to complete it.
--
-- Design rules, stated where they are hardest to break:
--   * a recovery token is stored as a digest, never as itself — a dump of this
--     table yields nothing that can be replayed, so the operator who issues a
--     link cannot later use it, and neither can anyone who reads the database;
--   * a token is single-use and expiring. Consuming it is an UPDATE, so the
--     window in which the same link could be spent twice is closed by the
--     database rather than by the application's good manners;
--   * completing a recovery never touches agreement content. Evidence tables
--     are untouched by this file, deliberately: a credential event is not an
--     agreement event and must never appear in a contract's timeline;
--   * nobody in any console role has a policy on this table. The console writes
--     through the service role after authorize(), and the account holder spends
--     the token through the app; no browser session can enumerate or alter it.
-- ---------------------------------------------------------------------------

create table if not exists password_recovery_requests (
  -- App-generated (`prr_<uuid>`) so the demo backend and Postgres agree on the
  -- identifier the console's audit row references. See lib/data/types.ts newId().
  id text primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  -- sha256('agree-e:recovery:' || token). Domain-separated in lib/crypto/hash.ts
  -- so a digest here can never collide with the same value hashed elsewhere.
  token_hash text not null unique,
  -- The operator who caused the link to exist. Null for a self-service flow,
  -- where nobody privileged was involved — a distinction worth preserving.
  issued_by uuid references auth.users(id) on delete set null,
  delivery text not null check (delivery in ('email','copy')),
  reason text,
  issued_at timestamptz not null default now(),
  expires_at timestamptz not null,
  consumed_at timestamptz,
  ip_hash text,
  user_agent text,
  -- A link that never expires is a permanent skeleton key in an inbox.
  constraint recovery_expiry_is_short check (expires_at <= issued_at + interval '24 hours')
);

create index if not exists password_recovery_user_idx
  on password_recovery_requests(user_id, consumed_at);
create index if not exists password_recovery_open_idx
  on password_recovery_requests(expires_at) where consumed_at is null;

comment on table password_recovery_requests is
  'Single-use password recovery tokens. Only the digest is stored: no read of this table — by an operator, a support agent or an engineer — can yield a usable credential.';
comment on column token_hash is
  'sha256 of the raw token. The raw value exists only in the link handed to the account holder and in their browser.';

-- ------------------------------------------------------------------ consume --
-- Spending a token is one statement, so two submissions racing on the same link
-- cannot both succeed: the second sees consumed_at already set and is refused.
create or replace function consume_recovery_token(p_token_hash text, p_ip_hash text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_row password_recovery_requests;
  v_closed integer;
begin
  update password_recovery_requests
     set consumed_at = now()
   where token_hash = p_token_hash
     and consumed_at is null
     and expires_at > now()
  returning * into v_row;

  if v_row.id is null then
    -- Distinguish the three failures for the log, but return one shape. The
    -- caller does not need to tell a user which of them applied.
    return jsonb_build_object(
      'ok', false,
      'error', case
        when exists (select 1 from password_recovery_requests where token_hash = p_token_hash and consumed_at is not null)
          then 'already_used'
        when exists (select 1 from password_recovery_requests where token_hash = p_token_hash)
          then 'expired'
        else 'unknown_token'
      end
    );
  end if;

  -- Every other outstanding link for this account dies with this one: a
  -- forgotten email sitting in an inbox must not stay a way back in.
  with others as (
    update password_recovery_requests
       set consumed_at = now()
     where user_id = v_row.user_id
       and consumed_at is null
    returning 1
  )
  select count(*) into v_closed from others;

  -- Sessions are terminated at the provider (GoTrue admin logout) by the
  -- application, which holds the service key; this row is the record that the
  -- account's credentials were reset through a link.
  insert into security_events (user_id, type, severity, detail, ip_hash, occurred_at)
  values (
    v_row.user_id,
    'password_recovery_completed',
    'notice',
    format('Recovery link completed; %s outstanding link(s) closed by the same act.', v_closed),
    p_ip_hash,
    now()
  );

  return jsonb_build_object(
    'ok', true,
    'user_id', v_row.user_id,
    'request_id', v_row.id,
    'issued_by', v_row.issued_by,
    -- Returned so the caller can also clear force_password_reset and record the
    -- password change against the profile, in the same request.
    'consumed_at', v_row.consumed_at
  );
end $$;

revoke all on function consume_recovery_token(text, text) from anon, authenticated;

-- --------------------------------------------------------------------- RLS --
alter table password_recovery_requests enable row level security;

-- No policy is created for anon or authenticated — deny by default, and mean it.
-- The account holder does not read this table either: they hold the raw token and
-- the app hashes it. Reading the table would be reading digests, which is
-- useless to them and dangerous to everyone else. The only two ways in are the
-- server-side service role (issue) and consume_recovery_token() above (spend).
revoke all on table password_recovery_requests from anon, authenticated;
