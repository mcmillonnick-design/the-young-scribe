-- The Young Scribe v2 — multi-family schema.
-- Runs in the SAME Supabase project as v1 (no new project needed).
-- All v2 objects are namespaced with a v2_ prefix so they don't touch or
-- conflict with the existing profiles/app_config tables. Run this once in
-- the SQL Editor. Safe to run before the live app is cut over to v2 —
-- nothing here is referenced by the current live site.

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------------
-- Tables
-- ---------------------------------------------------------------------

-- Single-use codes you generate and hand out to friends.
create table if not exists v2_invite_codes (
  code text primary key,
  note text,
  used_by uuid references auth.users(id),
  used_at bigint,
  created_at bigint not null
);

-- One row per family, keyed by the parent's Supabase Auth user id.
create table if not exists v2_families (
  id uuid primary key references auth.users(id) on delete cascade,
  family_name text not null,
  admin_pin text not null,
  is_owner boolean not null default false,
  created_at bigint not null
);

-- Kid sub-profiles. username is unique across the WHOLE platform, so a kid
-- can log in from the shared homepage with no family-specific link.
create table if not exists v2_kids (
  id uuid primary key default gen_random_uuid(),
  family_id uuid not null references v2_families(id) on delete cascade,
  username text not null unique,
  password_hash text not null,
  name text not null,
  avatar text not null,
  progress jsonb not null default '{}'::jsonb,
  log jsonb not null default '[]'::jsonb,
  created_at bigint not null,
  updated_at bigint not null
);

-- Short-lived tokens issued on kid login, so a kid's browser can resume
-- their session and record results without re-entering a password every
-- time, and so writes can be tied to a real prior login instead of a
-- guessable id.
create table if not exists v2_kid_sessions (
  token text primary key,
  kid_id uuid not null references v2_kids(id) on delete cascade,
  created_at bigint not null,
  expires_at bigint not null
);

-- ---------------------------------------------------------------------
-- Row Level Security
-- ---------------------------------------------------------------------
-- Parents interact with v2_families/v2_kids directly as their authenticated
-- selves — RLS scopes every row to auth.uid(). Kids never authenticate via
-- Supabase Auth at all, so every kid-facing action goes through a narrow
-- SECURITY DEFINER function below instead of direct table access; the
-- underlying tables (and invite codes, and sessions) have RLS enabled with
-- NO policies for anon/authenticated, meaning direct access is denied by
-- default and only these functions (which run with elevated privilege) can
-- reach them.

alter table v2_invite_codes enable row level security;
alter table v2_kid_sessions enable row level security;

alter table v2_families enable row level security;
create policy "family reads own row" on v2_families for select using (auth.uid() = id);
create policy "family updates own row" on v2_families for update using (auth.uid() = id) with check (auth.uid() = id);
-- No insert/delete policy: a family row is created only via v2_complete_signup below.

alter table v2_kids enable row level security;
create policy "parent reads own kids" on v2_kids for select using (auth.uid() = family_id);
create policy "parent inserts own kids" on v2_kids for insert with check (auth.uid() = family_id);
create policy "parent updates own kids" on v2_kids for update using (auth.uid() = family_id) with check (auth.uid() = family_id);
create policy "parent deletes own kids" on v2_kids for delete using (auth.uid() = family_id);

-- ---------------------------------------------------------------------
-- Functions
-- ---------------------------------------------------------------------

-- Call right after supabase.auth.signUp() + sign-in succeeds, to spend an
-- invite code and create the family row. Atomic: the UPDATE ... WHERE
-- used_by IS NULL only ever succeeds for one caller per code.
create or replace function v2_complete_signup(p_invite_code text, p_family_name text, p_admin_pin text)
returns void
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_uid uuid := auth.uid();
  v_now bigint := (extract(epoch from now()) * 1000)::bigint;
begin
  if v_uid is null then
    raise exception 'Not authenticated';
  end if;
  if exists (select 1 from v2_families where id = v_uid) then
    raise exception 'This account already has a family';
  end if;

  update v2_invite_codes set used_by = v_uid, used_at = v_now
    where code = p_invite_code and used_by is null;
  if not found then
    raise exception 'That invite code is invalid or already used';
  end if;

  insert into v2_families (id, family_name, admin_pin, created_at)
    values (v_uid, p_family_name, p_admin_pin, v_now);
end;
$$;

-- Only a family flagged is_owner may mint new invite codes.
create or replace function v2_generate_invite_code(p_note text)
returns text
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_uid uuid := auth.uid();
  v_code text;
begin
  if not exists (select 1 from v2_families where id = v_uid and is_owner) then
    raise exception 'Not authorized';
  end if;
  v_code := upper(substr(encode(gen_random_bytes(5), 'hex'), 1, 8));
  insert into v2_invite_codes (code, note, created_at)
    values (v_code, p_note, (extract(epoch from now()) * 1000)::bigint);
  return v_code;
end;
$$;

-- List invite codes for the owner console (owner-only).
create or replace function v2_list_invite_codes()
returns table(code text, note text, used_by uuid, used_at bigint, created_at bigint)
language plpgsql
security definer
set search_path = public, extensions
as $$
begin
  if not exists (select 1 from v2_families where id = auth.uid() and is_owner) then
    raise exception 'Not authorized';
  end if;
  return query select c.code, c.note, c.used_by, c.used_at, c.created_at
    from v2_invite_codes c order by c.created_at desc;
end;
$$;

-- Create a kid under the calling (authenticated) parent's own family.
-- SECURITY INVOKER (the default) — RLS's insert policy on v2_kids already
-- restricts this to the caller's own family_id.
create or replace function v2_create_kid(p_username text, p_password text, p_name text, p_avatar text)
returns uuid
language plpgsql
security invoker
set search_path = public, extensions
as $$
declare
  v_id uuid := gen_random_uuid();
  v_now bigint := (extract(epoch from now()) * 1000)::bigint;
begin
  insert into v2_kids (id, family_id, username, password_hash, name, avatar, created_at, updated_at)
    values (v_id, auth.uid(), lower(trim(p_username)), crypt(p_password, gen_salt('bf')), p_name, p_avatar, v_now, v_now);
  return v_id;
end;
$$;

-- Reset a kid's password (parent-only, own kids only via RLS on the UPDATE).
create or replace function v2_set_kid_password(p_kid_id uuid, p_new_password text)
returns void
language plpgsql
security invoker
set search_path = public, extensions
as $$
begin
  update v2_kids set password_hash = crypt(p_new_password, gen_salt('bf')), updated_at = (extract(epoch from now()) * 1000)::bigint
    where id = p_kid_id;
  if not found then
    raise exception 'Kid not found or not yours';
  end if;
end;
$$;

-- Kid login: verify credentials, issue a session token, return everything
-- the app needs to run — never the password hash.
create or replace function v2_kid_login(p_username text, p_password text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_kid v2_kids;
  v_token text;
  v_now bigint := (extract(epoch from now()) * 1000)::bigint;
begin
  select * into v_kid from v2_kids where username = lower(trim(p_username));
  if not found or crypt(p_password, v_kid.password_hash) <> v_kid.password_hash then
    return null;
  end if;
  v_token := encode(gen_random_bytes(24), 'hex');
  insert into v2_kid_sessions (token, kid_id, created_at, expires_at)
    values (v_token, v_kid.id, v_now, v_now + 30::bigint * 24 * 60 * 60 * 1000);
  return jsonb_build_object(
    'token', v_token, 'kidId', v_kid.id, 'familyId', v_kid.family_id,
    'username', v_kid.username, 'name', v_kid.name, 'avatar', v_kid.avatar,
    'progress', v_kid.progress, 'log', v_kid.log
  );
end;
$$;

-- Resume a saved session (page reload) without re-entering a password.
create or replace function v2_kid_resume(p_token text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_kid v2_kids;
  v_now bigint := (extract(epoch from now()) * 1000)::bigint;
begin
  select k.* into v_kid from v2_kids k
    join v2_kid_sessions s on s.kid_id = k.id
    where s.token = p_token and s.expires_at > v_now;
  if not found then return null; end if;
  return jsonb_build_object(
    'token', p_token, 'kidId', v_kid.id, 'familyId', v_kid.family_id,
    'username', v_kid.username, 'name', v_kid.name, 'avatar', v_kid.avatar,
    'progress', v_kid.progress, 'log', v_kid.log
  );
end;
$$;

-- Record a lesson result for the session holder only.
create or replace function v2_kid_record_result(
  p_token text, p_lesson_id text, p_lesson_title text,
  p_stars int, p_wpm int, p_acc int, p_refs jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_kid_id uuid;
  v_progress jsonb;
  v_log jsonb;
  v_prev jsonb;
  v_merged jsonb;
  v_now bigint := (extract(epoch from now()) * 1000)::bigint;
begin
  select kid_id into v_kid_id from v2_kid_sessions where token = p_token and expires_at > v_now;
  if not found then raise exception 'Session expired — please log in again'; end if;

  select progress, log into v_progress, v_log from v2_kids where id = v_kid_id;
  v_prev := coalesce(v_progress -> p_lesson_id, jsonb_build_object('stars',0,'bestWpm',0,'bestAccuracy',0));
  v_merged := jsonb_build_object(
    'stars', greatest((v_prev->>'stars')::int, p_stars),
    'bestWpm', greatest((v_prev->>'bestWpm')::int, p_wpm),
    'bestAccuracy', greatest((v_prev->>'bestAccuracy')::int, p_acc)
  );
  v_progress := coalesce(v_progress, '{}'::jsonb) || jsonb_build_object(p_lesson_id, v_merged);
  v_log := coalesce(v_log, '[]'::jsonb) || jsonb_build_array(jsonb_build_object(
    'lessonId', p_lesson_id, 'lessonTitle', p_lesson_title, 'stars', p_stars,
    'wpm', p_wpm, 'acc', p_acc, 'refs', coalesce(p_refs, '[]'::jsonb), 'at', v_now
  ));
  if jsonb_array_length(v_log) > 40 then
    v_log := (
      select jsonb_agg(elem order by ord)
      from jsonb_array_elements(v_log) with ordinality as t(elem, ord)
      where ord > jsonb_array_length(v_log) - 40
    );
  end if;

  update v2_kids set progress = v_progress, log = v_log, updated_at = v_now where id = v_kid_id;
  return v_merged;
end;
$$;

-- Family-scoped leaderboard, resolved from the kid's own session token.
create or replace function v2_kid_leaderboard(p_token text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_family_id uuid;
  v_now bigint := (extract(epoch from now()) * 1000)::bigint;
begin
  select k.family_id into v_family_id from v2_kid_sessions s
    join v2_kids k on k.id = s.kid_id
    where s.token = p_token and s.expires_at > v_now;
  if not found then raise exception 'Session expired — please log in again'; end if;

  return (select coalesce(jsonb_agg(jsonb_build_object(
      'id', id, 'name', name, 'avatar', avatar, 'progress', progress
    )), '[]'::jsonb) from v2_kids where family_id = v_family_id);
end;
$$;

-- Parent-side family-scoped leaderboard + progress dashboard use the same
-- shape and can just query v2_kids directly (RLS already scopes it).

-- ---------------------------------------------------------------------
-- Explicit execute grants (belt-and-suspenders — Postgres grants EXECUTE
-- to PUBLIC by default, but some Supabase projects tighten that).
-- ---------------------------------------------------------------------
grant execute on function v2_kid_login(text, text) to anon, authenticated;
grant execute on function v2_kid_resume(text) to anon, authenticated;
grant execute on function v2_kid_record_result(text, text, text, int, int, int, jsonb) to anon, authenticated;
grant execute on function v2_kid_leaderboard(text) to anon, authenticated;
grant execute on function v2_complete_signup(text, text, text) to authenticated;
grant execute on function v2_create_kid(text, text, text, text) to authenticated;
grant execute on function v2_set_kid_password(uuid, text) to authenticated;
grant execute on function v2_generate_invite_code(text) to authenticated;
grant execute on function v2_list_invite_codes() to authenticated;
