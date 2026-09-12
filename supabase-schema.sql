-- The Young Scribe — Supabase schema.
-- Run this once in your project's SQL Editor (Supabase dashboard → SQL Editor → New query → Run).

create table if not exists profiles (
  id text primary key,
  name text not null,
  avatar text not null,
  pin text not null,
  progress jsonb not null default '{}'::jsonb,
  log jsonb not null default '[]'::jsonb,
  created_at bigint not null,
  updated_at bigint not null
);

create table if not exists app_config (
  id text primary key,
  pin text,
  updated_at bigint
);

-- The Young Scribe has no user accounts of its own — kids log in with a
-- simple 4-digit PIN checked in the app's JavaScript, not through Supabase
-- Auth. That means Row Level Security can't tell "a kid's browser" apart
-- from anyone else on the internet who has your project's anon key, so
-- these policies are intentionally open on just the two tables this app
-- uses (nothing else in your project is exposed).
--
-- This is a proportionate, not bulletproof, security level for a small
-- private family app. Don't post the app's URL publicly or anywhere
-- search engines would index it, and you're fine.

alter table profiles enable row level security;
create policy "public select profiles" on profiles for select using (true);
create policy "public insert profiles" on profiles for insert with check (true);
create policy "public update profiles" on profiles for update using (true) with check (true);
create policy "public delete profiles" on profiles for delete using (true);

alter table app_config enable row level security;
create policy "public select config" on app_config for select using (true);
create policy "public insert config" on app_config for insert with check (true);
create policy "public update config" on app_config for update using (true) with check (true);
