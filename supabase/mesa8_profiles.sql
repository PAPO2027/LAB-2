-- MESA 8: perfil y progreso persistente por cuenta de jugador.
-- Ejecuta este archivo una sola vez en Supabase > SQL Editor.

create table if not exists public.mesa8_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  username text not null,
  username_key text not null unique,
  wins integer not null default 0 check (wins >= 0),
  losses integer not null default 0 check (losses >= 0),
  coins integer not null default 120 check (coins >= 0),
  played integer not null default 0 check (played >= 0),
  potted integer not null default 0 check (potted >= 0),
  owned text[] not null default array['wood','cobalt','carbon']::text[],
  cue_id text not null default 'wood',
  skin text not null default 'red',
  updated_at timestamptz not null default now()
);

alter table public.mesa8_profiles enable row level security;

grant select, insert, update on public.mesa8_profiles to authenticated;

drop policy if exists "Players can read their own MESA 8 profile"
  on public.mesa8_profiles;
create policy "Players can read their own MESA 8 profile"
  on public.mesa8_profiles
  for select
  to authenticated
  using ((select auth.uid()) = user_id);

drop policy if exists "Players can create their own MESA 8 profile"
  on public.mesa8_profiles;
create policy "Players can create their own MESA 8 profile"
  on public.mesa8_profiles
  for insert
  to authenticated
  with check ((select auth.uid()) = user_id);

drop policy if exists "Players can update their own MESA 8 profile"
  on public.mesa8_profiles;
create policy "Players can update their own MESA 8 profile"
  on public.mesa8_profiles
  for update
  to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);
