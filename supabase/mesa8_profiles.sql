-- MESA 8: cuentas con nombre de usuario y contraseña, sin correos ficticios.
-- Ejecuta este archivo una sola vez en Supabase > SQL Editor.
-- No se conceden permisos de acceso directo a anon/authenticated.
-- La Edge Function mesa8-account es la única que lee y modifica estas tablas.

create table if not exists public.mesa8_accounts (
  id uuid primary key default gen_random_uuid(),
  username text not null check (char_length(username) between 3 and 18),
  username_key text not null unique,
  password_salt text not null,
  password_hash text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.mesa8_sessions (
  id uuid primary key default gen_random_uuid(),
  account_id uuid not null references public.mesa8_accounts(id) on delete cascade,
  token_hash text not null unique,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);

create index if not exists mesa8_sessions_account_id_idx
  on public.mesa8_sessions(account_id);
create index if not exists mesa8_sessions_expires_at_idx
  on public.mesa8_sessions(expires_at);

create table if not exists public.mesa8_profiles (
  account_id uuid primary key references public.mesa8_accounts(id) on delete cascade,
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

alter table public.mesa8_accounts enable row level security;
alter table public.mesa8_sessions enable row level security;
alter table public.mesa8_profiles enable row level security;

revoke all on public.mesa8_accounts from anon, authenticated;
revoke all on public.mesa8_sessions from anon, authenticated;
revoke all on public.mesa8_profiles from anon, authenticated;

grant all on public.mesa8_accounts to service_role;
grant all on public.mesa8_sessions to service_role;
grant all on public.mesa8_profiles to service_role;
