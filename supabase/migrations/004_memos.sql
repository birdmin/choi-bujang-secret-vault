create table if not exists public.memos (
  id uuid primary key,
  owner_id uuid not null references auth.users(id) on delete cascade,
  title text not null,
  body text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.memos enable row level security;

revoke all on public.memos from anon, authenticated;
grant all on public.memos to service_role;
