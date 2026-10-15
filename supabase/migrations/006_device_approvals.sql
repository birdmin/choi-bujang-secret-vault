-- Stage 11: server-side device approval registry.
-- Device secrets are stored only as SHA-256 hashes; never store a browser private key here.
create table if not exists public.device_approvals (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  device_token_hash text not null unique
    check (device_token_hash ~ '^[0-9a-f]{64}$'),
  status text not null default 'pending'
    check (status in ('pending', 'approved', 'revoked')),
  requested_at timestamptz not null default now(),
  reviewed_at timestamptz,
  reviewed_by uuid references auth.users(id) on delete set null,
  constraint device_approvals_review_consistency
    check (
      (status = 'pending' and reviewed_at is null)
      or (status in ('approved', 'revoked') and reviewed_at is not null)
    )
);

create index if not exists device_approvals_owner_status_idx
  on public.device_approvals (owner_id, status);

alter table public.device_approvals enable row level security;
revoke all on table public.device_approvals from public, anon, authenticated;

-- The service-role API accesses this table server-side. Browser clients cannot
-- read, insert, approve, or revoke rows directly.
