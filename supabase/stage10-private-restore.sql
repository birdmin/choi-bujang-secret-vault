-- Stage 10: private virtual-memo recovery source and audit append table.
-- Run in Supabase SQL Editor only after reviewing the table names and schema.
-- No real student records belong in either table.

create table if not exists public.private_memo_snapshots (
  memo_id uuid primary key,
  owner_id uuid not null,
  title text not null,
  body text not null,
  content_sha256 text not null check (content_sha256 ~ '^[a-f0-9]{64}$'),
  test_identity text not null check (test_identity = 'b'),
  created_at timestamptz not null default now()
);

alter table public.private_memo_snapshots enable row level security;
revoke all on table public.private_memo_snapshots from public, anon, authenticated;

create table if not exists public.memo_restore_audit (
  id bigint generated always as identity primary key,
  memo_id uuid not null,
  owner_id uuid not null,
  content_sha256 text not null check (content_sha256 ~ '^[a-f0-9]{64}$'),
  snapshot_source text not null check (snapshot_source = 'private_memo_snapshots'),
  test_identity text not null check (test_identity = 'b'),
  event text not null check (event = 'single_virtual_memo_restored'),
  created_at timestamptz not null default now()
);

alter table public.memo_restore_audit enable row level security;
revoke all on table public.memo_restore_audit from public, anon, authenticated;

-- The endpoint uses the server-only SUPABASE_SECRET_KEY. Never expose it to a browser.
-- Populate private_memo_snapshots with ONE synthetic B-owned test memo, its UUID owner_id,
-- and SHA-256 of the exact UTF-8 body. Do not copy actual student content.
