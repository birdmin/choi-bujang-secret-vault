revoke all on table public.memos from public, anon, authenticated;

grant select, insert, update, delete
on table public.memos
to authenticated;

alter table public.memos enable row level security;

drop policy if exists "memos_select_own" on public.memos;
drop policy if exists "memos_insert_own" on public.memos;
drop policy if exists "memos_update_own" on public.memos;
drop policy if exists "memos_delete_own" on public.memos;

create policy "memos_select_own"
on public.memos
for select
to authenticated
using (auth.uid() = owner_id);

create policy "memos_insert_own"
on public.memos
for insert
to authenticated
with check (auth.uid() = owner_id);

create policy "memos_update_own"
on public.memos
for update
to authenticated
using (auth.uid() = owner_id)
with check (auth.uid() = owner_id);

create policy "memos_delete_own"
on public.memos
for delete
to authenticated
using (auth.uid() = owner_id);
