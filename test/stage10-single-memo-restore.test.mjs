import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

const route = await readFile(new URL('../api/restore-memo.js', import.meta.url), 'utf8');
const migration = await readFile(new URL('../supabase/stage10-private-restore.sql', import.meta.url), 'utf8');
const digest = value => createHash('sha256').update(value, 'utf8').digest('hex');

test('restore endpoint is POST-only, B-test-identity-only and uses private snapshot', () => {
  assert.match(route, /request\.method !== 'POST'/u);
  assert.match(route, /identity\.kind !== 'judge' \|\| identity\.identity !== 'b'/u);
  assert.match(route, /from\('private_memo_snapshots'\)/u);
  assert.match(route, /\.eq\('test_identity', 'b'\)/u);
});

test('restore compares ID, owner and SHA-256 before accepting the result', () => {
  assert.match(route, /\.eq\('memo_id', memoId\)/u);
  assert.match(route, /current\.owner_id !== snapshot\.owner_id/u);
  assert.match(route, /sha256\(snapshot\.body\)/u);
  assert.match(route, /restored\.id !== snapshot\.memo_id/u);
  assert.match(route, /sha256\(restored\.body\)/u);
});

test('restore writes one target and appends an audit row without delete/truncate logic', () => {
  assert.match(route, /\.eq\('id', snapshot\.memo_id\)/u);
  assert.match(route, /\.eq\('owner_id', snapshot\.owner_id\)/u);
  assert.match(route, /from\('memo_restore_audit'\)\.insert/u);
  assert.doesNotMatch(route, /\.delete\(|truncate\s+table/iu);
});

test('private snapshot and audit tables are not granted to public client roles', () => {
  assert.match(migration, /alter table public\.private_memo_snapshots enable row level security/iu);
  assert.match(migration, /revoke all on table public\.private_memo_snapshots from public, anon, authenticated/iu);
  assert.match(migration, /revoke all on table public\.memo_restore_audit from public, anon, authenticated/iu);
});

test('SHA-256 fixture is stable for a synthetic body', () => {
  assert.equal(digest('synthetic B memo only'), digest('synthetic B memo only'));
  assert.match(digest('synthetic B memo only'), /^[a-f0-9]{64}$/u);
});
