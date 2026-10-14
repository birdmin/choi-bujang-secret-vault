import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { diffSafePolicy, verifySafePolicySnapshot } from '../src/policy-diff.mjs';

const snapshot = JSON.parse(await readFile(new URL('../backups/safe-policy.json', import.meta.url), 'utf8'));
const safePolicy = {
  allowedRoutes: [
    'GET /api/notes/:id',
    'GET /api/class-notices',
    'GET /api/class-notices/:id',
  ],
  ruleIds: [
    'device_registered',
    'step_up_required',
    'resource_route_allowed',
    'resource_route_denied',
  ],
  resourceIds: {
    studentMemos: 'student-memos',
    instructorNotices: 'instructor-notices',
  },
};

test('검증된 사본과 동일하면 차이만 빈 배열로 반환한다', () => {
  assert.equal(verifySafePolicySnapshot(snapshot), true);
  const result = diffSafePolicy({
    snapshot,
    currentPolicy: structuredClone(safePolicy),
    currentVersion: 'stage-9-current',
  });
  assert.deepEqual(result.changes, []);
  assert.equal(result.snapshotVersion, 'stage8-verified-2f6c695');
  assert.equal(result.currentVersion, 'stage-9-current');
  assert.deepEqual(result.scope, ['allowedRoutes', 'ruleIds', 'resourceIds']);
  assert.equal(result.execution, 'preview_only');
});

test('변경된 정책 항목만 차이에 포함한다', () => {
  const currentPolicy = structuredClone(safePolicy);
  currentPolicy.allowedRoutes = ['GET /api/notes/:id'];
  currentPolicy.ruleIds.push('unexpected_rule');
  const result = diffSafePolicy({ snapshot, currentPolicy, currentVersion: 'stage-9-test' });
  assert.deepEqual(result.changes.map(change => change.field), ['allowedRoutes', 'ruleIds']);
  assert.deepEqual(result.changes[0], {
    field: 'allowedRoutes',
    before: safePolicy.allowedRoutes,
    after: ['GET /api/notes/:id'],
  });
  assert.equal(result.changes.some(change => change.field === 'resourceIds'), false);
});

test('안전 정책 사본이 없으면 중단한다', () => {
  assert.throws(() => diffSafePolicy({
    snapshot: null,
    currentPolicy: safePolicy,
    currentVersion: 'stage-9-test',
  }), /SAFE_POLICY_SNAPSHOT_MISSING/u);
});

test('검증 해시가 맞지 않으면 중단한다', () => {
  const tampered = structuredClone(snapshot);
  tampered.policy.allowedRoutes.pop();
  assert.throws(() => diffSafePolicy({
    snapshot: tampered,
    currentPolicy: safePolicy,
    currentVersion: 'stage-9-test',
  }), /SAFE_POLICY_SNAPSHOT_CHECKSUM_FAILED/u);
});

test('현재 정책이 범위를 벗어나거나 버전이 없으면 중단한다', () => {
  assert.throws(() => diffSafePolicy({
    snapshot,
    currentPolicy: { ...safePolicy, adminBypass: true },
    currentVersion: 'stage-9-test',
  }), /CURRENT_POLICY_SCOPE_INVALID/u);
  assert.throws(() => diffSafePolicy({
    snapshot,
    currentPolicy: safePolicy,
    currentVersion: '',
  }), /CURRENT_POLICY_VERSION_REQUIRED/u);
});
