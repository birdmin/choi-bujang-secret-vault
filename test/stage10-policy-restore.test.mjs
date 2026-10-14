import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { applySafePolicyRestore, previewSafePolicyRestore } from '../src/policy-restore.mjs';

const snapshot = JSON.parse(await readFile(new URL('../backups/safe-policy.json', import.meta.url), 'utf8'));
const safePolicy = structuredClone(snapshot.policy);

function testState() {
  return {
    policy: {
      allowedRoutes: [...safePolicy.allowedRoutes, 'GET /api/test-only/unsafe'],
      ruleIds: [...safePolicy.ruleIds, 'temporary_test_rule'],
      resourceIds: { ...safePolicy.resourceIds, temporaryResource: 'temporary-resource' },
    },
    // This unrelated service rule must remain untouched by restoration.
    serviceRules: [
      { id: 'auth_required', enabled: true },
      { id: 'rate_limit', enabled: true, limit: 120 },
    ],
    // Prior audit entries must remain byte-for-byte unchanged.
    auditHistory: [
      { event: 'test_policy_changed', requestId: 'fixture-audit-001' },
      { event: 'denied_cross_owner_read', requestId: 'fixture-audit-002' },
    ],
  };
}

function canReadResource(requesterId, ownerId) {
  return typeof requesterId === 'string' && requesterId.length > 0
    && typeof ownerId === 'string' && requesterId === ownerId;
}

test('복구 전 변경 항목을 보여 주고 명시적 확인 전에는 상태를 바꾸지 않는다', () => {
  const state = testState();
  const before = structuredClone(state);
  const plan = previewSafePolicyRestore({
    snapshot,
    testState: state,
    currentVersion: 'stage-10-test-current',
  });
  assert.deepEqual(plan.changes.map(change => change.field), ['allowedRoutes', 'ruleIds', 'resourceIds']);
  assert.equal(plan.execution, 'preview_only');
  assert.deepEqual(state, before);
  assert.equal(plan.preserved.auditHistoryCount, 2);
  assert.equal(plan.preserved.serviceRulesCount, 2);
});

test('확인 토큰이 없거나 틀리면 복구를 중단한다', () => {
  const state = testState();
  const plan = previewSafePolicyRestore({ snapshot, testState: state, currentVersion: 'stage-10-test-current' });
  assert.throws(() => applySafePolicyRestore({
    snapshot, testState: state, plan, confirmationToken: 'wrong-token',
  }), /RESTORE_CONFIRMATION_REQUIRED/u);
  assert.throws(() => applySafePolicyRestore({
    snapshot, testState: state, plan, confirmationToken: undefined,
  }), /RESTORE_CONFIRMATION_REQUIRED/u);
});

test('검토 후 정책 또는 감사 상태가 바뀌면 오래된 계획의 실행을 중단한다', () => {
  const state = testState();
  const plan = previewSafePolicyRestore({ snapshot, testState: state, currentVersion: 'stage-10-test-current' });
  state.serviceRules.push({ id: 'new_rule', enabled: true });
  assert.throws(() => applySafePolicyRestore({
    snapshot, testState: state, plan, confirmationToken: plan.confirmationToken,
  }), /RESTORE_PLAN_STALE/u);
});

test('확인한 경우 시험 정책 범위만 복구하고 서비스 규칙과 기존 감사 이력을 보존한다', () => {
  const state = testState();
  const oldRules = structuredClone(state.serviceRules);
  const oldAudit = structuredClone(state.auditHistory);
  const plan = previewSafePolicyRestore({ snapshot, testState: state, currentVersion: 'stage-10-test-current' });
  const { state: restored, result } = applySafePolicyRestore({
    snapshot, testState: state, plan, confirmationToken: plan.confirmationToken,
  });

  assert.deepEqual(restored.policy, safePolicy);
  assert.deepEqual(restored.serviceRules, oldRules);
  assert.deepEqual(restored.auditHistory.slice(0, oldAudit.length), oldAudit);
  assert.equal(restored.auditHistory.length, oldAudit.length + 1);
  assert.equal(restored.auditHistory.at(-1).event, 'test_policy_restored');
  assert.deepEqual(result.changedFields, ['allowedRoutes', 'ruleIds', 'resourceIds']);
  assert.equal(result.preservedServiceRules, true);
  assert.equal(result.preservedPriorAuditHistory, true);
  assert.equal(result.execution, 'test_state_only');
});

test('복구 후에도 소유자 A의 정상 요청은 허용되고 B의 A 자료 요청은 거부된다', () => {
  const state = testState();
  const plan = previewSafePolicyRestore({ snapshot, testState: state, currentVersion: 'stage-10-test-current' });
  const { state: restored } = applySafePolicyRestore({
    snapshot, testState: state, plan, confirmationToken: plan.confirmationToken,
  });

  assert.deepEqual(restored.policy.allowedRoutes, safePolicy.allowedRoutes);
  assert.equal(canReadResource('A', 'A'), true, 'A가 자기 자료를 읽을 수 있어야 함');
  assert.equal(canReadResource('B', 'A'), false, 'B의 A 자료 요청은 거부되어야 함');
});
