import { createHash } from 'node:crypto';
import { verifySafePolicySnapshot, diffSafePolicy } from './policy-diff.mjs';

const POLICY_FIELDS = Object.freeze(['allowedRoutes', 'ruleIds', 'resourceIds']);

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])]));
  }
  return value;
}

function fingerprint(value) {
  return createHash('sha256').update(JSON.stringify(stable(value)), 'utf8').digest('hex');
}

function clone(value) {
  return structuredClone(value);
}

function readPolicy(state) {
  if (!state || typeof state !== 'object' || !state.policy || typeof state.policy !== 'object') {
    throw new Error('TEST_POLICY_STATE_INVALID');
  }
  for (const field of POLICY_FIELDS) {
    if (!(field in state.policy)) throw new Error('TEST_POLICY_FIELD_MISSING');
  }
  if (!Array.isArray(state.auditHistory)) throw new Error('AUDIT_HISTORY_INVALID');
  if (!Array.isArray(state.serviceRules)) throw new Error('SERVICE_RULES_INVALID');
  return Object.fromEntries(POLICY_FIELDS.map(field => [field, clone(state.policy[field])]));
}

/**
 * Creates a review-only restore plan. This module mutates no files or operational policy.
 * The caller must display the plan and explicitly submit its confirmation token to apply it.
 */
export function previewSafePolicyRestore({ snapshot, testState, currentVersion }) {
  verifySafePolicySnapshot(snapshot);
  const currentPolicy = readPolicy(testState);
  const diff = diffSafePolicy({ snapshot, currentPolicy, currentVersion });
  const planPayload = {
    schema: 'aleph.policy-restore-plan.v1',
    snapshotVersion: snapshot.version,
    snapshotCommit: snapshot.sourceCommit,
    currentVersion,
    changes: diff.changes,
    currentPolicyFingerprint: fingerprint(currentPolicy),
    auditHistoryLength: testState.auditHistory.length,
    serviceRulesFingerprint: fingerprint(testState.serviceRules),
  };
  return {
    ...planPayload,
    confirmationToken: fingerprint(planPayload),
    execution: 'preview_only',
    preserved: {
      serviceRulesCount: testState.serviceRules.length,
      auditHistoryCount: testState.auditHistory.length,
    },
  };
}

/**
 * Applies a previously reviewed plan to an in-memory TEST policy state only.
 * Fails closed if the snapshot, plan, or current state changed since preview.
 */
export function applySafePolicyRestore({ snapshot, testState, plan, confirmationToken, actor = 'stage10-test-operator' }) {
  verifySafePolicySnapshot(snapshot);
  if (!plan || plan.schema !== 'aleph.policy-restore-plan.v1'
    || typeof confirmationToken !== 'string'
    || confirmationToken !== plan.confirmationToken
    || fingerprint({
      schema: plan.schema,
      snapshotVersion: plan.snapshotVersion,
      snapshotCommit: plan.snapshotCommit,
      currentVersion: plan.currentVersion,
      changes: plan.changes,
      currentPolicyFingerprint: plan.currentPolicyFingerprint,
      auditHistoryLength: plan.auditHistoryLength,
      serviceRulesFingerprint: plan.serviceRulesFingerprint,
    }) !== confirmationToken) {
    throw new Error('RESTORE_CONFIRMATION_REQUIRED');
  }
  if (plan.snapshotVersion !== snapshot.version || plan.snapshotCommit !== snapshot.sourceCommit) {
    throw new Error('RESTORE_SNAPSHOT_MISMATCH');
  }

  const currentPolicy = readPolicy(testState);
  if (fingerprint(currentPolicy) !== plan.currentPolicyFingerprint
    || testState.auditHistory.length !== plan.auditHistoryLength
    || fingerprint(testState.serviceRules) !== plan.serviceRulesFingerprint) {
    throw new Error('RESTORE_PLAN_STALE');
  }

  const actualDiff = diffSafePolicy({ snapshot, currentPolicy, currentVersion: plan.currentVersion });
  if (JSON.stringify(actualDiff.changes) !== JSON.stringify(plan.changes)) {
    throw new Error('RESTORE_PLAN_CHANGED');
  }

  const nextState = clone(testState);
  for (const field of POLICY_FIELDS) nextState.policy[field] = clone(snapshot.policy[field]);
  // Preserve all existing audit records and append a new record rather than rewriting history.
  nextState.auditHistory.push({
    event: 'test_policy_restored',
    snapshotVersion: snapshot.version,
    snapshotCommit: snapshot.sourceCommit,
    changedFields: plan.changes.map(change => change.field),
    actor,
    scope: [...snapshot.scope],
  });

  return {
    state: nextState,
    result: {
      restoredVersion: snapshot.version,
      changedFields: plan.changes.map(change => change.field),
      preservedServiceRules: fingerprint(nextState.serviceRules) === plan.serviceRulesFingerprint,
      preservedPriorAuditHistory: JSON.stringify(nextState.auditHistory.slice(0, plan.auditHistoryLength))
        === JSON.stringify(testState.auditHistory),
      execution: 'test_state_only',
    },
  };
}
