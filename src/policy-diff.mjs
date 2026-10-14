import { createHash, timingSafeEqual } from 'node:crypto';

const SNAPSHOT_SCHEMA = 'aleph.safe-policy-snapshot.v1';
const POLICY_FIELDS = Object.freeze(['allowedRoutes', 'ruleIds', 'resourceIds']);

function digestPayload(snapshot) {
  return JSON.stringify({
    schema: snapshot.schema,
    version: snapshot.version,
    sourceCommit: snapshot.sourceCommit,
    scope: snapshot.scope,
    policy: snapshot.policy,
  });
}

function sha256(value) {
  return createHash('sha256').update(value, 'utf8').digest();
}

function equalDigest(actualHex, expectedHex) {
  if (typeof actualHex !== 'string' || !/^[a-f0-9]{64}$/u.test(actualHex)) return false;
  const actual = Buffer.from(actualHex, 'hex');
  const expected = Buffer.from(expectedHex, 'hex');
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

function validatePolicy(policy, label) {
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) {
    throw new Error(`${label}_POLICY_INVALID`);
  }
  if (Object.keys(policy).sort().join(',') !== [...POLICY_FIELDS].sort().join(',')) {
    throw new Error(`${label}_POLICY_SCOPE_INVALID`);
  }
  if (!Array.isArray(policy.allowedRoutes)
    || policy.allowedRoutes.some(value => typeof value !== 'string' || !value.trim())
    || !Array.isArray(policy.ruleIds)
    || policy.ruleIds.some(value => typeof value !== 'string' || !value.trim())
    || !policy.resourceIds || typeof policy.resourceIds !== 'object'
    || Array.isArray(policy.resourceIds)
    || Object.values(policy.resourceIds).some(value => typeof value !== 'string' || !value.trim())) {
    throw new Error(`${label}_POLICY_INVALID`);
  }
}

export function verifySafePolicySnapshot(snapshot) {
  if (!snapshot || typeof snapshot !== 'object' || Array.isArray(snapshot)) {
    throw new Error('SAFE_POLICY_SNAPSHOT_MISSING');
  }
  if (snapshot.schema !== SNAPSHOT_SCHEMA
    || typeof snapshot.version !== 'string' || !snapshot.version.trim()
    || typeof snapshot.sourceCommit !== 'string' || !/^[a-f0-9]{40}$/u.test(snapshot.sourceCommit)
    || !Array.isArray(snapshot.scope)
    || snapshot.scope.join(',') !== POLICY_FIELDS.join(',')
    || typeof snapshot.sha256 !== 'string') {
    throw new Error('SAFE_POLICY_SNAPSHOT_INVALID');
  }
  validatePolicy(snapshot.policy, 'SAFE_SNAPSHOT');

  const expected = sha256(digestPayload(snapshot));
  if (!equalDigest(snapshot.sha256, expected.toString('hex'))) {
    throw new Error('SAFE_POLICY_SNAPSHOT_CHECKSUM_FAILED');
  }
  return true;
}

export function diffSafePolicy({ snapshot, currentPolicy, currentVersion }) {
  verifySafePolicySnapshot(snapshot);
  validatePolicy(currentPolicy, 'CURRENT');
  if (typeof currentVersion !== 'string' || !currentVersion.trim()) {
    throw new Error('CURRENT_POLICY_VERSION_REQUIRED');
  }

  const changes = [];
  for (const field of snapshot.scope) {
    const before = snapshot.policy[field];
    const after = currentPolicy[field];
    if (JSON.stringify(before) !== JSON.stringify(after)) {
      changes.push({ field, before, after });
    }
  }

  return {
    snapshotVersion: snapshot.version,
    snapshotCommit: snapshot.sourceCommit,
    currentVersion,
    scope: [...snapshot.scope],
    changes,
    execution: 'preview_only',
  };
}
