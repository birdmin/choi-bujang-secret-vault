import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { resolve, join } from 'node:path';
import { diffSafePolicy } from '../src/policy-diff.mjs';

const root = resolve(import.meta.dirname, '..');

try {
  let snapshot;
  try {
    snapshot = JSON.parse(await readFile(join(root, 'backups', 'safe-policy.json'), 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') throw new Error('SAFE_POLICY_SNAPSHOT_MISSING');
    if (error instanceof SyntaxError) throw new Error('SAFE_POLICY_SNAPSHOT_INVALID_JSON');
    throw error;
  }

  const config = JSON.parse(await readFile(join(root, 'aleph.config.json'), 'utf8'));
  const { RULE_IDS } = await import(pathToFileURL(join(root, 'src', 'decider.mjs')).href);
  const { RESOURCE_IDS } = await import(pathToFileURL(join(root, 'src', 'resource-ids.mjs')).href);
  const preview = diffSafePolicy({
    snapshot,
    currentPolicy: {
      allowedRoutes: config.allowedRoutes,
      ruleIds: RULE_IDS,
      resourceIds: RESOURCE_IDS,
    },
    currentVersion: `stage-${config.step}-current`,
  });

  process.stdout.write('복구 실행 전 정책 차이 미리보기 (실제 정책 변경 없음)\n');
  process.stdout.write(`기준 버전: ${preview.snapshotVersion} · 기준 커밋: ${preview.snapshotCommit}\n`);
  process.stdout.write(`현재 시험 버전: ${preview.currentVersion}\n`);
  process.stdout.write(`검사 범위: ${preview.scope.join(', ')}\n`);
  if (preview.changes.length === 0) {
    process.stdout.write('차이: 없음\n');
  } else {
    process.stdout.write('변경된 항목만 표시합니다:\n');
    process.stdout.write(`${JSON.stringify(preview.changes, null, 2)}\n`);
  }
  process.stdout.write('상태: 미리보기 전용 · 복원/운영 정책 변경은 실행하지 않음\n');
} catch (error) {
  process.stderr.write(`정책 차이 확인 중단: ${error.message}\n`);
  process.exitCode = 1;
}
