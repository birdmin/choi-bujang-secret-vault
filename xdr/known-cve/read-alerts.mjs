import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const directory = path.dirname(fileURLToPath(import.meta.url));
const fixturePath = path.resolve(directory, '../fixtures/known-cve.json');

function cleanText(value) {
  if (typeof value !== 'string') return '';
  return value
    .replace(/Bearer\s+[^\s,;]+/giu, 'Bearer [숨김]')
    .replace(/(?:password|passwd|token|secret|api[_-]?key)\s*[:=]\s*[^\s,;]+/giu, '[민감값 숨김]');
}

function cleanAccount(value) {
  if (typeof value !== 'string' || value.length === 0) return null;
  if (/(password|passwd|token|secret|api[_-]?key)/iu.test(value)) return '[민감값 숨김]';
  return cleanText(value);
}

export function readAlerts(alerts) {
  if (!Array.isArray(alerts)) throw new TypeError('alerts_must_be_an_array');

  return alerts.map((alert) => ({
    timestamp: typeof alert?.timestamp === 'string' ? cleanText(alert.timestamp) : null,
    sourceAddress: typeof alert?.data?.srcip === 'string' ? cleanText(alert.data.srcip) : null,
    account: cleanAccount(alert?.data?.srcuser),
    ruleLevel: Number.isFinite(alert?.rule?.level) ? alert.rule.level : null,
    description: cleanText(alert?.rule?.description ?? ''),
  }));
}

async function main() {
  const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
  if (fixture?.moduleKey !== 'known-cve' || !Array.isArray(fixture.alerts)) {
    throw new TypeError('invalid_known_cve_fixture');
  }

  const rows = readAlerts(fixture.alerts);
  for (const row of rows) console.log(JSON.stringify(row));
  console.log(JSON.stringify({
    alertCount: fixture.alerts.length,
    outputLineCount: rows.length,
  }));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error('known-cve alert reader failed');
    process.exitCode = 1;
  });
}
