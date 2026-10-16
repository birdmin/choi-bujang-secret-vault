import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const fixturePath = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'persistence.json');

export async function readAlerts() {
  const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== 'persistence' || !Array.isArray(fixture.alerts)) {
    throw new Error('경보 묶음 형식이 올바르지 않습니다.');
  }

  return fixture.alerts.map((alert) => ({
    timestamp: typeof alert?.timestamp === 'string' ? alert.timestamp : '',
    sourceAddress: typeof alert?.data?.srcip === 'string' ? alert.data.srcip : '',
    account: typeof alert?.data?.srcuser === 'string' ? alert.data.srcuser : '',
    ruleLevel: Number.isFinite(alert?.rule?.level) ? alert.rule.level : null,
    description: typeof alert?.rule?.description === 'string' ? alert.rule.description : '',
  }));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    for (const row of await readAlerts()) console.log(JSON.stringify(row));
  } catch {
    console.error('경보를 읽지 못했습니다.');
    process.exitCode = 1;
  }
}
