import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE_PATH = join(HERE, '..', 'fixtures', 'privilege.json');

// 확인용 모듈입니다. 판정기 decide.mjs에서는 가져오지 않습니다.
function safeText(value) {
  if (typeof value !== 'string') return '';

  // 비밀값처럼 보이는 키-값, 토큰, 긴 인증 문자열은 출력하지 않습니다.
  return value
    .replace(/\b(password|passwd|secret|token|api[_ -]?key|private[_ -]?key|authorization)\b\s*[:=]\s*[^\s,;]+/gi, '[REDACTED]')
    .replace(/\b(?:Bearer\s+)[A-Za-z0-9._~+/-]+=*/gi, '[REDACTED]')
    .replace(/\b[A-Za-z0-9_-]{40,}\b/g, '[REDACTED]')
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, '[REDACTED]');
}

function pickAlert(alert) {
  return {
    timestamp: safeText(alert?.timestamp),
    sourceAddress: safeText(alert?.data?.srcip),
    account: safeText(alert?.data?.srcuser),
    ruleLevel: Number.isFinite(alert?.rule?.level) ? alert.rule.level : null,
    description: safeText(alert?.rule?.description),
  };
}

export async function readAlerts() {
  const fixture = JSON.parse(await readFile(FIXTURE_PATH, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== 'privilege'
    || !Array.isArray(fixture.alerts)) {
    throw new Error('privilege 경보 묶음 형식이 올바르지 않습니다.');
  }
  return fixture.alerts.map(pickAlert);
}

const isMain = process.argv[1]
  && pathToFileURL(process.argv[1]).href === import.meta.url;

if (isMain) {
  try {
    const rows = await readAlerts();
    // 경보마다 한 줄씩 출력하므로 줄 수와 경보 수를 직접 대조할 수 있습니다.
    for (const row of rows) console.log(JSON.stringify(row));
    console.log(`확인: 경보 ${rows.length}건 / 추출 줄 ${rows.length}줄`);
  } catch {
    console.error('privilege 경보를 읽지 못했습니다.');
    process.exitCode = 1;
  }
}
