import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';

const START = Date.UTC(2026, 9, 1, 0, 0, 0);
const subject = 'learner_fixture';
const otherSubject = 'other_fixture';
const observe = { action: 'observe' };

function reads(count, {
  intervalSeconds = 2,
  owner = subject,
  start = START,
  method = 'GET',
} = {}) {
  return Array.from({ length: count }, (_, index) => ({
    at: new Date(start + index * intervalSeconds * 1000).toISOString(),
    method,
    identity: { sub: owner },
  }));
}

const propose = {
  action: 'propose_revocation',
  reasonCode: 'burst_read',
  subject,
};

const cases = [
  {
    name: '정상 조회 30건은 observe',
    events: reads(30),
    expected: observe,
  },
  {
    name: '10분 안에 정확히 120건은 observe',
    events: reads(120),
    expected: observe,
  },
  {
    name: '10분 안에 121건은 burst_read 제안',
    events: reads(121),
    expected: propose,
  },
  {
    name: '같은 10분 구간의 200건은 burst_read 제안',
    events: reads(200),
    expected: propose,
  },
  {
    name: '다른 사용자의 사건은 합산하지 않음',
    events: [
      ...reads(100, { owner: subject }),
      ...reads(100, { owner: otherSubject }),
    ],
    expected: observe,
  },
  {
    name: 'GET이 아닌 사건은 집계하지 않음',
    events: reads(121, { method: 'POST' }),
    expected: observe,
  },
  {
    name: '10분 구간을 넘어서 흩어진 200건은 observe',
    events: reads(200, { intervalSeconds: 7 }),
    expected: observe,
  },
  {
    name: '네트워크·기기 필드 없이 계약의 세 필드만으로 탐지',
    events: reads(121),
    expected: propose,
  },
];

export async function checkDetection(detect) {
  if (typeof detect !== 'function') {
    throw new TypeError('src/detect.mjs에서 detect 함수를 내보내야 합니다.');
  }

  const results = [];
  for (const item of cases) {
    const actual = await detect(item.events);
    results.push({
      name: item.name,
      passed: Boolean(isDeepStrictEqual(actual, item.expected)),
    });
  }
  return results;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const { detect } = await import('../src/detect.mjs');
    const results = await checkDetection(detect);
    for (const item of results) {
      process.stdout.write(`${item.passed ? '통과' : '확인 필요'} · ${item.name}\n`);
    }
    process.stdout.write('가상 사건 연습이며 실제 접속 회수나 심판 통과 증거가 아닙니다.\n');
    if (results.some((item) => !item.passed)) process.exitCode = 1;
  } catch (error) {
    process.stderr.write(`탐지 연습 첫 오류: ${error.message}\n`);
    process.exitCode = 1;
  }
}
