import test from 'node:test';
import assert from 'node:assert/strict';
import { detect as detectEvents } from '../src/detect.mjs';
import { detect as detectRequest } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

const START = Date.UTC(2026, 9, 1, 0, 0, 0);
const subject = 'learner_fixture';
const otherSubject = 'other_fixture';

function reads(count, {
  owner = subject,
  intervalSeconds = 2,
  method = 'GET',
} = {}) {
  return Array.from({ length: count }, (_, index) => ({
    at: new Date(START + index * intervalSeconds * 1000).toISOString(),
    method,
    identity: { sub: owner },
  }));
}

test('정상 조회 30건은 observe로 유지한다', () => {
  assert.deepEqual(detectEvents(reads(30)), { action: 'observe' });
});

test('10분 안에 정확히 120건은 observe로 유지한다', () => {
  assert.deepEqual(detectEvents(reads(120)), { action: 'observe' });
});

test('같은 사용자의 10분 안 GET 121건은 burst_read를 제안한다', () => {
  assert.deepEqual(detectEvents(reads(121)), {
    action: 'propose_revocation',
    reasonCode: 'burst_read',
    subject,
  });
});

test('제안 결과에는 계약의 세 키만 포함한다', () => {
  const result = detectEvents(reads(121));
  assert.deepEqual(Object.keys(result).sort(), ['action', 'reasonCode', 'subject']);
});

test('다른 사용자의 조회는 합산하지 않는다', () => {
  assert.deepEqual(detectEvents([
    ...reads(100, { owner: subject }),
    ...reads(100, { owner: otherSubject }),
  ]), { action: 'observe' });
});

test('GET이 아닌 사건은 집계하지 않는다', () => {
  assert.deepEqual(detectEvents(reads(121, { method: 'POST' })), { action: 'observe' });
});

test('10분 구간을 넘어서 흩어진 조회는 합산하지 않는다', () => {
  assert.deepEqual(detectEvents(reads(200, { intervalSeconds: 7 })), { action: 'observe' });
});

test('network와 deviceId 필드가 없어도 계약의 세 필드로 탐지한다', () => {
  assert.deepEqual(detectEvents(reads(121)), {
    action: 'propose_revocation',
    reasonCode: 'burst_read',
    subject,
  });
});

test('지역이나 기기 정보만으로는 조회 계약의 결과를 바꾸지 않는다', () => {
  assert.deepEqual(detectEvents(reads(30)), { action: 'observe' });
});

test('판정기의 별도 탐지는 기존 계약대로 복합 의심을 판정한다', () => {
  const { suspicious } = fixtureRequests();

  assert.deepEqual(detectRequest(suspicious), {
    action: 'propose_revocation',
    reasonCode: 'compound_network_burst',
    subject: suspicious.subjectId,
    deviceId: suspicious.deviceId,
    propose_revocation: {
      targetDeviceId: suspicious.deviceId,
      reasonCode: 'composite_anomaly',
    },
  });
});

test('정상 판정 사건에는 제안 필드가 없다', () => {
  const { normal } = fixtureRequests();
  const result = detectRequest(normal);

  assert.deepEqual(result, { action: 'observe' });
  assert.equal(Object.hasOwn(result, 'propose_revocation'), false);
});

test('판정기 탐지는 중첩 네트워크·기기·사건 별칭에서 제안한다', () => {
  const result = detectRequest({
    subjectId: subject,
    context: { network: 'unusual', deviceId: 'aaaaaaaaaaaaaaaa' },
    recentEvents: [
      { eventType: 'risk_signal', age_seconds: 60, readCount: 20 },
    ],
  });

  assert.deepEqual(result, {
    action: 'propose_revocation',
    reasonCode: 'compound_network_burst',
    subject,
    deviceId: 'aaaaaaaaaaaaaaaa',
    propose_revocation: {
      targetDeviceId: 'aaaaaaaaaaaaaaaa',
      reasonCode: 'composite_anomaly',
    },
  });
});
