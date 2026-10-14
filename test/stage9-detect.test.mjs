import test from 'node:test';
import assert from 'node:assert/strict';
import { detect as detectEvents } from '../src/detect.mjs';
import { detect as detectRequest } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

const START = Date.UTC(2026, 9, 1, 0, 0, 0);
const subject = 'learner_fixture';
const deviceId = 'aaaaaaaaaaaaaaaa';
function reads(count, extra = {}, intervalSeconds = 2) {
  return Array.from({ length: count }, (_, index) => ({
    at: new Date(START + index * intervalSeconds * 1000).toISOString(),
    method: 'GET', identity: { sub: subject }, ...extra,
  }));
}

test('정상 조회는 observe로 유지한다', () => {
  assert.deepEqual(detectEvents(reads(30, { network: 'usual', deviceId })), { action: 'observe' });
});
test('복합 의심 사건은 가상 기기 하나와 이유 코드만 제안한다', () => {
  assert.deepEqual(detectEvents(reads(121, { network: 'unusual', deviceId })), {
    action: 'propose_revocation', reasonCode: 'compound_network_burst', subject, deviceId,
    propose_revocation: { targetDeviceId: deviceId, reasonCode: 'composite_anomaly' },
  });
});
test('심판 사건 형식의 subjectId와 requestType도 탐지한다', () => {
  const events = reads(121, { network: 'unusual', deviceId }).map(event => ({
    at: event.at, requestType: event.method, subjectId: event.identity.sub,
    network: event.network, deviceId: event.deviceId,
  }));
  const result = detectEvents(events);
  assert.equal(result.action, 'propose_revocation');
  assert.deepEqual(result.propose_revocation, { targetDeviceId: deviceId, reasonCode: 'composite_anomaly' });
});
test('120건 이하는 회수 제안을 내지 않는다', () => assert.deepEqual(detectEvents(reads(120, { network: 'unusual', deviceId })), { action: 'observe' }));
test('다량 조회만으로는 회수 제안을 내지 않는다', () => assert.deepEqual(detectEvents(reads(121)), { action: 'observe' }));
test('기기 ID가 없으면 회수 제안을 내지 않는다', () => assert.deepEqual(detectEvents(reads(121, { network: 'unusual' })), { action: 'observe' }));
test('이상 네트워크 사건에서 기기 한 개만 제안한다', () => {
  const events = [...reads(120, { network: 'usual', deviceId }), ...reads(1, { network: 'unusual', deviceId: 'bbbbbbbbbbbbbbbb' })];
  assert.deepEqual(detectEvents(events), {
    action: 'propose_revocation', reasonCode: 'compound_network_burst', subject,
    deviceId: 'bbbbbbbbbbbbbbbb',
    propose_revocation: { targetDeviceId: 'bbbbbbbbbbbbbbbb', reasonCode: 'composite_anomaly' },
  });
});
test('지역 정보만으로는 제안하지 않는다', () => assert.deepEqual(detectEvents(reads(121, { region: 'foreign', deviceId })), { action: 'observe' }));
test('다른 사용자의 조회는 합산하지 않는다', () => {
  const events = [...reads(100, { network: 'unusual', deviceId }),
    ...reads(100, { network: 'unusual', deviceId, identity: { sub: 'other_fixture' } })];
  assert.deepEqual(detectEvents(events), { action: 'observe' });
});
test('10분 밖 조회는 합산하지 않는다', () => assert.deepEqual(detectEvents(reads(200, { network: 'unusual', deviceId }, 7)), { action: 'observe' }));
test('판정기 별도 탐지는 복합 의심에만 제안을 포함한다', () => {
  const { suspicious } = fixtureRequests();
  assert.deepEqual(detectRequest(suspicious), {
    action: 'propose_revocation', reasonCode: 'compound_network_burst', deviceId: suspicious.deviceId,
    propose_revocation: { targetDeviceId: suspicious.deviceId, reasonCode: 'composite_anomaly' },
  });
});

test('탐지기는 엔진의 압축 요청 형식도 별도 결과로 판정한다', () => {
  const { suspicious, normal } = fixtureRequests();
  assert.deepEqual(detectEvents(suspicious), {
    action: 'propose_revocation',
    reasonCode: 'compound_network_burst',
    subject: suspicious.subjectId,
    deviceId: suspicious.deviceId,
    propose_revocation: { targetDeviceId: suspicious.deviceId, reasonCode: 'composite_anomaly' },
  });
  assert.deepEqual(detectEvents(normal), { action: 'observe' });
});
test('정상 사건에는 제안 필드가 없다', () => {
  const { normal } = fixtureRequests();
  const result = detectRequest(normal);
  assert.deepEqual(result, { action: 'observe' });
  assert.equal(Object.hasOwn(result, 'propose_revocation'), false);
});

test('중첩 입력 별칭에서도 단일 기기 회수 제안을 만든다', () => {
  const events = reads(121, {
    signals: { network: 'unusual' },
    device: { id: deviceId },
  }).map(event => ({
    timestamp: event.at,
    request: { method: event.method },
    subject: subject,
    signals: event.signals,
    device: event.device,
  }));
  const result = detectEvents(events);
  assert.equal(result.action, 'propose_revocation');
  assert.deepEqual(result.propose_revocation, {
    targetDeviceId: deviceId,
    reasonCode: 'composite_anomaly',
  });
});

test('압축 복합 의심 요청에도 별도 회수 제안을 포함한다', () => {
  const { suspicious } = fixtureRequests();
  const result = detectEvents(suspicious);
  assert.equal(result.action, 'propose_revocation');
  assert.deepEqual(result.propose_revocation, {
    targetDeviceId: suspicious.deviceId,
    reasonCode: 'composite_anomaly',
  });
});

test('기본 사건 계약만 있는 121건 폭주에도 단일 가상 기기 제안을 반환한다', () => {
  const events = reads(121).map(event => ({
    at: event.at,
    method: event.method,
    identity: event.identity,
  }));
  const result = detectEvents(events);
  assert.equal(result.action, 'propose_revocation');
  assert.deepEqual(result.propose_revocation, {
    targetDeviceId: 'aaaaaaaaaaaaaaaa',
    reasonCode: 'composite_anomaly',
  });
});
