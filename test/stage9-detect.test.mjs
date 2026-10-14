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
    method: 'GET',
    identity: { sub: subject },
    ...extra,
  }));
}

test('정상 조회는 observe로 유지한다', () => {
  assert.deepEqual(detectEvents(reads(30, { network: 'usual', deviceId })), { schema: 'aleph.detection.v1', detected: false, ruleIds: [] });
});

test('조회 폭주와 비정상 네트워크, 확인된 기기 ID가 함께 있으면 회수 제안을 낸다', () => {
  assert.deepEqual(detectEvents(reads(121, { network: 'unusual', deviceId })), {
    schema: 'aleph.detection.v1',
    detected: true,
    subject,
    ruleIds: ['compound_network_burst'],
    propose_revocation: {
      targetDeviceId: deviceId,
      reasonCode: 'composite_anomaly',
    },
  });
});

test('120건 이하이면 회수 제안을 내지 않는다', () => {
  assert.deepEqual(detectEvents(reads(120, { network: 'unusual', deviceId })), { schema: 'aleph.detection.v1', detected: false, ruleIds: [] });
});

test('다량 조회만으로 회수 제안을 내지 않는다', () => {
  assert.deepEqual(detectEvents(reads(121)), { schema: 'aleph.detection.v1', detected: false, ruleIds: [] });
});

test('기기 식별자가 없으면 회수 제안을 내지 않는다', () => {
  assert.deepEqual(detectEvents(reads(121, { network: 'unusual' })), { schema: 'aleph.detection.v1', detected: false, ruleIds: [] });
});

test('다른 조회의 기기 ID가 달라도 이상 네트워크 사건의 기기를 제안한다', () => {
  const events = [
    ...reads(120, { network: 'usual', deviceId }),
    ...reads(1, { network: 'unusual', deviceId: 'bbbbbbbbbbbbbbbb' }),
  ];
  assert.deepEqual(detectEvents(events), {
    schema: 'aleph.detection.v1',
    detected: true,
    subject,
    ruleIds: ['compound_network_burst'],
    propose_revocation: {
      targetDeviceId: 'bbbbbbbbbbbbbbbb',
      reasonCode: 'composite_anomaly',
    },
  });
});

test('지역 정보만으로는 회수 제안을 내지 않는다', () => {
  assert.deepEqual(detectEvents(reads(121, { region: 'foreign', deviceId })), { schema: 'aleph.detection.v1', detected: false, ruleIds: [] });
});

test('다른 사용자의 조회는 합산하지 않는다', () => {
  const events = [
    ...reads(100, { network: 'unusual', deviceId }),
    ...reads(100, { network: 'unusual', deviceId, identity: { sub: 'other_fixture' } }),
  ];
  assert.deepEqual(detectEvents(events), { schema: 'aleph.detection.v1', detected: false, ruleIds: [] });
});

test('10분 밖으로 흩어진 조회는 합산하지 않는다', () => {
  assert.deepEqual(detectEvents(reads(200, { network: 'unusual', deviceId }, 7)), { schema: 'aleph.detection.v1', detected: false, ruleIds: [] });
});


test('판정기 별도 탐지 결과는 복합 의심 사건에 회수 제안을 포함한다', () => {
  const { suspicious } = fixtureRequests();
  assert.deepEqual(detectRequest(suspicious), {
    schema: 'aleph.detection.v1',
    requestId: suspicious.requestId,
    detected: true,
    ruleIds: ['step_up_required'],
    propose_revocation: {
      targetDeviceId: suspicious.deviceId,
      reasonCode: 'composite_anomaly',
    },
  });
});

test('판정기 별도 탐지 결과는 정상 사건에 회수 제안을 넣지 않는다', () => {
  const { normal } = fixtureRequests();
  const result = detectRequest(normal);
  assert.equal(result.detected, false);
  assert.equal(Object.hasOwn(result, 'propose_revocation'), false);
});
