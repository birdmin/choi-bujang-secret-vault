// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 6단계: 등록된 기기의 자료실 읽기 요청만 허용합니다.
// 7단계 제작 1: 접속 신호의 출처와 값이 계약에 맞는지 검사합니다. 위험도 판정은 아직 하지 않습니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['device_registered']);

function validateSignals(signals) {
  if (!signals || typeof signals !== 'object' || Array.isArray(signals)) {
    throw new TypeError('invalid_signals');
  }

  const keys = Object.keys(signals).sort().join(',');
  if (keys !== 'hour,network,region,source') {
    throw new TypeError('invalid_signals');
  }

  // 실제 엔진 경로는 신뢰할 접속 정보를 제공하지 않는다고 명시합니다.
  // 이 경우 누락된 지역·네트워크·시각을 정상값으로 보완하지 않습니다.
  if (signals.source === 'none') {
    if (signals.region !== 'unknown' || signals.network !== 'unknown'
        || !(signals.hour === null || signals.hour === 'unknown')) {
      throw new TypeError('untrusted_signals_source');
    }
    return;
  }

  // judge_fixture는 심판/연습에서 만든 가상 입력임을 나타낼 뿐,
  // 브라우저 헤더나 실제 위치의 증거로 승격하지 않습니다.
  if (signals.source === 'judge_fixture') {
    if (typeof signals.region !== 'string' || signals.region.length === 0
        || typeof signals.network !== 'string' || signals.network.length === 0
        || !Number.isInteger(signals.hour) || signals.hour < 0 || signals.hour > 23) {
      throw new TypeError('invalid_signals');
    }
    return;
  }

  // 출처가 불명확하거나 알 수 없는 출처는 정상 신호로 처리하지 않습니다.
  throw new TypeError('untrusted_signals_source');
}

export async function decide(request) {
  if (!request || typeof request !== 'object' || Array.isArray(request)) {
    throw new TypeError('invalid_request');
  }

  validateSignals(request.signals);

  if (request.deviceRegistered !== true) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: [RULE_IDS[0]],
    };
  }

  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: [RULE_IDS[0]],
  };
}
