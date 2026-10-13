```javascript
// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 6단계: 등록된 기기의 자료실 읽기 요청만 허용합니다.
// 7단계: 엔진이 전달한 가상 신호의 출처를 검사하고,
// 복합 이상 접속은 추가 확인으로 보내며, 유효한 재확인 뒤에는 허용합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.

export const RULE_IDS = Object.freeze([
  'device_registered',
  'step_up_required',
]);

function validateSignals(signals) {
  if (!signals || typeof signals !== 'object' || Array.isArray(signals)) {
    throw new TypeError('invalid_signals');
  }

  if (Object.keys(signals).sort().join(',') !== 'hour,network,region,source') {
    throw new TypeError('invalid_signals');
  }

  if (signals.source === 'none') {
    if (
      signals.region !== 'unknown'
      || signals.network !== 'unknown'
      || !(signals.hour === null || signals.hour === 'unknown')
    ) {
      throw new TypeError('untrusted_signals_source');
    }

    return false;
  }

  if (signals.source !== 'judge_fixture') {
    throw new TypeError('untrusted_signals_source');
  }

  if (
    typeof signals.region !== 'string'
    || signals.region.length === 0
    || typeof signals.network !== 'string'
    || signals.network.length === 0
    || !Number.isInteger(signals.hour)
    || signals.hour < 0
    || signals.hour > 23
  ) {
    throw new TypeError('invalid_signals');
  }

  return true;
}

function hasCompositeRisk(request, hasFixtureSignals) {
  // 실제 요청의 브라우저 제공 위치·네트워크·시각은
  // 위험 판정의 근거로 사용하지 않습니다.
  if (!hasFixtureSignals) {
    return false;
  }

  const { hour, network } = request.signals;

  // 평소와 다른 시각
  const unusualHour = hour < 6 || hour >= 23;

  // 낯선 네트워크
  const unfamiliarNetwork = network === 'unusual';

  // 최근 5분 이내에 발생한 10건 이상의 대량 읽기
  const bulkReading = Array.isArray(request.recentEvents)
    && request.recentEvents.some(event =>
      event
      && ['bulk_read', 'read_bulk', 'read_many', 'read', 'risk_signal']
        .includes(event.kind)
      && Number.isInteger(event.ageSeconds)
      && event.ageSeconds >= 0
      && event.ageSeconds <= 300
      && Number.isInteger(event.count)
      && event.count >= 10
    );

  // 세 조건이 모두 맞을 때만 복합 이상 접속으로 판정합니다.
  return unusualHour && unfamiliarNetwork && bulkReading;
}

function hasRecentVerifiedStepUp(stepUp) {
  // 엔진이 확인한 최근 재인증만 인정합니다.
  // verified 값은 브라우저에서 임의로 전달된 값을 신뢰하면 안 됩니다.
  return Boolean(
    stepUp
    && stepUp.verified === true
    && Number.isInteger(stepUp.authAgeSeconds)
    && stepUp.authAgeSeconds >= 0
    && stepUp.authAgeSeconds <= 900
  );
}

export async function decide(request) {
  if (!request || typeof request !== 'object' || Array.isArray(request)) {
    throw new TypeError('invalid_request');
  }

  const hasFixtureSignals = validateSignals(request.signals);

  // 기존 기기 등록 규칙을 유지합니다.
  if (request.deviceRegistered !== true) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: [RULE_IDS[0]],
    };
  }

  const compositeRisk = hasCompositeRisk(request, hasFixtureSignals);
  const verifiedStepUp = hasRecentVerifiedStepUp(request.stepUp);

  // 복합 이상 접속은 유효한 최근 재인증이 없으면 추가 확인합니다.
  if (compositeRisk && !verifiedStepUp) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'step_up',
      reasonCode: 'step_up_required',
      ruleIds: [RULE_IDS[1]],
    };
  }

  // 정상 접속 또는 재확인을 마친 복합 이상 접속은 허용합니다.
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: [RULE_IDS[0]],
  };
}
```
