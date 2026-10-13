// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 6단계: 등록된 기기의 자료실 읽기 요청만 허용합니다.
// 7단계: 엔진이 전달한 가상 신호의 출처를 검사하고, 복합 이상 접속은 추가 확인으로 보냅니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required']);

function validateSignals(signals) {
  if (!signals || typeof signals !== 'object' || Array.isArray(signals)) {
    throw new TypeError('invalid_signals');
  }
  if (Object.keys(signals).sort().join(',') !== 'hour,network,region,source') {
    throw new TypeError('invalid_signals');
  }

  if (signals.source === 'none') {
    if (signals.region !== 'unknown' || signals.network !== 'unknown'
        || !(signals.hour === null || signals.hour === 'unknown')) {
      throw new TypeError('untrusted_signals_source');
    }
    return false;
  }

  if (signals.source !== 'judge_fixture') {
    throw new TypeError('untrusted_signals_source');
  }
  if (typeof signals.region !== 'string' || signals.region.length === 0
      || typeof signals.network !== 'string' || signals.network.length === 0
      || !Number.isInteger(signals.hour) || signals.hour < 0 || signals.hour > 23) {
    throw new TypeError('invalid_signals');
  }
  return true;
}

function hasCompositeRisk(request, hasFixtureSignals) {
  if (!hasFixtureSignals) return false;

  const { region, hour, network } = request.signals;
  // The fixture's foreign region represents a region change; real-path signals are unknown.
  const unusualRegion = region !== 'local';
  const unusualHour = hour < 6 || hour >= 23;
  const unfamiliarNetwork = network === 'unusual';
  const bulkModification = Array.isArray(request.recentEvents)
    && request.recentEvents.some(event =>
      event && ['bulk_modify', 'bulk_write', 'modify', 'write', 'risk_signal'].includes(event.kind)
      && Number.isInteger(event.ageSeconds) && event.ageSeconds >= 0
      && event.ageSeconds <= 300
      && Number.isInteger(event.count) && event.count >= 10
    );

  return unusualRegion && unusualHour && unfamiliarNetwork && bulkModification;
}

export async function decide(request) {
  if (!request || typeof request !== 'object' || Array.isArray(request)) {
    throw new TypeError('invalid_request');
  }

  const hasFixtureSignals = validateSignals(request.signals);

  if (request.deviceRegistered !== true) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: [RULE_IDS[0]],
    };
  }

  if (hasCompositeRisk(request, hasFixtureSignals)) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'step_up',
      reasonCode: 'step_up_required',
      ruleIds: [RULE_IDS[1]],
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
