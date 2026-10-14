// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 6단계: 등록된 기기의 자료실 읽기 요청만 허용합니다.
// 7단계: 엔진이 전달한 가상 신호의 출처를 검사하고,
// 복합 이상 접속은 추가 확인으로 보내며, 유효한 재확인 뒤에는 허용합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.

export const RULE_IDS = Object.freeze([
  'device_registered',
  'step_up_required',
  'resource_route_allowed',
  'resource_route_denied',
]);

const ROUTE_POLICY = Object.freeze({
  memo: {
    service: 'notes',
    method: 'GET',
    path: /^\/notes\/(?!export$)[^/]+$/,
    route: 'GET /notes/:id',
  },
  classNoticeCollection: {
    service: 'class-notices',
    method: 'GET',
    path: /^\/class-notices$/,
    route: 'GET /class-notices',
  },
  classNoticeDetail: {
    service: 'class-notices',
    method: 'GET',
    path: /^\/class-notices\/(?!export$)[^/]+$/,
    route: 'GET /class-notices/:id',
  },
  instructorMaterial: {
    service: 'instructor-materials',
    path: /^\/instructor-materials(?:\/[^/]+)?$/,
  },
});

function routeAllowed(request) {
  if (typeof request.service !== 'string'
    || typeof request.method !== 'string'
    || typeof request.path !== 'string'
    || typeof request.route !== 'string') return false;

  // 쿼리로 기능을 선택하지 못하게 하고, 경로의 모양과 서비스·메서드를 함께 확인합니다.
  if (request.path.includes('?') || request.path.includes('#')) return false;
  if (request.queryLength !== 0) return false;

  const { memo, classNoticeCollection, classNoticeDetail, instructorMaterial } = ROUTE_POLICY;

  if (instructorMaterial.service === request.service
    && instructorMaterial.path.test(request.path)) return false;

  if (memo.service === request.service) {
    return request.method === memo.method
      && memo.path.test(request.path)
      && request.route === memo.route;
  }

  if (classNoticeCollection.service === request.service) {
    return request.method === classNoticeCollection.method
      && ((classNoticeCollection.path.test(request.path)
        && request.route === classNoticeCollection.route)
        || (classNoticeDetail.path.test(request.path)
          && request.route === classNoticeDetail.route));
  }

  return false;
}

function routeDecision(request, allowed) {
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: allowed ? 'allow' : 'deny',
    reasonCode: allowed ? 'approved' : 'route_not_allowed',
    ruleIds: [allowed ? 'resource_route_allowed' : 'resource_route_denied'],
  };
}

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

  const { network } = request.signals;

  // 낯선 네트워크
  const unfamiliarNetwork = network === 'unusual';

  // 엔진이 전달한 risk_signal 사건 중 최근 5분 이내 10건 이상
  const bulkReading = Array.isArray(request.recentEvents)
    && request.recentEvents.some(event =>
      event
      && event.kind === 'risk_signal'
      && Number.isInteger(event.ageSeconds)
      && event.ageSeconds >= 0
      && event.ageSeconds <= 300
      && Number.isInteger(event.count)
      && event.count >= 10
    );

  // 낯선 네트워크와 갑작스러운 다량 조회가 함께 있을 때만 복합 이상 접속으로 판정합니다.
  // 지역 하나만으로는 확정하지 않으며, 지역은 판정 조건에 넣지 않습니다.
  return unfamiliarNetwork && bulkReading;
}

function hasRecentVerifiedStepUp(stepUp) {
  // 엔진이 확인한 최근 재인증만 인정합니다.
  // verified 값은 브라우저에서 임의로 전달된 값을 신뢰하면 안 됩니다.
  return Boolean(
    stepUp
    && stepUp.verified === true
    && Number.isInteger(stepUp.authAgeSeconds)
    && stepUp.authAgeSeconds >= 0
    && stepUp.authAgeSeconds <= 300
  );
}

export async function decide(request) {
  if (!request || typeof request !== 'object' || Array.isArray(request)) {
    throw new TypeError('invalid_request');
  }

  // 구역 경로 정책을 먼저 적용합니다. 요청에는 역할이 없으므로 강사 권한을 추정하지 않습니다.
  if (!routeAllowed(request)) {
    return routeDecision(request, false);
  }

  let hasFixtureSignals;
  try {
    hasFixtureSignals = validateSignals(request.signals);
  } catch {
    // 계약에 맞지 않거나 신뢰할 수 없는 신호는 허용하지 않고 추가 확인으로 보냅니다.
    // 기존 등록된 RULE_IDS와 허용된 reasonCode만 사용합니다.
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'step_up',
      reasonCode: 'step_up_required',
      ruleIds: [RULE_IDS[1]],
    };
  }

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
    ruleIds: [RULE_IDS[0], 'resource_route_allowed'],
  };
}

// 별도 탐지 결과입니다. decide()의 5개 이름 응답은 바꾸지 않습니다.
// 회수 API는 만들지 않고, 회수 "제안"만 대상 기기 한 개와 이유 코드로 남깁니다.
export const REVOCATION_REASON_CODE = 'composite_anomaly';

export function detect(request) {
  if (!request || typeof request !== 'object' || Array.isArray(request)) {
    return { schema: 'aleph.detection.v1', detected: false };
  }

  let hasFixtureSignals;
  try {
    hasFixtureSignals = validateSignals(request.signals);
  } catch {
    return { schema: 'aleph.detection.v1', requestId: request.requestId, detected: false };
  }

  const detected = hasCompositeRisk(request, hasFixtureSignals);
  // 탐지 결과는 접근 허용/거부와 별개입니다. 등록 여부가 false인 요청도
  // 엔진이 제공한 형식의 기기 ID가 있으면 의심 사건의 대상 후보를 특정할 수 있습니다.
  // 실제 권한 변경은 하지 않고, 회수 제안만 기록합니다.
  const deviceOk = typeof request.deviceId === 'string'
    && /^[0-9a-f]{16}$/.test(request.deviceId);

  const result = {
    schema: 'aleph.detection.v1',
    requestId: request.requestId,
    detected,
    ruleIds: detected ? [RULE_IDS[1]] : [],
  };

  // 제안은 판정(decide) 응답과 분리된 탐지 결과에만 기록합니다.
  // 복합 이상이 확인되고 대상 가상 기기가 특정될 때만 명시적으로 제안합니다.
  if (detected && deviceOk) {
    result.propose_revocation = {
      targetDeviceId: request.deviceId,
      reasonCode: REVOCATION_REASON_CODE,
    };
  }

  return result;
}
