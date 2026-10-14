
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
  if (
    typeof request.service !== 'string'
    || typeof request.method !== 'string'
    || typeof request.path !== 'string'
    || typeof request.route !== 'string'
  ) {
    return false;
  }

  if (
    request.path.includes('?')
    || request.path.includes('#')
    || request.queryLength !== 0
  ) {
    return false;
  }

  const {
    memo,
    classNoticeCollection,
    classNoticeDetail,
    instructorMaterial,
  } = ROUTE_POLICY;

  if (
    instructorMaterial.service === request.service
    && instructorMaterial.path.test(request.path)
  ) {
    return false;
  }

  if (memo.service === request.service) {
    return request.method === memo.method
      && memo.path.test(request.path)
      && request.route === memo.route;
  }

  if (classNoticeCollection.service === request.service) {
    return request.method === classNoticeCollection.method
      && (
        (
          classNoticeCollection.path.test(request.path)
          && request.route === classNoticeCollection.route
        )
        || (
          classNoticeDetail.path.test(request.path)
          && request.route === classNoticeDetail.route
        )
      );
  }

  return false;
}

function routeDecision(request, allowed) {
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: allowed ? 'allow' : 'deny',
    reasonCode: allowed ? 'approved' : 'route_not_allowed',
    ruleIds: [
      allowed
        ? 'resource_route_allowed'
        : 'resource_route_denied',
    ],
  };
}

function validateSignals(signals) {
  if (
    !signals
    || typeof signals !== 'object'
    || Array.isArray(signals)
  ) {
    throw new TypeError('invalid_signals');
  }

  if (
    Object.keys(signals).sort().join(',')
    !== 'hour,network,region,source'
  ) {
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
  if (!hasFixtureSignals) {
    return false;
  }

  const { network } = request.signals;

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

  return network === 'unusual' && bulkReading;
}

function hasRecentVerifiedStepUp(stepUp) {
  return Boolean(
    stepUp
    && stepUp.verified === true
    && Number.isInteger(stepUp.authAgeSeconds)
    && stepUp.authAgeSeconds >= 0
    && stepUp.authAgeSeconds <= 900
  );
}

export async function decide(request) {
  if (
    !request
    || typeof request !== 'object'
    || Array.isArray(request)
  ) {
    throw new TypeError('invalid_request');
  }

  if (!routeAllowed(request)) {
    return routeDecision(request, false);
  }

  let hasFixtureSignals;

  try {
    hasFixtureSignals = validateSignals(request.signals);
  } catch {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'step_up',
      reasonCode: 'step_up_required',
      ruleIds: [RULE_IDS[1]],
    };
  }

  if (request.deviceRegistered !== true) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: [RULE_IDS[0]],
    };
  }

  const compositeRisk = hasCompositeRisk(
    request,
    hasFixtureSignals,
  );

  const verifiedStepUp = hasRecentVerifiedStepUp(request.stepUp);

  if (compositeRisk && !verifiedStepUp) {
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
    ruleIds: [
      RULE_IDS[0],
      'resource_route_allowed',
    ],
  };
}

export const REVOCATION_REASON_CODE = 'composite_anomaly';

// 탐지 결과는 decide()의 기존 5개 필드 응답과 분리합니다.
// 계약에 정의된 기기 ID 한 개와 가명 주체만 참조하며,
// 실제 회수는 수행하지 않습니다.
export function detect(request) {
  if (
    !request
    || typeof request !== 'object'
    || Array.isArray(request)
  ) {
    return { action: 'observe' };
  }

  const network = request.signals?.network;
  const deviceId = request.deviceId;

  const recentEvents = Array.isArray(request.recentEvents)
    ? request.recentEvents
    : [];

  const bulkReading = recentEvents.some(event =>
    event
    && typeof event === 'object'
    && !Array.isArray(event)
    && event.kind === 'risk_signal'
    && Number.isInteger(event.ageSeconds)
    && event.ageSeconds >= 0
    && event.ageSeconds <= 300
    && Number.isInteger(event.count)
    && event.count >= 10
  );

  if (
    network !== 'unusual'
    || !bulkReading
    || typeof deviceId !== 'string'
    || !/^[0-9a-f]{16}$/.test(deviceId)
  ) {
    return { action: 'observe' };
  }

  const subject = request.subjectId;

  return {
    action: 'propose_revocation',
    reasonCode: 'compound_network_burst',
    ...(typeof subject === 'string' && subject.length > 0
      ? { subject }
      : {}),
    deviceId,
    propose_revocation: {
      targetDeviceId: deviceId,
      reasonCode: REVOCATION_REASON_CODE,
    },
  };
}
