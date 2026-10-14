
 // ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 6단계: 등록된 기기의 자료실 읽기 요청만 허용합니다.
// 7단계: 엔진이 전달한 가상 신호의 출처를 검사하고,
// 복합 이상 접속은 추가 확인으로 보내며, 유효한 재확인 뒤에는 허용합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.


export function detect(request) {
  if (!request || typeof request !== 'object' || Array.isArray(request)) {
    return { action: 'observe' };
  }

  const network = [
    request.signals?.network,
    request.network,
    request.context?.network,
    request.request?.network,
  ].find(value => typeof value === 'string') ?? null;

  const deviceId = [
    request.deviceId,
    request.device?.id,
    request.identity?.deviceId,
    request.context?.deviceId,
    request.request?.deviceId,
  ].find(value => typeof value === 'string' && value.length > 0) ?? null;

  const recentEvents = Array.isArray(request.recentEvents) ? request.recentEvents : [];

  const bulkReading = recentEvents.some(event => {
    if (!event || typeof event !== 'object' || Array.isArray(event)) return false;

    const kind = event.kind ?? event.type ?? event.eventType;
    const age = event.ageSeconds ?? event.age_seconds;
    const count = event.count ?? event.readCount ?? event.total;

    return kind === 'risk_signal'
      && Number.isInteger(age) && age >= 0 && age <= 300
      && Number.isInteger(count) && count >= 10;
  });

  if (network !== 'unusual' || !bulkReading
    || typeof deviceId !== 'string'
    || !/^[0-9a-f]{16}$/.test(deviceId)) {
    return { action: 'observe' };
  }

  const subject = [
    request.subjectId,
    request.identity?.sub,
    request.subject,
    request.pseudonym,
  ].find(value => typeof value === 'string' && value.length > 0);

  return {
    action: 'propose_revocation',
    reasonCode: 'compound_network_burst',
    ...(subject ? { subject } : {}),
    deviceId,
    propose_revocation: {
      targetDeviceId: deviceId,
      reasonCode: REVOCATION_REASON_CODE,
    },
  };
}
