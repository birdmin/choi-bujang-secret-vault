const WINDOW_MS = 10 * 60 * 1000;
const READ_THRESHOLD = 120;

const ALLOWED_METHODS = new Set([
  'GET',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
]);

function readEvent(event) {
  if (!event || typeof event !== 'object' || Array.isArray(event)) {
    return null;
  }

  const at = event.at;
  const method = event.method;
  const sub = event.identity?.sub;

  if (
    typeof at !== 'string' ||
    !Number.isFinite(Date.parse(at)) ||
    typeof method !== 'string' ||
    !ALLOWED_METHODS.has(method) ||
    typeof sub !== 'string' ||
    sub.length === 0
  ) {
    return null;
  }

  const network =
    typeof event.network === 'string'
      ? event.network
      : typeof event.signals?.network === 'string'
        ? event.signals.network
        : null;

  const deviceId =
    typeof event.deviceId === 'string'
      ? event.deviceId
      : null;

  return {
    timestamp: Date.parse(at),
    method,
    subject: sub,
    network,
    deviceId,
  };
}

const observe = () => ({ action: 'observe' });

export function detect(events) {
  if (!Array.isArray(events)) {
    throw new TypeError('invalid_detection_events');
  }

  const safeEvents = events
    .map(readEvent)
    .filter((event) => event !== null);

  const readsBySubject = new Map();

  for (const event of safeEvents) {
    if (event.method !== 'GET') continue;

    const current = readsBySubject.get(event.subject) ?? [];
    current.push(event);
    readsBySubject.set(event.subject, current);
  }

  for (const [subject, reads] of readsBySubject) {
    reads.sort((a, b) => a.timestamp - b.timestamp);

    for (let start = 0; start < reads.length; start += 1) {
      const first = reads[start];
      const windowReads = [];

      for (let index = start; index < reads.length; index += 1) {
        if (reads[index].timestamp - first.timestamp >= WINDOW_MS) {
          break;
        }

        windowReads.push(reads[index]);
      }

      if (windowReads.length <= READ_THRESHOLD) continue;

      // 조회 폭주와 비정상 네트워크 신호가 같은 시간 창에 있어야 합니다.
      const unusualNetworkRead = windowReads.find(
        (event) => event.network === 'unusual',
      );

      if (!unusualNetworkRead || !unusualNetworkRead.deviceId) continue;

      // 별도 탐지 결과에만 회수 제안을 기록합니다. 실제 권한은 변경하지 않습니다.
      // 바깥 reasonCode는 탐지 규칙 코드, 안쪽 reasonCode는 제안 사유 코드입니다.
      return {
        action: 'propose_revocation',
        reasonCode: 'compound_network_burst',
        subject,
        deviceId: unusualNetworkRead.deviceId,
        propose_revocation: {
          deviceId: unusualNetworkRead.deviceId,
          reasonCode: 'composite_anomaly',
        },
      };
    }
  }

  return observe();
}
