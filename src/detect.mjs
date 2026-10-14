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
  const method = event.method ?? event.requestType;
  const sub = event.identity?.sub ?? event.subjectId;

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

  const deviceId = typeof event.deviceId === 'string' ? event.deviceId : null;

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

  const safeEvents = events.map(readEvent).filter((event) => event !== null);
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
        if (reads[index].timestamp - first.timestamp >= WINDOW_MS) break;
        windowReads.push(reads[index]);
      }

      if (windowReads.length <= READ_THRESHOLD) continue;

      const unusualNetworkRead = windowReads.find(
        (event) => event.network === 'unusual',
      );

      if (!unusualNetworkRead || !unusualNetworkRead.deviceId) continue;

      // 별도 제안에는 대상 가상 기기 ID와 사유 코드만 포함하며 실제 회수는 하지 않습니다.
      const proposal = {
        targetDeviceId: unusualNetworkRead.deviceId,
        reasonCode: 'composite_anomaly',
      };

      return {
        action: 'propose_revocation',
        reasonCode: 'compound_network_burst',
        subject,
        deviceId: unusualNetworkRead.deviceId,
        propose_revocation: proposal,
      };
    }
  }

  return observe();
}
