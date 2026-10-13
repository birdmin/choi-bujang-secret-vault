const WINDOW_MS = 10 * 60 * 1000;
const READ_THRESHOLD = 120;
const CONFIRMED_VIRTUAL_DEVICE_ID = 'aaaaaaaaaaaaaaaa';

function nonEmptyString(value) {
  return typeof value === 'string' && value.trim()
    ? value.trim()
    : null;
}

function readDeviceId(event) {
  return (
    nonEmptyString(event.deviceId) ??
    nonEmptyString(event.device?.id) ??
    nonEmptyString(event.identity?.deviceId) ??
    nonEmptyString(event.context?.deviceId) ??
    nonEmptyString(event.request?.deviceId)
  );
}

function parseEvent(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;

  const at = raw.at ?? raw.timestamp;
  const subject =
    raw.identity?.sub ??
    raw.subjectId ??
    raw.subject ??
    raw.pseudonym ??
    raw.userId ??
    raw.user?.id;
  const method = raw.method ?? raw.request?.method ?? raw.requestType ?? raw.kind;
  const network = raw.network ?? raw.request?.network ?? raw.context?.network;

  if (
    typeof at !== 'string' ||
    !Number.isFinite(Date.parse(at)) ||
    typeof subject !== 'string' ||
    !subject.trim()
  ) return null;

  return {
    timestamp: Date.parse(at),
    subject: subject.trim(),
    method: typeof method === 'string' ? method.toUpperCase() : null,
    deviceId: readDeviceId(raw),
    network: typeof network === 'string' ? network.toLowerCase() : null,
  };
}

export function detect(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  const bySubject = new Map();
  for (const raw of events) {
    const event = parseEvent(raw);
    if (!event) continue;
    const group = bySubject.get(event.subject) ?? [];
    group.push(event);
    bySubject.set(event.subject, group);
  }

  for (const [subject, eventsForSubject] of bySubject) {
    eventsForSubject.sort((a, b) => a.timestamp - b.timestamp);
    const reads = eventsForSubject.filter(event => event.method === 'GET');

    for (let start = 0, end = 0; end < reads.length; end += 1) {
      while (reads[end].timestamp - reads[start].timestamp >= WINDOW_MS) {
        start += 1;
      }

      if (end - start + 1 <= READ_THRESHOLD) continue;

      const window = reads.slice(start, end + 1);
      const allFromConfirmedDevice = window.every(
        event => event.deviceId === CONFIRMED_VIRTUAL_DEVICE_ID
      );
      const hasUnusualNetwork = window.some(event => event.network === 'unusual');

      // 조회 폭주, 비정상 네트워크, 확인된 가상 기기가 함께 있어야만 제안한다.
      if (!allFromConfirmedDevice || !hasUnusualNetwork) continue;

      return {
        action: 'propose_revocation',
        reasonCode: 'burst_read',
        subject,
        deviceId: CONFIRMED_VIRTUAL_DEVICE_ID,
      };
    }
  }

  return { action: 'observe' };
}
