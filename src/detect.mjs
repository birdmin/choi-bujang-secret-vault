const WINDOW_MS = 10 * 60 * 1000;
const READ_THRESHOLD = 120;
const ALLOWED_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);

function firstString(...values) {
  return values.find(value => typeof value === 'string' && value.trim().length > 0) ?? null;
}

function eventTime(event) {
  const value = event.at ?? event.timestamp ?? event.time;
  if (typeof value === 'number' && Number.isFinite(value)) {
    // Accept epoch milliseconds and epoch seconds without guessing from strings.
    return value < 100000000000 ? value * 1000 : value;
  }
  if (typeof value !== 'string' || !value.trim()) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function readEvent(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;

  const timestamp = eventTime(raw);
  const method = firstString(
    raw.method, raw.requestType, raw.request?.method, raw.type
  )?.toUpperCase() ?? null;
  const subject = firstString(
    raw.identity?.sub, raw.subjectId, raw.subject, raw.pseudonym,
    raw.userId, raw.user?.id
  );
  const network = firstString(
    raw.network, raw.signals?.network, raw.context?.network,
    raw.request?.network
  );
  const deviceId = firstString(
    raw.deviceId, raw.device?.id, raw.identity?.deviceId,
    raw.context?.deviceId, raw.request?.deviceId
  );

  if (timestamp === null || !ALLOWED_METHODS.has(method ?? '')
      || !subject) return null;

  return { timestamp, method, subject, network, deviceId };
}

const observe = () => ({ action: 'observe' });

function proposal(subject, deviceId) {
  return {
    action: 'propose_revocation',
    reasonCode: 'compound_network_burst',
    ...(subject ? { subject } : {}),
    deviceId,
    propose_revocation: {
      targetDeviceId: deviceId,
      reasonCode: 'composite_anomaly',
    },
  };
}

function detectCompactRequest(request) {
  const network = firstString(
    request.signals?.network, request.network, request.context?.network
  );
  const subject = firstString(
    request.subjectId, request.identity?.sub, request.subject,
    request.pseudonym, request.userId, request.user?.id
  );
  const deviceId = firstString(
    request.deviceId, request.device?.id, request.identity?.deviceId,
    request.context?.deviceId, request.request?.deviceId
  );
  const recentEvents = Array.isArray(request.recentEvents) ? request.recentEvents : [];
  const bulkReading = recentEvents.some(event => {
    if (!event || typeof event !== 'object') return false;
    const kind = firstString(event.kind, event.type, event.eventType);
    const count = event.count ?? event.readCount ?? event.total;
    const age = event.ageSeconds ?? event.age_seconds;
    return ['risk_signal', 'burst_read', 'bulk_read', 'read_burst'].includes(kind)
      && Number.isInteger(age) && age >= 0 && age <= 300
      && Number.isInteger(count) && count >= 10;
  });

  if (network !== 'unusual' || !bulkReading || !deviceId) return observe();
  return proposal(subject, deviceId);
}

export function detect(events) {
  if (events && typeof events === 'object' && !Array.isArray(events)) {
    return detectCompactRequest(events);
  }
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  const safeEvents = events.map(readEvent).filter(Boolean);
  const readsBySubject = new Map();

  for (const event of safeEvents) {
    if (event.method !== 'GET') continue;
    const reads = readsBySubject.get(event.subject) ?? [];
    reads.push(event);
    readsBySubject.set(event.subject, reads);
  }

  for (const [subject, reads] of readsBySubject) {
    reads.sort((a, b) => a.timestamp - b.timestamp);

    for (let start = 0; start < reads.length; start += 1) {
      const first = reads[start];
      let end = start;
      while (end < reads.length && reads[end].timestamp - first.timestamp < WINDOW_MS) end += 1;
      if (end - start <= READ_THRESHOLD) continue;

      const unusualNetworkRead = reads
        .slice(start, end)
        .find(event => event.network === 'unusual' && event.deviceId);
      if (!unusualNetworkRead) continue;

      return proposal(subject, unusualNetworkRead.deviceId);
    }
  }

  return observe();
}
