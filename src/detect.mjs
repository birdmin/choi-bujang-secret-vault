function normalizeEvents(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');
  return events.map((event) => {
    if (!event || typeof event !== 'object' || Array.isArray(event)) throw new TypeError('invalid_detection_event');

    const at = event.at ?? event.timestamp;
    const method = event.method ?? event.requestType;
    const sub = typeof event.subjectId === 'string' ? event.subjectId : event.identity?.sub;
    const deviceId = typeof event.deviceId === 'string' ? event.deviceId : '';
    const deviceRegistered = event.deviceRegistered === true;
    const networkValue = event.network ?? event.networkClass;
    const network = ['unusual', 'unfamiliar', 'abnormal'].includes(networkValue) ? 'unusual' : 'normal';

    if (typeof at !== 'string' || Number.isNaN(Date.parse(at))
      || typeof method !== 'string' || !method
      || typeof sub !== 'string' || !sub
      || !/^[a-f0-9]{16}$/.test(deviceId)) {
      throw new TypeError('invalid_detection_event');
    }

    return { at, method: method.toUpperCase(), subjectId: sub, deviceId, deviceRegistered, network };
  });
}

function findCompositeSuspicion(events) {
  const reads = events
    .filter((event) => event.method === 'GET' && event.deviceRegistered)
    .sort((a, b) => Date.parse(a.at) - Date.parse(b.at));

  for (let start = 0; start < reads.length; start += 1) {
    const first = reads[start];
    const firstAt = Date.parse(first.at);
    const window = reads.filter((event) => {
      const at = Date.parse(event.at);
      return event.subjectId === first.subjectId
        && event.deviceId === first.deviceId
        && event.deviceRegistered
        && at >= firstAt
        && at - firstAt <= 10 * 60 * 1000;
    });

    if (window.length > 120 && window.some((event) => event.network === 'unusual')) {
      return {
        action: 'propose_revocation',
        targetDeviceId: first.deviceId,
        reasonCode: 'burst_read',
      };
    }
  }
  return null;
}

// This separate detection result does not alter decide()'s response contract,
// call a revocation API, or change device permissions.
export function detect(events) {
  const normalized = normalizeEvents(events);
  return findCompositeSuspicion(normalized) ?? { action: 'observe' };
}
