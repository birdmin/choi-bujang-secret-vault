  const CONFIRMED_VIRTUAL_DEVICE_ID = 'aaaaaaaaaaaaaaaa';

function normalizeEvents(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');
  return events.map((event) => {
    if (!event || typeof event !== 'object' || Array.isArray(event)) throw new TypeError('invalid_detection_event');
    const at = event.at;
    const method = event.method;
    const sub = event.identity?.sub;
    if (typeof at !== 'string' || Number.isNaN(Date.parse(at)) || typeof method !== 'string' || !method || typeof sub !== 'string' || !sub) {
      throw new TypeError('invalid_detection_event');
    }
    // 회수 제안은 확인된 단일 가상 기기에만 한정합니다.
    const deviceId = typeof event.deviceId === 'string' ? event.deviceId : '';
    const deviceRegistered = event.deviceRegistered === true;
    const network = event.network === 'unusual' ? 'unusual' : 'normal';
    return { at, method, identity: { sub }, deviceId, deviceRegistered, network };
  });
}

function findCompositeSuspicion(events) {
  const reads = events
    .filter((event) => event.method === 'GET')
    .sort((a, b) => Date.parse(a.at) - Date.parse(b.at));

  for (let start = 0; start < reads.length; start += 1) {
    const first = reads[start];
    if (first.deviceId !== CONFIRMED_VIRTUAL_DEVICE_ID || !first.deviceRegistered) continue;
    const firstAt = Date.parse(first.at);
    const window = reads.filter((event) => {
      const at = Date.parse(event.at);
      return event.identity.sub === first.identity.sub
        && event.deviceId === CONFIRMED_VIRTUAL_DEVICE_ID
        && event.deviceRegistered
        && at >= firstAt
        && at - firstAt <= 10 * 60 * 1000;
    });

    
if (window.length > 120 && window.some((event) => event.network === 'unusual')) {
  return {
    action: 'propose_revocation',
    targetDeviceId: CONFIRMED_VIRTUAL_DEVICE_ID,
    reasonCode: 'burst_read',
  };
}

  }
  return null;
}

// This is a separate detection result. It does not alter decide()'s allow/deny contract
// and does not call a revocation API or change device permissions.
export function detect(events) {
  const normalized = normalizeEvents(events);
  return findCompositeSuspicion(normalized) ?? { action: 'observe' };
}
