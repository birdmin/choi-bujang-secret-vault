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
    // 네트워크는 가상 사건에 명시적으로 제공된 경우에만 사용합니다.
    // 지역 정보는 판정 근거로 사용하지 않습니다.
    const network = event.network === 'unusual' ? 'unusual' : 'normal';
    return { at, method, identity: { sub }, network };
  });
}

function hasCompositeSuspicion(events) {
  const reads = events
    .filter((event) => event.method === 'GET')
    .sort((a, b) => Date.parse(a.at) - Date.parse(b.at));

  for (let start = 0; start < reads.length; start += 1) {
    const firstAt = Date.parse(reads[start].at);
    const window = reads.filter((event) => {
      const at = Date.parse(event.at);
      return event.identity.sub === reads[start].identity.sub
        && at >= firstAt
        && at - firstAt <= 10 * 60 * 1000;
    });

    if (window.length > 120 && window.some((event) => event.network === 'unusual')) {
      return reads[start].identity.sub;
    }
  }
  return null;
}

export function detect(events) {
  const normalized = normalizeEvents(events);
  const subject = hasCompositeSuspicion(normalized);
  if (subject) {
    return { action: 'propose_revocation', reasonCode: 'burst_read', subject };
  }
  return { action: 'observe' };
}
