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
    return { at, method, identity: { sub } };
  });
}

export function detect(events) {
  normalizeEvents(events);
  return { action: 'observe' };
}
