const WINDOW_MS = 10 * 60 * 1000;
const READ_THRESHOLD = 120;

function eventTime(event) {
  if (typeof event.at !== 'string' || !event.at.trim()) return null;
  const parsed = Date.parse(event.at);
  return Number.isFinite(parsed) ? parsed : null;
}

function readEvent(event) {
  if (!event || typeof event !== 'object' || Array.isArray(event)) return null;

  const timestamp = eventTime(event);
  const method = typeof event.method === 'string' ? event.method.toUpperCase() : null;
  const subject = typeof event.identity?.sub === 'string' && event.identity.sub.trim()
    ? event.identity.sub
    : null;

  if (timestamp === null || method !== 'GET' || subject === null) return null;
  return { timestamp, subject };
}

const observe = () => ({ action: 'observe' });

export function detect(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  const readsBySubject = new Map();

  for (const rawEvent of events) {
    const event = readEvent(rawEvent);
    if (!event) continue;

    const reads = readsBySubject.get(event.subject) ?? [];
    reads.push(event.timestamp);
    readsBySubject.set(event.subject, reads);
  }

  for (const [subject, timestamps] of readsBySubject) {
    timestamps.sort((a, b) => a - b);

    for (let start = 0; start < timestamps.length; start += 1) {
      let end = start;
      while (
        end < timestamps.length
        && timestamps[end] - timestamps[start] < WINDOW_MS
      ) {
        end += 1;
      }

      if (end - start > READ_THRESHOLD) {
        return {
          action: 'propose_revocation',
          reasonCode: 'burst_read',
          subject,
        };
      }
    }
  }

  return observe();
}
