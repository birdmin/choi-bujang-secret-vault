// Signatures are kept here from patterns.json and applied to request arguments.
const PATTERNS = Object.freeze({
  sql: /(?:['"]\s*(?:or|and)\s+['"]?\d+\s*=\s*\d+|\bunion\s+(?:all\s+)?select\b|--(?:\s|$)|%23)/iu,
  script: /<\s*\/?\s*script\b|%3c\s*\/?\s*script\b/iu,
  traversal: /(?:\.\.|%2e%2e)(?:\/|%2f|\\\\|%5c)/iu,
  weak: /(?:['"]|%27|%22|;|%3b|\b(?:union|select|script|sql|up)\b)/iu,
});
const result = (action, confidence, reason) => ({ action, confidence, reason });

function decode(value) {
  if (typeof value !== 'string') return '';
  let text = value.replace(/\+/g, ' ');
  try { text = decodeURIComponent(text); } catch {}
  return text.toLowerCase();
}

function requestArguments(alert) {
  const data = alert?.data ?? {};
  const out = [];
  for (const field of ['args', 'query', 'body', 'request_body']) {
    if (typeof data[field] === 'string') out.push(decode(data[field]));
  }
  if (typeof data.url === 'string') {
    const query = data.url.split('?')[1] ?? '';
    for (const pair of query.split('&')) {
      const i = pair.indexOf('=');
      if (i >= 0) out.push(decode(pair.slice(i + 1)));
    }
  }
  return out.join(' ');
}

function repetition(alert) {
  const data = alert?.data ?? {};
  const values = [data.count, data.attempts, alert?.count, alert?.attempts];
  const count = Math.max(0, ...values.map(v => {
    const n = Number(v);
    return Number.isFinite(n) && n >= 0 ? n : 0;
  }));
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const matches = [...description.matchAll(/(\d+)\s*(?:번|회|건)/gu)].map(m => Number(m[1]));
  return Math.max(count, 0, ...matches);
}

export function decide(alert) {
  if (!alert || typeof alert !== 'object') return result('record', 0.05, 'no_matching_pattern');
  const request = requestArguments(alert);
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const src = typeof alert?.data?.srcip === 'string' ? alert.data.srcip.trim() : '';
  const count = repetition(alert);
  const sql = PATTERNS.sql.test(request);
  const script = PATTERNS.script.test(request);
  const traversalMatches = request.match(new RegExp(PATTERNS.traversal.source, 'giu')) ?? [];
  const traversal = traversalMatches.length >= 2;
  const clear = Number(sql) + Number(script) + Number(traversal) === 1;
  const repeatEvidence = src.length > 0 && count >= 2;
  if (clear && repeatEvidence) {
    if (sql) return result('block', 0.94, 'repeated_sql_injection');
    if (script) return result('block', 0.94, 'repeated_script_injection');
    return result('block', 0.94, 'repeated_path_traversal');
  }
  const weak = PATTERNS.weak.test(request)
    || /(?:주입|삽입|SQL|스크립트|경로 이탈|경로를.*거슬러|구분 문자|따옴표)/iu.test(description);
  if (weak || sql || script || traversalMatches.length) {
    return result('alert', 0.65, 'possible_web_injection_unconfirmed');
  }
  return result('record', 0.05, 'no_matching_pattern');
}
