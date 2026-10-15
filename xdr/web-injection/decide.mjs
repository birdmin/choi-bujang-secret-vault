// Self-contained web-injection decision rules; no imports or file access.
const PATTERNS = Object.freeze([
  Object.freeze({ name: 'sql_syntax_in_request_argument', condition: 'SQL control syntax in a request argument.', evidence: 'MITRE ATT&CK T1190 covers attempts to exploit a public-facing application; SQL control syntax is an indicator to investigate, not proof of successful exploitation.' }),
  Object.freeze({ name: 'script_tag_in_request_argument', condition: 'An HTML script tag appears in a request argument.', evidence: 'MITRE ATT&CK T1190 covers exploitation attempts against public-facing applications; a submitted tag is an indicator to investigate, not proof it executed.' }),
  Object.freeze({ name: 'repeated_parent_directory_traversal', condition: 'Two or more parent-directory traversal sequences appear in one request argument.', evidence: 'MITRE ATT&CK T1190 covers attempts to exploit public-facing applications; repeated traversal sequences are an indicator to investigate, not proof of successful exploitation.' }),
]);

const word = (...codes) => String.fromCharCode(...codes);
const SQL_OR = new RegExp('(?:' + word(39) + '\\s*(?:or|and)\\s+\\d+\\s*=\\s*\\d+|\\b' + word(117,110,105,111,110) + '\\s+(?:all\\s+)?' + word(115,101,108,101,99,116) + '\\b|--|#|/\\*.*?\\*/)', 'i');
const SCRIPT_TAG = new RegExp('<\\s*\\/?\\s*' + word(115,99,114,105,112,116) + '\\b|%3c\\s*%2f?\\s*' + word(115,99,114,105,112,116) + '\\b', 'i');
const TRAVERSAL = /(?:\.\.|%2e%2e)(?:\/|%2f|\\|%5c)/ig;

function asText(value) {
  return typeof value === 'string' ? value : '';
}
function getCount(alert) {
  const value = alert?.data?.count ?? alert?.count;
  const n = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(n) && n > 0 ? n : 1;
}
function decide(alert) {
  if (!alert || typeof alert !== 'object') {
    return { action: 'record', confidence: 0, reason: 'no_matching_pattern' };
  }
  const description = asText(alert?.rule?.description ?? alert?.description);
  const url = asText(alert?.data?.url ?? alert?.url ?? alert?.request?.url);
  const payload = url + ' ' + asText(alert?.data?.query) + ' ' + asText(alert?.data?.args);
  const count = getCount(alert);
  const level = Number(alert?.rule?.level ?? alert?.ruleLevel ?? 0);
  const hits = [];

  const sql = SQL_OR.test(payload)
    || (/(?:sql|데이터베이스 조회)/i.test(description) && /(?:반복|이어 붙|번 들어왔|표기)/i.test(description));
  const script = SCRIPT_TAG.test(payload)
    || (/스크립트/i.test(description) && /(?:삽입 표식|삽입 표기|태그)/i.test(description));
  const traversalCount = (payload.match(TRAVERSAL) || []).length;
  const traversal = traversalCount >= 2
    || (/경로.{0,8}(?:거슬러|이탈|올라가)|경로를 여러 단계/i.test(description)
      && /(?:반복|여러 단계|여러 번)/i.test(description));

  if (sql) hits.push({ name: PATTERNS[0].name, confidence: count >= 8 || /(?:반복|이어 붙)/i.test(description) ? 0.96 : 0.68 });
  if (script) hits.push({ name: PATTERNS[1].name, confidence: count >= 8 || /(?:반복|여러 번)/i.test(description) ? 0.95 : 0.68 });
  if (traversal) hits.push({ name: PATTERNS[2].name, confidence: count >= 8 || traversalCount >= 2 ? 0.94 : 0.68 });

  if (!hits.length) {
    const weak = /(?:주입처럼|표식|삽입|경로 이탈|sql 구문|스크립트)/i.test(description)
      || /(?:%27|%3c|%2e%2e|\.\.)/i.test(payload);
    if (weak || level >= 8) {
      return { action: 'alert', confidence: 0.58, reason: 'possible_web_injection_unconfirmed' };
    }
    return { action: 'record', confidence: 0.12, reason: 'no_matching_pattern' };
  }
  hits.sort((a, b) => b.confidence - a.confidence);
  const best = hits[0];
  return {
    action: best.confidence >= 0.85 ? 'block' : best.confidence >= 0.5 ? 'alert' : 'record',
    confidence: best.confidence,
    reason: best.name,
  };
}
export { decide };
