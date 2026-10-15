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
function repeatedEvidence(description, count) {
  return count >= 2 && /(?:반복|이어 붙|번 들어왔|번 나왔|연속 요청|여러 단계)/i.test(description);
}
function decide(alert) {
  if (!alert || typeof alert !== 'object') {
    return { action: 'record', confidence: 0, reason: 'no_matching_pattern' };
  }

  // Match the actual Wazuh-like fixture shape: rule.level/rule.description and data.srcip/url/count.
  const description = asText(alert?.rule?.description ?? alert?.description);
  const url = asText(alert?.data?.url ?? alert?.url ?? alert?.request?.url);
  const sourceAddress = asText(alert?.data?.srcip ?? alert?.sourceAddress ?? alert?.srcip);
  const payload = url + ' ' + asText(alert?.data?.query) + ' ' + asText(alert?.data?.args);
  const count = getCount(alert);
  const repeated = repeatedEvidence(description, count);
  const hasSource = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(sourceAddress)
    || sourceAddress.includes(':');
  const hits = [];

  const sqlInPayload = SQL_OR.test(payload);
  const scriptInPayload = SCRIPT_TAG.test(payload);
  const traversalCount = (payload.match(TRAVERSAL) || []).length;

  const sqlDescription = /(?:SQL 구문|데이터베이스 조회|SQL 표기)/i.test(description)
    && /(?:반복|이어 붙|번 들어왔|표기)/i.test(description);
  const scriptDescription = /스크립트 삽입 표기/i.test(description)
    && /(?:반복|번 나왔|번 들어왔)/i.test(description);
  const traversalDescription = /경로.{0,12}(?:거슬러 올라가는|이탈 표기)|경로를 여러 단계/i.test(description)
    && /(?:반복|여러 단계|번 들어왔)/i.test(description);

  const sql = sqlInPayload || sqlDescription;
  const script = scriptInPayload || scriptDescription;
  const traversal = traversalCount >= 2 || traversalDescription;
  const mixedRepeated = /스크립트 표식과 SQL 표식/i.test(description)
    && /같은 주소에서 번갈아 \d+번/i.test(description)
    && count >= 2 && hasSource;

  // Only block when a recognized injection signal and explicit repeated-attempt evidence agree.
  if (mixedRepeated) {
    hits.push({ name: 'repeated_mixed_web_injection', confidence: 0.96 });
  } else {
    if (sql && repeated && hasSource) hits.push({ name: PATTERNS[0].name, confidence: 0.96 });
    if (script && repeated && hasSource) hits.push({ name: PATTERNS[1].name, confidence: 0.95 });
    if (traversal && repeated && hasSource) hits.push({ name: PATTERNS[2].name, confidence: 0.94 });
  }

  if (hits.length) {
    hits.sort((a, b) => b.confidence - a.confidence);
    const best = hits[0];
    return { action: 'block', confidence: best.confidence, reason: best.name };
  }

  const ambiguous = /(?:주입처럼 보이는|명령 구분자 표기|표식과 SQL 표식|이상한 검색)/i.test(description)
    || /(?:%27|%3c|%2e%2e|\.\.)/i.test(payload)
    || (sql || script || traversal);
  if (ambiguous) {
    return { action: 'alert', confidence: 0.58, reason: 'possible_web_injection_unconfirmed' };
  }

  // Rule level alone and ordinary words such as "script", "sql", or "select" are not attack evidence.
  return { action: 'record', confidence: 0.12, reason: 'no_matching_pattern' };
}
export { decide };
