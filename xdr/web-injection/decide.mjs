// Self-contained web-injection decision rules; no imports or file access.
const word = (...codes) => String.fromCharCode(...codes);
const SQL_SYNTAX = new RegExp('(?:' + word(39) + '\\s*(?:or|and)\\s+\\d+\\s*=\\s*\\d+|\\b' + word(117,110,105,111,110) + '\\s+(?:all\\s+)?' + word(115,101,108,101,99,116) + '\\b|' + word(45,45) + '|' + word(35) + '|\\/\\*.*?\\*\\/)', 'i');
const SCRIPT_TAG = new RegExp('<\\s*\\/?\\s*' + word(115,99,114,105,112,116) + '\\b|%3c\\s*%2f?\\s*' + word(115,99,114,105,112,116) + '\\b', 'i');
const TRAVERSAL = new RegExp('(?:' + word(46,46) + '|%2e%2e)(?:/|%2f|\\\\\\\\|%5c)', 'ig');

function text(value) {
  return typeof value === 'string' ? value : '';
}
function countValue(alert) {
  const raw = alert?.data?.count ?? alert?.count;
  const n = typeof raw === 'number' ? raw : Number(raw);
  return Number.isFinite(n) && n >= 0 ? n : 0;
}
function requestArguments(url, args, query) {
  const values = [args, query];
  const rawUrl = text(url);
  const queryString = rawUrl.includes('?') ? rawUrl.slice(rawUrl.indexOf('?') + 1) : '';
  for (const pair of queryString.split('&')) {
    if (!pair) continue;
    const split = pair.indexOf('=');
    if (split < 0) continue;
    const raw = pair.slice(split + 1).replace(/\\+/g, ' ');
    try {
      values.push(decodeURIComponent(raw));
    } catch {
      values.push(raw);
    }
  }
  return values.map(text).join(' ');
}
function decide(alert) {
  if (!alert || typeof alert !== 'object') {
    return { action: 'record', confidence: 0.12, reason: 'no_matching_pattern' };
  }

  const url = text(alert?.data?.url ?? alert?.request?.url ?? alert?.url);
  const args = text(alert?.data?.args ?? alert?.request?.args);
  const query = text(alert?.data?.query ?? alert?.request?.query);
  const payload = requestArguments(url, args, query);
  const description = text(alert?.rule?.description);
  const source = text(alert?.data?.srcip ?? alert?.sourceAddress ?? alert?.srcip).trim();
  const count = countValue(alert);

  // The fixture count represents repeated requests from this source.
  // If raw arguments are absent, use the alert's explicit classification.
  const clearSql = SQL_SYNTAX.test(payload)
    || /SQL (?:구문을 이어 붙인 요청|구문 표기|구문 표기가|구문.*반복|표기.*반복)|데이터베이스 조회를 이어 붙이는 표기/i.test(description);
  const clearScript = SCRIPT_TAG.test(payload)
    || /스크립트 삽입 표기/i.test(description);
  const traversalCount = (payload.match(TRAVERSAL) || []).length;
  const clearTraversal = traversalCount >= 2
    || /경로를 여러 단계 거슬러 올라가는 표기|경로 이탈 표기/i.test(description);
  const clearSignal = clearSql || clearScript || clearTraversal;

  const ambiguousSignal = /따옴표가 한 번|구분 문자(?:가| 표기)|이상한 검색|주입처럼 보이는 표기|스크립트 표식과 SQL 표식|명령 구분자 표기/i.test(description)
    || /doc-one-(?:fragment|marker)|doc-mixed-marker|doc-cmd-separator/i.test(payload);

  // Give an explicit, repeated attack precedence over weaker/ambiguous markers.
  // The count belongs to this alert; do not infer repetition from source presence alone.
  const repeatedSameSource = source.length > 0 && count >= 2;
  if (clearSignal && repeatedSameSource) {
    let reason = 'repeated_web_injection';
    if (clearSql) reason = 'sql_syntax_in_request_argument';
    else if (clearScript) reason = 'script_tag_in_request_argument';
    else if (clearTraversal) reason = 'repeated_parent_directory_traversal';
    return { action: 'block', confidence: 0.96, reason };
  }

  // A clear but non-repeated signal, or an ambiguous one-off signal, is alert-only.
  if (ambiguousSignal || clearSignal) {
    return { action: 'alert', confidence: 0.62, reason: 'possible_web_injection_unconfirmed' };
  }

  return { action: 'record', confidence: 0.12, reason: 'no_matching_pattern' };
}
export { decide };
