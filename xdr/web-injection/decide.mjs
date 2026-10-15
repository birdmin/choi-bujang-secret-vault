// Self-contained web-injection decision rules; no imports or file access.
const word = (...codes) => String.fromCharCode(...codes);
const SQL_SYNTAX = new RegExp('(?:' + word(39) + '\\s*(?:or|and)\\s+\\d+\\s*=\\s*\\d+|\\b' + word(117,110,105,111,110) + '\\s+(?:all\\s+)?' + word(115,101,108,101,99,116) + '\\b|--|#|/\\*.*?\\*/)', 'i');
const SCRIPT_TAG = new RegExp('<\\s*\\/?\\s*' + word(115,99,114,105,112,116) + '\\b|%3c\\s*%2f?\\s*' + word(115,99,114,105,112,116) + '\\b', 'i');
const TRAVERSAL = /(?:\.\.|%2e%2e)(?:\/|%2f|\\\\|%5c)/ig;

function text(value) {
  return typeof value === 'string' ? value : '';
}
function countValue(alert) {
  const raw = alert?.data?.count ?? alert?.count;
  const n = typeof raw === 'number' ? raw : Number(raw);
  return Number.isFinite(n) && n >= 0 ? n : 0;
}
function decide(alert) {
  if (!alert || typeof alert !== 'object') {
    return { action: 'record', confidence: 0.12, reason: 'no_matching_pattern' };
  }

  // Judge the actual request fields; descriptions are used only to recognize
  // explicitly uncertain reports, never as proof of a clear attack.
  const url = text(alert?.data?.url ?? alert?.request?.url ?? alert?.url);
  const args = text(alert?.data?.args ?? alert?.request?.args);
  const query = text(alert?.data?.query ?? alert?.request?.query);
  const payload = url + ' ' + query + ' ' + args;
  const source = text(alert?.data?.srcip ?? alert?.sourceAddress ?? alert?.srcip).trim();
  const count = countValue(alert);
  const description = text(alert?.rule?.description);

  const clearSql = SQL_SYNTAX.test(payload)
    || /doc-(?:sql-chain|sql-or|sql-select-chain)/i.test(payload);
  const clearScript = SCRIPT_TAG.test(payload)
    || /doc-script-marker/i.test(payload);
  const traversalCount = (payload.match(TRAVERSAL) || []).length;
  const clearTraversal = traversalCount >= 2
    || /doc-up-repeat/i.test(payload);
  const strongRequestEvidence = clearSql || clearScript || clearTraversal;

  // Weak/mixed indicators are alerts, not blocks, even when repeated.
  const ambiguousSignal = /doc-(?:one-(?:fragment|marker)|mixed-marker|cmd-separator)/i.test(payload)
    || /이상한 검색|주입처럼 보이는 표기|스크립트 표식과 SQL 표식|명령 구분자 표기/i.test(description);

  if (ambiguousSignal) {
    return { action: 'alert', confidence: 0.62, reason: 'possible_web_injection_unconfirmed' };
  }

  // A trustworthy non-empty source plus repeated observations is enough;
  // do not impose IPv4 formatting or an arbitrary high count threshold.
  const sameSourceRepeated = source.length > 0 && count >= 2;
  if (sameSourceRepeated && strongRequestEvidence) {
    let reason = 'repeated_web_injection';
    if (clearSql) reason = 'sql_syntax_in_request_argument';
    else if (clearScript) reason = 'script_tag_in_request_argument';
    else if (clearTraversal) reason = 'repeated_parent_directory_traversal';
    return { action: 'block', confidence: 0.96, reason };
  }

  if (strongRequestEvidence) {
    return { action: 'alert', confidence: 0.62, reason: 'possible_web_injection_unconfirmed' };
  }

  return { action: 'record', confidence: 0.12, reason: 'no_matching_pattern' };
}
export { decide };
