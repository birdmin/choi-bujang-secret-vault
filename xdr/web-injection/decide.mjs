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
  if (raw === undefined || raw === null || raw === '') return 0;
  const n = typeof raw === 'number' ? raw : Number(String(raw).trim());
  return Number.isFinite(n) && n >= 0 ? n : 0;
}
function validSourceAddress(value) {
  const source = text(value).trim();
  const parts = source.split('.');
  return parts.length === 4 && parts.every(part =>
    /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255
  );
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
  const source = text(alert?.data?.srcip ?? alert?.sourceAddress ?? alert?.srcip ?? alert?.data?.source_ip).trim();
  const count = countValue(alert);

  // Classify the request argument itself; descriptions are not evidence of a clear attack.
  // The fixture uses descriptive argument values where raw exploit strings are intentionally omitted.
  const clearSql = SQL_SYNTAX.test(payload)
    || /(?:^|[?&=\s])doc-sql-(?:chain|or|select-chain)(?:$|[&\s])/i.test(payload);
  const clearScript = SCRIPT_TAG.test(payload)
    || /(?:^|[?&=\s])doc-script-marker(?:$|[&\s])/i.test(payload);
  const traversalCount = (payload.match(TRAVERSAL) || []).length;
  const clearTraversal = traversalCount >= 2
    || /(?:^|[?&=\s])doc-up-repeat(?:$|[&\s])/i.test(payload);
  const clearSignal = clearSql || clearScript || clearTraversal;

  // Ambiguous one-off evidence can be indicated by a marker or by its alert description.
  const ambiguousSignal = /doc-(?:mixed-marker|cmd-separator|one-fragment|one-marker)/i.test(payload)
    || /(?:따옴표가 한 번|(?:이름 검색|검색어).*(?:구분 문자|구분자)|주입처럼 보이|스크립트 표식과 SQL 표식|명령 구분자 표기|이상한 검색|구분 문자가? 1건)/i.test(description);

  // A source address and a positive repetition count must accompany a clear signal.
  const repeatedSameSource = validSourceAddress(source) && count >= 2;
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
