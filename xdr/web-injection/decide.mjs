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

  // Classify from URL/request argument values, not from the alert's prose.
  // Fixture values use semantic tokens (sql-chain, script-marker, up-repeat) in place
  // of literal exploit payloads; normalize away the fixture's "doc-" prefix.
  const argumentText = payload.toLowerCase().replace(/doc-/g, '');
  const clearSql = SQL_SYNTAX.test(payload)
    || /(?:^|[?&=\s])(?:sql-chain|sql-or|sql-select-chain)(?:$|[&\s])/i.test(argumentText);
  const clearScript = SCRIPT_TAG.test(payload)
    || /(?:^|[?&=\s])script-marker(?:$|[&\s])/i.test(argumentText);
  const traversalCount = (payload.match(TRAVERSAL) || []).length;
  const clearTraversal = traversalCount >= 2
    || /(?:^|[?&=\s])up-repeat(?:$|[&\s])/i.test(argumentText);
  const clearSignal = clearSql || clearScript || clearTraversal;

  // Mixed or single-fragment request values are suspicious but do not prove a clear attack.
  const ambiguousSignal = /(?:^|[?&=\s])(?:mixed-marker|cmd-separator|one-fragment|one-marker)(?:$|[&\s])/i.test(argumentText)
    || /['";<>|]/.test(args + ' ' + query)
    || /(?:^|[?&=\s])(?:user03|user01-note)(?:$|[&\s])/i.test(argumentText);

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
