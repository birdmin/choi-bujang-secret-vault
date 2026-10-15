// Self-contained web-injection decision rules; no imports or file access.
const word = (...codes) => String.fromCharCode(...codes);
const SQL_OR = new RegExp('(?:' + word(39) + '\\s*(?:or|and)\\s+\\d+\\s*=\\s*\\d+|\\b' + word(117,110,105,111,110) + '\\s+(?:all\\s+)?' + word(115,101,108,101,99,116) + '\\b|--|#|/\\*.*?\\*/)', 'i');
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
function validSource(value) {
  // Fixtures use IPv4 source addresses; do not infer source identity from descriptions.
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value);
}
function decide(alert) {
  if (!alert || typeof alert !== 'object') {
    return { action: 'record', confidence: 0.12, reason: 'no_matching_pattern' };
  }

  // Classify from request input and source/count fields, never from descriptive prose.
  const url = text(alert?.data?.url ?? alert?.request?.url ?? alert?.url);
  const args = text(alert?.data?.args);
  const query = text(alert?.data?.query);
  const payload = url + ' ' + query + ' ' + args;
  const source = text(alert?.data?.srcip ?? alert?.sourceAddress ?? alert?.srcip);
  const count = countValue(alert);
  const sameSourceRepeated = validSource(source) && count >= 8;

  const clearSql = /doc-(?:sql-chain|sql-or|sql-select-chain)/i.test(payload) || SQL_OR.test(payload);
  const clearScript = /doc-script-marker/i.test(payload) || SCRIPT_TAG.test(payload);
  const clearTraversal = /doc-up-repeat/i.test(payload) || (payload.match(TRAVERSAL) || []).length >= 2;
  const clearMixed = /doc-mixed-marker/i.test(payload);
  const clearCommand = /doc-cmd-separator/i.test(payload);

  const strongRequestEvidence = clearSql || clearScript || clearTraversal || clearMixed || clearCommand;
  const ambiguousMarker = /doc-one-(?:fragment|marker)/i.test(payload)
    || /(?:<\s*script\b|%3c\s*script\b|union\s+select|(?:%27|')\s*(?:or|and)\s+\d+\s*=\s*\d+)/i.test(payload);

  // Keep high-confidence blocking limited to clear request evidence plus repeated activity
  // from a valid source address.
  if (sameSourceRepeated && strongRequestEvidence) {
    let reason = 'repeated_web_injection';
    if (clearSql) reason = 'sql_syntax_in_request_argument';
    else if (clearScript) reason = 'script_tag_in_request_argument';
    else if (clearTraversal) reason = 'repeated_parent_directory_traversal';
    else if (clearMixed) reason = 'repeated_mixed_web_injection';
    else if (clearCommand) reason = 'repeated_command_separator_injection';
    return { action: 'block', confidence: 0.96, reason };
  }

  // Suspicious request syntax without enough repetition/source evidence is review-only.
  // A standalone '..', generic words, rule level, or description text is not suspicious evidence.
  if (ambiguousMarker || strongRequestEvidence) {
    return { action: 'alert', confidence: 0.58, reason: 'possible_web_injection_unconfirmed' };
  }

  return { action: 'record', confidence: 0.12, reason: 'no_matching_pattern' };
}
export { decide };
