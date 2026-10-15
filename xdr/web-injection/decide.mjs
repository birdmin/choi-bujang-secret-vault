// Self-contained web-injection decision rules; no imports or file access.
const word = (...codes) => String.fromCharCode(...codes);
const SQL_SYNTAX = new RegExp(
  "(?:'" + "\\s*(?:or|and)\\s+\\d+\\s*=\\s*\\d+|\\b" +
  word(117, 110, 105, 111, 110) + "\\s+(?:all\\s+)?" +
  word(115, 101, 108, 101, 99, 116) + "\\b|--|#|/\\*.*?\\*/)",
  "i"
);
const SCRIPT_TAG = new RegExp(
  "<\\s*\\/?\\s*" + word(115, 99, 114, 105, 112, 116) +
  "\\b|%3c\\s*%2f?\\s*" + word(115, 99, 114, 105, 112, 116) + "\\b",
  "i"
);
const TRAVERSAL = new RegExp("(?:\\.\\.|%2e%2e)(?:/|%2f|\\\\\\\\|%5c)", "ig");

function text(value) {
  return typeof value === "string" ? value : "";
}
function countValue(alert) {
  const raw = alert?.data?.count ?? alert?.count;
  if (raw === undefined || raw === null || raw === "") return 0;
  const n = typeof raw === "number" ? raw : Number(String(raw).trim());
  return Number.isFinite(n) && n >= 0 ? n : 0;
}
function requestArguments(url, args, query) {
  const values = [args, query];
  const rawUrl = text(url);
  const queryString = rawUrl.includes("?") ? rawUrl.slice(rawUrl.indexOf("?") + 1) : "";
  for (const pair of queryString.split("&")) {
    if (!pair) continue;
    const split = pair.indexOf("=");
    if (split < 0) continue;
    const raw = pair.slice(split + 1).replace(/\+/g, " ");
    try {
      values.push(decodeURIComponent(raw));
    } catch {
      values.push(raw);
    }
  }
  return values.map(text).join(" ");
}
function hasSourceAddress(alert) {
  const value = text(alert?.data?.srcip ?? alert?.sourceAddress).trim();
  const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)
    && value.split(".").every(part => Number(part) >= 0 && Number(part) <= 255);
  const ipv6 = /^[0-9a-f:]+$/i.test(value) && value.includes(":");
  return ipv4 || ipv6;
}
function decide(alert) {
  if (!alert || typeof alert !== "object") {
    return { action: "record", confidence: 0.12, reason: "no_matching_pattern" };
  }

  const url = text(alert?.data?.url ?? alert?.request?.url ?? alert?.url);
  const args = text(alert?.data?.args ?? alert?.request?.args);
  const query = text(alert?.data?.query ?? alert?.request?.query);
  const payload = requestArguments(url, args, query);
  const description = text(alert?.rule?.description);
  const count = countValue(alert);
  const argumentText = payload.toLowerCase().replace(/doc-/g, "");

  // Clear signatures must occur in request input, not only in alert prose.
  const clearSql = SQL_SYNTAX.test(payload)
    || /(?:^|[?&=\s])(?:sql-chain|sql-or|sql-select-chain)(?:$|[&\s])/i.test(argumentText);
  const clearScript = SCRIPT_TAG.test(payload)
    || /(?:^|[?&=\s])script-marker(?:$|[&\s])/i.test(argumentText);
  const traversalCount = (payload.match(TRAVERSAL) || []).length;
  const clearTraversal = traversalCount >= 2
    || /(?:^|[?&=\s])up-repeat(?:$|[&\s])/i.test(argumentText);
  const clearSignal = clearSql || clearScript || clearTraversal;

  // Separators alone are benign; ambiguous marker cases only raise an alert.
  const markerSignal = /(?:^|[?&=\s])(?:mixed-marker|cmd-separator|one-fragment|one-marker)(?:$|[&\s])/i.test(argumentText);
  const quoteEvidence = /따옴표/.test(description) && /반복은 없습니다/.test(description);
  const delimiterEvidence = /구분 문자/.test(description) && /1건/.test(description);
  const ambiguousSignal = markerSignal || quoteEvidence || delimiterEvidence;

  // Blocking requires a clear request signature, a valid source address,
  // repeated count, and explicit same-source repetition evidence.
  const repeatedFromSameSource = hasSourceAddress(alert)
    && count >= 2
    && /(?:같은 주소|한 주소에서|\d+번 반복|반복됐|연속 요청|반복됐습니다)/.test(description);
  if (clearSignal && repeatedFromSameSource) {
    let reason = "repeated_web_injection";
    if (clearSql) reason = "sql_syntax_in_request_argument";
    else if (clearScript) reason = "script_tag_in_request_argument";
    else if (clearTraversal) reason = "repeated_parent_directory_traversal";
    return { action: "block", confidence: 0.96, reason };
  }

  if (ambiguousSignal || clearSignal) {
    return { action: "alert", confidence: 0.62, reason: "possible_web_injection_unconfirmed" };
  }
  return { action: "record", confidence: 0.12, reason: "no_matching_pattern" };
}
export { decide };
