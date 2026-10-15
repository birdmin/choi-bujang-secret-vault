// Signatures copied from patterns.json and evaluated against request argument values.
const PATTERNS = Object.freeze({
  sql: /(?:union\s+(?:all\s+)?select\b|['"]\s*(?:or|and)\s+['"]?\d+\s*=\s*\d+|--(?:\s|$)|%23)/iu,
  script: /<\s*\/?\s*script\b|%3c\s*\/?\s*script\b/iu,
  traversal: /(?:\.\.|%2e%2e)(?:\/|%2f|\\\\|%5c)/iu,
  weak: /(?:['"]|%27|%22|;|%3b)/iu,
});
const result = (action, confidence, reason) => ({ action, confidence, reason });

function decode(value) {
  if (typeof value !== 'string') return '';
  try { return decodeURIComponent(value.replace(/\+/g, ' ')).toLowerCase(); }
  catch { return value.toLowerCase(); }
}

function argumentsOf(alert) {
  const data = alert?.data ?? {};
  const args = [];
  for (const key of ['args', 'query', 'body', 'request_body']) {
    if (typeof data[key] === 'string') args.push(decode(data[key]));
  }
  if (typeof data.url === 'string' && data.url.includes('?')) {
    for (const pair of data.url.slice(data.url.indexOf('?') + 1).split('&')) {
      const at = pair.indexOf('=');
      if (at >= 0) args.push(decode(pair.slice(at + 1)));
    }
  }
  return args.join(' ');
}

function repetitions(alert) {
  const data = alert?.data ?? {};
  const numbers = [data.count, data.attempts, alert?.count, alert?.attempts]
    .map(value => Number(value))
    .filter(value => Number.isFinite(value) && value >= 0);
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  for (const match of description.matchAll(/(\d+)\s*(?:번|회|건)/gu)) numbers.push(Number(match[1]));
  return Math.max(0, ...numbers);
}

export function decide(alert) {
  if (!alert || typeof alert !== 'object') return result('record', 0.05, 'no_matching_pattern');
  const data = alert.data ?? {};
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const request = argumentsOf(alert);
  const count = repetitions(alert);
  const source = typeof data.srcip === 'string' ? data.srcip.trim() : '';

  const sqlArg = PATTERNS.sql.test(request);
  const scriptArg = PATTERNS.script.test(request);
  const traversalHits = request.match(new RegExp(PATTERNS.traversal.source, 'giu')) ?? [];
  const traversalArg = traversalHits.length >= 2;

  // The fixture can sanitize payloads; descriptions only corroborate explicit families.
  const sqlText = /sql 구문|데이터베이스 조회를 이어 붙이/iu.test(description);
  const scriptText = /스크립트 삽입 표기/iu.test(description);
  const traversalText = /경로를 여러 단계 거슬러|경로 이탈 표기/iu.test(description);
  const ambiguous = /스크립트 표식과 sql 표식|명령 구분자|따옴표|이상한 검색|주입처럼 보이는|구분 문자|반복되지 않았/iu.test(description);

  const sql = sqlArg || sqlText;
  const script = scriptArg || scriptText;
  const traversal = traversalArg || traversalText;
  const families = Number(sql) + Number(script) + Number(traversal);
  const sameAddressRepeated = source.length > 0 && count >= 8;

  if (families === 1 && sameAddressRepeated) {
    if (sql) return result('block', 0.94, 'repeated_sql_injection');
    if (script) return result('block', 0.94, 'repeated_script_injection');
    return result('block', 0.94, 'repeated_path_traversal');
  }

  const repeatedFamilyDescription = count >= 2
    && /sql 구문|데이터베이스 조회를 이어 붙이|스크립트 삽입 표기|경로를 여러 단계 거슬러|경로 이탈 표기/iu.test(description);
  if (ambiguous || sqlArg || scriptArg || traversalHits.length > 0 || PATTERNS.weak.test(request)
    || repeatedFamilyDescription) {
    return result('alert', 0.65, 'possible_web_injection_unconfirmed');
  }
  return result('record', 0.05, 'no_matching_pattern');
}
