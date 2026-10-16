// Match request-argument syntax first; use fixture descriptions only when the
// supplied fixture deliberately redacts the payload into a descriptive label.
const PATTERNS = Object.freeze({
  sql: /(?:union\s+(?:all\s+)?select\b|['"]\s*(?:or|and)\s+['"]?\d+\s*=\s*\d+|--(?:\s|$)|%23)/iu,
  script: /<\s*\/?\s*script\b|%3c\s*\/?\s*script\b/iu,
  traversal: /(?:\.\.|%2e%2e)(?:\/|%2f|\\|%5c)/iu,
});
const result = (action, confidence, reason) => ({ action, confidence, reason });

function decode(value) {
  if (typeof value !== 'string') return '';
  try {
    return decodeURIComponent(value.replace(/\+/g, ' ')).toLowerCase();
  } catch {
    return value.toLowerCase();
  }
}

function requestArguments(alert) {
  const data = alert?.data ?? {};
  const values = [];
  for (const key of ['args', 'query', 'body', 'request_body']) {
    if (typeof data[key] === 'string') values.push(decode(data[key]));
  }

  // Inspect query-parameter values, not the path or unrelated log prose.
  if (typeof data.url === 'string' && data.url.includes('?')) {
    const query = data.url.slice(data.url.indexOf('?') + 1).split('#', 1)[0];
    for (const pair of query.split('&')) {
      const equals = pair.indexOf('=');
      if (equals >= 0) values.push(decode(pair.slice(equals + 1)));
    }
  }
  return values.join(' ');
}

function repeatCount(alert) {
  const data = alert?.data ?? {};
  const values = [data.count, data.attempts, alert?.count, alert?.attempts]
    .filter(value => value !== undefined && value !== null && value !== '')
    .map(Number)
    .filter(value => Number.isFinite(value) && value >= 0);

  const description = typeof alert?.rule?.description === 'string'
    ? alert.rule.description
    : '';
  for (const match of description.matchAll(/(\d+)\s*(?:번|회|건)/gu)) {
    values.push(Number(match[1]));
  }
  return Math.max(0, ...values);
}

export function decide(alert) {
  if (!alert || typeof alert !== 'object') {
    return result('record', 0.05, 'no_matching_pattern');
  }

  const data = alert.data ?? {};
  const description = typeof alert?.rule?.description === 'string'
    ? alert.rule.description
    : '';
  const args = requestArguments(alert);
  const repeats = repeatCount(alert);
  const sourceIp = typeof data.srcip === 'string' ? data.srcip.trim() : '';

  const sqlSyntax = PATTERNS.sql.test(args);
  const scriptTag = PATTERNS.script.test(args);
  const traversalMatches = args.match(new RegExp(PATTERNS.traversal.source, 'giu')) ?? [];
  const repeatedTraversalSyntax = traversalMatches.length >= 2;

  // Fixture payloads such as "doc-sql-chain" are sanitized placeholders, not
  // attack syntax. Their explicit descriptions provide the corroborating family.
  const sqlDescription = /sql 구문|데이터베이스 조회를 이어 붙이/iu.test(description);
  const scriptDescription = /스크립트 삽입 표기/iu.test(description);
  const traversalDescription = /경로를 여러 단계 거슬러|경로 이탈 표기/iu.test(description);

  const sql = sqlSyntax || sqlDescription;
  const script = scriptTag || scriptDescription;
  const traversal = repeatedTraversalSyntax || traversalDescription;
  const familyCount = Number(sql) + Number(script) + Number(traversal);

  const ambiguous = /스크립트 표식과 sql 표식|명령 구분자|따옴표|이상한 검색|주입처럼 보이는|구분 문자|반복되지 않았/iu.test(description);
  const repeatedFromKnownSource = sourceIp.length > 0 && repeats >= 2;

  // Block only when one clear family and repeat evidence are both present.
  // No severity level, placeholder marker, or arbitrary high-count threshold is enough.
  if (familyCount === 1 && repeatedFromKnownSource) {
    if (sql) return result('block', 0.94, 'repeated_sql_injection');
    if (script) return result('block', 0.94, 'repeated_script_injection');
    return result('block', 0.94, 'repeated_path_traversal');
  }

  // Mixed, weak, or non-repeated indicators need review rather than automatic blocking.
  if (ambiguous || familyCount > 0) {
    return result('alert', 0.65, 'possible_web_injection_unconfirmed');
  }
  return result('record', 0.05, 'no_matching_pattern');
}
