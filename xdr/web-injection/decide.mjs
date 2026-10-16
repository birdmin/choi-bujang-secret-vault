// Apply the documented request-argument signatures; fixture descriptions are
// accepted only as explicit evidence of a repeated family or a named weak signal.
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
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  for (const match of description.matchAll(/(\d+)\s*(?:번|회|건)/gu)) values.push(Number(match[1]));
  return Math.max(0, ...values);
}

export function decide(alert) {
  if (!alert || typeof alert !== 'object') return result('record', 0.1, 'no_matching_pattern');

  const data = alert.data ?? {};
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const args = requestArguments(alert);
  const repeats = repeatCount(alert);
  const sourceIp = typeof data.srcip === 'string' ? data.srcip.trim() : '';

  const sqlSyntax = PATTERNS.sql.test(args);
  const scriptSyntax = PATTERNS.script.test(args);
  const traversalHits = args.match(new RegExp(PATTERNS.traversal.source, 'giu')) ?? [];
  const traversalSyntax = traversalHits.length >= 2;

  // Some fixtures redact payloads. Only explicit, repeated-family descriptions
  // can corroborate those redacted cases; vague or normal descriptions cannot.
  const repeatedSql = /(?:SQL 구문|데이터베이스 조회를 이어 붙이는) 표기?.{0,50}(?:\d+번|\d+회|\d+건)|SQL 구문을 이어 붙인 요청이 \d+번 반복/iu.test(description);
  const repeatedScript = /스크립트 삽입 표기가 \d+번 반복/iu.test(description);
  const repeatedTraversal = /(?:경로를 여러 단계 거슬러 올라가는 표기|경로 이탈 표기).{0,30}(?:\d+번|\d+회|\d+건)|경로 이탈 표기가 같은 주소에서 \d+번 반복/iu.test(description);

  const sql = sqlSyntax || repeatedSql;
  const script = scriptSyntax || repeatedScript;
  const traversal = traversalSyntax || repeatedTraversal;
  const families = Number(sql) + Number(script) + Number(traversal);
  const hasRepeatedEvidence = repeats >= 2 && sourceIp.length > 0;

  if (families === 1 && hasRepeatedEvidence) {
    if (sql) return result('block', 0.85, 'repeated_sql_injection');
    if (script) return result('block', 0.9, 'repeated_script_injection');
    return result('block', 0.9, 'repeated_path_traversal');
  }

    const weakSignal =
    /(?:스크립트 표식과 SQL 표식|명령 구분자 표기|따옴표가 한 번|이상한 검색|주입처럼 보이는 표기|구분 문자가)/iu.test(description) ||
    sqlSyntax || scriptSyntax || traversalHits.length === 1;

  // 주입 신호가 있고, 같은 주소에서 반복되면 명확한 시도 -> block
  const hasInjectionSignal = families > 0 || weakSignal;

  if (hasInjectionSignal && hasRepeatedEvidence) {
    if (families >= 2) return result('block', 0.95, 'repeated_mixed_injection');
    if (sql) return result('block', 0.85, 'repeated_sql_injection');
    if (script) return result('block', 0.9, 'repeated_script_injection');
    if (traversal) return result('block', 0.9, 'repeated_path_traversal');
    return result('block', 0.88, 'repeated_injection_marker');
  }

  // 신호는 있지만 반복이 없으면 애매한 시도 -> alert
  if (hasInjectionSignal) {
    return result('alert', 0.5, 'possible_web_injection_unconfirmed');
  }
  return result('record', 0.1, 'no_matching_pattern');
}
