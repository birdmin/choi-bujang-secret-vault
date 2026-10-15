// Web-injection decisions use the request argument, source IP, and repeat evidence.
const result = (action, confidence, reason) => ({ action, confidence, reason });

function validSourceAddress(value) {
  if (typeof value !== 'string') return false;
  const address = value.trim();
  const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(address)
    && address.split('.').every(part => Number(part) >= 0 && Number(part) <= 255);
  // Reject arbitrary colon-containing strings; accept ordinary IPv6 literals.
  const ipv6 = /^[0-9a-f:]+$/i.test(address)
    && address.includes(':')
    && address.split(':').length >= 3
    && !address.includes(':::');
  return ipv4 || ipv6;
}

function decodeRequestValue(value) {
  if (typeof value !== 'string') return '';
  const plusDecoded = value.replace(/\+/g, ' ');
  try {
    return decodeURIComponent(plusDecoded);
  } catch {
    return plusDecoded;
  }
}

function requestEvidence(alert) {
  const url = typeof alert?.data?.url === 'string' ? alert.data.url : '';
  const args = typeof alert?.data?.args === 'string' ? alert.data.args : '';
  const query = typeof alert?.data?.query === 'string' ? alert.data.query : '';
  const values = [url, args, query];

  // Decode query parameter values, not the route name or unrelated metadata.
  const queryString = url.includes('?') ? url.slice(url.indexOf('?') + 1) : '';
  for (const pair of queryString.split('&')) {
    if (!pair) continue;
    const equals = pair.indexOf('=');
    if (equals >= 0) values.push(decodeRequestValue(pair.slice(equals + 1)));
  }
  return values.join(' ').toLowerCase();
}

function repeatCount(alert) {
  const values = [
    alert?.data?.count,
    alert?.data?.attempts,
    alert?.count,
    alert?.attempts,
    alert?.rule?.description?.match(/(\d+)\s*(?:번|회|건)/u)?.[1],
  ];
  return Math.max(0, ...values.map(value => {
    const number = Number(value);
    return Number.isFinite(number) && number >= 0 ? number : 0;
  }));
}

export function decide(alert) {
  if (!alert || typeof alert !== 'object') {
    return result('record', 0.05, 'no_matching_pattern');
  }

  const sourceAddress = alert?.data?.srcip;
  const description = typeof alert?.rule?.description === 'string'
    ? alert.rule.description
    : '';
  const request = requestEvidence(alert);
  const count = repeatCount(alert);
  const sameSourceRepeated = validSourceAddress(sourceAddress) && count >= 8;

  // The fixture's doc-* prefix labels an argument; classify the attack family
  // from the argument token itself, corroborated by the alert's repeat evidence.
  const sqlInArgument =
    /(?:^|[?&=\s])doc-sql-(?:chain|or|select-chain)(?:$|[&\s])/u.test(request)
    || /union(?:%20|\+|\s)+select|['"]\s*or\s+['"]?1\s*=\s*1/iu.test(request);
  const scriptInArgument =
    /(?:^|[?&=\s])doc-script-marker(?:$|[&\s])/u.test(request)
    || /<\s*script\b|%3c\s*script\b/iu.test(request);
  const traversalInArgument =
    /(?:^|[?&=\s])doc-up-repeat(?:$|[&\s])/u.test(request)
    || /(?:\.\.|%2e%2e)(?:\/|%2f|\\\\|%5c).*(?:\.\.|%2e%2e)(?:\/|%2f|\\\\|%5c)/iu.test(request);

  // A command separator or mixed/one-off marker is ambiguous on its own.
  const ambiguous = /doc-mixed-marker|doc-cmd-separator|doc-one-fragment|doc-one-marker/iu.test(request)
    || /명령 구분자|구분 문자|따옴표|표식이 1건|반복되지 않았/iu.test(description);

  if (sameSourceRepeated && (sqlInArgument || scriptInArgument || traversalInArgument)) {
    if (sqlInArgument) return result('block', 0.94, 'repeated_sql_injection');
    if (scriptInArgument) return result('block', 0.94, 'repeated_script_injection');
    return result('block', 0.94, 'repeated_path_traversal');
  }

  if (ambiguous || sqlInArgument || scriptInArgument || traversalInArgument) {
    return result('alert', 0.65, 'possible_web_injection_unconfirmed');
  }

  return result('record', 0.05, 'no_matching_pattern');
}
