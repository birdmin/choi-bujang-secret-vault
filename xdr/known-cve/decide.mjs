const PATTERNS = Object.freeze([
  {
    name: 'log4shell_jndi_in_header',
    matches: (alert) => {
      const headers = [
        alert?.data?.useragent,
        alert?.data?.header,
        alert?.data?.headers,
      ];
      return headers.some((value) => hasJndiLookup(value));
    },
    confidence: 0.98,
    action: 'block',
  },
  {
    name: 'log4shell_jndi_in_argument',
    matches: (alert) => hasJndiLookup(alert?.data?.url),
    confidence: 0.98,
    action: 'block',
  },
  {
    name: 'known_vulnerability_probe_trace',
    matches: (alert) => {
      const description = String(alert?.rule?.description ?? '');
      const url = String(alert?.data?.url ?? '');
      return /점검 흔적|점검 도구|probe trace|vulnerability probe/iu.test(description)
        || /(?:^|[/._-])(?:probe|scanner|class-check)(?:[/._?&=-]|$)/iu.test(url);
    },
    confidence: 0.65,
    action: 'alert',
  },
]);

function hasJndiLookup(value) {
  if (typeof value !== 'string') return false;
  return /\$\s*\{\s*jndi\s*:\s*(?:ldap|ldaps|rmi|dns|iiop|http|https)\s*:/iu.test(value);
}

function hasPartialKnownCveSignal(alert) {
  const description = String(alert?.rule?.description ?? '');
  const url = String(alert?.data?.url ?? '');
  const userAgent = String(alert?.data?.useragent ?? '');
  const text = [description, url, userAgent].join(' ');

  if (/CVE-2021-44228/iu.test(text)) return true;
  if (/\bjndi\b/iu.test(text)) return true;
  if (/조회 형태가 잘린|조회 구문은 없습니다|중괄호가 한 번|점검 도구와 비슷한/iu.test(description)) return true;
  return false;
}

/**
 * Evaluate one Wazuh-shaped alert without I/O or external dependencies.
 * A full JNDI lookup expression is a clear known-exploit signal; weaker
 * CVE-related indicators are only reported for review.
 */
export function decide(alert) {
  for (const pattern of PATTERNS) {
    if (pattern.matches(alert)) {
      return {
        action: pattern.action,
        confidence: pattern.confidence,
        reason: pattern.name,
      };
    }
  }

  if (hasPartialKnownCveSignal(alert)) {
    return {
      action: 'alert',
      confidence: 0.6,
      reason: 'known_cve_ambiguous_signal',
    };
  }

  return {
    action: 'record',
    confidence: 0.1,
    reason: 'no_known_cve_pattern',
  };
}
