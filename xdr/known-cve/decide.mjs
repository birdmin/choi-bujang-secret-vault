const PATTERNS = Object.freeze([
  {
    name: 'log4shell_jndi_in_header',
    condition: 'A request header value contains a JNDI lookup expression using the ${jndi:...} form.',
    evidence: 'CVE-2021-44228 (Log4Shell) exploitation commonly used JNDI lookup strings in request headers; MITRE ATT&CK T1190 covers exploitation of a public-facing application.',
    matches: (alert) => [
      alert?.data?.useragent,
      alert?.data?.header,
      alert?.data?.headers,
    ].some(hasJndiLookup),
    confidence: 0.98,
    action: 'block',
  },
  {
    name: 'log4shell_jndi_in_argument',
    condition: 'A request URL or parameter value contains a JNDI lookup expression using the ${jndi:...} form.',
    evidence: 'CVE-2021-44228 exploitation attempts may place JNDI lookup strings in request parameters; MITRE ATT&CK T1190 covers exploitation of a public-facing application.',
    matches: (alert) => hasJndiLookup(alert?.data?.url),
    confidence: 0.98,
    action: 'block',
  },
  {
    name: 'known_vulnerability_probe_trace',
    condition: 'An alert explicitly describes a known-vulnerability checking tool or probe trace; do not infer this from a generic library name, the word jndi, a CVE name alone, or a partial expression.',
    evidence: 'The known-cve fixture includes an alert describing a checking-tool-like trace, and the task explicitly permits traces of known-vulnerability checking tools as a signal.',
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
  return /\\$\\s*\\{\\s*jndi\\s*:\\s*(?:ldap|ldaps|rmi|dns|iiop|http|https)\\s*:/iu.test(value);
}

function hasPartialKnownCveSignal(alert) {
  // Only inspect request data for an actual, incomplete lookup expression.
  // CVE/JNDI words in descriptions or ordinary query values are not evidence.
  const requestValues = [
    alert?.data?.useragent,
    alert?.data?.header,
    alert?.data?.headers,
    alert?.data?.url,
    alert?.data?.uri,
    alert?.data?.query,
    alert?.data?.args,
    alert?.data?.parameters,
  ];

  const hasIncompleteLookup = requestValues.some((value) => {
    const text = typeof value === 'string'
      ? value
      : value && typeof value === 'object'
        ? Object.values(value).filter((item) => typeof item === 'string').join(' ')
        : '';
    if (!text) return false;

    // Full, supported expressions are handled as block above. This catches
    // partial JNDI lookup syntax, including a missing protocol or closing brace.
    return /\\$\\s*\\{\\s*jndi(?:\\s*:\\s*(?:ldap|ldaps|rmi|dns|iiop|http|https)?(?:\\s*:\\s*[^}\\s]*)?)?/iu.test(text)
      || /\\$\\s*\\{\\s*jnd\\s*:?/iu.test(text);
  });

  if (hasIncompleteLookup) return true;

  // A specific probe/scanner trace is an alert even without a payload.
  const description = String(alert?.rule?.description ?? '');
  const url = String(alert?.data?.url ?? '');
  return /점검 흔적|점검 도구|probe trace|vulnerability probe/iu.test(description)
    || /(?:^|[/._-])(?:probe|scanner|class-check)(?:[/._?&=-]|$)/iu.test(url);
}

/**
 * Evaluate one Wazuh-shaped alert without I/O or external dependencies.
 * A full JNDI lookup expression is a clear known-exploit signal; weaker
 * request-data indicators are only reported for review. A MITRE label alone
 * is not evidence of an exploit attempt.
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
