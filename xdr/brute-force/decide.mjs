// Brute-force patterns are embedded here so the judge can load this file alone.
const PATTERNS = Object.freeze([
  Object.freeze({
    name: 'repeated_login_failures_same_source',
    condition: 'Within a short time window, repeated login failures originate from the same source address.',
    evidence: 'MITRE ATT&CK T1110 describes brute force attempts that repeatedly try credentials to gain access.'
  }),
  Object.freeze({
    name: 'password_spraying_across_accounts',
    condition: 'The same source address attempts authentication against multiple accounts using a shared candidate password.',
    evidence: 'MITRE ATT&CK T1110.003 (Password Spraying) describes trying a password or small set of passwords against many accounts.'
  })
]);

const FAILURE_TERMS = /login failures?|authentication failures?|로그인 실패|인증 실패/i;
const SUCCESS_TERMS = /로그인이 성공|로그인 성공|로그아웃|비밀번호 변경이 성공|자료실 화면이 열렸|세션 유지를 확인|로그인 상태가 유지/i;
const SPRAY_TERMS = /multiple accounts?.{0,60}(same|shared) password|same password.{0,60}multiple accounts?|여러 계정.{0,30}같은 비밀번호|계정 \d+개에 같은 비밀번호|서로 다른 계정.{0,30}같은 비밀번호/i;
const MULTI_ACCOUNT_TERMS = /여러 계정|계정 \d+개|서로 다른 계정|accounts?\s*\d+/i;

function getDescription(alert) {
  return typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
}

function getFailureCount(alert, description) {
  const rawCount = alert?.data?.count;
  const count = typeof rawCount === 'number' ? rawCount : Number(rawCount);
  if (Number.isFinite(count) && count > 0) return count;
  const match = description.match(/(?:실패|failure|failures)\D{0,20}(\d+)\s*(?:건|회|개)?/i)
    || description.match(/(\d+)\s*(?:건|회|개)?\s*(?:의 )?(?:로그인 )?실패/i);
  return match ? Number(match[1]) : 0;
}

/**
 * Decide whether a single alert indicates brute-force activity.
 * This function is self-contained: it performs no imports or file I/O.
 */
export function decide(alert) {
  const description = getDescription(alert);
  const level = Number(alert?.rule?.level);
  const sourceAddress = typeof alert?.data?.srcip === 'string' ? alert.data.srcip.trim() : '';
  const account = typeof alert?.data?.srcuser === 'string' ? alert.data.srcuser.trim() : '';
  const failureCount = getFailureCount(alert, description);
  const hasFailureSignal = FAILURE_TERMS.test(description) || failureCount > 0;
  const hasSpraySignal = SPRAY_TERMS.test(description)
    || (MULTI_ACCOUNT_TERMS.test(description)
      && typeof alert?.data?.accounts === 'string'
      && alert.data.accounts.split(',').map((value) => value.trim()).filter(Boolean).length >= 3);

  if (!description || !Number.isFinite(level) || level < 0 || !sourceAddress || !account) {
    return { action: 'record', confidence: 0.1, reason: 'no_supported_pattern' };
  }

  if (SUCCESS_TERMS.test(description) && !hasFailureSignal && !hasSpraySignal) {
    return { action: 'record', confidence: 0.05, reason: 'no_supported_pattern' };
  }

  if (hasSpraySignal && sourceAddress && (level >= 10 || failureCount >= 10)) {
    return {
      action: 'block',
      confidence: 0.96,
      reason: PATTERNS[1].name
    };
  }

  if (hasFailureSignal && sourceAddress && failureCount >= 20 && level >= 10) {
    return {
      action: 'block',
      confidence: 0.9,
      reason: PATTERNS[0].name
    };
  }

  if (hasSpraySignal) {
    return {
      action: 'alert',
      confidence: 0.7,
      reason: PATTERNS[1].name
    };
  }

  if (hasFailureSignal && (failureCount >= 3 || level >= 7)) {
    return {
      action: 'alert',
      confidence: 0.6,
      reason: PATTERNS[0].name
    };
  }

  return { action: 'record', confidence: 0.2, reason: 'no_supported_pattern' };
}
