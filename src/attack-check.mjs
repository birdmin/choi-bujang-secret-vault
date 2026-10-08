// The student changes this check as each stage adds an attack to the same app.
//
// Never return tokens, private keys, real names, or note bodies.

export async function runAttackChecks(config) {
  let app;

  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }

  if (
    app.protocol !== 'https:' ||
    app.username ||
    app.password ||
    app.search ||
    app.hash ||
    app.pathname !== '/' ||
    app.hostname.endsWith('.example')
  ) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }

  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) {
    throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
  }

  if (config.step < 4) {
    throw new Error('4단계 저장점에서 메모 소유권 점검을 실행해야 합니다.');
  }

  const results = [];

  const memoResponse = await fetch(new URL('/api/memos', app), {
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
  });

  let memoJson = null;
  try {
    memoJson = await memoResponse.json();
  } catch {
    memoJson = null;
  }

  results.push({
    attackId: 'anonymous_memo_list_read',
    expected: '비로그인 메모 목록 요청은 JSON 401/403으로 차단됨',
    observed: memoResponse.status === 401 || memoResponse.status === 403
      ? '비로그인 /api/memos가 JSON 오류로 차단됨 (HTTP ' + memoResponse.status + ')'
      : '비로그인 /api/memos가 예상 상태가 아님 (HTTP ' + memoResponse.status + ', JSON ' + (memoJson !== null ? '확인' : '없음') + ')',
  });

  const alephResponse = await fetch(new URL('/aleph.json', app), {
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
  });

  results.push({
    attackId: 'anonymous_runtime_config_read',
    expected: '빌드 시 생성된 /aleph.json이 배포되어 있음',
    observed: alephResponse.ok
      ? '배포된 /aleph.json 확인 (HTTP ' + alephResponse.status + ')'
      : '배포된 /aleph.json을 확인하지 못함 (HTTP ' + alephResponse.status + ')',
  });

  const indexResponse = await fetch(new URL('/', app), {
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
  });

  const indexHtml = await indexResponse.text();

  const publicSupabaseKeyPattern = /(?:sb_publishable_[A-Za-z0-9._-]+|(?:anon|anonymous)[^\n]{0,80}eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)/i;
  const hasPublicSupabaseKey = publicSupabaseKeyPattern.test(indexHtml);

  results.push({
    attackId: 'browser_supabase_public_key_exposure',
    expected: '첫 화면 코드에 Supabase 공개 키(sb_publishable_ 또는 anon 키)가 없어야 함',
    observed: hasPublicSupabaseKey
      ? '첫 화면 코드에서 Supabase 공개 키 패턴이 발견됨'
      : '첫 화면 코드에서 Supabase 공개 키 패턴을 찾지 못함',
  });

  let originalApi;

  try {
    originalApi = new URL(config.originalApiUrl);
  } catch {
    throw new Error('aleph.config.json의 원본 API HTTPS 경로를 확인해 주세요.');
  }

  if (
    originalApi.protocol !== 'https:' ||
    originalApi.username ||
    originalApi.password ||
    originalApi.search ||
    originalApi.hash
  ) {
    throw new Error('원본 API 주소에는 HTTPS 경로만 기록해야 합니다.');
  }

  const originalApiResponse = await fetch(originalApi, {
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
  });

  results.push({
    attackId: 'original_api_direct_read',
    expected: '원본 자료 API를 공개 키 없이 직접 요청해도 자료가 노출되지 않아야 함',
    observed: originalApiResponse.status === 401 || originalApiResponse.status === 403
      ? '원본 자료 API 직접 요청이 인증 오류로 차단됨 (HTTP ' + originalApiResponse.status + ')'
      : '원본 자료 API 직접 요청이 예상 상태가 아님 (HTTP ' + originalApiResponse.status + ')',
  });

  const nosniff = indexResponse.headers.get('x-content-type-options');

  results.push({
    attackId: 'response_header_nosniff',
    expected: '첫 화면 응답에 X-Content-Type-Options: nosniff가 적용됨',
    observed: nosniff?.toLowerCase() === 'nosniff'
      ? '첫 화면 응답에서 X-Content-Type-Options: nosniff 확인'
      : '첫 화면 응답의 X-Content-Type-Options가 예상값이 아님 (' + (nosniff ?? '없음') + ')',
  });

  return results;
}
