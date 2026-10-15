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
  // Record evidence from the response actually received. Prefer the request ID
  // supplied by the server/platform; never fabricate one if no ID is exposed.
  const responseEvidence = (response) => {
    const requestId = response.headers.get('x-request-id')
      || response.headers.get('request-id')
      || response.headers.get('sb-request-id')
      || response.headers.get('x-kong-request-id')
      || response.headers.get('cf-ray')
      || response.headers.get('x-vercel-id')
      || 'not_provided_by_response';
    const checkedAt = new Date().toISOString();
    return `HTTP ${response.status}; requestId=${requestId}; checkedAt=${checkedAt}`;
  };
  const checkedFetch = async (label, url, options = {}) => {
    try {
      return await fetch(url, options);
    } catch (error) {
      const cause = error?.cause?.code || error?.cause?.message || error?.message || 'unknown';
      try {
        const probe = await fetch(url, { ...options, redirect: 'manual' });
        const location = probe.headers.get('location');
        if (probe.status >= 300 && probe.status < 400) {
          let destination = '확인 불가';
          try {
            destination = location ? new URL(location, url).origin + new URL(location, url).pathname : 'Location 헤더 없음';
          } catch {}
          throw new Error(`HTTP ${probe.status}, redirect target: ${destination}`);
        }
      } catch (probeError) {
        if (probeError.message?.startsWith('HTTP ')) {
          throw new Error(`공격 점검 요청 실패 [${label}] (${new URL(url).origin}): ${probeError.message}`);
        }
      }
      throw new Error(`공격 점검 요청 실패 [${label}] (${new URL(url).origin}): ${cause}`);
    }
  };

  const memoResponse = await checkedFetch('anonymous_memo_list_read', new URL('/api/notes', app), {
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
      ? '비로그인 /api/notes가 JSON 오류로 차단됨 (HTTP ' + memoResponse.status + '); ' + responseEvidence(memoResponse)
      : '비로그인 /api/notes가 예상 상태가 아님 (HTTP ' + memoResponse.status + ', JSON ' + (memoJson !== null ? '확인' : '없음') + '); ' + responseEvidence(memoResponse),
  });

  const alephResponse = await checkedFetch('anonymous_runtime_config_read', new URL('/aleph.json', app), {
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
  });

  let alephJson = null;
  try {
    alephJson = await alephResponse.json();
  } catch {
    alephJson = null;
  }

  const deployedAllowedRoutes = Array.isArray(alephJson?.allowedRoutes)
    ? alephJson.allowedRoutes
    : [];
  const deployedOriginalApiUrl = typeof alephJson?.originalApiUrl === 'string'
    ? alephJson.originalApiUrl
    : '';

  const deploymentIdentityComplete =
    alephResponse.ok &&
    deployedAllowedRoutes.length === config.allowedRoutes.length &&
    config.allowedRoutes.every((route) => deployedAllowedRoutes.includes(route)) &&
    deployedOriginalApiUrl === config.originalApiUrl;

  results.push({
    attackId: 'anonymous_runtime_config_read',
    expected: '배포된 /aleph.json에 allowedRoutes와 원본 HTTPS API 경로가 포함되어 있어야 함',
    observed: deploymentIdentityComplete
      ? '배포된 /aleph.json에서 allowedRoutes와 originalApiUrl 확인 (HTTP ' + alephResponse.status + '); ' + responseEvidence(alephResponse)
      : '배포된 /aleph.json의 배포 식별 정보가 설정과 일치하지 않음 (HTTP ' + alephResponse.status + '); ' + responseEvidence(alephResponse),
  });

  const indexResponse = await checkedFetch('response_header_nosniff', new URL('/', app), {
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
      ? '첫 화면 코드에서 Supabase 공개 키 패턴이 발견됨; ' + responseEvidence(indexResponse)
      : '첫 화면 코드에서 Supabase 공개 키 패턴을 찾지 못함; ' + responseEvidence(indexResponse),
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

  const originalApiResponse = await checkedFetch('original_api_direct_read', originalApi, {
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
  });

  results.push({
    attackId: 'original_api_direct_read',
    expected: '원본 자료 API를 공개 키 없이 직접 요청해도 자료가 노출되지 않아야 함',
    observed: originalApiResponse.status === 401 || originalApiResponse.status === 403
      ? '원본 자료 API 직접 요청이 인증 오류로 차단됨 (HTTP ' + originalApiResponse.status + '); ' + responseEvidence(originalApiResponse)
      : '원본 자료 API 직접 요청이 예상 상태가 아님 (HTTP ' + originalApiResponse.status + '); ' + responseEvidence(originalApiResponse),
  });

  const nosniff = indexResponse.headers.get('x-content-type-options');

  results.push({
    attackId: 'response_header_nosniff',
    expected: '첫 화면 응답에 X-Content-Type-Options: nosniff가 적용됨',
    observed: nosniff?.toLowerCase() === 'nosniff'
      ? '첫 화면 응답에서 X-Content-Type-Options: nosniff 확인; ' + responseEvidence(indexResponse)
      : '첫 화면 응답의 X-Content-Type-Options가 예상값이 아님 (' + (nosniff ?? '없음') + '); ' + responseEvidence(indexResponse),
  });

  return results;
}
