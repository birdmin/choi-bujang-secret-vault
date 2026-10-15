// The student changes this check as each stage adds an attack to the same app.
//
// Never return tokens, private keys, real names, or note bodies.
// This bundle runner has no access to the judge's server-side request ledger.
// Therefore it must not turn its own unrelated HTTP probes into judge evidence.
// Until a matching judge request record is available, each check is not_run.

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

  // These are the five checks in the submission record. No corresponding
  // judge request IDs/timestamps were supplied to this runner, so do not
  // invent HTTP statuses, request IDs, or timestamps and do not send probes
  // that could be misrepresented as judge-recorded attacks.
  return [
    {
      attackId: 'anonymous_memo_list_read',
      expected: '비로그인 메모 목록 요청은 JSON 401/403으로 차단됨',
      observed: 'not_run',
    },
    {
      attackId: 'anonymous_runtime_config_read',
      expected: '배포된 /aleph.json에 allowedRoutes와 원본 HTTPS API 경로가 포함되어 있어야 함',
      observed: 'not_run',
    },
    {
      attackId: 'browser_supabase_public_key_exposure',
      expected: '첫 화면 코드에 Supabase 공개 키(sb_publishable_ 또는 anon 키)가 없어야 함',
      observed: 'not_run',
    },
    {
      attackId: 'original_api_direct_read',
      expected: '원본 자료 API를 공개 키 없이 직접 요청해도 자료가 노출되지 않아야 함',
      observed: 'not_run',
    },
    {
      attackId: 'response_header_nosniff',
      expected: '첫 화면 응답에 X-Content-Type-Options: nosniff가 적용됨',
      observed: 'not_run',
    },
  ];
}
