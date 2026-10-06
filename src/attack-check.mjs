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

  if (config.step < 2) {
    throw new Error('2단계 이후의 공격 점검은 2단계 저장점에서 실행해야 합니다.');
  }

  const results = [];

  const dataResponse = await fetch(new URL('/data.json', app), {
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
  });

  let notes = null;

  if (dataResponse.ok) {
    try {
      const data = await dataResponse.json();
      notes = data?.notes;
    } catch {
      notes = null;
    }
  }

  const staticNotesEmpty =
    Array.isArray(notes) && notes.length === 0;

  results.push({
    attackId: 'anonymous_static_note_read',
    expected: '비로그인 정적 파일에서 가상 메모가 보이지 않음',
    observed: staticNotesEmpty
      ? '비로그인 /data.json에서 메모 0건 확인'
      : `비로그인 /data.json에서 메모가 제거되지 않음 (HTTP ${dataResponse.status})`,
  });

  const apiResponse = await fetch(new URL('/api/notes', app), {
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
  });

  let apiNotes = null;

  if (apiResponse.ok) {
    try {
      const data = await apiResponse.json();
      apiNotes = data?.notes;
    } catch {
      apiNotes = null;
    }
  }

  const apiPublic =
    Array.isArray(apiNotes) && apiNotes.length > 0;

  results.push({
    attackId: 'anonymous_api_note_read',
    expected: '2단계에서는 공개 API의 접근 제어가 아직 없음을 확인',
    observed: apiPublic
      ? '비로그인 /api/notes에서 서버 측 가상 메모가 반환됨'
      : `비로그인 /api/notes에서 가상 메모가 반환되지 않음 (HTTP ${apiResponse.status})`,
  });

  return results;
}
