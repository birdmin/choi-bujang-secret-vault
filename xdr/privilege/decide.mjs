// 독립 실행형 권한 상승 판정기: 외부 모듈, 파일 I/O, 네트워크 요청을 사용하지 않습니다.
const PATTERNS = Object.freeze([
  {
    name: 'unexpected_admin_group_addition',
    condition: '관리자 그룹 추가가 명시되고 경보 수준이 높거나 반복·연계 정황이 있다.',
    mitre: ['T1078'],
    evidence: 'T1078은 유효한 계정의 악용과 관련되며, 관리자 그룹 편입은 계정 권한 악용을 조사할 신호다.',
  },
  {
    name: 'unfamiliar_admin_command',
    condition: '관리자 명령이 명시되고 새 관리자 계정·다른 계정 권한·처음 보는 주소 등 비정상 정황이 함께 있다.',
    mitre: ['T1068', 'T1078'],
    evidence: 'T1068은 권한 상승 악용, T1078은 유효 계정 악용과 관련되며, 비정상 정황과 결합한 관리자 명령은 조사 근거다.',
  },
  {
    name: 'admin_use_outside_work_hours',
    condition: '경보 설명에 업무 시간 밖 권한 사용이 명시되고 관리자 권한 변경 또는 명령 실행이 함께 나타난다.',
    mitre: ['T1068', 'T1078'],
    evidence: 'T1068과 T1078은 권한 상승 및 계정 악용과 관련되며, 업무 시간 밖 권한 사용은 이상 징후로 취급한다.',
  },
]);

function text(value) {
  return typeof value === 'string' ? value.toLowerCase() : '';
}

function decide(alert) {
  const description = text(alert && alert.rule && alert.rule.description);
  const group = text(alert && alert.data && alert.data.group);
  const level = Number(alert && alert.rule && alert.rule.level);
  const hasAdminGroup = /administrators|관리자 그룹/.test(group + ' ' + description)
    && /추가|들어갔|들어왔|편입|추가됐|추가되/.test(description);
  const hasAdminCommand = /관리자 명령|권한 명령/.test(description);
  const becameAdmin = /방금 관리자가 된|관리자 그룹에 들어가고 곧바로|그룹 추가와 명령 실행|관리자 권한으로 바뀌/.test(description);
  const otherAccountPrivilege = /다른 계정의 권한|처음 보는 주소|요청 주소는 처음/.test(description);
  const outsideHours = /수업 시간 밖|업무처럼 보이지 않는 시각|업무 시간 밖/.test(description);
  const repeatedGroupChange = /다시 관리자로|계정 4개|반복/.test(description)
    || Number(alert && alert.data && alert.data.count) >= 2;

  let pattern = null;
  let confidence = 0;
  let reason = '일치하는 권한 상승 패턴이 없어 정상 또는 근거 부족 이벤트로 기록';

  if (hasAdminGroup && hasAdminCommand && level >= 10) {
    pattern = PATTERNS[1];
    confidence = 0.99;
  } else if (hasAdminCommand && (becameAdmin || otherAccountPrivilege) && level >= 10) {
    pattern = PATTERNS[1];
    confidence = 0.96;
  } else if (hasAdminCommand && outsideHours && level >= 10) {
    pattern = PATTERNS[2];
    confidence = 0.92;
  } else if (hasAdminGroup && level >= 10 && repeatedGroupChange) {
    pattern = PATTERNS[0];
    confidence = 0.93;
  } else if (hasAdminGroup && level >= 12) {
    pattern = PATTERNS[0];
    confidence = 0.88;
  } else if (hasAdminGroup && level >= 9) {
    pattern = PATTERNS[0];
    confidence = 0.68;
  } else if (hasAdminCommand && level >= 10) {
    pattern = PATTERNS[1];
    confidence = 0.62;
  } else if (/권한 상승/.test(description) && level >= 7) {
    pattern = PATTERNS[1];
    confidence = 0.56;
  } else if (hasAdminCommand && /실패|취소/.test(description)) {
    pattern = PATTERNS[1];
    confidence = 0.52;
  }

  if (pattern) reason = pattern.name;
  const action = confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record';
  return { action, confidence, reason };
}

export { decide };
