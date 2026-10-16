const PATTERNS = [
  {
    id: 'unsigned_new_service',
    name: '서명 없는 새 서비스 등록',
    condition: '새 서비스 등록·변경과 서명 부재 또는 임시 실행 경로가 함께 관찰됨',
    evidence: 'MITRE ATT&CK T1543: 서비스·데몬·에이전트 생성 또는 변경을 통한 지속성',
  },
  {
    id: 'unfamiliar_scheduled_task',
    name: '낯선 예약 작업',
    condition: '낯선 예약 작업이 생성·변경되며 실행 대상이나 실행 맥락이 비정상적임',
    evidence: 'MITRE ATT&CK T1053: 예약 작업 기능을 이용한 코드 실행',
  },
  {
    id: 'startup_folder_change',
    name: '시작 폴더 변경',
    condition: '시작 폴더에 알 수 없는 실행 파일·바로가기가 추가되거나 관련 설정이 변경됨',
    evidence: 'MITRE ATT&CK T1547.001: 시작 폴더를 이용한 로그인 시 자동 실행',
  },
];

const THRESHOLDS = Object.freeze({ block: 0.85, alert: 0.5 });

function textOf(value) {
  return typeof value === 'string' ? value.toLowerCase() : '';
}

function result(confidence, patternName) {
  const bounded = Math.max(0, Math.min(1, confidence));
  return {
    action: bounded >= THRESHOLDS.block ? 'block' : bounded >= THRESHOLDS.alert ? 'alert' : 'record',
    confidence: bounded,
    reason: patternName || '등록된 지속성 패턴과 일치하지 않음',
  };
}

export function decide(alert) {
  const description = textOf(alert?.rule?.description);
  const path = textOf(alert?.data?.path);
  const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const level = Number.isFinite(alert?.rule?.level) ? alert.rule.level : 0;

  const serviceSignal = /서명 없는 새 서비스|서비스 등록|서비스 실행 파일이 바뀌었|서비스가 .*등록|서비스.*남도록 등록|unsigned.*service|service.*(created|registered|modified)/i.test(description);
  const unsignedSignal = /서명 없|서명은 확인되지 않|서명이 없습니다|unsigned|signature.*(missing|invalid|unknown)/i.test(description);
  const taskSignal = /예약 작업|scheduled task|scheduled task/i.test(description);
  const unfamiliarTask = /처음 보는|낯선|임의 문자열|평소 목록에 없|unfamiliar|unknown|random/i.test(description);
  const startupSignal = /시작 폴더|시작 프로그램|시작 항목|startup folder|startup item/i.test(description);
  const startupPath = /\\startup\\|start menu\\programs\\startup/i.test(path);
  const tempPath = /\\appdata\\local\\temp\\|\\temp\\|\/tmp\//i.test(path);
  const repeated = /연속으로|3건|반복|multiple|repeated/i.test(description) || Number(alert?.data?.count) >= 3;
  const combined = /함께 가리킵니다|같은 임시 파일|both.*service.*task/i.test(description);
  const explicitBenign = /로그인했습니다|로그아웃했습니다|읽기만 했|업데이트 예약이 평소 시각|정의 업데이트가 평소|서명된 채로 실행|기존 예약 작업이 .*마쳤/i.test(description);

  // 명시적인 정상 설명은 낮은 확신도로 기록한다.
  if (explicitBenign && !unsignedSignal && !unfamiliarTask && !startupPath) {
    return result(0.05, '정상 활동');
  }

  // 강한 조합: 구체적인 지속성 행위와 의심스러운 대상·반복·다중 기법이 함께 나타남.
  if (combined && tempPath) {
    return result(0.99, PATTERNS[0].name + ' + ' + PATTERNS[1].name);
  }
  if (serviceSignal && unsignedSignal && (tempPath || repeated) && level >= 10) {
    return result(0.96, PATTERNS[0].name);
  }
  if (taskSignal && unfamiliarTask && tempPath && level >= 9) {
    return result(0.93, PATTERNS[1].name);
  }
  if (startupSignal && startupPath && /평소 목록에 없는|알 수 없는|추가됐|추가되었|unknown|unapproved/i.test(description) && level >= 9) {
    return result(0.91, PATTERNS[2].name);
  }
  if (serviceSignal && /다시 켜도 남도록|지속성|persistence/i.test(description) && tempPath && level >= 9) {
    return result(0.88, PATTERNS[0].name);
  }

  // 일부 신호만 있거나 맥락이 불충분하면 경보로 남긴다.
  if (startupSignal && startupPath) {
    return result(0.68, PATTERNS[2].name);
  }
  if (startupSignal && /변경이 1건|이어 실행된 기록은 없습니다|서명은 아직 모릅니다/i.test(description)) {
    return result(0.58, PATTERNS[2].name);
  }
  if (taskSignal && (unfamiliarTask || unsignedSignal || /수업 시간|수업 과제|수업 중/i.test(description))) {
    return result(0.65, PATTERNS[1].name);
  }
  if (serviceSignal && (unsignedSignal || /설명만|한 번 멈췄다가|실행 파일은 그대로/i.test(description))) {
    return result(0.62, PATTERNS[0].name);
  }
  if (tempPath && level >= 8) {
    return result(0.52, '임시 경로 실행 파일');
  }

  // MITRE 표식이나 낮은 규칙 수준만으로 공격을 단정하지 않는다.
  if (mitre.includes('T1543') && level >= 7 && serviceSignal) {
    return result(0.55, PATTERNS[0].name);
  }
  if (mitre.includes('T1053') && level >= 6 && taskSignal) {
    return result(0.52, PATTERNS[1].name);
  }

  return result(0.1, '등록된 지속성 패턴과 일치하지 않음');
}
