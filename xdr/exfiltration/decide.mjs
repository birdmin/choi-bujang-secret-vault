const PATTERNS = [
  {
    name: 'large_transfer_to_unfamiliar_destination',
    condition: '처음 보는 목적지로 대용량 자료 전송',
    mitre: ['T1041', 'T1048'],
    evidence: 'MITRE ATT&CK T1041은 명령·제어 통로를 통한 유출, T1048은 대체 프로토콜을 통한 유출을 다룬다.',
  },
  {
    name: 'archive_transfer_outside_business_hours',
    condition: '업무 시간 밖 압축 파일 반출',
    mitre: ['T1048'],
    evidence: 'MITRE ATT&CK T1048은 대체 프로토콜을 통한 유출을 다룬다. 업무 시간 밖 압축 파일 반출은 조사 신호이지 단독 확정 증거는 아니다.',
  },
];

const THRESHOLDS = Object.freeze({ block: 0.85, alert: 0.5 });
const BLOCK_BYTES = 50000000; // 5천만 바이트 이상이면 대용량
const MIN_ALERT_LEVEL = 5;    // 이보다 낮은 수준(정상 활동)은 기록만 한다

function textOf(value) {
  return typeof value === 'string' ? value.toLowerCase() : '';
}

function num(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function result(confidence, reason) {
  const value = Math.max(0, Math.min(1, confidence));
  return {
    action:
      value >= THRESHOLDS.block
        ? 'block'
        : value >= THRESHOLDS.alert
          ? 'alert'
          : 'record',
    confidence: value,
    reason,
  };
}

export function decide(alert) {
  const description = textOf(alert?.rule?.description);
  const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const level = num(alert?.rule?.level);
  const bytes = num(alert?.data?.bytes);
  const destination = textOf(alert?.data?.dstip);
  const sent = Boolean(destination) && bytes > 0;

  const hasExfilMitre = mitre.includes('T1041') || mitre.includes('T1048');
  const unfamiliar =
    /처음 보는|낯선|평소와 다른|쓰지 않던 포트|unfamiliar|unknown destination/i
      .test(description);
  const archive = /압축 파일|압축파일|archive|zip/i.test(description);
  const outside =
    /업무 시간 밖|업무시간 밖|수업 시간 밖|수업시간 밖|outside business hours|after hours/i
      .test(description);

  // 근거 패턴 이름: 업무 시간 밖 압축 반출이면 두 번째, 아니면 첫 번째
  const patternName =
    archive && outside ? PATTERNS[1].name : PATTERNS[0].name;

  // 1) 명확한 공격: 목적지와 전송량이 있고, 5천만 바이트 이상이며,
  //    T1041/T1048로 분류된 전송만 차단 후보로 둔다.
  if (sent && bytes >= BLOCK_BYTES && hasExfilMitre) {
    return result(unfamiliar ? 0.96 : 0.9, patternName);
  }

  // 2) 애매한 시도: 유출 관련 분류(T1041/T1048)가 붙은 경보 중
  //    정상 활동 수준(level 5 미만)이 아닌 것은 차단하지 않고 알림으로 남긴다.
  if (hasExfilMitre && level >= MIN_ALERT_LEVEL) {
    return result(0.65, patternName);
  }

  // 3) 그 밖의 정상·근거 없는 이벤트는 기록만 한다.
  return result(0.05, 'no_matching_exfiltration_pattern');
}
