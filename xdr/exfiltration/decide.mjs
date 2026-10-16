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
  const bytes = num(alert?.data?.bytes);
  const files = num(alert?.data?.files);
  const count = num(alert?.data?.count);
  const destination = textOf(alert?.data?.dstip);
  const sent = Boolean(destination) && bytes > 0;

  const unfamiliar =
    /처음 보는|낯선|평소와 다른|쓰지 않던 포트|unfamiliar|unknown destination/i
      .test(description);
  const large =
    bytes >= 50000000 ||
    /대용량|큰 파일|자료실 전체|메모 묶음/i.test(description);
  const archive = /압축 파일|압축파일|archive|zip/i.test(description);
  const outside =
    /업무 시간 밖|업무시간 밖|수업 시간 밖|수업시간 밖|outside business hours|after hours/i
      .test(description);
  const repeated =
    count >= 8 || /\d+번 반복|연속 전송|반복됐습니다/i.test(description);
  const noTransfer =
    /외부 전송은 아직 없습니다|전송은 없습니다|파일 전송은 없습니다|전송이 실패/i
      .test(description);
  const normal =
    /내 메모|반 공지|수업 자료 주소|검색 결과|화면 새로고침|로그아웃|세션 확인|다음 수업 공지|첨부 그림/i
      .test(description);

  // 외부 전송이 없거나 실패한 경우에는 차단하지 않는다.
  if (noTransfer || !sent) {
    return result(0.02, 'no_matching_exfiltration_pattern');
  }

  // 일상적인 앱 동작과 작은 정상 전송은 기록만 한다.
  if (normal && bytes < 50000000 && !unfamiliar && !archive) {
    return result(0.05, 'no_matching_exfiltration_pattern');
  }

  // 처음 보는 목적지와 대용량 전송이 함께 확인된 경우
  if (unfamiliar && large && bytes >= 50000000) {
    return result(0.96, PATTERNS[0].name);
  }

  // 업무 시간 밖 압축 파일 반출과 낯선 목적지가 함께 확인된 경우
  if (archive && outside && unfamiliar && bytes >= 50000000) {
    return result(0.97, PATTERNS[1].name);
  }

  // 명령 통로를 통한 대용량 전송이 반복되는 경우
  if (mitre.includes('T1041') && large && repeated && bytes >= 50000000) {
    return result(0.88, PATTERNS[0].name);
  }

  // 업무 시간 밖 대용량 압축 파일 전송
  if (archive && outside && bytes >= 50000000) {
    return result(0.86, PATTERNS[1].name);
  }

  // 일부 의심 신호만 확인되면 추가 확인 대상으로 분류
  if (unfamiliar || archive || outside || large || repeated || files >= 20 || count >= 3) {
    return result(0.65, unfamiliar || large ? PATTERNS[0].name : PATTERNS[1].name);
  }

  return result(0.08, 'no_matching_exfiltration_pattern');
}
