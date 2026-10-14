# 9단계 탐지 연습 사건 계약

`npm run detect:test`는 `src/detect.mjs`의 `detect(events)`에 가상 조회 사건을 전달합니다. 기본 사건 형식은 다음과 같습니다.

```js
{
  at: '2026-10-01T00:00:00.000Z',
  method: 'GET',
  identity: { sub: 'learner_fixture' },
  network: 'unusual',
  deviceId: 'aaaaaaaaaaaaaaaa'
}
```

같은 `identity.sub`의 GET 조회가 10분 안에 120건을 초과하고, 그 구간 안에 `network: 'unusual'`인 사건과 해당 사건의 기기 ID가 확인되면 다음과 같이 반환합니다.

```js
{
  action: 'propose_revocation',
  reasonCode: 'compound_network_burst',
  subject: 'learner_fixture',
  deviceId: 'aaaaaaaaaaaaaaaa',
  propose_revocation: {
    targetDeviceId: 'aaaaaaaaaaaaaaaa',
    reasonCode: 'composite_anomaly'
  }
}
```

바깥 `reasonCode`는 탐지 규칙 코드이며, 별도 `propose_revocation` 안에는 대상 가상 기기 한 개와 회수 제안 사유 코드만 들어갑니다. 실제 회수 API를 만들거나 기기 권한을 변경하지 않습니다.

정상 조회, 정확히 120건, 조회 폭주만 있는 사건, 비정상 네트워크 신호가 없는 사건, 비정상 네트워크 사건에서 기기 ID를 확인할 수 없는 경우에는 `{ action: 'observe' }`를 반환하고 회수 제안을 포함하지 않습니다. 지역 정보만으로는 탐지하지 않습니다. 서로 다른 주체의 조회를 합산하지 않으며, 10분 창 밖의 조회도 합산하지 않습니다.

`src/decider.mjs`의 `detect(request)`도 별도 탐지 결과이며, 복합 의심 사건에만 `propose_revocation`을 포함하고 정상 사건에는 해당 필드를 넣지 않습니다. 이는 `decide(request)`의 기존 5개 필드 응답과 별개입니다.

이 명령은 가상 사건을 사용하는 연습입니다. 실제 접속 회수를 수행하거나 심판 통과를 증명하지 않습니다.
