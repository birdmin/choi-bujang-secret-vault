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

같은 `identity.sub`의 GET 조회가 10분 안에 120건을 초과하고, 그 구간 안에 `network: 'unusual'`인 사건과 해당 사건의 기기 ID가 확인되면 다음을 반환합니다.

```js
{
  schema: 'aleph.detection.v1',
  detected: true,
  subject: 'learner_fixture',
  ruleIds: ['compound_network_burst'],
  propose_revocation: {
    targetDeviceId: 'aaaaaaaaaaaaaaaa',
    reasonCode: 'composite_anomaly'
  }
}
```

정확히 120건이거나, 조회 폭주만 있거나, 비정상 네트워크 신호가 없거나, 비정상 네트워크 사건에서 기기 ID를 확인할 수 없으면 `{ schema: 'aleph.detection.v1', detected: false, ruleIds: [] }`를 반환합니다. 다른 조회의 기기 ID가 다르더라도 제안 대상은 비정상 네트워크 사건에서 확인한 단일 기기입니다. 서로 다른 주체의 조회를 합산하지 않으며, 10분 창 밖의 조회도 합산하지 않습니다. 탐지 결과에는 `propose_revocation` 필드도 함께 포함되며, 실제 접근 응답이나 기기 상태를 변경하지 않습니다.

이 명령은 가상 사건을 사용하는 로컬 연습입니다. 실제 접속 회수를 수행하거나 심판 통과를 증명하지 않습니다.
