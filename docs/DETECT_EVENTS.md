# 9단계 탐지 연습 사건 계약

`npm run detect:test`는 `src/detect.mjs`의 `detect(events)`에 가상 접속 사건을 전달합니다. 각 사건은 `at`, `method`, `identity.sub`를 포함하며, 복합 의심 판정에는 네트워크 분류와 대상 기기 ID도 전달되어야 합니다.

```js
{
  at: '2026-10-01T00:00:00.000Z',
  method: 'GET',
  identity: { sub: 'learner_fixture' },
  network: 'unusual',
  deviceId: 'aaaaaaaaaaaaaaaa'
}
```

같은 `identity.sub`의 GET 조회가 10분 미만의 한 구간에서 120건을 초과하고, 그 구간에 `network: 'unusual'`인 사건과 기기 ID가 있을 때만 다음 별도 탐지 결과를 반환합니다.

```js
{
  action: 'propose_revocation',
  reasonCode: 'compound_network_burst',
  subject: 'learner_fixture',
  deviceId: 'aaaaaaaaaaaaaaaa'
}
```

정상 네트워크, 120건 이하, 기기 ID 누락, 서로 다른 사용자로 나뉜 조회, 또는 10분 창 밖으로 흩어진 조회는 `{ action: 'observe' }`를 반환합니다. 실제 회수 API를 호출하거나 권한을 변경하지 않습니다. 실제 사건과 회수 여부는 심판이 별도로 확인합니다. 이 로컬 연습의 통과를 심판 판정으로 표시하지 않습니다.
