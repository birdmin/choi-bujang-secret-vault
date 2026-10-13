# 9단계 탐지 연습 사건 계약

`npm run detect:test`는 학생이 작성한 `src/detect.mjs`의 `detect(events)`에 가상 조회 사건을 전달합니다. 사건에는 시각, 메서드, 가명 주체, 네트워크 분류, 기기 ID 및 등록 여부가 포함됩니다.

```js
{
  at: '2026-10-01T00:00:00.000Z',
  method: 'GET',
  identity: { sub: 'learner_fixture' },
  network: 'unusual',
  deviceId: 'aaaaaaaaaaaaaaaa',
  deviceRegistered: true
}
```

탐지 규칙은 같은 가명 주체와 확인된 가상 기기 `aaaaaaaaaaaaaaaa`의 GET 조회가 어느 10분 구간에서든 120건을 넘고, 그 구간에 `network: 'unusual'` 사건이 하나 이상 있을 때만 별도 결과 `{ propose_revocation: { targetDeviceId: 'aaaaaaaaaaaaaaaa', reasonCode: 'burst_read' } }`를 반환합니다. 정확히 120건, 다량 조회만 있는 경우, 비정상 네트워크만 있는 경우, 미확인 기기 또는 다른 기기인 경우는 제안하지 않습니다. 지역 정보만으로 판정하지 않습니다. 서로 다른 사용자나 기기의 사건을 합산하지 않습니다.

이 제안은 연습용 탐지 결과일 뿐입니다. 실제 회수 API를 호출하거나 기기 권한을 변경하지 않습니다. 실제 회수 여부와 시각은 심판이 확인합니다. `src/decider.mjs`의 기존 접속 허용·거부 응답 계약은 이 탐지 결과와 별개로 유지됩니다. 이 명령의 통과를 실제 접속 차단이나 심판 판정으로 표시하지 않습니다.
