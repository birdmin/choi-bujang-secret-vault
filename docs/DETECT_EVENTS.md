# 9단계 탐지 연습 사건 계약

`npm run detect:test`는 학생이 작성한 `src/detect.mjs`의 `detect(events)`에 가상 조회 사건을 전달합니다. 각 사건은 다음 값을 가집니다.

```js
{ at: '2026-10-01T00:00:00.000Z', method: 'GET', identity: { sub: 'learner_fixture' }, network: 'normal' }
```

`network`는 가상 사건의 네트워크 분류이며 `normal` 또는 `unusual`입니다. **같은 `identity.sub`의 GET 조회가 어느 10분 구간에서든 120건을 넘고, 그 구간에 `network: 'unusual'` 사건이 하나 이상 있을 때만** `{ action: 'propose_revocation', reasonCode: 'burst_read', subject: '해당 sub' }`를 돌려줍니다. 나머지는 `{ action: 'observe' }`입니다. 정확히 120건, 다량 조회만 있는 경우, 비정상 네트워크만 있는 경우는 회수 제안 대상이 아닙니다. 지역 정보만으로 판정하지 않습니다. 다른 사용자의 사건을 합산하거나 10분 밖의 사건을 같은 묶음으로 세지 않습니다.

이 파일의 사건 모양은 **연습용**입니다. 브라우저가 보낸 사용자 번호를 신원으로 취급하지 않습니다. 운영 반 엔진이 검증한 사건을 전달하고 회수 제안을 집행하는 경로는 별도로 연결·시험해야 합니다. 이 명령의 통과를 실제 접속 차단이나 심판 판정으로 표시하지 않습니다.
