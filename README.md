# BYTE BACK 방어전 시작 틀 R5

이 저장소는 1단계에서 학생 본인이 GitHub 저장소와 Vercel 배포를 만드는 출발점입니다. 포함된 메모 네 건은 가상 자료입니다. 실제 학생 자료, 토큰, 비밀키를 넣지 마세요.

## 학생이 하는 일: 세 걸음

1. GitHub 계정을 만듭니다.
2. 방어전 1단계 카드의 **Deploy** 버튼을 누릅니다. Vercel에 GitHub로 로그인하고, 새 저장소가 **본인 계정의 Public 저장소**인지 확인한 뒤 Deploy를 누릅니다.
3. 배포가 끝나면 화면에 나온 `https://…vercel.app` 주소를 방어전 1단계 카드에 붙여넣고 제출합니다. 저장소 주소나 설정 파일은 적지 않습니다.

배포가 끝나면 `/`에서 점령된 가상 자료실을 볼 수 있습니다. `/data.json`에는 같은 가상 메모가 공개됩니다. 이 공개 상태를 확인하는 것이 1단계의 출발점입니다. 1단계 접수와 심판 판정은 포털에서 확인합니다.

## 시작 틀의 자동 처리

`vercel.json`은 정적 결과물 `public`을 배포합니다. 빌드 명령 `npm run build`는 Vercel이 제공하는 GitHub 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증하고 `public/aleph.json`을 생성합니다. 이 값이 없으면 빌드가 실패하므로, 성공한 것처럼 빈 주소를 내보내지 않습니다. `aleph.json`의 내용만으로 저장소 소유권이나 방어 성공을 인정하지 않습니다. 심판이 공개 저장소의 실제 커밋과 배포된 자료를 따로 대조해야 합니다.

`aleph.config.json`의 `repoUrl`과 `publicAppUrl`은 이전 제출 묶음 방식의 자리표시자입니다. 1단계에서는 학생이 편집하지 않습니다. 2단계 이후 코딩 도구가 필요한 설정과 보호 기능을 단계별로 작성합니다. `npm run bundle`과 `bundle-notes.json`도 1단계의 세 걸음에는 포함되지 않습니다.

로컬에서 가상 화면만 확인할 때는 `npm run build -- --local`을 사용합니다. 로컬 실행은 Vercel 배포나 심판 접수를 증명하지 않습니다. 저장소의 `src/attack-check.mjs`는 실제 배포가 된 뒤 `/data.json`을 비로그인으로 요청해 공개 가상 메모의 확인 표시를 읽습니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 2단계부터는 자료 보호를 구현할 때 `public/data.json`을 복사하는 1단계 빌드 흐름도 함께 바꿔야 합니다. 3단계 이후의 로그인, 허용 경로, 5단계의 원본 API 주소, 6단계 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.


## 2단계: 자료를 코드 밖으로 옮긴 뒤 확인

2단계에서는 공개 정적 파일에서 가상 메모를 제거하고, 서버 함수 `/api/notes`가 학습용 Supabase `notes` 테이블에서 가상 메모를 읽도록 변경했습니다.

### 현재 배포 파일과 GitHub 최신 파일 검색 확인

가상 메모 문장이 현재 공개 파일에 남아 있는지 다음 문장을 기준으로 검색합니다.

- `실습용 가상 과제 기록`
- `실습용 가상 포트폴리오 기록`
- `실습용 가상 리추얼 기록`
- `실습용 가상 행정 기록`

GitHub에서는 최신 `main` 브랜치의 파일을 검색하고, 공개 배포에서는 `/data.json`을 비로그인 상태에서 직접 열어 확인합니다.

현재 확인 결과:
- GitHub 최신 파일의 `data.json`: 위 네 문장이 없음
- 공개 `/data.json`: `notes: []`로 반환되며 위 네 문장이 없음
- 공개 `/api/notes`: 위 네 문장이 서버 API 응답으로 반환됨

### 공개 API의 남은 약점

현재 `/api/notes`는 인증 없이 공개 주소로 접근할 수 있으며, 요청하면 학습용 가상 메모 네 건을 반환합니다.

따라서 2단계에서는 정적 파일에서 자료를 제거하고 서버 측으로 옮겼지만, API 자체의 접근 제어가 완료된 것은 아닙니다. 이 공개 API의 접근 제어는 다음 단계에서 다룹니다.

또한 과거 GitHub 커밋과 과거 Vercel 배포에는 2단계 이전의 공개 자료가 남아 있을 수 있습니다. 따라서 과거 노출이 완전히 해소되었다고 간주하지 않습니다.

## 4단계 저장점: 메모 소유권과 DB 권한 보호

4단계에서는 로그인한 사용자의 검증된 ID를 메모의 소유자로 사용하고, 메모 읽기·추가·수정·삭제 API에서 `owner_id` 소유권을 확인하도록 했습니다. 메모 추가 시 요청 본문의 소유자 ID를 믿지 않고 서버에서 검증한 사용자 ID를 저장하며, 수정·삭제에서는 기존 행과 요청 대상 행의 소유자가 모두 본인인지 확인합니다.

학습 DB의 `public.memos`에는 RLS를 켜고 `public`, `anon`, `authenticated`의 기존 테이블 권한을 회수한 뒤 `authenticated`에 SELECT·INSERT·UPDATE·DELETE만 부여했습니다. SELECT·DELETE는 기존 행의 `auth.uid() = owner_id`, INSERT는 새 행의 `auth.uid() = owner_id`, UPDATE는 기존 행과 새 행 모두의 `auth.uid() = owner_id`를 정책으로 검사합니다.

현재 자료 API 경로:
- GET `/api/memos`
- POST `/api/memos`
- GET `/api/memos/:id`
- PUT `/api/memos/:id`
- DELETE `/api/memos/:id`

현재 확인된 직접 점검:
- B의 자기 메모 목록 조회: 정상
- B의 A 메모 상세 조회: `404 MEMO_NOT_FOUND`로 거부
- RLS 적용 후에도 API의 소유권 검사 유지

저장점에서 다시 제출 묶음을 만들 때는 `npm run bundle`을 실행합니다. 이 명령은 커밋되지 않은 파일을 거부하고 현재 HEAD의 커밋·변경 파일·허용 경로·공격 점검 결과를 `artifacts/submission.json`으로 생성합니다. `bundle-notes.json`과 `artifacts/submission.json`은 저장소에 커밋하지 않습니다.


## 5단계 저장점: 자료 요청을 서버 한곳으로 모읍니다

5단계에서는 브라우저의 메모 자료 읽기·추가·수정·삭제를 Vercel 서버 함수로만 처리하도록 유지하고, Supabase `public.memos`에 대한 `PUBLIC`·`anon`·`authenticated`의 직접 테이블 권한을 회수했습니다. 로그인(Auth) 호출은 기존 Supabase Auth 흐름을 보존하고, 서버 함수의 로그인 검증과 `owner_id` 소유권 검사는 유지합니다.

현재 자료 API 경로:
- GET `/api/memos`
- POST `/api/memos`
- GET `/api/memos/:id`
- PUT `/api/memos/:id`
- DELETE `/api/memos/:id`

현재 `aleph.config.json`의 `originalApiUrl`은 쿼리 없는 원본 자료 HTTPS 경로이며, `allowedRoutes`에는 위 서버 함수 경로가 기록되어 있습니다. `vercel.json`에는 `X-Content-Type-Options: nosniff`가 적용되어 있습니다.

학습 DB에서 확인한 `public.memos` 직접 권한:
- 적용 전: `authenticated`의 SELECT·INSERT·UPDATE·DELETE 4개
- 적용 후: `PUBLIC`·`anon`·`authenticated` 모두 직접 권한 없음
- 다른 테이블은 변경하지 않음

제출 전 직접 확인 항목:
- 브라우저 메모 CRUD 요청이 서버 함수 경로만 사용하는지 확인
- A 정상 동작, B 타인 메모 거부, 무로그인 거부 확인
- 원본 자료 HTTPS 경로를 공개 키로 직접 요청했을 때 메모 자료가 노출되지 않는지 확인

저장점에서 다시 제출 묶음을 만들 때는 `npm run bundle`을 실행합니다. 이 명령은 커밋되지 않은 파일을 거부하고 현재 HEAD의 커밋·변경 파일·허용 경로·직접 점검 결과를 `artifacts/submission.json`으로 생성합니다. `bundle-notes.json`과 `artifacts/submission.json`은 저장소에 커밋하지 않습니다.
