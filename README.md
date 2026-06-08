# SOC Pilot - GitHub Pages Version

GitHub Pages에서 바로 실행되는 정적 웹앱 버전입니다.

## 올리는 법

1. 이 폴더 안의 `index.html`을 GitHub 저장소 루트에 업로드합니다.
2. GitHub 저장소에서 Settings → Pages로 이동합니다.
3. Branch를 `main`, folder를 `/root`로 설정합니다.
4. 몇 분 뒤 아래 주소로 접속합니다.

```txt
https://사용자명.github.io/저장소명/
```

## 포함 기능

- 단일 보안 알림 룰 기반 분석
- CSV 대량 처리
- 반복 이벤트 자동 병합
- 사건 큐 저장
- 대응 액션 상태 변경
- Markdown 보고서 다운로드

## 빠진 기능

기존 Python 버전의 서버 기능은 GitHub Pages에서 실행되지 않기 때문에 제거했습니다.

- Python HTTP 서버
- SQLite DB
- OpenAI/API 서버 연동
- 서버 사이드 제3자 AI 검증

데이터는 브라우저 localStorage에 저장됩니다.
