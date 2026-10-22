# 설정 (toml)

## 주요 설정 항목 요약

| 설정 항목 | 설명 | 기본값 |
| --- | --- | --- |
| giganto_name | Giganto 서버 이름. TLS 연결 시 서버 이름으로 사용 (필수) | - |
| giganto_ingest_srv_addr | 집계 결과를 전송할 서버 주소 | - |
| giganto_publish_srv_addr | 이벤트 데이터를 받아올 서버 주소 | - |
| last_timestamp_data | 마지막 전송 시각 저장 파일 경로 (필수) | - |

## 설정 예시

```toml
giganto_name = "giganto.example.local"
giganto_ingest_srv_addr = "10.10.10.20:38370"
giganto_publish_srv_addr = "10.10.10.20:38371"
last_timestamp_data = "/path/to/last_timestamp.json"
```

로그

crusher는 로그를 표준 출력에 씁니다. 수준은 `RUST_LOG`로 정하며 기본값은 `info`입니다. 표준 출력이나 표준 오류가
systemd 저널에 연결되어 있으면(`JOURNAL_STREAM`) 각 이벤트를 syslog 우선순위(`<3>` 오류, `<4>` 경고,
`<6>` 정보, `<7>` 디버그·트레이스)로 시작하는 한 줄로, 타임스탬프와 색상 코드 없이 쓰고, 이벤트 안의 줄바꿈은 `\n`으로
씁니다. 패닉은 오류 항목 하나로 기록합니다. 그 밖의 경우 색상 코드는 터미널에만 씁니다. `log_path`는 제거되었으며 이를 지정한
설정은 거부됩니다.

`last_timestamp_data` 파일 형식

- 파일이 있으면 이전 처리 시각을 읽어 이어서 처리합니다.
- 파일이 없으면 처음부터 시작합니다.
- 실행 중 마지막 처리 시각이 파일에 저장됩니다.
