# 설정 (toml)

## 주요 설정 항목 요약

| 설정 항목 | 설명 | 기본값 |
| --- | --- | --- |
| giganto_name | Giganto 서버 이름. TLS 연결 시 서버 이름으로 사용 | - |
| giganto_ingest_srv_addr | 집계 결과를 전송할 서버 주소 | - |
| giganto_publish_srv_addr | 이벤트 데이터를 받아올 서버 주소 | - |
| last_timestamp_data | 마지막 전송 시각 저장 파일 경로 (필수) | - |
| log_path | 로그 파일 경로 | 미지정 시 stdout |

## 설정 예시

```toml
giganto_name = "giganto.example.local"
giganto_ingest_srv_addr = "10.10.10.20:38370"
giganto_publish_srv_addr = "10.10.10.20:38371"
last_timestamp_data = "/path/to/last_timestamp.json"
log_path = "/path/to/crusher.log"
```

`log-path` 동작

- 미지정: stdout로 출력
- 지정 + 쓰기 가능: 해당 파일로 출력
- 지정 + 쓰기 불가: Crusher 종료

`last_timestamp_data` 파일 형식

- 파일이 있으면 이전 처리 시각을 읽어 이어서 처리합니다.
- 파일이 없으면 처음부터 시작합니다.
- 실행 중 마지막 처리 시각이 파일에 저장됩니다.
