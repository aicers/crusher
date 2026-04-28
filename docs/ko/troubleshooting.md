# 문제 해결 (자주 겪는 이슈)

## 프로세스가 시작되지 않을 때

- 인증서, 개인 키, CA 인증서 경로가 올바른지 확인합니다.
- 로컬 설정 모드라면 설정 파일 경로가 올바른지 확인합니다.
- 로그 경로가 지정되었다면 해당 파일에 쓰기 권한이 있는지 확인합니다.

## `last_timestamp_data` 파일 오류

- 파일 경로가 올바른지 확인합니다.
- 상위 디렉터리에 쓰기 권한이 있는지 확인합니다.
- 기존 파일이 있다면 JSON 형식이 올바른지 확인합니다.

## 연결되지 않을 때

<!-- markdownlint-disable MD007 MD013 -->
- Manager
    - `<SERVER_NAME>@<SERVER_IP>:<SERVER_PORT>` 형식이 올바른지 확인합니다.
    - Manager 서버 주소와 포트가 맞는지 확인합니다.
    - 인증서 검증에 필요한 CA 인증서가 맞는지 확인합니다.
- Giganto
    - `giganto_ingest_srv_addr`, `giganto_publish_srv_addr` 설정값을 확인합니다.
    - `giganto_name` 설정값을 확인합니다.
<!-- markdownlint-enable MD007 MD013 -->
