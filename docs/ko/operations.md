# 실행

## 실행 커맨드

Crusher는 아래 형태로 실행합니다.

<!-- markdownlint-disable MD013 -->
```bash
crusher [-c <CONFIG_PATH>] --cert <CERT_PATH> --key <KEY_PATH> --ca-certs <CA1[,CA2,...]> <SERVER_NAME>@<SERVER_IP>:<SERVER_PORT>
```
<!-- markdownlint-enable MD013 -->

- `-c <CONFIG_PATH>`: TOML 설정 파일 경로
- `--cert <CERT_PATH>`: Crusher 인증서(PEM) (필수)
- `--key <KEY_PATH>`: Crusher 개인키(PEM) (필수)
- `--ca-certs <CA_CERT_PATH>[,...]`: 접속 대상 서버 검증용 CA 인증서(PEM) 목록 (필수)
- `<SERVER_NAME>@<SERVER_IP>:<SERVER_PORT>` : Manager 서버 주소 (필수)

## 로컬 설정 모드

```bash
crusher -c /path/to/crusher/config.toml \
  --cert /path/to/crusher/certs/cert.pem \
  --key /path/to/crusher/certs/key.pem \
  --ca-certs /path/to/crusher/certs/ca_cert.pem \
  manager@10.0.0.1:38390
```

## 원격 설정 모드

```bash
crusher \
  --cert /path/to/crusher/cert.pem \
  --key /path/to/crusher/key.pem \
  --ca-certs /path/to/crusher/ca_cert.pem \
  manager@10.0.0.1:38390
```

이 경우 설정은 Manager 서버에서 받아옵니다.

## 시작 직후 확인할 항목

- 프로세스가 즉시 종료되지 않는지 확인합니다.
- 인증서 또는 설정 파일에 오류가 없는지 확인합니다.
- Manager 및 Giganto 와 연결되는지 확인합니다.
- 로그가 정상적으로 출력되는지 확인합니다.
