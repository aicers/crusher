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

Manager에 이 인스턴스의 설정이 아직 없으면 Manager는 `001.crusher unregistered`
같은 사유로 요청을 거절합니다. Crusher는 이를
`Waiting for a configuration from the Manager: <사유>` 경고로 기록하고 유휴
모드에서 기다립니다. 인스턴스를 설정하기 전에는 정상적인 동작이며, Manager가
설정을 보내면 Crusher가 바로 시작합니다.

## 윈도가 기록되는 시점

Crusher는 정책의 시계열을 윈도(주기 하나) 단위로, 윈도가 끝난 뒤에 기록합니다.

- 이벤트가 많은 소스에서는 다음 윈도의 첫 이벤트가 도착할 때 윈도가 기록됩니다.
  센서는 이벤트를 묶어서 보내므로, 윈도가 끝난 뒤 센서의 다음 묶음이 도착하는
  시점입니다. 600초 단위로 묶어 보내는 센서라면 윈도가 끝나고 최대 10분 뒤입니다.
- 이벤트가 적은 소스에서는 윈도가 끝나고 최대 약 15분 뒤에 기록됩니다. Crusher는
  늦게 도착하는 센서 묶음과 시계 차이를 고려해 윈도가 끝나고 900초를 기다린 뒤,
  30초 동안 이벤트가 없으면 윈도를 닫습니다.
- 늦은 센서 묶음처럼 윈도가 기록된 뒤에 도착한 이벤트는 그 윈도를 보정합니다.
  Crusher는 그 윈도를 한 번 더 기록해 앞서 기록한 값을 대체합니다. 마지막으로
  기록한 윈도보다 오래된 이벤트는 버리고, 버린 이벤트 수를 경고로 기록합니다.
- 이벤트가 없는 윈도는 기록하지 않습니다. 0으로 채운 행 대신 빈 구간으로 보입니다.
- 진행 중인 윈도는 기록하지 않습니다. Crusher가 멈추거나 다시 연결하거나 정책이
  멈추면 진행 중인 윈도는 버려지고, 정책이 다시 실행될 때 Data Store에 저장된
  이벤트로 다시 만들어집니다. 이때 마지막으로 기록한 윈도도 한 번 더 기록합니다.
- 새 정책은 Data Store에 저장된 모든 이벤트로 만들어집니다.
- 정책의 출발지·목적지 주소 조건은 실시간 이벤트와 저장된 이벤트에 똑같이
  적용됩니다.

## 시작 직후 확인할 항목

- 프로세스가 즉시 종료되지 않는지 확인합니다.
- 인증서 또는 설정 파일에 오류가 없는지 확인합니다.
- Manager 및 Giganto 와 연결되는지 확인합니다.
- 로그가 정상적으로 출력되는지 확인합니다.
