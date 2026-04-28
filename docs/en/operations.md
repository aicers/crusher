# Operations

## Execution Command

Crusher is started using the following command.

<!-- markdownlint-disable MD013 -->
```bash
crusher [-c <CONFIG_PATH>] --cert <CERT_PATH> --key <KEY_PATH> --ca-certs <CA1[,CA2,...]> <SERVER_NAME>@<SERVER_IP>:<SERVER_PORT>
```
<!-- markdownlint-enable MD013 -->

- `-c <CONFIG_PATH>`: TOML configuration file path (required for local mode)
- `--cert <CERT_PATH>`: Crusher certificate (PEM) (required)
- `--key <KEY_PATH>`: Crusher private key (PEM) (required)
- `--ca-certs <CA_CERT_PATH>[,...]`: CA certificates for verifying the target
  server (PEM) (required)
- `<SERVER_NAME>@<SERVER_IP>:<SERVER_PORT>`: Manager server address (required)

## Local Configuration Mode

```bash
crusher -c /path/to/crusher/config.toml \
  --cert /path/to/crusher/certs/cert.pem \
  --key /path/to/crusher/certs/key.pem \
  --ca-certs /path/to/crusher/certs/ca_cert.pem \
  manager@10.0.0.1:38390
```

## Remote Configuration Mode

```bash
crusher \
  --cert /path/to/crusher/cert.pem \
  --key /path/to/crusher/key.pem \
  --ca-certs /path/to/crusher/ca_cert.pem \
  manager@10.0.0.1:38390
```

In this mode, configuration is retrieved from the Manager server.

## Items to Check After Startup

- Verify that the process does not terminate immediately
- Verify that there are no errors in certificates or configuration
- Verify connectivity to the Manager and Giganto servers
- Verify that logs are being generated as expected
