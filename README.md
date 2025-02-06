# Crusher

Crusher generates statistics from raw events.

## Requirements

- REview 0.42.0 or higher
- Giganto 0.23.0 or higher

## Usage

You can run Crusher by invoking the following command:

```sh
crusher \
 --cert <CERT_PATH> \
 --key <KEY_PATH> \
 --ca-certs <CA_CERTS_PATH> \
 <SERVER_NAME>@<SERVER_IP>:<SERVER_PORT>
```

To run Crusher with a local configuration file, with multiple CA certificates:

```sh
crusher \
 -c <CONFIG_PATH> \
 --cert <CERT_PATH> \
 --key <KEY_PATH> \
 --ca-certs <CA_CERTS_PATH> \
 --ca-certs <CA_CERTS_PATH> \
 <SERVER_NAME>@<SERVER_IP>:<SERVER_PORT>
```

## Arguments

- `<CONFIG_PATH>`: Path to the TOML configuration file (optional).
  - If provided, Crusher runs in local mode, ignoring configuration updates
    from the manager server.
  - If omitted, Crusher runs in remote mode, with its configuration managed
    by the manager server.
- `<CERT_PATH>`: Path to the certificate file (**required**).
- `<KEY_PATH>`: Path to the private key file (**required**).
- `<CA_CERTS_PATH>`: Path to the CA certificates file (**required**).
- `<SERVER_NAME>`: Name of the manager server. This must match with the DNS name
  in the certificate (**required**).
- `<SERVER_IP>:<SERVER_PORT>`: The IP address and port number of the manager
  server (**required**).

## Example

- Remote mode

```sh
crusher \
 --cert path/to/cert.pem \
 --key path/to/key.pem \
 --ca-certs path/to/ca_cert.pem \
 manager@10.0.0.1:38390
```

- Local mode

```sh
crusher \
 -c path/to/config.toml \
 --cert path/to/cert.pem \
 --key path/to/key.pem \
 --ca-certs path/to/ca_cert.pem \
 manager@10.0.0.1:38390
```

## Configuration

In the configuration file, you can specify the following options:

<!-- markdownlint-disable -->

| Field                      | Description                                                                     | Required | Default    |
| -------------------------- | ------------------------------------------------------------------------------- | -------- | ---------- |
| `giganto_name`             | Name of the Giganto server                                                      | Yes      | localhost  |
| `giganto_ingest_srv_addr`  | Giganto's ingest IP address and port number                                     | Yes      | [::]:38370 |
| `giganto_publish_srv_addr` | Giganto's publish IP address and port number                                    | Yes      | [::]:38371 |
| `last_timestamp_data`      | JSON file that stores the timestamp of the last time series per sampling policy | Yes      | -          |
| `log_dir`                  | Directory for log files                                                         | No       | -          |

<!-- markdownlint-enable -->

- `giganto_name`: This must match with the DNS name in the certificate.
- `log_dir`: If not provided, logs are printed to stdout/stderr.

## Configuration Example

```toml
giganto_name = "localhost"
giganto_ingest_srv_addr = "127.0.0.1:38370"
giganto_publish_srv_addr = "127.0.0.1:38371"
last_timestamp_data = "tests/time_data.json"
log_dir = "/data/logs/apps"
```

## Copyright

- Copyright 2023-2025 ClumL Inc.
