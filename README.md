# Crusher

Crusher generates statistics from raw events.

## Requirements

- REview 0.42.0 or higher
- Giganto 0.23.0 or higher

## Usage

You can run Crusher by invoking the following command:

```sh
crusher \
 --cert <CERT_PATH> --key <KEY_PATH> --ca-certs <CA_CERTS_PATH> \
 <SERVER_NAME>@<SERVER_IP>:<SERVER_PORT>
```

To run Crusher with a local configuration file, with multiple CA certificates:

```sh
crusher \
 -c <CONFIG_PATH> \
 --cert <CERT_PATH>
 --key <KEY_PATH> \
 --ca-certs <CA_CERTS_PATH> \
 --ca-certs <CA_CERTS_PATH> \
 <SERVER_NAME>@<SERVER_IP>:<SERVER_PORT>
```

In these commands:

- `<CONFIG_PATH>` is the path to your TOML configuration file.
  - If not provided, Crusher runs in remote mode:
    - Attempts to fetch the configuration from the Manager server on startup.
    - Updates the configuration upon a request from the Manager server.
    - If an error occurs, waits for an updated configuration from the Manager
      server.
  - If provided, Crusher runs in local mode, which ignores configuration updates
    from the Manager server.
- `<CERT_PATH>` is the path to the certificate file for the current module.
- `<KEY_PATH>` is the path to the private key file for the current module.
- `<CA_CERTS_PATH>` is a CA certificate files. Multiple CA certificates can be
  specified by repeating the `--ca-certs` option.
- `<SERVER_NAME>` is the name of the Manager server, and
  `<SERVER_IP>:<SERVER_PORT>` is the IP address and port number of the Manager
  server. Ensure that `<SERVER_NAME>` matches the DNS name specified in the
  certificate.

## Example

```sh
crusher \
 --cert path/to/cert.pem \
 --key path/to/key.pem \
 --ca-certs path/to/ca_cert.pem \
 manager@10.0.0.1:38390
```

```sh
crusher \
 -c path/to/config.toml \
 --cert path/to/cert.pem \
 --key path/to/key.pem \
 --ca-certs path/to/ca_cert.pem \
 --ca-certs path/to/ca_cert2.pem \
 manager@10.0.0.1:38390
```

## Configuration file

The following is key values in the TOML configuration file.

- `giganto_name`: the name of the Giganto. This must match with the DNS name in
  the certificate.
- `giganto_ingest_srv_addr`: Giganto's ingest IP address and port number.
- `giganto_publish_srv_addr`: Giganto's publish IP address and port number.
- `last_timestamp_data`: File that stores the timestamp of the last time series
  per sampling policy.
- `log_dir`: Path to the log directory. If the path is not provided or the log
  file cannot be created in the directory, logs will be printed to stdout. Once
  set, it remains unchanged throughout the process.

Example

```toml
giganto_name = "localhost"
giganto_ingest_srv_addr = "127.0.0.1:38370"
giganto_publish_srv_addr = "127.0.0.1:38371"
last_timestamp_data = "tests/time_data.json"
log_dir = "/data/logs/apps"
```

## Copyright

- Copyright 2023-2025 ClumL Inc.
