# Crusher

Crusher generates statistics from raw events.

## Requirements

* REview 0.33.0 or higher
* Giganto 0.17.0 or higher

## Usage

You can run Crusher by invoking the following command:

```sh
crusher path/to/config.toml
```

where `config.toml` is a configuration file in TOML format.

## Configuration file

The following is key values in the TOML configuration file.

* `key`: Crusher's private key file.
* `cert`: Crusher's certificate file.
* `roots`: RootCA file. (for Giganto, Review)
* `giganto_name`: the name of the Giganto. This must match with the DNS name in
  the certificate.
* `giganto_ingest_address`: IP address and port number of `Giganto ingest`.
* `giganto_publish_address`: IP address and port number of `Giganto publish`.
* `review_name`: the name of the review. This must match with the DNS name in
  the certificate.
* `review_address`: IP address and port number of `review`.
* `last_timestamp_data`: File that stores the timestamp of the last time series
  per `sampling policy`.
* `log_dir`: Path to the log file.

Example

```toml
key = "key.pem"
cert = "cert.pem"
roots = ["ca1.pem", "ca2.pem", "ca3.pem"]
giganto_name = "localhost"
giganto_ingest_address = "127.0.0.1:38370"
giganto_publish_address = "127.0.0.1:38371"
review_name = "localhost"
review_address ="127.0.0.1:38390"
last_timestamp_data = "tests/time_data.json"
log_dir = "/data/logs/apps"
```

By default, giganto reads the config file from the following directories:

* Linux: `$HOME/.config/crusher/config.toml`
* macOS: `$HOME/Library/Application Support/com.einsis.crusher/config.toml`

## Copyright

* Copyright 2023 ClumL Inc.
