# Crusher

Crusher generates statistics from raw events.

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
* `giganto_ingestion_address`: IP address and port number of `Giganto ingestion`.
* `giganto_publish_address`: IP address and port number of `Giganto publish`.
* `review_name`: the name of the review. This must match with the DNS name in
  the certificate.
* `review_address`: IP address and port number of `review`.
* `agent_id`: a unique identifier for the agent on the host where the agent is
  running.
* `last_timestamp_data`: File that stores the timestamp of the last time series
  per `sampling policy`.

Example

```toml
key = "key.pem"
cert = "cert.pem"
roots = ["ca1.pem", "ca2.pem", "ca3.pem"]
giganto_name = "localhost"
giganto_ingestion_address = "127.0.0.1:38370"
giganto_publish_address = "127.0.0.1:38371"
review_name = "localhost"
review_address ="127.0.0.1:38390"
agent_id ="crusher"
last_timestamp_data = "tests/time_data.json"
```

By default, giganto reads the config file from the following directories:

* Linux: `$HOME/.config/crusher/config.toml`
* macOS: `$HOME/Library/Application Support/com.einsis.crusher/config.toml`

## Copyright

* Copyright 2022 EINSIS, Inc.
