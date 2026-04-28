# Overview

Crusher is a program that receives event data from Giganto (via its publish
endpoint), aggregates it into periodic statistical data, and sends the results
back to Giganto (via its ingest endpoint). It supports two execution modes: one
using a locally specified configuration file, and another using configuration
provided by the Manager server.

## Key Features

<!-- markdownlint-disable MD007 MD013 -->
- Receives event data and generates statistical data based on defined policies.
- Provides configuration through one of the following modes:
    - **Local configuration mode**: Executes using a user-provided TOML configuration file
    - **Remote configuration mode**: Connects to a Manager server at startup and retrieves configuration
- Persists the last processed timestamp to allow continuation after restart.
<!-- markdownlint-enable MD007 MD013 -->

## Execution Modes

- **Local configuration mode**: Uses a TOML configuration file specified
  with `-c <CONFIG_PATH>`
- **Remote configuration mode**: Runs without `-c` and retrieves configuration
  from a Manager server

## Security Assumption (TLS)

Crusher uses QUIC/TLS connections and requires the following at startup:

- The client certificate, private key, and CA certificates must be provided
  using the `--cert`, `--key`, and `--ca-certs` options.

## Manual Map

- **Prerequisites**: Prepare configuration file, certificates/keys, and CA
  certificates.
- **Configuration**: Configure Giganto addresses and storage file paths.
- **Operations**: Run in local or remote configuration mode.
- **Troubleshooting**: Common issues and recovery steps.

## Quick Start

1. Prepare the `last_timestamp_data` file path
2. Create `config.toml` if needed
3. Prepare the certificate, private key, and CA certificates
4. Start Crusher
5. Verify connectivity to the Manager and Giganto servers
6. Check logs to confirm normal operation
