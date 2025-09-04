# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Updated `Conn` event field from `duration` to `end_time` to ensure
  consistency with other protocol events. The field now represents the
  session's final timestamp instead of the session duration.
- Updated `giganto-client` dependency to support type-driven stream
  requests, replacing `NodeType`-based handling with `StreamRequestPayload`
  enum for improved API consistency. This update also adds `start_time`
  field to all protocol event structures.
- Bumped bincode crate to 2.0 and modified the related code.
- Updated `roxy` dependency to version 0.5.0 with new `ResourceUsage` struct
  fields: `disk_used_bytes` and `disk_available_bytes`.
- Updated `review-protocol` dependency to version 0.12.0.

## [0.6.4] - 2025-07-16

### Changed

- Updated the roxy library dependency to 0.4.0 to support accurate measurement
  of disk usage at the correct data store path.

## [0.6.3] - 2025-05-26

### Fixed

- Fixed bugs where the connections to the manager and data-store were not
  re-established after either application was restarted.

### Changed

- Replaced the `log_dir` configuration option with `log_path`. The `log_path`
  option requires a full file path, including the filename. In addition, the
  `LOG_FILENAME` environment variable has been removed.

## [0.6.2] - 2025-04-08

### Fixed

- Fixed the issue where the connection to the manager server was re-established
  for each request instead of being reused. This caused unexpected behavior
  where the node status was not updated on the manager server. The manager
  server sends two consecutive requests (resource and ping) to check the node status.
  If Crusher disconnects after handling the first request, the subsequent
  request (ping, in this case) is not processed properly.

## [0.6.1] - 2025-03-14

### Changed

- Changed the format of the `--ca-certs` CLI argument for multiple values from
  `--ca-certs <PATH1> --ca-certs <PATH2>` to `--ca-certs <PATH1>[,<PATH2>,...]`.
- Renamed the log file from crusher.log to time_series_generator.log.

## [0.6.0] - 2025-02-20

### Changed

- Changed `REQUIRED_MANAGER_VERSION` to 0.42.0.
- Updated review-protocol to version 0.9.0.
  - Send the agent status to the manager.
  - Updated the signatures of `sampling_policy_list`, `delete_sampling_policy`.
  - Replaced the `RequestedPolicy`, `Policy` structs with the `SamplingPolicy`.
- Updated giganto-client to version 0.22.0.

### Removed

- Removed default configuration file: /usr/local/aice/conf/crusher.toml
  - If a configuration file is not specified in the CLI argument, Crusher runs
    in remote mode.

## [0.5.0] - 2024-11-26

### Changed

- Configuration options required for establishing a connection with the central
  management server must be specified directly via command-line interface. The
  following options and arguments are required:
  - `--cert`: Specifies the certificate file for the current module.
  - `--key`: Specifies the private key file for the certificate.
  - `--ca-certs`: Specifies the CA certificate files. Multiple CA certificates
    can be provided by using this option multiple times.
  - The Manager server's name and address must be provided as a command-line
    argument in the format `<server_name>@<server_ip>:<server_port>`.
- The configuration file, previously provided as a positional command-line
  argument, must now be specified using the `-c` option. This change allows for
  additional command-line arguments to be used alongside the configuration file.
  However, providing a local configuration file is optional.
- If `log_dir` is not specified in the configuration file or the log file cannot
  be created, logs will be printed to stdout.
- Changed `source` to `sensor`, which is a more appropriate term for the name of
  the device that sensed/captured the raw event.
- Changed `REQUIRED_GIGANTO_VERSION` to 0.23.0.

### Removed

- Removed cert, key, ca_certs, review_name and review_rpc_srv_addr from the
  configuration file; now mandatory via CLI.
- Removed OS-specific configuration directory.
  - Linux: $HOME/.config/crusher/config.toml
  - macOS: $HOME/Library/Application Support/com.cluml.crusher/config.toml

## [0.4.1] - 2024-10-04

### Changed

- Correct how to refer to other required modules in the code.
  - Changed `REVIEW_PROTOCOL_VERSION` to `REQUIRED_MANAGER_VERSION`.
  - Used `REQUIRED_GIGANTO_VERSION` instead of names that include `INGEST` or `PUBLISH`.
- Changed `REQUIRED_MANAGER_VERSION` to 0.39.0.
- Updated review-protocol to version 0.7.0.
  - As `get_config` was removed from `review-protocol::request::handler`,
    Removed the `get_config` related code from the crusher.

## [0.4.0] - 2024-09-27

### Added

- Support `shutdown`, `reload_config` via oinq.
- Added a `Certs` to store commonly used certificate information.

### Changed

- Applied code import ordering by `StdExternalCrate`. From now on, all code is
  expected to be formatted using
  `cargo fmt -- --config group_imports=StdExternalCrate`.
- Changed CrusherConfig with oinq `Config`.
- Modified logging behavior for debug and release builds
- Changed logs to stdout and file
- Changed configuration fields name.
  - `roots` to `ca_certs`. It also introduces support for multiple CA certificates.
  - `giganto_ingest_address` to `giganto_ingest_srv_addr`.
  - `giganto_publish_address` to `giganto_publish_srv_addr`.
  - `review_address` to `review_rpc_srv_addr`.
- Updated giganto-client to version 0.20.0. Updating to this version results in
  the following changes.
  - Updated the version of quinn, rustls from 0.10, 0.21 to 0.11, 0.23. With the
    update to this version, the usage of the quinn and rustls crates has
    changed, so code affected by the update has also been modified.
  - Updated the protocol version of the REview and Giganto.
    - Changed `REVIEW_PROTOCOL_VERSION` to 0.38.0.
    - Changed `PUBLISH_PROTOCOL_VERSION` to 0.21.0.
    - Changed `INGEST_PROTOCOL_VERSION` to 0.21.0.
  - Added more network data type. (`Bootp`, `Dhcp`)
- Changed the form of timeseries sent to Giganto to `Vec<(i64,Vec<u8>)>`.
  Currently, Giganto has changed to send and receive a certain number of events
  at once to optimize sending and receiving large amounts of data. For
  timeseries, one event is generated per period, and it takes too long to
  collect and send a certain number of timeseries events, so it was changed to
  send only one event as a vector.
- Updated review-protocol to version 0.6.0.
  - Modified to use `ConnectionBuilder` to simplify the handling of connections
    with Central Manager.
  - As `set_config` was removed from `review-protocol::request::handler`,
    Removed the `set_config` related code from the crusher.

## [0.3.2] - 2024-01-25

### Changed

- Changed `REVIEW_PROTOCOL_VERSION` to 0.27.0.
- Changed `PUBLISH_PROTOCOL_VERSION` to 0.17.0.

## [0.3.1] - 2023-11-07

### Added

- Support remote control
- Send the list of processes to REview using oinq.
- Changed `RecordType` to `RawEventKind`, as the communication protocol type
  defined in giganto-client 0.15.1 is integrated.

## [0.3.0] - 2023-07-06

### Added

- Add more network data type. (`Mqtt`, `Ldap`, `Tls`, `Smb`, `Nfs`)

## [0.2.0] - 2023-05-19

### Added

- Add more network data type. (`Ftp`)
- Delete the policies by requested IDs.

### Changed

- Removes the `agent_id` provided in the config file. This value is provided by
  the CN in the certificate in the form of `agent_id@host_id`.
- Requires REview 0.23.x

## [0.1.0] - 2023-03-30

### Added

- Receive timeseries generation policy generated by the REview and convert it to
  a model.
- Request a network stream to Giganto's publish for each model.
- Send the generated timeseries to Giganto's ingest.
- Save the model's id and the last time the timeseries was sent to a file.

[Unreleased]: https://github.com/aicers/crusher/compare/0.6.4...main
[0.6.4]: https://github.com/aicers/crusher/compare/0.6.3...0.6.4
[0.6.3]: https://github.com/aicers/crusher/compare/0.6.2...0.6.3
[0.6.2]: https://github.com/aicers/crusher/compare/0.6.1...0.6.2
[0.6.1]: https://github.com/aicers/crusher/compare/0.6.0...0.6.1
[0.6.0]: https://github.com/aicers/crusher/compare/0.5.0...0.6.0
[0.5.0]: https://github.com/aicers/crusher/compare/0.4.1...0.5.0
[0.4.1]: https://github.com/aicers/crusher/compare/0.4.0...0.4.1
[0.4.0]: https://github.com/aicers/crusher/compare/0.3.2...0.4.0
[0.3.2]: https://github.com/aicers/crusher/compare/0.3.1...0.3.2
[0.3.1]: https://github.com/aicers/crusher/compare/0.3.0...0.3.1
[0.3.0]: https://github.com/aicers/crusher/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/aicers/crusher/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/aicers/crusher/tree/0.1.0
