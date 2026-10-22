# Configuration (toml)

## Key Configuration Summary

<!-- markdownlint-disable MD013 -->
| Configuration | Description | Default |
| --- | --- | --- |
| giganto_name | Giganto server name (used as the TLS server name; required) | - |
| giganto_ingest_srv_addr | Address of the server to which aggregated data is sent | - |
| giganto_publish_srv_addr | Address of the server from which event data is received | - |
| last_timestamp_data | File path for storing the last processed timestamp (required) | - |
<!-- markdownlint-enable MD013 -->

## Configuration Example

```toml
giganto_name = "giganto.example.local"
giganto_ingest_srv_addr = "10.10.10.20:38370"
giganto_publish_srv_addr = "10.10.10.20:38371"
last_timestamp_data = "/path/to/last_timestamp.json"
```

Logging

Crusher writes its log to standard output; `RUST_LOG` sets the level (default
`info`); when standard output or standard error is connected to the systemd
journal (`JOURNAL_STREAM`), each event is one line starting with its syslog
priority (`<3>` error, `<4>` warning, `<6>` info, `<7>` debug and trace),
without a timestamp or colour codes, line breaks inside an event written as
`\n`, and a panic is logged as one error entry; elsewhere colour codes are
written only to a terminal. `log_path` was removed, and a configuration naming
it is refused.

`last_timestamp_data` File Behavior

- If the file exists, processing resumes from the last recorded timestamp
- If the file does not exist, processing starts from the beginning
- The last processed timestamp is continuously updated during execution
