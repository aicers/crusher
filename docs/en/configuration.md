# Configuration (toml)

## Key Configuration Summary

<!-- markdownlint-disable MD013 -->
| Configuration | Description | Default |
| --- | --- | --- |
| giganto_name | Giganto server name (used as the TLS server name) | - |
| giganto_ingest_srv_addr | Address of the server to which aggregated data is sent | - |
| giganto_publish_srv_addr | Address of the server from which event data is received | - |
| last_timestamp_data | File path for storing the last processed timestamp (required) | - |
| log_path | Log file path | `stdout` if not specified |
<!-- markdownlint-enable MD013 -->

## Configuration Example

```toml
giganto_name = "giganto.example.local"
giganto_ingest_srv_addr = "10.10.10.20:38370"
giganto_publish_srv_addr = "10.10.10.20:38371"
last_timestamp_data = "/path/to/last_timestamp.json"
log_path = "/path/to/crusher.log"
```

`log-path` Behavior

- Not specified: logs are written to stdout
- Specified and writable: logs are written to the specified file
- Specified but not writable: Crusher terminates

`last_timestamp_data` File Behavior

- If the file exists, processing resumes from the last recorded timestamp
- If the file does not exist, processing starts from the beginning
- The last processed timestamp is continuously updated during execution
