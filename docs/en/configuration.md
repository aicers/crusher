# Configuration (toml)

## Key Configuration Summary

<!-- markdownlint-disable MD013 -->
| Configuration | Description | Default |
| --- | --- | --- |
| giganto_name | Giganto server name (used as the TLS server name; required) | - |
| giganto_ingest_srv_addr | Address of the server to which aggregated data is sent | - |
| giganto_publish_srv_addr | Address of the server from which event data is received | - |
| last_timestamp_data | File path for storing each policy's resume position and write generation (required) | - |
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

- The file holds an object for each policy ID with up to two fields:
  `timestamp`, the start of the last window the Data Store acknowledged, in
  Unix nanoseconds, where the policy resumes; and `generation`, the write
  generation of the policy's latest stream request, in Unix milliseconds. For
  example:
  `{"42": {"timestamp": 1700006400000000000, "generation": 1764000000000}}`
- A policy with a `timestamp` resumes from that window, which it writes again;
  one without starts from the beginning.
- If the file does not exist, it is created empty, and every policy starts
  from the beginning.
- Crusher updates `timestamp` as windows are acknowledged and `generation` at
  each stream request of a grouped policy.
- Deleting a policy, or changing its content, removes its `timestamp` and
  keeps its `generation`, so that a policy created again with the same ID
  still gets a greater generation.
- Only Crusher writes the file: do not edit it by hand. A file not in this
  form stops Crusher at startup.
