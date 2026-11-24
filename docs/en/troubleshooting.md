# Troubleshooting (Common Issues)

## When the process does not start

- Verify that the certificate, private key, and CA certificate paths are correct
- In local configuration mode, verify that the configuration file path is correct
- Read the log with `journalctl -u <unit>` (under systemd) or on standard output

## `last_timestamp_data` File Issues

- Verify that the file path is correct
- Verify that the parent directory has write permissions
- If the file exists, verify that it is in valid JSON format
- A file in the form an earlier Crusher wrote, a number for each policy ID
  such as `{"42": 1700006400000000000}`, is rejected at startup: Crusher does
  not start and leaves the file unchanged. This version is installed fresh:
  start it without that file, which it then creates anew.

## When Connection Fails

<!-- markdownlint-disable MD007 MD013 -->
- Manager
    - Verify that the `<SERVER_NAME>@<SERVER_IP>:<SERVER_PORT>` format is correct
    - Verify that the Manager server address and port are correct
    - Verify that the CA certificates used for verification are correct
- Giganto
    - Verify the `giganto_ingest_srv_addr` and `giganto_publish_srv_addr` settings
    - Verify the `giganto_name` setting
<!-- markdownlint-enable MD007 MD013 -->
