# Troubleshooting (Common Issues)

## When the process does not start

- Verify that the certificate, private key, and CA certificate paths are correct
- In local configuration mode, verify that the configuration file path is correct
- If a log path is specified, verify that the file has write permissions

## `last_timestamp_data` File Issues

- Verify that the file path is correct
- Verify that the parent directory has write permissions
- If the file exists, verify that it is in valid JSON format

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
