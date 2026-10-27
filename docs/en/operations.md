# Operations

## Execution Command

Crusher is started using the following command.

<!-- markdownlint-disable MD013 -->
```bash
crusher [-c <CONFIG_PATH>] --cert <CERT_PATH> --key <KEY_PATH> --ca-certs <CA1[,CA2,...]> <SERVER_NAME>@<SERVER_IP>:<SERVER_PORT>
```
<!-- markdownlint-enable MD013 -->

- `-c <CONFIG_PATH>`: TOML configuration file path (required for local mode)
- `--cert <CERT_PATH>`: Crusher certificate (PEM) (required)
- `--key <KEY_PATH>`: Crusher private key (PEM) (required)
- `--ca-certs <CA_CERT_PATH>[,...]`: CA certificates for verifying the target
  server (PEM) (required)
- `<SERVER_NAME>@<SERVER_IP>:<SERVER_PORT>`: Manager server address (required)

## Local Configuration Mode

```bash
crusher -c /path/to/crusher/config.toml \
  --cert /path/to/crusher/certs/cert.pem \
  --key /path/to/crusher/certs/key.pem \
  --ca-certs /path/to/crusher/certs/ca_cert.pem \
  manager@10.0.0.1:38390
```

## Remote Configuration Mode

```bash
crusher \
  --cert /path/to/crusher/cert.pem \
  --key /path/to/crusher/key.pem \
  --ca-certs /path/to/crusher/ca_cert.pem \
  manager@10.0.0.1:38390
```

In this mode, configuration is retrieved from the Manager server.

Until the Manager has a configuration for this instance, it refuses the
request with a reason such as `001.crusher unregistered`. Crusher logs this as
a warning, `Waiting for a configuration from the Manager: <reason>`, and waits
in idle mode. This is normal before the instance is configured: Crusher starts
as soon as the Manager sends its configuration.

## When a Window Is Written

Crusher writes a policy's time series one window (one period) at a time, once
the window has ended:

- On a busy source, a window is written when the first event of a later window
  arrives. A Sensor sends events in batches, so this is when the Sensor's next
  batch arrives after the window's end: up to 10 minutes after it with a Sensor
  that batches for 600 seconds.
- On a quiet source, a window is written at most about 15 minutes after its
  end. Crusher waits 900 seconds past the end for a late Sensor batch and clock
  skew, and closes the window once no event has arrived for 30 seconds.
- An event that arrives after its window was written, such as one in a late
  Sensor batch, corrects that window: Crusher writes it once more, replacing
  the earlier write. An event older than the last written window is dropped,
  and Crusher logs a warning with the number of events dropped.
- A window without events is never written: a reader sees a gap, not a row of
  zeros.
- A window still in progress is not written. When Crusher stops, reconnects,
  or a policy stops, the window in progress is discarded; when the policy runs
  again, Crusher rebuilds it from the events the Data Store holds and writes
  the last written window once more.
- A new policy is built over all events the Data Store holds.
- A policy's source and destination address filters apply to live and stored
  events alike.

## Items to Check After Startup

- Verify that the process does not terminate immediately
- Verify that there are no errors in certificates or configuration
- Verify connectivity to the Manager and Giganto servers
- Verify that logs are being generated as expected
