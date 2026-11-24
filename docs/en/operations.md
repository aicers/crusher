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
every sensor of the policy has passed the window's end:

- A policy reads one stream from the Data Store for each of its sensors, and
  adds the events of all its sensors into the same windows. When a stream
  starts, the Data Store first replays the stored events from where the policy
  resumes, then marks the end of the replay, and then sends events as they
  arrive.
- A sensor's stream passes a window once it delivers an event more than 900
  seconds after the window's end, whether it is replaying or not. Crusher
  waits 900 seconds past the end for a late Sensor batch and clock skew: a
  Sensor sends events in batches of up to 600 seconds.
- A quiet stream passes a window once its replay has ended, no event has
  arrived on it for 30 seconds, and the clock is at least 900 seconds past the
  window's end. On a quiet source, a window is thus written about 15 minutes
  after its end. A stream that is still replaying never passes a window this
  way, however long it is quiet: its replay has not caught up yet.
- A window is written once every stream of the policy has passed it. Until
  then, a stream that has not opened, or a stream that is still replaying and
  has not yet delivered an event past the window's end plus 900 seconds, holds
  the policy's windows open. While any stream of a policy has not opened or is
  still replaying, Crusher logs a warning every 10 minutes with the policy ID,
  the number of streams not yet opened, and the number of opened streams still
  replaying.
- Crusher builds the earliest window not yet written and the one after it at
  the same time. A stream that delivers an event further ahead, such as one
  replaying faster than the others, pauses until the others catch up. None of
  its events are lost. With windows shorter than 900 seconds, an event no more
  than 900 seconds past the end of the earliest window is counted at once
  instead of pausing its stream, since that stream has not yet passed that
  window. Up to 2 + 900 / window length (rounded down) windows are then built
  at once: 17 with 60-second windows.
- An event that arrives after its window was written, such as one in a late
  Sensor batch, corrects that window: Crusher writes it once more, replacing
  the earlier write. An event older than the last written window is dropped,
  and Crusher logs a warning with the number of events dropped.
- A window without events is never written: a reader sees a gap, not a row of
  zeros.
- A window still in progress is not written. When Crusher stops, reconnects,
  or a policy stops, the window in progress is discarded; when the policy runs
  again, Crusher rebuilds it from the events the Data Store holds and writes
  the last written window once more. If a sensor's stream ends on its own, the
  policy's windows are not written until Crusher reconnects or restarts.
- A new policy is built over all events the Data Store holds.
- A policy's source and destination address filters apply to live and stored
  events alike.

Crusher adds up every event of every sensor of a policy and cannot tell
whether two sensors saw the same communication. When assigning several
sensors to one policy, the operator is responsible for two conditions that
Crusher cannot check:

- The IP addresses the sensors monitor do not overlap.
- No communication is seen by more than one of the sensors. A communication
  that two sensors both see is counted twice.

## Items to Check After Startup

- Verify that the process does not terminate immediately
- Verify that there are no errors in certificates or configuration
- Verify connectivity to the Manager and Giganto servers
- Verify that logs are being generated as expected
