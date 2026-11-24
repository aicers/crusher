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
- An ungrouped policy never writes a window without events: a reader sees a
  gap, not a row of zeros. A grouped policy writes a marker for such a window
  instead (see [Window Markers and Write
  Generations](#window-markers-and-write-generations)).
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

## Per-IP Series

A policy grouped by source or destination writes one series per IP of the
customer's internal network instead of one summed series. The windows of all
of its IPs follow the rules above together:

- A policy grouped by source splits by the event's source address, a policy
  grouped by destination by its destination address. The series of an IP has
  the ID `P/IP`, the policy ID and the IP as written in the usual notation:
  `42/10.100.0.5` or `42/2001:db8::1`. An IPv4 address and the IPv4-mapped
  IPv6 address of it are different IPs. A grouped policy writes only the
  markers of its windows under its own ID `P` (see below); an ungrouped
  policy writes its single series under `P`.
- An event counts only if the IP on the grouping side is in the policy's
  internal network: it is one of its hosts, or lies in one of its networks or
  ranges. An event with an external IP on that side writes no series, but
  still moves its stream past a window, so it can get a window written.
- The policy's counterpart scope filters on the other endpoint: internal
  counts only events whose other endpoint is in the internal network too,
  external only those whose other endpoint is outside it, and any counts both.
  An ungrouped policy must count every counterpart; one with another scope is
  skipped with a warning naming the policy ID, as is a policy grouped by
  customer network, which Crusher does not support yet.
- The events of every sensor of the policy for the same IP add into the same
  series. When a window is written, the rows of all its IPs are written
  together, in ascending order of their series IDs, so a quiet IP's window is
  written when the policy's window closes, not when that IP next appears. An
  event that arrives after its window was written corrects that IP's row, or
  adds a row for an IP that had none in the window.
- A change to the policy's internal network alone does not restart the policy
  or discard its resume position. The new network applies from the window
  after the one containing the latest event the policy has received; earlier
  windows keep the network they had, and their rows stay as written. An IP
  added to the network is counted from that window on, and an IP removed from
  it gets no window from that window on. When the policy's streams are
  requested again, after a restart or a reconnect, the current network
  applies to every window from where the policy resumes.
- A grouped policy whose internal network is empty counts no events. Crusher
  logs a warning with the policy ID for each of its windows that is due while
  the network is empty, from the window of the first event the policy receives
  on. The policy keeps running.
- A grouped policy keeps a series for at most 10,000 IPs at a time. The IPs
  are taken in the order their events arrive and are kept for as long as the
  policy runs, however quiet. Events of further IPs are not counted. When a
  window is due in which such IPs were refused, Crusher logs a warning with
  the policy ID and the number of refused IPs. When the policy's streams are
  requested again, the IPs are taken anew from the replayed events.

## Window Markers and Write Generations

A grouped policy marks each window it writes as complete, so that a reader can
tell whether it sees every IP row of the window or only those stored so far.
An ungrouped policy writes no marker and no generation.

- Every IP row of a grouped policy ends with one element after its slot
  values: the write generation of the run that wrote it.
- After all IP rows of a window, on the same stream, Crusher writes the
  window's marker under the policy's own ID `P`, at the window's start. It
  holds two values: the number of IP rows of the window, and the generation.
  The Data Store stores a policy's rows in the order Crusher sends them, so
  once the marker is visible, every IP row before it is visible too. A reader
  takes only the IP rows of the marker's generation. When Crusher requests
  the policy's streams again on the same connection, or the policy returns
  after it was deleted, Crusher writes the new run's rows only once the Data
  Store has stored every row the earlier run sent, so that no earlier row is
  stored after them. If that takes longer than 10 seconds, Crusher reconnects
  to the Data Store. Before it reconnects to the Data Store, Crusher likewise
  finishes what it sent on the old connection, the earlier run's rows still
  waited for included, and waits, with no time limit, until the Data Store
  has stored it, logging a warning every 10 seconds while it waits. If the
  old connection is already lost, or is lost during the wait, Crusher cannot
  learn whether the Data Store stored what it received there, and reconnects
  without waiting further.
- If Crusher cannot send one of a run's rows or markers, for example because
  that wait timed out, it sends nothing more of that run, so that no marker is
  stored without a row it counts. It then requests the policy's streams again,
  and the new run rewrites from the checkpoint with a new generation.
- Crusher fixes a new generation each time it requests the policy's streams:
  at startup, when the policy changes or returns to the policy list, and when
  it reconnects to the Data Store. The generation is the clock at the request
  in Unix milliseconds, or one more than the policy's previous generation if
  that is larger, so it always grows, also across restarts and a clock set
  back. Crusher stores it in the `last_timestamp_data` file before it writes
  any row of it.
- A grouped policy closes every window, including one in which no IP was
  counted, such as a window whose internal network is empty, and writes the
  marker `[0, generation]` for it. Such a window closes only once a stream of
  the policy has delivered an event more than 900 seconds past its end: quiet
  streams past their replay end do not close it, and the later windows wait
  behind it. Windows close in time order. A new policy writes no marker for
  the windows before the one of the first event it receives.
- When Crusher requests the policy's streams again, it rewrites the window
  where the policy resumes and every later one with the new generation: the
  IP rows first, then the new marker. An IP the new run no longer counts
  there, for example after a change to the internal network, gets no new row.
  Its earlier row stays in the Data Store with its earlier generation, which
  the new marker excludes. A window that now has no IP rows gets
  `[0, generation]`.
- An event that arrives after its window's marker was written corrects the
  row of its IP with the same generation and does not write the marker again.
  For an IP without a row in the window, Crusher writes the new row and the
  marker counting it, `[n + 1, generation]`, together in one write. When the
  next window closes, Crusher logs a warning with the policy ID and the number
  of IP rows corrected or added after their marker since the previous close.

## Items to Check After Startup

- Verify that the process does not terminate immediately
- Verify that there are no errors in certificates or configuration
- Verify connectivity to the Manager and Giganto servers
- Verify that logs are being generated as expected
