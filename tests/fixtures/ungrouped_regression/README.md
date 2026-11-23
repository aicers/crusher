# Ungrouped policy regression fixture

Each `<name>.input.json` holds one ungrouped single-sensor policy and the raw
events Giganto replays for it, in order. Each `<name>.expected.json` is what
crusher `0.12.4` stored for that input: for every Giganto key (series id,
window start in nanoseconds), the last window value written.

| Input                 | Kind | Measure          | Slot   | Window | Offset |
| --------------------- | ---- | ---------------- | ------ | ------ | ------ |
| `conn_count`          | Conn | Count            | 15 min | 1 h    | 0      |
| `conn_sum_orig_bytes` | Conn | Sum(`OrigBytes`) | 30 min | 2 h    | +1 h   |
| `dns_count`           | Dns  | Count            | 1 h    | 1 day  | +9 h   |
| `rdp_count`           | Rdp  | Count            | 5 min  | 30 min | 0      |
| `http_count`          | Http | Count            | 1 h    | 6 h    | -5 h   |
| `late_event`          | Conn | Sum(`OrigBytes`) | 15 min | 1 h    | 0      |

In `late_event`, an event of the window starting at 00:00 arrives after the
window starting at 01:00 has opened, while the 00:00 window is the last closed
one.

The `0.12.4` policy equivalent to an input has the same kind, its `interval`,
`period` and `offset` are the slot, window and UTC offset, and its `column` is
`None` for Count and `Some(7)` for Sum(`OrigBytes`).

## How the expected output was produced

The expected output comes from crusher tag `0.12.4` (commit `5856df5`)
without change, plus the test-only harness in `harness-0.12.4.patch`. The
harness feeds each input to crusher through fake Giganto Publish and Ingest
servers, follows it with two events days later that close its last window,
and records every window crusher writes to the Ingest server. The test
`subscribe::tests::regression` runs the same harness against the current code
and compares the result with these files.

To regenerate the output, from the root of a checkout of this branch:

```sh
fixtures=$PWD/tests/fixtures/ungrouped_regression
old=$(mktemp -d)/crusher-0.12.4
git worktree add --detach "$old" 0.12.4
git -C "$old" apply "$fixtures/harness-0.12.4.patch"
(cd "$old" && CRUSHER_REGRESSION_FIXTURES="$fixtures" \
  cargo test generate_ungrouped_regression_fixture -- --ignored)
git worktree remove --force "$old"
```

The command overwrites every `<name>.expected.json` in this directory.
