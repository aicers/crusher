//! Replays the raw events of `tests/fixtures/ungrouped_regression` through
//! crusher and fake Giganto servers, and checks that what crusher stores for
//! each ungrouped single-sensor policy equals what crusher 0.12.4 stored for
//! the equivalent policy of its own schema. The fixture's `README.md` says how
//! the expected output was produced.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use super::{
    CloseTimer, ConnField, CounterpartScope, Duration, GeneratorFrame, GroupByUnit,
    HostNetworkGroup, Measure, PolicyRawEventKind, PublishBehavior, TimeSeriesGenerationPolicy,
    cert_key, cleanup_test_resources, setup_request_client, spawn_subscribe_client_with_timer,
    start_window_servers_with,
};
use crate::cancellation::CancellationCoordinator;
use crate::subscribe::tests::FakeGigantoServer;
use crate::subscribe::{Conn, Dns, Http, Rdp};

const FIXTURE_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/ungrouped_regression"
);
const INPUTS: [&str; 6] = [
    "conn_count",
    "conn_sum_orig_bytes",
    "dns_count",
    "rdp_count",
    "http_count",
    "late_event",
];
const POLICY_ID: u32 = 1;
const DAY_NANOS: i64 = 86_400_000_000_000;
/// Long enough that no window of a test run is written for an idle stream.
const NEVER: Duration = Duration::from_secs(3600);
const RUN_TIMEOUT: Duration = Duration::from_secs(30);

/// One input: a policy and the raw events Giganto replays for it, in order.
#[derive(Deserialize)]
struct Input {
    kind: InputKind,
    measure: InputMeasure,
    slot_size_secs: u64,
    window_size_secs: u64,
    utc_offset: i32,
    events: Vec<InputEvent>,
}

#[derive(Clone, Copy, Deserialize)]
enum InputKind {
    Conn,
    Dns,
    Rdp,
    Http,
}

/// The measure, which crusher 0.12.4 expressed as `column` `None` and
/// `Some(7)`.
#[derive(Clone, Copy, Deserialize)]
enum InputMeasure {
    Count,
    SumOrigBytes,
}

#[derive(Clone, Deserialize)]
struct InputEvent {
    timestamp: i64,
    orig_addr: IpAddr,
    resp_addr: IpAddr,
    #[serde(default)]
    orig_bytes: u64,
}

/// The value Giganto stores last under one key.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct StoredWindow {
    series_id: String,
    window_start: i64,
    series: Vec<f64>,
}

fn policy(input: &Input) -> TimeSeriesGenerationPolicy {
    TimeSeriesGenerationPolicy {
        id: POLICY_ID,
        raw_event_kind: match input.kind {
            InputKind::Conn => PolicyRawEventKind::Conn,
            InputKind::Dns => PolicyRawEventKind::Dns,
            InputKind::Rdp => PolicyRawEventKind::Rdp,
            InputKind::Http => PolicyRawEventKind::Http,
        },
        measure: match input.measure {
            InputMeasure::Count => Measure::Count,
            InputMeasure::SumOrigBytes => Measure::Sum(ConnField::OrigBytes),
        },
        group_by: None,
        group_by_unit: GroupByUnit::Ip,
        counterpart_scope: CounterpartScope::Any,
        slot_size: Duration::from_secs(input.slot_size_secs),
        window_size: Duration::from_secs(input.window_size_secs),
        utc_offset: input.utc_offset,
        src_ip: None,
        dst_ip: None,
        sensors: vec!["sensor".to_string()],
        time_series_type: None,
        internal_networks: HostNetworkGroup::default(),
    }
}

/// Encodes `event` as the giganto-client record of `kind`.
#[allow(clippy::too_many_lines)] // One literal per kind.
fn record(kind: InputKind, event: &InputEvent) -> Vec<u8> {
    let orig_addr = event.orig_addr;
    let resp_addr = event.resp_addr;
    let encoded = match kind {
        InputKind::Conn => bincode::serialize(&Conn {
            orig_addr,
            orig_port: 50_000,
            resp_addr,
            resp_port: 443,
            proto: 6,
            conn_state: "SF".to_string(),
            start_time: event.timestamp,
            duration: 1_000,
            service: "-".to_string(),
            orig_bytes: event.orig_bytes,
            resp_bytes: 0,
            orig_pkts: 1,
            resp_pkts: 1,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
        }),
        InputKind::Dns => bincode::serialize(&Dns {
            orig_addr,
            orig_port: 50_000,
            resp_addr,
            resp_port: 53,
            proto: 17,
            start_time: event.timestamp,
            duration: 1_000,
            orig_pkts: 1,
            resp_pkts: 1,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            query: "example.com".to_string(),
            answer: Vec::new(),
            trans_id: 1,
            rtt: 1,
            qclass: 1,
            qtype: 1,
            rcode: 0,
            aa_flag: false,
            tc_flag: false,
            rd_flag: true,
            ra_flag: true,
            ttl: Vec::new(),
        }),
        InputKind::Rdp => bincode::serialize(&Rdp {
            orig_addr,
            orig_port: 50_000,
            resp_addr,
            resp_port: 3389,
            proto: 6,
            start_time: event.timestamp,
            duration: 1_000,
            orig_pkts: 1,
            resp_pkts: 1,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            cookie: String::new(),
        }),
        InputKind::Http => bincode::serialize(&Http {
            orig_addr,
            orig_port: 50_000,
            resp_addr,
            resp_port: 80,
            proto: 6,
            start_time: event.timestamp,
            duration: 1_000,
            orig_pkts: 1,
            resp_pkts: 1,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            uri: "/".to_string(),
            referer: String::new(),
            version: "1.1".to_string(),
            user_agent: String::new(),
            request_len: 0,
            response_len: 0,
            status_code: 200,
            status_msg: "OK".to_string(),
            username: String::new(),
            password: String::new(),
            cookie: String::new(),
            content_encoding: String::new(),
            content_type: String::new(),
            cache_control: String::new(),
            filenames: Vec::new(),
            mime_types: Vec::new(),
            body: Vec::new(),
            state: String::new(),
        }),
    };
    encoded.expect("a fixture record serializes")
}

fn read_input(name: &str) -> Input {
    let path = format!("{FIXTURE_DIR}/{name}.input.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parsing {path}: {e}"))
}

fn read_expected(name: &str) -> Vec<StoredWindow> {
    let path = format!("{FIXTURE_DIR}/{name}.expected.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parsing {path}: {e}"))
}

/// Runs crusher over `input` and returns, per Giganto key, the window value
/// written last.
///
/// Two events far after the input follow it. The first closes the input's
/// last window; the second closes the first one's window, whose write, after
/// every write of the input on the same ingest stream, ends the run. Nothing
/// is closed by the timer, so the result depends only on the events' order.
async fn run(input: &Input) -> Vec<StoredWindow> {
    let last = input
        .events
        .iter()
        .map(|event| event.timestamp)
        .max()
        .expect("an input has events");
    let mut events = input.events.clone();
    let flush = events.last().cloned().expect("an input has events");
    for timestamp in [last + 2 * DAY_NANOS, last + 4 * DAY_NANOS] {
        events.push(InputEvent {
            timestamp,
            orig_bytes: 0,
            ..flush.clone()
        });
    }
    let records: Vec<GeneratorFrame> = events
        .iter()
        .map(|event| GeneratorFrame::Event(event.timestamp, record(input.kind, event)))
        .collect();

    let servers = start_window_servers_with(
        FakeGigantoServer::new_ingest(),
        FakeGigantoServer::new_publish()
            .with_publish_behavior(PublishBehavior::Records(records.into())),
    );
    let coordinator = CancellationCoordinator::new();
    let (review, actor_task, _, _dir, policy_handle) =
        setup_request_client(None, &coordinator).await;
    policy_handle
        .replace_policies(vec![policy(input)])
        .await
        .unwrap();
    let client_handle = spawn_subscribe_client_with_timer(
        &cert_key(),
        actor_task,
        servers.ingest_addr,
        servers.publish_addr,
        policy_handle.clone(),
        coordinator.clone(),
        CloseTimer::new(|| i64::MIN, NEVER, NEVER),
    );

    let mut stored = BTreeMap::new();
    loop {
        let (window_start, series) = tokio::time::timeout(RUN_TIMEOUT, servers.series.recv())
            .await
            .expect("crusher writes the flushing window before the deadline")
            .expect("the written-window channel stays open");
        if window_start > last {
            break;
        }
        // The record as Giganto stores it: the series id, then the values.
        let (series_id, values): (String, Vec<f64>) =
            bincode::deserialize(&bincode::serialize(&series).expect("a window serializes"))
                .expect("a window is a series id and its values");
        stored.insert((series_id, window_start), values);
    }

    drop(review);
    drop(policy_handle);
    cleanup_test_resources(coordinator, client_handle, servers.handles).await;
    stored
        .into_iter()
        .map(|((series_id, window_start), series)| StoredWindow {
            series_id,
            window_start,
            series,
        })
        .collect()
}

#[serial_test::serial]
#[tokio::test]
async fn ungrouped_policies_store_what_0_12_4_stored() {
    for name in INPUTS {
        let input = read_input(name);
        let stored = run(&input).await;
        assert_eq!(stored, read_expected(name), "{name}");
    }
}
