//! A policy over several sensors runs one generator stream per sensor through
//! the real Publish control loop. The test plays Giganto: it answers the
//! requests by opening the streams itself and sends each stream's frames, its
//! stored events, its replay-end frame and its realtime events, when the test
//! needs them.

use std::sync::{Arc, Mutex};

use giganto_client::frame::{send_bytes, send_raw};
use giganto_client::publish::send_time_series_generator_replay_end;
use quinn::{Connection, Endpoint, SendStream};
use review_protocol::request::Handler;
use review_protocol::types::{ConnField, Measure, TimeSeriesGenerationPolicy};
use serial_test::serial;
use tempfile::TempDir;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::{Duration, Instant, timeout};

use super::{
    BASE_TS_NANOS, BASE_WINDOW_START_NANOS, DAY_NANOS, FakeGigantoServer, HOST, PublishBehavior,
    TEST_TIMEOUT, cert_key, gen_conn, join_test_task, new_policy, setup_request_client,
};
use crate::cancellation::CancellationCoordinator;
use crate::policy::PolicyHandle;
use crate::subscribe::time_series::{CLOSE_GRACE_SECS, SECOND_TO_NANO, TimeSeries};
use crate::subscribe::{
    CloseTimer, REQUIRED_GIGANTO_VERSION, RequestStreamRecord, RequestTimeSeriesGeneratorStream,
    client, publish_connection_control,
};

const POLICY_ID: u32 = 1;
/// How long a test watches for a window that must not be written.
const QUIET: Duration = Duration::from_millis(800);
/// The idle time of tests that close windows by the wall clock.
const IDLE: Duration = Duration::from_millis(300);
const CHECK: Duration = Duration::from_millis(20);

type Request = (
    Connection,
    RequestStreamRecord,
    RequestTimeSeriesGeneratorStream,
);

/// Returns the time `secs` into the `day`-th 1-day window of [`new_policy`]
/// after the one of [`BASE_TS_NANOS`], in nanoseconds.
fn in_window(day: i64, secs: i64) -> i64 {
    BASE_WINDOW_START_NANOS + day * DAY_NANOS + secs * SECOND_TO_NANO
}

/// Returns the start of the `day`-th 1-day window, in seconds.
fn window_start_secs(day: i64) -> i64 {
    in_window(day, 0) / SECOND_TO_NANO
}

/// Returns an event time past the end of window `day` plus the grace: an
/// event there passes that window.
fn past_grace(day: i64) -> i64 {
    in_window(day + 1, CLOSE_GRACE_SECS + 1)
}

fn bundle_policy() -> TimeSeriesGenerationPolicy {
    let mut policy = new_policy(POLICY_ID);
    policy.sensors = vec!["s1".to_string(), "s2".to_string()];
    policy
}

/// A timer that never lets a stream pass by the wall clock.
fn event_time_only() -> CloseTimer {
    CloseTimer::new(|| i64::MIN, CHECK, IDLE)
}

/// A timer whose wall clock is ten days past every window of the tests.
fn wall_clock_far_past() -> CloseTimer {
    let now = window_start_secs(10);
    CloseTimer::new(move || now, CHECK, IDLE)
}

/// The real Publish control loop of one policy, against a Giganto whose
/// streams the test opens and drives.
struct Bundle {
    coordinator: CancellationCoordinator,
    review: crate::request::Client,
    actor: JoinHandle<anyhow::Result<()>>,
    handle: PolicyHandle,
    requests: async_channel::Receiver<Request>,
    series: async_channel::Receiver<TimeSeries>,
    control: JoinHandle<anyhow::Result<()>>,
    server: JoinHandle<()>,
    shutdown: Arc<Notify>,
    endpoint: Endpoint,
    _dir: TempDir,
}

impl Bundle {
    /// Starts `policy` with its checkpoint at `checkpoint`, if any.
    async fn start(
        policy: TimeSeriesGenerationPolicy,
        checkpoint: Option<i64>,
        close_timer: CloseTimer,
    ) -> Self {
        let coordinator = CancellationCoordinator::new();
        let (mut review, actor, _, dir, handle) = setup_request_client(None, &coordinator).await;
        let id = policy.id;
        review
            .time_series_generation_policy_list(&[policy])
            .await
            .unwrap();
        if let Some(checkpoint) = checkpoint {
            handle.record_ack(id, checkpoint).await.unwrap();
            assert_eq!(
                handle.stream_policy(id).await.unwrap().unwrap().start,
                checkpoint
            );
        }
        let (sender, requests) = async_channel::unbounded();
        let shutdown = Arc::new(Notify::new());
        let (addr, server) = FakeGigantoServer::new_publish()
            .with_publish_behavior(PublishBehavior::RecordRequests { sender })
            .start_publish(shutdown.clone());
        let endpoint = client::config(&cert_key()).unwrap();
        let control_endpoint = endpoint.clone();
        let control_handle = handle.clone();
        let control_coordinator = coordinator.clone();
        let (series_send, series) = async_channel::unbounded();
        let control = tokio::spawn(async move {
            publish_connection_control(
                series_send,
                addr,
                HOST,
                &control_endpoint,
                REQUIRED_GIGANTO_VERSION,
                control_handle,
                Arc::new(Notify::new()),
                control_coordinator,
                close_timer,
            )
            .await
        });
        Self {
            coordinator,
            review,
            actor,
            handle,
            requests,
            series,
            control,
            server,
            shutdown,
            endpoint,
            _dir: dir,
        }
    }

    /// Waits for `count` stream requests and returns the connection they
    /// arrived on and the requests.
    async fn requests(&self, count: usize) -> (Connection, Vec<Request>) {
        let mut requests = Vec::with_capacity(count);
        for _ in 0..count {
            requests.push(
                timeout(TEST_TIMEOUT, self.requests.recv())
                    .await
                    .expect("the stream request arrives")
                    .expect("the request channel stays open"),
            );
        }
        let connection = requests.first().expect("a request").0.clone();
        (connection, requests)
    }

    /// Waits for `count` stream requests and opens a stream for each.
    async fn open_streams(&self, count: usize) -> Vec<GigantoStream> {
        let (connection, _) = self.requests(count).await;
        let mut streams = Vec::with_capacity(count);
        for _ in 0..count {
            streams.push(GigantoStream::open(&connection, POLICY_ID).await);
        }
        streams
    }

    async fn next_window(&self) -> TimeSeries {
        timeout(TEST_TIMEOUT, self.series.recv())
            .await
            .expect("a window is written before the test deadline")
            .expect("the written-window channel stays open")
    }

    async fn assert_no_window(&self, why: &str) {
        if let Ok(written) = timeout(QUIET, self.series.recv()).await {
            panic!("{why}: {written:?}");
        }
    }

    async fn finish(self) {
        self.coordinator
            .request_cancellation("bundle test complete");
        join_test_task("Publish control", self.control)
            .await
            .unwrap();
        self.endpoint.close(0u32.into(), &[]);
        self.shutdown.notify_one();
        join_test_task("Giganto Publish server", self.server).await;
        drop(self.review);
        drop(self.handle);
        join_test_task("policy actor", self.actor).await.unwrap();
        assert!(self.coordinator.wait_for_drain(TEST_TIMEOUT).await);
    }
}

/// A generator stream the test sends as Giganto would.
struct GigantoStream(SendStream);

impl GigantoStream {
    async fn open(connection: &Connection, id: u32) -> Self {
        let mut stream = connection.open_uni().await.unwrap();
        send_raw(&mut stream, id.to_string().as_bytes())
            .await
            .unwrap();
        Self(stream)
    }

    async fn event(&mut self, timestamp: i64) {
        send_bytes(&mut self.0, &timestamp.to_le_bytes())
            .await
            .unwrap();
        send_raw(&mut self.0, &bincode::serialize(&gen_conn()).unwrap())
            .await
            .unwrap();
    }

    async fn try_event(&mut self, timestamp: i64) {
        if send_bytes(&mut self.0, &timestamp.to_le_bytes())
            .await
            .is_ok()
        {
            let _ = send_raw(&mut self.0, &bincode::serialize(&gen_conn()).unwrap()).await;
        }
    }

    async fn replay_end(&mut self) {
        // Giganto sends the request's start, which crusher does not read.
        send_time_series_generator_replay_end(&mut self.0, 0)
            .await
            .unwrap();
    }
}

/// Collects the log lines of the current thread while it is alive. A
/// `current_thread` test runs every task on that thread.
struct LogCapture {
    lines: Arc<Mutex<Vec<u8>>>,
    _guard: tracing::subscriber::DefaultGuard,
}

#[derive(Clone)]
struct LogWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl LogCapture {
    fn start() -> Self {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let writer = LogWriter(lines.clone());
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        Self {
            lines,
            _guard: tracing::subscriber::set_default(subscriber),
        }
    }

    fn count(&self, text: &str) -> usize {
        let lines = self
            .lines
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        String::from_utf8_lossy(&lines).matches(text).count()
    }
}

/// A two-sensor policy sends one request per sensor with the same start and
/// id. The events of both streams add into the same window and slot, a third
/// stream with the policy's id is dropped, and the window closes only once
/// both streams have passed its end plus the grace.
#[serial]
#[tokio::test]
async fn two_sensor_policy_adds_both_streams_into_one_window() {
    let bundle = Bundle::start(bundle_policy(), None, event_time_only()).await;
    let (connection, requests) = bundle.requests(2).await;
    let sensors: Vec<Option<&str>> = requests
        .iter()
        .map(|(_, _, request)| request.sensor.as_deref())
        .collect();
    assert_eq!(sensors, [Some("s1"), Some("s2")]);
    for (_, record_type, request) in &requests {
        assert_eq!(*record_type, RequestStreamRecord::Conn);
        assert_eq!(request.id, POLICY_ID.to_string());
        assert_eq!(request.start, 0, "both start at the policy's checkpoint");
    }

    let mut first = GigantoStream::open(&connection, POLICY_ID).await;
    let mut second = GigantoStream::open(&connection, POLICY_ID).await;
    let mut third = GigantoStream::open(&connection, POLICY_ID).await;
    first.event(BASE_TS_NANOS).await;
    first.event(BASE_TS_NANOS + 1).await;
    second.event(BASE_TS_NANOS + 2).await;
    // The stream may already be stopped, so the event may not be sent.
    third.try_event(BASE_TS_NANOS + 3).await;
    let stopped = timeout(TEST_TIMEOUT, third.0.stopped())
        .await
        .expect("the third stream is stopped");
    assert_eq!(stopped.unwrap(), Some(0u32.into()));

    first.event(past_grace(0)).await;
    bundle
        .assert_no_window("one stream past the window keeps it open")
        .await;
    second.event(past_grace(0)).await;
    let window = bundle.next_window().await;
    assert_eq!(window.time_series_id, POLICY_ID.to_string());
    assert_eq!(window.start_secs, window_start_secs(0));
    // BASE_TS_NANOS is 80 000 s into its window: slot 88 of 900 s.
    assert_eq!(window.series.get(88), Some(&3.0));
    assert_eq!(window.series.iter().sum::<f64>(), 3.0);
    bundle.finish().await;
}

/// With the wall clock already past the window, as after a restart, a stream
/// that has not sent its replay-end frame does not pass by idle, however long
/// its replay pauses. Its later replayed events count in the window, which
/// closes by idle once its replay ends.
#[serial]
#[tokio::test]
async fn replaying_stream_does_not_pass_by_idle() {
    let bundle = Bundle::start(
        bundle_policy(),
        Some(BASE_WINDOW_START_NANOS),
        wall_clock_far_past(),
    )
    .await;
    let mut streams = bundle.open_streams(2).await;
    let [first, second] = streams.as_mut_slice() else {
        unreachable!("two streams were opened");
    };
    first.event(BASE_TS_NANOS).await;
    first.replay_end().await;
    second.event(BASE_TS_NANOS + 1).await;
    bundle
        .assert_no_window("a replaying stream quiet past the idle time passes nothing")
        .await;

    second.event(BASE_TS_NANOS + 2).await;
    second.replay_end().await;
    let replay_ended = Instant::now();
    let window = bundle.next_window().await;
    assert!(replay_ended.elapsed() >= IDLE, "closed by idle");
    assert_eq!(window.start_secs, window_start_secs(0));
    assert_eq!(window.series.iter().sum::<f64>(), 3.0);
    bundle.finish().await;
}

/// A stream with nothing to replay passes by idle starting from its
/// replay-end frame.
#[serial]
#[tokio::test]
async fn stream_with_nothing_to_replay_closes_by_idle() {
    let bundle = Bundle::start(
        bundle_policy(),
        Some(BASE_WINDOW_START_NANOS),
        wall_clock_far_past(),
    )
    .await;
    let mut streams = bundle.open_streams(2).await;
    let [first, second] = streams.as_mut_slice() else {
        unreachable!("two streams were opened");
    };
    first.event(BASE_TS_NANOS).await;
    first.replay_end().await;
    bundle
        .assert_no_window("the other stream has not reached its replay end")
        .await;
    second.replay_end().await;
    let replay_ended = Instant::now();
    let window = bundle.next_window().await;
    assert!(replay_ended.elapsed() >= IDLE, "closed by idle");
    assert_eq!(window.series.iter().sum::<f64>(), 1.0);
    bundle.finish().await;
}

/// A stream that has not opened, and then one that has opened but is still
/// replaying, hold the window open, and the policy warns about them each
/// period with their counts. The late stream's events of the window count
/// there.
#[serial]
#[tokio::test]
async fn stalled_streams_hold_the_window_open_with_a_warning() {
    const STALL: Duration = Duration::from_millis(200);
    let logs = LogCapture::start();
    let bundle = Bundle::start(
        bundle_policy(),
        Some(BASE_WINDOW_START_NANOS),
        wall_clock_far_past().with_stall_warning(STALL),
    )
    .await;
    let (connection, _) = bundle.requests(2).await;
    let mut first = GigantoStream::open(&connection, POLICY_ID).await;
    first.event(BASE_TS_NANOS).await;
    first.replay_end().await;
    bundle
        .assert_no_window("a stream that has not opened holds the window open")
        .await;
    let unopened = "Policy 1 holds its windows open: 1 of its 2 streams have not opened and 0 \
                    opened streams are still replaying";
    assert!(logs.count(unopened) >= 2, "warned each period");

    let mut second = GigantoStream::open(&connection, POLICY_ID).await;
    second.event(BASE_TS_NANOS + 1).await;
    bundle
        .assert_no_window("a replaying stream before the window's end plus the grace")
        .await;
    let replaying = "Policy 1 holds its windows open: 0 of its 2 streams have not opened and 1 \
                     opened streams are still replaying";
    assert!(logs.count(replaying) >= 2, "warned each period");

    second.replay_end().await;
    let window = bundle.next_window().await;
    assert_eq!(window.start_secs, window_start_secs(0));
    assert_eq!(window.series.iter().sum::<f64>(), 2.0);
    let warnings = logs.count("holds its windows open");
    bundle
        .assert_no_window("the next window has no events")
        .await;
    assert_eq!(
        logs.count("holds its windows open"),
        warnings,
        "no warning once every stream opened and ended its replay"
    );
    bundle.finish().await;
}

/// Without any replay-end frame, windows close by event time alone. An event
/// of the next window during the window's grace counts there. An event two
/// windows ahead pauses its stream until the window closes; the held event then
/// counts in its window and the stream resumes.
#[serial]
#[tokio::test]
async fn windows_close_by_event_time_and_a_paused_stream_resumes() {
    let bundle = Bundle::start(
        bundle_policy(),
        Some(BASE_WINDOW_START_NANOS),
        event_time_only(),
    )
    .await;
    let mut streams = bundle.open_streams(2).await;
    let [first, second] = streams.as_mut_slice() else {
        unreachable!("two streams were opened");
    };
    first.event(BASE_TS_NANOS).await;
    // In window 1, during window 0's grace.
    first.event(in_window(1, 100)).await;
    // Two windows ahead and past window 0's grace: the stream pauses.
    first.event(in_window(2, 1000)).await;
    second.event(BASE_TS_NANOS + 1).await;
    bundle
        .assert_no_window("one stream past the window keeps it open")
        .await;

    second.event(past_grace(0)).await;
    let window = bundle.next_window().await;
    assert_eq!(window.start_secs, window_start_secs(0));
    assert_eq!(window.series.iter().sum::<f64>(), 2.0);

    // Both streams move four windows ahead; windows 1 and 2 close.
    first.event(in_window(4, 1000)).await;
    second.event(in_window(4, 1000)).await;
    let window = bundle.next_window().await;
    assert_eq!(window.start_secs, window_start_secs(1));
    assert_eq!(window.series.iter().sum::<f64>(), 2.0);
    let window = bundle.next_window().await;
    assert_eq!(window.start_secs, window_start_secs(2));
    assert_eq!(window.series.iter().sum::<f64>(), 1.0, "the held event");
    bundle.finish().await;
}

/// A paused stream resumes once the other stream passes the window by idle
/// after its replay end.
#[serial]
#[tokio::test]
async fn paused_stream_resumes_when_the_other_passes_by_idle() {
    let bundle = Bundle::start(
        bundle_policy(),
        Some(BASE_WINDOW_START_NANOS),
        wall_clock_far_past(),
    )
    .await;
    let mut streams = bundle.open_streams(2).await;
    let [first, second] = streams.as_mut_slice() else {
        unreachable!("two streams were opened");
    };
    first.event(BASE_TS_NANOS).await;
    first.event(in_window(2, 1000)).await;
    second.event(BASE_TS_NANOS + 1).await;
    second.replay_end().await;
    let window = bundle.next_window().await;
    assert_eq!(window.start_secs, window_start_secs(0));
    assert_eq!(window.series.iter().sum::<f64>(), 2.0);

    first.replay_end().await;
    let window = bundle.next_window().await;
    assert_eq!(window.start_secs, window_start_secs(2));
    assert_eq!(window.series.iter().sum::<f64>(), 1.0, "the held event");
    bundle.finish().await;
}

/// Two sensors replayed at different speeds lose none of the slower sensor's
/// events: the first sends its whole replay before the second sends any.
#[serial]
#[tokio::test]
async fn replay_at_different_speeds_drops_no_events() {
    const HOUR_SECS: i64 = 3600;
    const HOURS: i64 = 4;
    let mut policy = bundle_policy();
    policy.window_size = Duration::from_secs(3600);
    let start = BASE_TS_NANOS / (HOUR_SECS * SECOND_TO_NANO) * (HOUR_SECS * SECOND_TO_NANO);
    let bundle = Bundle::start(policy, Some(start), event_time_only()).await;
    let mut streams = bundle.open_streams(2).await;
    // One event every 10 minutes over four hours, then one far ahead.
    let events: Vec<i64> = (0..HOURS * 6)
        .map(|i| start + i * 600 * SECOND_TO_NANO)
        .chain([start + 10 * HOUR_SECS * SECOND_TO_NANO])
        .collect();
    for stream in &mut streams {
        for timestamp in &events {
            stream.event(*timestamp).await;
        }
    }
    let mut windows = Vec::new();
    for _ in 0..HOURS {
        let window = bundle.next_window().await;
        windows.push((window.start_secs, window.series));
    }
    let start_secs = start / SECOND_TO_NANO;
    let expected: Vec<(i64, Vec<f64>)> = (0..HOURS)
        .map(|hour| (start_secs + hour * HOUR_SECS, vec![4.0, 2.0, 4.0, 2.0]))
        .collect();
    assert_eq!(windows, expected);
    bundle.finish().await;
}

/// A second replay-end frame on a stream is warned about and skipped.
#[serial]
#[tokio::test]
async fn second_replay_end_frame_is_warned_and_skipped() {
    let logs = LogCapture::start();
    let bundle = Bundle::start(
        new_policy(POLICY_ID),
        Some(BASE_WINDOW_START_NANOS),
        wall_clock_far_past(),
    )
    .await;
    let mut streams = bundle.open_streams(1).await;
    let [stream] = streams.as_mut_slice() else {
        unreachable!("one stream was opened");
    };
    stream.event(BASE_TS_NANOS).await;
    stream.replay_end().await;
    stream.replay_end().await;
    let window = bundle.next_window().await;
    assert_eq!(window.series.iter().sum::<f64>(), 1.0);
    assert_eq!(
        logs.count("Skipping a second replay-end frame on a stream of policy 1"),
        1
    );
    bundle.finish().await;
}

/// A policy changed before every stream of its earlier request arrived is
/// requested again on a new Publish connection, since a stream still to come
/// could answer either request. Once every stream has arrived, a change is
/// requested again on the same connection.
#[serial]
#[tokio::test]
async fn changed_policy_is_requested_again_once_every_stream_arrived() {
    let mut bundle = Bundle::start(bundle_policy(), None, event_time_only()).await;
    let changed = |measure| TimeSeriesGenerationPolicy {
        measure,
        ..bundle_policy()
    };

    // One of the two streams has arrived when the policy changes.
    let (connection, _) = bundle.requests(2).await;
    let _first = GigantoStream::open(&connection, POLICY_ID).await;
    bundle
        .review
        .time_series_generation_policy_list(&[changed(Measure::Sum(ConnField::Duration))])
        .await
        .unwrap();
    let (replaced, requests) = bundle.requests(2).await;
    assert_ne!(
        replaced.stable_id(),
        connection.stable_id(),
        "requested again on a new connection"
    );
    assert!(
        requests.iter().all(
            |(request_connection, _, _)| request_connection.stable_id() == replaced.stable_id()
        )
    );

    // Both streams arrive before the next change: the window closes only once
    // both have passed it, so its write shows that both were bound.
    let mut streams = [
        GigantoStream::open(&replaced, POLICY_ID).await,
        GigantoStream::open(&replaced, POLICY_ID).await,
    ];
    for stream in &mut streams {
        stream.event(BASE_TS_NANOS).await;
        stream.event(past_grace(0)).await;
    }
    let window = bundle.next_window().await;
    assert_eq!(window.start_secs, window_start_secs(0));
    bundle
        .review
        .time_series_generation_policy_list(&[changed(Measure::Sum(ConnField::OrigBytes))])
        .await
        .unwrap();
    let (same, _) = bundle.requests(2).await;
    assert_eq!(
        same.stable_id(),
        replaced.stable_id(),
        "requested again on the same connection"
    );
    bundle.finish().await;
}

/// Giganto keeps every requested stream open, so a policy with more sensors
/// than quinn's default limit of inbound streams still has every stream open
/// at once, and its window closes once all of them have passed it.
#[serial]
#[tokio::test]
async fn every_stream_of_a_policy_over_the_default_stream_limit_opens() {
    const SENSORS: usize = 120;
    let mut policy = new_policy(POLICY_ID);
    policy.sensors = (0..SENSORS).map(|sensor| format!("s{sensor}")).collect();
    let bundle = Bundle::start(policy, None, event_time_only()).await;
    let (connection, _) = bundle.requests(SENSORS).await;
    let mut streams = Vec::with_capacity(SENSORS);
    for _ in 0..SENSORS {
        streams.push(
            timeout(TEST_TIMEOUT, GigantoStream::open(&connection, POLICY_ID))
                .await
                .expect("crusher lets Giganto open every requested stream"),
        );
    }
    for stream in &mut streams {
        stream.event(BASE_TS_NANOS).await;
        stream.event(past_grace(0)).await;
    }
    let window = bundle.next_window().await;
    assert_eq!(window.start_secs, window_start_secs(0));
    assert_eq!(window.series.iter().sum::<f64>(), 120.0);
    bundle.finish().await;
}

/// A stream that keeps delivering replayed events does not keep the policy from
/// warning about its stream that has not opened.
///
/// On this `current_thread` runtime a stream's reader refills its frame only
/// while the runner waits, so frames alone cannot starve the warning here; on a
/// multi-threaded runtime they could, and the runner polls the warning timer
/// before the frames for that reason.
#[serial]
#[tokio::test]
async fn stall_warning_is_logged_while_another_stream_keeps_replaying() {
    const STALL: Duration = Duration::from_millis(100);
    const BURST: Duration = Duration::from_millis(500);
    let logs = LogCapture::start();
    let bundle = Bundle::start(
        bundle_policy(),
        Some(BASE_WINDOW_START_NANOS),
        event_time_only().with_stall_warning(STALL),
    )
    .await;
    let (connection, _) = bundle.requests(2).await;
    let mut replaying = GigantoStream::open(&connection, POLICY_ID).await;
    let unopened = "Policy 1 holds its windows open: 1 of its 2 streams have not opened and 1 \
                    opened streams are still replaying";
    let burst_end = Instant::now() + BURST;
    let mut sent = 0;
    while Instant::now() < burst_end {
        replaying.event(BASE_TS_NANOS + sent).await;
        sent += 1;
    }
    assert!(
        logs.count(unopened) >= 2,
        "warned each period while {sent} events were replayed"
    );
    bundle
        .assert_no_window("a stream that has not opened holds the window open")
        .await;
    bundle.finish().await;
}
