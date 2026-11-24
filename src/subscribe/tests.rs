mod bundle;
mod records;
mod regression;

use std::collections::HashMap;
use std::time::Duration;
use std::{
    fs,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use giganto_client::{
    connection::server_handshake,
    frame::{recv_raw, send_bytes, send_raw},
    ingest::receive_record_header,
    publish::stream::StreamRequestPayload,
    publish::{receive_stream_request, send_time_series_generator_replay_end},
};
use quinn::{
    Connection, Endpoint, RecvStream, SendStream, ServerConfig, crypto::rustls::QuicServerConfig,
};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
    SanType, string::Ia5String,
};
use review_protocol::request::Handler;
use review_protocol::types::{
    ConnField, CounterpartScope, GroupByUnit, HostNetworkGroup, Measure,
    RawEventKind as PolicyRawEventKind, TimeSeriesGenerationPolicy,
};
use rustls::{pki_types::CertificateDer, server::WebPkiClientVerifier};
use serial_test::serial;
use tempfile::TempDir;
use tokio::sync::Notify;
use tokio::time::{Instant, sleep, timeout};

use super::time_series::TimeSeries;
use super::*;
use crate::cancellation::{CancellationCoordinator, CancellationPhase};
use crate::client::{Certs, SharedTlsBytes, TlsBytes};
use crate::policy::{PolicyHandle, spawn_policy_actor};

const CERT_PATH: &str = "tests/cert.pem";
const KEY_PATH: &str = "tests/key.pem";
const CA_CERT_PATH: &str = "tests/ca_cert.pem";
const HOST: &str = "localhost";
const SECS_PER_MINUTE: u64 = 60;
const SECS_PER_DAY: u64 = 86_400;
const DEFAULT_POLICY_ID: u32 = 1;
const BASE_TS_NANOS: i64 = 1_700_000_000_000_000_000;
const DAY_NANOS: i64 = 86_400_000_000_000;
/// The start of the 1-day window of [`BASE_TS_NANOS`] for [`new_policy`].
const BASE_WINDOW_START_NANOS: i64 = 1_699_920_000_000_000_000;
// Functional waits allow for CI scheduling and disk latency. Tests of the
// production shutdown deadline keep their own explicit timing assertions.
const TEST_TIMEOUT: Duration = Duration::from_secs(15);
const RECONNECT_TEST_TIMEOUT: Duration =
    Duration::from_secs(SERVER_RETRY_INTERVAL + TEST_TIMEOUT.as_secs());

async fn join_test_task<T>(name: &str, mut task: tokio::task::JoinHandle<T>) -> T {
    if let Ok(result) = timeout(TEST_TIMEOUT, &mut task).await {
        result.unwrap_or_else(|error| panic!("{name} failed: {error}"))
    } else {
        task.abort();
        panic!("{name} did not finish within {TEST_TIMEOUT:?}");
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectionPath {
    Ingest,
    Publish,
}

type PeerCertEvent = (ConnectionPath, Vec<u8>);

/// Selects how the fake publish server emits inbound uni streams in
/// response to client stream requests. Tests use this to drive the
/// dispatcher down specific code paths (out-of-order arrival, unknown
/// id, deleted policy).
#[derive(Clone)]
enum PublishBehavior {
    /// Open one uni stream per request, immediately, in request order.
    Default,
    /// Collect `expected` requests, then open uni streams in REVERSE
    /// order. Verifies the dispatcher binds streams by id read off the
    /// wire, not by request order.
    ReverseOrder { expected: usize },
    /// For each request, first open a uni stream announcing `stale_id`
    /// (which the policy actor does not know about), then the real
    /// stream. Verifies the dispatcher silently drops unknown-id
    /// streams without breaking subsequent traffic.
    StaleIdFirst { stale_id: u32 },
    /// Collect `expected` requests, then notify `request_received` and
    /// wait on `release` before opening the inbound streams. Lets the
    /// test mutate policy state (e.g., delete) between request landing
    /// and stream arrival.
    HoldUntilSignal {
        expected: usize,
        request_received: Arc<Notify>,
        release: Arc<Notify>,
    },
    /// Records stream-open requests without opening response streams.
    RecordRequests {
        sender: async_channel::Sender<(
            Connection,
            RequestStreamRecord,
            RequestTimeSeriesGeneratorStream,
        )>,
    },
    /// Answers each request with a stream carrying these frames, without a
    /// delay, and keeps it open.
    Records(Arc<[GeneratorFrame]>),
}

/// A frame the fake publish server sends on a time series generator stream.
#[derive(Clone)]
enum GeneratorFrame {
    /// A raw event: its timestamp and its bincode-serialized record.
    Event(i64, Vec<u8>),
    /// The replay-end frame, carrying the `start` of the stream request.
    ReplayEnd(i64),
}

#[derive(Clone)]
enum IngestBehavior {
    Default,
    HoldAckStreamOpen {
        client_finished: Arc<Notify>,
        release: Arc<Notify>,
    },
    /// Reads the first stream of each connection only after this delay, so
    /// that a write on a later stream would be stored before it.
    DelayFirstStream(Duration),
    /// Stores the first frame received on any connection only `delay` after
    /// receiving it, and notifies `received` on its receipt, so that a frame
    /// written on a later connection would be stored before it.
    DelayFirstStore {
        delay: Duration,
        received: Arc<Notify>,
        pending: Arc<AtomicBool>,
    },
    /// Stores the first frame received on any connection only once `release`
    /// is notified, and notifies `received` on its receipt.
    HoldFirstStore {
        received: Arc<Notify>,
        release: Arc<Notify>,
        pending: Arc<AtomicBool>,
    },
}

struct FakeGigantoServer {
    server_config: ServerConfig,
    server_address: SocketAddr,
    ingest_notify: Option<async_channel::Sender<u32>>,
    series_notify: Option<async_channel::Sender<(i64, TimeSeries)>>,
    /// Reports the rows of each ingest frame together, in the order stored.
    frame_notify: Option<async_channel::Sender<Vec<(i64, TimeSeries)>>>,
    peer_cert_notify: Option<async_channel::Sender<PeerCertEvent>>,
    publish_timestamps: Vec<i64>,
    /// Keeps each default stream open after its events, as Giganto does,
    /// instead of finishing it.
    publish_hold_streams: bool,
    publish_repeat_delay: Duration,
    publish_behavior: PublishBehavior,
    ingest_behavior: IngestBehavior,
}

struct TestServerHandlers {
    ingest_shutdown: Arc<Notify>,
    publish_shutdown: Arc<Notify>,
    ingest_handle: tokio::task::JoinHandle<()>,
    publish_handle: tokio::task::JoinHandle<()>,
}

impl FakeGigantoServer {
    fn new_ingest() -> Self {
        let server_config = config_server();
        let server_address = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0);
        FakeGigantoServer {
            server_config,
            server_address,
            ingest_notify: None,
            series_notify: None,
            frame_notify: None,
            peer_cert_notify: None,
            publish_timestamps: Vec::new(),
            publish_hold_streams: false,
            publish_repeat_delay: Duration::from_millis(0),
            publish_behavior: PublishBehavior::Default,
            ingest_behavior: IngestBehavior::Default,
        }
    }

    fn new_ingest_with_config(server_config: ServerConfig) -> Self {
        let server_address = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0);
        FakeGigantoServer {
            server_config,
            server_address,
            ingest_notify: None,
            series_notify: None,
            frame_notify: None,
            peer_cert_notify: None,
            publish_timestamps: Vec::new(),
            publish_hold_streams: false,
            publish_repeat_delay: Duration::from_millis(0),
            publish_behavior: PublishBehavior::Default,
            ingest_behavior: IngestBehavior::Default,
        }
    }

    fn new_publish() -> Self {
        let server_config = config_server();
        let server_address = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0);
        FakeGigantoServer {
            server_config,
            server_address,
            ingest_notify: None,
            series_notify: None,
            frame_notify: None,
            peer_cert_notify: None,
            publish_timestamps: one_window_then_next(),
            publish_hold_streams: false,
            publish_repeat_delay: Duration::from_millis(200),
            publish_behavior: PublishBehavior::Default,
            ingest_behavior: IngestBehavior::Default,
        }
    }

    fn new_publish_with_config(server_config: ServerConfig) -> Self {
        let server_address = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0);
        FakeGigantoServer {
            server_config,
            server_address,
            ingest_notify: None,
            series_notify: None,
            frame_notify: None,
            peer_cert_notify: None,
            publish_timestamps: one_window_then_next(),
            publish_hold_streams: false,
            publish_repeat_delay: Duration::from_millis(200),
            publish_behavior: PublishBehavior::Default,
            ingest_behavior: IngestBehavior::Default,
        }
    }

    fn with_publish_timestamps(mut self, timestamps: Vec<i64>) -> Self {
        self.publish_timestamps = timestamps;
        self
    }

    fn with_held_streams(mut self) -> Self {
        self.publish_hold_streams = true;
        self
    }

    fn with_series_notify(mut self, notify: async_channel::Sender<(i64, TimeSeries)>) -> Self {
        self.series_notify = Some(notify);
        self
    }

    fn with_frame_notify(mut self, notify: async_channel::Sender<Vec<(i64, TimeSeries)>>) -> Self {
        self.frame_notify = Some(notify);
        self
    }

    fn with_notify(mut self, notify: async_channel::Sender<u32>) -> Self {
        self.ingest_notify = Some(notify);
        self
    }

    fn with_peer_cert_notify(mut self, notify: async_channel::Sender<PeerCertEvent>) -> Self {
        self.peer_cert_notify = Some(notify);
        self
    }

    fn with_publish_behavior(mut self, behavior: PublishBehavior) -> Self {
        self.publish_behavior = behavior;
        self
    }

    fn with_ingest_behavior(mut self, behavior: IngestBehavior) -> Self {
        self.ingest_behavior = behavior;
        self
    }

    fn start_ingest(self, shutdown: Arc<Notify>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let endpoint = Endpoint::server(self.server_config, self.server_address).expect("endpoint");
        let local_addr = endpoint.local_addr().expect("local_addr");
        let ingest_notify = self.ingest_notify.clone();
        let notifies = IngestNotify {
            series: self.series_notify.clone(),
            frames: self.frame_notify.clone(),
        };
        let peer_cert_notify = self.peer_cert_notify.clone();
        let behavior = self.ingest_behavior;
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(conn) = endpoint.accept() => {
                        let notify = ingest_notify.clone();
                        let notifies = notifies.clone();
                        let peer_cert_notify = peer_cert_notify.clone();
                        let behavior = behavior.clone();
                        tokio::spawn(async move {
                            if let Ok(connection) = conn.await {
                                handle_ingest_connection(
                                    connection,
                                    notify,
                                    notifies,
                                    peer_cert_notify,
                                    behavior,
                                )
                                .await;
                            }
                        });
                    }
                    () = shutdown.notified() => {
                        endpoint.close(0u32.into(), &[]);
                        break;
                    }
                }
            }
        });
        (local_addr, handle)
    }

    fn start_publish(self, shutdown: Arc<Notify>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let endpoint = Endpoint::server(self.server_config, self.server_address).expect("endpoint");
        let local_addr = endpoint.local_addr().expect("local_addr");
        let publish_timestamps: Arc<[i64]> = self.publish_timestamps.into();
        let publish_repeat_delay = self.publish_repeat_delay;
        let hold_streams = self.publish_hold_streams;
        let peer_cert_notify = self.peer_cert_notify.clone();
        let behavior = self.publish_behavior;
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(conn) = endpoint.accept() => {
                        let peer_cert_notify = peer_cert_notify.clone();
                        let behavior = behavior.clone();
                        let publish_timestamps = publish_timestamps.clone();
                        tokio::spawn(async move {
                            if let Ok(connection) = conn.await {
                                handle_publish_connection(
                                    connection,
                                    &publish_timestamps,
                                    publish_repeat_delay,
                                    hold_streams,
                                    peer_cert_notify,
                                    behavior,
                                )
                                .await;
                            }
                        });
                    }
                    () = shutdown.notified() => {
                        endpoint.close(0u32.into(), &[]);
                        break;
                    }
                }
            }
        });
        (local_addr, handle)
    }
}

/// Where the fake ingest server reports what it stores.
#[derive(Clone, Default)]
struct IngestNotify {
    /// Each stored row, with its timestamp.
    series: Option<async_channel::Sender<(i64, TimeSeries)>>,
    /// The rows of each stored frame together.
    frames: Option<async_channel::Sender<Vec<(i64, TimeSeries)>>>,
}

async fn handle_ingest_connection(
    connection: Connection,
    notify: Option<async_channel::Sender<u32>>,
    series_notify: IngestNotify,
    peer_cert_notify: Option<async_channel::Sender<PeerCertEvent>>,
    behavior: IngestBehavior,
) {
    notify_peer_cert(
        &connection,
        ConnectionPath::Ingest,
        peer_cert_notify.as_ref(),
    )
    .await;

    let version_req = format!("={REQUIRED_GIGANTO_VERSION}");
    if server_handshake(&connection, &version_req).await.is_err() {
        return;
    }

    let mut first_stream = true;
    while let Ok((send, recv)) = connection.accept_bi().await {
        let notify = notify.clone();
        let series_notify = series_notify.clone();
        let (delay, behavior) = match &behavior {
            IngestBehavior::DelayFirstStream(delay) => (
                if first_stream { *delay } else { Duration::ZERO },
                IngestBehavior::Default,
            ),
            behavior => (Duration::ZERO, behavior.clone()),
        };
        first_stream = false;
        tokio::spawn(async move {
            sleep(delay).await;
            handle_ingest_stream(send, recv, notify, series_notify, behavior).await;
        });
    }
}

async fn handle_publish_connection(
    connection: Connection,
    timestamps: &[i64],
    repeat_delay: Duration,
    hold_streams: bool,
    peer_cert_notify: Option<async_channel::Sender<PeerCertEvent>>,
    behavior: PublishBehavior,
) {
    notify_peer_cert(
        &connection,
        ConnectionPath::Publish,
        peer_cert_notify.as_ref(),
    )
    .await;

    let version_req = format!("={REQUIRED_GIGANTO_VERSION}");
    let Ok((_send, mut recv)) = server_handshake(&connection, &version_req).await else {
        return;
    };

    match behavior {
        PublishBehavior::Default => {
            handle_default_publish(
                &connection,
                &mut recv,
                timestamps,
                repeat_delay,
                hold_streams,
            )
            .await;
        }
        PublishBehavior::ReverseOrder { expected } => {
            handle_reverse_order_publish(
                &connection,
                &mut recv,
                expected,
                timestamps,
                repeat_delay,
            )
            .await;
        }
        PublishBehavior::StaleIdFirst { stale_id } => {
            handle_stale_id_publish(&connection, &mut recv, stale_id, timestamps, repeat_delay)
                .await;
        }
        PublishBehavior::HoldUntilSignal {
            expected,
            request_received,
            release,
        } => {
            handle_hold_until_signal_publish(
                &connection,
                &mut recv,
                expected,
                request_received,
                release,
                timestamps,
                repeat_delay,
            )
            .await;
        }
        PublishBehavior::RecordRequests { sender } => {
            while let Ok(payload) = receive_stream_request(&mut recv).await {
                if let StreamRequestPayload::TimeSeriesGenerator {
                    record_type,
                    request,
                } = payload
                    && sender
                        .send((connection.clone(), record_type, request))
                        .await
                        .is_err()
                {
                    return;
                }
            }
        }
        PublishBehavior::Records(records) => {
            let mut streams = Vec::new();
            while let Ok(payload) = receive_stream_request(&mut recv).await {
                let StreamRequestPayload::TimeSeriesGenerator { request, .. } = payload else {
                    continue;
                };
                let Ok(mut uni) = connection.open_uni().await else {
                    return;
                };
                let _ = send_raw(&mut uni, request.id.as_bytes()).await;
                for frame in records.iter() {
                    match frame {
                        GeneratorFrame::Event(timestamp, record) => {
                            let _ = send_bytes(&mut uni, &timestamp.to_le_bytes()).await;
                            let _ = send_raw(&mut uni, record).await;
                        }
                        GeneratorFrame::ReplayEnd(start) => {
                            let _ = send_time_series_generator_replay_end(&mut uni, *start).await;
                        }
                    }
                }
                streams.push(uni);
            }
        }
    }
    // Dropping the connection would discard stream data still in flight, such
    // as the event that closes a window. Close only once the client does.
    connection.closed().await;
}

/// Opens a generator stream for `policy_id_bytes` and sends an event of
/// `record_bytes` at each of `timestamps`, spaced by `repeat_delay`, then the
/// replay-end frame, as Giganto does for a replay of stored events.
async fn open_and_emit_stream(
    connection: &Connection,
    policy_id_bytes: &[u8],
    record_bytes: &[u8],
    timestamps: &[i64],
    repeat_delay: Duration,
    hold_open: bool,
) {
    let Ok(mut uni) = connection.open_uni().await else {
        return;
    };
    let _ = send_raw(&mut uni, policy_id_bytes).await;
    for (idx, ts) in timestamps.iter().enumerate() {
        let _ = send_bytes(&mut uni, &ts.to_le_bytes()).await;
        let _ = send_raw(&mut uni, record_bytes).await;
        if idx + 1 < timestamps.len() {
            sleep(repeat_delay).await;
        }
    }
    // The frame carries the request's start, which crusher does not read.
    let _ = send_time_series_generator_replay_end(&mut uni, 0).await;
    if hold_open {
        connection.closed().await;
    }
    let _ = uni.finish();
}

async fn handle_default_publish(
    connection: &Connection,
    recv: &mut RecvStream,
    timestamps: &[i64],
    repeat_delay: Duration,
    hold_streams: bool,
) {
    loop {
        let Ok(payload) = receive_stream_request(recv).await else {
            break;
        };
        let (policy_id, record_bytes) = match payload {
            StreamRequestPayload::TimeSeriesGenerator { request, .. } => {
                (request.id, bincode::serialize(&gen_conn()).unwrap())
            }
            _ => continue,
        };
        open_and_emit_stream(
            connection,
            policy_id.as_bytes(),
            &record_bytes,
            timestamps,
            repeat_delay,
            hold_streams,
        )
        .await;
    }
}

async fn handle_reverse_order_publish(
    connection: &Connection,
    recv: &mut RecvStream,
    expected: usize,
    timestamps: &[i64],
    repeat_delay: Duration,
) {
    let mut requests = Vec::with_capacity(expected);
    for _ in 0..expected {
        let Ok(payload) = receive_stream_request(recv).await else {
            return;
        };
        if let StreamRequestPayload::TimeSeriesGenerator { request, .. } = payload {
            requests.push((request.id, bincode::serialize(&gen_conn()).unwrap()));
        }
    }
    requests.reverse();
    for (policy_id, record_bytes) in requests {
        open_and_emit_stream(
            connection,
            policy_id.as_bytes(),
            &record_bytes,
            timestamps,
            repeat_delay,
            false,
        )
        .await;
    }
}

async fn handle_stale_id_publish(
    connection: &Connection,
    recv: &mut RecvStream,
    stale_id: u32,
    timestamps: &[i64],
    repeat_delay: Duration,
) {
    loop {
        let Ok(payload) = receive_stream_request(recv).await else {
            break;
        };
        let (policy_id, record_bytes) = match payload {
            StreamRequestPayload::TimeSeriesGenerator { request, .. } => {
                (request.id, bincode::serialize(&gen_conn()).unwrap())
            }
            _ => continue,
        };
        let stale = stale_id.to_string();
        // First open a uni stream announcing the stale id; the
        // dispatcher must drop it without breaking the connection.
        open_and_emit_stream(
            connection,
            stale.as_bytes(),
            &record_bytes,
            &timestamps[..1],
            repeat_delay,
            false,
        )
        .await;
        // Then the real stream — must be processed normally.
        open_and_emit_stream(
            connection,
            policy_id.as_bytes(),
            &record_bytes,
            timestamps,
            repeat_delay,
            false,
        )
        .await;
    }
}

async fn handle_hold_until_signal_publish(
    connection: &Connection,
    recv: &mut RecvStream,
    expected: usize,
    request_received: Arc<Notify>,
    release: Arc<Notify>,
    timestamps: &[i64],
    repeat_delay: Duration,
) {
    let mut requests = Vec::with_capacity(expected);
    for _ in 0..expected {
        let Ok(payload) = receive_stream_request(recv).await else {
            return;
        };
        if let StreamRequestPayload::TimeSeriesGenerator { request, .. } = payload {
            requests.push((request.id, bincode::serialize(&gen_conn()).unwrap()));
        }
    }
    request_received.notify_one();
    release.notified().await;
    for (policy_id, record_bytes) in requests {
        open_and_emit_stream(
            connection,
            policy_id.as_bytes(),
            &record_bytes,
            timestamps,
            repeat_delay,
            false,
        )
        .await;
    }
}

async fn handle_ingest_stream(
    mut send: SendStream,
    mut recv: RecvStream,
    notify: Option<async_channel::Sender<u32>>,
    series_notify: IngestNotify,
    behavior: IngestBehavior,
) {
    let mut header_buf = [0_u8; 4];
    if receive_record_header(&mut recv, &mut header_buf)
        .await
        .is_err()
    {
        return;
    }

    // A bi-di stream carries one header followed by any number of batches
    // until the client closes it. Looping here lets tests observe multiple
    // ACKs on the same stream while a single sender task remains active.
    loop {
        let mut buf = Vec::new();
        if recv_raw(&mut recv, &mut buf).await.is_err() {
            if let IngestBehavior::HoldAckStreamOpen {
                client_finished,
                release,
            } = behavior
            {
                client_finished.notify_one();
                release.notified().await;
            }
            return;
        }

        let Ok(batch) = bincode::deserialize::<Vec<(i64, Vec<u8>)>>(&buf) else {
            continue;
        };
        if let IngestBehavior::DelayFirstStore {
            delay,
            received,
            pending,
        } = &behavior
            && pending.swap(false, Ordering::SeqCst)
        {
            received.notify_one();
            sleep(*delay).await;
        }
        if let IngestBehavior::HoldFirstStore {
            received,
            release,
            pending,
        } = &behavior
            && pending.swap(false, Ordering::SeqCst)
        {
            received.notify_one();
            release.notified().await;
        }
        // The policy id is the part of the series id before `/`.
        let policy_id = batch
            .first()
            .and_then(|(_, payload)| bincode::deserialize::<TimeSeries>(payload).ok())
            .and_then(|series| {
                let id = series
                    .time_series_id
                    .split_once('/')
                    .map_or(series.time_series_id.as_str(), |(id, _)| id);
                id.parse::<u32>().ok()
            })
            .unwrap_or(0);
        if let Some(frames) = &series_notify.frames {
            let rows = batch
                .iter()
                .filter_map(|(timestamp, payload)| {
                    Some((
                        *timestamp,
                        bincode::deserialize::<TimeSeries>(payload).ok()?,
                    ))
                })
                .collect();
            let _ = frames.send(rows).await;
        }
        for (timestamp, payload) in batch {
            if let Some(series_notify) = &series_notify.series
                && let Ok(series) = bincode::deserialize::<TimeSeries>(&payload)
            {
                let _ = series_notify.send((timestamp, series)).await;
            }
            if send_bytes(&mut send, &timestamp.to_be_bytes())
                .await
                .is_err()
            {
                return;
            }
            if let Some(notify) = &notify {
                let _ = notify.send(policy_id).await;
            }
        }
    }
}

async fn notify_peer_cert(
    connection: &Connection,
    path: ConnectionPath,
    notify: Option<&async_channel::Sender<PeerCertEvent>>,
) {
    let Some(notify) = notify else {
        return;
    };
    let Some(peer_identity) = connection.peer_identity() else {
        return;
    };
    let Ok(peer_certs) = peer_identity.downcast::<Vec<CertificateDer<'static>>>() else {
        return;
    };
    let Some(leaf_cert) = peer_certs.first() else {
        return;
    };
    let _ = notify.send((path, leaf_cert.as_ref().to_vec())).await;
}

fn start_servers() -> (
    async_channel::Receiver<u32>,
    TestServerHandlers,
    SocketAddr,
    SocketAddr,
) {
    let (ingest_ack_send, ingest_ack_recv) = async_channel::bounded::<u32>(10);
    let ingest_server = FakeGigantoServer::new_ingest().with_notify(ingest_ack_send);
    let publish_server = FakeGigantoServer::new_publish();
    let ingest_shutdown = Arc::new(Notify::new());
    let publish_shutdown = Arc::new(Notify::new());
    let (ingest_addr, ingest_handle) = ingest_server.start_ingest(ingest_shutdown.clone());
    let (publish_addr, publish_handle) = publish_server.start_publish(publish_shutdown.clone());
    (
        ingest_ack_recv,
        TestServerHandlers {
            ingest_shutdown,
            publish_shutdown,
            ingest_handle,
            publish_handle,
        },
        ingest_addr,
        publish_addr,
    )
}

fn start_servers_with_config(
    ingest_server_config: ServerConfig,
    publish_server_config: ServerConfig,
    peer_cert_notify: async_channel::Sender<PeerCertEvent>,
) -> (
    async_channel::Receiver<u32>,
    TestServerHandlers,
    SocketAddr,
    SocketAddr,
) {
    let (ingest_ack_send, ingest_ack_recv) = async_channel::bounded::<u32>(10);
    let ingest_server = FakeGigantoServer::new_ingest_with_config(ingest_server_config)
        .with_notify(ingest_ack_send)
        .with_peer_cert_notify(peer_cert_notify.clone());
    let publish_server = FakeGigantoServer::new_publish_with_config(publish_server_config)
        .with_peer_cert_notify(peer_cert_notify);
    let ingest_shutdown = Arc::new(Notify::new());
    let publish_shutdown = Arc::new(Notify::new());
    let (ingest_addr, ingest_handle) = ingest_server.start_ingest(ingest_shutdown.clone());
    let (publish_addr, publish_handle) = publish_server.start_publish(publish_shutdown.clone());
    (
        ingest_ack_recv,
        TestServerHandlers {
            ingest_shutdown,
            publish_shutdown,
            ingest_handle,
            publish_handle,
        },
        ingest_addr,
        publish_addr,
    )
}

struct TestHarness {
    coordinator: CancellationCoordinator,
    request_client: crate::request::Client,
    policy_handle: PolicyHandle,
    client_handle: tokio::task::JoinHandle<()>,
    server_handles: TestServerHandlers,
    ingest_ack_recv: async_channel::Receiver<u32>,
    last_time_series_path: PathBuf,
    temp_dir: TempDir,
}

impl TestHarness {
    async fn new(policies: &[TimeSeriesGenerationPolicy]) -> Self {
        let (ingest_ack_recv, server_handles, ingest_addr, publish_addr) = start_servers();
        let certs = cert_key();
        let coordinator = CancellationCoordinator::new();
        let (request_client, actor_task, last_time_series_path, temp_dir, policy_handle) =
            setup_request_client(None, &coordinator).await;

        let mut rc = request_client;
        rc.time_series_generation_policy_list(policies)
            .await
            .unwrap();

        let client_handle = spawn_subscribe_client(
            &certs,
            actor_task,
            ingest_addr,
            publish_addr,
            policy_handle.clone(),
            coordinator.clone(),
        );

        Self {
            coordinator,
            request_client: rc,
            policy_handle,
            client_handle,
            server_handles,
            ingest_ack_recv,
            last_time_series_path,
            temp_dir,
        }
    }

    async fn wait_for_ack(&self) -> u32 {
        timeout(TEST_TIMEOUT, self.ingest_ack_recv.recv())
            .await
            .expect("Ingest ACK should arrive before the test deadline")
            .expect("Ingest ACK channel should remain open")
    }

    async fn wait_for_timestamp(&self, ids: &[u32]) -> HashMap<String, i64> {
        timeout(
            TEST_TIMEOUT,
            wait_for_policy_ids(&self.last_time_series_path, ids, true),
        )
        .await
        .expect("Expected policy IDs to appear in time_data.json")
    }

    async fn wait_for_timestamp_removed(&self, ids: &[u32]) -> HashMap<String, i64> {
        timeout(
            TEST_TIMEOUT,
            wait_for_policy_ids(&self.last_time_series_path, ids, false),
        )
        .await
        .expect("Expected policy IDs to be removed from time_data.json")
    }

    async fn cleanup(self) {
        drop(self.request_client);
        drop(self.policy_handle);
        cleanup_test_resources(self.coordinator, self.client_handle, self.server_handles).await;
    }
}

async fn setup_request_client(
    existing_path: Option<&Path>,
    coordinator: &CancellationCoordinator,
) -> (
    crate::request::Client,
    tokio::task::JoinHandle<Result<()>>,
    PathBuf,
    TempDir,
    PolicyHandle,
) {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let last_time_series_path =
        existing_path.map_or_else(|| temp_dir.path().join("time_data.json"), Path::to_path_buf);
    let tls_bytes = crate::client::SharedTlsBytes::new(crate::client::TlsBytes::new(
        fs::read(CERT_PATH).unwrap(),
        fs::read(KEY_PATH).unwrap(),
        vec![fs::read(CA_CERT_PATH).unwrap()],
    ));
    let (policy_handle, actor_task) =
        spawn_policy_actor(last_time_series_path.clone(), coordinator)
            .await
            .unwrap();
    let mut request_client = crate::request::Client::new(
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
        HOST.to_string(),
        tls_bytes,
        Arc::new(Notify::new()),
    );
    request_client.set_policy_handle(policy_handle.clone());
    (
        request_client,
        actor_task,
        last_time_series_path,
        temp_dir,
        policy_handle,
    )
}

fn new_policy(id: u32) -> TimeSeriesGenerationPolicy {
    TimeSeriesGenerationPolicy {
        id,
        raw_event_kind: PolicyRawEventKind::Conn,
        measure: Measure::Count,
        group_by: None,
        group_by_unit: GroupByUnit::Ip,
        counterpart_scope: CounterpartScope::Any,
        slot_size: Duration::from_secs(15 * SECS_PER_MINUTE),
        window_size: Duration::from_secs(SECS_PER_DAY),
        utc_offset: 0,
        src_ip: None,
        dst_ip: None,
        sensors: vec!["cluml".to_string()],
        time_series_type: None,
        internal_networks: HostNetworkGroup::default(),
    }
}

/// Events of the window of [`BASE_TS_NANOS`], then one a period later for
/// [`new_policy`], which closes that window so that it is written.
fn one_window_then_next() -> Vec<i64> {
    vec![
        BASE_TS_NANOS,
        BASE_TS_NANOS + 1,
        BASE_TS_NANOS + 2,
        BASE_TS_NANOS + DAY_NANOS,
    ]
}

fn spawn_subscribe_client(
    certs: &Certs,
    actor_task: tokio::task::JoinHandle<Result<()>>,
    ingest_addr: SocketAddr,
    publish_addr: SocketAddr,
    policy_handle: PolicyHandle,
    coordinator: CancellationCoordinator,
) -> tokio::task::JoinHandle<()> {
    spawn_subscribe_client_with_timer(
        certs,
        actor_task,
        ingest_addr,
        publish_addr,
        policy_handle,
        coordinator,
        CloseTimer::default(),
    )
}

fn spawn_subscribe_client_with_timer(
    certs: &Certs,
    actor_task: tokio::task::JoinHandle<Result<()>>,
    ingest_addr: SocketAddr,
    publish_addr: SocketAddr,
    policy_handle: PolicyHandle,
    coordinator: CancellationCoordinator,
    close_timer: CloseTimer,
) -> tokio::task::JoinHandle<()> {
    let client = Client::new(ingest_addr, publish_addr, HOST.to_string(), certs)
        .expect("test client should build an endpoint")
        .with_close_timer(close_timer);

    tokio::spawn(async move {
        client
            .run(policy_handle, actor_task, coordinator)
            .await
            .expect("subscribe client completes successfully");
    })
}

async fn wait_for_policy_ids(
    last_time_series_path: &Path,
    ids: &[u32],
    should_exist: bool,
) -> HashMap<String, i64> {
    loop {
        if last_time_series_path.exists() {
            let map = read_time_data_map(last_time_series_path);
            if ids
                .iter()
                .all(|id| map.contains_key(&id.to_string()) == should_exist)
            {
                return map;
            }
        }
        sleep(Duration::from_millis(50)).await;
    }
}

async fn cleanup_test_resources(
    coordinator: CancellationCoordinator,
    client_handle: tokio::task::JoinHandle<()>,
    server_handles: TestServerHandlers,
) {
    coordinator.request_cancellation("test cleanup");
    server_handles.ingest_shutdown.notify_one();
    server_handles.publish_shutdown.notify_one();

    tokio::join!(
        join_test_task("subscribe client", client_handle),
        join_test_task("Giganto Ingest server", server_handles.ingest_handle),
        join_test_task("Giganto Publish server", server_handles.publish_handle)
    );
    INGEST_CHANNEL.write().await.clear();
}

async fn cleanup_server_resources(server_handles: TestServerHandlers) {
    server_handles.ingest_shutdown.notify_one();
    server_handles.publish_shutdown.notify_one();

    tokio::join!(
        join_test_task("Giganto Ingest server", server_handles.ingest_handle),
        join_test_task("Giganto Publish server", server_handles.publish_handle)
    );
}

/// Returns the `timestamp` of each policy in the checkpoint file that has
/// one.
fn read_time_data_map(last_time_series_path: &Path) -> HashMap<String, i64> {
    read_checkpoints(last_time_series_path)
        .into_iter()
        .filter_map(|(id, (timestamp, _))| Some((id, timestamp?)))
        .collect()
}

/// Returns the `timestamp` and the `generation` of each policy in the
/// checkpoint file.
fn read_checkpoints(last_time_series_path: &Path) -> HashMap<String, (Option<i64>, Option<u64>)> {
    let content = fs::read_to_string(last_time_series_path).unwrap_or_default();
    if content.trim().is_empty() {
        return HashMap::new();
    }
    let file: HashMap<String, serde_json::Map<String, serde_json::Value>> =
        serde_json::from_str(&content).expect("Failed to parse time_data.json");
    file.into_iter()
        .map(|(id, fields)| {
            let timestamp = fields
                .get("timestamp")
                .map(|value| value.as_i64().expect("the timestamp is an i64"));
            let generation = fields
                .get("generation")
                .map(|value| value.as_u64().expect("the generation is a u64"));
            (id, (timestamp, generation))
        })
        .collect()
}

fn config_server() -> ServerConfig {
    let certs = cert_key();

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let client_auth = WebPkiClientVerifier::builder_with_provider(
        Arc::new(certs.ca_certs.clone()),
        Arc::clone(&provider),
    )
    .build()
    .expect("Failed to build client certificate verifier");

    let server_crypto = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("aws-lc-rs supports the default protocol versions")
        .with_client_cert_verifier(client_auth)
        .with_single_cert(certs.certs.clone(), certs.key.clone_key())
        .unwrap();

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(server_crypto).expect("Failed to generate TLS server config"),
    ));

    Arc::get_mut(&mut server_config.transport)
        .unwrap()
        .max_concurrent_uni_streams(0_u8.into());

    server_config
}

#[derive(Clone)]
struct ReloadPolicyManager {
    calls: Arc<AtomicUsize>,
    first_policy: TimeSeriesGenerationPolicy,
    sync_events: async_channel::Sender<usize>,
}

#[async_trait::async_trait]
impl review_protocol::server::Handler for ReloadPolicyManager {
    async fn get_time_series_generation_policy_list(
        &self,
        _peer: &str,
    ) -> Result<Vec<TimeSeriesGenerationPolicy>, String> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        let _ = self.sync_events.send(call).await;
        if call == 1 {
            Ok(vec![self.first_policy.clone()])
        } else {
            Ok(Vec::new())
        }
    }
}

fn start_reload_policy_manager(
    policy: TimeSeriesGenerationPolicy,
) -> (
    SocketAddr,
    async_channel::Receiver<usize>,
    Arc<Notify>,
    tokio::task::JoinHandle<()>,
) {
    let endpoint = Endpoint::server(
        config_server(),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
    )
    .expect("manager endpoint");
    let address = endpoint.local_addr().expect("manager address");
    let shutdown = Arc::new(Notify::new());
    let shutdown_for_task = shutdown.clone();
    let (sync_send, sync_recv) = async_channel::unbounded();
    let handler = ReloadPolicyManager {
        calls: Arc::new(AtomicUsize::new(0)),
        first_policy: policy,
        sync_events: sync_send,
    };
    let server_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                connecting = endpoint.accept() => {
                    let Some(connecting) = connecting else {
                        break;
                    };
                    let mut handler = handler.clone();
                    tokio::spawn(async move {
                        let Ok(connection) = connecting.await else {
                            return;
                        };
                        let address = connection.remote_address();
                        if review_protocol::server::handshake(
                            &connection,
                            address,
                            ">=0",
                            crate::request::REQUIRED_MANAGER_VERSION,
                        )
                        .await
                        .is_err()
                        {
                            return;
                        }
                        while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                            let _ = review_protocol::server::handle(
                                &mut handler,
                                &mut send,
                                &mut recv,
                                "test",
                            )
                            .await;
                        }
                    });
                }
                () = shutdown_for_task.notified() => {
                    endpoint.close(0_u32.into(), &[]);
                    break;
                }
            }
        }
    });
    (address, sync_recv, shutdown, server_handle)
}

fn start_stalled_giganto_endpoint() -> (SocketAddr, Arc<Notify>, tokio::task::JoinHandle<()>) {
    let endpoint = Endpoint::server(
        config_server(),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
    )
    .expect("stalled Giganto endpoint");
    let address = endpoint.local_addr().expect("stalled Giganto address");
    let shutdown = Arc::new(Notify::new());
    let shutdown_for_task = shutdown.clone();
    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                connecting = endpoint.accept() => {
                    let Some(connecting) = connecting else {
                        break;
                    };
                    tokio::spawn(async move {
                        if let Ok(connection) = connecting.await {
                            connection.closed().await;
                        }
                    });
                }
                () = shutdown_for_task.notified() => {
                    endpoint.close(0_u32.into(), &[]);
                    break;
                }
            }
        }
    });
    (address, shutdown, handle)
}

fn write_run_config(
    path: &Path,
    timestamp_path: &Path,
    ingest_addr: SocketAddr,
    publish_addr: SocketAddr,
) {
    fs::write(
        path,
        format!(
            r#"
giganto_name = "{HOST}"
giganto_ingest_srv_addr = "{ingest_addr}"
giganto_publish_srv_addr = "{publish_addr}"
last_timestamp_data = "{}"
"#,
            timestamp_path.display()
        ),
    )
    .expect("write run config");
}

struct RotatedTlsMaterial {
    client_cert_pem: Vec<u8>,
    client_key_pem: Vec<u8>,
    ca_cert_pem: Vec<u8>,
    server_config: ServerConfig,
    client_leaf_der: Vec<u8>,
}

fn generate_params(is_ca: bool, cn: &str, sans: &[&str]) -> CertificateParams {
    let mut params = CertificateParams::default();
    if is_ca {
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    } else {
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
    }
    params
        .distinguished_name
        .push(DnType::CommonName, cn.to_string());
    params.subject_alt_names = sans
        .iter()
        .map(|san| {
            if let Ok(ip) = san.parse::<IpAddr>() {
                SanType::IpAddress(ip)
            } else {
                let dns =
                    Ia5String::try_from(*san).expect("DNS name must be valid ASCII (Ia5String)");
                SanType::DnsName(dns)
            }
        })
        .collect();

    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(30);

    params
}

fn generate_ca(cn: &str) -> (Certificate, KeyPair) {
    let key_pair = KeyPair::generate().expect("generate CA key pair");
    let cert = generate_params(true, cn, &[])
        .self_signed(&key_pair)
        .expect("generate self-signed CA certificate");
    (cert, key_pair)
}

fn generate_leaf(
    cn: &str,
    sans: &[&str],
    issuer_cert: &Certificate,
    issuer_key: &KeyPair,
) -> (Certificate, KeyPair) {
    let key_pair = KeyPair::generate().expect("generate leaf key pair");
    let issuer = rcgen::Issuer::from_ca_cert_pem(&issuer_cert.pem(), issuer_key)
        .expect("create certificate issuer");
    let cert = generate_params(false, cn, sans)
        .signed_by(&key_pair, &issuer)
        .expect("sign leaf certificate");
    (cert, key_pair)
}

fn server_config_from_material(
    server_cert_pem: &[u8],
    server_key_pem: &[u8],
    client_ca_pem: &[u8],
) -> ServerConfig {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let client_auth = WebPkiClientVerifier::builder_with_provider(
        Arc::new(Certs::to_ca_certs(&[client_ca_pem]).expect("parse client CA")),
        Arc::clone(&provider),
    )
    .build()
    .expect("build client certificate verifier");

    let server_crypto = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("aws-lc-rs supports the default protocol versions")
        .with_client_cert_verifier(client_auth)
        .with_single_cert(
            Certs::to_cert_chain(server_cert_pem).expect("parse server cert chain"),
            Certs::to_private_key(server_key_pem).expect("parse server private key"),
        )
        .expect("build server crypto");

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(server_crypto).expect("generate TLS server config"),
    ));

    Arc::get_mut(&mut server_config.transport)
        .expect("server transport config")
        .max_concurrent_uni_streams(0_u8.into());

    server_config
}

fn generate_rotated_tls_material() -> RotatedTlsMaterial {
    let (ca_cert, ca_key) = generate_ca("crusher-rotated-ca");
    let (server_cert, server_key) = generate_leaf(HOST, &[HOST], &ca_cert, &ca_key);
    let (client_cert, client_key) = generate_leaf("crusher-rotated-client", &[], &ca_cert, &ca_key);

    let client_cert_pem = client_cert.pem().into_bytes();
    let client_key_pem = client_key.serialize_pem().into_bytes();
    let ca_cert_pem = ca_cert.pem().into_bytes();
    let server_cert_pem = server_cert.pem().into_bytes();
    let server_key_pem = server_key.serialize_pem().into_bytes();

    let client_certs = Certs::try_new(&client_cert_pem, &client_key_pem, &[ca_cert_pem.as_slice()])
        .expect("parse rotated client certs");
    let client_leaf_der = client_certs
        .certs
        .first()
        .expect("rotated client leaf")
        .as_ref()
        .to_vec();
    let server_config =
        server_config_from_material(&server_cert_pem, &server_key_pem, &ca_cert_pem);

    RotatedTlsMaterial {
        client_cert_pem,
        client_key_pem,
        ca_cert_pem,
        server_config,
        client_leaf_der,
    }
}

async fn wait_for_peer_cert_paths(
    peer_cert_recv: &async_channel::Receiver<PeerCertEvent>,
    expected_leaf_der: &[u8],
) {
    let mut saw_ingest = false;
    let mut saw_publish = false;
    for _ in 0..2 {
        let (path, cert_der) = timeout(Duration::from_secs(5), peer_cert_recv.recv())
            .await
            .expect("peer certificate observation should arrive")
            .expect("peer certificate channel should remain open");
        assert_eq!(
            cert_der, expected_leaf_der,
            "unexpected client certificate for {path:?}"
        );
        match path {
            ConnectionPath::Ingest => saw_ingest = true,
            ConnectionPath::Publish => saw_publish = true,
        }
    }
    assert!(
        saw_ingest,
        "expected an ingest connection using the observed client certificate"
    );
    assert!(
        saw_publish,
        "expected a publish connection using the observed client certificate"
    );
}

fn cert_key() -> Certs {
    let cert_pem = fs::read(CERT_PATH).unwrap();
    let cert = Certs::to_cert_chain(&cert_pem).unwrap();
    let key_pem = fs::read(KEY_PATH).unwrap();
    let key = Certs::to_private_key(&key_pem).unwrap();
    let ca_certs_pem = [fs::read(CA_CERT_PATH).unwrap()];
    let ca_certs =
        Certs::to_ca_certs(&ca_certs_pem.iter().map(Vec::as_slice).collect::<Vec<_>>()).unwrap();

    Certs {
        certs: cert.clone(),
        key: key.clone_key(),
        ca_certs: ca_certs.clone(),
    }
}

fn gen_conn() -> Conn {
    Conn {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_port: 80,
        proto: 6,
        service: String::new(),
        conn_state: "OK".to_string(),
        start_time: 500,
        duration: 12_345,
        orig_bytes: 77,
        resp_bytes: 295,
        orig_pkts: 397,
        resp_pkts: 511,
        orig_l2_bytes: 51235,
        resp_l2_bytes: 48203,
    }
}

#[serial]
#[tokio::test]
async fn time_series_generation_policy_flow_with_fake_giganto_server() {
    let policy = new_policy(DEFAULT_POLICY_ID);
    let harness = TestHarness::new(std::slice::from_ref(&policy)).await;

    assert!(harness.policy_handle.get_policy(policy.id).await.is_some());

    let id = harness.wait_for_ack().await;
    assert_eq!(id, policy.id);

    let map = harness.wait_for_timestamp(&[policy.id]).await;
    assert!(harness.last_time_series_path.exists());
    let expected: HashMap<String, i64> = [(policy.id.to_string(), BASE_WINDOW_START_NANOS)]
        .into_iter()
        .collect();
    assert_eq!(map, expected);

    harness.cleanup().await;
}

/// Test: Validates notify flow - when a policy is added, the client sends a stream
/// request and receives data from the server. When the policy is deleted, the stream
/// should be stopped and timestamp cleaned up.
#[serial]
#[tokio::test]
async fn time_series_generation_policy_notify_flow_with_delete() {
    let policy = new_policy(DEFAULT_POLICY_ID);
    let mut harness = TestHarness::new(std::slice::from_ref(&policy)).await;

    assert!(harness.policy_handle.get_policy(policy.id).await.is_some());

    let id = harness.wait_for_ack().await;
    assert_eq!(id, policy.id);

    let map = harness.wait_for_timestamp(&[policy.id]).await;
    assert!(harness.last_time_series_path.exists());
    let expected: HashMap<String, i64> = [(policy.id.to_string(), BASE_WINDOW_START_NANOS)]
        .into_iter()
        .collect();
    assert_eq!(map, expected);

    harness
        .request_client
        .delete_time_series_generation_policy(&[policy.id])
        .await
        .unwrap();

    let map = harness.wait_for_timestamp_removed(&[policy.id]).await;
    assert!(harness.last_time_series_path.exists());
    assert_eq!(map, HashMap::new());

    harness.cleanup().await;
}

/// Test: Adding multiple policies should create multiple concurrent streams.
#[serial]
#[tokio::test]
async fn time_series_generation_policy_multiple_streams() {
    let policy_a = new_policy(1);
    let policy_b = new_policy(2);
    let harness = TestHarness::new(&[policy_a.clone(), policy_b.clone()]).await;

    assert!(
        harness
            .policy_handle
            .get_policy(policy_a.id)
            .await
            .is_some()
    );
    assert!(
        harness
            .policy_handle
            .get_policy(policy_b.id)
            .await
            .is_some()
    );

    let mut expected_ids = vec![policy_a.id, policy_b.id];
    for _ in 0..2 {
        let id = harness.wait_for_ack().await;
        expected_ids.retain(|expected| *expected != id);
    }
    assert!(
        expected_ids.is_empty(),
        "Not all policy IDs produced streams: {expected_ids:?}"
    );

    let map = harness
        .wait_for_timestamp(&[policy_a.id, policy_b.id])
        .await;
    assert!(harness.last_time_series_path.exists());
    let expected: HashMap<String, i64> = [
        (policy_a.id.to_string(), BASE_WINDOW_START_NANOS),
        (policy_b.id.to_string(), BASE_WINDOW_START_NANOS),
    ]
    .into_iter()
    .collect();
    assert_eq!(map, expected);

    harness.cleanup().await;
}

/// Test: After cancellation, all tracked tasks must drain within the
/// timeout and no tasks remain alive.
#[serial]
#[tokio::test]
async fn cancellation_drains_all_tasks() {
    let policy = new_policy(DEFAULT_POLICY_ID);
    let harness = TestHarness::new(std::slice::from_ref(&policy)).await;

    let _ = harness.wait_for_ack().await;
    let _ = harness.wait_for_timestamp(&[policy.id]).await;

    harness.coordinator.request_cancellation("drain test");
    harness.server_handles.ingest_shutdown.notify_one();
    harness.server_handles.publish_shutdown.notify_one();

    drop(harness.request_client);
    drop(harness.policy_handle);
    let drained = harness
        .coordinator
        .wait_for_drain(Duration::from_secs(10))
        .await;
    assert!(drained, "Drain should complete within timeout");
    assert_eq!(harness.coordinator.phase(), CancellationPhase::Completed);
    assert_eq!(harness.coordinator.tracker().active_count(), 0);

    let _ = tokio::join!(
        harness.client_handle,
        harness.server_handles.ingest_handle,
        harness.server_handles.publish_handle,
    );
    INGEST_CHANNEL.write().await.clear();
}

/// Test: Timestamp file is flushed and consistent after cancellation.
#[serial]
#[tokio::test]
async fn cancellation_flushes_timestamps() {
    let policy = new_policy(DEFAULT_POLICY_ID);
    let harness = TestHarness::new(std::slice::from_ref(&policy)).await;

    let _ = harness.wait_for_ack().await;
    let map_before = harness.wait_for_timestamp(&[policy.id]).await;

    harness.coordinator.request_cancellation("flush test");
    harness.server_handles.ingest_shutdown.notify_one();
    harness.server_handles.publish_shutdown.notify_one();

    drop(harness.request_client);
    drop(harness.policy_handle);
    let drained = harness
        .coordinator
        .wait_for_drain(Duration::from_secs(10))
        .await;
    assert!(drained, "Drain should complete");

    let _ = tokio::join!(
        harness.client_handle,
        harness.server_handles.ingest_handle,
        harness.server_handles.publish_handle,
    );
    INGEST_CHANNEL.write().await.clear();

    assert!(
        harness.last_time_series_path.exists(),
        "Timestamp file must survive cancellation"
    );
    let map_after = read_time_data_map(&harness.last_time_series_path);
    for (k, v) in &map_before {
        assert_eq!(
            map_after.get(k),
            Some(v),
            "Timestamp for policy {k} must be preserved after cancellation"
        );
    }
}

/// Test: Shutdown near ACK delivery must preserve persisted timestamp
/// state.
///
/// The publish server sends 3 ACKs with 200ms gaps. We cancel after the
/// first ACK notification and then verify the timestamp on disk is not
/// older than the pre-cancellation value. This checks that cancellation
/// does not regress persisted timestamp state.
#[serial]
#[tokio::test]
async fn cancellation_drain_captures_inflight_acks() {
    let policy = new_policy(DEFAULT_POLICY_ID);
    let harness = TestHarness::new(std::slice::from_ref(&policy)).await;

    let _ = harness.wait_for_ack().await;
    let _ = harness.wait_for_timestamp(&[policy.id]).await;
    let ts_before = read_time_data_map(&harness.last_time_series_path)
        .get(&policy.id.to_string())
        .copied()
        .expect("timestamp must exist for policy");

    harness
        .coordinator
        .request_cancellation("inflight-ack drain test");
    harness.server_handles.ingest_shutdown.notify_one();
    harness.server_handles.publish_shutdown.notify_one();

    drop(harness.request_client);
    drop(harness.policy_handle);
    let drained = harness
        .coordinator
        .wait_for_drain(Duration::from_secs(10))
        .await;
    assert!(drained, "Drain should complete within timeout");

    let _ = tokio::join!(
        harness.client_handle,
        harness.server_handles.ingest_handle,
        harness.server_handles.publish_handle,
    );
    INGEST_CHANNEL.write().await.clear();

    let ts_after = read_time_data_map(&harness.last_time_series_path)
        .get(&policy.id.to_string())
        .copied()
        .expect("timestamp must survive cancellation");
    assert!(
        ts_after >= ts_before,
        "Final timestamp ({ts_after}) must be >= pre-cancellation ({ts_before}); \
         drain should not lose in-flight ACKs"
    );
}

/// A peer that keeps its ACK direction open after the client finishes its
/// send direction must not make shutdown unbounded. Closing the endpoint at
/// the deadline must release the ACK receiver so the policy actor can
/// still perform its final flush.
#[serial]
#[tokio::test]
async fn stalled_ack_stream_recovers_and_actor_flushes_before_return() {
    let client_finished = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let (ingest_ack_send, ingest_ack_recv) = async_channel::bounded::<u32>(4);
    let ingest_server = FakeGigantoServer::new_ingest()
        .with_notify(ingest_ack_send)
        .with_ingest_behavior(IngestBehavior::HoldAckStreamOpen {
            client_finished: client_finished.clone(),
            release: release.clone(),
        });
    let publish_server = FakeGigantoServer::new_publish();
    let ingest_shutdown = Arc::new(Notify::new());
    let publish_shutdown = Arc::new(Notify::new());
    let (ingest_addr, ingest_handle) = ingest_server.start_ingest(ingest_shutdown.clone());
    let (publish_addr, publish_handle) = publish_server.start_publish(publish_shutdown.clone());

    let coordinator = CancellationCoordinator::new();
    let (mut request_client, actor_task, timestamp_path, _temp_dir, policy_handle) =
        setup_request_client(None, &coordinator).await;
    let policy = new_policy(DEFAULT_POLICY_ID);
    request_client
        .time_series_generation_policy_list(std::slice::from_ref(&policy))
        .await
        .expect("policy setup succeeds");
    let client = Client::new(ingest_addr, publish_addr, HOST.to_string(), &cert_key())
        .expect("subscribe client");
    let client_handle = tokio::spawn(client.run(policy_handle, actor_task, coordinator.clone()));

    timeout(Duration::from_secs(5), ingest_ack_recv.recv())
        .await
        .expect("initial ACK arrives")
        .expect("ACK channel remains open");
    timeout(
        Duration::from_secs(5),
        wait_for_policy_ids(&timestamp_path, &[policy.id], true),
    )
    .await
    .expect("initial timestamp is persisted");

    let shutdown_started = Instant::now();
    drop(request_client);
    coordinator.request_cancellation("stalled ACK test");
    timeout(Duration::from_secs(5), client_finished.notified())
        .await
        .expect("server observes the finished client send stream");

    timeout(Duration::from_secs(12), client_handle)
        .await
        .expect("client shutdown remains bounded")
        .expect("client task joins")
        .expect("forced endpoint close should recover the graceful timeout");
    assert!(
        shutdown_started.elapsed()
            >= SHUTDOWN_DRAIN_TIMEOUT
                .checked_sub(FORCED_DRAIN_GRACE)
                .expect("forced drain grace is shorter than the shutdown timeout"),
        "the peer should hold the ACK stream through the graceful deadline"
    );

    assert_eq!(
        coordinator.phase(),
        CancellationPhase::Completed,
        "forced endpoint close must release ACK receivers and flush the actor before returning"
    );
    assert_eq!(coordinator.tracker().active_count(), 0);
    assert!(timestamp_path.exists(), "actor output must remain durable");

    release.notify_waiters();
    ingest_shutdown.notify_one();
    publish_shutdown.notify_one();
    let _ = tokio::join!(ingest_handle, publish_handle);
    INGEST_CHANNEL.write().await.clear();
}

/// Consecutive writes of one policy that both reach the ingest control before
/// its sender is installed go out on that one sender, in order. A second
/// sender would carry the correction on its own stream, and Giganto would
/// store it before the slower original, which would then replace it.
#[serial]
#[tokio::test]
async fn ingest_control_queues_consecutive_writes_on_one_sender() {
    INGEST_CHANNEL.write().await.clear();
    let (stored_send, stored) = async_channel::unbounded();
    let shutdown = Arc::new(Notify::new());
    let (ingest_addr, ingest_handle) = FakeGigantoServer::new_ingest()
        .with_series_notify(stored_send)
        .with_ingest_behavior(IngestBehavior::DelayFirstStream(Duration::from_millis(500)))
        .start_ingest(shutdown.clone());
    let endpoint = client::config(&cert_key()).expect("client endpoint");
    let coordinator = CancellationCoordinator::new();
    let dir = tempfile::tempdir().unwrap();
    let (policy_handle, actor_task) =
        spawn_policy_actor(dir.path().join("timestamps.json"), &coordinator)
            .await
            .unwrap();
    policy_handle
        .replace_policies(vec![new_policy(DEFAULT_POLICY_ID)])
        .await
        .unwrap();

    // Both writes are queued before the ingest control runs.
    let (series_send, series_recv) = async_channel::unbounded();
    for value in [1.0, 2.0] {
        series_send
            .try_send(IngestFrame::from(TimeSeries {
                time_series_id: DEFAULT_POLICY_ID.to_string(),
                policy_id: DEFAULT_POLICY_ID,
                start_secs: BASE_WINDOW_START_NANOS / 1_000_000_000,
                series: vec![value],
            }))
            .unwrap();
    }
    let control = tokio::spawn({
        let coordinator = coordinator.clone();
        let policy_handle = policy_handle.clone();
        async move {
            ingest_connection_control(
                series_recv,
                ingest_addr,
                HOST,
                &endpoint,
                REQUIRED_GIGANTO_VERSION,
                policy_handle,
                Arc::new(Notify::new()),
                coordinator,
            )
            .await
            .expect("ingest control exits cleanly");
            endpoint
        }
    });

    let mut values = Vec::new();
    for _ in 0..2 {
        let (_, series) = timeout(TEST_TIMEOUT, stored.recv())
            .await
            .expect("both writes are stored")
            .unwrap();
        values.extend(series.series);
    }
    assert_eq!(values, [1.0, 2.0], "the correction is stored last");

    coordinator.request_cancellation("ordered ingest test");
    drop(series_send);
    let endpoint = control.await.expect("ingest control joins");
    drop(policy_handle);
    assert!(coordinator.wait_for_drain(Duration::from_secs(5)).await);
    actor_task.await.unwrap().unwrap();
    endpoint.close(0u32.into(), &[]);
    shutdown.notify_one();
    ingest_handle.await.expect("ingest server joins");
    INGEST_CHANNEL.write().await.clear();
}

/// A restarting policy change cancels the token of the policy's sender, which
/// may still be writing with its queue installed. The next run's IP row and
/// marker then go out together on a sender of the new run, not into that
/// queue, whose sender would drop the row once it saw its token, leaving the
/// marker to be stored without it. A frame the stopped run still wrote is
/// dropped rather than written between them.
///
/// The old sender's write is on its own QUIC stream, which Giganto reads
/// late here. The new sender writes only once Giganto has stored it, so the
/// old run's row is not stored after the new run's row and marker, where it
/// would replace the row the marker counts.
#[serial]
#[tokio::test]
async fn ingest_control_bypasses_the_queue_of_a_replaced_request() {
    INGEST_CHANNEL.write().await.clear();
    let (stored_send, stored) = async_channel::unbounded();
    let shutdown = Arc::new(Notify::new());
    let (ingest_addr, ingest_handle) = FakeGigantoServer::new_ingest()
        .with_series_notify(stored_send)
        .with_ingest_behavior(IngestBehavior::DelayFirstStream(Duration::from_millis(500)))
        .start_ingest(shutdown.clone());
    let endpoint = client::config(&cert_key()).expect("client endpoint");
    let coordinator = CancellationCoordinator::new();
    let dir = tempfile::tempdir().unwrap();
    let (policy_handle, actor_task) =
        spawn_policy_actor(dir.path().join("timestamps.json"), &coordinator)
            .await
            .unwrap();
    policy_handle
        .replace_policies(vec![new_policy(DEFAULT_POLICY_ID)])
        .await
        .unwrap();
    let old_run = policy_handle
        .get_policy_token(DEFAULT_POLICY_ID)
        .await
        .expect("the policy is active");

    let start_secs = BASE_WINDOW_START_NANOS / 1_000_000_000;
    let frame = |id: String, value, run: &CancellationToken| {
        IngestFrame::from(TimeSeries {
            time_series_id: id,
            policy_id: DEFAULT_POLICY_ID,
            start_secs,
            series: vec![value],
        })
        .of_run(run)
    };
    let ip_row = format!("{DEFAULT_POLICY_ID}/10.0.0.1");
    let (series_send, series_recv) = async_channel::unbounded();
    series_send
        .try_send(frame(ip_row.clone(), 9.0, &old_run))
        .unwrap();
    let control = tokio::spawn({
        let coordinator = coordinator.clone();
        let policy_handle = policy_handle.clone();
        async move {
            ingest_connection_control(
                series_recv,
                ingest_addr,
                HOST,
                &endpoint,
                REQUIRED_GIGANTO_VERSION,
                policy_handle,
                Arc::new(Notify::new()),
                coordinator,
            )
            .await
            .expect("ingest control exits cleanly");
            endpoint
        }
    });
    // The old run's row starts its sender, which writes it on the first
    // stream: Giganto reads that stream only after a delay.
    wait_for_ingest_channel(DEFAULT_POLICY_ID, true)
        .await
        .expect("the old run's row starts the policy's sender");

    let changed = TimeSeriesGenerationPolicy {
        slot_size: Duration::from_secs(5 * SECS_PER_MINUTE),
        ..new_policy(DEFAULT_POLICY_ID)
    };
    policy_handle.replace_policies(vec![changed]).await.unwrap();
    assert!(old_run.is_cancelled(), "the change restarts the policy");
    let new_run = policy_handle
        .get_policy_token(DEFAULT_POLICY_ID)
        .await
        .expect("the changed policy is active");
    for (id, value, run) in [
        (ip_row.clone(), 1.0, &new_run),
        (ip_row.clone(), 9.5, &old_run),
        (DEFAULT_POLICY_ID.to_string(), 2.0, &new_run),
    ] {
        series_send.try_send(frame(id, value, run)).unwrap();
    }

    let mut writes = Vec::new();
    for _ in 0..3 {
        let (_, series) = timeout(TEST_TIMEOUT, stored.recv())
            .await
            .expect("the old run's row and the new run's row and marker are stored")
            .unwrap();
        writes.push((series.time_series_id, series.series));
    }
    assert_eq!(
        writes,
        [
            (ip_row.clone(), vec![9.0]),
            (ip_row, vec![1.0]),
            (DEFAULT_POLICY_ID.to_string(), vec![2.0]),
        ],
        "the old run's write is stored first, the row precedes its marker, \
         and the stopped run's later frame is dropped"
    );

    coordinator.request_cancellation("replaced request test");
    drop(series_send);
    let endpoint = control.await.expect("ingest control joins");
    drop(policy_handle);
    assert!(coordinator.wait_for_drain(Duration::from_secs(5)).await);
    actor_task.await.unwrap().unwrap();
    assert!(
        stored.try_recv().is_err(),
        "nothing else is stored, the stopped run's frame included"
    );
    endpoint.close(0u32.into(), &[]);
    shutdown.notify_one();
    ingest_handle.await.expect("ingest server joins");
    INGEST_CHANNEL.write().await.clear();
}

/// A reconnect replaces the ingest connection while Giganto has received a
/// policy's frame on it but not yet stored it, and holds it, with the
/// connection up, for several of the reconnect's warning intervals. The
/// policy's next writes, on the new connection, are stored only after that
/// frame: an old-generation row stored after the new run's row and marker
/// would replace the row the marker counts.
#[serial]
#[tokio::test]
async fn reconnect_stores_the_old_connections_writes_before_the_new_ones() {
    INGEST_CHANNEL.write().await.clear();
    let (stored_send, stored) = async_channel::unbounded();
    let received = Arc::new(Notify::new());
    let shutdown = Arc::new(Notify::new());
    let (ingest_addr, ingest_handle) = FakeGigantoServer::new_ingest()
        .with_series_notify(stored_send)
        .with_ingest_behavior(IngestBehavior::DelayFirstStore {
            delay: STORE_BEFORE_RECONNECT_WARN_INTERVAL * 5,
            received: received.clone(),
            pending: Arc::new(AtomicBool::new(true)),
        })
        .start_ingest(shutdown.clone());
    let endpoint = client::config(&cert_key()).expect("client endpoint");
    let coordinator = CancellationCoordinator::new();
    let dir = tempfile::tempdir().unwrap();
    let (policy_handle, actor_task) =
        spawn_policy_actor(dir.path().join("timestamps.json"), &coordinator)
            .await
            .unwrap();
    policy_handle
        .replace_policies(vec![new_policy(DEFAULT_POLICY_ID)])
        .await
        .unwrap();
    let run = policy_handle
        .get_policy_token(DEFAULT_POLICY_ID)
        .await
        .expect("the policy is active");

    let start_secs = BASE_WINDOW_START_NANOS / 1_000_000_000;
    let frame = |id: String, value| {
        IngestFrame::from(TimeSeries {
            time_series_id: id,
            policy_id: DEFAULT_POLICY_ID,
            start_secs,
            series: vec![value],
        })
        .of_run(&run)
    };
    let ip_row = format!("{DEFAULT_POLICY_ID}/10.0.0.1");
    let (series_send, series_recv) = async_channel::unbounded();
    series_send.try_send(frame(ip_row.clone(), 9.0)).unwrap();
    let connection_notify = Arc::new(Notify::new());
    let control = tokio::spawn({
        let coordinator = coordinator.clone();
        let policy_handle = policy_handle.clone();
        let connection_notify = connection_notify.clone();
        async move {
            ingest_connection_control(
                series_recv,
                ingest_addr,
                HOST,
                &endpoint,
                REQUIRED_GIGANTO_VERSION,
                policy_handle,
                connection_notify,
                coordinator,
            )
            .await
            .expect("ingest control exits cleanly");
            endpoint
        }
    });
    timeout(TEST_TIMEOUT, received.notified())
        .await
        .expect("Giganto receives the old connection's row");

    // The reconnect signal, as a lost Publish connection gives it, and then
    // the rows of the run requested on the new connections.
    connection_notify.notify_one();
    for (id, value) in [(ip_row.clone(), 1.0), (DEFAULT_POLICY_ID.to_string(), 2.0)] {
        series_send.try_send(frame(id, value)).unwrap();
    }

    let mut writes = Vec::new();
    for _ in 0..3 {
        let (_, series) = timeout(RECONNECT_TEST_TIMEOUT, stored.recv())
            .await
            .expect("the old row and the new row and marker are stored")
            .unwrap();
        writes.push((series.time_series_id, series.series));
    }
    assert_eq!(
        writes,
        [
            (ip_row.clone(), vec![9.0]),
            (ip_row, vec![1.0]),
            (DEFAULT_POLICY_ID.to_string(), vec![2.0]),
        ],
        "the old connection's row is stored first, and the row precedes its marker"
    );

    coordinator.request_cancellation("reconnect ordering test");
    drop(series_send);
    let endpoint = control.await.expect("ingest control joins");
    drop(policy_handle);
    assert!(coordinator.wait_for_drain(Duration::from_secs(5)).await);
    actor_task.await.unwrap().unwrap();
    endpoint.close(0u32.into(), &[]);
    shutdown.notify_one();
    ingest_handle.await.expect("ingest server joins");
    INGEST_CHANNEL.write().await.clear();
}

/// A replaced request's sender has written a frame that Giganto received but
/// holds unstored beyond [`PREVIOUS_STREAM_STORE_TIMEOUT`]. The next run's
/// sender, waiting for it, times out and signals a reconnect. The reconnect
/// still waits for that frame through the failed sender's entry, so the next
/// run's writes on the new connection are stored after it: an old-generation
/// row stored after the new run's row and marker would replace the row the
/// marker counts.
#[serial]
#[tokio::test]
async fn replacement_timeout_keeps_the_old_senders_writes_before_the_new_ones() {
    INGEST_CHANNEL.write().await.clear();
    let (stored_send, stored) = async_channel::unbounded();
    let received = Arc::new(Notify::new());
    let shutdown = Arc::new(Notify::new());
    let (ingest_addr, ingest_handle) = FakeGigantoServer::new_ingest()
        .with_series_notify(stored_send)
        .with_ingest_behavior(IngestBehavior::DelayFirstStore {
            delay: PREVIOUS_STREAM_STORE_TIMEOUT + STORE_BEFORE_RECONNECT_WARN_INTERVAL * 5,
            received: received.clone(),
            pending: Arc::new(AtomicBool::new(true)),
        })
        .start_ingest(shutdown.clone());
    let endpoint = client::config(&cert_key()).expect("client endpoint");
    let coordinator = CancellationCoordinator::new();
    let dir = tempfile::tempdir().unwrap();
    let (policy_handle, actor_task) =
        spawn_policy_actor(dir.path().join("timestamps.json"), &coordinator)
            .await
            .unwrap();
    policy_handle
        .replace_policies(vec![new_policy(DEFAULT_POLICY_ID)])
        .await
        .unwrap();
    let old_run = policy_handle
        .get_policy_token(DEFAULT_POLICY_ID)
        .await
        .expect("the policy is active");

    let start_secs = BASE_WINDOW_START_NANOS / 1_000_000_000;
    let frame = |id: String, value, run: &CancellationToken| {
        IngestFrame::from(TimeSeries {
            time_series_id: id,
            policy_id: DEFAULT_POLICY_ID,
            start_secs,
            series: vec![value],
        })
        .of_run(run)
    };
    let ip_row = format!("{DEFAULT_POLICY_ID}/10.0.0.1");
    let (series_send, series_recv) = async_channel::unbounded();
    series_send
        .try_send(frame(ip_row.clone(), 9.0, &old_run))
        .unwrap();
    let connection_notify = Arc::new(Notify::new());
    let control = tokio::spawn({
        let coordinator = coordinator.clone();
        let policy_handle = policy_handle.clone();
        let connection_notify = connection_notify.clone();
        async move {
            ingest_connection_control(
                series_recv,
                ingest_addr,
                HOST,
                &endpoint,
                REQUIRED_GIGANTO_VERSION,
                policy_handle,
                connection_notify,
                coordinator,
            )
            .await
            .expect("ingest control exits cleanly");
            endpoint
        }
    });
    timeout(TEST_TIMEOUT, received.notified())
        .await
        .expect("Giganto receives the old run's row");

    let changed = TimeSeriesGenerationPolicy {
        slot_size: Duration::from_secs(5 * SECS_PER_MINUTE),
        ..new_policy(DEFAULT_POLICY_ID)
    };
    policy_handle.replace_policies(vec![changed]).await.unwrap();
    assert!(old_run.is_cancelled(), "the change restarts the policy");
    let new_run = policy_handle
        .get_policy_token(DEFAULT_POLICY_ID)
        .await
        .expect("the changed policy is active");

    // The next run's first row starts a sender that waits for the old one,
    // times out and signals a reconnect; the row it held is lost with it,
    // and its request stops.
    let lost = new_run.child_token();
    let failed = connection_notify.notified();
    tokio::pin!(failed);
    failed.as_mut().enable();
    series_send
        .try_send(frame(ip_row.clone(), 0.5, &lost))
        .unwrap();
    timeout(TEST_TIMEOUT, failed)
        .await
        .expect("the replacing sender times out and signals a reconnect");
    assert!(lost.is_cancelled(), "the request that lost its row stops");
    assert!(!new_run.is_cancelled(), "the policy stays active");

    // The rows of the policy's next request, written on the new connection.
    let rewrite = new_run.child_token();
    for (id, value) in [(ip_row.clone(), 1.0), (DEFAULT_POLICY_ID.to_string(), 2.0)] {
        series_send.try_send(frame(id, value, &rewrite)).unwrap();
    }

    let mut writes = Vec::new();
    for _ in 0..3 {
        let (_, series) = timeout(RECONNECT_TEST_TIMEOUT, stored.recv())
            .await
            .expect("the old run's row and the new run's row and marker are stored")
            .unwrap();
        writes.push((series.time_series_id, series.series));
    }
    assert_eq!(
        writes,
        [
            (ip_row.clone(), vec![9.0]),
            (ip_row, vec![1.0]),
            (DEFAULT_POLICY_ID.to_string(), vec![2.0]),
        ],
        "the old run's row is stored first, and the row precedes its marker"
    );

    coordinator.request_cancellation("replacement timeout ordering test");
    drop(series_send);
    let endpoint = control.await.expect("ingest control joins");
    drop(policy_handle);
    assert!(coordinator.wait_for_drain(Duration::from_secs(5)).await);
    actor_task.await.unwrap().unwrap();
    endpoint.close(0u32.into(), &[]);
    shutdown.notify_one();
    ingest_handle.await.expect("ingest server joins");
    INGEST_CHANNEL.write().await.clear();
}

/// A request's two IP rows and their marker are queued, through queues of
/// the production capacity, behind a sender that waits for a replaced
/// request's frame Giganto holds unstored: the first row is the sender's
/// own, the second is in its queue, and the marker is blocked on that queue.
/// The sender times out and drops both rows. The marker, which the closing
/// queue hands back to the ingest control, is dropped with them, and is not
/// written by another sender once the old frame is stored, with the
/// connection still up: a marker visible without the rows it counts would
/// claim rows Giganto never stored. The request stops, and only the next
/// request's rows and marker follow the old frame.
#[serial]
#[tokio::test]
async fn failed_sender_drops_the_rest_of_its_request() {
    const OTHER_POLICY_ID: u32 = DEFAULT_POLICY_ID + 1;
    INGEST_CHANNEL.write().await.clear();
    let (stored_send, stored) = async_channel::unbounded();
    let received = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let shutdown = Arc::new(Notify::new());
    let (ingest_addr, ingest_handle) = FakeGigantoServer::new_ingest()
        .with_series_notify(stored_send)
        .with_ingest_behavior(IngestBehavior::HoldFirstStore {
            received: received.clone(),
            release: release.clone(),
            pending: Arc::new(AtomicBool::new(true)),
        })
        .start_ingest(shutdown.clone());
    let endpoint = client::config(&cert_key()).expect("client endpoint");
    let coordinator = CancellationCoordinator::new();
    let dir = tempfile::tempdir().unwrap();
    let (policy_handle, actor_task) =
        spawn_policy_actor(dir.path().join("timestamps.json"), &coordinator)
            .await
            .unwrap();
    policy_handle
        .replace_policies(vec![
            new_policy(DEFAULT_POLICY_ID),
            new_policy(OTHER_POLICY_ID),
        ])
        .await
        .unwrap();
    let old_run = policy_handle
        .get_policy_token(DEFAULT_POLICY_ID)
        .await
        .expect("the policy is active");
    let other_run = policy_handle
        .get_policy_token(OTHER_POLICY_ID)
        .await
        .expect("the other policy is active");

    let start_secs = BASE_WINDOW_START_NANOS / 1_000_000_000;
    let frame = |policy_id: u32, id: &str, value, run: &CancellationToken| {
        IngestFrame::from(TimeSeries {
            time_series_id: id.to_string(),
            policy_id,
            start_secs,
            series: vec![value],
        })
        .of_run(run)
    };
    let ip_a = format!("{DEFAULT_POLICY_ID}/10.0.0.1");
    let ip_b = format!("{DEFAULT_POLICY_ID}/10.0.0.2");
    let marker = DEFAULT_POLICY_ID.to_string();
    let other = OTHER_POLICY_ID.to_string();
    let (series_send, series_recv) = async_channel::bounded(TIME_SERIES_CHANNEL_SIZE);
    series_send
        .send(frame(DEFAULT_POLICY_ID, &ip_a, 9.0, &old_run.child_token()))
        .await
        .unwrap();
    let connection_notify = Arc::new(Notify::new());
    let control = tokio::spawn({
        let coordinator = coordinator.clone();
        let policy_handle = policy_handle.clone();
        let connection_notify = connection_notify.clone();
        async move {
            ingest_connection_control(
                series_recv,
                ingest_addr,
                HOST,
                &endpoint,
                REQUIRED_GIGANTO_VERSION,
                policy_handle,
                connection_notify,
                coordinator,
            )
            .await
            .expect("ingest control exits cleanly");
            endpoint
        }
    });
    timeout(TEST_TIMEOUT, received.notified())
        .await
        .expect("Giganto receives the old run's row");

    let changed = TimeSeriesGenerationPolicy {
        slot_size: Duration::from_secs(5 * SECS_PER_MINUTE),
        ..new_policy(DEFAULT_POLICY_ID)
    };
    policy_handle
        .replace_policies(vec![changed, new_policy(OTHER_POLICY_ID)])
        .await
        .unwrap();
    assert!(old_run.is_cancelled(), "the change restarts the policy");
    assert!(!other_run.is_cancelled(), "the other policy is unchanged");
    let new_run = policy_handle
        .get_policy_token(DEFAULT_POLICY_ID)
        .await
        .expect("the changed policy is active");

    // The request's rows and marker, all queued before the sender times out,
    // and then another policy's row, which the ingest control takes only
    // once it has routed the marker.
    let lost = new_run.child_token();
    let failed = connection_notify.notified();
    tokio::pin!(failed);
    failed.as_mut().enable();
    let producer = tokio::spawn({
        let series_send = series_send.clone();
        let frames = [
            frame(DEFAULT_POLICY_ID, &ip_a, 1.0, &lost),
            frame(DEFAULT_POLICY_ID, &ip_b, 1.0, &lost),
            frame(DEFAULT_POLICY_ID, &marker, 2.0, &lost),
            frame(OTHER_POLICY_ID, &other, 7.0, &other_run.child_token()),
        ];
        async move {
            for frame in frames {
                series_send.send(frame).await.unwrap();
            }
        }
    });
    timeout(TEST_TIMEOUT, failed)
        .await
        .expect("the replacing sender times out and signals a reconnect");
    let (_, series) = timeout(TEST_TIMEOUT, stored.recv())
        .await
        .expect("the other policy's row is stored")
        .unwrap();
    assert_eq!(
        (series.time_series_id, series.series),
        (other.clone(), vec![7.0]),
        "the other policy's row, routed after the marker, is stored first"
    );
    producer
        .await
        .expect("every frame is handed to the ingest control");
    assert!(lost.is_cancelled(), "the request that lost its rows stops");
    assert!(!new_run.is_cancelled(), "the policy stays active");

    // Giganto stores the old run's row with the connection up, and the
    // reconnect signal follows, as the stopped request's runner gives it.
    release.notify_one();
    let (_, series) = timeout(TEST_TIMEOUT, stored.recv())
        .await
        .expect("the old run's row is stored")
        .unwrap();
    assert_eq!(
        (series.time_series_id, series.series),
        (ip_a.clone(), vec![9.0])
    );
    connection_notify.notify_one();

    // The rows of the policy's next request, written on the new connection.
    let rewrite = new_run.child_token();
    for (id, value) in [(&ip_a, 1.0), (&ip_b, 1.0), (&marker, 2.0)] {
        series_send
            .send(frame(DEFAULT_POLICY_ID, id, value, &rewrite))
            .await
            .unwrap();
    }
    let mut writes = Vec::new();
    for _ in 0..3 {
        let (_, series) = timeout(RECONNECT_TEST_TIMEOUT, stored.recv())
            .await
            .expect("the next request's rows and marker are stored")
            .unwrap();
        writes.push((series.time_series_id, series.series));
    }
    assert_eq!(
        writes,
        [(ip_a, vec![1.0]), (ip_b, vec![1.0]), (marker, vec![2.0]),],
        "no marker of the stopped request is stored, and the next request's \
         marker follows both rows it counts"
    );

    coordinator.request_cancellation("failed sender request test");
    drop(series_send);
    let endpoint = control.await.expect("ingest control joins");
    drop(policy_handle);
    assert!(coordinator.wait_for_drain(Duration::from_secs(5)).await);
    actor_task.await.unwrap().unwrap();
    assert!(
        stored.try_recv().is_err(),
        "nothing else is stored, the stopped request's marker included"
    );
    endpoint.close(0u32.into(), &[]);
    shutdown.notify_one();
    ingest_handle.await.expect("ingest server joins");
    INGEST_CHANNEL.write().await.clear();
}

/// Windows still queued in the ingest control at shutdown are handed to an
/// ingest sender: the first starts one, and the next is queued behind it.
#[serial]
#[tokio::test]
async fn shutdown_drain_writes_series_queued_in_the_ingest_control() {
    INGEST_CHANNEL.write().await.clear();
    let (stored_send, stored) = async_channel::unbounded();
    let shutdown = Arc::new(Notify::new());
    let (ingest_addr, ingest_handle) = FakeGigantoServer::new_ingest()
        .with_series_notify(stored_send)
        .start_ingest(shutdown.clone());
    let endpoint = client::config(&cert_key()).expect("client endpoint");
    let connection = ingest_connect(&endpoint, ingest_addr, HOST, REQUIRED_GIGANTO_VERSION)
        .await
        .expect("ingest connection");
    let coordinator = CancellationCoordinator::new();
    let dir = tempfile::tempdir().unwrap();
    let (policy_handle, actor_task) =
        spawn_policy_actor(dir.path().join("timestamps.json"), &coordinator)
            .await
            .unwrap();

    let (series_send, series_recv) = async_channel::unbounded();
    for value in [1.0, 2.0] {
        series_send
            .try_send(IngestFrame::from(TimeSeries {
                time_series_id: DEFAULT_POLICY_ID.to_string(),
                policy_id: DEFAULT_POLICY_ID,
                start_secs: BASE_WINDOW_START_NANOS / 1_000_000_000,
                series: vec![value],
            }))
            .unwrap();
    }
    drop(series_send);
    drain_series_at_shutdown(
        &series_recv,
        &coordinator,
        &Arc::new(connection),
        &ConnectionLifecycle::new(),
        &policy_handle,
        &Arc::new(Notify::new()),
    )
    .await;

    let mut values = Vec::new();
    for _ in 0..2 {
        let (_, series) = timeout(TEST_TIMEOUT, stored.recv())
            .await
            .expect("both queued series are stored")
            .unwrap();
        values.extend(series.series);
    }
    assert_eq!(values, [1.0, 2.0]);

    coordinator.request_cancellation("shutdown drain test");
    drop(policy_handle);
    assert!(coordinator.wait_for_drain(Duration::from_secs(5)).await);
    actor_task.await.unwrap().unwrap();
    endpoint.close(0u32.into(), &[]);
    shutdown.notify_one();
    ingest_handle.await.expect("ingest server joins");
    INGEST_CHANNEL.write().await.clear();
}

/// A window and its correction still in the ingest control at shutdown follow
/// the original write on its sender's stream, and so does the next window.
/// A second sender would carry them on their own stream, which Giganto could
/// store first: the original would then replace its correction, and the next
/// window's ACK would move the checkpoint past it, so no resume rebuilds it.
#[serial]
#[tokio::test]
async fn shutdown_drain_keeps_corrections_behind_the_window_they_replace() {
    INGEST_CHANNEL.write().await.clear();
    let (stored_send, stored) = async_channel::unbounded();
    let shutdown = Arc::new(Notify::new());
    let (ingest_addr, ingest_handle) = FakeGigantoServer::new_ingest()
        .with_series_notify(stored_send)
        .with_ingest_behavior(IngestBehavior::DelayFirstStream(Duration::from_millis(500)))
        .start_ingest(shutdown.clone());
    let endpoint = client::config(&cert_key()).expect("client endpoint");
    let coordinator = CancellationCoordinator::new();
    let dir = tempfile::tempdir().unwrap();
    let timestamps_path = dir.path().join("timestamps.json");
    let (policy_handle, actor_task) = spawn_policy_actor(timestamps_path.clone(), &coordinator)
        .await
        .unwrap();
    policy_handle
        .replace_policies(vec![new_policy(DEFAULT_POLICY_ID)])
        .await
        .unwrap();

    let window_start_secs = BASE_WINDOW_START_NANOS / 1_000_000_000;
    let next_start_secs = (BASE_WINDOW_START_NANOS + DAY_NANOS) / 1_000_000_000;
    let window = |start_secs, value| {
        IngestFrame::from(TimeSeries {
            time_series_id: DEFAULT_POLICY_ID.to_string(),
            policy_id: DEFAULT_POLICY_ID,
            start_secs,
            series: vec![value],
        })
    };
    let (series_send, series_recv) = async_channel::unbounded();
    series_send
        .try_send(window(window_start_secs, 1.0))
        .unwrap();
    let control = tokio::spawn({
        let coordinator = coordinator.clone();
        let policy_handle = policy_handle.clone();
        async move {
            ingest_connection_control(
                series_recv,
                ingest_addr,
                HOST,
                &endpoint,
                REQUIRED_GIGANTO_VERSION,
                policy_handle,
                Arc::new(Notify::new()),
                coordinator,
            )
            .await
            .expect("ingest control exits cleanly");
            endpoint
        }
    });
    wait_for_ingest_channel(DEFAULT_POLICY_ID, true)
        .await
        .expect("the original write starts the policy's sender");

    // Let the sender observe the cancellation before the drain takes the
    // correction and the next window.
    coordinator.request_cancellation("shutdown ordering test");
    sleep(Duration::from_millis(100)).await;
    series_send
        .try_send(window(window_start_secs, 2.0))
        .unwrap();
    series_send.try_send(window(next_start_secs, 3.0)).unwrap();
    drop(series_send);

    let mut writes = Vec::new();
    for _ in 0..3 {
        let (timestamp, series) = timeout(TEST_TIMEOUT, stored.recv())
            .await
            .expect("all three writes are stored")
            .unwrap();
        writes.push((timestamp, series.series));
    }
    assert_eq!(
        writes,
        [
            (BASE_WINDOW_START_NANOS, vec![1.0]),
            (BASE_WINDOW_START_NANOS, vec![2.0]),
            (BASE_WINDOW_START_NANOS + DAY_NANOS, vec![3.0]),
        ],
        "the correction is stored after the window it replaces"
    );

    let endpoint = control.await.expect("ingest control joins");
    drop(policy_handle);
    assert!(coordinator.wait_for_drain(Duration::from_secs(5)).await);
    actor_task.await.unwrap().unwrap();
    assert_eq!(
        read_time_data_map(&timestamps_path).get(&DEFAULT_POLICY_ID.to_string()),
        Some(&(BASE_WINDOW_START_NANOS + DAY_NANOS)),
        "the checkpoint is the last written window"
    );
    endpoint.close(0u32.into(), &[]);
    shutdown.notify_one();
    ingest_handle.await.expect("ingest server joins");
    INGEST_CHANNEL.write().await.clear();
}

/// A series accepted into an existing per-policy ingest queue before
/// cancellation must still be transmitted before the sender exits.
#[serial]
#[tokio::test]
async fn cancellation_drains_queued_time_series() {
    INGEST_CHANNEL.write().await.clear();
    let (ack_send, ack_recv) = async_channel::bounded::<u32>(4);
    let shutdown = Arc::new(Notify::new());
    let (ingest_addr, ingest_handle) = FakeGigantoServer::new_ingest()
        .with_notify(ack_send)
        .start_ingest(shutdown.clone());

    let endpoint = client::config(&cert_key()).expect("client endpoint");
    let connection = ingest_connect(&endpoint, ingest_addr, HOST, REQUIRED_GIGANTO_VERSION)
        .await
        .expect("ingest connection");
    let coordinator = CancellationCoordinator::new();
    let dir = tempfile::tempdir().unwrap();
    let (policy_handle, actor_task) =
        spawn_policy_actor(dir.path().join("timestamps.json"), &coordinator)
            .await
            .unwrap();
    policy_handle
        .replace_policies(vec![new_policy(DEFAULT_POLICY_ID)])
        .await
        .unwrap();
    let policy_id = DEFAULT_POLICY_ID;
    let first = IngestFrame::from(TimeSeries {
        time_series_id: policy_id.to_string(),
        policy_id,
        start_secs: 1,
        series: vec![1.0],
    });
    let second = IngestFrame::from(TimeSeries {
        time_series_id: policy_id.to_string(),
        policy_id,
        start_secs: 2,
        series: vec![2.0],
    });

    let sender_token = CancellationToken::new();
    let recv_channel = register_ingest_queue(policy_id, sender_token.clone()).await;
    let sender_task = coordinator.tracker().spawn(send_time_series(
        Arc::new(connection),
        first,
        recv_channel,
        sender_token,
        ConnectionLifecycle::new(),
        policy_handle,
        Arc::new(Notify::new()),
        coordinator.clone(),
    ));

    let first_ack = timeout(Duration::from_secs(5), ack_recv.recv())
        .await
        .expect("first ACK arrives")
        .expect("ACK channel remains open");
    assert_eq!(first_ack, DEFAULT_POLICY_ID);
    wait_for_ingest_channel(policy_id, true)
        .await
        .expect("per-policy queue is registered");

    let queued_sender = INGEST_CHANNEL
        .read()
        .await
        .get(&policy_id)
        .map(|queue| queue.frames.clone())
        .expect("per-policy sender exists");
    queued_sender
        .try_send(second)
        .expect("second series is queued before cancellation");
    coordinator.request_cancellation("queued-series drain test");
    // The ingest control closes the queues once its own drain is done.
    close_ingest_queues().await;

    sender_task
        .await
        .expect("sender task joins")
        .expect("queued series is sent successfully");
    let second_ack = timeout(Duration::from_secs(5), ack_recv.recv())
        .await
        .expect("queued series ACK arrives")
        .expect("ACK channel remains open");
    assert_eq!(second_ack, DEFAULT_POLICY_ID);
    assert!(
        coordinator.wait_for_drain(Duration::from_secs(5)).await,
        "ACK receiver drains"
    );

    actor_task.await.unwrap().unwrap();
    endpoint.close(0u32.into(), &[]);
    shutdown.notify_one();
    ingest_handle.await.expect("ingest server joins");
    INGEST_CHANNEL.write().await.clear();
}

/// Verifies that connection drain does not return until every task tracked for
/// the ending connection generation has completed.
#[serial]
#[tokio::test]
async fn connection_generation_drain_waits_for_tracked_children() {
    let publish_shutdown = Arc::new(Notify::new());
    let (publish_addr, publish_handle) =
        FakeGigantoServer::new_publish().start_publish(publish_shutdown.clone());
    let endpoint = crate::client::config(&cert_key()).expect("client endpoint");
    let (connection, _send) =
        publish_connect(&endpoint, publish_addr, HOST, REQUIRED_GIGANTO_VERSION)
            .await
            .expect("publish connection");

    let lifecycle = ConnectionLifecycle::new();
    let child_token = lifecycle.token.clone();
    let child_started = Arc::new(Notify::new());
    let child_started_for_task = child_started.clone();
    let cancellation_observed = Arc::new(Notify::new());
    let cancellation_observed_for_task = cancellation_observed.clone();
    let release_child = Arc::new(Notify::new());
    let release_child_for_task = release_child.clone();
    let child_handle = lifecycle.tasks.spawn(async move {
        child_started_for_task.notify_one();
        child_token.cancelled().await;
        cancellation_observed_for_task.notify_one();
        release_child_for_task.notified().await;
    });
    child_started.notified().await;

    let drain = drain_connection_generation(&connection, &lifecycle, "test publish");
    tokio::pin!(drain);
    tokio::select! {
        () = cancellation_observed.notified() => {}
        result = &mut drain => panic!("drain returned before child cancellation: {result:?}"),
    }
    assert!(
        timeout(Duration::from_millis(100), &mut drain)
            .await
            .is_err(),
        "drain must continue waiting while a tracked child is still running",
    );

    release_child.notify_one();
    timeout(Duration::from_secs(1), &mut drain)
        .await
        .expect("drain completes after child exit")
        .expect("connection drain succeeds");
    child_handle.await.expect("tracked child joins");

    publish_shutdown.notify_one();
    publish_handle.await.expect("publish server joins");
}

/// The subscribe supervisor must return the policy actor's I/O error
/// instead of reporting a successful drain.
#[serial]
#[tokio::test]
async fn policy_actor_failure_is_propagated() {
    let (_ack_recv, server_handles, ingest_addr, publish_addr) = start_servers();
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let invalid_path = temp_dir.path().join("time_data.json");
    let coordinator = CancellationCoordinator::new();
    let (policy_handle, actor_task) = spawn_policy_actor(invalid_path.clone(), &coordinator)
        .await
        .unwrap();
    fs::remove_file(&invalid_path).unwrap();
    fs::create_dir(&invalid_path).unwrap();
    let client = Client::new(ingest_addr, publish_addr, HOST.to_string(), &cert_key())
        .expect("subscribe client");

    coordinator.request_cancellation("actor failure test");
    let error = timeout(
        Duration::from_secs(5),
        client.run(policy_handle, actor_task, coordinator.clone()),
    )
    .await
    .expect("client exits after cancellation")
    .expect_err("policy actor error must reach the supervisor");
    assert!(
        error.to_string().contains("policy actor failed"),
        "unexpected error: {error:#}"
    );

    cleanup_server_resources(server_handles).await;
    INGEST_CHANNEL.write().await.clear();
}

/// Test: After cancellation + simulated restart, time data is consistent
/// and readable.
#[serial]
#[tokio::test]
async fn restart_state_consistency() {
    let policy = new_policy(DEFAULT_POLICY_ID);

    // --- First run ---
    let harness = TestHarness::new(std::slice::from_ref(&policy)).await;
    let _ = harness.wait_for_ack().await;
    let _ = harness.wait_for_timestamp(&[policy.id]).await;

    let first_run_map = read_time_data_map(&harness.last_time_series_path);
    let first_ts = *first_run_map
        .get(&policy.id.to_string())
        .expect("policy timestamp must exist after first run");
    let last_time_series_path = harness.last_time_series_path.clone();
    let _keep_temp = harness.temp_dir;
    drop(harness.request_client);
    drop(harness.policy_handle);
    cleanup_test_resources(
        harness.coordinator,
        harness.client_handle,
        harness.server_handles,
    )
    .await;

    // --- Second run: re-use persisted timestamp file ---

    let (ingest_ack_recv2, server_handles2, ingest_addr2, publish_addr2) = start_servers();
    let certs = cert_key();
    let coordinator2 = CancellationCoordinator::new();
    let (mut request_client2, actor_task2, _, _keep_dir, policy_handle2) =
        setup_request_client(Some(&last_time_series_path), &coordinator2).await;

    request_client2
        .time_series_generation_policy_list(std::slice::from_ref(&policy))
        .await
        .unwrap();

    let client_handle2 = spawn_subscribe_client(
        &certs,
        actor_task2,
        ingest_addr2,
        publish_addr2,
        policy_handle2,
        coordinator2.clone(),
    );

    let _ = timeout(Duration::from_secs(5), ingest_ack_recv2.recv())
        .await
        .expect("Ingest ACK should arrive within 5s on second run");

    let _ = timeout(
        Duration::from_secs(5),
        wait_for_policy_ids(&last_time_series_path, &[policy.id], true),
    )
    .await
    .expect("Policy ID present in time_data.json on second run");

    let second_run_map = read_time_data_map(&last_time_series_path);
    let second_ts = *second_run_map
        .get(&policy.id.to_string())
        .expect("policy timestamp must exist after second run");
    assert!(
        second_ts >= first_ts,
        "Second-run timestamp ({second_ts}) must be >= first-run ({first_ts}); \
         restart must not lose persisted state"
    );

    drop(request_client2);
    cleanup_test_resources(coordinator2, client_handle2, server_handles2).await;
}

/// Servers whose Publish side emits `publish_timestamps` on every stream and
/// then keeps it open, as Giganto does, and whose Ingest side reports every
/// written window with its timestamp.
struct WindowServers {
    series: async_channel::Receiver<(i64, TimeSeries)>,
    handles: TestServerHandlers,
    ingest_addr: SocketAddr,
    publish_addr: SocketAddr,
}

fn start_window_servers(publish_timestamps: Vec<i64>) -> WindowServers {
    start_window_servers_with(
        FakeGigantoServer::new_ingest(),
        FakeGigantoServer::new_publish().with_publish_timestamps(publish_timestamps),
    )
}

fn start_window_servers_with(
    ingest_server: FakeGigantoServer,
    publish_server: FakeGigantoServer,
) -> WindowServers {
    let (series_send, series) = async_channel::unbounded();
    let ingest_server = ingest_server.with_series_notify(series_send);
    let publish_server = publish_server.with_held_streams();
    let ingest_shutdown = Arc::new(Notify::new());
    let publish_shutdown = Arc::new(Notify::new());
    let (ingest_addr, ingest_handle) = ingest_server.start_ingest(ingest_shutdown.clone());
    let (publish_addr, publish_handle) = publish_server.start_publish(publish_shutdown.clone());
    WindowServers {
        series,
        handles: TestServerHandlers {
            ingest_shutdown,
            publish_shutdown,
            ingest_handle,
            publish_handle,
        },
        ingest_addr,
        publish_addr,
    }
}

async fn next_written_window(
    series: &async_channel::Receiver<(i64, TimeSeries)>,
) -> (i64, TimeSeries) {
    timeout(TEST_TIMEOUT, series.recv())
        .await
        .expect("a window should be written before the test deadline")
        .expect("the written-window channel should remain open")
}

/// A source that falls silent after the events of one window gets that window
/// written by the timer, once the wall clock is past its end plus the grace and
/// no event has been received for the idle gate.
#[serial]
#[tokio::test]
async fn silent_source_window_is_written_by_the_timer() {
    const IDLE: Duration = Duration::from_millis(1500);
    let servers = start_window_servers(vec![BASE_TS_NANOS, BASE_TS_NANOS + 1, BASE_TS_NANOS + 2]);
    let coordinator = CancellationCoordinator::new();
    let (mut review, actor_task, path, _dir, policy_handle) =
        setup_request_client(None, &coordinator).await;
    let policy = new_policy(DEFAULT_POLICY_ID);
    review
        .time_series_generation_policy_list(std::slice::from_ref(&policy))
        .await
        .unwrap();

    // The injected wall clock is exactly at the window's end plus the grace.
    let window_end_secs = (BASE_WINDOW_START_NANOS + DAY_NANOS) / 1_000_000_000;
    let now = window_end_secs + time_series::CLOSE_GRACE_SECS;
    let close_timer = CloseTimer::new(move || now, Duration::from_millis(50), IDLE);
    let started = Instant::now();
    let client_handle = spawn_subscribe_client_with_timer(
        &cert_key(),
        actor_task,
        servers.ingest_addr,
        servers.publish_addr,
        policy_handle.clone(),
        coordinator.clone(),
        close_timer,
    );

    let (timestamp, series) = next_written_window(&servers.series).await;
    // The server spaces the three events by its repeat delay, and the timer
    // waits for the idle gate after the last of them.
    assert!(
        started.elapsed() >= IDLE + 2 * FakeGigantoServer::new_publish().publish_repeat_delay,
        "written after {:?}, before the idle gate",
        started.elapsed()
    );
    assert_eq!(timestamp, BASE_WINDOW_START_NANOS);
    assert_eq!(series.time_series_id, policy.id.to_string());
    assert_eq!(series.series.iter().sum::<f64>(), 3.0);
    let map = timeout(TEST_TIMEOUT, wait_for_policy_ids(&path, &[policy.id], true))
        .await
        .expect("the timer-closed window is acknowledged");
    assert_eq!(map[&policy.id.to_string()], BASE_WINDOW_START_NANOS);

    // The window is written once.
    assert!(
        timeout(IDLE * 2, servers.series.recv()).await.is_err(),
        "a timer-closed window must not be written again without a new event"
    );

    drop(review);
    drop(policy_handle);
    cleanup_test_resources(coordinator, client_handle, servers.handles).await;
}

/// A grouped policy writes its IP's row under `P/IP` on one ingest stream,
/// keyed by its policy id, and the ACK of that stream moves its checkpoint.
#[serial]
#[tokio::test]
async fn grouped_policy_writes_ip_rows_and_its_ack_moves_its_checkpoint() {
    INGEST_CHANNEL.write().await.clear();
    let servers = start_window_servers(one_window_then_next());
    let coordinator = CancellationCoordinator::new();
    let (mut review, actor_task, path, _dir, policy_handle) =
        setup_request_client(None, &coordinator).await;
    let mut policy = new_policy(DEFAULT_POLICY_ID);
    policy.group_by = Some(review_protocol::types::EndpointRole::Source);
    // `gen_conn` is from 192.168.4.76 to itself.
    policy.internal_networks = HostNetworkGroup {
        hosts: Vec::new(),
        networks: vec!["192.168.4.0/24".parse().unwrap()],
        ip_ranges: Vec::new(),
    };
    policy.counterpart_scope = CounterpartScope::Internal;
    review
        .time_series_generation_policy_list(std::slice::from_ref(&policy))
        .await
        .unwrap();
    let client_handle = spawn_subscribe_client(
        &cert_key(),
        actor_task,
        servers.ingest_addr,
        servers.publish_addr,
        policy_handle.clone(),
        coordinator.clone(),
    );

    let (timestamp, series) = next_written_window(&servers.series).await;
    assert_eq!(timestamp, BASE_WINDOW_START_NANOS);
    assert_eq!(series.time_series_id, "1/192.168.4.76");
    let (generation, slots) = series.series.split_last().unwrap();
    assert_eq!(slots.iter().sum::<f64>(), 3.0);
    let (timestamp, marker) = next_written_window(&servers.series).await;
    assert_eq!(timestamp, BASE_WINDOW_START_NANOS);
    assert_eq!(marker.time_series_id, "1", "the marker follows the IP row");
    assert_eq!(marker.series, [1.0, *generation]);
    let map = timeout(TEST_TIMEOUT, wait_for_policy_ids(&path, &[policy.id], true))
        .await
        .expect("the grouped window is acknowledged");
    assert_eq!(
        stored_generation(&path),
        *generation,
        "the rows carry the generation stored for the request"
    );
    assert_eq!(
        map,
        HashMap::from([(policy.id.to_string(), BASE_WINDOW_START_NANOS)]),
        "the checkpoint is the policy's"
    );
    let queues: Vec<u32> = INGEST_CHANNEL.read().await.keys().copied().collect();
    assert_eq!(
        queues,
        [policy.id],
        "one ingest queue, keyed by the policy id"
    );

    drop(review);
    drop(policy_handle);
    cleanup_test_resources(coordinator, client_handle, servers.handles).await;
    INGEST_CHANNEL.write().await.clear();
}

/// Runs [`new_policy`] over a generator stream carrying `frames` and returns
/// the windows written before the first one starting at or after `until`, each
/// as its start, its series id and its values. The timer never fires and the
/// wall clock is never past a window, so windows close only by event time and
/// the result depends only on the frames.
async fn windows_of_generator_stream(
    frames: Vec<GeneratorFrame>,
    until: i64,
) -> Vec<(i64, String, Vec<f64>)> {
    const NEVER: Duration = Duration::from_secs(3600);
    let servers = start_window_servers_with(
        FakeGigantoServer::new_ingest(),
        FakeGigantoServer::new_publish()
            .with_publish_behavior(PublishBehavior::Records(frames.into())),
    );
    let coordinator = CancellationCoordinator::new();
    let (review, actor_task, _path, _dir, policy_handle) =
        setup_request_client(None, &coordinator).await;
    policy_handle
        .replace_policies(vec![new_policy(DEFAULT_POLICY_ID)])
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

    let mut windows = Vec::new();
    loop {
        let (start, series) = next_written_window(&servers.series).await;
        if start >= until {
            break;
        }
        windows.push((start, series.time_series_id, series.series));
    }

    drop(review);
    drop(policy_handle);
    cleanup_test_resources(coordinator, client_handle, servers.handles).await;
    windows
}

/// A replay-end frame is not an event: with the timer never firing, a stream
/// with the frame between two events writes the same windows, in the same
/// order and with the same values, as the same stream without it. The frame
/// adds nothing to a window and does not move the stream's watermark.
#[serial]
#[tokio::test]
async fn replay_end_frame_does_not_change_the_written_windows() {
    let record = bincode::serialize(&gen_conn()).unwrap();
    let event = |timestamp| GeneratorFrame::Event(timestamp, record.clone());
    // Two events in the first window, then one in each of the next three
    // windows. Each of those is more than the grace past the end of the
    // window before it, so the stream passes that window, which closes; the
    // last closes the third, whose write ends the run.
    let frames = |replay_end: bool| {
        let mut frames = vec![event(BASE_TS_NANOS)];
        if replay_end {
            // Giganto sends the request's start here. A later time makes a
            // frame that moved the watermark close the first window before
            // its second event, which would write it twice.
            frames.push(GeneratorFrame::ReplayEnd(BASE_TS_NANOS + 10 * DAY_NANOS));
        }
        frames.extend([
            event(BASE_TS_NANOS + 1),
            event(BASE_TS_NANOS + DAY_NANOS),
            event(BASE_TS_NANOS + 2 * DAY_NANOS),
            event(BASE_TS_NANOS + 3 * DAY_NANOS),
        ]);
        frames
    };
    let until = BASE_WINDOW_START_NANOS + 2 * DAY_NANOS;

    let without = windows_of_generator_stream(frames(false), until).await;
    let with = windows_of_generator_stream(frames(true), until).await;

    let sums: Vec<(i64, f64)> = without
        .iter()
        .map(|(start, _, values)| (*start, values.iter().sum()))
        .collect();
    assert_eq!(
        sums,
        [
            (BASE_WINDOW_START_NANOS, 2.0),
            (BASE_WINDOW_START_NANOS + DAY_NANOS, 1.0),
        ]
    );
    assert_eq!(with, without);
}

/// A window and its correction reach Giganto in the order they were written,
/// so the corrected value is the one stored, even when the original write is
/// slow to arrive. The correction follows the close at once: the late event is
/// sent with no delay after the event that closes the window.
#[serial]
#[tokio::test]
async fn window_correction_is_stored_after_the_window_it_replaces() {
    let mut publish_server = FakeGigantoServer::new_publish().with_publish_timestamps(vec![
        BASE_TS_NANOS,
        BASE_TS_NANOS + DAY_NANOS,
        BASE_TS_NANOS + 1,
    ]);
    publish_server.publish_repeat_delay = Duration::ZERO;
    let servers = start_window_servers_with(
        FakeGigantoServer::new_ingest()
            .with_ingest_behavior(IngestBehavior::DelayFirstStream(Duration::from_millis(500))),
        publish_server,
    );
    let coordinator = CancellationCoordinator::new();
    let (mut review, actor_task, path, _dir, policy_handle) =
        setup_request_client(None, &coordinator).await;
    let policy = new_policy(DEFAULT_POLICY_ID);
    review
        .time_series_generation_policy_list(std::slice::from_ref(&policy))
        .await
        .unwrap();
    // Not past any window's end: only events close windows in this test.
    let not_due = CloseTimer::new(
        || BASE_TS_NANOS / 1_000_000_000,
        Duration::from_millis(50),
        Duration::ZERO,
    );
    let client_handle = spawn_subscribe_client_with_timer(
        &cert_key(),
        actor_task,
        servers.ingest_addr,
        servers.publish_addr,
        policy_handle.clone(),
        coordinator.clone(),
        not_due,
    );

    let written = [
        next_written_window(&servers.series).await,
        next_written_window(&servers.series).await,
    ];
    assert_eq!(written[0].0, BASE_WINDOW_START_NANOS);
    assert_eq!(written[1].0, BASE_WINDOW_START_NANOS);
    assert_eq!(
        written.map(|(_, series)| series.series.iter().sum::<f64>()),
        [1.0, 2.0],
        "the correction is stored last"
    );
    let map = timeout(TEST_TIMEOUT, wait_for_policy_ids(&path, &[policy.id], true))
        .await
        .expect("the window is acknowledged");
    assert_eq!(map[&policy.id.to_string()], BASE_WINDOW_START_NANOS);

    drop(review);
    drop(policy_handle);
    cleanup_test_resources(coordinator, client_handle, servers.handles).await;
}

/// The window open at shutdown is not written. The next run resumes at the
/// saved checkpoint, rewrites that window from the replay, writes the one that
/// was open once a later event closes it, and never writes a zero row.
#[serial]
#[tokio::test]
async fn restart_writes_the_window_open_at_shutdown_and_no_zero_row() {
    let first_window = vec![BASE_TS_NANOS, BASE_TS_NANOS + 1, BASE_TS_NANOS + 2];
    let open_window = BASE_TS_NANOS + DAY_NANOS;
    let open_window_start = BASE_WINDOW_START_NANOS + DAY_NANOS;
    let policy = new_policy(DEFAULT_POLICY_ID);
    // Not past any window's end: only events close windows in this test.
    let not_due = || {
        CloseTimer::new(
            || BASE_TS_NANOS / 1_000_000_000,
            Duration::from_millis(50),
            Duration::ZERO,
        )
    };

    // --- First run: the first window is written, the next one stays open ---
    let mut first_run = first_window.clone();
    first_run.push(open_window);
    let servers = start_window_servers(first_run);
    let coordinator = CancellationCoordinator::new();
    let (mut review, actor_task, path, dir, policy_handle) =
        setup_request_client(None, &coordinator).await;
    review
        .time_series_generation_policy_list(std::slice::from_ref(&policy))
        .await
        .unwrap();
    let client_handle = spawn_subscribe_client_with_timer(
        &cert_key(),
        actor_task,
        servers.ingest_addr,
        servers.publish_addr,
        policy_handle.clone(),
        coordinator.clone(),
        not_due(),
    );
    let (timestamp, series) = next_written_window(&servers.series).await;
    assert_eq!(timestamp, BASE_WINDOW_START_NANOS);
    assert_eq!(series.series.iter().sum::<f64>(), 3.0);
    timeout(TEST_TIMEOUT, wait_for_policy_ids(&path, &[policy.id], true))
        .await
        .expect("the first window is acknowledged");
    // Give the worker time to count the event of the open window.
    sleep(Duration::from_millis(300)).await;
    drop(review);
    drop(policy_handle);
    cleanup_test_resources(coordinator, client_handle, servers.handles).await;
    assert!(
        servers.series.try_recv().is_err(),
        "the window open at shutdown must not be written"
    );
    assert_eq!(
        read_time_data_map(&path)[&policy.id.to_string()],
        BASE_WINDOW_START_NANOS
    );

    // --- Second run: resume from the saved checkpoint ---
    let mut second_run = first_window;
    second_run.extend([open_window, open_window + DAY_NANOS]);
    let servers = start_window_servers(second_run);
    let coordinator = CancellationCoordinator::new();
    let (mut review, actor_task, _, _keep_dir, policy_handle) =
        setup_request_client(Some(&path), &coordinator).await;
    review
        .time_series_generation_policy_list(std::slice::from_ref(&policy))
        .await
        .unwrap();
    assert_eq!(
        policy_handle
            .stream_policy(policy.id)
            .await
            .unwrap()
            .unwrap()
            .start,
        BASE_WINDOW_START_NANOS,
        "the resume starts at the last written window"
    );
    let client_handle = spawn_subscribe_client_with_timer(
        &cert_key(),
        actor_task,
        servers.ingest_addr,
        servers.publish_addr,
        policy_handle.clone(),
        coordinator.clone(),
        not_due(),
    );
    let written = [
        next_written_window(&servers.series).await,
        next_written_window(&servers.series).await,
    ];
    assert_eq!(
        written[0].0, BASE_WINDOW_START_NANOS,
        "rewritten from the replay"
    );
    assert_eq!(written[0].1.series.iter().sum::<f64>(), 3.0);
    assert_eq!(
        written[1].0, open_window_start,
        "the window open at shutdown"
    );
    assert_eq!(written[1].1.series.iter().sum::<f64>(), 1.0);
    let map = timeout(TEST_TIMEOUT, async {
        loop {
            let map = read_time_data_map(&path);
            if map.get(&policy.id.to_string()) == Some(&open_window_start) {
                return map;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the checkpoint advances to the window open at shutdown");
    assert_eq!(map.len(), 1);

    drop(review);
    drop(policy_handle);
    cleanup_test_resources(coordinator, client_handle, servers.handles).await;
    for (timestamp, series) in written
        .into_iter()
        .chain(std::iter::from_fn(|| servers.series.try_recv().ok()))
    {
        assert_ne!(timestamp, 0, "no window is written at 1970-01-01");
        assert!(
            series.series.iter().any(|value| *value != 0.0),
            "no all-zero window is written: {series:?}"
        );
    }
    drop(dir);
}

/// Servers whose Publish side answers every request with a stream carrying
/// `frames` and keeps it open, and whose Ingest side reports the rows of each
/// stored ingest frame together, as `(series id, timestamp, data)`.
struct FrameServers {
    frames: async_channel::Receiver<Vec<(i64, TimeSeries)>>,
    handles: TestServerHandlers,
    ingest_addr: SocketAddr,
    publish_addr: SocketAddr,
}

type StoredRow = (String, i64, Vec<f64>);

impl FrameServers {
    fn start(frames: Vec<GeneratorFrame>) -> Self {
        let (frame_send, frame_recv) = async_channel::unbounded();
        let ingest_server = FakeGigantoServer::new_ingest().with_frame_notify(frame_send);
        let publish_server = FakeGigantoServer::new_publish()
            .with_publish_behavior(PublishBehavior::Records(frames.into()));
        let ingest_shutdown = Arc::new(Notify::new());
        let publish_shutdown = Arc::new(Notify::new());
        let (ingest_addr, ingest_handle) = ingest_server.start_ingest(ingest_shutdown.clone());
        let (publish_addr, publish_handle) = publish_server.start_publish(publish_shutdown.clone());
        Self {
            frames: frame_recv,
            handles: TestServerHandlers {
                ingest_shutdown,
                publish_shutdown,
                ingest_handle,
                publish_handle,
            },
            ingest_addr,
            publish_addr,
        }
    }

    /// Returns the rows of the next stored ingest frame.
    async fn next(&self) -> Vec<StoredRow> {
        timeout(TEST_TIMEOUT, self.frames.recv())
            .await
            .expect("a frame is stored before the test deadline")
            .expect("the frame channel stays open")
            .into_iter()
            .map(|(timestamp, row)| (row.time_series_id, timestamp, row.series))
            .collect()
    }
}

/// A raw Conn event from `orig` to an external IP at `timestamp`.
fn conn_from(timestamp: i64, orig: &str) -> GeneratorFrame {
    let conn = Conn {
        orig_addr: orig.parse().unwrap(),
        resp_addr: "8.8.8.8".parse().unwrap(),
        ..gen_conn()
    };
    GeneratorFrame::Event(timestamp, bincode::serialize(&conn).unwrap())
}

const IP_A: &str = "192.168.4.76";
const IP_B: &str = "192.168.4.77";
const EXTERNAL_IP: &str = "8.8.8.8";

/// [`new_policy`] grouped by source over `192.168.4.0/24`.
fn grouped_policy() -> TimeSeriesGenerationPolicy {
    let mut policy = new_policy(DEFAULT_POLICY_ID);
    policy.group_by = Some(review_protocol::types::EndpointRole::Source);
    policy.internal_networks = HostNetworkGroup {
        hosts: Vec::new(),
        networks: vec!["192.168.4.0/24".parse().unwrap()],
        ip_ranges: Vec::new(),
    };
    policy
}

/// A 1-day IP row of [`new_policy`] whose only event is in the slot of
/// [`BASE_TS_NANOS`] (88), as stored: its slots, then `generation`.
fn base_slot_row(id: &str, window_start: i64, count: f64, generation: f64) -> StoredRow {
    let mut data = vec![0.0; 96];
    data[88] = count;
    data.push(generation);
    (id.to_owned(), window_start, data)
}

/// The marker of the window starting at `window_start`, as stored.
fn stored_marker(window_start: i64, rows: f64, generation: f64) -> StoredRow {
    (
        DEFAULT_POLICY_ID.to_string(),
        window_start,
        vec![rows, generation],
    )
}

/// Returns the generation the checkpoint file holds for the default policy.
#[allow(clippy::cast_precision_loss)] // Generations are below 2^53.
fn stored_generation(path: &Path) -> f64 {
    read_checkpoints(path)[&DEFAULT_POLICY_ID.to_string()]
        .1
        .expect("a grouped request stores its generation") as f64
}

/// Runs [`grouped_policy`] over [`FrameServers`] carrying `frames`, with its
/// checkpoint file at `path` if given, and windows closing by event time
/// only.
struct GroupedRun {
    coordinator: CancellationCoordinator,
    review: crate::request::Client,
    policy_handle: PolicyHandle,
    client_handle: tokio::task::JoinHandle<()>,
    servers: FrameServers,
    path: PathBuf,
    dir: TempDir,
}

impl GroupedRun {
    async fn start(path: Option<&Path>, frames: Vec<GeneratorFrame>) -> Self {
        const NEVER: Duration = Duration::from_secs(3600);
        INGEST_CHANNEL.write().await.clear();
        let servers = FrameServers::start(frames);
        let coordinator = CancellationCoordinator::new();
        let (mut review, actor_task, path, dir, policy_handle) =
            setup_request_client(path, &coordinator).await;
        review
            .time_series_generation_policy_list(&[grouped_policy()])
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
        Self {
            coordinator,
            review,
            policy_handle,
            client_handle,
            servers,
            path,
            dir,
        }
    }

    /// Stops the run and returns the directory it was given or created.
    async fn stop(self) -> TempDir {
        drop(self.review);
        drop(self.policy_handle);
        cleanup_test_resources(self.coordinator, self.client_handle, self.servers.handles).await;
        self.dir
    }
}

/// A grouped close writes each IP row, ending with the run's generation, in
/// its own frame and then the marker. After the marker, a new IP's row and
/// the marker counting it arrive in one frame, and an existing IP's
/// correction alone. A window without IP rows closes with `[0, generation]`
/// once an event passes it, and a late event there writes its row and
/// `[1, generation]` in one frame.
#[serial]
#[tokio::test]
async fn grouped_corrections_after_the_marker_arrive_in_one_frame() {
    let w0 = BASE_WINDOW_START_NANOS;
    let w1 = BASE_WINDOW_START_NANOS + DAY_NANOS;
    let run = GroupedRun::start(
        None,
        vec![
            conn_from(BASE_TS_NANOS, IP_A),
            // Passes w0, which closes; w1 counts nothing.
            conn_from(BASE_TS_NANOS + DAY_NANOS, EXTERNAL_IP),
            conn_from(BASE_TS_NANOS + 1, IP_B),
            conn_from(BASE_TS_NANOS + 2, IP_A),
            // Passes w1, which closes without IP rows.
            conn_from(BASE_TS_NANOS + 2 * DAY_NANOS, EXTERNAL_IP),
            conn_from(BASE_TS_NANOS + DAY_NANOS + 1, IP_A),
        ],
    )
    .await;
    let first = run.servers.next().await;
    let generation = stored_generation(&run.path);
    assert_eq!(
        first,
        [base_slot_row("1/192.168.4.76", w0, 1.0, generation)],
        "the generation stored for the request"
    );
    assert_eq!(
        run.servers.next().await,
        [stored_marker(w0, 1.0, generation)]
    );
    assert_eq!(
        run.servers.next().await,
        [
            base_slot_row("1/192.168.4.77", w0, 1.0, generation),
            stored_marker(w0, 2.0, generation),
        ],
        "a new IP's row and the marker in one frame"
    );
    assert_eq!(
        run.servers.next().await,
        [base_slot_row("1/192.168.4.76", w0, 2.0, generation)],
        "a correction alone"
    );
    assert_eq!(
        run.servers.next().await,
        [stored_marker(w1, 0.0, generation)],
        "a window without IP rows"
    );
    assert_eq!(
        run.servers.next().await,
        [
            base_slot_row("1/192.168.4.76", w1, 1.0, generation),
            stored_marker(w1, 1.0, generation),
        ],
        "a late row in a window without IP rows, with the marker"
    );
    drop(run.stop().await);
}

/// After a stop following the ACK of window T, a restart requests from T
/// with a greater generation, which is on disk before its first row, and
/// rewrites T and the later windows with it, IP rows before each marker. No
/// window before T is written again.
#[serial]
#[tokio::test]
async fn grouped_restart_rewrites_from_the_checkpoint_with_a_new_generation() {
    let w0 = BASE_WINDOW_START_NANOS;
    let w1 = BASE_WINDOW_START_NANOS + DAY_NANOS;
    let run = GroupedRun::start(
        None,
        vec![
            conn_from(BASE_TS_NANOS, IP_A),
            conn_from(BASE_TS_NANOS + 1, IP_B),
            conn_from(BASE_TS_NANOS + DAY_NANOS, IP_A),
        ],
    )
    .await;
    let mut written = Vec::new();
    for _ in 0..3 {
        written.extend(run.servers.next().await);
    }
    let first = stored_generation(&run.path);
    assert_eq!(
        written,
        [
            base_slot_row("1/192.168.4.76", w0, 1.0, first),
            base_slot_row("1/192.168.4.77", w0, 1.0, first),
            stored_marker(w0, 2.0, first),
        ]
    );
    let checkpoint = timeout(TEST_TIMEOUT, async {
        loop {
            if let Some(timestamp) =
                read_time_data_map(&run.path).get(&DEFAULT_POLICY_ID.to_string())
            {
                return *timestamp;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the window is acknowledged");
    assert_eq!(checkpoint, w0);
    let path = run.path.clone();
    let dir = run.stop().await;

    let run = GroupedRun::start(
        Some(&path),
        vec![
            // Before the checkpoint: not part of the resumed request.
            conn_from(BASE_TS_NANOS - DAY_NANOS, IP_B),
            conn_from(BASE_TS_NANOS, IP_A),
            conn_from(BASE_TS_NANOS + DAY_NANOS, IP_A),
            conn_from(BASE_TS_NANOS + 2 * DAY_NANOS, EXTERNAL_IP),
        ],
    )
    .await;
    let first_frame = run.servers.next().await;
    let second = stored_generation(&path);
    assert!(second > first, "{second} > {first}");
    let mut written = first_frame;
    for _ in 0..3 {
        written.extend(run.servers.next().await);
    }
    assert_eq!(
        written,
        [
            base_slot_row("1/192.168.4.76", w0, 1.0, second),
            stored_marker(w0, 1.0, second),
            base_slot_row("1/192.168.4.76", w1, 1.0, second),
            stored_marker(w1, 1.0, second),
        ],
        "T is rewritten with the IPs of this run, then the later window"
    );
    drop(run.stop().await);
    drop(dir);
}

/// Verifies that a policy queued in an ending `run()` generation cannot be
/// consumed by the next generation after reload.
#[serial]
#[tokio::test(flavor = "current_thread")]
async fn reload_does_not_open_policy_queued_by_previous_run() {
    let policy = new_policy(DEFAULT_POLICY_ID);
    let (manager_addr, sync_events, manager_shutdown, manager_handle) =
        start_reload_policy_manager(policy);

    let (stalled_ingest_addr, stalled_ingest_shutdown, stalled_ingest_handle) =
        start_stalled_giganto_endpoint();
    let (stalled_publish_addr, stalled_publish_shutdown, stalled_publish_handle) =
        start_stalled_giganto_endpoint();

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let config_path = temp_dir.path().join("crusher.toml");
    let timestamp_path = temp_dir.path().join("time_data.json");
    write_run_config(
        &config_path,
        &timestamp_path,
        stalled_ingest_addr,
        stalled_publish_addr,
    );

    let cert_pem = fs::read(CERT_PATH).expect("read client cert");
    let key_pem = fs::read(KEY_PATH).expect("read client key");
    let ca_pem = fs::read(CA_CERT_PATH).expect("read CA cert");
    let certs = cert_key();
    let request_client = crate::request::Client::new(
        manager_addr,
        HOST.to_string(),
        SharedTlsBytes::new(TlsBytes::new(cert_pem, key_pem, vec![ca_pem])),
        Arc::new(Notify::new()),
    );
    let args = crate::CmdLineArgs {
        config: Some(config_path.to_str().expect("UTF-8 config path").to_string()),
        cert: CERT_PATH.to_string(),
        key: KEY_PATH.to_string(),
        ca_certs: vec![CA_CERT_PATH.to_string()],
        manager_server: format!("{HOST}@{manager_addr}")
            .parse()
            .expect("manager server address"),
    };

    let first_tls_reload = Arc::new(Notify::new());
    let first_tls_reload_for_driver = first_tls_reload.clone();
    let first_run = async {
        let driver = async {
            assert_eq!(sync_events.recv().await.expect("first policy sync"), 1);
            // The manager event is emitted just before its response is returned.
            // Give the policy actor time to register the restored policy while
            // the stalled publish handshake prevents it from being consumed.
            sleep(Duration::from_millis(200)).await;
            first_tls_reload_for_driver.notify_one();
        };
        let (result, ()) = tokio::join!(
            crate::run(
                &args,
                &certs,
                request_client.clone(),
                Arc::new(Notify::new()),
                first_tls_reload,
                Arc::new(Notify::new()),
            ),
            driver,
        );
        result
    };
    let first_reason = timeout(Duration::from_secs(5), first_run)
        .await
        .expect("first run exits after reload")
        .expect("first run succeeds");
    assert_eq!(first_reason, crate::RunExitReason::TlsReload);

    stalled_ingest_shutdown.notify_one();
    stalled_publish_shutdown.notify_one();
    let _ = tokio::join!(stalled_ingest_handle, stalled_publish_handle);

    let ingest_shutdown = Arc::new(Notify::new());
    let publish_shutdown = Arc::new(Notify::new());
    let (ingest_addr, ingest_handle) =
        FakeGigantoServer::new_ingest().start_ingest(ingest_shutdown.clone());
    let (open_send, open_recv) = async_channel::bounded(1);
    let (peer_send, peer_recv) = async_channel::bounded(1);
    let publish_server = FakeGigantoServer::new_publish()
        .with_publish_behavior(PublishBehavior::RecordRequests { sender: open_send })
        .with_peer_cert_notify(peer_send);
    let (publish_addr, publish_handle) = publish_server.start_publish(publish_shutdown.clone());
    write_run_config(&config_path, &timestamp_path, ingest_addr, publish_addr);

    let second_shutdown = Arc::new(Notify::new());
    let second_shutdown_for_driver = second_shutdown.clone();
    let second_run = async {
        let driver = async {
            assert_eq!(sync_events.recv().await.expect("second policy sync"), 2);
            let (path, _) = timeout(Duration::from_secs(3), peer_recv.recv())
                .await
                .expect("second publish connection")
                .expect("peer event channel open");
            assert_eq!(path, ConnectionPath::Publish);
            assert!(
                timeout(Duration::from_millis(300), open_recv.recv())
                    .await
                    .is_err(),
                "the new run must not open a policy queued by the previous run",
            );
            second_shutdown_for_driver.notify_one();
        };
        let (result, ()) = tokio::join!(
            crate::run(
                &args,
                &certs,
                request_client,
                Arc::new(Notify::new()),
                Arc::new(Notify::new()),
                second_shutdown,
            ),
            driver,
        );
        result
    };
    let second_reason = timeout(Duration::from_secs(5), second_run)
        .await
        .expect("second run exits after shutdown")
        .expect("second run succeeds");
    assert_eq!(second_reason, crate::RunExitReason::Shutdown);

    ingest_shutdown.notify_one();
    publish_shutdown.notify_one();
    manager_shutdown.notify_one();
    let _ = tokio::join!(ingest_handle, publish_handle, manager_handle);
}

/// Spawns a subscribe client wired to a publish endpoint with the
/// given [`PublishBehavior`]. Returns the resources the test needs to
/// observe ACKs and tear everything down.
async fn run_with_publish_behavior(
    policies: &[TimeSeriesGenerationPolicy],
    behavior: PublishBehavior,
) -> (
    CancellationCoordinator,
    crate::request::Client,
    PolicyHandle,
    tokio::task::JoinHandle<()>,
    TestServerHandlers,
    async_channel::Receiver<u32>,
    PathBuf,
    TempDir,
) {
    let (ingest_ack_send, ingest_ack_recv) = async_channel::bounded::<u32>(10);
    let ingest_server = FakeGigantoServer::new_ingest().with_notify(ingest_ack_send);
    let publish_server = FakeGigantoServer::new_publish().with_publish_behavior(behavior);
    let ingest_shutdown = Arc::new(Notify::new());
    let publish_shutdown = Arc::new(Notify::new());
    let (ingest_addr, ingest_handle) = ingest_server.start_ingest(ingest_shutdown.clone());
    let (publish_addr, publish_handle) = publish_server.start_publish(publish_shutdown.clone());

    let certs = cert_key();
    let coordinator = CancellationCoordinator::new();
    let (mut request_client, actor_task, last_time_series_path, temp_dir, policy_handle) =
        setup_request_client(None, &coordinator).await;
    request_client
        .time_series_generation_policy_list(policies)
        .await
        .unwrap();

    let client_handle = spawn_subscribe_client(
        &certs,
        actor_task,
        ingest_addr,
        publish_addr,
        policy_handle.clone(),
        coordinator.clone(),
    );

    (
        coordinator,
        request_client,
        policy_handle,
        client_handle,
        TestServerHandlers {
            ingest_shutdown,
            publish_shutdown,
            ingest_handle,
            publish_handle,
        },
        ingest_ack_recv,
        last_time_series_path,
        temp_dir,
    )
}

/// Deleting and then re-adding a policy on a live connection must create a
/// fresh stream. The deleted policy's stream has already arrived, so its
/// cancelled request can be dropped and the ID requested again on the same
/// connection.
#[serial]
#[tokio::test]
async fn delete_then_readd_same_id_starts_fresh_stream() {
    let policy = new_policy(DEFAULT_POLICY_ID);
    let mut harness = TestHarness::new(std::slice::from_ref(&policy)).await;

    // Initial add: observe ACK + timestamp.
    let id = harness.wait_for_ack().await;
    assert_eq!(id, policy.id);
    let _ = harness.wait_for_timestamp(&[policy.id]).await;

    // Successful deletion removes the checkpoint directly in the policy actor.
    harness
        .request_client
        .delete_time_series_generation_policy(&[policy.id])
        .await
        .unwrap();
    let map_after_delete = harness.wait_for_timestamp_removed(&[policy.id]).await;
    assert_eq!(map_after_delete.get(&policy.id.to_string()), None);

    // Re-add the same policy id on the same live publish connection.
    // The subscribe client must send a fresh stream request and
    // the fake server must respond with a new inbound stream — which
    // drives a fresh ACK back through the ingest path.
    harness
        .request_client
        .time_series_generation_policy_list(std::slice::from_ref(&policy))
        .await
        .unwrap();

    let id = harness.wait_for_ack().await;
    assert_eq!(
        id, policy.id,
        "re-added policy must produce a fresh ACK on the same live connection"
    );
    let map_after_readd = harness.wait_for_timestamp(&[policy.id]).await;
    assert!(
        map_after_readd.contains_key(&policy.id.to_string()),
        "the active policy must accept new ACKs after re-registration"
    );

    harness.cleanup().await;
}

/// Regression test for delete teardown on the ingest side: deleting a
/// policy must stop the active `send_time_series` task and remove its
/// `INGEST_CHANNEL` entry. Without this, an old sender could survive
/// the delete and interfere with later work for the same id.
#[serial]
#[tokio::test]
async fn delete_policy_tears_down_ingest_channel_entry() {
    let policy = new_policy(DEFAULT_POLICY_ID);
    let mut harness = TestHarness::new(std::slice::from_ref(&policy)).await;

    let id = harness.wait_for_ack().await;
    assert_eq!(id, policy.id);
    let _ = harness.wait_for_timestamp(&[policy.id]).await;

    // `INGEST_CHANNEL` is populated after the first `send_time_series`
    // opens its bi-di stream and installs its sender. Wait for it so
    // the delete below has something to tear down.
    wait_for_ingest_channel(policy.id, true)
        .await
        .expect("INGEST_CHANNEL entry must appear after first ACK");

    harness
        .request_client
        .delete_time_series_generation_policy(&[policy.id])
        .await
        .unwrap();
    let _ = harness.wait_for_timestamp_removed(&[policy.id]).await;

    wait_for_ingest_channel(policy.id, false)
        .await
        .expect("INGEST_CHANNEL entry must be cleared when the policy is deleted");

    harness.cleanup().await;
}

async fn wait_for_ingest_channel(policy_id: u32, should_exist: bool) -> Result<(), ()> {
    timeout(Duration::from_secs(5), async {
        loop {
            let present = INGEST_CHANNEL.read().await.contains_key(&policy_id);
            if present == should_exist {
                return;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .map_err(|_| ())
}

/// Test: Inbound streams must be dispatched by the policy id read off
/// the wire, not by the order in which the requests went out. Here the
/// publish server collects both stream requests and then opens uni
/// streams in REVERSE order; both policies must still receive the
/// correct ACKs because the dispatcher binds streams by id.
#[serial]
#[tokio::test]
async fn inbound_stream_dispatch_is_id_keyed() {
    let policy_a = new_policy(1);
    let policy_b = new_policy(2);
    let (
        coordinator,
        request_client,
        policy_handle,
        client_handle,
        server_handles,
        ingest_ack_recv,
        _,
        _temp,
    ) = run_with_publish_behavior(
        &[policy_a.clone(), policy_b.clone()],
        PublishBehavior::ReverseOrder { expected: 2 },
    )
    .await;

    let mut expected_ids = vec![policy_a.id, policy_b.id];
    for _ in 0..2 {
        // Each stream's window is written when its closing event arrives, and
        // the server emits the reversed streams one after the other.
        let id = timeout(TEST_TIMEOUT, ingest_ack_recv.recv())
            .await
            .expect("ACK should arrive before the test deadline")
            .expect("ACK channel should remain open");
        expected_ids.retain(|e| *e != id);
    }
    assert!(
        expected_ids.is_empty(),
        "Both policies should receive correct ACKs even with reversed stream arrival: {expected_ids:?}"
    );

    drop(request_client);
    drop(policy_handle);
    cleanup_test_resources(coordinator, client_handle, server_handles).await;
}

/// Test: A uni stream that announces a policy id the dispatcher does
/// not know about (e.g., a delete that raced with stream-open on the
/// server side) must be dropped silently; subsequent valid streams on
/// the same connection must continue to work normally.
#[serial]
#[tokio::test]
async fn inbound_stream_for_unknown_policy_is_dropped() {
    let policy = new_policy(DEFAULT_POLICY_ID);
    let (
        coordinator,
        request_client,
        policy_handle,
        client_handle,
        server_handles,
        ingest_ack_recv,
        _,
        _temp,
    ) = run_with_publish_behavior(
        std::slice::from_ref(&policy),
        PublishBehavior::StaleIdFirst { stale_id: 9999 },
    )
    .await;

    // The real policy's ACK must still arrive even though the
    // dispatcher saw an unknown-id stream first.
    let id = timeout(Duration::from_secs(5), ingest_ack_recv.recv())
        .await
        .expect("ACK for the real policy must arrive within 5s")
        .expect("ACK channel should remain open");
    assert_eq!(id, policy.id);

    drop(request_client);
    drop(policy_handle);
    cleanup_test_resources(coordinator, client_handle, server_handles).await;
}

/// Test: When a policy is deleted between the request being sent and
/// the inbound stream arriving, the dispatcher must drop the orphaned
/// stream silently. Other policies on the same connection must still
/// receive their streams normally.
#[serial]
#[tokio::test]
async fn inbound_stream_arrival_after_delete_is_dropped() {
    let policy_a = new_policy(1);
    let policy_b = new_policy(2);
    let request_received = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let (
        coordinator,
        mut request_client,
        policy_handle,
        client_handle,
        server_handles,
        ingest_ack_recv,
        _,
        _temp,
    ) = run_with_publish_behavior(
        &[policy_a.clone(), policy_b.clone()],
        PublishBehavior::HoldUntilSignal {
            expected: 2,
            request_received: request_received.clone(),
            release: release.clone(),
        },
    )
    .await;

    // Server has both stream requests in hand and is now blocked on
    // `release`. Delete policy_a before its inbound stream is opened.
    timeout(Duration::from_secs(5), request_received.notified())
        .await
        .expect("server should receive both stream requests within 5s");
    request_client
        .delete_time_series_generation_policy(&[policy_a.id])
        .await
        .unwrap();

    // Let the server open both inbound streams. The dispatcher must
    // bind policy_b normally and drop policy_a (deleted) silently.
    release.notify_one();

    // Collect ACKs until policy_b's window is written, which happens only
    // after the server has emitted both streams, then any that follow
    // shortly. Only policy_b should produce ACKs.
    let mut received = Vec::new();
    timeout(TEST_TIMEOUT, async {
        while !received.contains(&policy_b.id) {
            received.push(ingest_ack_recv.recv().await.expect("ACK channel open"));
        }
    })
    .await
    .expect("policy_b's window should be written");
    while let Ok(Ok(id)) = timeout(Duration::from_millis(800), ingest_ack_recv.recv()).await {
        received.push(id);
    }
    assert!(
        !received.contains(&policy_a.id),
        "deleted policy {} must not produce ACKs; got {received:?}",
        policy_a.id,
    );
    assert!(
        received.contains(&policy_b.id),
        "live policy {} must still produce ACKs after sibling delete; got {received:?}",
        policy_b.id,
    );

    drop(request_client);
    drop(policy_handle);
    cleanup_test_resources(coordinator, client_handle, server_handles).await;
}

/// Test: When a policy's content is replaced after its stream request went
/// out but before Giganto opened the inbound stream, that stream belongs to
/// the old content's request. The dispatcher must not bind it to the new
/// content, and the new content must be requested on a fresh Publish
/// connection, where its stream produces data.
#[serial]
#[tokio::test]
async fn delayed_stream_of_replaced_policy_is_not_bound_to_new_content() {
    let original = new_policy(DEFAULT_POLICY_ID);
    let replacement = TimeSeriesGenerationPolicy {
        measure: Measure::Sum(ConnField::Duration),
        ..original.clone()
    };
    let request_received = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let (
        coordinator,
        mut request_client,
        policy_handle,
        client_handle,
        server_handles,
        ingest_ack_recv,
        _,
        _temp,
    ) = run_with_publish_behavior(
        std::slice::from_ref(&original),
        PublishBehavior::HoldUntilSignal {
            expected: 1,
            request_received: request_received.clone(),
            release: release.clone(),
        },
    )
    .await;

    // Giganto holds the original request; replace the content before it
    // opens the inbound stream for that request.
    timeout(TEST_TIMEOUT, request_received.notified())
        .await
        .expect("server should receive the original stream request");
    request_client
        .time_series_generation_policy_list(std::slice::from_ref(&replacement))
        .await
        .unwrap();
    release.notify_one();

    // The delayed stream carries the original request's data. Bound to the
    // replacement it would produce windows, and so ACKs, for the new content.
    let early = timeout(Duration::from_millis(1500), ingest_ack_recv.recv()).await;
    assert!(
        early.is_err(),
        "the original request's stream must not produce data for the replacement: {early:?}"
    );

    // The replacement is requested on a new connection and its own stream
    // is processed normally.
    timeout(TEST_TIMEOUT, request_received.notified())
        .await
        .expect("the replacement should be requested on a new Publish connection");
    release.notify_one();
    let id = timeout(TEST_TIMEOUT, ingest_ack_recv.recv())
        .await
        .expect("ACK for the replacement should arrive")
        .expect("ACK channel should remain open");
    assert_eq!(id, replacement.id);
    assert_eq!(
        policy_handle
            .get_policy(replacement.id)
            .await
            .unwrap()
            .measure,
        replacement.measure
    );

    drop(request_client);
    drop(policy_handle);
    cleanup_test_resources(coordinator, client_handle, server_handles).await;
}

/// Acceptance test for issue #315: a real `SIGHUP` delivers through the
/// process-level handler into the TLS reload seam, the main-loop rerun
/// boundary rebuilds the shared `subscribe::Client`, and both ingest and
/// publish continue against the rebuilt endpoint. Rotating to mismatched
/// material must not swap the daemon's endpoint; ingest/publish keep
/// running against the last-known-good endpoint.
#[cfg(unix)]
#[serial]
#[tokio::test(flavor = "current_thread")]
async fn sighup_rerun_rebuilds_shared_endpoint_for_ingest_and_publish() {
    let (peer_cert_send, peer_cert_recv) = async_channel::bounded::<PeerCertEvent>(8);
    let (ingest_ack_recv, server_handles, ingest_addr, publish_addr) =
        start_servers_with_config(config_server(), config_server(), peer_cert_send.clone());

    // Stage the cert/key/CA on disk in a rotation-friendly location so the
    // test can mutate the files between SIGHUPs.
    let tls_dir = tempfile::tempdir().expect("tempdir");
    let cert_path = tls_dir.path().join("cert.pem");
    let key_path = tls_dir.path().join("key.pem");
    let ca_path = tls_dir.path().join("ca.pem");
    let cert_pem = fs::read(CERT_PATH).expect("read cert fixture");
    let key_pem = fs::read(KEY_PATH).expect("read key fixture");
    let ca_pem = fs::read(CA_CERT_PATH).expect("read ca fixture");
    fs::write(&cert_path, &cert_pem).expect("write cert");
    fs::write(&key_path, &key_pem).expect("write key");
    fs::write(&ca_path, &ca_pem).expect("write ca");

    let args = crate::CmdLineArgs {
        config: None,
        cert: cert_path.to_str().expect("utf-8 cert path").to_string(),
        key: key_path.to_str().expect("utf-8 key path").to_string(),
        ca_certs: vec![ca_path.to_str().expect("utf-8 ca path").to_string()],
        manager_server: "manager@127.0.0.1:38390"
            .parse()
            .expect("valid manager address"),
    };

    // Install the real SIGHUP handler used by main(). A libc::raise below
    // will traverse the same POSIX signal → tokio::signal::unix path the
    // daemon uses in production.
    let tls_reload = Arc::new(Notify::new());
    crate::register_tls_reload_signal_handler(tls_reload.clone());
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Iteration 1: register a policy, build the shared endpoint, and drive
    // both ingest and publish to a first ACK. Each iteration creates its own
    // policy actor and restores checkpoints from the same file, like main::run.
    let coordinator_1 = CancellationCoordinator::new();
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let last_time_series_path = temp_dir.path().join("time_data.json");
    let (policy_handle, actor_task) =
        spawn_policy_actor(last_time_series_path.clone(), &coordinator_1)
            .await
            .unwrap();
    let tls_bytes = crate::client::SharedTlsBytes::new(crate::client::TlsBytes::new(
        fs::read(CERT_PATH).unwrap(),
        fs::read(KEY_PATH).unwrap(),
        vec![fs::read(CA_CERT_PATH).unwrap()],
    ));
    let mut request_client = crate::request::Client::new(
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
        HOST.to_string(),
        tls_bytes,
        Arc::new(Notify::new()),
    );
    request_client.set_policy_handle(policy_handle.clone());
    let policy = new_policy(DEFAULT_POLICY_ID);
    request_client
        .time_series_generation_policy_list(std::slice::from_ref(&policy))
        .await
        .unwrap();

    let (mut certs, _raw_tls) = crate::load_tls_material_with_bytes(&args).expect("initial load");
    let initial_client_leaf_der = certs
        .certs
        .first()
        .expect("initial client leaf")
        .as_ref()
        .to_vec();
    let client_handle_1 = spawn_subscribe_client(
        &certs,
        actor_task,
        ingest_addr,
        publish_addr,
        policy_handle.clone(),
        coordinator_1.clone(),
    );

    let id = timeout(Duration::from_secs(5), ingest_ack_recv.recv())
        .await
        .expect("initial ingest ACK before SIGHUP")
        .expect("ingest ACK channel open");
    assert_eq!(id, policy.id);
    wait_for_peer_cert_paths(&peer_cert_recv, &initial_client_leaf_der).await;

    // Rotate to a genuinely new valid TLS set before SIGHUP so the reload path
    // must reread fresh files and converge to a new client certificate.
    let rotated = generate_rotated_tls_material();
    fs::write(&cert_path, &rotated.client_cert_pem).expect("rotate cert");
    fs::write(&key_path, &rotated.client_key_pem).expect("rotate key");
    fs::write(&ca_path, &rotated.ca_cert_pem).expect("rotate ca");

    // Act: deliver a real SIGHUP. The process-level handler must translate
    // it into a tls_reload notification.
    // SAFETY: `libc::raise` only targets the current process; no other
    // threads rely on the default SIGHUP disposition.
    unsafe {
        libc::raise(libc::SIGHUP);
    }
    timeout(Duration::from_secs(2), tls_reload.notified())
        .await
        .expect("SIGHUP delivers tls_reload notification");

    // Drive the main-loop rerun boundary: shutdown the existing shared
    // endpoint, reload TLS material from disk, and rebuild the shared
    // subscribe::Client. This mirrors the `RunExitReason::TlsReload` branch
    // in `main::main`.
    drop(policy_handle);
    drop(request_client);
    coordinator_1.request_cancellation("TLS reload rerun");
    let _ = client_handle_1.await;
    INGEST_CHANNEL.write().await.clear();
    cleanup_server_resources(server_handles).await;

    let (ingest_ack_recv, server_handles, ingest_addr, publish_addr) = start_servers_with_config(
        rotated.server_config.clone(),
        rotated.server_config.clone(),
        peer_cert_send.clone(),
    );

    (certs, _) = crate::load_tls_material_with_bytes(&args).expect("valid material reloads");
    assert_eq!(
        certs.certs.first().expect("reloaded client leaf").as_ref(),
        rotated.client_leaf_der.as_slice(),
        "rerun should reload the rotated client certificate",
    );
    let coordinator_2 = CancellationCoordinator::new();
    let (policy_handle, actor_task) =
        spawn_policy_actor(last_time_series_path.clone(), &coordinator_2)
            .await
            .unwrap();
    let mut request_client = crate::request::Client::new(
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
        HOST.to_string(),
        crate::client::SharedTlsBytes::new(crate::client::TlsBytes::new(
            fs::read(CERT_PATH).unwrap(),
            fs::read(KEY_PATH).unwrap(),
            vec![fs::read(CA_CERT_PATH).unwrap()],
        )),
        Arc::new(Notify::new()),
    );
    request_client.set_policy_handle(policy_handle.clone());
    request_client
        .time_series_generation_policy_list(std::slice::from_ref(&policy))
        .await
        .unwrap();
    let client_handle_2 = spawn_subscribe_client(
        &certs,
        actor_task,
        ingest_addr,
        publish_addr,
        policy_handle.clone(),
        coordinator_2.clone(),
    );

    // Assert: the rebuilt endpoint drives both ingest and publish end to end;
    // an ingest ACK arrives on the fresh connection opened with the reloaded
    // TLS material.
    let id = timeout(Duration::from_secs(5), ingest_ack_recv.recv())
        .await
        .expect("ingest ACK after SIGHUP-driven rebuild")
        .expect("ingest ACK channel open");
    assert_eq!(id, policy.id);
    wait_for_peer_cert_paths(&peer_cert_recv, &rotated.client_leaf_der).await;

    // Invalid-material case: rotate the key to an unrelated pair so the
    // loader's endpoint-build validation rejects the candidate certs.
    let unrelated = rcgen::KeyPair::generate().expect("generate unrelated key");
    fs::write(&key_path, unrelated.serialize_pem().as_bytes()).expect("rotate to bad key");

    // SAFETY: see earlier `libc::raise` call.
    unsafe {
        libc::raise(libc::SIGHUP);
    }
    timeout(Duration::from_secs(2), tls_reload.notified())
        .await
        .expect("second SIGHUP delivers tls_reload notification");

    // The main-loop would attempt to load the rotated material; this call
    // must fail and the caller must keep the last-known-good `certs`.
    let reload_err = crate::load_tls_material_with_bytes(&args)
        .err()
        .expect("mismatched material must be rejected");
    assert!(
        format!("{reload_err:#}").contains("client endpoint"),
        "unexpected reload error: {reload_err:#}"
    );
    assert_eq!(
        certs
            .certs
            .first()
            .expect("last-known-good client leaf")
            .as_ref(),
        rotated.client_leaf_der.as_slice(),
        "failed reload must preserve the last-known-good rotated certificate",
    );

    // The existing subscribe::Client (still running with the last-known-good
    // endpoint) must keep processing new policies, proving that a failed
    // reload does not tear down ingest/publish. Adding a fresh policy to
    // the complete list forces a new publish stream request that must
    // yield an ACK.
    let extra_policy = new_policy(DEFAULT_POLICY_ID + 1);
    request_client
        .time_series_generation_policy_list(&[policy, extra_policy.clone()])
        .await
        .unwrap();
    let id = timeout(Duration::from_secs(5), ingest_ack_recv.recv())
        .await
        .expect("last-known-good endpoint keeps producing ACKs after failed reload")
        .expect("ingest ACK channel open");
    assert_eq!(id, extra_policy.id);

    drop(request_client);
    drop(policy_handle);
    cleanup_test_resources(coordinator_2, client_handle_2, server_handles).await;
    drop(temp_dir);
}

mod policy_lifecycle {
    use super::*;

    // This scope starts after the serial lock is acquired. It bounds actor replies
    // and setup too, not just the individual network waits and teardown joins.
    async fn run_test(future: impl std::future::Future<Output = ()>) {
        timeout(Duration::from_secs(60), future)
            .await
            .expect("policy lifecycle test completes within its deadline");
    }

    /// Runs the real Publish control loop against a QUIC peer which records requests
    /// without replying with data streams, to exercise pending-request deduplication
    /// and reconnection through the production watch loop.
    struct PublishProbe {
        requests: async_channel::Receiver<(
            Connection,
            RequestStreamRecord,
            RequestTimeSeriesGeneratorStream,
        )>,
        control: tokio::task::JoinHandle<Result<()>>,
        server: tokio::task::JoinHandle<()>,
        shutdown: Arc<Notify>,
        endpoint: Endpoint,
    }

    impl PublishProbe {
        fn start(handle: PolicyHandle, coordinator: CancellationCoordinator) -> Self {
            let (sender, requests) = async_channel::unbounded();
            let shutdown = Arc::new(Notify::new());
            let (addr, server) = FakeGigantoServer::new_publish()
                .with_publish_behavior(PublishBehavior::RecordRequests { sender })
                .start_publish(shutdown.clone());
            let endpoint = client::config(&cert_key()).unwrap();
            let client_endpoint = endpoint.clone();
            let (series, _unused) = async_channel::bounded(1);
            let control = tokio::spawn(async move {
                publish_connection_control(
                    series,
                    addr,
                    HOST,
                    &client_endpoint,
                    REQUIRED_GIGANTO_VERSION,
                    handle,
                    Arc::new(Notify::new()),
                    coordinator,
                    CloseTimer::default(),
                )
                .await
            });
            Self {
                requests,
                control,
                server,
                shutdown,
                endpoint,
            }
        }

        async fn next(&self) -> (Connection, RequestTimeSeriesGeneratorStream) {
            let (connection, _, request) = self.next_with_record().await;
            (connection, request)
        }

        async fn next_with_record(
            &self,
        ) -> (
            Connection,
            RequestStreamRecord,
            RequestTimeSeriesGeneratorStream,
        ) {
            timeout(RECONNECT_TEST_TIMEOUT, self.requests.recv())
                .await
                .unwrap()
                .unwrap()
        }

        async fn assert_no_additional_requests(&self) {
            // Call only after the expected request arrives. The production loop
            // keeps the stream open, so this is a bounded observation window,
            // not an assertion that snapshot processing has finished.
            match timeout(Duration::from_secs(1), self.requests.recv()).await {
                Err(_) => {}
                Ok(Ok((_, _, request))) => {
                    panic!("unexpected additional request: {}", request.id)
                }
                Ok(Err(error)) => panic!("Publish request channel closed unexpectedly: {error}"),
            }
        }

        async fn finish(self, coordinator: &CancellationCoordinator) {
            coordinator.request_cancellation("Publish probe complete");
            join_test_task("Publish control", self.control)
                .await
                .unwrap();
            self.endpoint.close(0u32.into(), &[]);
            self.shutdown.notify_one();
            join_test_task("Giganto Publish server", self.server).await;
        }
    }

    #[tokio::test]
    async fn add_then_delete_before_publish_connection_never_opens_deleted_policy() {
        run_test(async {
            let coordinator = CancellationCoordinator::new();
            let (mut review, actor, path, _dir, handle) =
                setup_request_client(None, &coordinator).await;
            review
                .time_series_generation_policy_list(&[new_policy(42)])
                .await
                .unwrap();
            handle.record_ack(42, 123).await.unwrap();
            review
                .delete_time_series_generation_policy(&[42])
                .await
                .unwrap();
            review
                .time_series_generation_policy_list(&[new_policy(7)])
                .await
                .unwrap();

            let probe = PublishProbe::start(handle.clone(), coordinator.clone());
            assert_eq!(probe.next().await.1.id, "7");
            probe.assert_no_additional_requests().await;
            assert!(!read_time_data_map(&path).contains_key("42"));
            probe.finish(&coordinator).await;
            drop(review);
            drop(handle);
            join_test_task("policy actor", actor).await.unwrap();
            assert!(coordinator.wait_for_drain(TEST_TIMEOUT).await);
        })
        .await;
    }

    #[tokio::test]
    async fn latest_snapshot_does_not_duplicate_pending_stream_requests() {
        run_test(async {
            let coordinator = CancellationCoordinator::new();
            let (mut review, actor, _, _dir, handle) =
                setup_request_client(None, &coordinator).await;
            let probe = PublishProbe::start(handle.clone(), coordinator.clone());
            review
                .time_series_generation_policy_list(&[new_policy(42)])
                .await
                .unwrap();
            assert_eq!(probe.next().await.1.id, "42");
            // The peer still has not opened the inbound stream for 42. Updating the
            // full snapshot with another policy must not send a second request for 42.
            review
                .time_series_generation_policy_list(&[new_policy(42), new_policy(7)])
                .await
                .unwrap();
            assert_eq!(probe.next().await.1.id, "7");
            probe.assert_no_additional_requests().await;
            probe.finish(&coordinator).await;
            drop(review);
            drop(handle);
            join_test_task("policy actor", actor).await.unwrap();
        })
        .await;
    }

    /// Only a policy of a network kind, ungrouped over every counterpart or
    /// grouped by single IP, is requested, once, for its kind and its sensor;
    /// every other policy in the same list, among them grouped policies by
    /// `OwnedNetwork`, is skipped and requests nothing.
    #[tokio::test]
    async fn only_runnable_policy_is_requested_for_its_kind_and_sensor() {
        run_test(async {
            let coordinator = CancellationCoordinator::new();
            let (mut review, actor, _, _dir, handle) =
                setup_request_client(None, &coordinator).await;
            let mut runnable = new_policy(7);
            runnable.raw_event_kind = PolicyRawEventKind::Dns;
            let mut skipped: Vec<TimeSeriesGenerationPolicy> = (1..=7).map(new_policy).collect();
            skipped[0].group_by = Some(review_protocol::types::EndpointRole::Source);
            skipped[0].group_by_unit = GroupByUnit::OwnedNetwork;
            skipped[1].group_by = Some(review_protocol::types::EndpointRole::Destination);
            skipped[1].group_by_unit = GroupByUnit::OwnedNetwork;
            skipped[2].counterpart_scope = CounterpartScope::Internal;
            skipped[3].counterpart_scope = CounterpartScope::External;
            skipped[4].sensors.clear();
            skipped[5].raw_event_kind = PolicyRawEventKind::ProcessCreate;
            skipped[6].raw_event_kind = PolicyRawEventKind::Dns;
            skipped[6].measure = Measure::Sum(ConnField::OrigBytes);
            skipped[6].id = 8;
            let mut list = skipped;
            list.push(runnable);
            review
                .time_series_generation_policy_list(&list)
                .await
                .unwrap();
            assert_eq!(handle.get_all_policy_ids(), [7]);

            let probe = PublishProbe::start(handle.clone(), coordinator.clone());
            let (_, record_type, request) = probe.next_with_record().await;
            assert_eq!(record_type, RequestStreamRecord::Dns);
            assert_eq!(request.id, "7");
            assert_eq!(request.sensor.as_deref(), Some("cluml"));
            assert_eq!(request.start, 0);
            probe.assert_no_additional_requests().await;
            probe.finish(&coordinator).await;
            drop(review);
            drop(handle);
            join_test_task("policy actor", actor).await.unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn reconnect_replays_active_policy_with_saved_resume_timestamp() {
        run_test(async {
            let coordinator = CancellationCoordinator::new();
            let (mut review, actor, _, _dir, handle) =
                setup_request_client(None, &coordinator).await;
            let mut policy = new_policy(42);
            policy.src_ip = Some("192.0.2.1".parse().unwrap());
            policy.dst_ip = Some("192.0.2.2".parse().unwrap());
            review
                .time_series_generation_policy_list(std::slice::from_ref(&policy))
                .await
                .unwrap();
            let probe = PublishProbe::start(handle.clone(), coordinator.clone());
            let (connection, first) = probe.next().await;
            assert_eq!(first.start, 0);
            assert_eq!(first.src_ip, policy.src_ip);
            assert_eq!(first.dst_ip, policy.dst_ip);
            assert_eq!(first.sensor.as_deref(), Some("cluml"));
            handle.record_ack(42, 123).await.unwrap();
            let _ = handle.stream_policy(42).await.unwrap();
            connection.close(0u32.into(), b"simulate Giganto connection loss");
            // No policy-change notification is emitted after disconnect.
            let (_, resumed) = probe.next().await;
            assert_eq!(resumed.id, "42");
            // The resume starts at the saved window itself, to write it again.
            assert_eq!(resumed.start, 123);
            assert_eq!(resumed.src_ip, policy.src_ip);
            assert_eq!(resumed.dst_ip, policy.dst_ip);
            assert_eq!(resumed.sensor.as_deref(), Some("cluml"));
            probe.finish(&coordinator).await;
            drop(review);
            drop(handle);
            join_test_task("policy actor", actor).await.unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn deletion_during_giganto_disconnect_persists_and_is_not_replayed() {
        run_test(async {
            let coordinator = CancellationCoordinator::new();
            let (mut review, actor, path, _dir, handle) =
                setup_request_client(None, &coordinator).await;
            review
                .time_series_generation_policy_list(&[new_policy(42)])
                .await
                .unwrap();
            let probe = PublishProbe::start(handle.clone(), coordinator.clone());
            let (connection, _) = probe.next().await;
            handle.record_ack(42, 123).await.unwrap();
            let _ = handle.stream_policy(42).await.unwrap();
            connection.close(0u32.into(), b"simulate Giganto connection loss");

            // Execute the same Review request handler while Publish is disconnected.
            timeout(
                TEST_TIMEOUT,
                review.delete_time_series_generation_policy(&[42]),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(!read_time_data_map(&path).contains_key("42"));
            review
                .time_series_generation_policy_list(&[new_policy(7)])
                .await
                .unwrap();
            assert_eq!(probe.next().await.1.id, "7");
            probe.finish(&coordinator).await;
            drop(review);
            drop(handle);
            join_test_task("policy actor", actor).await.unwrap();
            // Restart loads the actual file saved by the preceding run.
            let next_coordinator = CancellationCoordinator::new();
            let (next, next_actor) = spawn_policy_actor(path, &next_coordinator).await.unwrap();
            next.replace_policies(vec![new_policy(42)]).await.unwrap();
            assert_eq!(next.stream_policy(42).await.unwrap().unwrap().start, 0);
            drop(next);
            join_test_task("restarted policy actor", next_actor)
                .await
                .unwrap();
        })
        .await;
    }

    #[serial]
    #[tokio::test]
    async fn delete_after_publish_worker_finishes_still_removes_timestamp() {
        run_test(async {
            let coordinator = CancellationCoordinator::new();
            let (mut review, actor, path, _dir, handle) =
                setup_request_client(None, &coordinator).await;
            review
                .time_series_generation_policy_list(&[new_policy(42)])
                .await
                .unwrap();
            let state = handle.stream_policy(42).await.unwrap().unwrap();
            let shutdown = Arc::new(Notify::new());
            let mut fake = FakeGigantoServer::new_publish();
            fake.publish_repeat_delay = Duration::ZERO;
            let (addr, server) = fake.start_publish(shutdown.clone());
            let endpoint = client::config(&cert_key()).unwrap();
            let (connection, mut send) =
                publish_connect(&endpoint, addr, HOST, REQUIRED_GIGANTO_VERSION)
                    .await
                    .unwrap();
            process_network_stream(&mut send, &state, RequestStreamRecord::Conn)
                .await
                .unwrap();
            let mut recv = connection.accept_uni().await.unwrap();
            assert_eq!(
                receive_time_series_generator_stream_start_message(&mut recv)
                    .await
                    .unwrap(),
                42
            );
            let policy_token = state.token.clone();
            let connection_token = CancellationToken::new();
            let (sender, receiver) = async_channel::unbounded();
            let (stream_send, stream_recv) = mpsc::unbounded_channel();
            stream_send.send(recv).unwrap();
            let worker = coordinator.tracker().spawn(run_policy(
                state,
                stream_recv,
                sender,
                connection_token.clone(),
                coordinator.clone(),
                CloseTimer::default(),
                Arc::new(Notify::new()),
            ));
            // Join this worker itself, not an assumed total number of unrelated tasks.
            // Neither policy nor connection cancellation can account for its exit.
            join_test_task("Publish worker consumes EOF", worker)
                .await
                .unwrap();
            assert!(!policy_token.is_cancelled());
            assert!(!connection_token.is_cancelled());
            assert!(!coordinator.is_cancelled());
            assert!(connection.close_reason().is_none());
            assert_eq!(
                receiver.recv().await.unwrap().rows()[0].time_series_id,
                "42"
            );
            // Seed an acknowledged checkpoint after natural worker completion.
            handle.record_ack(42, 123).await.unwrap();
            let _ = handle.stream_policy(42).await.unwrap();
            assert_eq!(read_time_data_map(&path)["42"], 123);
            review
                .delete_time_series_generation_policy(&[42])
                .await
                .unwrap();
            assert!(!read_time_data_map(&path).contains_key("42"));
            assert!(handle.get_policy(42).await.is_none());
            coordinator.request_cancellation("EOF deletion test complete");
            endpoint.close(0u32.into(), &[]);
            shutdown.notify_one();
            join_test_task("Giganto Publish server", server).await;
            drop(review);
            drop(handle);
            join_test_task("policy actor", actor).await.unwrap();
            assert!(coordinator.wait_for_drain(TEST_TIMEOUT).await);
        })
        .await;
    }

    /// An ingest sender that drops a frame of a request stops that request.
    /// The request's runner then stops writing and signals a reconnect, whose
    /// request of the policy rewrites its windows with a new generation, while
    /// the policy itself stays active.
    #[serial]
    #[tokio::test]
    async fn runner_of_a_stopped_request_stops_and_signals_a_reconnect() {
        run_test(async {
            let coordinator = CancellationCoordinator::new();
            let (mut review, actor, _path, _dir, handle) =
                setup_request_client(None, &coordinator).await;
            review
                .time_series_generation_policy_list(&[new_policy(42)])
                .await
                .unwrap();
            let state = handle.stream_policy(42).await.unwrap().unwrap();
            let shutdown = Arc::new(Notify::new());
            let mut fake = FakeGigantoServer::new_publish().with_held_streams();
            fake.publish_repeat_delay = Duration::ZERO;
            let (addr, server) = fake.start_publish(shutdown.clone());
            let endpoint = client::config(&cert_key()).unwrap();
            let (connection, mut send) =
                publish_connect(&endpoint, addr, HOST, REQUIRED_GIGANTO_VERSION)
                    .await
                    .unwrap();
            process_network_stream(&mut send, &state, RequestStreamRecord::Conn)
                .await
                .unwrap();
            let mut recv = connection.accept_uni().await.unwrap();
            assert_eq!(
                receive_time_series_generator_stream_start_message(&mut recv)
                    .await
                    .unwrap(),
                42
            );
            let policy_token = state.token.clone();
            let connection_token = CancellationToken::new();
            let connection_notify = Arc::new(Notify::new());
            let reconnect = connection_notify.notified();
            tokio::pin!(reconnect);
            reconnect.as_mut().enable();
            let (sender, receiver) = async_channel::unbounded();
            let (stream_send, stream_recv) = mpsc::unbounded_channel();
            stream_send.send(recv).unwrap();
            let worker = coordinator.tracker().spawn(run_policy(
                state,
                stream_recv,
                sender,
                connection_token.clone(),
                coordinator.clone(),
                CloseTimer::default(),
                connection_notify.clone(),
            ));

            let written = timeout(TEST_TIMEOUT, receiver.recv())
                .await
                .expect("the runner writes its window")
                .unwrap();
            assert!(!written.run_stopped());
            // As an ingest sender does with a frame it drops.
            written.stop_run();
            timeout(TEST_TIMEOUT, reconnect)
                .await
                .expect("the runner signals a reconnect");
            join_test_task("runner of the stopped request", worker)
                .await
                .unwrap();
            assert!(!policy_token.is_cancelled(), "the policy stays active");
            assert!(!connection_token.is_cancelled());
            assert!(handle.get_policy(42).await.is_some());

            coordinator.request_cancellation("stopped request test complete");
            endpoint.close(0u32.into(), &[]);
            shutdown.notify_one();
            join_test_task("Giganto Publish server", server).await;
            drop(review);
            drop(handle);
            join_test_task("policy actor", actor).await.unwrap();
            assert!(coordinator.wait_for_drain(TEST_TIMEOUT).await);
        })
        .await;
    }

    /// The peer reads only the frame length, then withholds flow-control credit.
    /// Cancelling an in-progress frame must close the connection rather than append
    /// a different request to a partially written frame.
    async fn interrupt_blocked_request(delete_policy: bool) {
        let mut config = config_server();
        let transport = Arc::get_mut(&mut config.transport).unwrap();
        transport.stream_receive_window(1024u32.into());
        transport.receive_window(2048u32.into());
        let server_endpoint =
            Endpoint::server(config, SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0)).unwrap();
        let addr = server_endpoint.local_addr().unwrap();
        let (started, observed) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let connection = server_endpoint.accept().await.unwrap().await.unwrap();
            let (_send, mut recv) =
                server_handshake(&connection, &format!("={REQUIRED_GIGANTO_VERSION}"))
                    .await
                    .unwrap();
            let mut length = [0; 4];
            recv.read_exact(&mut length).await.unwrap();
            assert!(u32::from_be_bytes(length) > 2048);
            started.send(()).unwrap();
            connection.closed().await;
            drop(recv);
        });
        let coordinator = CancellationCoordinator::new();
        let (mut review, actor, _, _dir, handle) = setup_request_client(None, &coordinator).await;
        let mut policy = new_policy(42);
        policy.sensors = vec!["x".repeat(4 * 1024 * 1024)];
        review
            .time_series_generation_policy_list(&[policy])
            .await
            .unwrap();
        let endpoint = client::config(&cert_key()).unwrap();
        let control_endpoint = endpoint.clone();
        let control_handle = handle.clone();
        let control_coordinator = coordinator.clone();
        let (sender, _receiver) = async_channel::bounded(1);
        let control = tokio::spawn(async move {
            publish_connection_control(
                sender,
                addr,
                HOST,
                &control_endpoint,
                REQUIRED_GIGANTO_VERSION,
                control_handle,
                Arc::new(Notify::new()),
                control_coordinator,
                CloseTimer::default(),
            )
            .await
        });
        timeout(TEST_TIMEOUT, observed).await.unwrap().unwrap();
        assert!(!control.is_finished());
        if delete_policy {
            timeout(
                TEST_TIMEOUT,
                review.delete_time_series_generation_policy(&[42]),
            )
            .await
            .unwrap()
            .unwrap();
        } else {
            coordinator.request_cancellation("cancel blocked Publish request");
        }
        join_test_task("interrupted write closes connection", server).await;
        coordinator.request_cancellation("blocked write test complete");
        drop(review);
        drop(handle);
        join_test_task("Publish control", control).await.unwrap();
        join_test_task("policy actor", actor).await.unwrap();
        endpoint.close(0u32.into(), &[]);
        assert!(coordinator.wait_for_drain(TEST_TIMEOUT).await);
    }

    #[tokio::test]
    async fn shutdown_interrupts_publish_request_blocked_by_flow_control() {
        run_test(async {
            interrupt_blocked_request(false).await;
        })
        .await;
    }

    #[tokio::test]
    async fn policy_delete_interrupts_publish_request_blocked_by_flow_control() {
        run_test(async {
            interrupt_blocked_request(true).await;
        })
        .await;
    }

    #[serial]
    #[tokio::test]
    async fn giganto_shutdown_does_not_prevent_review_handler_deletion() {
        run_test(async {
            let policy = new_policy(42);
            let mut harness = TestHarness::new(std::slice::from_ref(&policy)).await;
            harness.wait_for_ack().await;
            harness.wait_for_timestamp(&[42]).await;
            harness.server_handles.ingest_shutdown.notify_one();
            harness.server_handles.publish_shutdown.notify_one();
            join_test_task(
                "Giganto Ingest server",
                harness.server_handles.ingest_handle,
            )
            .await;
            join_test_task(
                "Giganto Publish server",
                harness.server_handles.publish_handle,
            )
            .await;
            timeout(
                TEST_TIMEOUT,
                harness
                    .request_client
                    .delete_time_series_generation_policy(&[42]),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(!read_time_data_map(&harness.last_time_series_path).contains_key("42"));
            harness
                .coordinator
                .request_cancellation("Giganto offline test finished");
            drop(harness.request_client);
            drop(harness.policy_handle);
            join_test_task("subscribe client", harness.client_handle).await;
            assert_eq!(harness.coordinator.tracker().active_count(), 0);
            INGEST_CHANNEL.write().await.clear();
        })
        .await;
    }
}
