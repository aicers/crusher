use std::collections::HashMap;
use std::time::Duration;
use std::{
    fs,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
};

use chrono::Utc;
use giganto_client::{
    connection::server_handshake,
    frame::{recv_raw, send_bytes, send_raw},
    ingest::receive_record_header,
    publish::receive_stream_request,
    publish::stream::StreamRequestPayload,
};
use quinn::{
    Connection, Endpoint, RecvStream, SendStream, ServerConfig, crypto::rustls::QuicServerConfig,
};
use review_protocol::request::Handler;
use review_protocol::types::{SamplingKind, SamplingPolicy};
use serial_test::serial;
use tempfile::TempDir;
use tokio::sync::Notify;
use tokio::time::{sleep, timeout};

use super::time_series::clear_last_transfer_time;
use super::*;
use crate::cancellation::CancellationCoordinator;
use crate::client::Certs;
use crate::policy::{PolicyHandle, spawn_policy_actor};

const CERT_PATH: &str = "tests/cert.pem";
const KEY_PATH: &str = "tests/key.pem";
const CA_CERT_PATH: &str = "tests/ca_cert.pem";
const HOST: &str = "localhost";
const SECS_PER_MINUTE: u64 = 60;
const SECS_PER_DAY: u64 = 86_400;
const DEFAULT_POLICY_ID: u32 = 1;

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
}

struct FakeGigantoServer {
    server_config: ServerConfig,
    server_address: SocketAddr,
    ingest_notify: Option<async_channel::Sender<u32>>,
    publish_repeat_count: usize,
    publish_repeat_delay: Duration,
    publish_behavior: PublishBehavior,
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
            publish_repeat_count: 0,
            publish_repeat_delay: Duration::from_millis(0),
            publish_behavior: PublishBehavior::Default,
        }
    }

    fn new_publish() -> Self {
        let server_config = config_server();
        let server_address = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0);
        FakeGigantoServer {
            server_config,
            server_address,
            ingest_notify: None,
            publish_repeat_count: 3,
            publish_repeat_delay: Duration::from_millis(200),
            publish_behavior: PublishBehavior::Default,
        }
    }

    fn with_notify(mut self, notify: async_channel::Sender<u32>) -> Self {
        self.ingest_notify = Some(notify);
        self
    }

    fn with_publish_behavior(mut self, behavior: PublishBehavior) -> Self {
        self.publish_behavior = behavior;
        self
    }

    fn start_ingest(self, shutdown: Arc<Notify>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let endpoint = Endpoint::server(self.server_config, self.server_address).expect("endpoint");
        let local_addr = endpoint.local_addr().expect("local_addr");
        let ingest_notify = self.ingest_notify.clone();
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(conn) = endpoint.accept() => {
                        let notify = ingest_notify.clone();
                        tokio::spawn(async move {
                            if let Ok(connection) = conn.await {
                                handle_ingest_connection(connection, notify).await;
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
        let publish_repeat_count = self.publish_repeat_count;
        let publish_repeat_delay = self.publish_repeat_delay;
        let behavior = self.publish_behavior;
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(conn) = endpoint.accept() => {
                        let behavior = behavior.clone();
                        tokio::spawn(async move {
                            if let Ok(connection) = conn.await {
                                handle_publish_connection(
                                    connection,
                                    publish_repeat_count,
                                    publish_repeat_delay,
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

async fn handle_ingest_connection(
    connection: Connection,
    notify: Option<async_channel::Sender<u32>>,
) {
    let version_req = format!("={REQUIRED_GIGANTO_VERSION}");
    if server_handshake(&connection, &version_req).await.is_err() {
        return;
    }

    while let Ok((send, recv)) = connection.accept_bi().await {
        let notify = notify.clone();
        tokio::spawn(async move {
            handle_ingest_stream(send, recv, notify).await;
        });
    }
}

async fn handle_publish_connection(
    connection: Connection,
    repeat_count: usize,
    repeat_delay: Duration,
    behavior: PublishBehavior,
) {
    let version_req = format!("={REQUIRED_GIGANTO_VERSION}");
    let Ok((_send, mut recv)) = server_handshake(&connection, &version_req).await else {
        return;
    };

    match behavior {
        PublishBehavior::Default => {
            handle_default_publish(&connection, &mut recv, repeat_count, repeat_delay).await;
        }
        PublishBehavior::ReverseOrder { expected } => {
            handle_reverse_order_publish(
                &connection,
                &mut recv,
                expected,
                repeat_count,
                repeat_delay,
            )
            .await;
        }
        PublishBehavior::StaleIdFirst { stale_id } => {
            handle_stale_id_publish(&connection, &mut recv, stale_id, repeat_count, repeat_delay)
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
                repeat_count,
                repeat_delay,
            )
            .await;
        }
    }
}

async fn open_and_emit_stream(
    connection: &Connection,
    policy_id_bytes: &[u8],
    record_bytes: &[u8],
    repeat_count: usize,
    repeat_delay: Duration,
) {
    let Ok(mut uni) = connection.open_uni().await else {
        return;
    };
    let _ = send_raw(&mut uni, policy_id_bytes).await;
    for idx in 0..repeat_count {
        let ts = Utc::now().timestamp_nanos_opt().unwrap_or(i64::MAX);
        let _ = send_bytes(&mut uni, &ts.to_le_bytes()).await;
        let _ = send_raw(&mut uni, record_bytes).await;
        if idx + 1 < repeat_count {
            sleep(repeat_delay).await;
        }
    }
    let _ = uni.finish();
}

async fn handle_default_publish(
    connection: &Connection,
    recv: &mut RecvStream,
    repeat_count: usize,
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
        open_and_emit_stream(
            connection,
            policy_id.as_bytes(),
            &record_bytes,
            repeat_count,
            repeat_delay,
        )
        .await;
    }
}

async fn handle_reverse_order_publish(
    connection: &Connection,
    recv: &mut RecvStream,
    expected: usize,
    repeat_count: usize,
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
            repeat_count,
            repeat_delay,
        )
        .await;
    }
}

async fn handle_stale_id_publish(
    connection: &Connection,
    recv: &mut RecvStream,
    stale_id: u32,
    repeat_count: usize,
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
        open_and_emit_stream(connection, stale.as_bytes(), &record_bytes, 1, repeat_delay).await;
        // Then the real stream — must be processed normally.
        open_and_emit_stream(
            connection,
            policy_id.as_bytes(),
            &record_bytes,
            repeat_count,
            repeat_delay,
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
    repeat_count: usize,
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
            repeat_count,
            repeat_delay,
        )
        .await;
    }
}

async fn handle_ingest_stream(
    mut send: SendStream,
    mut recv: RecvStream,
    notify: Option<async_channel::Sender<u32>>,
) {
    let mut header_buf = [0_u8; 4];
    if receive_record_header(&mut recv, &mut header_buf)
        .await
        .is_err()
    {
        return;
    }

    // A bi-di stream carries one header followed by any number of
    // batches until the client closes it. Looping here lets tests
    // observe ACKs from multiple batches on the same stream — which
    // happens naturally when a policy is deleted and re-added on the
    // same live ingest connection (the client reuses the bi-di stream
    // via `INGEST_CHANNEL`).
    loop {
        let mut buf = Vec::new();
        if recv_raw(&mut recv, &mut buf).await.is_err() {
            return;
        }

        let Ok(batch) = bincode::deserialize::<Vec<(i64, Vec<u8>)>>(&buf) else {
            continue;
        };
        let policy_id = batch
            .first()
            .and_then(|(_, payload)| bincode::deserialize::<TimeSeries>(payload).ok())
            .and_then(|series| series.sampling_policy_id.parse::<u32>().ok())
            .unwrap_or(0);
        for (timestamp, _) in batch {
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
    async fn new(policies: &[SamplingPolicy]) -> Self {
        reset_last_transfer_time().await;
        let (ingest_ack_recv, server_handles, ingest_addr, publish_addr) = start_servers();
        let certs = cert_key();
        let coordinator = CancellationCoordinator::new();
        let (request_client, request_recv, last_time_series_path, temp_dir, policy_handle) =
            setup_request_client(policies.len().max(1), &coordinator);

        let mut rc = request_client;
        rc.sampling_policy_list(policies).await.unwrap();

        let client_handle = spawn_subscribe_client(
            &certs,
            request_recv,
            &last_time_series_path,
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
        timeout(Duration::from_secs(5), self.ingest_ack_recv.recv())
            .await
            .expect("Ingest ACK should arrive within 5s")
            .expect("Ingest ACK channel should remain open")
    }

    async fn wait_for_timestamp(&self, ids: &[u32]) -> HashMap<String, i64> {
        timeout(
            Duration::from_secs(5),
            wait_for_policy_ids(&self.last_time_series_path, ids, true),
        )
        .await
        .expect("Expected policy IDs to appear in time_data.json")
    }

    async fn wait_for_timestamp_removed(&self, ids: &[u32]) -> HashMap<String, i64> {
        timeout(
            Duration::from_secs(5),
            wait_for_policy_ids(&self.last_time_series_path, ids, false),
        )
        .await
        .expect("Expected policy IDs to be removed from time_data.json")
    }

    async fn cleanup(self) {
        cleanup_test_resources(self.coordinator, self.client_handle, self.server_handles).await;
    }
}

fn setup_request_client(
    buffer: usize,
    coordinator: &CancellationCoordinator,
) -> (
    crate::request::Client,
    async_channel::Receiver<SamplingPolicy>,
    PathBuf,
    TempDir,
    PolicyHandle,
) {
    let (request_send, request_recv) = async_channel::bounded::<SamplingPolicy>(buffer);
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let last_time_series_path = temp_dir.path().join("time_data.json");
    let policy_handle = spawn_policy_actor(request_send, coordinator);
    let mut request_client = crate::request::Client::new(
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
        HOST.to_string(),
        fs::read(CERT_PATH).unwrap(),
        fs::read(KEY_PATH).unwrap(),
        vec![fs::read(CA_CERT_PATH).unwrap()],
        Arc::new(Notify::new()),
    );
    request_client.set_policy_handle(policy_handle.clone());
    (
        request_client,
        request_recv,
        last_time_series_path,
        temp_dir,
        policy_handle,
    )
}

fn new_policy(id: u32) -> SamplingPolicy {
    SamplingPolicy {
        id,
        kind: SamplingKind::Conn,
        interval: Duration::from_secs(15 * SECS_PER_MINUTE),
        period: Duration::from_secs(SECS_PER_DAY),
        offset: 0,
        src_ip: None,
        dst_ip: None,
        node: Some("cluml".to_string()),
        column: None,
    }
}

fn spawn_subscribe_client(
    certs: &Certs,
    request_recv: async_channel::Receiver<SamplingPolicy>,
    last_time_series_path: &Path,
    ingest_addr: SocketAddr,
    publish_addr: SocketAddr,
    policy_handle: PolicyHandle,
    coordinator: CancellationCoordinator,
) -> tokio::task::JoinHandle<()> {
    let client = Client::new(
        ingest_addr,
        publish_addr,
        HOST.to_string(),
        last_time_series_path.to_path_buf(),
        certs,
        request_recv,
    );

    tokio::spawn(async move {
        let _ = client.run(policy_handle, coordinator).await;
    })
}

async fn reset_last_transfer_time() {
    clear_last_transfer_time().await;
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

    let _ = tokio::join!(
        client_handle,
        server_handles.ingest_handle,
        server_handles.publish_handle
    );
    INGEST_CHANNEL.write().await.clear();
}

fn read_time_data_map(last_time_series_path: &Path) -> HashMap<String, i64> {
    let content = fs::read_to_string(last_time_series_path).unwrap_or_default();
    if content.trim().is_empty() {
        return HashMap::new();
    }
    serde_json::from_str::<HashMap<String, i64>>(&content).expect("Failed to parse time_data.json")
}

fn config_server() -> ServerConfig {
    let certs = cert_key();

    let client_auth =
        rustls::server::WebPkiClientVerifier::builder(Arc::new(certs.ca_certs.clone()))
            .build()
            .expect("Failed to build client certificate verifier");

    let server_crypto = rustls::ServerConfig::builder()
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
    let tmp_dur = chrono::Duration::nanoseconds(12345);

    Conn {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_port: 80,
        proto: 6,
        service: String::new(),
        conn_state: "OK".to_string(),
        start_time: 500,
        duration: tmp_dur.num_nanoseconds().unwrap(),
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
async fn sampling_policy_flow_with_fake_giganto_server() {
    let policy = new_policy(DEFAULT_POLICY_ID);
    let harness = TestHarness::new(std::slice::from_ref(&policy)).await;

    assert!(harness.policy_handle.get_policy(policy.id).await.is_some());

    let id = harness.wait_for_ack().await;
    assert_eq!(id, policy.id);

    let map = harness.wait_for_timestamp(&[policy.id]).await;
    assert!(harness.last_time_series_path.exists());
    let expected: HashMap<String, i64> = [(policy.id.to_string(), 0)].into_iter().collect();
    assert_eq!(map, expected);

    harness.cleanup().await;
}

/// Test: Validates notify flow - when a policy is added, the client sends a stream
/// request and receives data from the server. When the policy is deleted, the stream
/// should be stopped and timestamp cleaned up.
#[serial]
#[tokio::test]
async fn sampling_policy_notify_flow_with_delete() {
    let policy = new_policy(DEFAULT_POLICY_ID);
    let mut harness = TestHarness::new(std::slice::from_ref(&policy)).await;

    assert!(harness.policy_handle.get_policy(policy.id).await.is_some());

    let id = harness.wait_for_ack().await;
    assert_eq!(id, policy.id);

    let map = harness.wait_for_timestamp(&[policy.id]).await;
    assert!(harness.last_time_series_path.exists());
    let expected: HashMap<String, i64> = [(policy.id.to_string(), 0)].into_iter().collect();
    assert_eq!(map, expected);

    harness
        .request_client
        .delete_sampling_policy(&[policy.id])
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
async fn sampling_policy_multiple_streams() {
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
    let expected: HashMap<String, i64> =
        [(policy_a.id.to_string(), 0), (policy_b.id.to_string(), 0)]
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
    use crate::cancellation::CancellationPhase;

    let policy = new_policy(DEFAULT_POLICY_ID);
    let harness = TestHarness::new(std::slice::from_ref(&policy)).await;

    let _ = harness.wait_for_ack().await;
    let _ = harness.wait_for_timestamp(&[policy.id]).await;

    harness.coordinator.request_cancellation("drain test");
    harness.server_handles.ingest_shutdown.notify_one();
    harness.server_handles.publish_shutdown.notify_one();

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

/// Test: In-flight ACK/timestamp messages sent near the cancellation
/// boundary are captured by the drain window and flushed to disk.
///
/// The publish server sends 3 ACKs with 200ms gaps. We cancel
/// immediately after the first ACK notification, so the remaining
/// ACKs arrive while `receive_time_series_timestamp` and
/// `write_last_timestamp` are draining.  The final timestamp on disk
/// must be >= the pre-cancellation value, proving the drain captured
/// in-flight messages.
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
    cleanup_test_resources(
        harness.coordinator,
        harness.client_handle,
        harness.server_handles,
    )
    .await;

    let read_result = crate::subscribe::read_last_timestamp(&last_time_series_path).await;
    assert!(
        read_result.is_ok(),
        "Timestamp file must be readable after cancellation: {read_result:?}"
    );

    // --- Second run: re-use persisted timestamp file ---
    reset_last_transfer_time().await;

    let (ingest_ack_recv2, server_handles2, ingest_addr2, publish_addr2) = start_servers();
    let certs = cert_key();
    let coordinator2 = CancellationCoordinator::new();
    let (mut request_client2, request_recv2, _, _keep_dir, policy_handle2) =
        setup_request_client(1, &coordinator2);

    request_client2
        .sampling_policy_list(std::slice::from_ref(&policy))
        .await
        .unwrap();

    let client_handle2 = spawn_subscribe_client(
        &certs,
        request_recv2,
        &last_time_series_path,
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

    cleanup_test_resources(coordinator2, client_handle2, server_handles2).await;
}

/// Spawns a subscribe client wired to a publish endpoint with the
/// given [`PublishBehavior`]. Returns the resources the test needs to
/// observe ACKs and tear everything down.
async fn run_with_publish_behavior(
    policies: &[SamplingPolicy],
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
    reset_last_transfer_time().await;

    let (ingest_ack_send, ingest_ack_recv) = async_channel::bounded::<u32>(10);
    let ingest_server = FakeGigantoServer::new_ingest().with_notify(ingest_ack_send);
    let publish_server = FakeGigantoServer::new_publish().with_publish_behavior(behavior);
    let ingest_shutdown = Arc::new(Notify::new());
    let publish_shutdown = Arc::new(Notify::new());
    let (ingest_addr, ingest_handle) = ingest_server.start_ingest(ingest_shutdown.clone());
    let (publish_addr, publish_handle) = publish_server.start_publish(publish_shutdown.clone());

    let certs = cert_key();
    let coordinator = CancellationCoordinator::new();
    let (mut request_client, request_recv, last_time_series_path, temp_dir, policy_handle) =
        setup_request_client(policies.len().max(1), &coordinator);
    request_client.sampling_policy_list(policies).await.unwrap();

    let client_handle = spawn_subscribe_client(
        &certs,
        request_recv,
        &last_time_series_path,
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

/// Test: After a policy is deleted on a live publish connection, a
/// re-add with the same id MUST open a fresh stream on that same
/// connection. This is the regression test for the startup-only-dedup
/// contract: no connection-lifetime dedupe set may survive into the
/// steady-state `request_recv.recv()` loop — otherwise a re-add would
/// be silently dropped as "already opened," breaking live
/// reconfiguration.
#[serial]
#[tokio::test]
async fn delete_then_readd_same_id_starts_fresh_stream() {
    let policy = new_policy(DEFAULT_POLICY_ID);
    let mut harness = TestHarness::new(std::slice::from_ref(&policy)).await;

    // Initial add: observe ACK + timestamp.
    let id = harness.wait_for_ack().await;
    assert_eq!(id, policy.id);
    let _ = harness.wait_for_timestamp(&[policy.id]).await;

    // Delete and confirm timestamp is removed (writer actor's Delete
    // command both removes the in-memory entry and rewrites the file).
    harness
        .request_client
        .delete_sampling_policy(&[policy.id])
        .await
        .unwrap();
    let map_after_delete = harness.wait_for_timestamp_removed(&[policy.id]).await;
    assert_eq!(map_after_delete.get(&policy.id.to_string()), None);

    // Re-add the same policy id on the same live publish connection.
    // The subscribe client must enqueue a fresh stream request and
    // the fake server must respond with a new inbound stream — which
    // drives a fresh ACK back through the ingest path.
    harness
        .request_client
        .sampling_policy_list(std::slice::from_ref(&policy))
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
        "timestamp for re-added policy must reappear; the writer \
         actor's tombstone must have been cleared by the new stream \
         worker's Reset command"
    );

    harness.cleanup().await;
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
    let (coordinator, _rc, _ph, client_handle, server_handles, ingest_ack_recv, _, _temp) =
        run_with_publish_behavior(
            &[policy_a.clone(), policy_b.clone()],
            PublishBehavior::ReverseOrder { expected: 2 },
        )
        .await;

    let mut expected_ids = vec![policy_a.id, policy_b.id];
    for _ in 0..2 {
        let id = timeout(Duration::from_secs(5), ingest_ack_recv.recv())
            .await
            .expect("ACK should arrive within 5s")
            .expect("ACK channel should remain open");
        expected_ids.retain(|e| *e != id);
    }
    assert!(
        expected_ids.is_empty(),
        "Both policies should receive correct ACKs even with reversed stream arrival: {expected_ids:?}"
    );

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
    let (coordinator, _rc, _ph, client_handle, server_handles, ingest_ack_recv, _, _temp) =
        run_with_publish_behavior(
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
        _ph,
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
        .delete_sampling_policy(&[policy_a.id])
        .await
        .unwrap();

    // Let the server open both inbound streams. The dispatcher must
    // bind policy_b normally and drop policy_a (deleted) silently.
    release.notify_one();

    // Drain any ACKs arriving within a short window — only policy_b
    // should produce ACKs.
    let mut received = Vec::new();
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

    cleanup_test_resources(coordinator, client_handle, server_handles).await;
}
