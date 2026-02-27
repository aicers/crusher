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
use crate::client::Certs;

const CERT_PATH: &str = "tests/cert.pem";
const KEY_PATH: &str = "tests/key.pem";
const CA_CERT_PATH: &str = "tests/ca_cert.pem";
const HOST: &str = "localhost";
const SECS_PER_MINUTE: u64 = 60;
const SECS_PER_DAY: u64 = 86_400;
const DEFAULT_POLICY_ID: u32 = 1;

struct FakeGigantoServer {
    server_config: ServerConfig,
    server_address: SocketAddr,
    ingest_notify: Option<async_channel::Sender<u32>>,
    publish_repeat_count: usize,
    publish_repeat_delay: Duration,
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
        }
    }

    fn with_notify(mut self, notify: async_channel::Sender<u32>) -> Self {
        self.ingest_notify = Some(notify);
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
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(conn) = endpoint.accept() => {
                        tokio::spawn(async move {
                            if let Ok(connection) = conn.await {
                                handle_publish_connection(
                                    connection,
                                    publish_repeat_count,
                                    publish_repeat_delay,
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
) {
    let version_req = format!("={REQUIRED_GIGANTO_VERSION}");
    let Ok((_send, mut recv)) = server_handshake(&connection, &version_req).await else {
        return;
    };

    loop {
        let Ok(payload) = receive_stream_request(&mut recv).await else {
            break;
        };
        let (policy_id, record_bytes) = match payload {
            StreamRequestPayload::TimeSeriesGenerator { request, .. } => {
                (request.id, bincode::serialize(&gen_conn()).unwrap())
            }
            _ => continue,
        };

        let Ok(mut uni) = connection.open_uni().await else {
            continue;
        };
        let _ = send_raw(&mut uni, policy_id.as_bytes()).await;

        for idx in 0..repeat_count {
            let ts = Utc::now().timestamp_nanos_opt().unwrap_or(i64::MAX);
            let _ = send_bytes(&mut uni, &ts.to_le_bytes()).await;
            let _ = send_raw(&mut uni, &record_bytes).await;
            if idx + 1 < repeat_count {
                sleep(repeat_delay).await;
            }
        }
        let _ = uni.finish();
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

    let mut buf = Vec::new();
    if recv_raw(&mut recv, &mut buf).await.is_err() {
        return;
    }

    if let Ok(batch) = bincode::deserialize::<Vec<(i64, Vec<u8>)>>(&buf) {
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

fn setup_request_client(
    buffer: usize,
) -> (
    crate::request::Client,
    async_channel::Receiver<SamplingPolicy>,
    PathBuf,
    TempDir,
) {
    let (request_send, request_recv) = async_channel::bounded::<SamplingPolicy>(buffer);
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let last_time_series_path = temp_dir.path().join("time_data.json");
    let request_client = crate::request::Client::new(
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
        HOST.to_string(),
        request_send,
        fs::read(CERT_PATH).unwrap(),
        fs::read(KEY_PATH).unwrap(),
        vec![fs::read(CA_CERT_PATH).unwrap()],
        Arc::new(Notify::new()),
    );
    (
        request_client,
        request_recv,
        last_time_series_path,
        temp_dir,
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
    request_client: &crate::request::Client,
) -> (tokio::task::JoinHandle<()>, Arc<Notify>) {
    let client = Client::new(
        ingest_addr,
        publish_addr,
        HOST.to_string(),
        last_time_series_path.to_path_buf(),
        certs,
        request_recv,
    );

    let client_shutdown = Arc::new(Notify::new());
    let client_shutdown_clone = client_shutdown.clone();
    let active_policy_list = request_client.active_policy_list.clone();
    let delete_policy_ids = request_client.delete_policy_ids.clone();

    let client_handle = tokio::spawn(async move {
        let _ = client
            .run(active_policy_list, delete_policy_ids, client_shutdown_clone)
            .await;
    });

    (client_handle, client_shutdown)
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
    client_shutdown: Arc<Notify>,
    client_handle: tokio::task::JoinHandle<()>,
    server_handles: TestServerHandlers,
    last_time_series_path: &Path,
) {
    client_shutdown.notify_one();
    server_handles.ingest_shutdown.notify_one();
    server_handles.publish_shutdown.notify_one();

    let _ = tokio::join!(
        client_handle,
        server_handles.ingest_handle,
        server_handles.publish_handle
    );
    INGEST_CHANNEL.write().await.clear();

    if last_time_series_path.exists() {
        let _ = fs::remove_file(last_time_series_path);
    }
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
    reset_last_transfer_time().await;
    // Arrange: start fake servers and a request client.
    let (ingest_ack_recv, server_handles, ingest_addr, publish_addr) = start_servers();

    let certs = cert_key();
    let (mut request_client, request_recv, last_time_series_path, _temp_dir) =
        setup_request_client(1);

    let policy = new_policy(DEFAULT_POLICY_ID);

    // Act: insert policy into request client.
    request_client
        .sampling_policy_list(std::slice::from_ref(&policy))
        .await
        .unwrap();

    // Assert: policy is tracked in the active list.
    assert!(
        request_client
            .active_policy_list
            .read()
            .await
            .contains_key(&policy.id)
    );

    let (client_handle, client_shutdown) = spawn_subscribe_client(
        &certs,
        request_recv,
        &last_time_series_path,
        ingest_addr,
        publish_addr,
        &request_client,
    );

    // Act/Assert: wait for ingest ACK and timestamp file creation.
    let id = timeout(Duration::from_secs(5), ingest_ack_recv.recv())
        .await
        .expect("Ingest ACK should arrive within 5s after adding sampling policy")
        .expect("Ingest ACK channel should remain open until ACK is received after adding sampling policy");
    assert_eq!(id, policy.id);

    let map = timeout(
        Duration::from_secs(5),
        wait_for_policy_ids(&last_time_series_path, &[policy.id], true),
    )
    .await
    .expect("No timeout: expected policy ID was written to time_data.json");

    assert!(last_time_series_path.exists());
    let expected: HashMap<String, i64> = [(policy.id.to_string(), 0)].into_iter().collect();
    assert_eq!(map, expected);

    // Cleanup: stop client and servers.
    cleanup_test_resources(
        client_shutdown,
        client_handle,
        server_handles,
        &last_time_series_path,
    )
    .await;
}

/// Test: Validates notify flow - when a policy is added, the client sends a stream
/// request and receives data from the server. When the policy is deleted, the stream
/// should be stopped and timestamp cleaned up.
#[serial]
#[tokio::test]
async fn sampling_policy_notify_flow_with_delete() {
    reset_last_transfer_time().await;
    // Arrange: start servers and request client.
    let (ingest_ack_recv, server_handles, ingest_addr, publish_addr) = start_servers();

    let certs = cert_key();
    let (mut request_client, request_recv, last_time_series_path, _temp_dir) =
        setup_request_client(1);
    let policy = new_policy(DEFAULT_POLICY_ID);

    // Act: insert policy.
    request_client
        .sampling_policy_list(std::slice::from_ref(&policy))
        .await
        .unwrap();

    // Assert: policy is tracked in the active list.
    assert!(
        request_client
            .active_policy_list
            .read()
            .await
            .contains_key(&policy.id)
    );

    let (client_handle, client_shutdown) = spawn_subscribe_client(
        &certs,
        request_recv,
        &last_time_series_path,
        ingest_addr,
        publish_addr,
        &request_client,
    );

    // Act/Assert: wait for ingest ACK and timestamp file creation.
    let id = timeout(Duration::from_secs(5), ingest_ack_recv.recv())
        .await
        .expect("Ingest ACK should arrive within 5s after adding sampling policy")
        .expect("Ingest ACK channel should remain open until ACK is received after adding sampling policy");
    assert_eq!(id, policy.id);

    let map = timeout(
        Duration::from_secs(5),
        wait_for_policy_ids(&last_time_series_path, &[policy.id], true),
    )
    .await
    .expect("No timeout: expected policy ID was written to time_data.json");

    assert!(last_time_series_path.exists());
    let expected: HashMap<String, i64> = [(policy.id.to_string(), 0)].into_iter().collect();
    assert_eq!(map, expected);

    // Act: delete policy.
    request_client
        .delete_sampling_policy(&[policy.id])
        .await
        .unwrap();

    // Assert: timestamp entry is removed after deletion.
    let map = timeout(
        Duration::from_secs(5),
        wait_for_policy_ids(&last_time_series_path, &[policy.id], false),
    )
    .await
    .expect("No timeout: expected policy ID was removed from time_data.json");

    assert!(last_time_series_path.exists());
    let expected: HashMap<String, i64> = HashMap::new();
    assert_eq!(map, expected);

    // Cleanup: stop client and servers.
    cleanup_test_resources(
        client_shutdown,
        client_handle,
        server_handles,
        &last_time_series_path,
    )
    .await;
}

/// Test: Adding multiple policies should create multiple concurrent streams.
#[serial]
#[tokio::test]
async fn sampling_policy_multiple_streams() {
    reset_last_transfer_time().await;
    // Arrange: start servers and request client with two policies.
    let (ingest_ack_recv, server_handles, ingest_addr, publish_addr) = start_servers();

    let certs = cert_key();
    let (mut request_client, request_recv, last_time_series_path, _temp_dir) =
        setup_request_client(2);
    let policy_a = new_policy(1);
    let policy_b = new_policy(2);

    // Act: insert two policies.
    request_client
        .sampling_policy_list(&[policy_a.clone(), policy_b.clone()])
        .await
        .unwrap();

    // Assert: both policies are active.
    assert!(
        request_client
            .active_policy_list
            .read()
            .await
            .contains_key(&policy_a.id)
    );
    assert!(
        request_client
            .active_policy_list
            .read()
            .await
            .contains_key(&policy_b.id)
    );

    let (client_handle, client_shutdown) = spawn_subscribe_client(
        &certs,
        request_recv,
        &last_time_series_path,
        ingest_addr,
        publish_addr,
        &request_client,
    );

    // Act/Assert: receive policy IDs for both streams.
    let mut expected_ids = vec![policy_a.id, policy_b.id];
    for _ in 0..2 {
        let id = timeout(Duration::from_secs(5), ingest_ack_recv.recv())
            .await
            .expect("Ingest ACKs for all sampling policies should arrive within 5s")
            .expect("Ingest ACK channel should remain open until ACKs for all sampling policies are received");
        expected_ids.retain(|expected| *expected != id);
    }
    assert!(
        expected_ids.is_empty(),
        "Not all policy IDs produced streams: {expected_ids:?}"
    );

    let map = timeout(
        Duration::from_secs(5),
        wait_for_policy_ids(&last_time_series_path, &[policy_a.id, policy_b.id], true),
    )
    .await
    .expect("No timeout: expected policy IDs were written to time_data.json");

    assert!(last_time_series_path.exists());
    let expected: HashMap<String, i64> =
        [(policy_a.id.to_string(), 0), (policy_b.id.to_string(), 0)]
            .into_iter()
            .collect();
    assert_eq!(map, expected);

    // Cleanup: stop client and servers.
    cleanup_test_resources(
        client_shutdown,
        client_handle,
        server_handles,
        &last_time_series_path,
    )
    .await;
}
