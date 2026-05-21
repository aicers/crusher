use std::collections::HashMap;
use std::time::Duration;
use std::{
    fs,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
};

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
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
    SanType, string::Ia5String,
};
use review_protocol::request::Handler;
use review_protocol::types::{SamplingKind, SamplingPolicy};
use rustls::{pki_types::CertificateDer, server::WebPkiClientVerifier};
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
const BASE_TS_NANOS: i64 = 1_700_000_000_000_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectionPath {
    Ingest,
    Publish,
}

type PeerCertEvent = (ConnectionPath, Vec<u8>);

struct FakeGigantoServer {
    server_config: ServerConfig,
    server_address: SocketAddr,
    ingest_notify: Option<async_channel::Sender<u32>>,
    peer_cert_notify: Option<async_channel::Sender<PeerCertEvent>>,
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
            peer_cert_notify: None,
            publish_repeat_count: 0,
            publish_repeat_delay: Duration::from_millis(0),
        }
    }

    fn new_ingest_with_config(server_config: ServerConfig) -> Self {
        let server_address = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0);
        FakeGigantoServer {
            server_config,
            server_address,
            ingest_notify: None,
            peer_cert_notify: None,
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
            peer_cert_notify: None,
            publish_repeat_count: 3,
            publish_repeat_delay: Duration::from_millis(200),
        }
    }

    fn new_publish_with_config(server_config: ServerConfig) -> Self {
        let server_address = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0);
        FakeGigantoServer {
            server_config,
            server_address,
            ingest_notify: None,
            peer_cert_notify: None,
            publish_repeat_count: 3,
            publish_repeat_delay: Duration::from_millis(200),
        }
    }

    fn with_notify(mut self, notify: async_channel::Sender<u32>) -> Self {
        self.ingest_notify = Some(notify);
        self
    }

    fn with_peer_cert_notify(mut self, notify: async_channel::Sender<PeerCertEvent>) -> Self {
        self.peer_cert_notify = Some(notify);
        self
    }

    fn start_ingest(self, shutdown: Arc<Notify>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let endpoint = Endpoint::server(self.server_config, self.server_address).expect("endpoint");
        let local_addr = endpoint.local_addr().expect("local_addr");
        let ingest_notify = self.ingest_notify.clone();
        let peer_cert_notify = self.peer_cert_notify.clone();
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(conn) = endpoint.accept() => {
                        let notify = ingest_notify.clone();
                        let peer_cert_notify = peer_cert_notify.clone();
                        tokio::spawn(async move {
                            if let Ok(connection) = conn.await {
                                handle_ingest_connection(connection, notify, peer_cert_notify).await;
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
        let peer_cert_notify = self.peer_cert_notify.clone();
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(conn) = endpoint.accept() => {
                        let peer_cert_notify = peer_cert_notify.clone();
                        tokio::spawn(async move {
                            if let Ok(connection) = conn.await {
                                handle_publish_connection(
                                    connection,
                                    publish_repeat_count,
                                    publish_repeat_delay,
                                    peer_cert_notify,
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
    peer_cert_notify: Option<async_channel::Sender<PeerCertEvent>>,
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
    peer_cert_notify: Option<async_channel::Sender<PeerCertEvent>>,
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
            let ts = BASE_TS_NANOS + i64::try_from(idx).expect("test repeat count fits in i64");
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
    let tls_bytes = crate::client::SharedTlsBytes::new(crate::client::TlsBytes::new(
        fs::read(CERT_PATH).unwrap(),
        fs::read(KEY_PATH).unwrap(),
        vec![fs::read(CA_CERT_PATH).unwrap()],
    ));
    let request_client = crate::request::Client::new(
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
        HOST.to_string(),
        request_send,
        tls_bytes,
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
    )
    .expect("test client should build an endpoint");

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
}

async fn cleanup_server_resources(server_handles: TestServerHandlers) {
    server_handles.ingest_shutdown.notify_one();
    server_handles.publish_shutdown.notify_one();

    let _ = tokio::join!(server_handles.ingest_handle, server_handles.publish_handle);
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
    let client_auth = WebPkiClientVerifier::builder(Arc::new(
        Certs::to_ca_certs(&[client_ca_pem]).expect("parse client CA"),
    ))
    .build()
    .expect("build client certificate verifier");

    let server_crypto = rustls::ServerConfig::builder()
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
    cleanup_test_resources(client_shutdown, client_handle, server_handles).await;
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
    cleanup_test_resources(client_shutdown, client_handle, server_handles).await;
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
    cleanup_test_resources(client_shutdown, client_handle, server_handles).await;
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
    reset_last_transfer_time().await;

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
    // both ingest and publish to a first ACK.
    let (mut request_client, request_recv, last_time_series_path, _temp_dir) =
        setup_request_client(1);
    let policy = new_policy(DEFAULT_POLICY_ID);
    request_client
        .sampling_policy_list(std::slice::from_ref(&policy))
        .await
        .unwrap();

    let mut certs = crate::load_tls_material(&args).expect("initial load");
    let initial_client_leaf_der = certs
        .certs
        .first()
        .expect("initial client leaf")
        .as_ref()
        .to_vec();
    let (client_handle_1, client_shutdown_1) = spawn_subscribe_client(
        &certs,
        request_recv.clone(),
        &last_time_series_path,
        ingest_addr,
        publish_addr,
        &request_client,
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
    // subscribe::Client. This mirrors the `RerunReason::TlsReload` branch
    // in `main::main`.
    client_shutdown_1.notify_one();
    let _ = client_handle_1.await;
    INGEST_CHANNEL.write().await.clear();
    cleanup_server_resources(server_handles).await;

    let (ingest_ack_recv, server_handles, ingest_addr, publish_addr) = start_servers_with_config(
        rotated.server_config.clone(),
        rotated.server_config.clone(),
        peer_cert_send.clone(),
    );

    certs = crate::load_tls_material(&args).expect("valid material reloads");
    assert_eq!(
        certs.certs.first().expect("reloaded client leaf").as_ref(),
        rotated.client_leaf_der.as_slice(),
        "rerun should reload the rotated client certificate",
    );
    let (client_handle_2, client_shutdown_2) = spawn_subscribe_client(
        &certs,
        request_recv.clone(),
        &last_time_series_path,
        ingest_addr,
        publish_addr,
        &request_client,
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
    let reload_err = crate::load_tls_material(&args)
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
    // endpoint) must keep producing ACKs for the same policy, proving that a
    // failed reload does not tear down ingest/publish.
    let id = timeout(Duration::from_secs(5), ingest_ack_recv.recv())
        .await
        .expect("last-known-good endpoint keeps producing ACKs after failed reload")
        .expect("ingest ACK channel open");
    assert_eq!(id, policy.id);

    cleanup_test_resources(client_shutdown_2, client_handle_2, server_handles).await;
}
