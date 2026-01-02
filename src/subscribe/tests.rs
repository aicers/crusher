use std::cmp::Ordering;
use std::sync::LazyLock;
use std::time::Duration;
use std::{
    collections::HashMap,
    fs,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use chrono::{DateTime, NaiveDate, Utc};
use quinn::{Connection, Endpoint, ServerConfig, crypto::rustls::QuicServerConfig};
use review_protocol::types::{SamplingKind, SamplingPolicy};
use tokio::sync::{Mutex, Notify, RwLock};

use super::{Client, Conn, TimeSeries};
use crate::client::Certs;

static TOKEN: LazyLock<Mutex<u32>> = LazyLock::new(|| Mutex::new(0));

const CERT_PATH: &str = "tests/cert.pem";
const KEY_PATH: &str = "tests/key.pem";
const CA_CERT_PATH: &str = "tests/ca_cert.pem";
const HOST: &str = "localhost";
const TEST_INGEST_PORT: u16 = 60190;
const TEST_PUBLISH_PORT: u16 = 60191;
const PROTOCOL_VERSION: &str = "0.4.0";
const LAST_TIME_SERIES_PATH: &str = "tests/time_data.json";
const SECS_PER_MINUTE: u64 = 60;
const SECS_PER_DAY: u64 = 86_400;

struct TestServer {
    server_config: ServerConfig,
    server_address: SocketAddr,
}

impl TestServer {
    fn new(port: u16) -> Self {
        let server_config = config_server();
        let server_address = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port);
        TestServer {
            server_config,
            server_address,
        }
    }

    async fn run(self) {
        let endpoint = Endpoint::server(self.server_config, self.server_address).expect("endpoint");
        while let Some(conn) = endpoint.accept().await {
            tokio::spawn(async move { handle_connection(conn).await });
        }
    }
}

async fn handle_connection(conn: quinn::Incoming) {
    let connection = conn.await.unwrap();
    connection_handshake(&connection).await;

    let conn_event = gen_conn();
    let conn_raw_event = bincode::serialize(&conn_event).unwrap();
    let conn_len = u32::try_from(conn_raw_event.len()).unwrap().to_le_bytes();

    let (mut send, _) = connection.accept_bi().await.unwrap();
    let ts = Utc::now().timestamp_nanos_opt().unwrap_or(i64::MAX);
    let mut send_buf: Vec<u8> = Vec::new();
    send_buf.extend(ts.to_le_bytes());
    send_buf.extend(conn_len);
    send_buf.extend_from_slice(&conn_raw_event);
    send.write_all(&send_buf).await.unwrap();
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

fn client() -> Client {
    let certs = cert_key();
    let (_, rx) = async_channel::unbounded();

    Client::new(
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), TEST_INGEST_PORT),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), TEST_PUBLISH_PORT),
        String::from(HOST),
        PathBuf::from(LAST_TIME_SERIES_PATH),
        &certs,
        rx,
    )
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

async fn connection_handshake(conn: &Connection) {
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .expect("Failed to open bidirectional channel");
    let version_len = u64::try_from(PROTOCOL_VERSION.len())
        .expect("less than u64::MAX")
        .to_le_bytes();

    let mut handshake_buf = Vec::with_capacity(version_len.len() + PROTOCOL_VERSION.len());
    handshake_buf.extend(version_len);
    handshake_buf.extend(PROTOCOL_VERSION.as_bytes());
    send.write_all(&handshake_buf)
        .await
        .expect("Failed to send handshake data");
    let mut resp_len_buf = [0; std::mem::size_of::<u64>()];
    recv.read_exact(&mut resp_len_buf)
        .await
        .expect("Failed to receive handshake data");
    let len = u64::from_le_bytes(resp_len_buf);

    let mut resp_buf = vec![0; len.try_into().expect("Failed to convert data type")];
    recv.read_exact(resp_buf.as_mut_slice()).await.unwrap();

    bincode::deserialize::<Option<&str>>(&resp_buf)
        .expect("Failed to deserialize recv data")
        .expect("Incompatible version");
}

fn test_conn_model() -> (SamplingPolicy, TimeSeries) {
    (
        SamplingPolicy {
            id: 0,
            kind: SamplingKind::Conn,
            interval: Duration::from_secs(15 * SECS_PER_MINUTE),
            period: Duration::from_secs(SECS_PER_DAY),
            offset: 32_400,
            src_ip: None,
            dst_ip: None,
            node: Some("cluml".to_string()),
            column: None,
        },
        TimeSeries {
            sampling_policy_id: "0".to_string(),
            start: DateTime::<Utc>::from_naive_utc_and_offset(
                NaiveDate::from_ymd_opt(2022, 11, 17)
                    .unwrap()
                    .and_hms_opt(0, 0, 0)
                    .unwrap(),
                Utc,
            ),
            series: vec![0_f64; 96],
        },
    )
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

// test만들다가 현재 test할 기능이 없어 쓰지 않지만
// 추가적으로 기능 구현할 때 수정하여 쓸수 있게 일단 남겨두었습니다.
// #[tokio::test]
#[allow(unused)]
async fn connect() {
    let _lock = TOKEN.lock().await;
    let ingest_server = TestServer::new(TEST_INGEST_PORT);
    let publish_server = TestServer::new(TEST_PUBLISH_PORT);
    tokio::spawn(ingest_server.run());
    tokio::spawn(publish_server.run());
    client()
        .run(
            Arc::new(RwLock::new(HashMap::new())),
            Arc::new(RwLock::new(Vec::new())),
            Arc::new(Notify::new()),
        )
        .await;
}

// start time: 2022/11/17 00:00:00
// input time: 2022/11/17 00:03:00 + 3min for loop
// interval: 15min
// period: 1day
#[tokio::test]
async fn timeseries_with_conn() {
    use crate::subscribe::TimeSeries;
    const THREE_MIN: i64 = 3;

    let (model, mut timeseries) = test_conn_model();
    let mut min: i64 = 3;
    let (sender, _receiver) = async_channel::bounded::<TimeSeries>(1);

    while min < 10 {
        // 3times
        let conn_event = gen_conn();
        let dur = chrono::TimeDelta::try_minutes(min).unwrap();

        let time = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2022, 11, 17)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap()
                .checked_add_signed(dur)
                .unwrap(),
            Utc,
        );

        timeseries
            .fill(
                &model,
                time,
                &crate::subscribe::Event::Conn(conn_event),
                &sender,
            )
            .await
            .unwrap();

        min += THREE_MIN;
    }

    assert_eq!(
        timeseries.series[36].partial_cmp(&3.0),
        Some(Ordering::Equal),
    );
}

#[cfg(feature = "integration-tests")]
mod integration {
    //! Integration tests for the subscription pipeline using a fake Giganto server.

    use std::{
        collections::HashMap,
        fs,
        net::{IpAddr, Ipv6Addr, SocketAddr},
        sync::Arc,
        time::Duration,
    };

    use quinn::{
        Connection, Endpoint, RecvStream, SendStream, ServerConfig,
        crypto::rustls::QuicServerConfig,
    };
    use review_protocol::types::{SamplingKind, SamplingPolicy};
    use serde::Serialize;
    use tempfile::NamedTempFile;
    use tokio::{
        sync::{Notify, RwLock},
        time::timeout,
    };

    use crate::{
        client::Certs,
        subscribe::{Client, time_series::read_last_timestamp},
    };

    const CERT_PATH: &str = "tests/cert.pem";
    const KEY_PATH: &str = "tests/key.pem";
    const CA_CERT_PATH: &str = "tests/ca_cert.pem";
    const GIGANTO_VERSION: &str = "0.26.0";
    const TIMEOUT_SECS: u64 = 10;
    const SECS_PER_MINUTE: u64 = 60;
    const SECS_PER_DAY: u64 = 86_400;
    const TEST_INGEST_PORT_BASE: u16 = 60200;
    const TEST_PUBLISH_PORT_BASE: u16 = 60300;

    /// Events tracked by the fake server for test assertions.
    #[derive(Debug, Clone)]
    enum StreamEvent {
        /// A stream was opened for a policy ID.
        Opened(u32),
        /// A stream was closed for a policy ID.
        Closed(u32),
        /// Time series data was received.
        #[allow(dead_code)]
        TimeSeriesReceived,
    }

    /// A fake Giganto server that tracks stream events for testing.
    struct FakeGigantoServer {
        ingest_port: u16,
        publish_port: u16,
        stream_events: Arc<RwLock<Vec<StreamEvent>>>,
    }

    impl FakeGigantoServer {
        /// Creates a new fake Giganto server on the specified ports.
        fn new(ingest_port: u16, publish_port: u16) -> Self {
            Self {
                ingest_port,
                publish_port,
                stream_events: Arc::new(RwLock::new(Vec::new())),
            }
        }

        /// Returns a handle to the stream events for assertions.
        fn stream_events(&self) -> Arc<RwLock<Vec<StreamEvent>>> {
            self.stream_events.clone()
        }

        /// Runs the fake server until shutdown is notified.
        async fn run(self, shutdown: Arc<Notify>) {
            let ingest_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), self.ingest_port);
            let publish_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), self.publish_port);

            let server_config = config_server();

            let ingest_endpoint =
                Endpoint::server(server_config.clone(), ingest_addr).expect("ingest endpoint");
            let publish_endpoint =
                Endpoint::server(server_config, publish_addr).expect("publish endpoint");

            let stream_events = self.stream_events.clone();
            let shutdown_clone = shutdown.clone();

            tokio::select! {
                () = Self::run_ingest_server(ingest_endpoint, stream_events.clone()) => {}
                () = Self::run_publish_server(publish_endpoint, stream_events) => {}
                () = shutdown_clone.notified() => {}
            }
        }

        async fn run_ingest_server(
            endpoint: Endpoint,
            stream_events: Arc<RwLock<Vec<StreamEvent>>>,
        ) {
            while let Some(conn) = endpoint.accept().await {
                let stream_events = stream_events.clone();
                tokio::spawn(async move {
                    if let Ok(connection) = conn.await {
                        Self::handle_ingest_connection(connection, stream_events).await;
                    }
                });
            }
        }

        async fn run_publish_server(
            endpoint: Endpoint,
            stream_events: Arc<RwLock<Vec<StreamEvent>>>,
        ) {
            while let Some(conn) = endpoint.accept().await {
                let stream_events = stream_events.clone();
                tokio::spawn(async move {
                    if let Ok(connection) = conn.await {
                        Self::handle_publish_connection(connection, stream_events).await;
                    }
                });
            }
        }

        async fn handle_ingest_connection(
            conn: Connection,
            stream_events: Arc<RwLock<Vec<StreamEvent>>>,
        ) {
            // Perform handshake - accept the bidirectional stream opened by the client
            let Ok((send, mut recv)) = conn.accept_bi().await else {
                return;
            };
            if Self::server_handshake_on_stream(send, &mut recv)
                .await
                .is_err()
            {
                return;
            }

            // Accept bidirectional streams for time series data
            while let Ok((send, recv)) = conn.accept_bi().await {
                let stream_events = stream_events.clone();
                tokio::spawn(async move {
                    Self::handle_ingest_stream(send, recv, stream_events).await;
                });
            }
        }

        async fn handle_publish_connection(
            conn: Connection,
            stream_events: Arc<RwLock<Vec<StreamEvent>>>,
        ) {
            // Perform handshake - accept the bidirectional stream opened by the client
            let Ok((send, mut recv)) = conn.accept_bi().await else {
                return;
            };
            if Self::server_handshake_on_stream(send, &mut recv)
                .await
                .is_err()
            {
                return;
            }

            // After handshake, the client sends stream requests on the SAME stream
            // We need to continuously read stream requests from recv
            let conn_clone = conn.clone();
            let stream_events_clone = stream_events.clone();
            tokio::spawn(async move {
                Self::handle_stream_requests(conn_clone, recv, stream_events_clone).await;
            });
        }

        async fn handle_stream_requests(
            conn: Connection,
            mut recv: RecvStream,
            stream_events: Arc<RwLock<Vec<StreamEvent>>>,
        ) {
            // Continuously read stream requests
            loop {
                // Read stream request (4 bytes length + bincode data)
                let mut len_buf = [0u8; 4];
                if recv.read_exact(&mut len_buf).await.is_err() {
                    break;
                }
                #[allow(clippy::cast_possible_truncation)]
                let len = u32::from_le_bytes(len_buf) as usize;
                let mut request_buf = vec![0u8; len];
                if recv.read_exact(&mut request_buf).await.is_err() {
                    break;
                }

                // Parse the policy ID from the request
                let policy_id = Self::extract_policy_id(&request_buf);

                // Record stream open
                stream_events
                    .write()
                    .await
                    .push(StreamEvent::Opened(policy_id));

                // Open a unidirectional stream to send data back
                let Ok(uni_send) = conn.open_uni().await else {
                    continue;
                };

                let stream_events_clone = stream_events.clone();
                tokio::spawn(async move {
                    Self::send_stream_data(uni_send, policy_id, stream_events_clone).await;
                });
            }
        }

        async fn send_stream_data(
            mut uni_send: SendStream,
            policy_id: u32,
            stream_events: Arc<RwLock<Vec<StreamEvent>>>,
        ) {
            // Send the stream start message (policy ID as string)
            let id_str = policy_id.to_string();
            let id_bytes = id_str.as_bytes();
            #[allow(clippy::cast_possible_truncation)]
            let id_len = (id_bytes.len() as u32).to_le_bytes();
            let mut start_msg = Vec::with_capacity(4 + id_bytes.len());
            start_msg.extend_from_slice(&id_len);
            start_msg.extend_from_slice(id_bytes);
            if uni_send.write_all(&start_msg).await.is_err() {
                stream_events
                    .write()
                    .await
                    .push(StreamEvent::Closed(policy_id));
                return;
            }

            // Continuously send test data so the client can check for deletion
            let conn_raw = gen_test_conn();

            loop {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;

                let timestamp = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(i64::MAX);

                // Send timestamp (8 bytes) + length (4 bytes) + data
                let mut event_buf = Vec::new();
                event_buf.extend_from_slice(&timestamp.to_le_bytes());
                #[allow(clippy::cast_possible_truncation)]
                let len = (conn_raw.len() as u32).to_le_bytes();
                event_buf.extend_from_slice(&len);
                event_buf.extend_from_slice(&conn_raw);

                if uni_send.write_all(&event_buf).await.is_err() {
                    // Stream was closed by the client
                    stream_events
                        .write()
                        .await
                        .push(StreamEvent::Closed(policy_id));
                    break;
                }
            }
        }

        async fn server_handshake_on_stream(
            mut send: SendStream,
            recv: &mut RecvStream,
        ) -> Result<(), ()> {
            // Read version length (8 bytes little-endian)
            let mut len_buf = [0u8; 8];
            if recv.read_exact(&mut len_buf).await.is_err() {
                return Err(());
            }
            #[allow(clippy::cast_possible_truncation)]
            let len = u64::from_le_bytes(len_buf) as usize;

            // Read version string
            let mut version_buf = vec![0u8; len];
            if recv.read_exact(&mut version_buf).await.is_err() {
                return Err(());
            }

            // Send response: length + bincode-serialized Option<&str>
            let response: Option<&str> = Some(GIGANTO_VERSION);
            let response_bytes = bincode::serialize(&response).unwrap_or_default();
            let response_len = (response_bytes.len() as u64).to_le_bytes();

            let mut response_buf = Vec::with_capacity(8 + response_bytes.len());
            response_buf.extend_from_slice(&response_len);
            response_buf.extend_from_slice(&response_bytes);

            if send.write_all(&response_buf).await.is_err() {
                return Err(());
            }

            Ok(())
        }

        #[allow(clippy::cast_possible_truncation)]
        async fn handle_ingest_stream(
            mut send: SendStream,
            mut recv: RecvStream,
            stream_events: Arc<RwLock<Vec<StreamEvent>>>,
        ) {
            // Read record type header (4 bytes length + data)
            let mut len_buf = [0u8; 4];
            if recv.read_exact(&mut len_buf).await.is_err() {
                return;
            }
            let len = u32::from_le_bytes(len_buf) as usize;
            let mut record_type_buf = vec![0u8; len];
            if recv.read_exact(&mut record_type_buf).await.is_err() {
                return;
            }

            // Continuously receive time series data
            loop {
                // Read batch data length
                let mut batch_len_buf = [0u8; 4];
                match recv.read_exact(&mut batch_len_buf).await {
                    Ok(()) => {}
                    Err(_) => break,
                }
                let batch_len = u32::from_le_bytes(batch_len_buf) as usize;

                // Read batch data
                let mut batch_buf = vec![0u8; batch_len];
                if recv.read_exact(&mut batch_buf).await.is_err() {
                    break;
                }

                // Try to deserialize to get the timestamp for ACK
                if let Ok(batch) = bincode::deserialize::<Vec<(i64, Vec<u8>)>>(&batch_buf) {
                    for (timestamp, _data) in &batch {
                        // Record that we received time series data
                        stream_events
                            .write()
                            .await
                            .push(StreamEvent::TimeSeriesReceived);

                        // Send ACK timestamp (8 bytes little-endian)
                        let ack_timestamp = timestamp.to_le_bytes();
                        if send.write_all(&ack_timestamp).await.is_err() {
                            return;
                        }
                    }
                }
            }
        }

        fn extract_policy_id(request_buf: &[u8]) -> u32 {
            // The StreamRequestPayload is bincode-serialized
            // We need to extract the policy ID from the request
            // For simplicity, we'll try to find a parseable u32 from the ID string field
            // The format is: TimeSeriesGenerator { record_type, request: { start, id, ... } }

            // Try to find the "id" field which should be a string representation of u32
            // This is a simplified extraction - in practice we'd deserialize properly
            // but that would require importing giganto-client types

            // Look for a string that could be a policy ID (1-4 digits)
            let s = String::from_utf8_lossy(request_buf);
            for word in s.split(|c: char| !c.is_ascii_digit()) {
                if !word.is_empty()
                    && let Ok(id) = word.parse::<u32>()
                    && id < 1000
                {
                    // Reasonable policy ID range
                    return id;
                }
            }
            0
        }
    }

    fn config_server() -> ServerConfig {
        let cert_pem = fs::read(CERT_PATH).expect("read cert");
        let key_pem = fs::read(KEY_PATH).expect("read key");
        let ca_cert_pem = fs::read(CA_CERT_PATH).expect("read ca cert");

        let certs: Vec<_> = rustls_pemfile::certs(&mut &*cert_pem)
            .collect::<Result<_, _>>()
            .expect("parse certs");
        let key = rustls_pemfile::private_key(&mut &*key_pem)
            .expect("parse key")
            .expect("no key");
        let ca_certs: Vec<_> = rustls_pemfile::certs(&mut &*ca_cert_pem)
            .collect::<Result<_, _>>()
            .expect("parse ca certs");

        let mut root_store = rustls::RootCertStore::empty();
        for cert in ca_certs {
            root_store.add(cert).expect("add ca cert");
        }

        let client_auth = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .expect("build client verifier");

        let server_crypto = rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_auth)
            .with_single_cert(certs, key)
            .expect("build server config");

        let mut server_config = ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(server_crypto).expect("quic server config"),
        ));

        Arc::get_mut(&mut server_config.transport)
            .expect("get transport")
            .max_concurrent_uni_streams(100u32.into())
            .max_concurrent_bidi_streams(100u32.into());

        server_config
    }

    /// Generates a test Conn event as raw bytes for sending to clients.
    /// This matches the Conn struct layout in giganto-client.
    fn gen_test_conn() -> Vec<u8> {
        #[derive(Serialize)]
        #[allow(clippy::struct_field_names)]
        struct Conn {
            orig_addr: IpAddr,
            resp_addr: IpAddr,
            orig_port: u16,
            resp_port: u16,
            proto: u8,
            service: String,
            conn_state: String,
            start_time: i64,
            duration: i64,
            orig_bytes: u64,
            resp_bytes: u64,
            orig_pkts: u64,
            resp_pkts: u64,
            orig_l2_bytes: u64,
            resp_l2_bytes: u64,
        }

        let conn = Conn {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_addr: "192.168.4.77".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_port: 80,
            proto: 6,
            service: String::new(),
            conn_state: "OK".to_string(),
            start_time: 500,
            duration: 12345,
            orig_bytes: 77,
            resp_bytes: 295,
            orig_pkts: 397,
            resp_pkts: 511,
            orig_l2_bytes: 51235,
            resp_l2_bytes: 48203,
        };

        bincode::serialize(&conn).unwrap_or_default()
    }

    fn test_policy(id: u32) -> SamplingPolicy {
        SamplingPolicy {
            id,
            kind: SamplingKind::Conn,
            interval: Duration::from_secs(15 * SECS_PER_MINUTE),
            period: Duration::from_secs(SECS_PER_DAY),
            offset: 32_400,
            src_ip: None,
            dst_ip: None,
            node: Some("test_node".to_string()),
            column: None,
        }
    }

    fn load_test_certs() -> Certs {
        let cert_pem = fs::read(CERT_PATH).expect("Failed to read cert.pem");
        let key_pem = fs::read(KEY_PATH).expect("Failed to read key.pem");
        let ca_cert_pem = fs::read(CA_CERT_PATH).expect("Failed to read ca_cert.pem");

        let certs = Certs::to_cert_chain(&cert_pem).expect("parse cert");
        let key = Certs::to_private_key(&key_pem).expect("parse key");
        let ca_certs = Certs::to_ca_certs(&[&ca_cert_pem]).expect("parse ca");

        Certs {
            certs,
            key,
            ca_certs,
        }
    }

    /// Test: When a policy is added, a stream should be opened.
    /// When the policy is deleted, the stream should be closed.
    #[tokio::test]
    async fn stream_lifecycle_on_policy_add_delete() {
        // Each test uses unique ports to avoid conflicts
        let port_offset = 0;
        let ingest_port = TEST_INGEST_PORT_BASE + port_offset;
        let publish_port = TEST_PUBLISH_PORT_BASE + port_offset;

        // Create a temporary file for timestamp data
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let last_series_time_path = temp_file.path().to_path_buf();

        // Initialize the timestamp file with empty JSON object
        std::fs::write(&last_series_time_path, "{}").expect("Failed to write timestamp file");

        // Start the fake Giganto server
        let server = FakeGigantoServer::new(ingest_port, publish_port);
        let stream_events = server.stream_events();
        let shutdown = Arc::new(Notify::new());
        let server_shutdown = shutdown.clone();

        let server_handle = tokio::spawn(async move {
            server.run(server_shutdown).await;
        });

        // Give the server time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Create the subscription client
        let (request_send, request_recv) = async_channel::bounded(10);
        let active_policy_list: Arc<RwLock<HashMap<u32, SamplingPolicy>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let delete_policy_ids: Arc<RwLock<Vec<u32>>> = Arc::new(RwLock::new(Vec::new()));

        let ingest_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), ingest_port);
        let publish_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), publish_port);

        let certs = load_test_certs();
        let client = Client::new(
            ingest_addr,
            publish_addr,
            "localhost".to_string(),
            last_series_time_path.clone(),
            &certs,
            request_recv,
        );

        let client_shutdown = Arc::new(Notify::new());
        let client_shutdown_clone = client_shutdown.clone();
        let active_policy_list_clone = active_policy_list.clone();
        let delete_policy_ids_clone = delete_policy_ids.clone();

        let client_handle = tokio::spawn(async move {
            let _ = client
                .run(
                    active_policy_list_clone,
                    delete_policy_ids_clone,
                    client_shutdown_clone,
                )
                .await;
        });

        // Give the client time to connect
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Add a policy - this should trigger a stream open
        let policy = test_policy(1);
        active_policy_list
            .write()
            .await
            .insert(policy.id, policy.clone());
        request_send
            .send(policy.clone())
            .await
            .expect("Failed to send policy");

        // Wait for stream open event
        let stream_open = timeout(Duration::from_secs(TIMEOUT_SECS), async {
            loop {
                let events = stream_events.read().await;
                if events.iter().any(|e| matches!(e, StreamEvent::Opened(1))) {
                    return true;
                }
                drop(events);
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;

        assert!(
            stream_open.is_ok(),
            "Timed out waiting for stream open event"
        );

        // Delete the policy - this should trigger stream close
        active_policy_list.write().await.remove(&1);
        delete_policy_ids.write().await.push(1);

        // Wait for stream close event
        let stream_close = timeout(Duration::from_secs(TIMEOUT_SECS), async {
            loop {
                let events = stream_events.read().await;
                if events.iter().any(|e| matches!(e, StreamEvent::Closed(1))) {
                    return true;
                }
                drop(events);
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;

        assert!(
            stream_close.is_ok(),
            "Timed out waiting for stream close event"
        );

        // Cleanup
        client_shutdown.notify_one();
        shutdown.notify_one();
        let _ = tokio::time::timeout(Duration::from_secs(2), client_handle).await;
        let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
    }

    /// Test: Adding multiple policies should open multiple streams.
    #[tokio::test]
    async fn multiple_policy_streams() {
        let port_offset = 2;
        let ingest_port = TEST_INGEST_PORT_BASE + port_offset;
        let publish_port = TEST_PUBLISH_PORT_BASE + port_offset;

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let last_series_time_path = temp_file.path().to_path_buf();
        std::fs::write(&last_series_time_path, "{}").expect("Failed to write timestamp file");

        let server = FakeGigantoServer::new(ingest_port, publish_port);
        let stream_events = server.stream_events();
        let shutdown = Arc::new(Notify::new());
        let server_shutdown = shutdown.clone();

        let server_handle = tokio::spawn(async move {
            server.run(server_shutdown).await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let (request_send, request_recv) = async_channel::bounded(10);
        let active_policy_list: Arc<RwLock<HashMap<u32, SamplingPolicy>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let delete_policy_ids: Arc<RwLock<Vec<u32>>> = Arc::new(RwLock::new(Vec::new()));

        let ingest_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), ingest_port);
        let publish_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), publish_port);

        let certs = load_test_certs();
        let client = Client::new(
            ingest_addr,
            publish_addr,
            "localhost".to_string(),
            last_series_time_path.clone(),
            &certs,
            request_recv,
        );

        let client_shutdown = Arc::new(Notify::new());
        let client_shutdown_clone = client_shutdown.clone();
        let active_policy_list_clone = active_policy_list.clone();
        let delete_policy_ids_clone = delete_policy_ids.clone();

        let client_handle = tokio::spawn(async move {
            let _ = client
                .run(
                    active_policy_list_clone,
                    delete_policy_ids_clone,
                    client_shutdown_clone,
                )
                .await;
        });

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Add multiple policies
        for id in 1..=3 {
            let policy = test_policy(id);
            active_policy_list
                .write()
                .await
                .insert(policy.id, policy.clone());
            request_send
                .send(policy)
                .await
                .expect("Failed to send policy");
        }

        // Wait for all stream open events
        let all_opened = timeout(Duration::from_secs(TIMEOUT_SECS), async {
            loop {
                let events = stream_events.read().await;
                let opened_count = events
                    .iter()
                    .filter(|e| matches!(e, StreamEvent::Opened(_)))
                    .count();
                if opened_count >= 3 {
                    return true;
                }
                drop(events);
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;

        assert!(
            all_opened.is_ok(),
            "Timed out waiting for all streams to open"
        );

        // Verify we have 3 distinct stream open events
        let events = stream_events.read().await;
        let opened_ids: Vec<u32> = events
            .iter()
            .filter_map(|e| {
                if let StreamEvent::Opened(id) = e {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect();
        assert!(opened_ids.contains(&1));
        assert!(opened_ids.contains(&2));
        assert!(opened_ids.contains(&3));

        // Cleanup
        client_shutdown.notify_one();
        shutdown.notify_one();
        let _ = tokio::time::timeout(Duration::from_secs(2), client_handle).await;
        let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
    }

    /// Test: `delete_policy_ids` triggers timestamp cleanup for deleted policies.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn delete_policy_triggers_timestamp_cleanup() {
        let port_offset = 4;
        let ingest_port = TEST_INGEST_PORT_BASE + port_offset;
        let publish_port = TEST_PUBLISH_PORT_BASE + port_offset;

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let last_series_time_path = temp_file.path().to_path_buf();

        // Initialize timestamp file with policy ID 1's timestamp
        #[allow(clippy::unreadable_literal)]
        let initial_timestamps = serde_json::json!({
            "1": 1668643200000000000_i64,
            "2": 1668729600000000000_i64
        });
        std::fs::write(
            &last_series_time_path,
            serde_json::to_string(&initial_timestamps).expect("serialize"),
        )
        .expect("Failed to write timestamp file");

        let server = FakeGigantoServer::new(ingest_port, publish_port);
        let stream_events = server.stream_events();
        let shutdown = Arc::new(Notify::new());
        let server_shutdown = shutdown.clone();

        let server_handle = tokio::spawn(async move {
            server.run(server_shutdown).await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Read the initial timestamp file to ensure policy 1 exists
        read_last_timestamp(&last_series_time_path)
            .await
            .expect("Failed to read timestamp");

        let (request_send, request_recv) = async_channel::bounded(10);
        let active_policy_list: Arc<RwLock<HashMap<u32, SamplingPolicy>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let delete_policy_ids: Arc<RwLock<Vec<u32>>> = Arc::new(RwLock::new(Vec::new()));

        let ingest_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), ingest_port);
        let publish_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), publish_port);

        let certs = load_test_certs();
        let client = Client::new(
            ingest_addr,
            publish_addr,
            "localhost".to_string(),
            last_series_time_path.clone(),
            &certs,
            request_recv,
        );

        let client_shutdown = Arc::new(Notify::new());
        let client_shutdown_clone = client_shutdown.clone();
        let active_policy_list_clone = active_policy_list.clone();
        let delete_policy_ids_clone = delete_policy_ids.clone();

        let client_handle = tokio::spawn(async move {
            let _ = client
                .run(
                    active_policy_list_clone,
                    delete_policy_ids_clone,
                    client_shutdown_clone,
                )
                .await;
        });

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Add policy 1
        let policy = test_policy(1);
        active_policy_list
            .write()
            .await
            .insert(policy.id, policy.clone());
        request_send
            .send(policy.clone())
            .await
            .expect("Failed to send policy");

        // Wait for stream open
        let stream_open = timeout(Duration::from_secs(TIMEOUT_SECS), async {
            loop {
                let events = stream_events.read().await;
                if events.iter().any(|e| matches!(e, StreamEvent::Opened(1))) {
                    return true;
                }
                drop(events);
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        assert!(stream_open.is_ok(), "Stream should open for policy 1");

        // Delete policy 1 - this should trigger timestamp cleanup
        active_policy_list.write().await.remove(&1);
        delete_policy_ids.write().await.push(1);

        // Wait for stream close and timestamp cleanup
        let cleanup_complete = timeout(Duration::from_secs(TIMEOUT_SECS), async {
            loop {
                // Check if stream was closed
                let events = stream_events.read().await;
                let stream_closed = events.iter().any(|e| matches!(e, StreamEvent::Closed(1)));
                drop(events);

                if stream_closed {
                    // Check if timestamp was cleaned up
                    let content =
                        std::fs::read_to_string(&last_series_time_path).unwrap_or_default();
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content)
                        && json.get("1").is_none()
                    {
                        return true;
                    }
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;

        assert!(
            cleanup_complete.is_ok(),
            "Timestamp cleanup should complete for deleted policy"
        );

        // Verify policy 2's timestamp is still present
        let content = std::fs::read_to_string(&last_series_time_path).expect("read file");
        let json: serde_json::Value = serde_json::from_str(&content).expect("parse json");
        assert!(
            json.get("2").is_some(),
            "Policy 2's timestamp should still exist"
        );

        // Cleanup
        client_shutdown.notify_one();
        shutdown.notify_one();
        let _ = tokio::time::timeout(Duration::from_secs(2), client_handle).await;
        let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
    }
}
