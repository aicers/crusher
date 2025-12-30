//! Fake Giganto server for integration testing.
//!
//! This module provides a minimal in-process Giganto server implementation
//! that mimics the real Giganto protocol for testing the subscription pipeline.

#![allow(
    clippy::cast_possible_truncation,
    clippy::struct_field_names,
    clippy::unwrap_used
)]

use std::{
    fs,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use quinn::{
    Connection, Endpoint, RecvStream, SendStream, ServerConfig, crypto::rustls::QuicServerConfig,
};
use tokio::sync::{Notify, RwLock};

pub const TEST_INGEST_PORT_BASE: u16 = 60200;
pub const TEST_PUBLISH_PORT_BASE: u16 = 60300;

const CERT_PATH: &str = "tests/cert.pem";
const KEY_PATH: &str = "tests/key.pem";
const CA_CERT_PATH: &str = "tests/ca_cert.pem";
const GIGANTO_VERSION: &str = "0.26.0";

/// Events tracked by the fake server for test assertions.
#[derive(Debug, Clone)]
pub enum StreamEvent {
    /// A stream was opened for a policy ID.
    Opened(u32),
    /// A stream was closed for a policy ID.
    Closed(u32),
    /// Time series data was received.
    #[allow(dead_code)]
    TimeSeriesReceived,
}

/// A fake Giganto server that tracks stream events for testing.
pub struct FakeGigantoServer {
    ingest_port: u16,
    publish_port: u16,
    stream_events: Arc<RwLock<Vec<StreamEvent>>>,
}

impl FakeGigantoServer {
    /// Creates a new fake Giganto server on the specified ports.
    pub fn new(ingest_port: u16, publish_port: u16) -> Self {
        Self {
            ingest_port,
            publish_port,
            stream_events: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Returns a handle to the stream events for assertions.
    pub fn stream_events(&self) -> Arc<RwLock<Vec<StreamEvent>>> {
        self.stream_events.clone()
    }

    /// Runs the fake server until shutdown is notified.
    pub async fn run(self, shutdown: Arc<Notify>) {
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

    async fn run_ingest_server(endpoint: Endpoint, stream_events: Arc<RwLock<Vec<StreamEvent>>>) {
        while let Some(conn) = endpoint.accept().await {
            let stream_events = stream_events.clone();
            tokio::spawn(async move {
                if let Ok(connection) = conn.await {
                    Self::handle_ingest_connection(connection, stream_events).await;
                }
            });
        }
    }

    async fn run_publish_server(endpoint: Endpoint, stream_events: Arc<RwLock<Vec<StreamEvent>>>) {
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
            event_buf.extend_from_slice(&(conn_raw.len() as u32).to_le_bytes());
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
    use std::net::IpAddr;

    use serde::Serialize;

    #[derive(Serialize)]
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
