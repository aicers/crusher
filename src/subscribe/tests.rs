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
    let conn_raw_event =
        bincode::serde::encode_to_vec(&conn_event, bincode::config::legacy()).unwrap();
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

    bincode::serde::decode_from_slice::<Option<String>, _>(&resp_buf, bincode::config::legacy())
        .expect("Failed to deserialize recv data")
        .0
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
