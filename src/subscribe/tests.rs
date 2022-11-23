use super::{Client, Conn, Kind};
use crate::{
    model::{Interval, Period, Policy, TimeSeries},
    to_cert_chain, to_private_key,
};

use chrono::{Duration, TimeZone, Utc};
use lazy_static::lazy_static;
use quinn::{Connection, Endpoint, ServerConfig};
use rustls::{Certificate, PrivateKey};
use std::{
    fs,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
};
use tokio::sync::Mutex;

lazy_static! {
    pub(crate) static ref TOKEN: Mutex<u32> = Mutex::new(0);
}

const CERT_PATH: &str = "tests/cert.pem";
const KEY_PATH: &str = "tests/key.pem";
const CA_CERT_PATH: &str = "tests/root.pem";
const HOST: &str = "localhost";
const TEST_INGESTION_PORT: u16 = 60190;
const TEST_PUBLISH_PORT: u16 = 60191;
const PROTOCOL_VERSION: &str = "0.4.0";

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

async fn handle_connection(conn: quinn::Connecting) {
    let connection = conn.await.unwrap();
    connection_handshake(&connection).await;

    let conn_event = gen_conn();
    let conn_raw_event = bincode::serialize(&conn_event).unwrap();
    let conn_len = u32::try_from(conn_raw_event.len()).unwrap().to_le_bytes();

    let (mut send, _) = connection.accept_bi().await.unwrap();
    let ts = Utc::now().timestamp_nanos();
    let mut send_buf: Vec<u8> = Vec::new();
    send_buf.extend(ts.to_le_bytes());
    send_buf.extend(conn_len);
    send_buf.extend_from_slice(&conn_raw_event);
    send.write_all(&send_buf).await.unwrap();
}

fn config_server() -> ServerConfig {
    let (cert, key, ca_certs) = cert_key();

    let mut client_auth_roots = rustls::RootCertStore::empty();
    for ca_cert in ca_certs {
        let root_cert: Vec<rustls::Certificate> = rustls_pemfile::certs(&mut &*ca_cert)
            .unwrap()
            .into_iter()
            .map(rustls::Certificate)
            .collect();
        if let Some(cert) = root_cert.get(0) {
            client_auth_roots.add(cert).unwrap();
        }
    }

    let client_auth = rustls::server::AllowAnyAuthenticatedClient::new(client_auth_roots);
    let server_crypto = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(client_auth)
        .with_single_cert(cert, key)
        .unwrap();

    let mut server_config = ServerConfig::with_crypto(Arc::new(server_crypto));

    Arc::get_mut(&mut server_config.transport)
        .unwrap()
        .max_concurrent_uni_streams(0_u8.into());

    server_config
}

fn client() -> Client {
    let (cert, key, ca_certs) = cert_key();
    let (_, rx) = async_channel::unbounded();

    Client::new(
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), TEST_INGESTION_PORT),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), TEST_PUBLISH_PORT),
        String::from(HOST),
        cert,
        key,
        ca_certs,
        rx,
    )
}

fn cert_key() -> (Vec<Certificate>, PrivateKey, Vec<Vec<u8>>) {
    let cert_pem = fs::read(CERT_PATH).unwrap();
    let cert = to_cert_chain(&cert_pem).unwrap();
    let key_pem = fs::read(KEY_PATH).unwrap();
    let key = to_private_key(&key_pem).unwrap();
    let ca_certs = vec![fs::read(CA_CERT_PATH).unwrap()];

    (cert, key, ca_certs)
}

async fn connection_handshake(conn: &Connection) {
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .expect("Failed to open bidirection channel");
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

    let mut resp_buf = Vec::new();
    resp_buf.resize(len.try_into().expect("Failed to convert data type"), 0);
    recv.read_exact(resp_buf.as_mut_slice()).await.unwrap();

    bincode::deserialize::<Option<&str>>(&resp_buf)
        .expect("Failed to deserialize recv data")
        .expect("Incompatible version");
}

fn test_conn_model() -> (Policy, TimeSeries) {
    (
        Policy {
            id: "0".to_string(),
            kind: Kind::Conn,
            interval: Interval::FifteenMinutes,
            period: Period::OneDay,
            offset: 32_400,
            src_ip: None,
            dst_ip: None,
            node: Some("einsis".to_string()),
            column: None,
        },
        TimeSeries {
            model_id: "0".to_string(),
            start: Utc.ymd(2022, 11, 17).and_hms(0, 0, 0),
            series: vec![0_f64; 96],
        },
    )
}

fn gen_conn() -> Conn {
    let tmp_dur = Duration::nanoseconds(12345);
    let conn = Conn {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_port: 80,
        proto: 6,
        duration: tmp_dur.num_nanoseconds().unwrap(),
        orig_bytes: 77,
        resp_bytes: 295,
        orig_pkts: 397,
        resp_pkts: 511,
    };

    conn
}

// test만들다가 현재 test할 기능이 없어 쓰지 않지만
// 추가적으로 기능 구현할 때 수정하여 쓸수 있게 일단 남겨두었습니다.
// #[tokio::test]
#[allow(unused)]
async fn connect() {
    let _lock = TOKEN.lock().await;
    let ingestion_server = TestServer::new(TEST_INGESTION_PORT);
    let publish_server = TestServer::new(TEST_PUBLISH_PORT);
    tokio::spawn(ingestion_server.run());
    tokio::spawn(publish_server.run());
    client().run().await;
}

// start time: 2022/11/17 00:00:00
// input time: 2022/11/17 00:03:00 + 3min for loop
// interval: 15min
// period: 1day
#[tokio::test]
async fn timeseries_with_conn() {
    use crate::model::time_series;
    const THREE_MIN: i64 = 3;

    let (model, mut timeseries) = test_conn_model();
    let mut min: i64 = 3;

    while min < 10 {
        // 3times
        let conn_event = gen_conn();
        let dur = Duration::minutes(min);
        let time = Utc
            .ymd(2022, 11, 17)
            .and_hms(0, 0, 0)
            .checked_add_signed(dur)
            .unwrap();
        time_series(
            &model,
            &mut timeseries,
            time,
            &crate::subscribe::Event::Conn(conn_event),
        )
        .unwrap();

        min += THREE_MIN;
    }

    assert_eq!(timeseries.series[36], 3.0)
}
