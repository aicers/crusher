#[cfg(test)]
mod tests;

use crate::{
    client::{config_client, SERVER_RETRY_INTERVAL},
    model::{convert_policy, time_series, Policy, TimeSeries},
    request::{RequestedKind, RequestedPolicy},
};
use anyhow::{bail, Context, Error, Result};
use async_channel::{Receiver, Sender};
use chrono::{TimeZone, Utc};
use lazy_static::lazy_static;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use num_traits::ToPrimitive;
use quinn::{Connection, ConnectionError, Endpoint, RecvStream, SendStream};
use rustls::{Certificate, PrivateKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::BufReader,
    mem,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    process::exit,
    sync::Arc,
};
use tokio::{
    sync::RwLock,
    task,
    time::{sleep, Duration},
};
use tracing::{error, info};

const INGESTION_PROTOCOL_VERSION: &str = "0.5.0";
const PUBLISH_PROTOCOL_VERSION: &str = "0.4.0";
const CRUSHER_CODE: u8 = 0x01;
const TIME_SERIES_CHANNEL_SIZE: usize = 1;
const LAST_TIME_SERIES_TIMESTAMP_CHANNEL_SIZE: usize = 1;
const INGESTION_TIME_SERIES_TYPE: u32 = 5;

lazy_static! {
    // A hashmap for data transfer to an already created asynchronous task
    pub static ref INGESTION_CHANNEL: RwLock<HashMap<String, Sender<TimeSeries>>> =
        RwLock::new(HashMap::new());
    // A hashmap for last series timestamp
    pub static ref LAST_TRANSFER_TIME: RwLock<HashMap<String,i64>> = RwLock::new(HashMap::new());
}

#[derive(Debug, PartialEq, Eq, TryFromPrimitive, IntoPrimitive, Clone, Copy, Deserialize)]
#[repr(u32)]
pub(crate) enum Kind {
    Conn = 0,
    Dns = 1,
    Rdp = 2,
    Http = 3,
}

impl From<RequestedKind> for Kind {
    fn from(k: RequestedKind) -> Self {
        match k {
            RequestedKind::Conn => Self::Conn,
            RequestedKind::Dns => Self::Dns,
            RequestedKind::Http => Self::Http,
            RequestedKind::Rdp => Self::Rdp,
        }
    }
}

pub(crate) enum Event {
    Conn(Conn),
    Dns(DnsConn),
    Http(HttpConn),
    Rdp(RdpConn),
}

impl Event {
    pub(crate) fn column_value(&self, column: usize) -> f64 {
        match self {
            Self::Conn(evt) => evt.column_value(column),
            Self::Dns(evt) => evt.column_value(column),
            Self::Http(evt) => evt.column_value(column),
            Self::Rdp(evt) => evt.column_value(column),
        }
    }
}

trait ColumnValue {
    fn column_value(&self, _: usize) -> f64 {
        1_f64
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Conn {
    orig_addr: IpAddr, // 0
    resp_addr: IpAddr,
    orig_port: u16,
    resp_port: u16,
    proto: u8,
    duration: i64,   // 5
    orig_bytes: u64, // 6
    resp_bytes: u64, // 7
    orig_pkts: u64,  // 8
    resp_pkts: u64,  // 9
}

impl ColumnValue for Conn {
    fn column_value(&self, column: usize) -> f64 {
        match column {
            5 => self.duration.to_f64().unwrap_or_default(),
            6 => self.orig_bytes.to_f64().unwrap_or_default(),
            7 => self.resp_bytes.to_f64().unwrap_or_default(),
            8 => self.orig_pkts.to_f64().unwrap_or_default(),
            9 => self.resp_pkts.to_f64().unwrap_or_default(),
            _ => 1_f64,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct DnsConn {
    orig_addr: IpAddr,
    resp_addr: IpAddr,
    orig_port: u16,
    resp_port: u16,
    proto: u8,
    query: String,
}

impl ColumnValue for DnsConn {}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RdpConn {
    orig_addr: IpAddr,
    resp_addr: IpAddr,
    orig_port: u16,
    resp_port: u16,
    cookie: String,
}

impl ColumnValue for RdpConn {}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct HttpConn {
    orig_addr: IpAddr,
    resp_addr: IpAddr,
    orig_port: u16,
    resp_port: u16,
    method: String,
    host: String,
    uri: String,
    referrer: String,
    user_agent: String,
    status_code: u16,
}

impl ColumnValue for HttpConn {}

pub struct Client {
    ingestion_addr: SocketAddr,
    publish_addr: SocketAddr,
    server_name: String,
    endpoint: Endpoint,
    request_recv: Receiver<RequestedPolicy>,
    last_series_time_path: PathBuf,
}

#[allow(clippy::too_many_arguments)]
impl Client {
    pub fn new(
        ingestion_addr: SocketAddr,
        publish_addr: SocketAddr,
        server_name: String,
        last_series_time_path: PathBuf,
        certs: Vec<Certificate>,
        key: PrivateKey,
        files: Vec<Vec<u8>>,
        request_recv: Receiver<RequestedPolicy>,
    ) -> Self {
        let endpoint = config_client(certs, key, files)
            .expect("server configuration error with cert, key or root");
        Client {
            ingestion_addr,
            publish_addr,
            server_name,
            endpoint,
            request_recv,
            last_series_time_path,
        }
    }

    pub async fn run(self) {
        let (sender, receiver) = async_channel::bounded::<TimeSeries>(TIME_SERIES_CHANNEL_SIZE);
        if let Err(e) = tokio::try_join!(
            ingestion_connection_control(
                receiver,
                self.ingestion_addr,
                self.server_name.clone(),
                self.endpoint.clone(),
                self.last_series_time_path,
                INGESTION_PROTOCOL_VERSION,
            ),
            publish_connection_control(
                sender,
                self.publish_addr,
                &self.server_name,
                &self.endpoint,
                PUBLISH_PROTOCOL_VERSION,
                &self.request_recv,
            )
        ) {
            error!("giganto connection error occur : {}", e);
        }
    }
}

async fn ingestion_connection_control(
    series_recv: Receiver<TimeSeries>,
    server_addr: SocketAddr,
    server_name: String,
    endpoint: Endpoint,
    last_series_time_path: PathBuf,
    version: &str,
) -> Result<()> {
    loop {
        match ingestion_connect(
            series_recv.clone(),
            &endpoint,
            server_addr,
            &server_name,
            last_series_time_path.clone(),
            version,
        )
        .await
        {
            Ok(_) => return Ok(()),
            Err(e) => {
                if let Some(e) = e.downcast_ref::<ConnectionError>() {
                    match e {
                        ConnectionError::ConnectionClosed(_)
                        | ConnectionError::ApplicationClosed(_)
                        | ConnectionError::Reset
                        | ConnectionError::TimedOut => {
                            error!(
                                "Retry connection to {} after {} seconds.",
                                server_addr, SERVER_RETRY_INTERVAL,
                            );
                            sleep(Duration::from_secs(SERVER_RETRY_INTERVAL)).await;
                            continue;
                        }
                        ConnectionError::TransportError(_) => {
                            error!("Invalid peer certificate contents");
                            exit(0)
                        }
                        _ => {}
                    }
                }
                bail!("Fail to connect to {}: {:?}", server_addr, e);
            }
        }
    }
}

async fn publish_connection_control(
    series_send: Sender<TimeSeries>,
    server_addr: SocketAddr,
    server_name: &str,
    endpoint: &Endpoint,
    version: &str,
    request_recv: &Receiver<RequestedPolicy>,
) -> Result<()> {
    loop {
        match publish_connect(
            series_send.clone(),
            endpoint,
            server_addr,
            server_name,
            version,
            request_recv,
        )
        .await
        {
            Ok(_) => return Ok(()),
            Err(e) => {
                if let Some(e) = e.downcast_ref::<ConnectionError>() {
                    match e {
                        ConnectionError::ConnectionClosed(_)
                        | ConnectionError::ApplicationClosed(_)
                        | ConnectionError::Reset
                        | ConnectionError::TimedOut => {
                            error!(
                                "Retry connection to {} after {} seconds.",
                                server_addr, SERVER_RETRY_INTERVAL,
                            );
                            sleep(Duration::from_secs(SERVER_RETRY_INTERVAL)).await;
                            continue;
                        }
                        ConnectionError::TransportError(_) => {
                            error!("Invalid peer certificate contents");
                            exit(0)
                        }
                        _ => {}
                    }
                }
                bail!("Fail to connect to {}: {:?}", server_addr, e);
            }
        }
    }
}

#[allow(clippy::too_many_lines)] // TODO: Remove this if not necessary when completing codes
async fn ingestion_connect(
    series_recv: Receiver<TimeSeries>,
    endpoint: &Endpoint,
    server_address: SocketAddr,
    server_name: &str,
    last_series_time_path: PathBuf,
    version: &str,
) -> Result<()> {
    let conn = endpoint.connect(server_address, server_name)?.await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    if let Err(e) = client_handshake(version, &mut send, &mut recv).await {
        error!("Giganto handshake failed: {:#}", e);
        bail!("{}", e);
    }
    info!("Connection established to server {}", server_address);

    let arc_conn = Arc::new(conn);

    // Write last time_series timestamp
    let (time_sender, time_receiver) =
        async_channel::bounded::<(String, i64)>(LAST_TIME_SERIES_TIMESTAMP_CHANNEL_SIZE);
    tokio::spawn(write_last_timestamp(last_series_time_path, time_receiver));

    // First time_series data receive
    while let Ok(series) = series_recv.recv().await {
        let connection = arc_conn.clone();
        tokio::spawn(send_time_series(connection, series, time_sender.clone()));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // TODO: Remove this if not necessary when completing codes
async fn publish_connect(
    series_send: Sender<TimeSeries>,
    endpoint: &Endpoint,
    server_address: SocketAddr,
    server_name: &str,
    version: &str,
    request_recv: &Receiver<RequestedPolicy>,
) -> Result<()> {
    let conn = endpoint.connect(server_address, server_name)?.await?;
    let (mut send, mut recv) = conn.open_bi().await?;

    if let Err(e) = client_handshake(version, &mut send, &mut recv).await {
        error!("Giganto handshake failed: {:#}", e);
        bail!("{}", e);
    }

    info!("Connection established to server {}", server_address);

    loop {
        let req_pol = request_recv.recv().await?;
        let conn = conn.clone();
        let sender = series_send.clone();
        let start: i64 = 0;

        // TODO: Read the recently saved time of period and send it to giganto (issue #13)
        // let saved_start = Utc.ymd(2022, 11, 10).and_hms(0, 0, 0).timestamp_nanos();

        // if saved_start > start {
        //     start = saved_start;
        // }

        let (policy, series) = convert_policy(start, req_pol);

        // TODO: Establish the channel by model (issue #15)
        request_network_stream(
            &mut send,
            policy.kind.into(),
            start,
            &policy.id,
            policy.src_ip,
            policy.dst_ip,
            policy.node.clone(),
        )
        .await?;

        task::spawn(async move { receiver(conn, policy, series, sender).await });
    }
}

#[inline]
fn error_in_ts(e: &Error) {
    error!("Failure in generating time series: {}", e);
}

async fn client_handshake(
    version: &str,
    send: &mut SendStream,
    recv: &mut RecvStream,
) -> Result<()> {
    let version_len = u64::try_from(version.len())
        .expect("less than u64::MAX")
        .to_le_bytes();

    let mut handshake_buf = Vec::with_capacity(version_len.len() + version.len());
    handshake_buf.extend(version_len);
    handshake_buf.extend(version.as_bytes());
    send.write_all(&handshake_buf).await?;

    let mut resp_len_buf = [0; std::mem::size_of::<u64>()];
    recv.read_exact(&mut resp_len_buf).await?;
    let len = u64::from_le_bytes(resp_len_buf);

    let mut resp_buf = Vec::new();
    resp_buf.resize(len.try_into()?, 0);
    recv.read_exact(resp_buf.as_mut_slice()).await?;

    if bincode::deserialize::<Option<&str>>(&resp_buf)
        .unwrap()
        .is_none()
    {
        bail!("Incompatible version");
    }

    Ok(())
}

async fn request_network_stream(
    send: &mut SendStream,
    protocol: u32,
    start: i64,
    model_id: &str,
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    node_id: Option<String>,
) -> Result<()> {
    let mut req_data: Vec<u8> = Vec::new();
    req_data.extend(CRUSHER_CODE.to_le_bytes());
    req_data.extend(protocol.to_le_bytes());

    let mut request_msg =
        bincode::serialize(&(start, model_id.to_string(), src_ip, dst_ip, node_id))?;
    let frame_len: u32 = request_msg.len().try_into()?;
    req_data.extend(frame_len.to_le_bytes());
    req_data.append(&mut request_msg);

    send.write_all(&req_data).await?;

    Ok(())
}

async fn recv_network_stream(recv: &mut RecvStream) -> Result<(i64, Vec<u8>)> {
    let mut ts_buf = [0; mem::size_of::<u64>()];
    let mut len_buf = [0; mem::size_of::<u32>()];
    let mut body_buf: Vec<u8> = Vec::new();

    recv.read_exact(&mut ts_buf).await?;
    let timestamp = i64::from_le_bytes(ts_buf);

    recv.read_exact(&mut len_buf).await?;

    let len: usize = u32::from_le_bytes(len_buf).try_into()?;
    body_buf.resize(len, 0);
    recv.read_exact(body_buf.as_mut_slice()).await?;

    Ok((timestamp, body_buf))
}

async fn receiver(
    conn: Connection,
    policy: Policy,
    mut series: TimeSeries,
    sender: Sender<TimeSeries>,
) -> Result<()> {
    if let Ok(mut recv) = conn.accept_uni().await {
        loop {
            match recv_network_stream(&mut recv).await {
                Ok((timestamp, raw_event)) => match policy.kind {
                    Kind::Conn => {
                        let (time, Ok(event)) = (
                            Utc.timestamp_nanos(timestamp),
                            bincode::deserialize::<Conn>(&raw_event),
                        ) else {
                            continue;
                        };
                        if let Err(e) =
                            time_series(&policy, &mut series, time, &Event::Conn(event), &sender)
                                .await
                        {
                            error_in_ts(&e);
                        }
                    }
                    Kind::Dns => {
                        let (time, Ok(event)) = (
                            Utc.timestamp_nanos(timestamp),
                            bincode::deserialize::<DnsConn>(&raw_event),
                        ) else {
                            continue;
                        };
                        if let Err(e) =
                            time_series(&policy, &mut series, time, &Event::Dns(event), &sender)
                                .await
                        {
                            error_in_ts(&e);
                        }
                    }
                    Kind::Rdp => {
                        let (time, Ok(event)) = (
                            Utc.timestamp_nanos(timestamp),
                            bincode::deserialize::<RdpConn>(&raw_event),
                        ) else {
                            continue;
                        };
                        if let Err(e) =
                            time_series(&policy, &mut series, time, &Event::Rdp(event), &sender)
                                .await
                        {
                            error_in_ts(&e);
                        }
                    }
                    Kind::Http => {
                        let (time, Ok(event)) = (
                            Utc.timestamp_nanos(timestamp),
                            bincode::deserialize::<HttpConn>(&raw_event),
                        ) else {
                            continue;
                        };
                        if let Err(e) =
                            time_series(&policy, &mut series, time, &Event::Http(event), &sender)
                                .await
                        {
                            error_in_ts(&e);
                        }
                    }
                },
                Err(e) => {
                    error!("recv stream error: {:?}", e);
                    break;
                }
            }
        }
    }
    Ok(())
}

async fn send_time_series(
    connection: Arc<Connection>,
    series: TimeSeries,
    time_sender: Sender<(String, i64)>,
) -> Result<()> {
    // Store sender channel (Channel for receiving the next time_series after the first transmission)
    let sampling_policy_id = series.sampling_policy_id.clone();
    let (send_channel, recv_channel) =
        async_channel::bounded::<TimeSeries>(TIME_SERIES_CHANNEL_SIZE);
    INGESTION_CHANNEL
        .write()
        .await
        .insert(sampling_policy_id.clone(), send_channel);

    let Ok((mut series_sender, series_receiver)) = connection.open_bi().await else{
        bail!("Failed to open bi-direction QUIC channel");
    };

    // First data transmission (record type + series data)
    first_series_data(&mut series_sender, series).await?;

    // Receive start time of giganto last saved time series.
    tokio::spawn(receive_time_series_timestamp(
        series_receiver,
        sampling_policy_id,
        time_sender,
    ));

    // Data transmission after the first time (only series data)
    while let Ok(series) = recv_channel.recv().await {
        series_data(&mut series_sender, series).await?;
    }

    Ok(())
}

async fn receive_time_series_timestamp(
    mut receiver: RecvStream,
    sampling_policy_id: String,
    time_sender: Sender<(String, i64)>,
) -> Result<()> {
    let mut timestamp_buf = [0; std::mem::size_of::<u64>()];
    loop {
        match receiver.read_exact(&mut timestamp_buf).await {
            Ok(()) => {
                let recv_timestamp = i64::from_be_bytes(timestamp_buf);
                time_sender
                    .send((sampling_policy_id.clone(), recv_timestamp))
                    .await?;
            }
            Err(quinn::ReadExactError::FinishedEarly) => {
                break;
            }
            Err(e) => {
                bail!("last series times error: {}", e);
            }
        }
    }
    Ok(())
}

async fn first_series_data(sender: &mut SendStream, series: TimeSeries) -> Result<()> {
    sender
        .write_all(&INGESTION_TIME_SERIES_TYPE.to_le_bytes())
        .await
        .context("Failed to send record type data")?;
    series_data(sender, series).await?;
    Ok(())
}

async fn series_data(sender: &mut SendStream, series: TimeSeries) -> Result<()> {
    let start_time = series.start.timestamp_nanos().to_le_bytes();
    let series_data = bincode::serialize(&series)?;
    let series_data_len = u32::try_from(series_data.len())?.to_le_bytes();
    let mut data: Vec<u8> =
        Vec::with_capacity(start_time.len() + series_data_len.len() + series_data.len());
    data.extend_from_slice(&start_time);
    data.extend_from_slice(&series_data_len);
    data.extend_from_slice(&series_data);
    sender
        .write_all(&data)
        .await
        .context("Failed to send body data")?;
    Ok(())
}

async fn write_last_timestamp(
    last_series_time_path: PathBuf,
    time_receiver: Receiver<(String, i64)>,
) -> Result<()> {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(last_series_time_path)
        .context("Failed to open last time series timestamp file")?;
    while let Ok((id, timestamp)) = time_receiver.recv().await {
        LAST_TRANSFER_TIME.write().await.insert(id, timestamp);
        serde_json::to_writer(&file, &(*LAST_TRANSFER_TIME.read().await))
            .context("Failed to write last time series timestamp file")?;
    }
    Ok(())
}

async fn _read_last_timestamp(last_series_time_path: PathBuf) -> Result<()> {
    let file = File::open(last_series_time_path)
        .context("Failed to open last time series timestamp file")?;
    let json: serde_json::Value = serde_json::from_reader(BufReader::new(file))?;
    let Value::Object(map_data) = json else {
        bail!("Failed to parse json data, invaild json format")
    };
    for (key, val) in map_data {
        let Value::Number(value) = val else {
            bail!("Failed to parse timestamp data, invaild json format");
        };
        let Some(timestamp) = value.as_i64() else {
            bail!("Failed to convert timestamp data, invaild time data");
        };
        LAST_TRANSFER_TIME.write().await.insert(key, timestamp);
    }
    Ok(())
}
