#[cfg(test)]
mod tests;

use super::model::time_series;
use crate::{
    client::{config_client, SERVER_RETRY_INTERVAL},
    model::{convert_policy, Policy, TimeSeries},
    request::{RequestedKind, RequestedPolicy},
};
use anyhow::{bail, Error, Result};
use async_channel::Receiver;
use chrono::{TimeZone, Utc};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use num_traits::ToPrimitive;
use quinn::{Connection, ConnectionError, Endpoint, RecvStream, SendStream};
use rustls::{Certificate, PrivateKey};
use serde::{Deserialize, Serialize};
use std::{
    mem,
    net::{IpAddr, SocketAddr},
    process::exit,
};
use tokio::{
    task,
    time::{sleep, Duration},
};
use tracing::{error, info};

const INGESTION_PROTOCOL_VERSION: &str = "0.5.0";
const PUBLISH_PROTOCOL_VERSION: &str = "0.4.0";
const CRUSHER_CODE: u8 = 0x01;

#[derive(Debug, Clone, Copy)]
enum ServerType {
    Ingestion,
    Publish,
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
}

impl Client {
    pub fn new(
        ingestion_addr: SocketAddr,
        publish_addr: SocketAddr,
        server_name: String,
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
        }
    }

    pub async fn run(self) {
        if let Err(e) = tokio::try_join!(
            connection_control(
                ServerType::Ingestion,
                self.ingestion_addr,
                &self.server_name,
                &self.endpoint,
                INGESTION_PROTOCOL_VERSION,
                &self.request_recv,
            ),
            connection_control(
                ServerType::Publish,
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

async fn connection_control(
    server_type: ServerType,
    server_addr: SocketAddr,
    server_name: &str,
    endpoint: &Endpoint,
    version: &str,
    request_recv: &Receiver<RequestedPolicy>,
) -> Result<()> {
    loop {
        match connect(
            server_type,
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
async fn connect(
    server_type: ServerType,
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
    match server_type {
        ServerType::Publish => {
            loop {
                let req_pol = request_recv.recv().await?;
                let conn = conn.clone();
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

                task::spawn(async move { receiver(conn, policy, series).await });
            }
        }
        ServerType::Ingestion => {}
    }

    Ok(())
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

async fn receiver(conn: Connection, policy: Policy, mut series: TimeSeries) -> Result<()> {
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
                        if let Err(e) = time_series(&policy, &mut series, time, &Event::Conn(event))
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
                        if let Err(e) = time_series(&policy, &mut series, time, &Event::Dns(event))
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
                        if let Err(e) = time_series(&policy, &mut series, time, &Event::Rdp(event))
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
                        if let Err(e) = time_series(&policy, &mut series, time, &Event::Http(event))
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
