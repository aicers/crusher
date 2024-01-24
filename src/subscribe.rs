#[cfg(test)]
mod tests;

use crate::{
    client::{self, SERVER_RETRY_INTERVAL},
    model::{convert_policy, time_series, Period, TimeSeries},
    request::{RequestedKind, RequestedPolicy},
};
use anyhow::{bail, Context, Error, Result};
use async_channel::{Receiver, Sender};
use chrono::{TimeZone, Utc};
use giganto_client::{
    connection::client_handshake,
    frame::RecvError,
    ingest::{
        network::{
            Conn, DceRpc, Dns, Ftp, Http, Kerberos, Ldap, Mqtt, Nfs, Ntlm, Rdp, Smb, Smtp, Ssh, Tls,
        },
        receive_ack_timestamp, send_event, send_record_header,
    },
    publish::{
        receive_crusher_data, receive_crusher_stream_start_message, send_stream_request,
        stream::{NodeType, RequestCrusherStream, RequestStreamRecord},
    },
    RawEventKind,
};
use lazy_static::lazy_static;
use num_traits::ToPrimitive;
use quinn::{Connection, ConnectionError, Endpoint, RecvStream, SendStream, VarInt, WriteError};
use rustls::{Certificate, PrivateKey};
use serde_json::Value;
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::exit,
    sync::Arc,
};
use tokio::{
    sync::{Mutex, Notify, RwLock},
    task,
    time::{sleep, Duration},
};
use tracing::{error, info, trace, warn};

const INGEST_PROTOCOL_VERSION: &str = "0.15.0";
const PUBLISH_PROTOCOL_VERSION: &str = "0.15.0";
const TIME_SERIES_CHANNEL_SIZE: usize = 1;
const LAST_TIME_SERIES_TIMESTAMP_CHANNEL_SIZE: usize = 1;
const SECOND_TO_NANO: i64 = 1_000_000_000;

lazy_static! {
    // A hashmap for data transfer to an already created asynchronous task
    pub static ref INGEST_CHANNEL: RwLock<HashMap<String, Sender<TimeSeries>>> =
        RwLock::new(HashMap::new());
    // A hashmap for last series timestamp
    pub static ref LAST_TRANSFER_TIME: RwLock<HashMap<String,i64>> = RwLock::new(HashMap::new());
}

impl From<RequestedKind> for RequestStreamRecord {
    fn from(k: RequestedKind) -> Self {
        match k {
            RequestedKind::Conn => Self::Conn,
            RequestedKind::Dns => Self::Dns,
            RequestedKind::Http => Self::Http,
            RequestedKind::Rdp => Self::Rdp,
            RequestedKind::Smtp => Self::Smtp,
            RequestedKind::Ntlm => Self::Ntlm,
            RequestedKind::Kerberos => Self::Kerberos,
            RequestedKind::Ssh => Self::Ssh,
            RequestedKind::DceRpc => Self::DceRpc,
            RequestedKind::Ftp => Self::Ftp,
            RequestedKind::Mqtt => Self::Mqtt,
            RequestedKind::Ldap => Self::Ldap,
            RequestedKind::Tls => Self::Tls,
            RequestedKind::Smb => Self::Smb,
            RequestedKind::Nfs => Self::Nfs,
        }
    }
}

pub(crate) enum Event {
    Conn(Conn),
    Dns(Dns),
    Http(Http),
    Rdp(Rdp),
    Smtp(Smtp),
    Ntlm(Ntlm),
    Kerberos(Kerberos),
    Ssh(Ssh),
    DceRpc(DceRpc),
    Ftp(Ftp),
    Mqtt(Mqtt),
    Ldap(Ldap),
    Tls(Tls),
    Smb(Smb),
    Nfs(Nfs),
}

impl Event {
    pub(crate) fn column_value(&self, column: usize) -> f64 {
        match self {
            Self::Conn(evt) => evt.column_value(column),
            Self::Dns(evt) => evt.column_value(column),
            Self::Http(evt) => evt.column_value(column),
            Self::Rdp(evt) => evt.column_value(column),
            Self::Smtp(evt) => evt.column_value(column),
            Self::Ntlm(evt) => evt.column_value(column),
            Self::Kerberos(evt) => evt.column_value(column),
            Self::Ssh(evt) => evt.column_value(column),
            Self::DceRpc(evt) => evt.column_value(column),
            Self::Ftp(evt) => evt.column_value(column),
            Self::Mqtt(evt) => evt.column_value(column),
            Self::Ldap(evt) => evt.column_value(column),
            Self::Tls(evt) => evt.column_value(column),
            Self::Smb(evt) => evt.column_value(column),
            Self::Nfs(evt) => evt.column_value(column),
        }
    }
}

trait ColumnValue {
    fn column_value(&self, _: usize) -> f64 {
        1_f64
    }
}

impl ColumnValue for Conn {
    fn column_value(&self, column: usize) -> f64 {
        match column {
            5 => self.duration.to_f64().unwrap_or_default(),
            7 => self.orig_bytes.to_f64().unwrap_or_default(),
            8 => self.resp_bytes.to_f64().unwrap_or_default(),
            9 => self.orig_pkts.to_f64().unwrap_or_default(),
            10 => self.resp_pkts.to_f64().unwrap_or_default(),
            _ => 1_f64,
        }
    }
}

impl ColumnValue for Dns {}

impl ColumnValue for Rdp {}

impl ColumnValue for Http {}

impl ColumnValue for Smtp {}

impl ColumnValue for Ntlm {}

impl ColumnValue for Kerberos {}

impl ColumnValue for Ssh {}

impl ColumnValue for DceRpc {}

impl ColumnValue for Ftp {}

impl ColumnValue for Mqtt {}

impl ColumnValue for Ldap {}

impl ColumnValue for Tls {}

impl ColumnValue for Smb {}

impl ColumnValue for Nfs {}

pub struct Client {
    ingest_addr: SocketAddr,
    publish_addr: SocketAddr,
    server_name: String,
    endpoint: Endpoint,
    request_recv: Receiver<RequestedPolicy>,
    last_series_time_path: PathBuf,
}

#[allow(clippy::too_many_arguments)]
impl Client {
    pub fn new(
        ingest_addr: SocketAddr,
        publish_addr: SocketAddr,
        server_name: String,
        last_series_time_path: PathBuf,
        certs: Vec<Certificate>,
        key: PrivateKey,
        files: Vec<Vec<u8>>,
        request_recv: Receiver<RequestedPolicy>,
    ) -> Self {
        let endpoint = client::config(certs, key, files)
            .expect("Server configuration error with cert, key or root");
        Client {
            ingest_addr,
            publish_addr,
            server_name,
            endpoint,
            request_recv,
            last_series_time_path,
        }
    }

    pub async fn run(
        self,
        active_policy_list: Arc<RwLock<HashMap<u32, RequestedPolicy>>>,
        delete_policy_ids: Arc<RwLock<Vec<u32>>>,
        wait_shutdown: Arc<Notify>,
    ) {
        let (sender, receiver) = async_channel::bounded::<TimeSeries>(TIME_SERIES_CHANNEL_SIZE);
        if let Err(e) = tokio::try_join!(
            ingest_connection_control(
                receiver,
                self.ingest_addr,
                self.server_name.clone(),
                self.endpoint.clone(),
                wait_shutdown.clone(),
                self.last_series_time_path.clone(),
                INGEST_PROTOCOL_VERSION,
            ),
            publish_connection_control(
                sender,
                self.publish_addr,
                &self.server_name,
                &self.endpoint,
                wait_shutdown.clone(),
                PUBLISH_PROTOCOL_VERSION,
                &self.request_recv,
                active_policy_list,
                delete_policy_ids,
                self.last_series_time_path,
            )
        ) {
            error!("Giganto connection error occur : {}", e);
        }
    }
}

async fn ingest_connection_control(
    series_recv: Receiver<TimeSeries>,
    server_addr: SocketAddr,
    server_name: String,
    endpoint: Endpoint,
    wait_shutdown: Arc<Notify>,
    last_series_time_path: PathBuf,
    version: &str,
) -> Result<()> {
    'connection: loop {
        let connection_notify = Arc::new(Notify::new());
        match ingest_connect(&endpoint, server_addr, &server_name, version).await {
            Ok(conn) => {
                let arc_conn = Arc::new(conn);

                // Write last time_series timestamp
                let (time_sender, time_receiver) = async_channel::bounded::<(String, i64)>(
                    LAST_TIME_SERIES_TIMESTAMP_CHANNEL_SIZE,
                );
                tokio::spawn(write_last_timestamp(
                    last_series_time_path.clone(),
                    time_receiver,
                ));

                loop {
                    tokio::select! {
                        () = connection_notify.notified() => {
                            drop(connection_notify);
                            INGEST_CHANNEL.write().await.clear();
                            error!(
                                "Stream channel closed. Retry connection to {}",
                                server_addr,
                            );
                            continue 'connection;
                        }
                        () = wait_shutdown.notified() => {
                            info!("Shutting down ingest channel");
                            endpoint.close(0u32.into(), &[]);
                            return Ok(());
                        }
                        Ok(series) = series_recv.recv() => {
                            // First time_series data receive
                            let connection = arc_conn.clone();
                            tokio::spawn(send_time_series(
                                connection,
                                series,
                                time_sender.clone(),
                                connection_notify.clone(),
                            ));
                        }
                    }
                }
            }
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

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
async fn publish_connection_control(
    series_send: Sender<TimeSeries>,
    server_addr: SocketAddr,
    server_name: &str,
    endpoint: &Endpoint,
    wait_shutdown: Arc<Notify>,
    version: &str,
    request_recv: &Receiver<RequestedPolicy>,
    active_policy_list: Arc<RwLock<HashMap<u32, RequestedPolicy>>>,
    delete_policy_ids: Arc<RwLock<Vec<u32>>>,
    last_series_time_path: PathBuf,
) -> Result<()> {
    'connection: loop {
        let connection_notify = Arc::new(Notify::new());
        match publish_connect(endpoint, server_addr, server_name, version).await {
            Ok((conn, send)) => {
                let req_send = Arc::new(Mutex::new(send));
                for req_pol in active_policy_list.read().await.values() {
                    if let Err(e) = process_network_stream(
                        conn.clone(),
                        series_send.clone(),
                        req_pol.clone(),
                        req_send.clone(),
                        connection_notify.clone(),
                        active_policy_list.clone(),
                        delete_policy_ids.clone(),
                        last_series_time_path.clone(),
                    )
                    .await
                    {
                        for cause in e.chain() {
                            if let Some(e) = cause.downcast_ref::<WriteError>() {
                                match e {
                                    WriteError::ConnectionLost(_) => {
                                        continue 'connection;
                                    }
                                    WriteError::Stopped(_) => {
                                        return Ok(());
                                    }
                                    _ => {}
                                }
                            }
                            if let Some(e) = cause.downcast_ref::<ConnectionError>() {
                                match e {
                                    ConnectionError::TimedOut | ConnectionError::LocallyClosed => {
                                        continue 'connection;
                                    }
                                    _ => {}
                                }
                            }
                        }
                        bail!("Cannot recover from open stream error: {}", e);
                    }
                }
                loop {
                    tokio::select! {
                        () = connection_notify.notified() => {
                            drop(connection_notify);
                            error!(
                                "Stream channel closed. Retry connection to {} after {} seconds.",
                                server_addr, SERVER_RETRY_INTERVAL,
                            );
                            sleep(Duration::from_secs(SERVER_RETRY_INTERVAL)).await;
                            continue 'connection;
                        }
                        () = wait_shutdown.notified() => {
                            info!("Shutting down publish channel");
                            endpoint.close(0u32.into(), &[]);
                            wait_shutdown.notify_one();
                            return Ok(());
                        }
                        Ok(req_pol) = request_recv.recv() => {
                            if let Err(e) = process_network_stream(
                                conn.clone(),
                                series_send.clone(),
                                req_pol,
                                req_send.clone(),
                                connection_notify.clone(),
                                active_policy_list.clone(),
                                delete_policy_ids.clone(),
                                last_series_time_path.clone(),
                            ).await
                            {
                                for cause in e.chain() {
                                    if let Some(e) = cause.downcast_ref::<WriteError>() {
                                        match e {
                                            WriteError::ConnectionLost(_) => {
                                                continue 'connection;
                                            }
                                            WriteError::Stopped(_) => {
                                                return Ok(());
                                            }
                                            _ => {}
                                        }
                                    }
                                    if let Some(e) = cause.downcast_ref::<ConnectionError>() {
                                        match e {
                                            ConnectionError::TimedOut | ConnectionError::LocallyClosed => {
                                                continue 'connection;
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                                bail!("Cannot recover from open stream error: {}", e);
                            }
                        }
                    }
                }
            }
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

async fn ingest_connect(
    endpoint: &Endpoint,
    server_address: SocketAddr,
    server_name: &str,
    version: &str,
) -> Result<Connection> {
    let conn = endpoint.connect(server_address, server_name)?.await?;
    client_handshake(&conn, version).await?;
    info!("Connection established to server {}", server_address);
    Ok(conn)
}

async fn publish_connect(
    endpoint: &Endpoint,
    server_address: SocketAddr,
    server_name: &str,
    version: &str,
) -> Result<(Connection, SendStream)> {
    let conn = endpoint.connect(server_address, server_name)?.await?;
    let (send, _) = client_handshake(&conn, version).await?;
    info!("Connection established to server {}", server_address);
    Ok((conn, send))
}

async fn calculate_series_start_time(req_pol: &RequestedPolicy) -> Result<i64> {
    let mut start: i64 = 0;
    if let Some(last_time) = LAST_TRANSFER_TIME.read().await.get(&req_pol.id.to_string()) {
        let Some(period) = u32::from(Period::from(req_pol.period.clone())).to_i64() else {
            bail!("Failed to convert period");
        };
        let Some(period_nano) = period.checked_mul(SECOND_TO_NANO) else {
            bail!("Failed to convert period to nanoseconds");
        };
        if let Some(last_timestamp) = last_time.checked_add(period_nano) {
            start = last_timestamp;
        }
    }
    Ok(start)
}

#[allow(clippy::too_many_arguments)]
async fn process_network_stream(
    conn: Connection,
    sender: Sender<TimeSeries>,
    req_pol: RequestedPolicy,
    send: Arc<Mutex<SendStream>>,
    connection_notify: Arc<Notify>,
    active_policy_list: Arc<RwLock<HashMap<u32, RequestedPolicy>>>,
    delete_policy_ids: Arc<RwLock<Vec<u32>>>,
    last_series_time_path: PathBuf,
) -> Result<()> {
    let start = calculate_series_start_time(&req_pol).await?;
    let req_msg = RequestCrusherStream {
        start,
        id: req_pol.id.to_string(),
        src_ip: req_pol.src_ip,
        dst_ip: req_pol.dst_ip,
        source: req_pol.node.clone(),
    };
    send_stream_request(
        &mut (*send.lock().await),
        RequestStreamRecord::from(req_pol.kind),
        NodeType::Crusher,
        req_msg,
    )
    .await?;
    task::spawn(async move {
        receiver(
            conn,
            sender,
            connection_notify,
            active_policy_list,
            delete_policy_ids,
            last_series_time_path,
        )
        .await
    });
    Ok(())
}

#[inline]
fn error_in_ts(e: &Error) {
    error!("Failure in generating time series: {}", e);
}

#[allow(clippy::too_many_lines)]
async fn receiver(
    conn: Connection,
    sender: Sender<TimeSeries>,
    connection_notify: Arc<Notify>,
    active_policy_list: Arc<RwLock<HashMap<u32, RequestedPolicy>>>,
    delete_policy_ids: Arc<RwLock<Vec<u32>>>,
    last_series_time_path: PathBuf,
) -> Result<()> {
    if let Ok(mut recv) = conn.accept_uni().await {
        let Ok(id) = receive_crusher_stream_start_message(&mut recv).await else {
            connection_notify.notify_one();
            warn!("Failed to receive stream id value");
            bail!("Failed to receive stream id value");
        };

        let req_pol = if let Some(req_pol) = active_policy_list.read().await.get(&id) {
            req_pol.clone()
        } else {
            bail!("Failed to get runtime policy data");
        };

        let start = calculate_series_start_time(&req_pol).await?;
        let (policy, mut series) = convert_policy(start, req_pol);

        info!("Stream's policy : {:?}", policy);
        loop {
            if delete_policy_ids.read().await.contains(&id) {
                recv.stop(VarInt::default())?;
                delete_last_timestamp(&last_series_time_path, id)?;
                delete_policy_ids
                    .write()
                    .await
                    .retain(|&delete_id| delete_id != id);
                break;
            }
            if let Ok((raw_event, timestamp)) = receive_crusher_data(&mut recv).await {
                match policy.kind {
                    RequestStreamRecord::Conn => {
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
                    RequestStreamRecord::Dns => {
                        let (time, Ok(event)) = (
                            Utc.timestamp_nanos(timestamp),
                            bincode::deserialize::<Dns>(&raw_event),
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
                    RequestStreamRecord::Rdp => {
                        let (time, Ok(event)) = (
                            Utc.timestamp_nanos(timestamp),
                            bincode::deserialize::<Rdp>(&raw_event),
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
                    RequestStreamRecord::Http => {
                        let (time, Ok(event)) = (
                            Utc.timestamp_nanos(timestamp),
                            bincode::deserialize::<Http>(&raw_event),
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
                    RequestStreamRecord::Smtp => {
                        let (time, Ok(event)) = (
                            Utc.timestamp_nanos(timestamp),
                            bincode::deserialize::<Smtp>(&raw_event),
                        ) else {
                            continue;
                        };
                        if let Err(e) =
                            time_series(&policy, &mut series, time, &Event::Smtp(event), &sender)
                                .await
                        {
                            error_in_ts(&e);
                        }
                    }
                    RequestStreamRecord::Ntlm => {
                        let (time, Ok(event)) = (
                            Utc.timestamp_nanos(timestamp),
                            bincode::deserialize::<Ntlm>(&raw_event),
                        ) else {
                            continue;
                        };
                        if let Err(e) =
                            time_series(&policy, &mut series, time, &Event::Ntlm(event), &sender)
                                .await
                        {
                            error_in_ts(&e);
                        }
                    }
                    RequestStreamRecord::Kerberos => {
                        let (time, Ok(event)) = (
                            Utc.timestamp_nanos(timestamp),
                            bincode::deserialize::<Kerberos>(&raw_event),
                        ) else {
                            continue;
                        };
                        if let Err(e) = time_series(
                            &policy,
                            &mut series,
                            time,
                            &Event::Kerberos(event),
                            &sender,
                        )
                        .await
                        {
                            error_in_ts(&e);
                        }
                    }
                    RequestStreamRecord::Ssh => {
                        let (time, Ok(event)) = (
                            Utc.timestamp_nanos(timestamp),
                            bincode::deserialize::<Ssh>(&raw_event),
                        ) else {
                            continue;
                        };
                        if let Err(e) =
                            time_series(&policy, &mut series, time, &Event::Ssh(event), &sender)
                                .await
                        {
                            error_in_ts(&e);
                        }
                    }
                    RequestStreamRecord::DceRpc => {
                        let (time, Ok(event)) = (
                            Utc.timestamp_nanos(timestamp),
                            bincode::deserialize::<DceRpc>(&raw_event),
                        ) else {
                            continue;
                        };
                        if let Err(e) =
                            time_series(&policy, &mut series, time, &Event::DceRpc(event), &sender)
                                .await
                        {
                            error_in_ts(&e);
                        }
                    }
                    RequestStreamRecord::Ftp => {
                        let (time, Ok(event)) = (
                            Utc.timestamp_nanos(timestamp),
                            bincode::deserialize::<Ftp>(&raw_event),
                        ) else {
                            continue;
                        };
                        if let Err(e) =
                            time_series(&policy, &mut series, time, &Event::Ftp(event), &sender)
                                .await
                        {
                            error_in_ts(&e);
                        }
                    }
                    RequestStreamRecord::Mqtt => {
                        let (time, Ok(event)) = (
                            Utc.timestamp_nanos(timestamp),
                            bincode::deserialize::<Mqtt>(&raw_event),
                        ) else {
                            continue;
                        };
                        if let Err(e) =
                            time_series(&policy, &mut series, time, &Event::Mqtt(event), &sender)
                                .await
                        {
                            error_in_ts(&e);
                        }
                    }
                    RequestStreamRecord::Ldap => {
                        let (time, Ok(event)) = (
                            Utc.timestamp_nanos(timestamp),
                            bincode::deserialize::<Ldap>(&raw_event),
                        ) else {
                            continue;
                        };
                        if let Err(e) =
                            time_series(&policy, &mut series, time, &Event::Ldap(event), &sender)
                                .await
                        {
                            error_in_ts(&e);
                        }
                    }
                    RequestStreamRecord::Tls => {
                        let (time, Ok(event)) = (
                            Utc.timestamp_nanos(timestamp),
                            bincode::deserialize::<Tls>(&raw_event),
                        ) else {
                            continue;
                        };
                        if let Err(e) =
                            time_series(&policy, &mut series, time, &Event::Tls(event), &sender)
                                .await
                        {
                            error_in_ts(&e);
                        }
                    }
                    RequestStreamRecord::Smb => {
                        let (time, Ok(event)) = (
                            Utc.timestamp_nanos(timestamp),
                            bincode::deserialize::<Smb>(&raw_event),
                        ) else {
                            continue;
                        };
                        if let Err(e) =
                            time_series(&policy, &mut series, time, &Event::Smb(event), &sender)
                                .await
                        {
                            error_in_ts(&e);
                        }
                    }
                    RequestStreamRecord::Nfs => {
                        let (time, Ok(event)) = (
                            Utc.timestamp_nanos(timestamp),
                            bincode::deserialize::<Nfs>(&raw_event),
                        ) else {
                            continue;
                        };
                        if let Err(e) =
                            time_series(&policy, &mut series, time, &Event::Nfs(event), &sender)
                                .await
                        {
                            error_in_ts(&e);
                        }
                    }
                    // pcap is not used in crusher
                    _ => {}
                }
            } else {
                connection_notify.notify_one();
                break;
            }
        }
    }
    Ok(())
}

async fn send_time_series(
    connection: Arc<Connection>,
    series: TimeSeries,
    time_sender: Sender<(String, i64)>,
    connection_notify: Arc<Notify>,
) -> Result<()> {
    // Store sender channel (Channel for receiving the next time_series after the first transmission)
    let sampling_policy_id = series.sampling_policy_id.clone();
    let (send_channel, recv_channel) =
        async_channel::bounded::<TimeSeries>(TIME_SERIES_CHANNEL_SIZE);
    INGEST_CHANNEL
        .write()
        .await
        .insert(sampling_policy_id.clone(), send_channel);

    let Ok((mut series_sender, series_receiver)) = connection.open_bi().await else {
        bail!("Failed to open bi-direction QUIC channel");
    };

    // First data transmission (record type + series data)
    send_record_header(&mut series_sender, RawEventKind::PeriodicTimeSeries).await?;
    send_event(
        &mut series_sender,
        series.start.timestamp_nanos_opt().unwrap_or(i64::MAX),
        series,
    )
    .await?;

    // Receive start time of giganto last saved time series.
    tokio::spawn(receive_time_series_timestamp(
        series_receiver,
        sampling_policy_id,
        time_sender,
        connection_notify,
    ));

    // Data transmission after the first time (only series data)
    while let Ok(series) = recv_channel.recv().await {
        send_event(
            &mut series_sender,
            series.start.timestamp_nanos_opt().unwrap_or(i64::MAX),
            series,
        )
        .await?;
    }
    Ok(())
}

async fn receive_time_series_timestamp(
    mut receiver: RecvStream,
    sampling_policy_id: String,
    time_sender: Sender<(String, i64)>,
    connection_notify: Arc<Notify>,
) -> Result<()> {
    loop {
        match receive_ack_timestamp(&mut receiver).await {
            Ok(timestamp) => {
                trace!(
                    "The time of the timeseries last sent by {}. : {}",
                    sampling_policy_id,
                    Utc.timestamp_nanos(timestamp)
                );
                time_sender
                    .send((sampling_policy_id.clone(), timestamp))
                    .await?;
            }
            Err(RecvError::ReadError(quinn::ReadExactError::FinishedEarly)) => {
                break;
            }
            Err(e) => {
                connection_notify.notify_one();
                bail!("Last series times error: {}", e);
            }
        }
    }
    Ok(())
}

async fn write_last_timestamp(
    last_series_time_path: PathBuf,
    time_receiver: Receiver<(String, i64)>,
) -> Result<()> {
    while let Ok((id, timestamp)) = time_receiver.recv().await {
        LAST_TRANSFER_TIME.write().await.insert(id, timestamp);
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&last_series_time_path)
            .context("Failed to open last time series timestamp file")?;
        serde_json::to_writer(&file, &(*LAST_TRANSFER_TIME.read().await))
            .context("Failed to write last time series timestamp file")?;
    }
    Ok(())
}

pub async fn read_last_timestamp(last_series_time_path: &Path) -> Result<()> {
    if last_series_time_path.exists() {
        let file = File::open(last_series_time_path)
            .context("Failed to open last time series timestamp file")?;
        let json: serde_json::Value = serde_json::from_reader(BufReader::new(file))?;
        let Value::Object(map_data) = json else {
            bail!("Failed to parse json data, invalid json format");
        };
        for (key, val) in map_data {
            let Value::Number(value) = val else {
                bail!("Failed to parse timestamp data, invalid json format");
            };
            #[rustfmt::skip] // rust-lang/rustfmt#4914
            let Some(timestamp) = value.as_i64() else {
                bail!("Failed to convert timestamp data, invalid time data");
            };
            LAST_TRANSFER_TIME.write().await.insert(key, timestamp);
        }
    }
    Ok(())
}

fn delete_last_timestamp(last_series_time_path: &Path, id: u32) -> Result<()> {
    let file = File::open(last_series_time_path)?;
    let id = format!("{id}");
    let mut json: serde_json::Value = serde_json::from_reader(BufReader::new(file))?;
    if let Value::Object(ref mut map_data) = json {
        map_data.remove(&id);
    }
    let file = File::create(last_series_time_path)?;
    serde_json::to_writer(BufWriter::new(file), &json)?;

    Ok(())
}
