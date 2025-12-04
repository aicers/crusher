#[cfg(test)]
mod tests;
mod time_series;

use std::path::Path;
use std::sync::LazyLock;
use std::{collections::HashMap, net::SocketAddr, path::PathBuf, process::exit, sync::Arc};

use anyhow::{Result, bail};
use async_channel::{Receiver, Sender};
use chrono::{TimeZone, Utc};
use giganto_client::{
    RawEventKind,
    connection::client_handshake,
    frame::{RecvError, send_raw},
    ingest::{
        network::{Conn, Dns, Http, Rdp},
        receive_ack_timestamp, send_record_header,
    },
    publish::{
        receive_time_series_generator_data, receive_time_series_generator_stream_start_message,
        send_stream_request,
        stream::{RequestStreamRecord, RequestTimeSeriesGeneratorStream, StreamRequestPayload},
    },
};
use num_traits::ToPrimitive;
use quinn::{Connection, ConnectionError, Endpoint, RecvStream, SendStream, VarInt, WriteError};
use review_protocol::types::{SamplingKind, SamplingPolicy};
use time_series::{SamplingPolicyExt, TimeSeries, delete_last_timestamp, write_last_timestamp};
use tokio::{
    sync::{Mutex, Notify, RwLock},
    task,
    time::{Duration, sleep},
};
use tracing::{debug, error, info, warn};

use crate::client::{self, Certs, SERVER_RETRY_INTERVAL};

const REQUIRED_GIGANTO_VERSION: &str = "0.26.0";
const TIME_SERIES_CHANNEL_SIZE: usize = 1;
const LAST_TIME_SERIES_TIMESTAMP_CHANNEL_SIZE: usize = 1;

// A hashmap for data transfer to an already created asynchronous task
static INGEST_CHANNEL: LazyLock<RwLock<HashMap<String, Sender<TimeSeries>>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

trait FromExt<T> {
    fn from_ext(t: T) -> Self;
}

impl FromExt<SamplingKind> for RequestStreamRecord {
    fn from_ext(k: SamplingKind) -> Self {
        match k {
            SamplingKind::Conn => Self::Conn,
            SamplingKind::Dns => Self::Dns,
            SamplingKind::Http => Self::Http,
            SamplingKind::Rdp => Self::Rdp,
        }
    }
}

#[allow(clippy::large_enum_variant)]
enum Event {
    Conn(Conn),
    Dns(Dns),
    Http(Http),
    Rdp(Rdp),
}

impl Event {
    fn column_value(&self, column: u32) -> f64 {
        match self {
            Self::Conn(evt) => evt.column_value(column),
            Self::Dns(evt) => evt.column_value(column),
            Self::Http(evt) => evt.column_value(column),
            Self::Rdp(evt) => evt.column_value(column),
        }
    }

    fn try_new(k: SamplingKind, raw_event: &[u8]) -> Result<Self> {
        Ok(match k {
            SamplingKind::Conn => Self::Conn(bincode::deserialize::<Conn>(raw_event)?),
            SamplingKind::Dns => Self::Dns(bincode::deserialize::<Dns>(raw_event)?),
            SamplingKind::Http => Self::Http(bincode::deserialize::<Http>(raw_event)?),
            SamplingKind::Rdp => Self::Rdp(bincode::deserialize::<Rdp>(raw_event)?),
        })
    }
}

trait ColumnValue {
    fn column_value(&self, _: u32) -> f64 {
        1_f64
    }
}

impl ColumnValue for Conn {
    fn column_value(&self, column: u32) -> f64 {
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

pub(crate) struct Client {
    ingest_addr: SocketAddr,
    publish_addr: SocketAddr,
    server_name: String,
    endpoint: Endpoint,
    request_recv: Receiver<SamplingPolicy>,
    last_series_time_path: PathBuf,
}

#[allow(clippy::too_many_arguments)]
impl Client {
    pub(crate) fn new(
        ingest_addr: SocketAddr,
        publish_addr: SocketAddr,
        server_name: String,
        last_series_time_path: PathBuf,
        certs: &Certs,
        request_recv: Receiver<SamplingPolicy>,
    ) -> Self {
        let endpoint =
            client::config(certs).expect("Server configuration error with cert, key or ca_certs");
        Client {
            ingest_addr,
            publish_addr,
            server_name,
            endpoint,
            request_recv,
            last_series_time_path,
        }
    }

    pub(crate) async fn run(
        self,
        active_policy_list: Arc<RwLock<HashMap<u32, SamplingPolicy>>>,
        delete_policy_ids: Arc<RwLock<Vec<u32>>>,
        shutdown: Arc<Notify>,
    ) -> Result<()> {
        let (sender, receiver) = async_channel::bounded::<TimeSeries>(TIME_SERIES_CHANNEL_SIZE);
        let connection_notify = Arc::new(Notify::new());
        tokio::select! {
            Err(e) = async {tokio::try_join!(
                ingest_connection_control(
                    receiver,
                    self.ingest_addr,
                    &self.server_name,
                    &self.endpoint,
                    &self.last_series_time_path,
                    REQUIRED_GIGANTO_VERSION,
                    connection_notify.clone(),
                ),
                publish_connection_control(
                    sender,
                    self.publish_addr,
                    &self.server_name,
                    &self.endpoint,
                    REQUIRED_GIGANTO_VERSION,
                    &self.request_recv,
                    active_policy_list,
                    delete_policy_ids,
                    &self.last_series_time_path,
                    connection_notify.clone(),
                )
            )} => {
                self.endpoint.close(0u32.into(), &[]);
                bail!("Data store's connection error occurred: {e}");
            }
            () = shutdown.notified() => {
                info!("Closing the connection to data store endpoint");
                self.endpoint.close(0u32.into(), &[]);
                shutdown.notify_one();
                Ok(())
            }
        }
    }
}

async fn ingest_connection_control(
    series_recv: Receiver<TimeSeries>,
    server_addr: SocketAddr,
    server_name: &str,
    endpoint: &Endpoint,
    last_series_time_path: &Path,
    version: &str,
    connection_notify: Arc<Notify>,
) -> Result<()> {
    'connection: loop {
        let connection_notify = connection_notify.clone();
        match ingest_connect(endpoint, server_addr, server_name, version).await {
            Ok(conn) => {
                let arc_conn = Arc::new(conn);

                // Write last time_series timestamp
                let (time_sender, time_receiver) = async_channel::bounded::<(String, i64)>(
                    LAST_TIME_SERIES_TIMESTAMP_CHANNEL_SIZE,
                );
                tokio::spawn(write_last_timestamp(
                    last_series_time_path.to_path_buf(),
                    time_receiver,
                ));

                loop {
                    tokio::select! {
                        () = connection_notify.notified() => {
                            drop(connection_notify);
                            INGEST_CHANNEL.write().await.clear();
                            warn!(
                                "Stream channel closed. Retry connection to {}",
                                server_addr,
                            );
                            continue 'connection;
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
                            warn!(
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
                bail!("Fail to connect to {server_addr}: {e:?}");
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
    version: &str,
    request_recv: &Receiver<SamplingPolicy>,
    active_policy_list: Arc<RwLock<HashMap<u32, SamplingPolicy>>>,
    delete_policy_ids: Arc<RwLock<Vec<u32>>>,
    last_series_time_path: &Path,
    connection_notify: Arc<Notify>,
) -> Result<()> {
    'connection: loop {
        let connection_notify = connection_notify.clone();
        match publish_connect(endpoint, server_addr, server_name, version).await {
            Ok((conn, send)) => {
                let req_send = Arc::new(Mutex::new(send));
                for policy in active_policy_list.read().await.values() {
                    if let Err(e) = process_network_stream(
                        conn.clone(),
                        series_send.clone(),
                        policy.clone(),
                        req_send.clone(),
                        connection_notify.clone(),
                        active_policy_list.clone(),
                        delete_policy_ids.clone(),
                        last_series_time_path.to_path_buf(),
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
                            if let Some(
                                ConnectionError::TimedOut | ConnectionError::LocallyClosed,
                            ) = cause.downcast_ref::<ConnectionError>()
                            {
                                continue 'connection;
                            }
                        }
                        bail!("Cannot recover from open stream error: {e}");
                    }
                }
                loop {
                    tokio::select! {
                        () = connection_notify.notified() => {
                            drop(connection_notify);
                            warn!(
                                "Stream channel closed. Retry connection to {} after {} seconds.",
                                server_addr, SERVER_RETRY_INTERVAL,
                            );
                            sleep(Duration::from_secs(SERVER_RETRY_INTERVAL)).await;
                            continue 'connection;
                        }
                        err = conn.closed() => {
                            warn!(
                                "Stream channel closed: {:?}. Retry connection to {} after {} seconds.",
                                err, server_addr, SERVER_RETRY_INTERVAL,
                            );
                            connection_notify.notify_waiters();
                            sleep(Duration::from_secs(SERVER_RETRY_INTERVAL)).await;
                            continue 'connection;
                        }
                        Ok(policy) = request_recv.recv() => {
                            info!("Stream's policy : {:?}", policy);
                            if let Err(e) = process_network_stream(
                                conn.clone(),
                                series_send.clone(),
                                policy,
                                req_send.clone(),
                                connection_notify.clone(),
                                active_policy_list.clone(),
                                delete_policy_ids.clone(),
                                last_series_time_path.to_path_buf(),
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
                                    if let Some(ConnectionError::TimedOut | ConnectionError::LocallyClosed) = cause.downcast_ref::<ConnectionError>() {
                                        continue 'connection;
                                    }
                                }
                                bail!("Cannot recover from open stream error: {e}");
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
                            warn!(
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
                bail!("Fail to connect to {server_addr}: {e:?}");
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
    info!(
        "Connection established to data store ingest server {}",
        server_address
    );
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
    info!(
        "Connection established to data store publish server {}",
        server_address
    );
    Ok((conn, send))
}

#[allow(clippy::too_many_arguments)]
async fn process_network_stream(
    conn: Connection,
    sender: Sender<TimeSeries>,
    policy: SamplingPolicy,
    send: Arc<Mutex<SendStream>>,
    connection_notify: Arc<Notify>,
    active_policy_list: Arc<RwLock<HashMap<u32, SamplingPolicy>>>,
    delete_policy_ids: Arc<RwLock<Vec<u32>>>,
    last_series_time_path: PathBuf,
) -> Result<()> {
    let start = policy.start_timestamp().await?;
    let req_msg = RequestTimeSeriesGeneratorStream {
        start,
        id: policy.id.to_string(),
        src_ip: policy.src_ip,
        dst_ip: policy.dst_ip,
        sensor: policy.node.clone(),
    };
    let payload = StreamRequestPayload::TimeSeriesGenerator {
        record_type: RequestStreamRecord::from_ext(policy.kind),
        request: req_msg,
    };
    send_stream_request(&mut (*send.lock().await), payload).await?;
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

#[allow(clippy::too_many_lines)]
async fn receiver(
    conn: Connection,
    sender: Sender<TimeSeries>,
    connection_notify: Arc<Notify>,
    active_policy_list: Arc<RwLock<HashMap<u32, SamplingPolicy>>>,
    delete_policy_ids: Arc<RwLock<Vec<u32>>>,
    last_series_time_path: PathBuf,
) -> Result<()> {
    if let Ok(mut recv) = conn.accept_uni().await {
        let Ok(id) = receive_time_series_generator_stream_start_message(&mut recv).await else {
            connection_notify.notify_waiters();
            warn!("Failed to receive stream id value");
            bail!("Failed to receive stream id value");
        };

        let policy = if let Some(policy) = active_policy_list.read().await.get(&id) {
            policy.clone()
        } else {
            bail!("Failed to get runtime policy data");
        };
        info!("Raw event {:?} has been connected", policy.kind);

        let mut series = TimeSeries::try_new(&policy).await?;

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
            if let Ok((raw_event, timestamp)) = receive_time_series_generator_data(&mut recv).await
            {
                let time = Utc.timestamp_nanos(timestamp);
                let Ok(event) = Event::try_new(policy.kind, &raw_event) else {
                    warn!(
                        "Failed to deserialize raw_event for sampling kind: {:?}",
                        policy.kind
                    );
                    continue;
                };
                if let Err(e) = series.fill(&policy, time, &event, &sender).await {
                    warn!("Failed to generate time series: {}", e);
                }
            } else {
                connection_notify.notify_waiters();
                break;
            }
        }
    }
    Ok(())
}

pub(crate) async fn read_last_timestamp(last_series_time_path: &Path) -> Result<()> {
    time_series::read_last_timestamp(last_series_time_path).await
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

    let serde_series = bincode::serialize(&series)?;
    let timesatmp = series.start.timestamp_nanos_opt().unwrap_or(i64::MAX);
    send_event_in_batch(&mut series_sender, &[(timesatmp, serde_series)]).await?;

    // Receive start time of giganto last saved time series.
    tokio::spawn(receive_time_series_timestamp(
        series_receiver,
        sampling_policy_id,
        time_sender,
        connection_notify,
    ));

    // Data transmission after the first time (only series data)
    while let Ok(series) = recv_channel.recv().await {
        let serde_series = bincode::serialize(&series)?;
        let timesatmp = series.start.timestamp_nanos_opt().unwrap_or(i64::MAX);
        send_event_in_batch(&mut series_sender, &[(timesatmp, serde_series)]).await?;
    }
    Ok(())
}

async fn send_event_in_batch(send: &mut SendStream, events: &[(i64, Vec<u8>)]) -> Result<()> {
    let buf = bincode::serialize(&events)?;
    send_raw(send, &buf).await?;
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
                debug!(
                    "The time of the timeseries last sent by {}. : {}",
                    sampling_policy_id,
                    Utc.timestamp_nanos(timestamp)
                );
                time_sender
                    .send((sampling_policy_id.clone(), timestamp))
                    .await?;
            }
            Err(RecvError::ReadError(quinn::ReadExactError::FinishedEarly(_))) => {
                break;
            }
            Err(e) => {
                connection_notify.notify_waiters();
                bail!("Last series times error: {e}");
            }
        }
    }
    Ok(())
}
