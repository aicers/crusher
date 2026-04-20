#[cfg(test)]
mod tests;
mod time_series;

use std::collections::HashSet;
use std::path::Path;
use std::sync::LazyLock;
use std::{collections::HashMap, net::SocketAddr, path::PathBuf, sync::Arc};

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
use time_series::{SamplingPolicyExt, TimeSeries, TimestampCommand, write_last_timestamp};
use tokio::{
    sync::{Notify, RwLock, oneshot},
    time::{Duration, sleep},
};
use tracing::{info, warn};

use crate::cancellation::CancellationCoordinator;
use crate::client::{self, Certs, SERVER_RETRY_INTERVAL};
use crate::policy::PolicyHandle;

pub(crate) const REQUIRED_GIGANTO_VERSION: &str = "0.26.0";
const TIME_SERIES_CHANNEL_SIZE: usize = 1;
const LAST_TIME_SERIES_TIMESTAMP_CHANNEL_SIZE: usize = 1;

/// A request sent to the `SendStream` actor task. The actor owns the
/// `SendStream` so no lock is needed across an await point.
type StreamSendRequest = (StreamRequestPayload, oneshot::Sender<Result<()>>);

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
        policy_handle: PolicyHandle,
        coordinator: CancellationCoordinator,
    ) -> Result<()> {
        let (sender, receiver) = async_channel::bounded::<TimeSeries>(TIME_SERIES_CHANNEL_SIZE);
        // The timestamp writer actor is the single owner of timestamp
        // file writes and in-memory `LAST_TRANSFER_TIME` mutations. It
        // outlives publish/ingest reconnects so tombstones persist
        // across connection churn, preventing late ACKs for deleted
        // policies from resurrecting timestamps.
        let (time_sender, time_receiver) =
            async_channel::bounded::<TimestampCommand>(LAST_TIME_SERIES_TIMESTAMP_CHANNEL_SIZE);
        coordinator.tracker().spawn(write_last_timestamp(
            self.last_series_time_path.clone(),
            time_receiver,
            coordinator.clone(),
        ));

        let connection_notify = Arc::new(Notify::new());
        tokio::select! {
            Err(e) = async {tokio::try_join!(
                ingest_connection_control(
                    receiver,
                    self.ingest_addr,
                    &self.server_name,
                    &self.endpoint,
                    REQUIRED_GIGANTO_VERSION,
                    time_sender.clone(),
                    connection_notify.clone(),
                    coordinator.clone(),
                ),
                publish_connection_control(
                    sender,
                    self.publish_addr,
                    &self.server_name,
                    &self.endpoint,
                    REQUIRED_GIGANTO_VERSION,
                    &self.request_recv,
                    policy_handle,
                    time_sender.clone(),
                    connection_notify.clone(),
                    coordinator.clone(),
                )
            )} => {
                self.endpoint.close(0u32.into(), &[]);
                bail!("Data store's connection error occurred: {e}");
            }
            () = coordinator.cancelled() => {
                info!("Closing the connection to data store endpoint");
                self.endpoint.close(0u32.into(), &[]);
                Ok(())
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn ingest_connection_control(
    series_recv: Receiver<TimeSeries>,
    server_addr: SocketAddr,
    server_name: &str,
    endpoint: &Endpoint,
    version: &str,
    time_sender: Sender<TimestampCommand>,
    connection_notify: Arc<Notify>,
    coordinator: CancellationCoordinator,
) -> Result<()> {
    'connection: loop {
        let connection_notify = connection_notify.clone();
        match ingest_connect(endpoint, server_addr, server_name, version).await {
            Ok(conn) => {
                let arc_conn = Arc::new(conn);

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
                            coordinator.tracker().spawn(send_time_series(
                                connection,
                                series,
                                time_sender.clone(),
                                connection_notify.clone(),
                                coordinator.clone(),
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
                            bail!("Invalid peer certificate contents");
                        }
                        _ => {}
                    }
                }
                bail!("Fail to connect to {server_addr}: {e:?}");
            }
        }
    }
}

/// Recovery decision for errors returned by [`process_network_stream`].
/// Only connection-level signals map to a variant; everything else is
/// treated as fatal by the caller.
enum StreamRecoveryAction {
    Reconnect,
    Exit,
}

fn classify_stream_error(err: &anyhow::Error) -> Option<StreamRecoveryAction> {
    for cause in err.chain() {
        if let Some(e) = cause.downcast_ref::<WriteError>() {
            match e {
                WriteError::ConnectionLost(_) => return Some(StreamRecoveryAction::Reconnect),
                WriteError::Stopped(_) => return Some(StreamRecoveryAction::Exit),
                _ => {}
            }
        }
        if let Some(ConnectionError::TimedOut | ConnectionError::LocallyClosed) =
            cause.downcast_ref::<ConnectionError>()
        {
            return Some(StreamRecoveryAction::Reconnect);
        }
    }
    None
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
async fn publish_connection_control(
    series_send: Sender<TimeSeries>,
    server_addr: SocketAddr,
    server_name: &str,
    endpoint: &Endpoint,
    version: &str,
    request_recv: &Receiver<SamplingPolicy>,
    policy_handle: PolicyHandle,
    time_sender: Sender<TimestampCommand>,
    connection_notify: Arc<Notify>,
    coordinator: CancellationCoordinator,
) -> Result<()> {
    'connection: loop {
        let connection_notify = connection_notify.clone();
        match publish_connect(endpoint, server_addr, server_name, version).await {
            Ok((conn, mut send)) => {
                // Spawn an actor task that owns the SendStream.
                // Callers send payloads through the channel, avoiding
                // any lock-across-await on the stream.
                let (stream_tx, mut stream_rx) = tokio::sync::mpsc::channel::<StreamSendRequest>(1);
                coordinator.tracker().spawn(async move {
                    while let Some((payload, reply)) = stream_rx.recv().await {
                        let result = send_stream_request(&mut send, payload)
                            .await
                            .map_err(Into::into);
                        let _ = reply.send(result);
                    }
                });

                // One dispatcher task per publish connection owns
                // `accept_uni()`. It reads each incoming stream's id
                // from the wire, looks up the matching policy state,
                // and only then spawns the per-stream worker. This
                // removes the previous race where one of many
                // policy-scoped receivers could be bound to the wrong
                // inbound stream.
                let dispatcher_handle = coordinator.tracker().spawn(run_inbound_dispatcher(
                    conn.clone(),
                    series_send.clone(),
                    connection_notify.clone(),
                    policy_handle.clone(),
                    time_sender.clone(),
                    coordinator.clone(),
                ));

                // Startup-only dedup: on (re)connect we replay the
                // full active-policy snapshot from the policy actor,
                // but the bounded `request_recv` may also hold the
                // same policies queued by recent adds. Without dedup
                // we'd open two streams per such policy. The set is
                // deliberately scoped to this block so it cannot bleed
                // into the steady-state loop below — steady state must
                // treat every `request_recv.recv()` as a fresh open so
                // a delete-then-readd on the same live connection
                // produces a new stream.
                {
                    let mut opened_policy_ids: HashSet<u32> = HashSet::new();
                    let policies = policy_handle.get_all_policies().await;
                    for policy in policies {
                        if !opened_policy_ids.insert(policy.id) {
                            continue;
                        }
                        if let Err(e) = process_network_stream(policy, stream_tx.clone()).await {
                            dispatcher_handle.abort();
                            if let Some(action) = classify_stream_error(&e) {
                                match action {
                                    StreamRecoveryAction::Reconnect => continue 'connection,
                                    StreamRecoveryAction::Exit => return Ok(()),
                                }
                            }
                            bail!("Cannot recover from open stream error: {e}");
                        }
                    }
                    // Drain any `request_recv` items enqueued before or
                    // during startup that duplicate the snapshot. Using
                    // `try_recv` (not `recv`) means we never block on
                    // the bounded channel — this is what prevents the
                    // restore-path deadlock when the sender is waiting
                    // for capacity. Non-duplicate items (policies added
                    // after the snapshot) are opened here so they are
                    // not lost before we reach the steady-state loop.
                    while let Ok(policy) = request_recv.try_recv() {
                        if !opened_policy_ids.insert(policy.id) {
                            continue;
                        }
                        if let Err(e) = process_network_stream(policy, stream_tx.clone()).await {
                            dispatcher_handle.abort();
                            if let Some(action) = classify_stream_error(&e) {
                                match action {
                                    StreamRecoveryAction::Reconnect => continue 'connection,
                                    StreamRecoveryAction::Exit => return Ok(()),
                                }
                            }
                            bail!("Cannot recover from open stream error: {e}");
                        }
                    }
                    // `opened_policy_ids` drops here so no dedup state
                    // survives into the steady-state loop.
                }
                loop {
                    tokio::select! {
                        () = connection_notify.notified() => {
                            drop(connection_notify);
                            dispatcher_handle.abort();
                            warn!(
                                "Stream channel closed. Retry connection to {} after {} seconds.",
                                server_addr, SERVER_RETRY_INTERVAL,
                            );
                            sleep(Duration::from_secs(SERVER_RETRY_INTERVAL)).await;
                            continue 'connection;
                        }
                        err = conn.closed() => {
                            dispatcher_handle.abort();
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
                            if let Err(e) = process_network_stream(policy, stream_tx.clone()).await
                            {
                                dispatcher_handle.abort();
                                if let Some(action) = classify_stream_error(&e) {
                                    match action {
                                        StreamRecoveryAction::Reconnect => continue 'connection,
                                        StreamRecoveryAction::Exit => return Ok(()),
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
                            bail!("Invalid peer certificate contents");
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

/// Sends the stream-open request for a policy. The actual inbound
/// stream is accepted by the per-connection dispatcher (see
/// [`run_inbound_dispatcher`]) and bound to its policy by id read off
/// the wire, so this function does not spawn any per-policy receiver.
async fn process_network_stream(
    policy: SamplingPolicy,
    stream_tx: tokio::sync::mpsc::Sender<StreamSendRequest>,
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
    // Send the payload to the actor task that owns the SendStream.
    // This avoids holding any lock across an await point.
    let (reply_tx, reply_rx) = oneshot::channel();
    stream_tx
        .send((payload, reply_tx))
        .await
        .map_err(|_| anyhow::anyhow!("SendStream actor closed"))?;
    reply_rx
        .await
        .map_err(|_| anyhow::anyhow!("SendStream actor dropped reply"))??;
    Ok(())
}

/// Owns `accept_uni()` for a single publish connection and centralises
/// inbound stream dispatch. For each accepted unidirectional stream
/// it reads the stream-start message to determine the policy id, then
/// looks up the live policy state from the policy actor and spawns a
/// per-stream worker. Streams whose policy was already deleted are
/// silently skipped — they are a normal consequence of a delete that
/// raced with an in-flight stream open.
async fn run_inbound_dispatcher(
    conn: Connection,
    sender: Sender<TimeSeries>,
    connection_notify: Arc<Notify>,
    policy_handle: PolicyHandle,
    time_sender: Sender<TimestampCommand>,
    coordinator: CancellationCoordinator,
) {
    loop {
        let recv_result = tokio::select! {
            biased;
            () = coordinator.cancelled() => return,
            result = conn.accept_uni() => result,
        };
        let mut recv = match recv_result {
            Ok(r) => r,
            Err(e) => {
                info!("Inbound stream dispatcher exiting: {e}");
                return;
            }
        };

        let id = tokio::select! {
            biased;
            () = coordinator.cancelled() => return,
            result = receive_time_series_generator_stream_start_message(&mut recv) => match result {
                Ok(id) => id,
                Err(e) => {
                    warn!("Failed to receive stream id value: {e}");
                    connection_notify.notify_waiters();
                    return;
                }
            }
        };

        let Some((policy, policy_token)) = policy_handle.get_policy_with_token(id).await else {
            info!(
                "Inbound stream for unknown/deleted policy {id}; \
                 dropping stream"
            );
            let _ = recv.stop(VarInt::default());
            continue;
        };

        let sender = sender.clone();
        let time_sender = time_sender.clone();
        let coord = coordinator.clone();
        coordinator.tracker().spawn(async move {
            run_stream_worker(recv, sender, policy, policy_token, time_sender, coord).await
        });
    }
}

/// Per-stream worker, spawned by [`run_inbound_dispatcher`] only after
/// the inbound stream has been bound to its policy by id. The worker
/// owns the recv stream and is responsible for decoding events,
/// reacting to per-policy deletion (`policy_token`), and global
/// cancellation.
///
/// When the inbound stream finishes or errors, the worker exits
/// silently; reconnection is driven by `conn.closed()` in
/// `publish_connection_control` and by `accept_uni()` in the
/// dispatcher, both of which observe genuine connection failures
/// directly. Forcing a reconnect from a single stream's end would
/// race-kill any sibling streams in flight.
async fn run_stream_worker(
    mut recv: RecvStream,
    sender: Sender<TimeSeries>,
    policy: SamplingPolicy,
    policy_token: tokio_util::sync::CancellationToken,
    time_sender: Sender<TimestampCommand>,
    coordinator: CancellationCoordinator,
) -> Result<()> {
    info!("Raw event {:?} has been connected", policy.kind);
    let id = policy.id;

    // A policy may be deleted and then re-added with the same id on
    // the same live publish connection. The writer actor carries a
    // tombstone for deleted ids to reject late ACKs; we clear that
    // tombstone here so fresh Writes on this new stream are accepted.
    let _ = time_sender.send(TimestampCommand::Reset { id }).await;

    let mut series = TimeSeries::try_new(&policy).await?;

    loop {
        tokio::select! {
            biased;
            () = coordinator.cancelled() => {
                info!("Stream worker for policy {id} shutting down");
                break;
            }
            () = policy_token.cancelled() => {
                info!("Policy {id} deleted, stopping stream worker");
                recv.stop(VarInt::default())?;
                // Route the delete through the writer actor so it remains
                // the single owner of timestamp-file writes and can set
                // a tombstone that blocks any late ACKs already in flight.
                let _ = time_sender.send(TimestampCommand::Delete { id }).await;
                break;
            }
            result = receive_time_series_generator_data(&mut recv) => {
                if let Ok((raw_event, timestamp)) = result {
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
                    info!("Stream for policy {id} ended");
                    break;
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn ensure_time_data_exists(path: &Path) -> std::io::Result<()> {
    time_series::ensure_time_data_exists(path)
}

/// Clears all cached senders from the global ingest channel map.
/// Should be called after top-level drain has completed to ensure no
/// stale senders survive into a subsequent run.
pub(crate) async fn clear_ingest_channel() {
    INGEST_CHANNEL.write().await.clear();
}

pub(crate) async fn read_last_timestamp(last_series_time_path: &Path) -> Result<()> {
    time_series::read_last_timestamp(last_series_time_path).await
}

async fn send_time_series(
    connection: Arc<Connection>,
    series: TimeSeries,
    time_sender: Sender<TimestampCommand>,
    connection_notify: Arc<Notify>,
    coordinator: CancellationCoordinator,
) -> Result<()> {
    // Store sender channel (Channel for receiving the next time_series after the first transmission)
    let sampling_policy_id = series.sampling_policy_id.clone();
    let (send_channel, recv_channel) =
        async_channel::bounded::<TimeSeries>(TIME_SERIES_CHANNEL_SIZE);
    // Keep a clone so we can identify our channel instance during cleanup.
    let send_channel_token = send_channel.clone();
    INGEST_CHANNEL
        .write()
        .await
        .insert(sampling_policy_id.clone(), send_channel);

    let result = async {
        let Ok((mut series_sender, series_receiver)) = connection.open_bi().await else {
            bail!("Failed to open bi-direction QUIC channel");
        };

        // First data transmission (record type + series data)
        send_record_header(&mut series_sender, RawEventKind::PeriodicTimeSeries).await?;

        let serde_series = bincode::serialize(&series)?;
        let timesatmp = series.start.timestamp_nanos_opt().unwrap_or(i64::MAX);
        send_event_in_batch(&mut series_sender, &[(timesatmp, serde_series)]).await?;

        // Receive start time of giganto last saved time series.
        coordinator.tracker().spawn(receive_time_series_timestamp(
            series_receiver,
            sampling_policy_id.clone(),
            time_sender,
            connection_notify,
            coordinator.clone(),
        ));

        // Data transmission after the first time (only series data)
        loop {
            tokio::select! {
                biased;
                () = coordinator.cancelled() => {
                    info!("send_time_series shutting down");
                    break;
                }
                result = recv_channel.recv() => {
                    match result {
                        Ok(series) => {
                            let serde_series = bincode::serialize(&series)?;
                            let timesatmp = series.start.timestamp_nanos_opt().unwrap_or(i64::MAX);
                            send_event_in_batch(&mut series_sender, &[(timesatmp, serde_series)]).await?;
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        Ok(())
    }
    .await;

    // Always clean up on both success and error paths.
    // Close our token to mark our channel instance, then only remove
    // the entry if it is still our channel (not a newer sender
    // registered by a reconnect).
    send_channel_token.close();
    let mut map = INGEST_CHANNEL.write().await;
    if let Some(existing) = map.get(&sampling_policy_id)
        && existing.is_closed()
    {
        map.remove(&sampling_policy_id);
    }
    drop(map);

    result
}

async fn send_event_in_batch(send: &mut SendStream, events: &[(i64, Vec<u8>)]) -> Result<()> {
    let buf = bincode::serialize(&events)?;
    send_raw(send, &buf).await?;
    Ok(())
}

/// Short grace period for draining remaining ACK/timestamp messages
/// after cancellation is signalled, so near-shutdown arrivals are not lost.
const ACK_DRAIN_TIMEOUT: Duration = Duration::from_millis(500);

async fn receive_time_series_timestamp(
    mut series_receiver: RecvStream,
    sampling_policy_id: String,
    time_sender: Sender<TimestampCommand>,
    connection_notify: Arc<Notify>,
    coordinator: CancellationCoordinator,
) -> Result<()> {
    loop {
        let result = tokio::select! {
            biased;
            () = coordinator.cancelled() => {
                info!(
                    %sampling_policy_id,
                    "receive_time_series_timestamp draining"
                );
                let drain_deadline =
                    tokio::time::Instant::now() + ACK_DRAIN_TIMEOUT;
                loop {
                    let remaining = drain_deadline
                        .saturating_duration_since(tokio::time::Instant::now());
                    if remaining.is_zero() {
                        break;
                    }
                    match tokio::time::timeout(
                        remaining,
                        receive_ack_timestamp(&mut series_receiver),
                    )
                    .await
                    {
                        Ok(Ok(ts)) => {
                            let _ = time_sender
                                .send(TimestampCommand::Write {
                                    id: sampling_policy_id.clone(),
                                    timestamp: ts,
                                })
                                .await;
                        }
                        _ => break,
                    }
                }
                return Ok(());
            }
            result = receive_ack_timestamp(&mut series_receiver) => result,
        };
        match result {
            Ok(timestamp) => {
                let _ = time_sender
                    .send(TimestampCommand::Write {
                        id: sampling_policy_id.clone(),
                        timestamp,
                    })
                    .await;
            }
            Err(RecvError::ReadError(quinn::ReadExactError::FinishedEarly(_))) => {
                break;
            }
            Err(e) => {
                warn!(
                    %sampling_policy_id,
                    "receive_time_series_timestamp error: {e}"
                );
                connection_notify.notify_waiters();
                break;
            }
        }
    }
    Ok(())
}
