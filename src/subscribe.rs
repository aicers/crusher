#[cfg(test)]
mod tests;
mod time_series;

use std::collections::HashSet;
use std::path::Path;
use std::sync::LazyLock;
use std::{collections::HashMap, net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::{Context, Result, bail};
use async_channel::{Receiver, Sender};
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
use time_series::{
    SECOND_TO_NANO, SamplingPolicyExt, TimeSeries, TimestampCommand, write_last_timestamp,
};
use tokio::{
    sync::{Notify, RwLock, oneshot},
    time::{Duration, sleep, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker as ConnectionTaskTracker;
use tracing::{info, warn};

use crate::cancellation::CancellationCoordinator;
#[cfg(test)]
use crate::cancellation::SHUTDOWN_TIMEOUT as SHUTDOWN_DRAIN_TIMEOUT;
use crate::client::{self, Certs, SERVER_RETRY_INTERVAL};
use crate::policy::PolicyHandle;

pub(crate) const REQUIRED_GIGANTO_VERSION: &str = "0.28.0";
const TIME_SERIES_CHANNEL_SIZE: usize = 1;
const LAST_TIME_SERIES_TIMESTAMP_CHANNEL_SIZE: usize = 1;
const FORCED_DRAIN_GRACE: Duration = Duration::from_secs(1);
const CONNECTION_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// A request sent to the `SendStream` actor task. The actor owns the
/// `SendStream` so no lock is needed across an await point.
type StreamSendRequest = (StreamRequestPayload, oneshot::Sender<Result<()>>);

#[derive(Clone)]
struct ConnectionLifecycle {
    token: CancellationToken,
    tasks: ConnectionTaskTracker,
}

impl ConnectionLifecycle {
    fn new() -> Self {
        Self {
            token: CancellationToken::new(),
            tasks: ConnectionTaskTracker::new(),
        }
    }
}

async fn drain_connection_generation(
    connection: &Connection,
    lifecycle: &ConnectionLifecycle,
    path: &str,
) -> Result<()> {
    lifecycle.token.cancel();
    connection.close(0u32.into(), &[]);
    lifecycle.tasks.close();
    timeout(CONNECTION_DRAIN_TIMEOUT, lifecycle.tasks.wait())
        .await
        .with_context(|| format!("Timed out while draining {path} connection tasks"))?;
    Ok(())
}

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
    ) -> Result<Self> {
        let endpoint = client::config(certs)?;
        Ok(Client {
            ingest_addr,
            publish_addr,
            server_name,
            endpoint,
            request_recv,
            last_series_time_path,
        })
    }

    // Keeps the shutdown stages together so resource ownership and endpoint
    // close ordering remain explicit.
    #[allow(clippy::too_many_lines)]
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
        let mut writer_handle = coordinator.tracker().spawn(write_last_timestamp(
            self.last_series_time_path.clone(),
            time_receiver,
        ));

        let connection_notify = Arc::new(Notify::new());
        let mut connection_controls = Box::pin(async {
            tokio::try_join!(
                ingest_connection_control(
                    receiver,
                    self.ingest_addr,
                    &self.server_name,
                    &self.endpoint,
                    REQUIRED_GIGANTO_VERSION,
                    policy_handle.clone(),
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
            )
        });

        let mut controls_completed = false;
        let mut writer_completed = false;
        let mut result = tokio::select! {
            biased;
            () = coordinator.cancelled() => {
                Ok(())
            }
            controls = &mut connection_controls => {
                controls_completed = true;
                coordinator.request_cancellation("data store connection control exit");
                match controls {
                    Ok(_) => Err(anyhow::anyhow!(
                        "Data store connection controls ended unexpectedly"
                    )),
                    Err(e) => Err(e).context("Data store's connection error occurred"),
                }
            }
            writer = &mut writer_handle => {
                writer_completed = true;
                coordinator.request_cancellation("timestamp writer exit");
                match writer {
                    Ok(Ok(())) => Err(anyhow::anyhow!(
                        "timestamp writer ended unexpectedly"
                    )),
                    Ok(Err(e)) => Err(e).context("timestamp writer failed"),
                    Err(e) => Err(anyhow::anyhow!("timestamp writer task panicked: {e}")),
                }
            }
        };

        let shutdown_deadline = coordinator
            .shutdown_deadline()
            .context("shutdown deadline was not initialized")?;
        let graceful_deadline = shutdown_deadline
            .checked_sub(FORCED_DRAIN_GRACE)
            .expect("forced drain grace is shorter than the shutdown timeout");

        if !controls_completed {
            let controls_result = timeout_at(graceful_deadline, connection_controls.as_mut()).await;
            match controls_result {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    if result.is_ok() {
                        result =
                            Err(e).context("Data store connection control failed during shutdown");
                    } else {
                        warn!("Data store connection control also failed during shutdown: {e:#}");
                    }
                }
                Err(_) => {
                    warn!("Timed out while stopping data store connection controls");
                }
            }
        }
        // Dropping a timed-out control future cancels both control loops
        // and releases their remaining channel endpoints.
        drop(connection_controls);

        // Drop the final producer owned by this supervisor. The writer
        // exits only after ACK receivers have dropped their clones and
        // all queued timestamp commands have been persisted.
        drop(time_sender);

        let mut drained = coordinator.wait_for_drain_until(graceful_deadline).await;

        let mut endpoint_closed = false;
        if !drained {
            warn!(
                "Graceful data store drain timed out; closing the endpoint to release ACK receivers"
            );
            self.endpoint.close(0u32.into(), &[]);
            endpoint_closed = true;

            drained = coordinator.wait_for_drain_until(shutdown_deadline).await;
            if !drained {
                warn!("Forced data store and timestamp drain timed out");
                if result.is_ok() {
                    result = Err(anyhow::anyhow!(
                        "Timed out while draining data store and timestamp tasks"
                    ));
                }
            }
        }

        if drained && endpoint_closed {
            info!("Forced data store drain completed within the shutdown deadline");
        }

        // A successful graceful or forced drain proves that the tracked
        // writer has completed, so collecting its JoinHandle result cannot
        // block.
        if drained && !writer_completed {
            let writer_result = match writer_handle.await {
                Ok(result) => result.context("timestamp writer failed"),
                Err(e) => Err(anyhow::anyhow!("timestamp writer task panicked: {e}")),
            };
            if let Err(e) = writer_result
                && result.is_ok()
            {
                result = Err(e);
            }
        }

        if !endpoint_closed {
            info!("Closing the connection to data store endpoint");
            self.endpoint.close(0u32.into(), &[]);
        }
        result
    }
}

#[allow(clippy::too_many_arguments)]
async fn ingest_connection_control(
    series_recv: Receiver<TimeSeries>,
    server_addr: SocketAddr,
    server_name: &str,
    endpoint: &Endpoint,
    version: &str,
    policy_handle: PolicyHandle,
    time_sender: Sender<TimestampCommand>,
    connection_notify: Arc<Notify>,
    coordinator: CancellationCoordinator,
) -> Result<()> {
    'connection: loop {
        let connection_notify = connection_notify.clone();
        let connect_result = tokio::select! {
            biased;
            () = coordinator.cancelled() => return Ok(()),
            result = ingest_connect(endpoint, server_addr, server_name, version) => result,
        };
        match connect_result {
            Ok(conn) => {
                let arc_conn = Arc::new(conn);
                let connection_lifecycle = ConnectionLifecycle::new();

                loop {
                    tokio::select! {
                        biased;
                        () = coordinator.cancelled() => {
                            // Producers observe the same cancellation and
                            // drop their senders. Keep receiving until the
                            // outer queue closes so a series already queued
                            // at the shutdown boundary is still handed to an
                            // ingest worker.
                            while let Ok(series) = series_recv.recv().await {
                                spawn_time_series_sender(
                                    &coordinator,
                                    arc_conn.clone(),
                                    series,
                                    CancellationToken::new(),
                                    connection_lifecycle.clone(),
                                    time_sender.clone(),
                                    connection_notify.clone(),
                                );
                            }
                            return Ok(());
                        }
                        () = connection_notify.notified() => {
                            drop(connection_notify);
                            INGEST_CHANNEL.write().await.clear();
                            drain_connection_generation(
                                arc_conn.as_ref(),
                                &connection_lifecycle,
                                "ingest",
                            )
                            .await?;
                            warn!(
                                "Stream channel closed. Retry connection to {}",
                                server_addr,
                            );
                            continue 'connection;
                        }
                        Ok(series) = series_recv.recv() => {
                            // Bind the freshly received series to the currently active policy id by
                            // looking up its `CancellationToken` in a single actor call. If the
                            // policy is no longer active by the time we dequeue the series, drop it
                            // instead of spawning another sender task.
                            let Some(policy_token) = policy_token_for_series(
                                &policy_handle,
                                &series.sampling_policy_id,
                            )
                            .await else {
                                continue;
                            };
                            let connection = arc_conn.clone();
                            spawn_time_series_sender(
                                &coordinator,
                                connection,
                                series,
                                policy_token,
                                connection_lifecycle.clone(),
                                time_sender.clone(),
                                connection_notify.clone(),
                            );
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
                            tokio::select! {
                                biased;
                                () = coordinator.cancelled() => return Ok(()),
                                () = sleep(Duration::from_secs(SERVER_RETRY_INTERVAL)) => {}
                            }
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
        let connect_result = tokio::select! {
            biased;
            () = coordinator.cancelled() => return Ok(()),
            result = publish_connect(endpoint, server_addr, server_name, version) => result,
        };
        match connect_result {
            Ok((conn, mut send)) => {
                let connection_lifecycle = ConnectionLifecycle::new();
                // Spawn an actor task that owns the SendStream.
                // Callers send payloads through the channel, avoiding
                // any lock-across-await on the stream.
                let (stream_tx, mut stream_rx) = tokio::sync::mpsc::channel::<StreamSendRequest>(1);
                let stream_token = connection_lifecycle.token.clone();
                let stream_actor = connection_lifecycle.tasks.track_future(async move {
                    loop {
                        let request = tokio::select! {
                            biased;
                            () = stream_token.cancelled() => break,
                            request = stream_rx.recv() => request,
                        };
                        let Some((payload, reply)) = request else {
                            break;
                        };
                        let result = send_stream_request(&mut send, payload)
                            .await
                            .map_err(Into::into);
                        let _ = reply.send(result);
                    }
                });
                coordinator.tracker().spawn(stream_actor);

                // One dispatcher task per publish connection owns
                // `accept_uni()`. It reads each incoming stream's id
                // from the wire, looks up the matching policy state,
                // and only then spawns the per-stream worker. This
                // removes the previous race where one of many
                // policy-scoped receivers could be bound to the wrong
                // inbound stream.
                let dispatcher = connection_lifecycle
                    .tasks
                    .track_future(run_inbound_dispatcher(
                        conn.clone(),
                        series_send.clone(),
                        connection_notify.clone(),
                        policy_handle.clone(),
                        time_sender.clone(),
                        connection_lifecycle.clone(),
                        coordinator.clone(),
                    ));
                let mut dispatcher_handle = coordinator.tracker().spawn(dispatcher);

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
                        if let Err(e) =
                            process_network_stream(policy, stream_tx.clone(), &coordinator).await
                        {
                            if let Some(action) = classify_stream_error(&e) {
                                match action {
                                    StreamRecoveryAction::Reconnect => {
                                        drain_connection_generation(
                                            &conn,
                                            &connection_lifecycle,
                                            "publish",
                                        )
                                        .await?;
                                        continue 'connection;
                                    }
                                    StreamRecoveryAction::Exit => {
                                        drain_connection_generation(
                                            &conn,
                                            &connection_lifecycle,
                                            "publish",
                                        )
                                        .await?;
                                        return Ok(());
                                    }
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
                        if let Err(e) =
                            process_network_stream(policy, stream_tx.clone(), &coordinator).await
                        {
                            if let Some(action) = classify_stream_error(&e) {
                                match action {
                                    StreamRecoveryAction::Reconnect => {
                                        drain_connection_generation(
                                            &conn,
                                            &connection_lifecycle,
                                            "publish",
                                        )
                                        .await?;
                                        continue 'connection;
                                    }
                                    StreamRecoveryAction::Exit => {
                                        drain_connection_generation(
                                            &conn,
                                            &connection_lifecycle,
                                            "publish",
                                        )
                                        .await?;
                                        return Ok(());
                                    }
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
                        biased;
                        () = coordinator.cancelled() => {
                            drain_connection_generation(
                                &conn,
                                &connection_lifecycle,
                                "publish",
                            )
                            .await?;
                            return Ok(());
                        }
                        dispatcher_result = &mut dispatcher_handle => {
                            warn!(
                                "Inbound dispatcher exited ({:?}). Retry connection to {} after {} seconds.",
                                dispatcher_result.err(), server_addr, SERVER_RETRY_INTERVAL,
                            );
                            drain_connection_generation(
                                &conn,
                                &connection_lifecycle,
                                "publish",
                            )
                            .await?;
                            tokio::select! {
                                biased;
                                () = coordinator.cancelled() => return Ok(()),
                                () = sleep(Duration::from_secs(SERVER_RETRY_INTERVAL)) => {}
                            }
                            continue 'connection;
                        }
                        () = connection_notify.notified() => {
                            drop(connection_notify);
                            drain_connection_generation(
                                &conn,
                                &connection_lifecycle,
                                "publish",
                            )
                            .await?;
                            warn!(
                                "Stream channel closed. Retry connection to {} after {} seconds.",
                                server_addr, SERVER_RETRY_INTERVAL,
                            );
                            tokio::select! {
                                biased;
                                () = coordinator.cancelled() => return Ok(()),
                                () = sleep(Duration::from_secs(SERVER_RETRY_INTERVAL)) => {}
                            }
                            continue 'connection;
                        }
                        err = conn.closed() => {
                            drain_connection_generation(
                                &conn,
                                &connection_lifecycle,
                                "publish",
                            )
                            .await?;
                            warn!(
                                "Stream channel closed: {:?}. Retry connection to {} after {} seconds.",
                                err, server_addr, SERVER_RETRY_INTERVAL,
                            );
                            connection_notify.notify_waiters();
                            tokio::select! {
                                biased;
                                () = coordinator.cancelled() => return Ok(()),
                                () = sleep(Duration::from_secs(SERVER_RETRY_INTERVAL)) => {}
                            }
                            continue 'connection;
                        }
                        Ok(policy) = request_recv.recv() => {
                            info!("Stream's policy : {:?}", policy);
                            if let Err(e) = process_network_stream(
                                policy,
                                stream_tx.clone(),
                                &coordinator,
                            )
                            .await
                            {
                                if let Some(action) = classify_stream_error(&e) {
                                    match action {
                                        StreamRecoveryAction::Reconnect => {
                                            drain_connection_generation(
                                                &conn,
                                                &connection_lifecycle,
                                                "publish",
                                            )
                                            .await?;
                                            continue 'connection;
                                        }
                                        StreamRecoveryAction::Exit => {
                                            drain_connection_generation(
                                                &conn,
                                                &connection_lifecycle,
                                                "publish",
                                            )
                                            .await?;
                                            return Ok(());
                                        }
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
                            tokio::select! {
                                biased;
                                () = coordinator.cancelled() => return Ok(()),
                                () = sleep(Duration::from_secs(SERVER_RETRY_INTERVAL)) => {}
                            }
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
    coordinator: &CancellationCoordinator,
) -> Result<()> {
    let start_timestamp_nanos = policy.start_timestamp_nanos().await?;
    let req_msg = RequestTimeSeriesGeneratorStream {
        start: start_timestamp_nanos,
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
    tokio::select! {
        biased;
        () = coordinator.cancelled() => return Ok(()),
        result = stream_tx.send((payload, reply_tx)) => {
            result.map_err(|_| anyhow::anyhow!("SendStream actor closed"))?;
        }
    }
    tokio::select! {
        biased;
        () = coordinator.cancelled() => return Ok(()),
        result = reply_rx => {
            result.map_err(|_| anyhow::anyhow!("SendStream actor dropped reply"))??;
        }
    }
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
    connection_lifecycle: ConnectionLifecycle,
    coordinator: CancellationCoordinator,
) {
    loop {
        let recv_result = tokio::select! {
            biased;
            () = coordinator.cancelled() => return,
            () = connection_lifecycle.token.cancelled() => return,
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
            () = connection_lifecycle.token.cancelled() => return,
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
        let worker_lifecycle = connection_lifecycle.clone();
        let policy_id = policy.id;
        let worker = connection_lifecycle.tasks.track_future(async move {
            if let Err(e) = run_stream_worker(
                recv,
                sender,
                policy,
                policy_token,
                worker_lifecycle.token,
                time_sender,
                coord,
            )
            .await
            {
                warn!(policy_id, "Stream worker failed: {e:#}");
            }
        });
        coordinator.tracker().spawn(worker);
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
    connection_token: tokio_util::sync::CancellationToken,
    time_sender: Sender<TimestampCommand>,
    coordinator: CancellationCoordinator,
) -> Result<()> {
    info!("Raw event {:?} has been connected", policy.kind);
    let id = policy.id;

    // A policy may be deleted and then re-added with the same id on
    // the same live publish connection. The writer actor carries a
    // tombstone for deleted ids to reject late ACKs; we clear that
    // tombstone here so fresh Writes on this new stream are accepted.
    time_sender
        .send(TimestampCommand::Reset { id })
        .await
        .context("timestamp writer closed while resetting a policy")?;

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
                time_sender
                    .send(TimestampCommand::Delete { id })
                    .await
                    .context("timestamp writer closed while deleting a policy")?;
                break;
            }
            () = connection_token.cancelled() => {
                info!("Stream worker for policy {id} stopping; publish connection replaced");
                break;
            }
            result = receive_time_series_generator_data(&mut recv) => {
                if let Ok((raw_event, timestamp_nanos)) = result {
                    let time_secs = timestamp_nanos.div_euclid(SECOND_TO_NANO);
                    let Ok(event) = Event::try_new(policy.kind, &raw_event) else {
                        warn!(
                            "Failed to deserialize raw_event for sampling kind: {:?}",
                            policy.kind
                        );
                        continue;
                    };
                    if let Err(e) = series.fill(&policy, time_secs, &event, &sender).await {
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

/// Resolves the current `CancellationToken` for a dequeued series by its
/// policy id. Returns `None` when the id is malformed or when the policy
/// is no longer active, signalling the caller to drop the series instead
/// of spawning a sender task for an inactive policy.
async fn policy_token_for_series(
    policy_handle: &PolicyHandle,
    sampling_policy_id: &str,
) -> Option<CancellationToken> {
    let id = sampling_policy_id.parse::<u32>().ok()?;
    policy_handle
        .get_policy_with_token(id)
        .await
        .map(|(_, token)| token)
}

#[allow(clippy::too_many_arguments)]
fn spawn_time_series_sender(
    coordinator: &CancellationCoordinator,
    connection: Arc<Connection>,
    series: TimeSeries,
    policy_token: CancellationToken,
    connection_lifecycle: ConnectionLifecycle,
    time_sender: Sender<TimestampCommand>,
    connection_notify: Arc<Notify>,
) {
    let sampling_policy_id = series.sampling_policy_id.clone();
    let error_notify = connection_notify.clone();
    let task_coordinator = coordinator.clone();
    let connection_tasks = connection_lifecycle.tasks.clone();
    let tracked = connection_tasks.track_future(async move {
        if let Err(e) = send_time_series(
            connection,
            series,
            policy_token,
            connection_lifecycle,
            time_sender,
            connection_notify,
            task_coordinator,
        )
        .await
        {
            warn!(%sampling_policy_id, "Time-series sender failed: {e:#}");
            error_notify.notify_waiters();
        }
    });
    coordinator.tracker().spawn(tracked);
}

async fn send_time_series(
    connection: Arc<Connection>,
    series: TimeSeries,
    policy_token: CancellationToken,
    connection_lifecycle: ConnectionLifecycle,
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

        send_time_series_record(&mut series_sender, &series).await?;

        // Receive start time of giganto last saved time series.
        let receiver = connection_lifecycle
            .tasks
            .track_future(receive_time_series_timestamp(
                series_receiver,
                sampling_policy_id.clone(),
                policy_token.clone(),
                connection_lifecycle.token.clone(),
                time_sender,
                connection_notify,
            ));
        coordinator.tracker().spawn(receiver);

        // Data transmission after the first time (only series data).
        // `policy_token` fires on delete so this old-generation sender
        // exits promptly instead of surviving into the next add of the
        // same id; the cleanup block below then removes our
        // `INGEST_CHANNEL` entry before the new generation re-registers.
        loop {
            tokio::select! {
                biased;
                () = coordinator.cancelled() => {
                    // Stop accepting new work, then transmit everything
                    // that was already accepted into this policy's queue.
                    send_channel_token.close();
                    while let Ok(series) = recv_channel.recv().await {
                        send_time_series_record(&mut series_sender, &series).await?;
                    }
                    info!("send_time_series drained and shutting down");
                    break;
                }
                () = policy_token.cancelled() => {
                    info!(
                        %sampling_policy_id,
                        "send_time_series stopping; policy deleted"
                    );
                    break;
                }
                () = connection_lifecycle.token.cancelled() => {
                    info!(
                        %sampling_policy_id,
                        "send_time_series stopping; ingest connection replaced"
                    );
                    break;
                }
                result = recv_channel.recv() => {
                    match result {
                        Ok(series) => {
                            send_time_series_record(&mut series_sender, &series).await?;
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        series_sender
            .finish()
            .context("Failed to finish the time series send stream")?;
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

async fn send_time_series_record(
    series_sender: &mut SendStream,
    series: &TimeSeries,
) -> Result<()> {
    let serde_series = bincode::serialize(series)?;
    let timestamp_nanos = series
        .start_secs
        .checked_mul(SECOND_TO_NANO)
        .unwrap_or(i64::MAX);
    send_event_in_batch(series_sender, &[(timestamp_nanos, serde_series)]).await
}

async fn send_event_in_batch(send: &mut SendStream, events: &[(i64, Vec<u8>)]) -> Result<()> {
    let buf = bincode::serialize(&events)?;
    send_raw(send, &buf).await?;
    Ok(())
}

async fn receive_time_series_timestamp(
    mut series_receiver: RecvStream,
    sampling_policy_id: String,
    policy_token: CancellationToken,
    connection_token: CancellationToken,
    time_sender: Sender<TimestampCommand>,
    connection_notify: Arc<Notify>,
) {
    loop {
        let result = tokio::select! {
            biased;
            () = policy_token.cancelled() => {
                // Policy deletion: exit immediately without draining.
                // The writer actor has (or will have) tombstoned this
                // id, so any ACK already in the kernel buffer would be
                // rejected anyway. Skipping the drain also frees this
                // task before the next add of the same id would try to
                // open a fresh bi-di stream.
                info!(
                    %sampling_policy_id,
                    "receive_time_series_timestamp stopping; policy deleted"
                );
                return;
            }
            () = connection_token.cancelled() => {
                info!(
                    %sampling_policy_id,
                    "receive_time_series_timestamp stopping; ingest connection replaced"
                );
                return;
            }
            result = receive_ack_timestamp(&mut series_receiver) => result,
        };
        match result {
            Ok(timestamp) => {
                if time_sender
                    .send(TimestampCommand::Write {
                        id: sampling_policy_id.clone(),
                        timestamp,
                    })
                    .await
                    .is_err()
                {
                    warn!(
                        %sampling_policy_id,
                        "Timestamp writer closed while recording an ACK"
                    );
                    return;
                }
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
}
