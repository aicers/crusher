#[cfg(test)]
mod tests;
mod time_series;

use std::sync::{LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

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
use review_protocol::types::SamplingKind;
use time_series::{TimeSeries, WindowBuilder};
use tokio::{
    sync::{Notify, RwLock, mpsc},
    time::{Duration, Instant, MissedTickBehavior, interval, sleep, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker as ConnectionTaskTracker;
use tracing::{info, warn};

use crate::cancellation::CancellationCoordinator;
#[cfg(test)]
use crate::cancellation::SHUTDOWN_TIMEOUT as SHUTDOWN_DRAIN_TIMEOUT;
use crate::client::{self, Certs, SERVER_RETRY_INTERVAL};
use crate::policy::{PolicyHandle, StreamPolicy};

pub(crate) const REQUIRED_GIGANTO_VERSION: &str = "0.28.0";
const TIME_SERIES_CHANNEL_SIZE: usize = 1;
const FORCED_DRAIN_GRACE: Duration = Duration::from_secs(1);
const CONNECTION_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a stream must have received no event before the timer closes its
/// open window. The idle gate keeps the timer from cutting a window that a
/// replay of stored events is still filling.
const CLOSE_IDLE_SECS: u64 = 30;

/// How often a stream worker checks whether its open window is due to close.
const CLOSE_CHECK_SECS: u64 = 10;

/// Decides when a stream worker closes the open window of a quiet stream:
/// every `check_interval`, once no event has been received for `idle` and the
/// wall clock is past the window's end plus its grace.
#[derive(Clone)]
struct CloseTimer {
    /// The wall clock, in seconds since the Unix epoch.
    now: Arc<dyn Fn() -> i64 + Send + Sync>,
    check_interval: Duration,
    idle: Duration,
}

#[cfg(test)]
impl CloseTimer {
    fn new(
        now: impl Fn() -> i64 + Send + Sync + 'static,
        check_interval: Duration,
        idle: Duration,
    ) -> Self {
        Self {
            now: Arc::new(now),
            check_interval,
            idle,
        }
    }
}

impl Default for CloseTimer {
    fn default() -> Self {
        Self {
            now: Arc::new(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |elapsed| {
                        i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
                    })
            }),
            check_interval: Duration::from_secs(CLOSE_CHECK_SECS),
            idle: Duration::from_secs(CLOSE_IDLE_SECS),
        }
    }
}

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
    fn orig_addr(&self) -> IpAddr {
        match self {
            Self::Conn(evt) => evt.orig_addr,
            Self::Dns(evt) => evt.orig_addr,
            Self::Http(evt) => evt.orig_addr,
            Self::Rdp(evt) => evt.orig_addr,
        }
    }

    fn resp_addr(&self) -> IpAddr {
        match self {
            Self::Conn(evt) => evt.resp_addr,
            Self::Dns(evt) => evt.resp_addr,
            Self::Http(evt) => evt.resp_addr,
            Self::Rdp(evt) => evt.resp_addr,
        }
    }

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
    close_timer: CloseTimer,
}

impl Client {
    pub(crate) fn new(
        ingest_addr: SocketAddr,
        publish_addr: SocketAddr,
        server_name: String,
        certs: &Certs,
    ) -> Result<Self> {
        let endpoint = client::config(certs)?;
        Ok(Client {
            ingest_addr,
            publish_addr,
            server_name,
            endpoint,
            close_timer: CloseTimer::default(),
        })
    }

    #[cfg(test)]
    fn with_close_timer(mut self, close_timer: CloseTimer) -> Self {
        self.close_timer = close_timer;
        self
    }

    // Keeps the shutdown stages together so resource ownership and endpoint
    // close ordering remain explicit.
    #[allow(clippy::too_many_lines)]
    pub(crate) async fn run(
        self,
        policy_handle: PolicyHandle,
        mut actor_task: tokio::task::JoinHandle<Result<()>>,
        coordinator: CancellationCoordinator,
    ) -> Result<()> {
        let (sender, receiver) = async_channel::bounded::<TimeSeries>(TIME_SERIES_CHANNEL_SIZE);
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
                    connection_notify.clone(),
                    coordinator.clone(),
                ),
                publish_connection_control(
                    sender,
                    self.publish_addr,
                    &self.server_name,
                    &self.endpoint,
                    REQUIRED_GIGANTO_VERSION,
                    policy_handle,
                    connection_notify.clone(),
                    coordinator.clone(),
                    self.close_timer.clone(),
                )
            )
        });

        let mut controls_completed = false;
        let mut actor_completed = false;
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
            actor = &mut actor_task => {
                actor_completed = true;
                coordinator.request_cancellation("policy actor exit");
                match actor {
                    Ok(Ok(())) => Err(anyhow::anyhow!(
                        "policy actor ended unexpectedly"
                    )),
                    Ok(Err(e)) => Err(e).context("policy actor failed"),
                    Err(e) => Err(anyhow::anyhow!("policy actor task panicked: {e}")),
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
        // policy actor has completed, so collecting its JoinHandle result cannot
        // block.
        if drained && !actor_completed {
            let actor_result = match actor_task.await {
                Ok(result) => result.context("policy actor failed"),
                Err(e) => Err(anyhow::anyhow!("policy actor task panicked: {e}")),
            };
            if let Err(e) = actor_result
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
                            drain_series_at_shutdown(
                                &series_recv,
                                &coordinator,
                                &arc_conn,
                                &connection_lifecycle,
                                &policy_handle,
                                &connection_notify,
                            )
                            .await;
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
                            // Queue behind the policy's live sender to keep its writes in order.
                            let Err(series) = queue_to_ingest_sender(series).await else {
                                continue;
                            };
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
                                policy_handle.clone(),
                                connection_notify.clone(),
                            )
                            .await;
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

/// Producers observe the same cancellation as the ingest control and drop
/// their senders. Keep receiving until the outer queue closes so a series
/// already queued at the shutdown boundary is still handed to an ingest worker.
async fn drain_series_at_shutdown(
    series_recv: &Receiver<TimeSeries>,
    coordinator: &CancellationCoordinator,
    connection: &Arc<Connection>,
    connection_lifecycle: &ConnectionLifecycle,
    policy_handle: &PolicyHandle,
    connection_notify: &Arc<Notify>,
) {
    while let Ok(series) = series_recv.recv().await {
        let Err(series) = queue_to_ingest_sender(series).await else {
            continue;
        };
        spawn_time_series_sender(
            coordinator,
            connection.clone(),
            series,
            CancellationToken::new(),
            connection_lifecycle.clone(),
            policy_handle.clone(),
            connection_notify.clone(),
        )
        .await;
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

#[allow(clippy::too_many_arguments)]
async fn publish_connection_control(
    series_send: Sender<TimeSeries>,
    server_addr: SocketAddr,
    server_name: &str,
    endpoint: &Endpoint,
    version: &str,
    policy_handle: PolicyHandle,
    connection_notify: Arc<Notify>,
    coordinator: CancellationCoordinator,
    close_timer: CloseTimer,
) -> Result<()> {
    loop {
        let connected = tokio::select! {
            biased;
            () = coordinator.cancelled() => return Ok(()),
            result = publish_connect(endpoint, server_addr, server_name, version) => result,
        };
        match connected {
            Ok((conn, mut send)) => {
                let lifecycle = ConnectionLifecycle::new();
                let requests = PublishRequests::default();
                let dispatcher = lifecycle.tasks.track_future(run_inbound_dispatcher(
                    conn.clone(),
                    series_send.clone(),
                    connection_notify.clone(),
                    requests.clone(),
                    lifecycle.clone(),
                    coordinator.clone(),
                    close_timer.clone(),
                ));
                let mut dispatcher = coordinator.tracker().spawn(dispatcher);
                let outcome = tokio::select! {
                    biased;
                    () = coordinator.cancelled() => Ok(StreamRecoveryAction::Exit),
                    result = &mut dispatcher => {
                        warn!("Inbound dispatcher exited: {:?}", result.err());
                        Ok(StreamRecoveryAction::Reconnect)
                    }
                    () = connection_notify.notified() => Ok(StreamRecoveryAction::Reconnect),
                    error = conn.closed() => {
                        warn!("Publish connection closed: {error}");
                        connection_notify.notify_waiters();
                        Ok(StreamRecoveryAction::Reconnect)
                    }
                    result = send_policy_requests(&mut send, &policy_handle, &requests) => result,
                };
                // A cancelled write may have sent part of a frame. Always close
                // and drain this connection before reusing the latest snapshot.
                drain_connection_generation(&conn, &lifecycle, "publish").await?;
                match outcome {
                    Ok(StreamRecoveryAction::Exit) => return Ok(()),
                    Ok(StreamRecoveryAction::Reconnect) => {}
                    Err(error) => match classify_stream_error(&error) {
                        Some(StreamRecoveryAction::Exit) => return Ok(()),
                        Some(StreamRecoveryAction::Reconnect) => {}
                        None => return Err(error).context("Cannot recover from open stream error"),
                    },
                }
            }
            Err(error) => match error.downcast_ref::<ConnectionError>() {
                Some(
                    ConnectionError::ConnectionClosed(_)
                    | ConnectionError::ApplicationClosed(_)
                    | ConnectionError::Reset
                    | ConnectionError::TimedOut,
                ) => {}
                Some(ConnectionError::TransportError(_)) => {
                    bail!("Invalid peer certificate contents")
                }
                _ => {
                    return Err(error).with_context(|| format!("Fail to connect to {server_addr}"));
                }
            },
        }
        warn!("Retry Publish connection to {server_addr} after {SERVER_RETRY_INTERVAL} seconds");
        tokio::select! {
            biased;
            () = coordinator.cancelled() => return Ok(()),
            () = sleep(Duration::from_secs(SERVER_RETRY_INTERVAL)) => {}
        }
    }
}

/// A stream request sent on one Publish connection, and whether Giganto's
/// inbound stream for it has arrived.
struct PublishRequest {
    state: StreamPolicy,
    answered: bool,
}

/// The stream requests of one Publish connection, keyed by policy ID. Giganto
/// names an inbound stream only by policy ID, so the dispatcher binds it to the
/// request recorded here, not to the policy's current content.
#[derive(Clone, Default)]
struct PublishRequests(Arc<Mutex<HashMap<u32, PublishRequest>>>);

impl PublishRequests {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u32, PublishRequest>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Takes the request an inbound stream for `id` answers. `None` means no
    /// request is waiting for one, or its policy was deleted or replaced since.
    fn answer(&self, id: u32) -> Option<StreamPolicy> {
        let mut requests = self.lock();
        let request = requests.get_mut(&id).filter(|request| !request.answered)?;
        request.answered = true;
        (!request.state.token.is_cancelled()).then(|| request.state.clone())
    }
}

/// Watches current state rather than replaying queued add events. Each connection
/// sends a policy once, including requests still waiting for an inbound stream.
///
/// A policy whose token was cancelled after its request went out (deleted,
/// absent from a list, or replaced with new content) is requested again only
/// once that request's inbound stream has arrived. Until then a stream for its
/// ID could answer either request, so the connection is replaced instead.
async fn send_policy_requests(
    send: &mut SendStream,
    policy_handle: &PolicyHandle,
    requests: &PublishRequests,
) -> Result<StreamRecoveryAction> {
    let mut policy_ids = policy_handle.subscribe();
    loop {
        let snapshot = policy_ids.borrow_and_update().clone();
        requests
            .lock()
            .retain(|_, request| !request.answered || !request.state.token.is_cancelled());
        for id in snapshot {
            {
                let mut requests = requests.lock();
                if let Some(request) = requests.get(&id) {
                    if !request.state.token.is_cancelled() {
                        continue;
                    }
                    if !request.answered {
                        info!(
                            "Reconnecting Publish: policy {id} changed before the stream \
                             for its earlier request arrived"
                        );
                        return Ok(StreamRecoveryAction::Reconnect);
                    }
                    requests.remove(&id);
                }
            }
            // Recheck after consuming the snapshot: deletion may have happened
            // while another policy's request was being written.
            let Some(state) = policy_handle.stream_policy(id).await? else {
                continue;
            };
            if state.token.is_cancelled() {
                continue;
            }
            // Record the request before writing it so that its stream cannot
            // arrive before the dispatcher can bind it.
            requests.lock().insert(
                id,
                PublishRequest {
                    state: state.clone(),
                    answered: false,
                },
            );
            tokio::select! {
                biased;
                () = state.token.cancelled() => return Ok(StreamRecoveryAction::Reconnect),
                result = process_network_stream(send, &state) => result?,
            }
        }
        policy_ids
            .changed()
            .await
            .context("Policy snapshot channel closed")?;
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

/// The Publish control task owns the request stream and writes requests in order.
async fn process_network_stream(send: &mut SendStream, state: &StreamPolicy) -> Result<()> {
    let policy = &state.policy;
    let request = RequestTimeSeriesGeneratorStream {
        start: state.start,
        id: policy.id.to_string(),
        src_ip: policy.src_ip,
        dst_ip: policy.dst_ip,
        sensor: policy.node.clone(),
    };
    send_stream_request(
        send,
        StreamRequestPayload::TimeSeriesGenerator {
            record_type: RequestStreamRecord::from_ext(policy.kind),
            request,
        },
    )
    .await?;
    Ok(())
}

/// Owns `accept_uni()` for a single publish connection and centralises
/// inbound stream dispatch. For each accepted unidirectional stream
/// it reads the stream-start message to determine the policy id, then
/// binds the stream to the request it answers on this connection and
/// spawns a per-stream worker with the policy state that request was
/// sent with. Streams whose policy was deleted or replaced since the
/// request are silently skipped — they are a normal consequence of a
/// change that raced with an in-flight stream open.
async fn run_inbound_dispatcher(
    conn: Connection,
    sender: Sender<TimeSeries>,
    connection_notify: Arc<Notify>,
    requests: PublishRequests,
    connection_lifecycle: ConnectionLifecycle,
    coordinator: CancellationCoordinator,
    close_timer: CloseTimer,
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

        let Some(state) = requests.answer(id) else {
            info!(
                "Inbound stream for unknown, deleted or replaced policy {id}; \
                 dropping stream"
            );
            let _ = recv.stop(VarInt::default());
            continue;
        };

        let sender = sender.clone();
        let coord = coordinator.clone();
        let worker_lifecycle = connection_lifecycle.clone();
        let policy_id = state.policy.id;
        let close_timer = close_timer.clone();
        let worker = connection_lifecycle.tasks.track_future(async move {
            if let Err(e) = run_stream_worker(
                recv,
                sender,
                state,
                worker_lifecycle.token,
                coord,
                close_timer,
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
/// building and writing their windows, closing a quiet stream's window
/// on `close_timer`, reacting to per-policy deletion (`policy_token`),
/// and global cancellation.
///
/// Shutdown, deletion and a replaced connection drop the open window
/// without writing it: it has not ended, and the resume rebuilds it from
/// the events Giganto stores.
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
    state: StreamPolicy,
    connection_token: tokio_util::sync::CancellationToken,
    coordinator: CancellationCoordinator,
    close_timer: CloseTimer,
) -> Result<()> {
    let StreamPolicy {
        policy,
        token: policy_token,
        start,
    } = state;
    info!("Raw event {:?} has been connected", policy.kind);
    let id = policy.id;
    let mut windows = WindowBuilder::try_new(&policy, start)?;

    // The timer must not interrupt a partly read event, so the stream is read
    // by its own future, which hands each complete event over this channel.
    let (event_send, mut event_recv) = mpsc::channel(1);
    let reader = async {
        while let Ok(event) = receive_time_series_generator_data(&mut recv).await {
            if event_send.send(event).await.is_err() {
                break;
            }
        }
        // Dropping the sender tells the builder that the stream ended once it
        // has taken the events already handed over.
        drop(event_send);
        std::future::pending::<()>().await;
    };
    let builder = async {
        let mut check = interval(close_timer.check_interval);
        check.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut last_received = Instant::now();
        loop {
            tokio::select! {
                biased;
                () = coordinator.cancelled() => {
                    info!("Stream worker for policy {id} shutting down");
                    return Ok(false);
                }
                () = policy_token.cancelled() => {
                    info!("Policy {id} deleted, stopping stream worker");
                    return Ok(true);
                }
                () = connection_token.cancelled() => {
                    info!("Stream worker for policy {id} stopping; publish connection replaced");
                    return Ok(false);
                }
                received = event_recv.recv() => {
                    let Some((raw_event, timestamp_nanos)) = received else {
                        info!("Stream for policy {id} ended");
                        return Ok(false);
                    };
                    last_received = Instant::now();
                    let Ok(event) = Event::try_new(policy.kind, &raw_event) else {
                        warn!(
                            "Failed to deserialize raw_event for sampling kind: {:?}",
                            policy.kind
                        );
                        continue;
                    };
                    match windows.add(timestamp_nanos, &event) {
                        Ok(Some(series)) => write_window(&sender, series).await?,
                        Ok(None) => {}
                        Err(e) => warn!("Failed to generate time series: {}", e),
                    }
                }
                _ = check.tick() => {
                    if last_received.elapsed() < close_timer.idle {
                        continue;
                    }
                    if let Some(series) = windows.close_if_due((close_timer.now)()) {
                        write_window(&sender, series).await?;
                    }
                }
            }
        }
    };
    let deleted: Result<bool> = tokio::select! {
        result = builder => result,
        () = reader => unreachable!("the stream reader never completes"),
    };
    if deleted? {
        recv.stop(VarInt::default())?;
    }
    Ok(())
}

/// Hands a window to the ingest control, which queues it to the policy's
/// ingest sender. Windows never bypass the control: one written directly to a
/// cached sender could overtake an earlier one still queued there.
async fn write_window(send_channel: &Sender<TimeSeries>, series: TimeSeries) -> Result<()> {
    send_channel.send(series).await?;
    Ok(())
}

/// Queues `series` to its policy's ingest sender. Returns the series back when
/// the policy has no sender, or its sender closed with a deleted policy, a
/// replaced ingest connection or shutdown, so that the caller starts one.
///
/// The ingest control takes every window in the order its stream worker wrote
/// it, and queues it here before it takes the next. A corrected window thus
/// follows the write it replaces on the same QUIC stream; a second sender
/// would carry it on another stream, which Giganto could store first.
async fn queue_to_ingest_sender(series: TimeSeries) -> Result<(), TimeSeries> {
    // Clone the sender out of the lock to avoid holding the RwLock read
    // guard across an await point.
    let cached_sender = INGEST_CHANNEL
        .read()
        .await
        .get(&series.sampling_policy_id)
        .cloned();
    let Some(sender) = cached_sender else {
        return Err(series);
    };
    sender
        .send(series)
        .await
        .map_err(|async_channel::SendError(series)| series)
}

/// Installs a new queue as the ingest sender of `sampling_policy_id`,
/// replacing a closed one. The ingest control installs it before it takes the
/// next window, so that window finds it.
async fn register_ingest_queue(sampling_policy_id: &str) -> Receiver<TimeSeries> {
    let (send_channel, recv_channel) =
        async_channel::bounded::<TimeSeries>(TIME_SERIES_CHANNEL_SIZE);
    INGEST_CHANNEL
        .write()
        .await
        .insert(sampling_policy_id.to_owned(), send_channel);
    recv_channel
}

/// Clears all cached senders from the global ingest channel map.
/// Should be called after top-level drain has completed to ensure no
/// stale senders survive into a subsequent run.
pub(crate) async fn clear_ingest_channel() {
    INGEST_CHANNEL.write().await.clear();
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

/// Starts the ingest sender of the policy `series` belongs to, with `series`
/// as its first write. Its queue is installed before this returns.
#[allow(clippy::too_many_arguments)]
async fn spawn_time_series_sender(
    coordinator: &CancellationCoordinator,
    connection: Arc<Connection>,
    series: TimeSeries,
    policy_token: CancellationToken,
    connection_lifecycle: ConnectionLifecycle,
    policy_handle: PolicyHandle,
    connection_notify: Arc<Notify>,
) {
    let sampling_policy_id = series.sampling_policy_id.clone();
    let recv_channel = register_ingest_queue(&sampling_policy_id).await;
    let error_notify = connection_notify.clone();
    let task_coordinator = coordinator.clone();
    let connection_tasks = connection_lifecycle.tasks.clone();
    let tracked = connection_tasks.track_future(async move {
        if let Err(e) = send_time_series(
            connection,
            series,
            recv_channel,
            policy_token,
            connection_lifecycle,
            policy_handle,
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

/// Writes `series` and then every window queued to `recv_channel`, the queue
/// [`register_ingest_queue`] installed for the policy, on one QUIC stream.
#[allow(clippy::too_many_arguments)]
async fn send_time_series(
    connection: Arc<Connection>,
    series: TimeSeries,
    recv_channel: Receiver<TimeSeries>,
    policy_token: CancellationToken,
    connection_lifecycle: ConnectionLifecycle,
    policy_handle: PolicyHandle,
    connection_notify: Arc<Notify>,
    coordinator: CancellationCoordinator,
) -> Result<()> {
    let sampling_policy_id = series.sampling_policy_id.clone();

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
                policy_handle,
                connection_notify,
            ));
        coordinator.tracker().spawn(receiver);

        // Data transmission after the first time (only series data).
        // `policy_token` fires on deletion so this sender exits promptly.
        // Cleanup below closes its channel and removes the cached sender.
        loop {
            tokio::select! {
                biased;
                () = coordinator.cancelled() => {
                    // Stop accepting new work, then transmit everything
                    // that was already accepted into this policy's queue.
                    recv_channel.close();
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
    // Close our channel to mark its instance, then only remove the entry
    // if it is still our channel (not a newer sender registered by a
    // reconnect).
    recv_channel.close();
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
        .checked_mul(time_series::SECOND_TO_NANO)
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
    policy_handle: PolicyHandle,
    connection_notify: Arc<Notify>,
) {
    let Ok(policy_id) = sampling_policy_id.parse() else {
        warn!(%sampling_policy_id, "Invalid policy id in ACK receiver");
        return;
    };
    loop {
        let result = tokio::select! {
            biased;
            () = policy_token.cancelled() => {
                // Policy deletion: exit immediately without draining.
                // The policy actor ignores ACKs for inactive policies.
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
                if policy_handle
                    .record_ack(policy_id, timestamp)
                    .await
                    .is_err()
                {
                    warn!(
                        %sampling_policy_id,
                        "Policy actor closed while recording an ACK"
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
