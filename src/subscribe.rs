#[cfg(test)]
mod tests;
mod time_series;

use std::sync::{LazyLock, Mutex};
use std::task::Poll;
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
        network::{
            Bootp, Conn, DceRpc, Dhcp, Dns, Ftp, Http, Icmp, Kerberos, Ldap, MalformedDns, Mqtt,
            Nfs, Ntlm, Radius, Rdp, Smb, Smtp, Ssh, Tls,
        },
        receive_ack_timestamp, send_record_header,
    },
    publish::{
        TimeSeriesGeneratorData, receive_time_series_generator_data,
        receive_time_series_generator_stream_start_message, send_stream_request,
        stream::{RequestStreamRecord, RequestTimeSeriesGeneratorStream, StreamRequestPayload},
    },
};
use num_traits::ToPrimitive;
use quinn::{Connection, ConnectionError, Endpoint, RecvStream, SendStream, VarInt, WriteError};
use review_protocol::types::{
    ConnField, Measure, RawEventKind as PolicyRawEventKind, TimeSeriesGenerationPolicy,
};
use time_series::{IngestFrame, PassClock, RunStart, WindowBuilder};
use tokio::{
    sync::{Notify, RwLock, mpsc},
    task::JoinSet,
    time::{
        Duration, Instant, MissedTickBehavior, interval, interval_at, sleep, timeout, timeout_at,
    },
};
use tokio_util::sync::{CancellationToken, DropGuard};
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
/// How long a policy's new ingest sender waits for Giganto to store what the
/// sender it replaces wrote before it fails and signals a reconnect. Shorter
/// in tests, which hold that storing beyond it.
const PREVIOUS_STREAM_STORE_TIMEOUT: Duration = if cfg!(test) {
    Duration::from_secs(2)
} else {
    Duration::from_secs(10)
};
/// How often a reconnect warns while it still waits for Giganto to store what
/// the senders on the connection it replaces wrote. Shorter in tests, which
/// hold that storing for several intervals.
const STORE_BEFORE_RECONNECT_WARN_INTERVAL: Duration = if cfg!(test) {
    Duration::from_millis(200)
} else {
    Duration::from_secs(10)
};

/// The fewest inbound streams a Publish connection lets Giganto have open at
/// once: quinn's default, which applied before crusher raised it.
const MIN_INBOUND_STREAMS: u64 = 100;

/// How long a stream must have received no event after its replay end before
/// it passes a window by the wall clock. A stream passes by the wall clock
/// only after its replay end, so a replay that pauses never cuts a window it
/// is still filling.
const CLOSE_IDLE_SECS: u64 = 30;

/// How often a policy runner checks whether a window is due to close.
const CLOSE_CHECK_SECS: u64 = 10;

/// How often a policy runner warns while a stream of its request has not
/// opened or is still replaying.
const STALL_WARNING_SECS: u64 = 600;

/// Decides when a policy runner closes windows its streams passed by being
/// quiet: every `check_interval`, a stream past its replay end that has
/// received no event for `idle` passes the windows whose end plus the grace
/// the wall clock has reached. Also sets how often a runner warns about
/// streams that hold its windows open.
#[derive(Clone)]
struct CloseTimer {
    /// The wall clock, in seconds since the Unix epoch.
    now: Arc<dyn Fn() -> i64 + Send + Sync>,
    check_interval: Duration,
    idle: Duration,
    stall_warning: Duration,
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
            stall_warning: Duration::from_secs(STALL_WARNING_SECS),
        }
    }

    fn with_stall_warning(mut self, stall_warning: Duration) -> Self {
        self.stall_warning = stall_warning;
        self
    }
}

impl CloseTimer {
    fn pass_clock(&self) -> PassClock {
        PassClock {
            wall_secs: (self.now)(),
            now: Instant::now(),
            idle: self.idle,
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
            stall_warning: Duration::from_secs(STALL_WARNING_SECS),
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

// The ingest queue of each policy's sender, by policy id. Every frame of a
// policy is written on that one sender's stream.
static INGEST_CHANNEL: LazyLock<RwLock<HashMap<u32, IngestQueue>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// The queue of a policy's ingest sender.
struct IngestQueue {
    frames: Sender<IngestFrame>,
    /// The policy token the sender stops on. Once it is cancelled, the sender
    /// drops whatever is still queued.
    run: CancellationToken,
    /// Cancelled once Giganto has stored everything the sender wrote and
    /// finished its side of the stream, or once the stream can carry nothing
    /// more (the sender failed or the connection was replaced), and in either
    /// case only after [`Self::previous`] is cancelled too. The entry stays
    /// installed until then, so that a sender replacing this one, and a
    /// reconnect, find it.
    stored: CancellationToken,
    /// The [`Self::stored`] of the sender this one replaced, if Giganto had
    /// not stored its writes yet when this one was installed.
    previous: Option<CancellationToken>,
}

/// The receiving end of a policy's ingest queue, as its sender takes it.
struct QueueRegistration {
    /// The frames queued to the sender.
    frames: Receiver<IngestFrame>,
    /// The sender's [`IngestQueue::stored`].
    stored: CancellationToken,
    /// The [`IngestQueue::stored`] of the sender this one replaced, which
    /// may still have writes on its own stream that Giganto has not stored.
    previous: Option<CancellationToken>,
}

/// Returns the Giganto stream kind that carries the raw events of `kind`.
///
/// Every network kind maps to the stream kind of the same name. The match
/// names every kind so that a kind added to review-protocol fails to compile
/// until it is classified here.
///
/// # Errors
///
/// Returns an error if `kind` is not a network kind.
pub(crate) fn stream_record(kind: PolicyRawEventKind) -> Result<RequestStreamRecord> {
    Ok(match kind {
        PolicyRawEventKind::Bootp => RequestStreamRecord::Bootp,
        PolicyRawEventKind::Conn => RequestStreamRecord::Conn,
        PolicyRawEventKind::DceRpc => RequestStreamRecord::DceRpc,
        PolicyRawEventKind::Dhcp => RequestStreamRecord::Dhcp,
        PolicyRawEventKind::Dns => RequestStreamRecord::Dns,
        PolicyRawEventKind::Ftp => RequestStreamRecord::Ftp,
        PolicyRawEventKind::Http => RequestStreamRecord::Http,
        PolicyRawEventKind::Icmp => RequestStreamRecord::Icmp,
        PolicyRawEventKind::Kerberos => RequestStreamRecord::Kerberos,
        PolicyRawEventKind::Ldap => RequestStreamRecord::Ldap,
        PolicyRawEventKind::MalformedDns => RequestStreamRecord::MalformedDns,
        PolicyRawEventKind::Mqtt => RequestStreamRecord::Mqtt,
        PolicyRawEventKind::Nfs => RequestStreamRecord::Nfs,
        PolicyRawEventKind::Ntlm => RequestStreamRecord::Ntlm,
        PolicyRawEventKind::Radius => RequestStreamRecord::Radius,
        PolicyRawEventKind::Rdp => RequestStreamRecord::Rdp,
        PolicyRawEventKind::Smb => RequestStreamRecord::Smb,
        PolicyRawEventKind::Smtp => RequestStreamRecord::Smtp,
        PolicyRawEventKind::Ssh => RequestStreamRecord::Ssh,
        PolicyRawEventKind::Tls => RequestStreamRecord::Tls,
        PolicyRawEventKind::ProcessCreate
        | PolicyRawEventKind::FileCreateTime
        | PolicyRawEventKind::NetworkConnect
        | PolicyRawEventKind::ProcessTerminate
        | PolicyRawEventKind::ImageLoad
        | PolicyRawEventKind::FileCreate
        | PolicyRawEventKind::RegistryValueSet
        | PolicyRawEventKind::RegistryKeyRename
        | PolicyRawEventKind::FileCreateStreamHash
        | PolicyRawEventKind::PipeEvent
        | PolicyRawEventKind::DnsQuery
        | PolicyRawEventKind::FileDelete
        | PolicyRawEventKind::ProcessTamper
        | PolicyRawEventKind::FileDeleteDetected
        | PolicyRawEventKind::Netflow5
        | PolicyRawEventKind::Netflow9 => {
            bail!("{kind:?} is not a network raw event kind")
        }
    })
}

/// Checks that the raw event kind and the measure of `policy` describe a
/// series this generator can build.
///
/// # Errors
///
/// Returns an error if the kind is not a network kind, or if the measure sums
/// a Conn field over another kind.
pub(crate) fn check_generation_spec(policy: &TimeSeriesGenerationPolicy) -> Result<()> {
    stream_record(policy.raw_event_kind)?;
    if let Measure::Sum(field) = policy.measure
        && policy.raw_event_kind != PolicyRawEventKind::Conn
    {
        bail!(
            "Sum({field:?}) is defined only on Conn, not on {:?}",
            policy.raw_event_kind
        );
    }
    Ok(())
}

// An event is decoded, counted and dropped at once, so boxing the large
// variants would only add an allocation per event.
#[allow(clippy::large_enum_variant)]
enum Event {
    Bootp(Bootp),
    Conn(Conn),
    DceRpc(DceRpc),
    Dhcp(Dhcp),
    Dns(Dns),
    Ftp(Ftp),
    Http(Http),
    Icmp(Icmp),
    Kerberos(Kerberos),
    Ldap(Ldap),
    MalformedDns(MalformedDns),
    Mqtt(Mqtt),
    Nfs(Nfs),
    Ntlm(Ntlm),
    Radius(Radius),
    Rdp(Rdp),
    Smb(Smb),
    Smtp(Smtp),
    Ssh(Ssh),
    Tls(Tls),
}

impl Event {
    fn orig_addr(&self) -> IpAddr {
        match self {
            Self::Bootp(evt) => evt.orig_addr,
            Self::Conn(evt) => evt.orig_addr,
            Self::DceRpc(evt) => evt.orig_addr,
            Self::Dhcp(evt) => evt.orig_addr,
            Self::Dns(evt) => evt.orig_addr,
            Self::Ftp(evt) => evt.orig_addr,
            Self::Http(evt) => evt.orig_addr,
            Self::Icmp(evt) => evt.orig_addr,
            Self::Kerberos(evt) => evt.orig_addr,
            Self::Ldap(evt) => evt.orig_addr,
            Self::MalformedDns(evt) => evt.orig_addr,
            Self::Mqtt(evt) => evt.orig_addr,
            Self::Nfs(evt) => evt.orig_addr,
            Self::Ntlm(evt) => evt.orig_addr,
            Self::Radius(evt) => evt.orig_addr,
            Self::Rdp(evt) => evt.orig_addr,
            Self::Smb(evt) => evt.orig_addr,
            Self::Smtp(evt) => evt.orig_addr,
            Self::Ssh(evt) => evt.orig_addr,
            Self::Tls(evt) => evt.orig_addr,
        }
    }

    fn resp_addr(&self) -> IpAddr {
        match self {
            Self::Bootp(evt) => evt.resp_addr,
            Self::Conn(evt) => evt.resp_addr,
            Self::DceRpc(evt) => evt.resp_addr,
            Self::Dhcp(evt) => evt.resp_addr,
            Self::Dns(evt) => evt.resp_addr,
            Self::Ftp(evt) => evt.resp_addr,
            Self::Http(evt) => evt.resp_addr,
            Self::Icmp(evt) => evt.resp_addr,
            Self::Kerberos(evt) => evt.resp_addr,
            Self::Ldap(evt) => evt.resp_addr,
            Self::MalformedDns(evt) => evt.resp_addr,
            Self::Mqtt(evt) => evt.resp_addr,
            Self::Nfs(evt) => evt.resp_addr,
            Self::Ntlm(evt) => evt.resp_addr,
            Self::Radius(evt) => evt.resp_addr,
            Self::Rdp(evt) => evt.resp_addr,
            Self::Smb(evt) => evt.resp_addr,
            Self::Smtp(evt) => evt.resp_addr,
            Self::Ssh(evt) => evt.resp_addr,
            Self::Tls(evt) => evt.resp_addr,
        }
    }

    /// Returns the value of `field` of a Conn event, or `None` for an event of
    /// another kind.
    fn conn_field(&self, field: ConnField) -> Option<f64> {
        let Self::Conn(evt) = self else {
            return None;
        };
        Some(match field {
            ConnField::Duration => evt.duration.to_f64().unwrap_or_default(),
            ConnField::OrigBytes => evt.orig_bytes.to_f64().unwrap_or_default(),
            ConnField::RespBytes => evt.resp_bytes.to_f64().unwrap_or_default(),
            ConnField::OrigPkts => evt.orig_pkts.to_f64().unwrap_or_default(),
            ConnField::RespPkts => evt.resp_pkts.to_f64().unwrap_or_default(),
        })
    }

    /// Decodes a raw event of the stream kind `record`.
    fn try_new(record: RequestStreamRecord, raw_event: &[u8]) -> Result<Self> {
        Ok(match record {
            RequestStreamRecord::Bootp => Self::Bootp(bincode::deserialize::<Bootp>(raw_event)?),
            RequestStreamRecord::Conn => Self::Conn(bincode::deserialize::<Conn>(raw_event)?),
            RequestStreamRecord::DceRpc => Self::DceRpc(bincode::deserialize::<DceRpc>(raw_event)?),
            RequestStreamRecord::Dhcp => Self::Dhcp(bincode::deserialize::<Dhcp>(raw_event)?),
            RequestStreamRecord::Dns => Self::Dns(bincode::deserialize::<Dns>(raw_event)?),
            RequestStreamRecord::Ftp => Self::Ftp(bincode::deserialize::<Ftp>(raw_event)?),
            RequestStreamRecord::Http => Self::Http(bincode::deserialize::<Http>(raw_event)?),
            RequestStreamRecord::Icmp => Self::Icmp(bincode::deserialize::<Icmp>(raw_event)?),
            RequestStreamRecord::Kerberos => {
                Self::Kerberos(bincode::deserialize::<Kerberos>(raw_event)?)
            }
            RequestStreamRecord::Ldap => Self::Ldap(bincode::deserialize::<Ldap>(raw_event)?),
            RequestStreamRecord::MalformedDns => {
                Self::MalformedDns(bincode::deserialize::<MalformedDns>(raw_event)?)
            }
            RequestStreamRecord::Mqtt => Self::Mqtt(bincode::deserialize::<Mqtt>(raw_event)?),
            RequestStreamRecord::Nfs => Self::Nfs(bincode::deserialize::<Nfs>(raw_event)?),
            RequestStreamRecord::Ntlm => Self::Ntlm(bincode::deserialize::<Ntlm>(raw_event)?),
            RequestStreamRecord::Radius => Self::Radius(bincode::deserialize::<Radius>(raw_event)?),
            RequestStreamRecord::Rdp => Self::Rdp(bincode::deserialize::<Rdp>(raw_event)?),
            RequestStreamRecord::Smb => Self::Smb(bincode::deserialize::<Smb>(raw_event)?),
            RequestStreamRecord::Smtp => Self::Smtp(bincode::deserialize::<Smtp>(raw_event)?),
            RequestStreamRecord::Ssh => Self::Ssh(bincode::deserialize::<Ssh>(raw_event)?),
            RequestStreamRecord::Tls => Self::Tls(bincode::deserialize::<Tls>(raw_event)?),
            RequestStreamRecord::Log
            | RequestStreamRecord::Pcap
            | RequestStreamRecord::FileCreate
            | RequestStreamRecord::FileDelete => {
                bail!("{record:?} is not a network raw event kind")
            }
        })
    }
}

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
        let (sender, receiver) = async_channel::bounded::<IngestFrame>(TIME_SERIES_CHANNEL_SIZE);
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
    series_recv: Receiver<IngestFrame>,
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
                            store_before_reconnect(&arc_conn, &coordinator).await;
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
                            route_series(
                                series,
                                &coordinator,
                                &arc_conn,
                                &connection_lifecycle,
                                &policy_handle,
                                &connection_notify,
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

/// Queues `series` behind its policy's live sender, which keeps the policy's
/// writes in order, or starts a sender with it. A frame of a replaced request
/// or a deleted policy is dropped, as its own sender would drop it, rather
/// than written behind the next run's.
async fn route_series(
    series: IngestFrame,
    coordinator: &CancellationCoordinator,
    connection: &Arc<Connection>,
    connection_lifecycle: &ConnectionLifecycle,
    policy_handle: &PolicyHandle,
    connection_notify: &Arc<Notify>,
) {
    if series.run_stopped() {
        return;
    }
    let Err(series) = queue_to_ingest_sender(series).await else {
        return;
    };
    // Bind the series to the currently active policy by looking up its
    // `CancellationToken` in a single actor call. If the policy is no longer
    // active, drop the series instead of spawning another sender task.
    let Some(policy_token) = policy_token_for_series(policy_handle, series.policy_id()).await
    else {
        return;
    };
    // A policy token is replaced only after it is cancelled, so a run still
    // live now is the run of the token just looked up.
    if series.run_stopped() {
        return;
    }
    spawn_time_series_sender(
        coordinator,
        connection.clone(),
        series,
        policy_token,
        connection_lifecycle.clone(),
        policy_handle.clone(),
        connection_notify.clone(),
    )
    .await;
}

/// Producers observe the same cancellation as the ingest control and drop
/// their senders. Keep receiving until the outer queue closes so a series
/// already queued at the shutdown boundary is still handed to an ingest worker.
///
/// Ingest senders keep taking windows at shutdown until this drain closes
/// their queues, so a correction still in the outer queue follows the window
/// it replaces on that window's stream.
async fn drain_series_at_shutdown(
    series_recv: &Receiver<IngestFrame>,
    coordinator: &CancellationCoordinator,
    connection: &Arc<Connection>,
    connection_lifecycle: &ConnectionLifecycle,
    policy_handle: &PolicyHandle,
    connection_notify: &Arc<Notify>,
) {
    while let Ok(series) = series_recv.recv().await {
        if series.run_stopped() {
            continue;
        }
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
    close_ingest_queues().await;
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
    series_send: Sender<IngestFrame>,
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
                let runners = PolicyRunners {
                    series: series_send.clone(),
                    lifecycle: lifecycle.clone(),
                    coordinator: coordinator.clone(),
                    close_timer: close_timer.clone(),
                };
                let dispatcher = lifecycle.tasks.track_future(run_inbound_dispatcher(
                    conn.clone(),
                    connection_notify.clone(),
                    requests.clone(),
                    lifecycle.clone(),
                    coordinator.clone(),
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
                    result = send_policy_requests(
                        &conn,
                        &mut send,
                        &policy_handle,
                        &requests,
                        &runners,
                    ) => result,
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

/// The stream requests of one policy sent on one Publish connection, one per
/// sensor, and how many of Giganto's inbound streams for them have arrived.
struct PublishRequest {
    state: StreamPolicy,
    /// The number of streams requested: one per sensor of the policy.
    expected: usize,
    answered: usize,
    /// Hands each inbound stream to the policy's runner.
    streams: mpsc::UnboundedSender<RecvStream>,
}

impl PublishRequest {
    fn all_answered(&self) -> bool {
        self.answered >= self.expected
    }
}

/// The stream requests of one Publish connection, keyed by policy ID. Giganto
/// names an inbound stream only by policy ID, so the dispatcher binds it to the
/// request recorded here, not to the policy's current content. The streams of
/// one policy are not told apart: each binds to the policy's request until as
/// many have arrived as were requested.
#[derive(Clone, Default)]
struct PublishRequests(Arc<Mutex<HashMap<u32, PublishRequest>>>);

impl PublishRequests {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u32, PublishRequest>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Binds an inbound stream for `id` to the request it answers, and returns
    /// where to hand it. `None` means no request is waiting for another
    /// stream, or its policy was deleted or replaced since.
    fn answer(&self, id: u32) -> Option<mpsc::UnboundedSender<RecvStream>> {
        let mut requests = self.lock();
        let request = requests
            .get_mut(&id)
            .filter(|request| !request.all_answered())?;
        request.answered += 1;
        (!request.state.token.is_cancelled()).then(|| request.streams.clone())
    }
}

/// What a Publish connection starts each policy's runner with.
struct PolicyRunners {
    series: Sender<IngestFrame>,
    lifecycle: ConnectionLifecycle,
    coordinator: CancellationCoordinator,
    close_timer: CloseTimer,
}

impl PolicyRunners {
    /// Starts the runner of the request `state` was sent with, and returns the
    /// sender the dispatcher hands that request's inbound streams to.
    fn spawn(&self, state: StreamPolicy) -> mpsc::UnboundedSender<RecvStream> {
        let (stream_send, stream_recv) = mpsc::unbounded_channel();
        let series = self.series.clone();
        let connection_token = self.lifecycle.token.clone();
        let coordinator = self.coordinator.clone();
        let close_timer = self.close_timer.clone();
        let policy_id = state.policy.id;
        let runner = self.lifecycle.tasks.track_future(async move {
            if let Err(e) = run_policy(
                state,
                stream_recv,
                series,
                connection_token,
                coordinator,
                close_timer,
            )
            .await
            {
                warn!(policy_id, "Policy runner failed: {e:#}");
            }
        });
        self.coordinator.tracker().spawn(runner);
        stream_send
    }
}

/// Watches current state rather than replaying queued add events. Each connection
/// sends a policy's requests once, including requests still waiting for an
/// inbound stream, and starts the policy's runner as it sends them. Taking the
/// policy's view for its requests fixes the write generation of a grouped
/// policy's run, which is on disk before the requests are written; if that
/// fails, nothing is requested and the error ends the Publish control.
///
/// A policy whose token was cancelled after its requests went out (deleted,
/// absent from a list, or replaced with new content) is requested again only
/// once every inbound stream of those requests has arrived. Until then a
/// stream for its ID could answer either request, so the connection is
/// replaced instead.
///
/// Giganto answers each request with a stream that stays open, so before
/// writing a policy's requests the connection lets Giganto open as many
/// streams at once as have been requested on it so far. The count only grows,
/// since a stream of an earlier request may still be open, and it never
/// exceeds what Giganto opens here: one stream per request.
async fn send_policy_requests(
    conn: &Connection,
    send: &mut SendStream,
    policy_handle: &PolicyHandle,
    requests: &PublishRequests,
    runners: &PolicyRunners,
) -> Result<StreamRecoveryAction> {
    let mut policy_ids = policy_handle.subscribe();
    let mut requested: u64 = 0;
    loop {
        let snapshot = policy_ids.borrow_and_update().clone();
        requests
            .lock()
            .retain(|_, request| !request.all_answered() || !request.state.token.is_cancelled());
        for id in snapshot {
            {
                let mut requests = requests.lock();
                if let Some(request) = requests.get(&id) {
                    if !request.state.token.is_cancelled() {
                        continue;
                    }
                    if !request.all_answered() {
                        info!(
                            "Reconnecting Publish: policy {id} changed before every stream \
                             of its earlier request arrived"
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
            // The actor starts only policies of a network kind, so this
            // conversion does not fail for a policy it handed out.
            let record_type = match stream_record(state.policy.raw_event_kind) {
                Ok(record_type) => record_type,
                Err(e) => {
                    warn!("Not requesting a stream for policy {id}: {e:#}");
                    continue;
                }
            };
            requested = requested
                .saturating_add(u64::try_from(state.policy.sensors.len()).unwrap_or(u64::MAX));
            allow_inbound_streams(conn, requested);
            // Record the request and start its runner before writing it so
            // that its streams cannot arrive before the dispatcher can bind
            // them.
            let streams = runners.spawn(state.clone());
            requests.lock().insert(
                id,
                PublishRequest {
                    state: state.clone(),
                    expected: state.policy.sensors.len(),
                    answered: 0,
                    streams,
                },
            );
            tokio::select! {
                biased;
                () = state.token.cancelled() => return Ok(StreamRecoveryAction::Reconnect),
                result = process_network_stream(send, &state, record_type) => result?,
            }
        }
        policy_ids
            .changed()
            .await
            .context("Policy snapshot channel closed")?;
    }
}

/// Lets Giganto have `requested` inbound streams open at once on `conn`, and
/// no fewer than [`MIN_INBOUND_STREAMS`].
fn allow_inbound_streams(conn: &Connection, requested: u64) {
    let limit = VarInt::from_u64(requested.max(MIN_INBOUND_STREAMS)).unwrap_or(VarInt::MAX);
    conn.set_max_concurrent_uni_streams(limit);
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
///
/// Sends one generator stream request per sensor of the policy, all from the
/// policy's checkpoint.
async fn process_network_stream(
    send: &mut SendStream,
    state: &StreamPolicy,
    record_type: RequestStreamRecord,
) -> Result<()> {
    let policy = &state.policy;
    for sensor in &policy.sensors {
        let request = RequestTimeSeriesGeneratorStream {
            start: state.start,
            id: policy.id.to_string(),
            src_ip: policy.src_ip,
            dst_ip: policy.dst_ip,
            sensor: Some(sensor.clone()),
        };
        send_stream_request(
            send,
            StreamRequestPayload::TimeSeriesGenerator {
                record_type,
                request,
            },
        )
        .await?;
    }
    Ok(())
}

/// Owns `accept_uni()` for a single publish connection and centralises
/// inbound stream dispatch. For each accepted unidirectional stream
/// it reads the stream-start message to determine the policy id, then
/// binds the stream to the request it answers on this connection and
/// hands it to that request's policy runner. Streams whose policy was
/// deleted or replaced since the request, and streams beyond the number
/// requested, are silently skipped — they are a normal consequence of a
/// change that raced with an in-flight stream open.
async fn run_inbound_dispatcher(
    conn: Connection,
    connection_notify: Arc<Notify>,
    requests: PublishRequests,
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

        let Some(runner) = requests.answer(id) else {
            info!(
                "Inbound stream for unknown, deleted or replaced policy {id}, or beyond \
                 its sensors; dropping stream"
            );
            let _ = recv.stop(VarInt::default());
            continue;
        };
        if let Err(mpsc::error::SendError(mut recv)) = runner.send(recv) {
            info!("Inbound stream for policy {id} whose runner has stopped; dropping stream");
            let _ = recv.stop(VarInt::default());
        }
    }
}

/// Reads the frames of one generator stream and hands each over `frames`. The
/// runner's timer must not interrupt a partly read frame, so each stream is
/// read by its own task. When the runner stops taking frames, as it does while
/// the stream is paused, the reader stops reading once one frame waits.
async fn read_generator_frames(
    mut recv: RecvStream,
    frames: mpsc::Sender<TimeSeriesGeneratorData>,
) {
    while let Ok(data) = receive_time_series_generator_data(&mut recv).await {
        if frames.send(data).await.is_err() {
            return;
        }
    }
    // Dropping the sender tells the runner that the stream ended once it has
    // taken the frames already handed over.
}

/// Waits for the next frame of a stream that is not paused, polling the
/// streams from `first` on so that none is starved. Returns the stream's index
/// and the frame, or `None` once the stream has ended.
fn next_frame<'a>(
    frames: &'a mut [Option<mpsc::Receiver<TimeSeriesGeneratorData>>],
    windows: &'a WindowBuilder,
    first: usize,
) -> impl Future<Output = (usize, Option<TimeSeriesGeneratorData>)> + 'a {
    std::future::poll_fn(move |cx| {
        let streams = frames.len();
        for offset in 0..streams {
            let index = (first + offset) % streams;
            if windows.is_paused(index) {
                continue;
            }
            let Some(receiver) = frames.get_mut(index).and_then(Option::as_mut) else {
                continue;
            };
            if let Poll::Ready(frame) = receiver.poll_recv(cx) {
                return Poll::Ready((index, frame));
            }
        }
        Poll::Pending
    })
}

/// Applies a frame that stream `index` of `policy` received to its windows, and
/// returns the ingest frames to write, in order.
fn take_frame(
    windows: &mut WindowBuilder,
    policy: &TimeSeriesGenerationPolicy,
    record_type: RequestStreamRecord,
    index: usize,
    frame: TimeSeriesGeneratorData,
    close_timer: &CloseTimer,
) -> Vec<IngestFrame> {
    let id = policy.id;
    match frame {
        TimeSeriesGeneratorData::ReplayEnd { .. } => {
            // The replay end is not an event: it neither counts nor moves the
            // stream's watermark.
            if !windows.replay_end(index, Instant::now()) {
                warn!(
                    policy_id = id,
                    "Skipping a second replay-end frame on a stream of policy {id}"
                );
            }
            Vec::new()
        }
        TimeSeriesGeneratorData::Event { record, timestamp } => {
            // Every received event moves the watermark, whether or not it is
            // then counted.
            windows.receive(index, timestamp, Instant::now());
            let mut written = windows.close_due(&close_timer.pass_clock());
            let Ok(event) = Event::try_new(record_type, &record) else {
                warn!(
                    "Failed to deserialize raw_event for raw event kind: {:?}",
                    policy.raw_event_kind
                );
                return written;
            };
            match windows.add(index, timestamp, &event) {
                Ok(series) => written.extend(series),
                Err(e) => warn!("Failed to generate time series: {}", e),
            }
            written
        }
    }
}

/// Starts reading a stream bound to `policy`, whose frames the runner then
/// takes from the end of `frames`.
fn bind_stream(
    recv: RecvStream,
    readers: &mut JoinSet<()>,
    frames: &mut Vec<Option<mpsc::Receiver<TimeSeriesGeneratorData>>>,
    policy: &TimeSeriesGenerationPolicy,
) {
    let (frame_send, frame_recv) = mpsc::channel(1);
    readers.spawn(read_generator_frames(recv, frame_send));
    frames.push(Some(frame_recv));
    info!(
        "Raw event {:?} stream {} of {} of policy {} has been connected",
        policy.raw_event_kind,
        frames.len(),
        policy.sensors.len(),
        policy.id,
    );
}

/// Warns if a stream of policy `id` has not opened or is still replaying, as
/// either holds the policy's windows open.
fn warn_if_stalled(windows: &WindowBuilder, id: u32, expected: usize) {
    let (unopened, replaying) = windows.stall_counts();
    if unopened > 0 || replaying > 0 {
        warn!(
            policy_id = id,
            unopened,
            replaying,
            "Policy {id} holds its windows open: {unopened} of its {expected} streams have not \
             opened and {replaying} opened streams are still replaying"
        );
    }
}

/// Runs one policy over the generator streams of one request, one per sensor.
/// Spawned when the request is sent, it takes each inbound stream the
/// dispatcher binds to the request, builds the policy's windows from the events
/// of all its streams, closes them as its streams pass them, and writes them.
/// It reacts to per-policy deletion (`policy_token`), to the Publish
/// connection being replaced (`connection_token`) and to global cancellation,
/// and follows changes of the policy's internal network from the next window
/// boundary on.
///
/// Shutdown, deletion and a replaced connection stop every stream and drop the
/// windows not yet closed without writing them: they are not complete, and the
/// resume rebuilds them from the events Giganto stores.
///
/// A stream that ends passes no further window, so the policy's windows stop
/// closing until the next request. Reconnection is driven by `conn.closed()`
/// in `publish_connection_control` and by `accept_uni()` in the dispatcher,
/// both of which observe genuine connection failures directly. Forcing a
/// reconnect from a single stream's end would race-kill any sibling streams in
/// flight.
// One select loop over every source a runner reacts to keeps their priority
// order visible in one place.
#[allow(clippy::too_many_lines)]
async fn run_policy(
    state: StreamPolicy,
    mut streams: mpsc::UnboundedReceiver<RecvStream>,
    sender: Sender<IngestFrame>,
    connection_token: CancellationToken,
    coordinator: CancellationCoordinator,
    close_timer: CloseTimer,
) -> Result<()> {
    let run = run_start(&state);
    let StreamPolicy {
        policy,
        token: policy_token,
        mut networks,
        ..
    } = state;
    let id = policy.id;
    let record_type = stream_record(policy.raw_event_kind)?;
    let expected = policy.sensors.len();
    let mut windows = WindowBuilder::try_new(&policy, run, expected)?;
    let mut readers = JoinSet::new();
    // The frames of each opened stream, by stream index; `None` once ended.
    let mut frames: Vec<Option<mpsc::Receiver<TimeSeriesGeneratorData>>> =
        Vec::with_capacity(expected);

    let result = async {
        let mut check = interval(close_timer.check_interval);
        check.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut stall = interval_at(
            Instant::now() + close_timer.stall_warning,
            close_timer.stall_warning,
        );
        stall.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut withdrawn = false;
        let mut networks_open = true;
        let mut first = 0;
        loop {
            tokio::select! {
                biased;
                () = coordinator.cancelled() => {
                    info!("Runner for policy {id} shutting down");
                    return Ok(());
                }
                () = policy_token.cancelled() => {
                    info!("Policy {id} deleted, stopping its runner");
                    return Ok(());
                }
                () = connection_token.cancelled() => {
                    info!("Runner for policy {id} stopping; publish connection replaced");
                    return Ok(());
                }
                // Before the frames, so that streams that keep delivering
                // frames cannot postpone the warning about the others.
                _ = stall.tick() => warn_if_stalled(&windows, id, expected),
                // Before the frames, so that a changed network takes effect
                // from the boundary its arrival sets.
                changed = networks.changed(), if networks_open => {
                    if changed.is_err() {
                        // The policy was removed; its token stops the runner.
                        networks_open = false;
                        continue;
                    }
                    let changed = networks.borrow_and_update().clone();
                    info!(policy_id = id, "Policy {id} received a changed internal network");
                    windows.change_networks(changed);
                }
                recv = streams.recv(), if !withdrawn && frames.len() < expected => {
                    let Some(recv) = recv else {
                        withdrawn = true;
                        continue;
                    };
                    if windows.open_stream().is_some() {
                        bind_stream(recv, &mut readers, &mut frames, &policy);
                    }
                }
                (index, frame) = next_frame(&mut frames, &windows, first) => {
                    first = index.wrapping_add(1);
                    match frame {
                        None => {
                            if let Some(ended) = frames.get_mut(index) {
                                *ended = None;
                            }
                            windows.end_stream(index, &close_timer.pass_clock());
                            info!("A stream of policy {id} ended");
                            if frames.len() == expected && frames.iter().all(Option::is_none) {
                                info!("Every stream of policy {id} ended");
                                return Ok(());
                            }
                        }
                        Some(frame) => {
                            let written = take_frame(
                                &mut windows,
                                &policy,
                                record_type,
                                index,
                                frame,
                                &close_timer,
                            );
                            for series in written {
                                write_window(&sender, series.of_run(&policy_token)).await?;
                            }
                        }
                    }
                }
                _ = check.tick() => {
                    for series in windows.close_due(&close_timer.pass_clock()) {
                        write_window(&sender, series.of_run(&policy_token)).await?;
                    }
                }
            }
        }
    }
    .await;
    // Stopping the readers drops their streams, which stops them.
    readers.shutdown().await;
    result
}

/// Returns how the run of the request `state` was taken for starts.
fn run_start(state: &StreamPolicy) -> RunStart {
    RunStart {
        start: state.start,
        resumed: state.resumed,
        generation: state.generation,
    }
}

/// Hands an ingest frame to the ingest control, which queues it to the
/// policy's ingest sender. Frames never bypass the control: one written
/// directly to a cached sender could overtake an earlier one still queued
/// there.
async fn write_window(send_channel: &Sender<IngestFrame>, series: IngestFrame) -> Result<()> {
    send_channel.send(series).await?;
    Ok(())
}

/// Queues `series` to its policy's ingest sender. Returns the series back when
/// the policy has no sender, or its sender closed with a deleted policy, a
/// replaced ingest connection or shutdown, or stops with a replaced request,
/// so that the caller starts one.
///
/// The ingest control takes every window in the order its policy runner wrote
/// it, and queues it here before it takes the next. A corrected window thus
/// follows the write it replaces on the same QUIC stream; a second sender
/// would carry it on another stream, which Giganto could store first.
async fn queue_to_ingest_sender(series: IngestFrame) -> Result<(), IngestFrame> {
    // Clone the sender out of the lock to avoid holding the RwLock read
    // guard across an await point.
    let cached = INGEST_CHANNEL
        .read()
        .await
        .get(&series.policy_id())
        .map(|queue| (queue.frames.clone(), queue.run.clone()));
    let Some((sender, run)) = cached else {
        return Err(series);
    };
    if run.is_cancelled() {
        // The sender of a replaced request can still be writing, its queue
        // still installed, but drops whatever is queued once it sees its
        // token. A row of the next run queued there would be lost, and the
        // window's marker, starting a sender of its own, stored without it.
        // Closing the queue lets nothing more in; the caller then starts the
        // next run's sender, whose queue replaces this one and which writes
        // only once Giganto has stored what this sender is still writing.
        sender.close();
        return Err(series);
    }
    sender
        .send(series)
        .await
        .map_err(|async_channel::SendError(series)| series)
}

/// Installs a new queue as the ingest sender of policy `policy_id`, which
/// stops on `run`, replacing a closed one. The ingest control installs it
/// before it takes the next window, so that window finds it.
///
/// The queue it replaces belongs to a sender that is stopping, but whose
/// last writes Giganto may not have stored yet. They are on another QUIC
/// stream, and Giganto keeps the order of one stream only, so the new sender
/// waits for them (`previous`) before it writes: an old-generation row stored
/// after the new run's row would replace it under a marker that counts it.
async fn register_ingest_queue(policy_id: u32, run: CancellationToken) -> QueueRegistration {
    let (send_channel, recv_channel) =
        async_channel::bounded::<IngestFrame>(TIME_SERIES_CHANNEL_SIZE);
    let stored = CancellationToken::new();
    let mut map = INGEST_CHANNEL.write().await;
    let previous = map
        .get(&policy_id)
        .map(|replaced| replaced.stored.clone())
        .filter(|previous| !previous.is_cancelled());
    map.insert(
        policy_id,
        IngestQueue {
            frames: send_channel,
            run,
            stored: stored.clone(),
            previous: previous.clone(),
        },
    );
    drop(map);
    QueueRegistration {
        frames: recv_channel,
        stored,
        previous,
    }
}

/// Lets every policy's ingest sender on `connection`, which a reconnect is
/// about to replace, write what is queued and finish its stream, and waits
/// until Giganto has stored what each sender and the one it replaced wrote.
///
/// Giganto keeps the order of one stream only, and the policy's next writes
/// go on a stream of the next connection. Without this wait a frame Giganto
/// received here but had not stored yet could be stored after the next run's
/// row and marker, and an old-generation row would replace the row the
/// marker counts. Giganto finishes its side of a stream only after storing
/// every frame of it, which is what the senders' `stored` tokens wait for.
///
/// The wait has no deadline while `connection` is up: giving up would let an
/// old-generation frame Giganto still holds be stored after the next run's
/// rows. It warns every [`STORE_BEFORE_RECONNECT_WARN_INTERVAL`] instead, and
/// ends early only when `connection` closes, since Giganto can then tell
/// nothing more about the frames it received on it, and at shutdown.
async fn store_before_reconnect(connection: &Connection, coordinator: &CancellationCoordinator) {
    let pending: Vec<CancellationToken> = {
        let map = INGEST_CHANNEL.read().await;
        for queue in map.values() {
            queue.frames.close();
        }
        map.values()
            .flat_map(|queue| std::iter::once(&queue.stored).chain(queue.previous.as_ref()))
            .filter(|stored| !stored.is_cancelled())
            .cloned()
            .collect()
    };
    if pending.is_empty() {
        return;
    }
    let all_stored = async {
        for stored in &pending {
            stored.cancelled().await;
        }
    };
    tokio::pin!(all_stored);
    let closed = connection.closed();
    tokio::pin!(closed);
    let mut waited = Duration::ZERO;
    loop {
        tokio::select! {
            biased;
            () = coordinator.cancelled() => return,
            () = &mut all_stored => return,
            error = &mut closed => {
                warn!(
                    "Ingest connection closed before Giganto stored every time series written on it: {error}"
                );
                return;
            }
            () = sleep(STORE_BEFORE_RECONNECT_WARN_INTERVAL) => {
                waited = waited.saturating_add(STORE_BEFORE_RECONNECT_WARN_INTERVAL);
                warn!(
                    "Giganto has not stored every time series written on the ingest connection being replaced after {waited:?}; still waiting before reconnecting"
                );
            }
        }
    }
}

/// Closes every policy's ingest queue. Each sender writes what is queued and
/// then finishes its stream.
async fn close_ingest_queues() {
    for queue in INGEST_CHANNEL.read().await.values() {
        queue.frames.close();
    }
}

/// Clears all cached senders from the global ingest channel map.
/// Should be called after top-level drain has completed to ensure no
/// stale senders survive into a subsequent run.
pub(crate) async fn clear_ingest_channel() {
    INGEST_CHANNEL.write().await.clear();
}

/// Resolves the current `CancellationToken` for a dequeued series by the id
/// of the policy it belongs to. Returns `None` when the policy is no longer
/// active, signalling the caller to drop the series instead of spawning a
/// sender task for an inactive policy.
async fn policy_token_for_series(
    policy_handle: &PolicyHandle,
    policy_id: u32,
) -> Option<CancellationToken> {
    policy_handle
        .get_policy_with_token(policy_id)
        .await
        .map(|(_, token)| token)
}

/// Starts the ingest sender of the policy `series` belongs to, with `series`
/// as its first write. Its queue is installed before this returns.
#[allow(clippy::too_many_arguments)]
async fn spawn_time_series_sender(
    coordinator: &CancellationCoordinator,
    connection: Arc<Connection>,
    series: IngestFrame,
    policy_token: CancellationToken,
    connection_lifecycle: ConnectionLifecycle,
    policy_handle: PolicyHandle,
    connection_notify: Arc<Notify>,
) {
    let policy_id = series.policy_id();
    let queue = register_ingest_queue(policy_id, policy_token.clone()).await;
    let task_coordinator = coordinator.clone();
    let connection_tasks = connection_lifecycle.tasks.clone();
    let tracked = connection_tasks.track_future(async move {
        // The sender logs its failure and signals the reconnect itself,
        // before it waits for its writes to be stored.
        let _ = send_time_series(
            connection,
            series,
            queue,
            policy_token,
            connection_lifecycle,
            policy_handle,
            connection_notify,
            task_coordinator,
        )
        .await;
    });
    coordinator.tracker().spawn(tracked);
}

/// Writes `series` and then every frame queued to `queue`, the queue
/// [`register_ingest_queue`] installed for the policy, on one QUIC stream.
///
/// It writes nothing before Giganto has stored what the sender it replaced
/// wrote, and it removes its queue only once Giganto has stored what it wrote
/// itself and what that sender wrote, so that the policy's writes are stored
/// in order across senders. A failure is logged and signals a reconnect.
#[allow(clippy::too_many_arguments)]
async fn send_time_series(
    connection: Arc<Connection>,
    series: IngestFrame,
    queue: QueueRegistration,
    policy_token: CancellationToken,
    connection_lifecycle: ConnectionLifecycle,
    policy_handle: PolicyHandle,
    connection_notify: Arc<Notify>,
    coordinator: CancellationCoordinator,
) -> Result<()> {
    let policy_id = series.policy_id();
    let QueueRegistration {
        frames: recv_channel,
        stored,
        previous,
    } = queue;
    let error_notify = connection_notify.clone();
    // Kept through the cleanup below: a sender that ends before the one it
    // replaced is stored must still hold that barrier.
    let predecessor = previous.clone();
    // Moved to the ACK receiver once it runs; dropped here otherwise, as
    // nothing this sender wrote is then waiting to be stored.
    let mut stored_guard = Some(stored.clone().drop_guard());

    let result = async {
        if let Some(previous) = previous {
            tokio::select! {
                biased;
                () = connection_lifecycle.token.cancelled() => return Ok(()),
                () = previous.cancelled() => {}
                () = sleep(PREVIOUS_STREAM_STORE_TIMEOUT) => bail!(
                    "the previous ingest stream of policy {policy_id} was not stored within {} seconds",
                    PREVIOUS_STREAM_STORE_TIMEOUT.as_secs(),
                ),
            }
            // The run may have stopped while this sender waited.
            if series.run_stopped() {
                return Ok(());
            }
        }

        let Ok((mut series_sender, series_receiver)) = connection.open_bi().await else {
            bail!("Failed to open bi-direction QUIC channel");
        };

        // First data transmission (record type + series data)
        send_record_header(&mut series_sender, RawEventKind::PeriodicTimeSeries).await?;

        send_ingest_frame(&mut series_sender, &series).await?;

        // Receive start time of giganto last saved time series.
        let receiver = connection_lifecycle
            .tasks
            .track_future(receive_time_series_timestamp(
                series_receiver,
                policy_id,
                policy_token.clone(),
                connection_lifecycle.token.clone(),
                policy_handle,
                connection_notify,
                stored_guard.take(),
            ));
        coordinator.tracker().spawn(receiver);

        // Data transmission after the first time (only series data).
        // `policy_token` fires on deletion so this sender exits promptly.
        // Cleanup below closes its channel and removes the cached sender.
        loop {
            tokio::select! {
                biased;
                () = coordinator.cancelled() => {
                    // Keep taking windows until the ingest control's drain
                    // closes this queue: a correction it still holds must
                    // follow the window it replaces on this stream. A
                    // replaced or closed connection ends the drain instead.
                    loop {
                        tokio::select! {
                            biased;
                            result = recv_channel.recv() => {
                                let Ok(series) = result else { break };
                                send_ingest_frame(&mut series_sender, &series).await?;
                            }
                            () = connection_lifecycle.token.cancelled() => break,
                            _ = connection.closed() => break,
                        }
                    }
                    info!("send_time_series drained and shutting down");
                    break;
                }
                () = policy_token.cancelled() => {
                    info!(policy_id, "send_time_series stopping; policy deleted");
                    break;
                }
                () = connection_lifecycle.token.cancelled() => {
                    info!(
                        policy_id,
                        "send_time_series stopping; ingest connection replaced"
                    );
                    break;
                }
                result = recv_channel.recv() => {
                    match result {
                        Ok(series) => {
                            send_ingest_frame(&mut series_sender, &series).await?;
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

    // Always clean up on both success and error paths. Closing our channel
    // marks this instance as finished.
    recv_channel.close();
    if let Err(e) = &result {
        // Signalled before the waits below, so that the reconnect starts
        // now and waits for the same writes through this sender's entry.
        warn!(policy_id, "Time-series sender failed: {e:#}");
        error_notify.notify_waiters();
    }
    release_ingest_queue(policy_id, predecessor, stored_guard, stored).await;

    result
}

/// Removes the finished ingest queue of policy `policy_id` once Giganto has
/// stored what its sender wrote (`stored`, held by `stored_guard` until then
/// unless the ACK receiver took it) and what the sender it replaced wrote
/// (`predecessor`).
///
/// The entry stays until then, so that a sender replacing this one, and a
/// reconnect's [`store_before_reconnect`], find it and wait. A sender that
/// ended before its predecessor was stored (its wait timed out, or its
/// connection was replaced) still stands for that predecessor's writes, as
/// the predecessor's own entry was replaced by this one. The predecessor's
/// `stored` is cancelled only once Giganto has stored its writes or its
/// connection is gone. The entry is removed only if it is still a finished
/// one, not that of a newer sender registered by a replaced request or a
/// reconnect.
async fn release_ingest_queue(
    policy_id: u32,
    predecessor: Option<CancellationToken>,
    stored_guard: Option<DropGuard>,
    stored: CancellationToken,
) {
    if let Some(predecessor) = predecessor {
        predecessor.cancelled().await;
    }
    drop(stored_guard);
    stored.cancelled().await;
    let mut map = INGEST_CHANNEL.write().await;
    if let Some(existing) = map.get(&policy_id)
        && existing.frames.is_closed()
        && existing.stored.is_cancelled()
    {
        map.remove(&policy_id);
    }
}

/// Sends every row of `frame`, keyed by its window start in nanoseconds, in
/// one time-series ingest frame, which Giganto stores with one write.
async fn send_ingest_frame(series_sender: &mut SendStream, frame: &IngestFrame) -> Result<()> {
    let events = frame
        .rows()
        .iter()
        .map(|row| {
            let timestamp_nanos = row
                .start_secs
                .checked_mul(time_series::SECOND_TO_NANO)
                .unwrap_or(i64::MAX);
            Ok((timestamp_nanos, bincode::serialize(row)?))
        })
        .collect::<Result<Vec<_>>>()?;
    send_event_in_batch(series_sender, &events).await
}

async fn send_event_in_batch(send: &mut SendStream, events: &[(i64, Vec<u8>)]) -> Result<()> {
    let buf = bincode::serialize(&events)?;
    send_raw(send, &buf).await?;
    Ok(())
}

/// Records each ACK of the ingest stream of policy `policy_id` against that
/// policy's checkpoint, and drops `stored` once Giganto has finished its side
/// of the stream, which it does only after storing every frame of it.
///
/// Once `policy_token` is cancelled the ACKs are no longer recorded: they are
/// of a run that stopped. The stream is still read to its end, so that the
/// sender replacing this one waits for its writes to be stored.
async fn receive_time_series_timestamp(
    mut series_receiver: RecvStream,
    policy_id: u32,
    policy_token: CancellationToken,
    connection_token: CancellationToken,
    policy_handle: PolicyHandle,
    connection_notify: Arc<Notify>,
    stored: Option<DropGuard>,
) {
    let mut recording = true;
    loop {
        // One read per ACK, kept across the policy token firing: dropping a
        // read part-way would lose the bytes it already took.
        let read = receive_ack_timestamp(&mut series_receiver);
        tokio::pin!(read);
        let result = loop {
            tokio::select! {
                biased;
                () = connection_token.cancelled() => {
                    info!(
                        policy_id,
                        "receive_time_series_timestamp stopping; ingest connection replaced"
                    );
                    return;
                }
                () = policy_token.cancelled(), if recording => {
                    // The policy actor ignores ACKs for inactive policies,
                    // but a restarted policy is active with a new run.
                    info!(
                        policy_id,
                        "receive_time_series_timestamp no longer recording; run stopped"
                    );
                    recording = false;
                }
                result = &mut read => break result,
            }
        };
        match result {
            Ok(timestamp) => {
                if recording
                    && policy_handle
                        .record_ack(policy_id, timestamp)
                        .await
                        .is_err()
                {
                    warn!(policy_id, "Policy actor closed while recording an ACK");
                    return;
                }
            }
            Err(RecvError::ReadError(quinn::ReadExactError::FinishedEarly(_))) => {
                break;
            }
            Err(e) if recording => {
                warn!(policy_id, "receive_time_series_timestamp error: {e}");
                connection_notify.notify_waiters();
                break;
            }
            Err(e) => {
                info!(
                    policy_id,
                    "receive_time_series_timestamp of a stopped run ended: {e}"
                );
                break;
            }
        }
    }
    drop(stored);
}
