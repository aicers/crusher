use std::collections::BTreeSet;
use std::future::Future;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use anyhow::{Result, bail};
use async_trait::async_trait;
use review_protocol::{
    AgentInfo,
    request::Handler as _,
    session::{
        AgentConnector, AgentHandle, AgentIncoming, AgentRunError, AgentTransportOptions,
        ClientPemError, CloseReason, SessionError, SessionOptions, TransportCloseKind,
        TransportFailure, client_config_from_pem,
    },
    types::{Status, TimeSeriesGenerationPolicy},
};
use tokio::{
    sync::{Mutex, Notify},
    time::{Duration, sleep},
};
use tracing::{info, warn};

use crate::cancellation::CancellationCoordinator;
use crate::client::{SERVER_RETRY_INTERVAL, SharedTlsBytes};
use crate::policy::PolicyHandle;

#[derive(Debug, PartialEq, Eq)]
enum ConnectErrorDisposition {
    Retry,
    InvalidPeerCertificate,
    Other,
}

/// The Manager answered a configuration request without a configuration, as
/// it does before this instance is configured (`… unregistered`). The main
/// loop treats this as a normal wait.
#[derive(Debug)]
pub(crate) struct ConfigUnavailable(pub(crate) SessionError);

impl std::fmt::Display for ConfigUnavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            SessionError::RemoteRejection(reason) => formatter.write_str(reason),
            error => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ConfigUnavailable {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// Separates the Manager's refusal to supply a configuration from a failed
/// exchange.
fn classify_config_error(error: SessionError) -> anyhow::Error {
    if matches!(error, SessionError::RemoteRejection(_)) {
        anyhow::Error::new(ConfigUnavailable(error))
    } else {
        anyhow::Error::new(error).context("Failed to get the configuration from the Manager server")
    }
}

/// Tells the main loop how `enter_idle_mode` returned so it can decide
/// whether to refresh the Giganto TLS material before the next rerun,
/// or to exit entirely after a SIGINT/SIGTERM was observed while idle.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum IdleExitReason {
    /// The idle wait ended either because the Manager reconnected or
    /// because a configuration reload was requested. No TLS refresh is
    /// required.
    Resumed,
    /// A repository-level TLS reload was requested (for example, via
    /// `SIGHUP`) while the client was idle. The caller should rebuild the
    /// shared Giganto endpoint from fresh TLS material before the next
    /// remote-mode rerun.
    TlsReload,
    /// A SIGINT/SIGTERM-style shutdown was requested while the client
    /// was idle. The caller should terminate the main loop instead of
    /// scheduling another remote-mode rerun.
    Shutdown,
}

fn retryable_session_error(error: &SessionError) -> bool {
    let SessionError::Transport { source, .. } = error else {
        return false;
    };
    matches!(
        source,
        TransportFailure::Closed {
            reason: CloseReason::Application { .. }
                | CloseReason::Transport(
                    TransportCloseKind::Crypto { .. }
                        | TransportCloseKind::IdleTimeout
                        | TransportCloseKind::Reset
                        | TransportCloseKind::Other
                ),
            ..
        } | TransportFailure::StreamFailed(_)
            | TransportFailure::Other(_)
    )
}

/// Returns whether a failed Manager exchange calls for a health-check-only wait.
pub(crate) fn needs_health_check(error: &anyhow::Error) -> bool {
    if let Some(error) = error.downcast_ref::<SessionError>() {
        return retryable_session_error(error);
    }
    match error.downcast_ref::<AgentRunError>() {
        Some(AgentRunError::Session(error) | AgentRunError::ResponseWrite(error)) => {
            retryable_session_error(error)
        }
        _ => false,
    }
}

fn classify_connect_error(error: &anyhow::Error) -> ConnectErrorDisposition {
    if error.downcast_ref::<ClientPemError>().is_some() {
        ConnectErrorDisposition::InvalidPeerCertificate
    } else if needs_health_check(error) {
        ConnectErrorDisposition::Retry
    } else {
        ConnectErrorDisposition::Other
    }
}

/// Shared storage for the active manager/control connection.
///
/// The connection lives behind an `Arc<Mutex<...>>` so that cloning a
/// [`Client`] (for example, to pass into a spawned task) preserves
/// access to the same underlying session.
/// That way the connection survives the common `run()` shutdown ->
/// respawn cycle triggered by SIGHUP: the spawned task exits, but the
/// retained handle in `main` keeps the connection alive so the next
/// reconnect attempt reuses it instead of tearing down the manager/
/// control path.
type SharedConnection = Arc<Mutex<ConnectionSlot>>;

/// The installed manager connection and the ID `connect()` gave it.
///
/// Each newly installed connection gets the next ID, so a caller can tell a
/// reconnect from a reuse of the same connection.
#[derive(Default)]
struct ConnectionSlot {
    connection: Option<ManagerConnection>,
    id: u64,
}

/// Keeps the request handle paired with its connection's unique incoming owner.
/// The mutex preserves that owner across cancellation and run-task respawns.
#[derive(Clone)]
struct ManagerConnection {
    handle: AgentHandle,
    incoming: Arc<Mutex<AgentIncoming>>,
}

#[derive(Clone)]
pub(crate) struct Client {
    server_address: SocketAddr,
    server_name: String,
    connection: SharedConnection,
    tls_bytes: SharedTlsBytes,
    config_reload: Arc<Notify>,
    status: Status,
    pub(crate) policy_handle: Option<PolicyHandle>,
}

impl Client {
    pub(crate) fn new(
        server_address: SocketAddr,
        server_name: String,
        tls_bytes: SharedTlsBytes,
        config_reload: Arc<Notify>,
    ) -> Self {
        Client {
            server_address,
            server_name,
            connection: Arc::new(Mutex::new(ConnectionSlot::default())),
            tls_bytes,
            config_reload,
            status: Status::Ready,
            policy_handle: None,
        }
    }

    pub(crate) fn set_policy_handle(&mut self, handle: PolicyHandle) {
        self.policy_handle = Some(handle);
    }

    pub(crate) async fn run(&mut self, coordinator: CancellationCoordinator) -> Result<()> {
        run_until_cancelled(coordinator, self.handle_incoming()).await
    }

    /// Pulls the complete policy list and applies it as a replacement.
    ///
    /// Returns whether the list was applied. A failed pull changes nothing, so
    /// every policy and checkpoint is kept.
    async fn sync_time_series_generation_policies(&mut self, connection: &AgentHandle) -> bool {
        match connection.get_time_series_generation_policy_list().await {
            Ok(policies) => {
                info!(
                    "Applying {} time-series generation policies from the Manager",
                    policies.len()
                );
                if let Err(e) = self.time_series_generation_policy_list(&policies).await {
                    warn!("Failed to apply time-series generation policies from the Manager: {e}");
                    return false;
                }
                true
            }
            Err(e) => {
                warn!("Failed to retrieve time-series generation policy list: {e}");
                false
            }
        }
    }

    async fn handle_incoming(&mut self) -> Result<()> {
        // The connection whose policy list was last applied. A change made
        // while Crusher was disconnected arrives only through a pull, so each
        // new connection is pulled before its first push is accepted. A failed
        // pull is retried before the next push on the same connection.
        let mut synced = None;
        loop {
            match self.connect_with_id().await {
                Ok((connection, id)) => {
                    if synced != Some(id)
                        && self
                            .sync_time_series_generation_policies(&connection.handle)
                            .await
                    {
                        synced = Some(id);
                    }
                    // The incoming guard intentionally spans acceptance and command handling.
                    match connection.incoming.lock().await.accept().await {
                        Ok(stream) => {
                            stream.run(self, |_| Ok(())).await?;
                        }
                        Err(e) => {
                            warn!("Failed to accept bidirectional stream: {:?}, retrying", e);
                            sleep(Duration::from_secs(SERVER_RETRY_INTERVAL)).await;
                        }
                    }
                }
                Err(e) => {
                    match classify_connect_error(&e) {
                        ConnectErrorDisposition::Retry => {
                            warn!(
                                "Retrying connection to {} in {} seconds",
                                self.server_address, SERVER_RETRY_INTERVAL,
                            );
                            sleep(Duration::from_secs(SERVER_RETRY_INTERVAL)).await;
                            continue;
                        }
                        ConnectErrorDisposition::InvalidPeerCertificate => {
                            bail!("Invalid peer certificate contents");
                        }
                        ConnectErrorDisposition::Other => {}
                    }
                    bail!("Failed to connect to {}: {:?}", self.server_address, e);
                }
            }
        }
    }

    async fn connect(&self) -> Result<AgentHandle> {
        self.connect_with_id()
            .await
            .map(|(connection, _)| connection.handle)
    }

    /// Returns the live connection, establishing one if needed, with its ID.
    async fn connect_with_id(&self) -> Result<(ManagerConnection, u64)> {
        // Fast path: if a live connection is already installed, return a
        // clone without holding the mutex across an async boundary.
        {
            let guard = self.connection.lock().await;
            if let Some(conn) = guard.connection.as_ref()
                && conn.handle.close_reason().is_none()
            {
                return Ok((conn.clone(), guard.id));
            }
        }

        // Each attempt uses a fresh snapshot, so rotation affects the next
        // reconnect while leaving the installed session alive.
        let tls = self.tls_bytes.snapshot();
        let roots = tls.ca_certs.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let tls = client_config_from_pem(&tls.cert, &tls.key, &roots)?;
        let address = SocketAddr::new(
            match self.server_address.ip() {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            },
            0,
        );
        let connector = AgentConnector::bind(
            address,
            tls,
            AgentTransportOptions::default(),
            SessionOptions::legacy_compatible(),
        )?;
        let agent = AgentInfo {
            agent_name: env!("CARGO_PKG_NAME").to_string(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            protocol_version: review_protocol::PROTOCOL_VERSION.to_string(),
            status: self.status,
            addr: address,
            capabilities: BTreeSet::new(),
            active_trust_epoch: None,
            manifest_formats: None,
            provisioning_fingerprint: None,
            audit_health: None,
        };
        let (handle, incoming) = connector
            .connect(self.server_address, &self.server_name, &agent)
            .await?;
        let new_conn = ManagerConnection {
            handle,
            incoming: Arc::new(Mutex::new(incoming)),
        };

        // Reacquire the lock and install the new connection only if
        // another caller has not already installed a live one.
        let mut guard = self.connection.lock().await;
        if let Some(existing) = guard.connection.as_ref()
            && existing.handle.close_reason().is_none()
        {
            return Ok((existing.clone(), guard.id));
        }
        guard.connection = Some(new_conn.clone());
        guard.id += 1;
        info!(
            "Connection established to the manager server {}",
            self.server_address
        );
        Ok((new_conn, guard.id))
    }

    /// Fetches this instance's configuration from the Manager.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigUnavailable`] if the Manager answers without a
    /// configuration, as it does before this instance is configured, or
    /// another error if the Manager cannot be reached or the request fails.
    pub(crate) async fn get_config(&mut self) -> Result<String> {
        info!("Fetching a configuration");
        let connection = self.connect().await?;
        connection.get_config().await.map_err(classify_config_error)
    }

    /// Enters the idle mode when a recoverable error occurs.
    ///
    /// If `health_check` is set to `true`, the method performs a connection check and returns immediately.
    ///
    /// For instance, if Crusher starts in remote mode before the Manager server is available,
    /// it should not wait for an `update_config` request. Instead, it can simply check the connection
    /// and retry as needed.
    ///
    /// While idle, the method also watches `tls_reload` so that a `SIGHUP`-
    /// driven TLS reload can wake the daemon and drive the next remote-mode
    /// rerun even when the Manager path is healthy-but-quiet, and watches
    /// `shutdown` so a SIGINT/SIGTERM observed during idle is reported back
    /// to the main loop instead of being absorbed.
    pub(crate) async fn enter_idle_mode(
        &mut self,
        health_check: bool,
        tls_reload: Arc<Notify>,
        shutdown: Arc<Notify>,
    ) -> IdleExitReason {
        info!("Entering idle mode");
        self.status = Status::Idle;
        let config_reload = self.config_reload.clone();
        let reason = tokio::select! {
            () = async {
                loop {
                    match self.try_connect(health_check).await {
                        Ok(()) => {
                            info!("The Manager server is now online");
                            return
                        },
                        Err(e) => {
                            info!("Connection attempt failed: {e}, retrying");
                            sleep(Duration::from_secs(SERVER_RETRY_INTERVAL)).await;
                        },
                    }
                }} => IdleExitReason::Resumed,
            () = config_reload.notified() => IdleExitReason::Resumed,
            () = tls_reload.notified() => IdleExitReason::TlsReload,
            () = shutdown.notified() => IdleExitReason::Shutdown,
        };
        self.status = Status::Ready;
        reason
    }

    #[cfg(test)]
    async fn enter_idle_mode_with_try_connect<F, Fut>(
        &mut self,
        health_check: bool,
        tls_reload: Arc<Notify>,
        shutdown: Arc<Notify>,
        mut try_connect: F,
    ) -> IdleExitReason
    where
        F: for<'a> FnMut(&'a mut Client, bool) -> Fut,
        Fut: Future<Output = Result<()>> + Send,
    {
        info!("Entering idle mode");
        self.status = Status::Idle;
        let config_reload = self.config_reload.clone();
        let reason = tokio::select! {
            () = async {
                loop {
                    match try_connect(self, health_check).await {
                        Ok(()) => {
                            info!("The Manager server is now online");
                            return
                        },
                        Err(e) => {
                            info!("Connection attempt failed: {e}, retrying");
                            sleep(Duration::from_secs(SERVER_RETRY_INTERVAL)).await;
                        },
                    }
                }} => IdleExitReason::Resumed,
            () = config_reload.notified() => IdleExitReason::Resumed,
            () = tls_reload.notified() => IdleExitReason::TlsReload,
            () = shutdown.notified() => IdleExitReason::Shutdown,
        };
        self.status = Status::Ready;
        reason
    }

    async fn try_connect(&mut self, health_check: bool) -> Result<()> {
        let (connection, _) = self.connect_with_id().await?;
        if health_check {
            return Ok(());
        }
        let stream = connection.incoming.lock().await.accept().await?;
        let mut idle_mode_handler = IdleModeHandler {
            config_reload: self.config_reload.clone(),
        };
        stream.run(&mut idle_mode_handler, |_| Ok(())).await?;
        Ok(())
    }
}

async fn run_until_cancelled<F>(coordinator: CancellationCoordinator, incoming: F) -> Result<()>
where
    F: Future<Output = Result<()>>,
{
    tokio::select! {
        biased;
        () = coordinator.cancelled() => {
            info!("Shutting down request handler");
        }
        Err(e) = incoming => {
            bail!(e);
        }
    };
    Ok(())
}

#[async_trait]
impl review_protocol::request::Handler for Client {
    async fn time_series_generation_policy_list(
        &mut self,
        policies: &[TimeSeriesGenerationPolicy],
    ) -> Result<(), String> {
        let handle = self
            .policy_handle
            .as_ref()
            .ok_or("policy actor not initialized")?;
        handle.replace_policies(policies.to_vec()).await
    }

    async fn delete_time_series_generation_policy(
        &mut self,
        policy_ids: &[u32],
    ) -> Result<(), String> {
        let handle = self
            .policy_handle
            .as_ref()
            .ok_or("policy actor not initialized")?;
        handle.delete_policies(policy_ids.to_vec()).await
    }

    async fn update_config(&mut self) -> Result<(), String> {
        info!("Configuration update request received");
        self.config_reload.notify_one();
        Ok(())
    }
}

struct IdleModeHandler {
    config_reload: Arc<Notify>,
}

#[async_trait]
impl review_protocol::request::Handler for IdleModeHandler {
    async fn update_config(&mut self) -> Result<(), String> {
        info!("Configuration update request received");
        self.config_reload.notify_one();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::net::{IpAddr, Ipv6Addr, SocketAddr};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;

    use review_protocol::request::Handler;
    use review_protocol::session::{ApplicationCode, ServerHandle, ServerStream};
    use review_protocol::types::{
        CounterpartScope, GroupByUnit, HostNetworkGroup, Measure, RawEventKind,
        TimeSeriesGenerationPolicy,
    };
    use rustls::server::WebPkiClientVerifier;

    use super::*;
    use crate::cancellation::CancellationCoordinator;
    use crate::client::{Certs, TlsBytes};
    use crate::policy::PolicyHandle;
    use crate::test_manager;

    const CERT_PATH: &str = "tests/cert.pem";
    const KEY_PATH: &str = "tests/key.pem";
    const CA_CERT_PATH: &str = "tests/ca_cert.pem";

    /// Creates a test client with a policy actor and default configuration.
    /// Returns the client, checkpoint directory, and the policy handle.
    async fn create_test_client() -> (Client, tempfile::TempDir, PolicyHandle) {
        let dir = tempfile::tempdir().unwrap();
        let config_reload = Arc::new(Notify::new());
        let coordinator = CancellationCoordinator::new();
        let (policy_handle, _actor) =
            crate::policy::spawn_policy_actor(dir.path().join("time_data.json"), &coordinator)
                .await
                .unwrap();

        let client = Client {
            server_address: "127.0.0.1:8080".parse().unwrap(),
            server_name: "test".to_string(),
            connection: Arc::new(Mutex::new(ConnectionSlot::default())),
            tls_bytes: SharedTlsBytes::new(TlsBytes::new(Vec::new(), Vec::new(), Vec::new())),
            config_reload,
            status: Status::Ready,
            policy_handle: Some(policy_handle.clone()),
        };

        (client, dir, policy_handle)
    }

    /// Creates a test time-series generation policy with the given ID.
    fn create_test_policy(id: u32) -> TimeSeriesGenerationPolicy {
        TimeSeriesGenerationPolicy {
            id,
            raw_event_kind: RawEventKind::Conn,
            measure: Measure::Count,
            group_by: None,
            group_by_unit: GroupByUnit::Ip,
            counterpart_scope: CounterpartScope::Any,
            slot_size: Duration::from_mins(1),
            window_size: Duration::from_hours(1),
            utc_offset: 0,
            src_ip: None,
            dst_ip: None,
            sensors: vec!["test_node".to_string()],
            time_series_type: None,
            internal_networks: HostNetworkGroup::default(),
        }
    }

    fn load_test_certs() -> (Vec<u8>, Vec<u8>, Vec<Vec<u8>>, Certs) {
        let cert_pem = fs::read(CERT_PATH).expect("read cert");
        let key_pem = fs::read(KEY_PATH).expect("read key");
        let ca_certs_pem = vec![fs::read(CA_CERT_PATH).expect("read ca cert")];
        let ca_slices = ca_certs_pem.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let certs = Certs::try_new(&cert_pem, &key_pem, &ca_slices).expect("parse certs");
        (cert_pem, key_pem, ca_certs_pem, certs)
    }

    fn create_test_server_config(certs: &Certs) -> Arc<rustls::ServerConfig> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let client_auth = WebPkiClientVerifier::builder_with_provider(
            Arc::new(certs.ca_certs.clone()),
            Arc::clone(&provider),
        )
        .build()
        .expect("build client cert verifier");

        let server_crypto = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("aws-lc-rs supports the default protocol versions")
            .with_client_cert_verifier(client_auth)
            .with_single_cert(certs.certs.clone(), certs.key.clone_key())
            .expect("build server tls config");

        Arc::new(server_crypto)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn node_requests_are_not_supported() {
        let config_reload = Arc::new(Notify::new());
        let mut client = Client::new(
            "127.0.0.1:8080".parse().expect("valid test address"),
            "test".to_string(),
            SharedTlsBytes::new(TlsBytes::new(Vec::new(), Vec::new(), Vec::new())),
            config_reload.clone(),
        );

        // Older managers may still send these requests to a module.
        assert_eq!(client.reboot().await, Err("not supported".to_string()));
        assert_eq!(client.shutdown().await, Err("not supported".to_string()));
        assert_eq!(
            client
                .resource_usage()
                .await
                .expect_err("unsupported usage"),
            "not supported"
        );
        assert_eq!(
            client
                .process_list()
                .await
                .expect_err("unsupported processes"),
            "not supported"
        );

        client
            .update_config()
            .await
            .expect("reload still supported");
        tokio::time::timeout(Duration::from_millis(100), config_reload.notified())
            .await
            .expect("reload notification delivered after unsupported requests");
    }

    // =========================================================================
    // Policy Replacement Tests: `time_series_generation_policy_list()`
    // =========================================================================

    #[tokio::test(flavor = "current_thread")]
    async fn add_policy_duplicate_entries() {
        // Test: Adding the same policy ID twice should only process it once
        let (mut client, _dir, policy_handle) = create_test_client().await;
        let policy = create_test_policy(1);

        // Add the policy first time
        let result = client
            .time_series_generation_policy_list(std::slice::from_ref(&policy))
            .await;
        assert!(result.is_ok());

        // Verify policy was added to active list
        assert_eq!(policy_handle.get_all_policy_ids().len(), 1);
        assert!(policy_handle.get_policy(1).await.is_some());

        // Add the same policy again (duplicate)
        let result = client.time_series_generation_policy_list(&[policy]).await;
        assert!(result.is_ok());

        // Verify still only one policy in active list
        assert_eq!(policy_handle.get_all_policy_ids().len(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn policy_list_replaces_the_active_set() {
        // Test: Each list is the complete set; an absent ID stops.
        let (mut client, _dir, policy_handle) = create_test_client().await;
        let policy1 = create_test_policy(1);
        let policy2 = create_test_policy(2);

        let result = client
            .time_series_generation_policy_list(&[policy1.clone(), policy2.clone()])
            .await;
        assert!(result.is_ok());
        assert_eq!(policy_handle.get_all_policy_ids().len(), 2);
        let token2 = policy_handle.get_policy_token(2).await.unwrap();

        // policy1 is kept, policy2 is absent, and policy3 is new.
        let policy3 = create_test_policy(3);
        let result = client
            .time_series_generation_policy_list(&[policy1, policy3])
            .await;
        assert!(result.is_ok());

        let mut ids = policy_handle.get_all_policy_ids();
        ids.sort_unstable();
        assert_eq!(ids, [1, 3]);
        assert!(token2.is_cancelled());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn add_policy_when_active_set_empty() {
        // Test: Adding the first policy updates the active set.
        let (mut client, _dir, policy_handle) = create_test_client().await;

        // Verify empty initial state
        assert_eq!(policy_handle.get_all_policy_ids(), [] as [u32; 0]);

        let policy = create_test_policy(1);
        let result = client.time_series_generation_policy_list(&[policy]).await;
        assert!(result.is_ok());

        assert_eq!(policy_handle.get_all_policy_ids().len(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn add_policy_rapid_add_remove_add_cycle() {
        // Test: Rapid add/remove/add cycle should work correctly
        let (mut client, _dir, policy_handle) = create_test_client().await;
        let policy = create_test_policy(1);

        // Add policy
        client
            .time_series_generation_policy_list(std::slice::from_ref(&policy))
            .await
            .expect("Success to add policy");
        assert_eq!(policy_handle.get_all_policy_ids().len(), 1);

        // Remove policy
        client
            .delete_time_series_generation_policy(&[1])
            .await
            .expect("Success to remove policy");
        assert_eq!(policy_handle.get_all_policy_ids(), [] as [u32; 0]);

        // Add policy again (should succeed since it was deleted)
        client
            .time_series_generation_policy_list(&[policy])
            .await
            .expect("Success to add policy");
        assert_eq!(policy_handle.get_all_policy_ids().len(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn empty_policy_list_stops_every_policy() {
        let (mut client, _dir, policy_handle) = create_test_client().await;

        let result = client.time_series_generation_policy_list(&[]).await;
        assert!(result.is_ok());
        assert_eq!(policy_handle.get_all_policy_ids(), [] as [u32; 0]);

        client
            .time_series_generation_policy_list(&[create_test_policy(1), create_test_policy(2)])
            .await
            .expect("Success to add policies");
        let result = client.time_series_generation_policy_list(&[]).await;
        assert!(result.is_ok());
        assert_eq!(policy_handle.get_all_policy_ids(), [] as [u32; 0]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn changed_policy_content_replaces_the_stored_policy() {
        let (mut client, _dir, policy_handle) = create_test_client().await;
        let original_policy = create_test_policy(1);

        client
            .time_series_generation_policy_list(std::slice::from_ref(&original_policy))
            .await
            .expect("Success to add policy");
        let old = policy_handle.get_policy_token(1).await.unwrap();

        let mut changed_policy = create_test_policy(1);
        changed_policy.slot_size = Duration::from_secs(30);
        changed_policy.sensors = vec!["updated_node".to_string()];

        client
            .time_series_generation_policy_list(&[changed_policy])
            .await
            .expect("No error or failure");

        assert!(old.is_cancelled());
        let stored = policy_handle.get_policy(1).await.unwrap();
        assert_eq!(stored.slot_size, Duration::from_secs(30));
        assert_eq!(stored.sensors, ["updated_node"]);
    }

    // =========================================================================
    // Policy Deletion Tests: `delete_time_series_generation_policy()`
    // =========================================================================
    #[tokio::test(flavor = "current_thread")]
    async fn delete_policy_multiple_times() {
        // Test: Multiple delete requests remove all requested policies.
        let (mut client, _dir, policy_handle) = create_test_client().await;

        // Add multiple policies first
        let policies: Vec<TimeSeriesGenerationPolicy> = (1..=5).map(create_test_policy).collect();
        client
            .time_series_generation_policy_list(&policies)
            .await
            .expect("Success to add policies");

        // Delete policies one by one
        client
            .delete_time_series_generation_policy(&[1])
            .await
            .expect("Success to delete policy");
        client
            .delete_time_series_generation_policy(&[2])
            .await
            .expect("Success to delete policy");
        client
            .delete_time_series_generation_policy(&[3])
            .await
            .expect("Success to delete policy");

        // Verify deleted policies are no longer active
        assert!(policy_handle.get_policy(1).await.is_none());
        assert!(policy_handle.get_policy(2).await.is_none());
        assert!(policy_handle.get_policy(3).await.is_none());

        // Verify active list only has remaining policies
        assert_eq!(policy_handle.get_all_policy_ids().len(), 2);
        assert!(policy_handle.get_policy(4).await.is_some());
        assert!(policy_handle.get_policy(5).await.is_some());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn delete_policy_batch() {
        // Test: Batch delete removes every requested ID.
        let (mut client, _dir, policy_handle) = create_test_client().await;

        // Add policies
        let policies: Vec<TimeSeriesGenerationPolicy> = (1..=5).map(create_test_policy).collect();
        client
            .time_series_generation_policy_list(&policies)
            .await
            .expect("Success to add policies");

        // Delete multiple in one call
        client
            .delete_time_series_generation_policy(&[1, 3, 5])
            .await
            .expect("Success to delete policies");

        // Verify deleted policies are gone, others remain active
        assert!(policy_handle.get_policy(1).await.is_none());
        assert!(policy_handle.get_policy(3).await.is_none());
        assert!(policy_handle.get_policy(5).await.is_none());
        assert!(policy_handle.get_policy(2).await.is_some());
        assert!(policy_handle.get_policy(4).await.is_some());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn delete_policy_ignores_non_existent_id() {
        // Test: Deleting a non-existent policy should be silently ignored
        let (mut client, _dir, policy_handle) = create_test_client().await;

        // Add a policy
        let policy = create_test_policy(1);
        client
            .time_series_generation_policy_list(&[policy])
            .await
            .expect("Success to add policy");

        // Try to delete a non-existent policy
        let result = client.delete_time_series_generation_policy(&[999]).await;
        assert!(result.is_ok());

        // Non-existent policy should not appear
        assert!(policy_handle.get_policy(999).await.is_none());

        // Active list should still have the original policy
        assert_eq!(policy_handle.get_all_policy_ids().len(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn delete_policy_ignores_non_existent_id_in_batch() {
        // Test: Deleting a non-existent policy should be silently ignored
        let (mut client, _dir, policy_handle) = create_test_client().await;

        let policies: Vec<TimeSeriesGenerationPolicy> = (1..=7).map(create_test_policy).collect();
        client
            .time_series_generation_policy_list(&policies)
            .await
            .expect("Success to add policies");

        // Try to delete a batch including non-existent policy and some existent policies
        let result = client
            .delete_time_series_generation_policy(&[1, 2, 3, 999, 4, 5])
            .await;
        assert!(result.is_ok());

        for id in [1, 2, 3, 4, 5] {
            assert!(policy_handle.get_policy(id).await.is_none());
        }
        assert!(policy_handle.get_policy(999).await.is_none());

        assert_eq!(policy_handle.get_all_policy_ids().len(), 2);
        assert!(policy_handle.get_policy(6).await.is_some());
        assert!(policy_handle.get_policy(7).await.is_some());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn delete_policy_empty_list() {
        // Test: Delete on empty active list should be no-op
        let (mut client, _dir, _policy_handle) = create_test_client().await;

        let result = client
            .delete_time_series_generation_policy(&[1, 2, 3])
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn delete_policy_no_double_delete() {
        // Test: Deleting the same ID twice is idempotent.
        let (mut client, _dir, policy_handle) = create_test_client().await;

        // Add a policy
        let policy = create_test_policy(1);
        client
            .time_series_generation_policy_list(&[policy])
            .await
            .expect("Success to add policy");

        // Delete it once
        client
            .delete_time_series_generation_policy(&[1])
            .await
            .expect("Success to delete policy");

        // Try to delete it again (already removed from active, so no-op)
        client
            .delete_time_series_generation_policy(&[1])
            .await
            .expect("No error or failure");

        // Policy should no longer be active
        assert!(policy_handle.get_policy(1).await.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn delete_policy_rapid_add_remove_same_id() {
        // Test: Rapid add/remove cycles of the same ID.
        // With per-policy CancellationTokens, re-add after delete
        // creates a fresh token — no consume step needed.
        let (mut client, _dir, policy_handle) = create_test_client().await;

        for _ in 0..3 {
            let policy = create_test_policy(1);
            client
                .time_series_generation_policy_list(&[policy])
                .await
                .expect("Success to add policy");

            let token = policy_handle.get_policy_token(1).await.unwrap();
            assert!(!token.is_cancelled());

            client
                .delete_time_series_generation_policy(&[1])
                .await
                .expect("Success to delete policy");

            assert!(policy_handle.get_policy(1).await.is_none());
            assert!(token.is_cancelled());
        }

        // Final state: empty active list
        assert_eq!(policy_handle.get_all_policy_ids(), [] as [u32; 0]);
    }

    // =========================================================================
    // Idle Mode Branching Tests
    // =========================================================================

    #[tokio::test(flavor = "current_thread")]
    async fn idle_mode_exits_on_reload() {
        // Test: Config reload notification should exit idle mode
        let (mut client, _dir, _policy_handle) = create_test_client().await;
        let config_reload = client.config_reload.clone();
        let tls_reload = Arc::new(Notify::new());
        let shutdown = Arc::new(Notify::new());

        // Spawn a task to notify config reload after a short delay
        let notify_task = tokio::spawn(async move {
            // Small delay to ensure enter_idle_mode is waiting
            tokio::time::sleep(Duration::from_millis(10)).await;
            config_reload.notify_one();
        });

        // Enter idle mode with health_check = false
        // This should wait for config reload notification
        let reason = tokio::time::timeout(
            Duration::from_millis(100),
            client.enter_idle_mode_with_try_connect(false, tls_reload, shutdown, |_, _| async {
                Err(anyhow::anyhow!("forced failure"))
            }),
        )
        .await
        .expect("No Timeout");
        assert_eq!(reason, IdleExitReason::Resumed);

        // Verify status is Ready after exiting idle mode
        assert!(matches!(client.status, Status::Ready));

        notify_task.await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn idle_mode_exits_on_tls_reload() {
        let (mut client, _dir, _) = create_test_client().await;
        let tls_reload = Arc::new(Notify::new());
        let shutdown = Arc::new(Notify::new());

        let notifier = tls_reload.clone();
        let notify_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            notifier.notify_one();
        });

        let reason = tokio::time::timeout(
            Duration::from_millis(100),
            client.enter_idle_mode_with_try_connect(false, tls_reload, shutdown, |_, _| async {
                Err(anyhow::anyhow!("forced failure"))
            }),
        )
        .await
        .expect("No Timeout");
        assert_eq!(reason, IdleExitReason::TlsReload);
        assert!(matches!(client.status, Status::Ready));

        notify_task.await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn idle_mode_exits_on_shutdown() {
        let (mut client, _dir, _) = create_test_client().await;
        let tls_reload = Arc::new(Notify::new());
        let shutdown = Arc::new(Notify::new());

        let notifier = shutdown.clone();
        let notify_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            notifier.notify_one();
        });

        let reason = tokio::time::timeout(
            Duration::from_millis(100),
            client.enter_idle_mode_with_try_connect(false, tls_reload, shutdown, |_, _| async {
                Err(anyhow::anyhow!("forced failure"))
            }),
        )
        .await
        .expect("No Timeout");
        assert_eq!(reason, IdleExitReason::Shutdown);
        assert!(matches!(client.status, Status::Ready));

        notify_task.await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn idle_mode_health_check_returns_immediately() {
        // Test: health_check=true returns without waiting for config_reload
        let (mut client, _dir, _policy_handle) = create_test_client().await;
        let config_reload = client.config_reload.clone();
        let tls_reload = Arc::new(Notify::new());
        let shutdown = Arc::new(Notify::new());
        let called = Arc::new(AtomicUsize::new(0));
        let called_ref = called.clone();

        let wait_task = tokio::spawn(async move {
            config_reload.notified().await;
        });

        let reason = tokio::time::timeout(
            Duration::from_millis(100),
            client.enter_idle_mode_with_try_connect(true, tls_reload, shutdown, move |_, _| {
                let called_ref = called_ref.clone();
                async move {
                    called_ref.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            }),
        )
        .await
        .expect("No Timeout");
        assert_eq!(reason, IdleExitReason::Resumed);

        assert_eq!(called.load(Ordering::SeqCst), 1);
        assert!(matches!(client.status, Status::Ready));

        tokio::time::timeout(Duration::from_millis(20), wait_task)
            .await
            .expect_err("Timeout");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn update_config_triggers_config_reload() {
        // Test: update_config should notify the config_reload
        let (mut client, _dir, _policy_handle) = create_test_client().await;
        let config_reload = client.config_reload.clone();

        // Spawn a task to wait for notification
        let wait_task = tokio::spawn(async move {
            config_reload.notified().await;
        });

        // Call update_config
        let result = client.update_config().await;
        assert!(result.is_ok());

        // Verify notification was received
        let received = tokio::time::timeout(Duration::from_millis(100), wait_task)
            .await
            .expect("No Timeout");
        assert!(received.is_ok());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn idle_mode_sets_status_to_idle() {
        // Test: Entering idle mode should set status to Idle
        let (mut client, _dir, _policy_handle) = create_test_client().await;
        let tls_reload = Arc::new(Notify::new());
        let shutdown = Arc::new(Notify::new());

        assert!(matches!(client.status, Status::Ready));

        // Notify from the connection attempt rather than beforehand, so the
        // attempt runs whichever branch `select!` polls first
        let reason = tokio::time::timeout(
            Duration::from_millis(100),
            client.enter_idle_mode_with_try_connect(false, tls_reload, shutdown, |client, _| {
                assert!(matches!(client.status, Status::Idle));
                client.config_reload.notify_one();
                async { Err(anyhow::anyhow!("forced failure")) }
            }),
        )
        .await
        .expect("No Timeout");
        assert_eq!(reason, IdleExitReason::Resumed);

        // After exiting, status should be Ready
        assert!(matches!(client.status, Status::Ready));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_incoming_retries_server_name_mismatch() {
        let (cert_pem, key_pem, ca_certs_pem, certs) = load_test_certs();
        let listener = test_manager::listener(
            create_test_server_config(&certs),
            "[::1]:0".parse().unwrap(),
        );
        let server_addr = listener.local_addr().unwrap();
        let (failed_send, failed_recv) = async_channel::unbounded();
        let server_task = tokio::spawn(async move {
            while let Some(pending) = listener.accept().await.unwrap() {
                assert!(pending.handshake().await.is_err());
                failed_send.send(()).await.unwrap();
            }
        });
        let mut client = Client::new(
            server_addr,
            "mismatched-server-name".to_string(),
            SharedTlsBytes::new(TlsBytes::new(cert_pem, key_pem, ca_certs_pem)),
            Arc::new(Notify::new()),
        );
        let Err(error) = client.connect().await else {
            panic!("server name must fail verification");
        };
        assert_eq!(
            classify_connect_error(&error),
            ConnectErrorDisposition::Retry
        );
        failed_recv.recv().await.unwrap();
        let incoming = tokio::spawn(async move { client.handle_incoming().await });
        tokio::time::timeout(Duration::from_secs(SERVER_RETRY_INTERVAL + 5), async {
            failed_recv.recv().await.unwrap();
            failed_recv.recv().await.unwrap();
        })
        .await
        .expect("server-name mismatch is retried on the next interval");
        assert!(!incoming.is_finished());
        incoming.abort();
        let _ = incoming.await;
        server_task.abort();
        let _ = server_task.await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_incoming_returns_invalid_peer_certificate_error() {
        let (cert, key, roots, _) = load_test_certs();
        let mut client =
            session_test_client("127.0.0.1:0".parse().unwrap(), Arc::new(Notify::new()));
        for bytes in [
            TlsBytes::new(Vec::new(), key.clone(), roots.clone()),
            TlsBytes::new(cert.clone(), Vec::new(), roots),
            TlsBytes::new(cert, key, Vec::new()),
        ] {
            client.tls_bytes.replace(bytes);
            let error = client
                .handle_incoming()
                .await
                .expect_err("unusable PEM is terminal");
            assert_eq!(error.to_string(), "Invalid peer certificate contents");
        }
    }

    #[test]
    fn classify_connect_error_marks_client_pem_error_as_invalid_certificate() {
        let error = anyhow::Error::new(ClientPemError::NoCertificate);
        assert_eq!(
            classify_connect_error(&error),
            ConnectErrorDisposition::InvalidPeerCertificate
        );
    }

    fn transport_error(reason: CloseReason) -> SessionError {
        SessionError::Transport {
            certainty: review_protocol::session::OutcomeCertainty::Unknown,
            source: TransportFailure::Closed {
                reason,
                source: Box::new(std::io::Error::other("test close")),
            },
        }
    }

    #[test]
    fn classify_connect_error_and_health_check_transport_dispositions() {
        for (reason, retry) in [
            (
                CloseReason::Application {
                    code: ApplicationCode::default(),
                    reason: Vec::new(),
                },
                true,
            ),
            (
                CloseReason::Transport(TransportCloseKind::Crypto { alert: Some(42) }),
                true,
            ),
            (
                CloseReason::Transport(TransportCloseKind::IdleTimeout),
                true,
            ),
            (CloseReason::Transport(TransportCloseKind::Reset), true),
            (CloseReason::Transport(TransportCloseKind::Other), true),
            (CloseReason::Local, false),
            (
                CloseReason::Transport(TransportCloseKind::VersionMismatch),
                false,
            ),
            (
                CloseReason::Transport(TransportCloseKind::ConnectionIdExhausted),
                false,
            ),
        ] {
            for wrapped in 0..3 {
                let error = transport_error(reason.clone());
                let error = match wrapped {
                    0 => anyhow::Error::new(error),
                    1 => anyhow::Error::new(AgentRunError::Session(error)),
                    _ => anyhow::Error::new(AgentRunError::ResponseWrite(error)),
                }
                .context("outer context");
                assert_eq!(
                    needs_health_check(&error),
                    retry,
                    "{reason:?}, wrapper {wrapped}"
                );
                assert_eq!(
                    classify_connect_error(&error),
                    if retry {
                        ConnectErrorDisposition::Retry
                    } else {
                        ConnectErrorDisposition::Other
                    }
                );
            }
        }
        for source in [
            TransportFailure::StreamFailed(Box::new(std::io::Error::other("stream"))),
            TransportFailure::Other(Box::new(std::io::Error::other("connect"))),
        ] {
            let error = anyhow::Error::new(SessionError::Transport {
                certainty: review_protocol::session::OutcomeCertainty::NotSent,
                source,
            });
            assert_eq!(
                classify_connect_error(&error),
                ConnectErrorDisposition::Retry
            );
            assert!(needs_health_check(&error));
        }
    }

    #[test]
    fn non_transport_session_errors_are_terminal_and_only_remote_rejection_is_a_wait() {
        use review_protocol::session::{FrameError, OutcomeCertainty};
        for error in [
            SessionError::StreamStopped {
                code: ApplicationCode::default(),
            },
            SessionError::Malformed {
                certainty: None,
                source: Box::new(std::io::Error::other("bad data")),
            },
            SessionError::IncompatibleProtocol {
                version: review_protocol::PROTOCOL_VERSION.to_string(),
                required: "<0.54.0".to_string(),
            },
            SessionError::RemoteRejection("unregistered".to_string()),
            SessionError::LimitExceeded {
                certainty: None,
                source: FrameError::InvalidLimit,
            },
            SessionError::Deadline {
                certainty: OutcomeCertainty::NotSent,
                source: None,
            },
        ] {
            assert!(!retryable_session_error(&error));
            let unavailable = matches!(error, SessionError::RemoteRejection(_));
            let error = anyhow::Error::new(error).context("connect failed");
            assert_eq!(
                classify_connect_error(&error),
                ConnectErrorDisposition::Other
            );
            assert!(!needs_health_check(&error));
            let error = error.downcast::<SessionError>().unwrap();
            assert_eq!(
                classify_config_error(error)
                    .downcast_ref::<ConfigUnavailable>()
                    .is_some(),
                unavailable
            );
        }
        let error = anyhow::Error::new(AgentRunError::AuthorizationDenied {
            service: review_protocol::service_id::SERVER_CONFIG_GET,
            source: review_protocol::auth::AuthorizationError::new("denied"),
        });
        assert!(!needs_health_check(&error));
    }

    #[test]
    fn classify_config_error_marks_only_the_managers_reason_as_a_wait() {
        let refused = classify_config_error(SessionError::RemoteRejection(
            "001.crusher unregistered".to_string(),
        ));
        let reason = refused
            .downcast_ref::<ConfigUnavailable>()
            .expect("the Manager's reason is a wait");
        assert_eq!(reason.to_string(), "001.crusher unregistered");
        for reason in [
            CloseReason::Local,
            CloseReason::Transport(TransportCloseKind::ConnectionIdExhausted),
            CloseReason::Transport(TransportCloseKind::Reset),
        ] {
            let error = classify_config_error(transport_error(reason));
            assert!(error.downcast_ref::<ConfigUnavailable>().is_none());
            assert!(error.downcast_ref::<SessionError>().is_some());
        }
    }

    // =========================================================================
    // Run method tests
    // =========================================================================

    #[tokio::test(flavor = "current_thread")]
    async fn run_exits_on_cancellation() {
        // Test: run() should exit cleanly when cancellation is requested.
        // Policy state is owned by the actor (spawned per-run), so
        // there is nothing to clear on the Client itself.
        let (mut client, _dir, _policy_handle) = create_test_client().await;

        let coordinator = CancellationCoordinator::new();
        coordinator.request_cancellation("test");

        let result = client.run(coordinator).await;
        assert!(result.is_ok());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_exits_promptly_while_incoming_handler_is_in_retry_sleep() {
        let coordinator = CancellationCoordinator::new();
        let coordinator_for_task = coordinator.clone();
        let retrying_incoming = async {
            sleep(Duration::from_secs(SERVER_RETRY_INTERVAL)).await;
            bail!("retry sleep completed before cancellation")
        };

        let handle = tokio::spawn(async move {
            run_until_cancelled(coordinator_for_task, retrying_incoming).await
        });

        tokio::task::yield_now().await;
        coordinator.request_cancellation("test retry sleep cancellation");

        let result = tokio::time::timeout(Duration::from_millis(200), handle)
            .await
            .expect("run should exit promptly after cancellation")
            .expect("run task should not panic");
        assert!(result.is_ok());
    }

    // =========================================================================
    // Startup sync test
    // =========================================================================

    struct TestManagerHandler;

    /// A configuration naming the removed `log_path` key.
    const LOG_PATH_CONFIG: &str = r#"
giganto_name = "localhost"
giganto_ingest_srv_addr = "[::1]:9"
giganto_publish_srv_addr = "[::1]:9"
last_timestamp_data = "/tmp/time_data.json"
log_path = "/tmp/crusher.log"
"#;

    #[async_trait::async_trait]
    impl review_protocol::server::Handler for TestManagerHandler {
        async fn get_config(&self, _peer: &str) -> Result<String, String> {
            Ok(LOG_PATH_CONFIG.to_string())
        }

        async fn get_time_series_generation_policy_list(
            &self,
            _peer: &str,
        ) -> Result<Vec<TimeSeriesGenerationPolicy>, String> {
            Ok(vec![create_test_policy(10), create_test_policy(20)])
        }
    }

    /// Spawns a server that performs the review-protocol handshake and
    /// answers requests with `TestManagerHandler`. Returns the server address
    /// and a handle to the driver task.
    fn spawn_test_manager_server(certs: &Certs) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let server_endpoint = test_manager::listener(
            create_test_server_config(certs),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
        );
        let server_addr = server_endpoint.local_addr().expect("read server address");

        let server_task = tokio::spawn(async move {
            if let Ok(Some(conn)) = server_endpoint.accept().await {
                let (_connection, mut incoming) =
                    test_manager::accept(conn).await.expect("handshake");
                let handler = Arc::new(TestManagerHandler);
                while let Ok(ServerStream::Requests(stream)) = incoming.accept().await {
                    let _ = stream.run(handler.clone()).await;
                }
            }
        });
        (server_addr, server_task)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn syncs_time_series_generation_policies_on_startup() {
        let (cert_pem, key_pem, ca_certs_pem, certs) = load_test_certs();
        let (server_addr, server_task) = spawn_test_manager_server(&certs);

        let dir = tempfile::tempdir().unwrap();
        let tls_bytes = SharedTlsBytes::new(TlsBytes::new(cert_pem, key_pem, ca_certs_pem));
        let coordinator = CancellationCoordinator::new();
        let (policy_handle, actor) =
            crate::policy::spawn_policy_actor(dir.path().join("time_data.json"), &coordinator)
                .await
                .unwrap();
        let mut client = Client::new(
            server_addr,
            "localhost".to_string(),
            tls_bytes,
            Arc::new(Notify::new()),
        );
        client.set_policy_handle(policy_handle.clone());

        let connection = client.connect().await.expect("connect to manager");
        assert!(
            client
                .sync_time_series_generation_policies(&connection)
                .await
        );

        // Verify policies were restored into the active list
        let mut ids = policy_handle.get_all_policy_ids();
        ids.sort_unstable();
        assert_eq!(ids, [10, 20]);
        assert!(policy_handle.get_policy(10).await.is_some());
        assert!(policy_handle.get_policy(20).await.is_some());

        let snapshot = policy_handle.subscribe();
        assert_eq!(snapshot.borrow().len(), 2);
        drop(client);
        drop(policy_handle);
        actor.await.unwrap().unwrap();

        server_task.abort();
    }

    /// A configuration the Manager server pushes that names the removed
    /// `log_path` key ends `run()` with the removal error, which the main
    /// loop logs before entering idle mode.
    #[tokio::test(flavor = "current_thread")]
    async fn run_refuses_pushed_config_naming_log_path() {
        let (cert_pem, key_pem, ca_certs_pem, certs) = load_test_certs();
        let (server_addr, server_task) = spawn_test_manager_server(&certs);

        let request_client = Client::new(
            server_addr,
            "localhost".to_string(),
            SharedTlsBytes::new(TlsBytes::new(cert_pem, key_pem, ca_certs_pem)),
            Arc::new(Notify::new()),
        );
        let args = crate::CmdLineArgs {
            config: None,
            cert: CERT_PATH.to_string(),
            key: KEY_PATH.to_string(),
            ca_certs: vec![CA_CERT_PATH.to_string()],
            manager_server: format!("localhost@{server_addr}")
                .parse()
                .expect("manager server address"),
        };
        assert!(args.is_remote_mode());

        let err = tokio::time::timeout(
            Duration::from_secs(5),
            crate::run(
                &args,
                &certs,
                request_client,
                Arc::new(Notify::new()),
                Arc::new(Notify::new()),
                Arc::new(Notify::new()),
            ),
        )
        .await
        .expect("run returns within timeout")
        .expect_err("a pushed configuration naming log_path must be refused");
        assert_eq!(format!("{err:#}"), crate::settings::LOG_PATH_REMOVED);

        server_task.abort();
    }

    // =========================================================================
    // Reconnect pull tests
    // =========================================================================

    type PullResponses =
        Arc<std::sync::Mutex<VecDeque<Result<Vec<TimeSeriesGenerationPolicy>, String>>>>;

    /// Answers each policy pull with the next scripted response.
    #[derive(Clone)]
    struct ScriptedPullHandler {
        responses: PullResponses,
        pulls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl review_protocol::server::Handler for ScriptedPullHandler {
        async fn get_time_series_generation_policy_list(
            &self,
            _peer: &str,
        ) -> Result<Vec<TimeSeriesGenerationPolicy>, String> {
            self.pulls.fetch_add(1, Ordering::SeqCst);
            self.responses
                .lock()
                .expect("responses lock")
                .pop_front()
                .unwrap_or_else(|| Err("no scripted response".to_string()))
        }
    }

    /// A fake Manager that serves scripted pulls on every connection and
    /// keeps the latest one so a test can push to it or close it.
    struct ScriptedManager {
        addr: SocketAddr,
        pulls: Arc<AtomicUsize>,
        latest_conn: Arc<std::sync::Mutex<Option<ServerHandle>>>,
        connected: async_channel::Receiver<ServerHandle>,
        handle: tokio::task::JoinHandle<()>,
    }

    impl ScriptedManager {
        fn spawn(
            certs: &Certs,
            responses: Vec<Result<Vec<TimeSeriesGenerationPolicy>, String>>,
        ) -> Self {
            let server_endpoint = test_manager::listener(
                create_test_server_config(certs),
                SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
            );
            let addr = server_endpoint.local_addr().expect("read server address");
            let handler = ScriptedPullHandler {
                responses: Arc::new(std::sync::Mutex::new(responses.into())),
                pulls: Arc::new(AtomicUsize::new(0)),
            };
            let pulls = handler.pulls.clone();
            let latest_conn: Arc<std::sync::Mutex<Option<ServerHandle>>> =
                Arc::new(std::sync::Mutex::new(None));
            let latest_conn_for_task = latest_conn.clone();
            let (connected_send, connected) = async_channel::unbounded();
            let handle = tokio::spawn(async move {
                let mut connections = tokio::task::JoinSet::new();
                while let Ok(Some(conn)) = server_endpoint.accept().await {
                    let handler = handler.clone();
                    let latest_conn = latest_conn_for_task.clone();
                    let connected_send = connected_send.clone();
                    connections.spawn(async move {
                        let Ok((connection, mut incoming)) = test_manager::accept(conn).await
                        else {
                            return;
                        };
                        *latest_conn.lock().expect("latest_conn lock") = Some(connection.clone());
                        connected_send
                            .send(connection)
                            .await
                            .expect("connection receiver retained");
                        let handler = Arc::new(handler);
                        while let Ok(ServerStream::Requests(stream)) = incoming.accept().await {
                            let _ = stream.run(handler.clone()).await;
                        }
                    });
                }
            });
            Self {
                addr,
                pulls,
                latest_conn,
                connected,
                handle,
            }
        }

        fn connection(&self) -> ServerHandle {
            self.latest_conn
                .lock()
                .expect("latest_conn lock")
                .clone()
                .expect("manager has a connection")
        }

        async fn push(&self, policies: &[TimeSeriesGenerationPolicy]) {
            self.connection()
                .send_time_series_generation_policies(policies)
                .await
                .expect("push time-series generation policies");
        }
    }

    fn session_test_client(address: SocketAddr, config_reload: Arc<Notify>) -> Client {
        let (cert, key, roots, _) = load_test_certs();
        Client::new(
            address,
            "localhost".to_string(),
            SharedTlsBytes::new(TlsBytes::new(cert, key, roots)),
            config_reload,
        )
    }

    #[tokio::test(flavor = "current_thread")]
    async fn incoming_accept_failure_waits_before_reconnecting() {
        let (_, _, _, certs) = load_test_certs();
        let manager = ScriptedManager::spawn(&certs, vec![Ok(Vec::new()), Ok(Vec::new())]);
        let reload = Arc::new(Notify::new());
        let client = session_test_client(manager.addr, reload.clone());
        let (first, first_id) = client.connect_with_id().await.unwrap();
        let server = manager.connected.recv().await.unwrap();
        let mut running = client.clone();
        let incoming = tokio::spawn(async move { running.handle_incoming().await });

        tokio::time::timeout(Duration::from_secs(SERVER_RETRY_INTERVAL + 5), async {
            // With no pushed stream, this lock is held only by the pending accept.
            while first.incoming.try_lock().is_ok() {
                tokio::task::yield_now().await;
            }
            let closed_at = tokio::time::Instant::now();
            server.close(ApplicationCode::default(), b"fail pending accept");
            let replacement = manager.connected.recv().await.unwrap();
            assert!(closed_at.elapsed() >= Duration::from_secs(SERVER_RETRY_INTERVAL));
            assert!(!incoming.is_finished(), "accept failure must not terminate");
            let (second, second_id) = client.connect_with_id().await.unwrap();
            assert_eq!(second_id, first_id + 1);
            assert_ne!(second.handle.id(), first.handle.id());
            assert!(!Arc::ptr_eq(&second.incoming, &first.incoming));
            replacement.send_config_update_cmd().await.unwrap();
            reload.notified().await;
        })
        .await
        .expect("accept failure retries on a fresh session after the interval");

        incoming.abort();
        let _ = incoming.await;
        manager.handle.abort();
        let _ = manager.handle.await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn incoming_runner_failure_terminates_the_handler() {
        let (_, _, _, certs) = load_test_certs();
        let manager = ScriptedManager::spawn(&certs, vec![Ok(Vec::new())]);
        let reload = Arc::new(Notify::new());
        let mut client = session_test_client(manager.addr, reload.clone());
        client.connect().await.unwrap();
        let server = manager.connected.recv().await.unwrap();

        tokio::time::timeout(Duration::from_secs(5), async {
            let mut incoming = Box::pin(client.handle_incoming());
            let mut command = Box::pin(server.send_config_update_cmd());
            let mut handled = Box::pin(reload.notified());
            // Stop driving the sender as soon as dispatch occurs, so its command
            // stream remains open while the runner is inside it.
            std::future::poll_fn(|cx| {
                assert!(incoming.as_mut().poll(cx).is_pending());
                if handled.as_mut().poll(cx).is_ready() {
                    return std::task::Poll::Ready(());
                }
                assert!(command.as_mut().poll(cx).is_pending());
                std::task::Poll::Pending
            })
            .await;

            server.close(ApplicationCode::default(), b"fail active runner");
            let error = incoming.await.unwrap_err();
            assert!(matches!(
                error.downcast_ref::<AgentRunError>(),
                Some(AgentRunError::Session(_) | AgentRunError::ResponseWrite(_))
            ));
            assert!(needs_health_check(&error));
            assert!(
                manager.connected.is_empty(),
                "runner failure must not retry"
            );
        })
        .await
        .expect("runner failure propagates out of handle_incoming");

        manager.handle.abort();
        let _ = manager.handle.await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn connect_uses_the_managers_address_family() {
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let (_, _, _, certs) = load_test_certs();
            let listener =
                test_manager::listener(create_test_server_config(&certs), address.parse().unwrap());
            let address = listener.local_addr().unwrap();
            let client = session_test_client(address, Arc::new(Notify::new()));
            let (agent, server) = tokio::time::timeout(Duration::from_secs(5), async {
                tokio::join!(client.connect(), async {
                    let pending = listener.accept().await.unwrap().unwrap();
                    test_manager::accept(pending).await.unwrap()
                })
            })
            .await
            .expect("connect using the Manager's address family");
            let agent = agent.unwrap();
            assert!(agent.close_reason().is_none());
            let review_protocol::session::HandshakeMetadata::Agent(info) = server.0.metadata()
            else {
                panic!("agent handshake metadata");
            };
            // The server replaces the advertised placeholder with the peer address.
            assert_eq!(info.addr.ip(), address.ip());
            assert_ne!(info.addr.port(), 0);
            assert_eq!(info.status, Status::Ready);
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_incoming_terminates_when_manager_refuses_protocol() {
        use review_protocol::session::{
            ProtocolWindow, ServerListener, ServerListenerOptions, ServerTransportOptions,
        };

        let (_, _, _, certs) = load_test_certs();
        let listener = ServerListener::bind(
            "[::1]:0".parse().unwrap(),
            create_test_server_config(&certs),
            ServerListenerOptions {
                transport: ServerTransportOptions::default(),
                session: SessionOptions::legacy_compatible(),
                protocol: ProtocolWindow::new(">=0", "0.49.0").unwrap(),
                handshake_timeout: Duration::from_secs(5),
            },
        )
        .unwrap();
        let mut client =
            session_test_client(listener.local_addr().unwrap(), Arc::new(Notify::new()));
        let (error, ()) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(client.handle_incoming(), async {
                let pending = listener.accept().await.unwrap().unwrap();
                assert!(matches!(
                    pending.handshake().await,
                    Err(SessionError::IncompatibleProtocol { .. })
                ));
            })
        })
        .await
        .expect("protocol refusal is terminal");
        let error = error.unwrap_err();
        assert!(error.to_string().contains("is incompatible with"));
    }

    fn assert_not_supported<T: std::fmt::Debug>(result: &Result<T, SessionError>) {
        assert!(
            matches!(result, Err(SessionError::RemoteRejection(reason)) if reason == "not supported"),
            "{result:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ready_session_serves_commands_and_rejects_node_requests() {
        use review_protocol::types::node::{NodeObservationRequest, NodePowerRequest};
        let (_, _, _, certs) = load_test_certs();
        let manager = ScriptedManager::spawn(&certs, vec![Ok(vec![create_test_policy(1)])]);
        let config_reload = Arc::new(Notify::new());
        let mut client = session_test_client(manager.addr, config_reload.clone());
        let dir = tempfile::tempdir().unwrap();
        let coordinator = CancellationCoordinator::new();
        let (policies, actor) =
            crate::policy::spawn_policy_actor(dir.path().join("time_data.json"), &coordinator)
                .await
                .unwrap();
        client.set_policy_handle(policies.clone());
        let incoming = tokio::spawn(async move { client.handle_incoming().await });
        tokio::time::timeout(Duration::from_secs(5), async {
            let server = manager.connected.recv().await.unwrap();
            assert!(matches!(server.metadata(), review_protocol::session::HandshakeMetadata::Agent(info) if info.status == Status::Ready));
            server.send_config_update_cmd().await.unwrap();
            config_reload.notified().await;
            assert_eq!(manager.pulls.load(Ordering::SeqCst), 1);
            assert_eq!(sorted_policy_ids(&policies), [1]);
            server.send_time_series_generation_policies(&[create_test_policy(2)]).await.unwrap();
            assert_eq!(sorted_policy_ids(&policies), [2]);
            assert_not_supported(&server.node_power(NodePowerRequest::GracefulReboot).await);
            assert_not_supported(&server.node_power(NodePowerRequest::GracefulShutdown).await);
            assert_not_supported(&server.node_observation(NodeObservationRequest::ResourceUsage).await);
            assert_not_supported(&server.node_observation(NodeObservationRequest::ProcessList).await);
            assert_not_supported(&server.send_run_detector_once(1).await);
        }).await.expect("Ready commands complete");
        stop_incoming_handler(policies, incoming, actor).await;
        manager.handle.abort();
        let _ = manager.handle.await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_respawn_serves_commands_on_the_retained_session() {
        let (_, _, _, certs) = load_test_certs();
        let manager = ScriptedManager::spawn(&certs, vec![Ok(Vec::new()), Ok(Vec::new())]);
        let reload = Arc::new(Notify::new());
        let mut client = session_test_client(manager.addr, reload.clone());
        let dir = tempfile::tempdir().unwrap();
        let policy_coordinator = CancellationCoordinator::new();
        let (policies, actor) = crate::policy::spawn_policy_actor(
            dir.path().join("time_data.json"),
            &policy_coordinator,
        )
        .await
        .unwrap();
        client.set_policy_handle(policies.clone());
        tokio::time::timeout(Duration::from_secs(5), async {
            let first_coordinator = CancellationCoordinator::new();
            let coordinator = first_coordinator.clone();
            let mut running = client.clone();
            let first_run = tokio::spawn(async move { running.run(coordinator).await });
            let server = manager.connected.recv().await.unwrap();
            let id = client.connect().await.unwrap().id();
            server.send_config_update_cmd().await.unwrap();
            reload.notified().await;
            first_coordinator.request_cancellation("TLS reload");
            first_run.await.unwrap().unwrap();
            let second_coordinator = CancellationCoordinator::new();
            let coordinator = second_coordinator.clone();
            let mut running = client.clone();
            let second_run = tokio::spawn(async move { running.run(coordinator).await });
            server
                .send_time_series_generation_policies(&[create_test_policy(7)])
                .await
                .unwrap();
            assert_eq!(sorted_policy_ids(&policies), [7]);
            assert_eq!(client.connect().await.unwrap().id(), id);
            assert_eq!(manager.pulls.load(Ordering::SeqCst), 2);
            assert!(manager.connected.is_empty(), "no second handshake");
            second_coordinator.request_cancellation("test done");
            second_run.await.unwrap().unwrap();
        })
        .await
        .expect("respawn retains the handle and incoming owner");
        drop(client);
        drop(policies);
        actor.await.unwrap().unwrap();
        manager.handle.abort();
        let _ = manager.handle.await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn idle_session_serves_one_stream_and_advertises_idle() {
        let (_, _, _, certs) = load_test_certs();
        let manager = ScriptedManager::spawn(&certs, Vec::new());
        let config_reload = Arc::new(Notify::new());
        let mut client = session_test_client(manager.addr, config_reload.clone());
        client.status = Status::Idle;
        let mut running = client.clone();
        let incoming = tokio::spawn(async move { running.try_connect(false).await });
        tokio::time::timeout(Duration::from_secs(5), async {
            let server = manager.connected.recv().await.unwrap();
            assert!(matches!(server.metadata(), review_protocol::session::HandshakeMetadata::Agent(info) if info.status == Status::Idle));
            server.send_config_update_cmd().await.unwrap();
            config_reload.notified().await;
            incoming.await.unwrap().unwrap();
            assert_eq!(manager.pulls.load(Ordering::SeqCst), 0);
            // The one stream ended, and the session remains available for a rerun.
            assert!(server.close_reason().is_none());
        }).await.expect("Idle command stream ends");
        manager.handle.abort();
        let _ = manager.handle.await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn idle_session_rejects_policies_node_requests_and_other_commands() {
        use review_protocol::types::node::{NodeObservationRequest, NodePowerRequest};

        let (_, _, _, certs) = load_test_certs();
        let manager = ScriptedManager::spawn(&certs, Vec::new());
        let reload = Arc::new(Notify::new());
        let mut client = session_test_client(manager.addr, reload.clone());
        client.status = Status::Idle;
        let handle = client.connect().await.unwrap();
        let server = manager.connected.recv().await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            // Each typed operation opens one stream, and Idle returns at its end.
            let policies = [create_test_policy(1)];
            let (completed, response) = tokio::join!(
                client.try_connect(false),
                server.send_time_series_generation_policies(&policies)
            );
            completed.unwrap();
            assert_not_supported(&response);
            for request in [
                NodePowerRequest::GracefulReboot,
                NodePowerRequest::GracefulShutdown,
            ] {
                let (completed, response) =
                    tokio::join!(client.try_connect(false), server.node_power(request));
                completed.unwrap();
                assert_not_supported(&response);
            }
            for request in [
                NodeObservationRequest::ResourceUsage,
                NodeObservationRequest::ProcessList,
            ] {
                let (completed, response) =
                    tokio::join!(client.try_connect(false), server.node_observation(request));
                completed.unwrap();
                assert_not_supported(&response);
            }
            let (completed, response) =
                tokio::join!(client.try_connect(false), server.send_run_detector_once(1));
            completed.unwrap();
            assert_not_supported(&response);
            assert_eq!(manager.pulls.load(Ordering::SeqCst), 0);
            assert!(handle.close_reason().is_none());
            assert!(
                tokio::time::timeout(Duration::ZERO, reload.notified())
                    .await
                    .is_err()
            );
        })
        .await
        .expect("Idle rejects unsupported commands on a reusable session");
        manager.handle.abort();
        let _ = manager.handle.await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn get_config_distinguishes_manager_rejection_from_connection_loss() {
        use review_protocol::session::ServerRequest;
        for lose_connection in [false, true] {
            let (_, _, _, certs) = load_test_certs();
            let listener = test_manager::listener(
                create_test_server_config(&certs),
                "127.0.0.1:0".parse().unwrap(),
            );
            let address = listener.local_addr().unwrap();
            let server_task = tokio::spawn(async move {
                let pending = listener.accept().await.unwrap().unwrap();
                let (server, mut incoming) = test_manager::accept(pending).await.unwrap();
                let ServerStream::Requests(mut stream) = incoming.accept().await.unwrap() else {
                    panic!("configuration request stream");
                };
                let Some(ServerRequest::GetConfig { reply, .. }) = stream.next().await.unwrap()
                else {
                    panic!("get_config request");
                };
                if lose_connection {
                    server.close(ApplicationCode::default(), b"lost during get_config");
                    drop(reply);
                } else {
                    reply
                        .respond(Err("001.crusher unregistered".to_string()))
                        .await
                        .unwrap();
                    stream.finish().unwrap();
                    server.closed().await;
                }
            });
            let mut client = session_test_client(address, Arc::new(Notify::new()));
            let error = tokio::time::timeout(Duration::from_secs(5), client.get_config())
                .await
                .unwrap()
                .unwrap_err();
            assert_eq!(
                error.downcast_ref::<ConfigUnavailable>().is_none(),
                lose_connection
            );
            if lose_connection {
                assert!(error.downcast_ref::<SessionError>().is_some());
                assert!(needs_health_check(&error));
            } else {
                assert_eq!(error.to_string(), "001.crusher unregistered");
            }
            server_task.abort();
            let _ = server_task.await;
        }
    }

    /// Polls `condition` until it holds, failing the test after a deadline
    /// that covers one reconnect retry interval.
    async fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
        let deadline = Duration::from_secs(SERVER_RETRY_INTERVAL + 10);
        tokio::time::timeout(deadline, async {
            while !condition() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting until {what}"));
    }

    fn sorted_policy_ids(handle: &PolicyHandle) -> Vec<u32> {
        let mut ids = handle.get_all_policy_ids();
        ids.sort_unstable();
        ids
    }

    async fn spawn_incoming_handler(
        addr: SocketAddr,
        dir: &tempfile::TempDir,
        initial: &[TimeSeriesGenerationPolicy],
    ) -> (
        PolicyHandle,
        tokio::task::JoinHandle<Result<()>>,
        tokio::task::JoinHandle<Result<()>>,
    ) {
        let (cert_pem, key_pem, ca_certs_pem, _) = load_test_certs();
        let coordinator = CancellationCoordinator::new();
        let (policy_handle, actor) =
            crate::policy::spawn_policy_actor(dir.path().join("time_data.json"), &coordinator)
                .await
                .unwrap();
        policy_handle
            .replace_policies(initial.to_vec())
            .await
            .unwrap();
        let mut client = Client::new(
            addr,
            "localhost".to_string(),
            SharedTlsBytes::new(TlsBytes::new(cert_pem, key_pem, ca_certs_pem)),
            Arc::new(Notify::new()),
        );
        client.set_policy_handle(policy_handle.clone());
        let incoming = tokio::spawn(async move { client.handle_incoming().await });
        (policy_handle, incoming, actor)
    }

    async fn stop_incoming_handler(
        policy_handle: PolicyHandle,
        incoming: tokio::task::JoinHandle<Result<()>>,
        actor: tokio::task::JoinHandle<Result<()>>,
    ) {
        incoming.abort();
        let _ = incoming.await;
        drop(policy_handle);
        actor.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn manager_reconnect_pulls_the_policy_list_again() {
        let (_, _, _, certs) = load_test_certs();
        let manager = ScriptedManager::spawn(
            &certs,
            vec![
                Ok(vec![create_test_policy(10), create_test_policy(20)]),
                Ok(vec![create_test_policy(30)]),
            ],
        );
        let dir = tempfile::tempdir().unwrap();
        let (policy_handle, incoming, actor) =
            spawn_incoming_handler(manager.addr, &dir, &[create_test_policy(1)]).await;

        wait_until("the first connection is pulled", || {
            sorted_policy_ids(&policy_handle) == [10, 20]
        })
        .await;

        // A push on the synced connection is applied without another pull.
        manager
            .push(&[create_test_policy(10), create_test_policy(40)])
            .await;
        assert_eq!(sorted_policy_ids(&policy_handle), [10, 40]);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(manager.pulls.load(Ordering::SeqCst), 1);

        // A change made while disconnected reaches Crusher through the pull
        // on the next connection.
        manager
            .connection()
            .close(ApplicationCode::default(), b"manager restart");
        wait_until("the new connection is pulled", || {
            sorted_policy_ids(&policy_handle) == [30]
        })
        .await;
        assert_eq!(manager.pulls.load(Ordering::SeqCst), 2);

        stop_incoming_handler(policy_handle, incoming, actor).await;
        manager.handle.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn failed_pull_keeps_policies_and_is_retried_before_the_next_push() {
        let (_, _, _, certs) = load_test_certs();
        let manager = ScriptedManager::spawn(
            &certs,
            vec![
                Err("temporarily unavailable".to_string()),
                Ok(vec![create_test_policy(5)]),
            ],
        );
        let dir = tempfile::tempdir().unwrap();
        let checkpoint = dir.path().join("time_data.json");
        fs::write(
            &checkpoint,
            r#"{"1":{"timestamp":100},"2":{"timestamp":200}}"#,
        )
        .unwrap();
        let (policy_handle, incoming, actor) = spawn_incoming_handler(
            manager.addr,
            &dir,
            &[create_test_policy(1), create_test_policy(2)],
        )
        .await;

        wait_until("the first pull fails", || {
            manager.pulls.load(Ordering::SeqCst) == 1
        })
        .await;
        // The handler is now waiting for a push; the failed pull changed nothing.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(sorted_policy_ids(&policy_handle), [1, 2]);
        assert!(policy_handle.get_policy_token(1).await.is_some());
        let saved: serde_json::Value =
            serde_json::from_slice(&fs::read(&checkpoint).unwrap()).unwrap();
        assert_eq!(
            saved,
            serde_json::json!({"1": {"timestamp": 100}, "2": {"timestamp": 200}})
        );

        // The failed pull does not block pushes, and the pull is retried
        // before the next push is accepted on the same connection.
        manager.push(&[create_test_policy(7)]).await;
        wait_until("the pull is retried", || {
            manager.pulls.load(Ordering::SeqCst) == 2
        })
        .await;
        wait_until("the retried pull is applied", || {
            sorted_policy_ids(&policy_handle) == [5]
        })
        .await;

        stop_incoming_handler(policy_handle, incoming, actor).await;
        manager.handle.abort();
    }

    // =========================================================================
    // Shared TLS Bytes Reload Tests
    // =========================================================================

    /// Spawns a minimal review-protocol server that performs the handshake
    /// once per connection. Returns the local server address, a shared
    /// counter that tracks successful handshakes, and a handle to the
    /// driver task.
    fn spawn_handshake_only_server(
        certs: &Certs,
    ) -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let server_endpoint = test_manager::listener(
            create_test_server_config(certs),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
        );
        let server_addr = server_endpoint.local_addr().expect("read server address");
        let handshake_count = Arc::new(AtomicUsize::new(0));
        let counter = handshake_count.clone();
        let handle = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            while let Ok(Some(conn)) = server_endpoint.accept().await {
                let counter = counter.clone();
                connections.spawn(async move {
                    let Ok((_connection, mut incoming)) = test_manager::accept(conn).await else {
                        return;
                    };
                    counter.fetch_add(1, Ordering::SeqCst);
                    // Keep the connection open; we only care that the
                    // handshake completed, so that the client side has
                    // observed the presented client certificate.
                    while incoming.accept().await.is_ok() {}
                });
            }
        });
        (server_addr, handshake_count, handle)
    }

    /// Acceptance test: `connect()` reads the current shared TLS bytes on
    /// every reconnect, so a swap performed between attempts takes effect
    /// on the next attempt.
    ///
    /// Replaces invalid initial bytes with valid ones and verifies that
    /// the first attempt fails (invalid bytes) while the second attempt
    /// succeeds (rotated bytes picked up from the shared store).
    #[tokio::test(flavor = "current_thread")]
    async fn reconnect_uses_rotated_shared_tls_bytes() {
        let (cert_pem, key_pem, ca_certs_pem, certs) = load_test_certs();
        let (server_addr, _handshake_count, server_handle) = spawn_handshake_only_server(&certs);

        // Start with empty bytes so the first reconnect attempt fails at
        // client_config_from_pem with a ClientPemError. This proves it reads from
        // the shared store rather than baking the bytes in at construction.
        let shared = SharedTlsBytes::new(TlsBytes::new(Vec::new(), Vec::new(), Vec::new()));
        let client = Client::new(
            server_addr,
            "localhost".to_string(),
            shared.clone(),
            Arc::new(Notify::new()),
        );

        let first = tokio::time::timeout(Duration::from_secs(3), client.connect())
            .await
            .expect("connect returns within timeout");
        assert!(
            first.is_err(),
            "empty shared bytes must fail in client_config_from_pem"
        );

        // Swap in valid bytes; this models the reload-time refresh.
        shared.replace(TlsBytes::new(cert_pem, key_pem, ca_certs_pem));

        let connected = tokio::time::timeout(Duration::from_secs(5), client.connect())
            .await
            .expect("connect returns within timeout")
            .expect("rotated bytes must produce a valid session");
        assert!(
            connected.close_reason().is_none(),
            "rebuilt connection must be alive"
        );

        server_handle.abort();
    }

    /// The shared store must not drop the existing session when
    /// bytes are swapped. Only a later reconnect attempt sees the new
    /// material, so an already established connection stays alive across
    /// a reload.
    #[tokio::test(flavor = "current_thread")]
    async fn reload_does_not_disconnect_existing_connection() {
        let (cert_pem, key_pem, ca_certs_pem, certs) = load_test_certs();
        let (server_addr, handshake_count, server_handle) = spawn_handshake_only_server(&certs);

        let shared = SharedTlsBytes::new(TlsBytes::new(
            cert_pem.clone(),
            key_pem.clone(),
            ca_certs_pem.clone(),
        ));
        let client = Client::new(
            server_addr,
            "localhost".to_string(),
            shared.clone(),
            Arc::new(Notify::new()),
        );

        let initial = tokio::time::timeout(Duration::from_secs(5), client.connect())
            .await
            .expect("connect returns within timeout")
            .expect("initial connection succeeds");
        assert!(initial.close_reason().is_none());

        // Wait for the server to record the handshake so the comparison
        // below is deterministic.
        for _ in 0..50 {
            if handshake_count.load(Ordering::SeqCst) >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(handshake_count.load(Ordering::SeqCst), 1);

        // Swap in new (equivalent) bytes; this models a reload that
        // rotated the material. The swap alone must not tear down the
        // connection, and the next `connect()` must reuse it (since the
        // existing connection is still healthy) rather than re-handshake.
        shared.replace(TlsBytes::new(cert_pem, key_pem, ca_certs_pem));

        let after = tokio::time::timeout(Duration::from_secs(5), client.connect())
            .await
            .expect("connect returns within timeout")
            .expect("connection stays open across reload");
        assert!(after.close_reason().is_none());

        // Give the server time to observe a spurious reconnect if the
        // reload path ever decides to tear down the existing connection.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            handshake_count.load(Ordering::SeqCst),
            1,
            "reload must not proactively reconnect the active connection",
        );

        server_handle.abort();
    }

    /// Test material for the A-to-B client-certificate rotation contract.
    ///
    /// Holds a freshly generated root CA plus two leaf client certificates
    /// ("A" and "B") signed by that CA, so the server trusts both and can
    /// accept either during mTLS. The leaf DER bytes are kept alongside
    /// the PEM-encoded `TlsBytes` so tests can assert which certificate
    /// the server actually observed on a given connection.
    struct SharedCaMaterial {
        server_certs: Certs,
        client_a_bytes: TlsBytes,
        client_b_bytes: TlsBytes,
        client_a_leaf_der: Vec<u8>,
        client_b_leaf_der: Vec<u8>,
    }

    struct Leaf {
        der: Vec<u8>,
        fullchain_pem: Vec<u8>,
        key_pem: Vec<u8>,
    }

    struct PeerCertTrackingServer {
        addr: SocketAddr,
        peer_certs: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
        handshake_count: Arc<AtomicUsize>,
        latest_conn: Arc<std::sync::Mutex<Option<ServerHandle>>>,
        handle: tokio::task::JoinHandle<()>,
    }

    /// Builds a CA with three leaves (server, client A, client B) so that
    /// the same server can accept connections presenting either client
    /// certificate. Without this split, an A-to-B rotation test cannot
    /// distinguish the presented material from the handshake outcome.
    fn shared_ca_material() -> SharedCaMaterial {
        use rcgen::{
            BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SanType, string::Ia5String,
        };

        let ca_kp = KeyPair::generate().expect("ca key");
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "reload-test-ca");
        let ca_cert = ca_params.self_signed(&ca_kp).expect("self-sign ca");
        let ca_pem = ca_cert.pem().into_bytes();
        let issuer = rcgen::Issuer::from_ca_cert_pem(&ca_cert.pem(), &ca_kp).expect("ca issuer");

        let make_leaf = |cn: &str| -> Leaf {
            let kp = KeyPair::generate().expect("leaf key");
            let mut params = CertificateParams::default();
            params
                .distinguished_name
                .push(DnType::CommonName, cn.to_string());
            params.subject_alt_names = vec![SanType::DnsName(
                Ia5String::try_from("localhost").expect("valid SAN"),
            )];
            let cert = params.signed_by(&kp, &issuer).expect("sign leaf");
            let mut fullchain_pem = cert.pem().into_bytes();
            fullchain_pem.extend_from_slice(&ca_pem);
            Leaf {
                der: cert.der().to_vec(),
                fullchain_pem,
                key_pem: kp.serialize_pem().into_bytes(),
            }
        };

        let server = make_leaf("reload-test-server");
        let first = make_leaf("reload-test-client-first");
        let second = make_leaf("reload-test-client-second");

        let server_certs =
            Certs::try_new(&server.fullchain_pem, &server.key_pem, &[ca_pem.as_slice()])
                .expect("server certs parse");

        SharedCaMaterial {
            server_certs,
            client_a_bytes: TlsBytes::new(first.fullchain_pem, first.key_pem, vec![ca_pem.clone()]),
            client_b_bytes: TlsBytes::new(second.fullchain_pem, second.key_pem, vec![ca_pem]),
            client_a_leaf_der: first.der,
            client_b_leaf_der: second.der,
        }
    }

    /// Spawns a server that records the DER-encoded leaf certificate the
    /// client presented on each accepted connection. Used to prove that a
    /// post-reload reconnect actually sends the rotated client cert on
    /// the wire rather than merely producing another valid handshake.
    ///
    /// The returned `latest_conn` handle lets the test trigger a reconnect
    /// by closing the most recently accepted session from the server side.
    fn spawn_server_tracking_peer_certs(certs: &Certs) -> PeerCertTrackingServer {
        let server_endpoint = test_manager::listener(
            create_test_server_config(certs),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
        );
        let server_addr = server_endpoint.local_addr().expect("read server address");
        let peer_certs: Arc<std::sync::Mutex<Vec<Vec<u8>>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let handshake_count = Arc::new(AtomicUsize::new(0));
        let latest_conn: Arc<std::sync::Mutex<Option<ServerHandle>>> =
            Arc::new(std::sync::Mutex::new(None));
        let peer_certs_for_task = peer_certs.clone();
        let handshake_count_for_task = handshake_count.clone();
        let latest_conn_for_task = latest_conn.clone();
        let handle = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            while let Ok(Some(conn)) = server_endpoint.accept().await {
                let peer_certs = peer_certs_for_task.clone();
                let handshake_count = handshake_count_for_task.clone();
                let latest_conn = latest_conn_for_task.clone();
                connections.spawn(async move {
                    let Ok((connection, mut incoming)) = test_manager::accept(conn).await else {
                        return;
                    };
                    if let Some(chain) = connection.peer_certificates()
                        && let Some(leaf) = chain.chain().first()
                    {
                        peer_certs
                            .lock()
                            .expect("peer_certs lock")
                            .push(leaf.clone());
                    }
                    handshake_count.fetch_add(1, Ordering::SeqCst);
                    *latest_conn.lock().expect("latest_conn lock") = Some(connection.clone());
                    while incoming.accept().await.is_ok() {}
                });
            }
        });
        PeerCertTrackingServer {
            addr: server_addr,
            peer_certs,
            handshake_count,
            latest_conn,
            handle,
        }
    }

    /// End-to-end client-cert rotation contract (#314): an initial
    /// connection presents cert A; a reload updates shared bytes to B
    /// while the active connection stays alive; a later reconnect
    /// (after the active session ends naturally) presents B on the wire.
    #[tokio::test(flavor = "current_thread")]
    async fn reconnect_presents_rotated_client_certificate_after_reload() {
        let material = shared_ca_material();
        let server = spawn_server_tracking_peer_certs(&material.server_certs);

        let shared = SharedTlsBytes::new(material.client_a_bytes);
        let client = Client::new(
            server.addr,
            "localhost".to_string(),
            shared.clone(),
            Arc::new(Notify::new()),
        );

        let initial = tokio::time::timeout(Duration::from_secs(5), client.connect())
            .await
            .expect("connect returns within timeout")
            .expect("initial connect with A succeeds");
        assert!(initial.close_reason().is_none());

        for _ in 0..50 {
            if server.handshake_count.load(Ordering::SeqCst) >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(server.handshake_count.load(Ordering::SeqCst), 1);
        assert_eq!(
            server
                .peer_certs
                .lock()
                .expect("peer_certs lock")
                .first()
                .cloned(),
            Some(material.client_a_leaf_der.clone()),
            "initial connection must present client cert A",
        );

        // Reload: swap shared bytes to B. The active connection must
        // remain alive, and the swap alone must not trigger a
        // server-side reconnect.
        shared.replace(material.client_b_bytes);
        assert!(
            initial.close_reason().is_none(),
            "swapping shared bytes must not tear down the active connection",
        );

        // Simulate the active session ending naturally (for example,
        // the server closing after rotating its own material). The
        // next `connect()` must rebuild using the rotated B bytes.
        server
            .latest_conn
            .lock()
            .expect("latest_conn lock")
            .as_ref()
            .expect("server has a live connection")
            .close(ApplicationCode::default(), b"rotate");

        // Wait for the close frame to propagate.
        for _ in 0..50 {
            if initial.close_reason().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            initial.close_reason().is_some(),
            "server-initiated close must propagate to the client",
        );

        let reconnected = tokio::time::timeout(Duration::from_secs(5), client.connect())
            .await
            .expect("reconnect returns within timeout")
            .expect("reconnect with B succeeds");
        assert!(reconnected.close_reason().is_none());

        for _ in 0..50 {
            if server.handshake_count.load(Ordering::SeqCst) >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(server.handshake_count.load(Ordering::SeqCst), 2);

        let observed = server.peer_certs.lock().expect("peer_certs lock").clone();
        assert_eq!(observed.len(), 2, "server records both connections");
        assert_eq!(
            observed[0], material.client_a_leaf_der,
            "first connection must have presented A",
        );
        assert_eq!(
            observed[1], material.client_b_leaf_der,
            "post-reload reconnect must present the rotated client cert B",
        );

        server.handle.abort();
    }

    /// Exercises the real SIGHUP reload handoff: `main.rs` notifies
    /// `shutdown` on `tls_reload`, which drives `request_client.run()`
    /// to exit. With the shared connection storage, dropping the
    /// spawned task must NOT drop the underlying session, because the outer `main`
    /// scope (modeled here by the retained `client` handle) keeps a
    /// clone of the shared `Arc`. The next reconnect attempt must
    /// observe the existing session rather than reopening a new one,
    /// which is how #314's "do not disconnect the active manager/
    /// control connection" contract is enforced on the wire.
    #[tokio::test(flavor = "current_thread")]
    async fn run_shutdown_preserves_active_manager_connection() {
        let (cert_pem, key_pem, ca_certs_pem, certs) = load_test_certs();
        let (server_addr, handshake_count, server_handle) = spawn_handshake_only_server(&certs);

        let shared = SharedTlsBytes::new(TlsBytes::new(cert_pem, key_pem, ca_certs_pem));
        let client = Client::new(
            server_addr,
            "localhost".to_string(),
            shared,
            Arc::new(Notify::new()),
        );

        let initial = tokio::time::timeout(Duration::from_secs(5), client.connect())
            .await
            .expect("connect returns within timeout")
            .expect("initial connect succeeds");
        assert!(initial.close_reason().is_none());

        for _ in 0..50 {
            if handshake_count.load(Ordering::SeqCst) >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(handshake_count.load(Ordering::SeqCst), 1);
        drop(initial);

        // Drive the same shutdown pattern `main.rs` uses on
        // `tls_reload`: spawn `run()` against a fresh coordinator, then
        // request cancellation to terminate the task.
        let coordinator = CancellationCoordinator::new();
        let coordinator_for_task = coordinator.clone();
        let mut client_for_task = client.clone();
        let run_task = tokio::spawn(async move { client_for_task.run(coordinator_for_task).await });

        // Allow the spawned task to enter its select loop.
        tokio::time::sleep(Duration::from_millis(50)).await;

        coordinator.request_cancellation("test shutdown");
        tokio::time::timeout(Duration::from_secs(2), run_task)
            .await
            .expect("run exits promptly")
            .expect("run task joins")
            .expect("run returns Ok on shutdown");

        // The outer handle still owns the shared connection state,
        // so the session must be intact. If `run()` shutdown had
        // dropped the connection, `close_reason()` would be `Some`.
        let reused = tokio::time::timeout(Duration::from_secs(5), client.connect())
            .await
            .expect("post-shutdown connect returns within timeout")
            .expect("post-shutdown connect succeeds");
        assert!(
            reused.close_reason().is_none(),
            "run() shutdown must not drop the active manager/control connection",
        );

        // No new handshake means the session was reused rather than
        // re-established, which is the wire-level contract required by
        // #314.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            handshake_count.load(Ordering::SeqCst),
            1,
            "shutdown must preserve the session; no second handshake should occur",
        );

        server_handle.abort();
    }

    // =========================================================================
    // IdleModeHandler tests
    // =========================================================================

    #[tokio::test(flavor = "current_thread")]
    async fn idle_mode_handler_update_config() {
        // Test: IdleModeHandler's update_config should notify config_reload
        let config_reload = Arc::new(Notify::new());
        let mut handler = IdleModeHandler {
            config_reload: config_reload.clone(),
        };

        // Spawn a task to wait for notification
        let wait_task = tokio::spawn(async move {
            config_reload.notified().await;
        });

        // Notify
        let result = handler.update_config().await;
        assert!(result.is_ok());

        // Verify notification was received
        let received = tokio::time::timeout(Duration::from_millis(100), wait_task)
            .await
            .expect("No Timeout");
        assert!(received.is_ok());
    }
}
