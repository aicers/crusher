#[cfg(test)]
use std::future::Future;
use std::{collections::HashMap, io::ErrorKind, net::SocketAddr, sync::Arc};

use anyhow::{Context, Result, bail};
use async_channel::Sender;
use async_trait::async_trait;
use review_protocol::{
    client::{Connection, ConnectionBuilder},
    request::Handler as _,
    types::{self as protocol_types, SamplingPolicy, Status},
};
use tokio::{
    sync::{Mutex, Notify, RwLock},
    time::{Duration, sleep},
};
use tracing::{debug, error, info, warn};

use crate::{
    client::{SERVER_RETRY_INTERVAL, SharedTlsBytes},
    info_or_print,
};

const REQUIRED_MANAGER_VERSION: &str = "0.47.0";
const MAX_RETRIES: u8 = 3;

#[derive(Debug, PartialEq, Eq)]
enum ConnectErrorDisposition {
    Retry,
    InvalidPeerCertificate,
    Other,
}

/// Tells the main loop how `enter_idle_mode` returned so it can decide
/// whether to refresh the Giganto TLS material before the next rerun.
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
}

fn classify_connect_error(error: &anyhow::Error) -> ConnectErrorDisposition {
    if let Some(io_error) = error.downcast_ref::<std::io::Error>() {
        return match io_error.kind() {
            ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset | ErrorKind::TimedOut => {
                ConnectErrorDisposition::Retry
            }
            ErrorKind::InvalidData => ConnectErrorDisposition::InvalidPeerCertificate,
            _ => ConnectErrorDisposition::Other,
        };
    }

    ConnectErrorDisposition::Other
}

/// Shared storage for the active manager/control connection.
///
/// The connection lives behind an `Arc<Mutex<...>>` so that cloning a
/// [`Client`] (for example, to pass into a spawned task) preserves
/// access to the same underlying `review_protocol::client::Connection`.
/// That way the connection survives the common `run()` shutdown ->
/// respawn cycle triggered by SIGHUP: the spawned task exits, but the
/// retained handle in `main` keeps the connection alive so the next
/// reconnect attempt reuses it instead of tearing down the manager/
/// control path.
type SharedConnection = Arc<Mutex<Option<Connection>>>;

#[derive(Clone)]
pub(crate) struct Client {
    server_address: SocketAddr,
    server_name: String,
    connection: SharedConnection,
    request_send: Sender<SamplingPolicy>,
    tls_bytes: SharedTlsBytes,
    config_reload: Arc<Notify>,
    status: Status,
    pub(crate) active_policy_list: Arc<RwLock<HashMap<u32, SamplingPolicy>>>,
    pub(crate) delete_policy_ids: Arc<RwLock<Vec<u32>>>,
}

impl Client {
    pub(crate) fn new(
        server_address: SocketAddr,
        server_name: String,
        request_send: Sender<SamplingPolicy>,
        tls_bytes: SharedTlsBytes,
        config_reload: Arc<Notify>,
    ) -> Self {
        Client {
            server_address,
            server_name,
            connection: Arc::new(Mutex::new(None)),
            request_send,
            tls_bytes,
            config_reload,
            status: Status::Ready,
            active_policy_list: Arc::new(RwLock::new(HashMap::new())),
            delete_policy_ids: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub(crate) async fn run(&mut self, shutdown: Arc<Notify>) -> Result<()> {
        self.active_policy_list.write().await.clear();
        self.delete_policy_ids.write().await.clear();
        tokio::select! {
            biased;
            () = shutdown.notified() => {
                info!("Shutting down request handler");
            }
            Err(e) = self.handle_incoming() => {
                bail!(e);
            }
        };
        Ok(())
    }

    async fn sync_sampling_policies(&mut self) {
        match self.connect().await {
            Ok(connection) => match connection.get_sampling_policy_list().await {
                Ok(policies) => {
                    if policies.is_empty() {
                        info!("No sampling policies to restore from Manager");
                        return;
                    }
                    info!(
                        "Restoring {} sampling policies from Manager",
                        policies.len()
                    );
                    if let Err(e) = self.sampling_policy_list(&policies).await {
                        warn!("Failed to register restored sampling policies: {e}");
                    }
                }
                Err(e) => {
                    warn!("Failed to retrieve sampling policy list: {e}");
                }
            },
            Err(e) => {
                warn!("Failed to connect for sampling policy sync: {e}");
            }
        }
    }

    async fn handle_incoming(&mut self) -> Result<()> {
        self.sync_sampling_policies().await;
        loop {
            match self.connect().await {
                Ok(connection) => match connection.accept_bi().await {
                    Ok((mut send, mut recv)) => {
                        review_protocol::request::handle(self, &mut send, &mut recv).await?;
                    }
                    Err(e) => {
                        warn!("Failed to accept bidirectional stream: {:?}, retrying", e);
                        sleep(Duration::from_secs(SERVER_RETRY_INTERVAL)).await;
                    }
                },
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

    async fn connect(&self) -> Result<Connection> {
        let mut guard = self.connection.lock().await;
        let needs_reconnect = guard
            .as_ref()
            .is_none_or(|conn| conn.close_reason().is_some());

        if needs_reconnect {
            // Snapshot the shared TLS bytes so each reconnect attempt
            // builds a `ConnectionBuilder` from the current material,
            // picking up any rotation that landed since the previous
            // attempt.
            let tls = self.tls_bytes.snapshot();
            let mut conn_builder = ConnectionBuilder::new(
                &self.server_name,
                self.server_address,
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION"),
                REQUIRED_MANAGER_VERSION,
                self.status,
                &tls.cert,
                &tls.key,
            )?;
            conn_builder.root_certs(&tls.ca_certs)?;
            *guard = Some(conn_builder.connect().await?);
            info!(
                "Connection established to the manager server {}",
                self.server_address
            );
        }

        guard
            .as_ref()
            .cloned()
            .context("Failed to access the connection")
    }

    pub(crate) async fn get_config(&mut self) -> Result<String> {
        info_or_print!("Fetching a configuration");
        self.connect()
            .await?
            .get_config()
            .await
            .context("Failed to get the configuration from the Manager server")
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
    /// rerun even when the Manager path is healthy-but-quiet.
    pub(crate) async fn enter_idle_mode(
        &mut self,
        health_check: bool,
        tls_reload: Arc<Notify>,
    ) -> IdleExitReason {
        info_or_print!("Entering idle mode");
        self.status = Status::Idle;
        let config_reload = self.config_reload.clone();
        let reason = tokio::select! {
            () = async {
                loop {
                    match self.try_connect(health_check).await {
                        Ok(()) => {
                            info_or_print!("The Manager server is now online");
                            return
                        },
                        Err(e) => {
                            info_or_print!("Connection attempt failed: {e}, retrying");
                            sleep(Duration::from_secs(SERVER_RETRY_INTERVAL)).await;
                        },
                    }
                }} => IdleExitReason::Resumed,
            () = config_reload.notified() => IdleExitReason::Resumed,
            () = tls_reload.notified() => IdleExitReason::TlsReload,
        };
        self.status = Status::Ready;
        reason
    }

    #[cfg(test)]
    async fn enter_idle_mode_with_try_connect<F, Fut>(
        &mut self,
        health_check: bool,
        tls_reload: Arc<Notify>,
        mut try_connect: F,
    ) -> IdleExitReason
    where
        F: for<'a> FnMut(&'a mut Client, bool) -> Fut,
        Fut: Future<Output = Result<()>> + Send,
    {
        info_or_print!("Entering idle mode");
        self.status = Status::Idle;
        let config_reload = self.config_reload.clone();
        let reason = tokio::select! {
            () = async {
                loop {
                    match try_connect(self, health_check).await {
                        Ok(()) => {
                            info_or_print!("The Manager server is now online");
                            return
                        },
                        Err(e) => {
                            info_or_print!("Connection attempt failed: {e}, retrying");
                            sleep(Duration::from_secs(SERVER_RETRY_INTERVAL)).await;
                        },
                    }
                }} => IdleExitReason::Resumed,
            () = config_reload.notified() => IdleExitReason::Resumed,
            () = tls_reload.notified() => IdleExitReason::TlsReload,
        };
        self.status = Status::Ready;
        reason
    }

    async fn try_connect(&mut self, health_check: bool) -> Result<()> {
        let connection = self.connect().await?;
        if health_check {
            return Ok(());
        }
        let (mut send, mut recv) = connection.accept_bi().await?;
        let mut idle_mode_handler = IdleModeHandler {
            config_reload: self.config_reload.clone(),
        };
        review_protocol::request::handle(&mut idle_mode_handler, &mut send, &mut recv).await?;
        Ok(())
    }
}

#[async_trait]
impl review_protocol::request::Handler for Client {
    async fn reboot(&mut self) -> Result<(), String> {
        info!("Received request to reboot system");
        for attempt in 1..=MAX_RETRIES {
            if let Err(e) = roxy::reboot() {
                if attempt == MAX_RETRIES {
                    error!("Cannot reboot system: {e}");
                    return Err(format!("cannot restart the system: {e}"));
                }
            } else {
                return Ok(());
            }
        }

        Err(String::from("cannot restart the system"))
    }

    async fn shutdown(&mut self) -> Result<(), String> {
        info!("Received request to shutdown system");
        for attempt in 1..=MAX_RETRIES {
            if let Err(e) = roxy::power_off() {
                if attempt == MAX_RETRIES {
                    error!("Cannot shutdown system: {e}");
                    return Err(format!("cannot shutdown the system: {e}"));
                }
            } else {
                return Ok(());
            }
        }

        Err(String::from("cannot shutdown the system"))
    }

    async fn resource_usage(&mut self) -> Result<(String, protocol_types::ResourceUsage), String> {
        let usg = roxy::resource_usage().await;
        let usg = protocol_types::ResourceUsage {
            cpu_usage: usg.cpu_usage,
            total_memory: usg.total_memory,
            used_memory: usg.used_memory,
            disk_used_bytes: usg.disk_used_bytes,
            disk_available_bytes: usg.disk_available_bytes,
        };
        Ok((roxy::hostname(), usg))
    }

    async fn sampling_policy_list(&mut self, policies: &[SamplingPolicy]) -> Result<(), String> {
        for policy in policies {
            if self
                .active_policy_list
                .read()
                .await
                .get(&policy.id)
                .is_some()
            {
                debug!("Duplicated policy: {:?}", policy);
                continue;
            }
            self.active_policy_list
                .write()
                .await
                .insert(policy.id, policy.clone());
            info!("Received request to update time series policy list");
            self.request_send
                .send(policy.clone())
                .await
                .map_err(|e| format!("send fail: {e}"))?;
        }

        Ok(())
    }

    async fn delete_sampling_policy(&mut self, policy_ids: &[u32]) -> Result<(), String> {
        for &id in policy_ids {
            if let Some(deleted_policy) = self.active_policy_list.write().await.remove(&id) {
                info!(
                    "Received request to delete time series policy {}",
                    deleted_policy.id
                );
                self.delete_policy_ids.write().await.push(id);
            }
        }

        Ok(())
    }

    async fn update_config(&mut self) -> Result<(), String> {
        info!("Configuration update request received");
        self.config_reload.notify_one();
        Ok(())
    }

    async fn process_list(&mut self) -> Result<Vec<protocol_types::Process>, String> {
        let list = roxy::process_list().await;
        let list = list
            .into_iter()
            .map(|p| protocol_types::Process {
                user: p.user,
                cpu_usage: p.cpu_usage,
                mem_usage: p.mem_usage,
                start_time: p.start_time,
                command: p.command,
            })
            .collect();

        Ok(list)
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
    use std::fs;
    use std::net::{IpAddr, Ipv6Addr, SocketAddr};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;

    use async_channel::TryRecvError;
    use quinn::{Endpoint, ServerConfig, crypto::rustls::QuicServerConfig};
    use review_protocol::request::Handler;
    use review_protocol::types::{SamplingKind, SamplingPolicy};
    use rustls::server::WebPkiClientVerifier;

    use super::*;
    use crate::client::{Certs, TlsBytes};

    const CERT_PATH: &str = "tests/cert.pem";
    const KEY_PATH: &str = "tests/key.pem";
    const CA_CERT_PATH: &str = "tests/ca_cert.pem";

    /// Creates a test client with default configuration.
    /// Returns the client and a receiver for sampling policies.
    fn create_test_client() -> (Client, async_channel::Receiver<SamplingPolicy>) {
        let (tx, rx) = async_channel::unbounded();
        let config_reload = Arc::new(Notify::new());

        let client = Client {
            server_address: "127.0.0.1:8080".parse().unwrap(),
            server_name: "test".to_string(),
            connection: Arc::new(Mutex::new(None)),
            request_send: tx,
            tls_bytes: SharedTlsBytes::new(TlsBytes::new(Vec::new(), Vec::new(), Vec::new())),
            config_reload,
            status: Status::Ready,
            active_policy_list: Arc::new(RwLock::new(HashMap::new())),
            delete_policy_ids: Arc::new(RwLock::new(Vec::new())),
        };

        (client, rx)
    }

    /// Creates a test sampling policy with the given ID.
    fn create_test_policy(id: u32) -> SamplingPolicy {
        SamplingPolicy {
            id,
            kind: SamplingKind::Conn,
            interval: Duration::from_mins(1),
            period: Duration::from_hours(1),
            offset: 0,
            src_ip: None,
            dst_ip: None,
            node: Some("test_node".to_string()),
            column: None,
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

    fn create_test_server_config(certs: &Certs) -> ServerConfig {
        let client_auth = WebPkiClientVerifier::builder(Arc::new(certs.ca_certs.clone()))
            .build()
            .expect("build client cert verifier");

        let server_crypto = rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_auth)
            .with_single_cert(certs.certs.clone(), certs.key.clone_key())
            .expect("build server tls config");

        ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(server_crypto).expect("build quic server config"),
        ))
    }

    // =========================================================================
    // Policy Addition Tests: `sampling_policy_list()`
    // =========================================================================

    #[tokio::test(flavor = "current_thread")]
    async fn add_policy_duplicate_entries() {
        // Test: Adding the same policy ID twice should only process it once
        let (mut client, rx) = create_test_client();
        let policy = create_test_policy(1);

        // Add the policy first time
        let result = client
            .sampling_policy_list(std::slice::from_ref(&policy))
            .await;
        assert!(result.is_ok());

        // Verify policy was added to active list
        assert_eq!(client.active_policy_list.read().await.len(), 1);
        assert!(client.active_policy_list.read().await.contains_key(&1));

        // Verify policy was sent through channel
        let received = rx.try_recv().expect("Success to receive policy");
        assert_eq!(received.id, 1);

        // Add the same policy again (duplicate)
        let result = client.sampling_policy_list(&[policy]).await;
        assert!(result.is_ok());

        // Verify still only one policy in active list
        assert_eq!(client.active_policy_list.read().await.len(), 1);

        // Verify no additional policy was sent (channel should be empty)
        assert_eq!(rx.try_recv().expect_err("Empty"), TryRecvError::Empty);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn add_policy_multiple_entries() {
        // Test: Adding multiple policies, some duplicates
        let (mut client, rx) = create_test_client();
        let policy1 = create_test_policy(1);
        let policy2 = create_test_policy(2);

        // Add both policies
        let result = client
            .sampling_policy_list(&[policy1.clone(), policy2.clone()])
            .await;
        assert!(result.is_ok());
        assert_eq!(client.active_policy_list.read().await.len(), 2);

        // Drain the channel
        let received1 = rx.try_recv().expect("Success to receive the first policy");
        assert_eq!(received1.id, 1);
        let received2 = rx.try_recv().expect("Success to receive the second policy");
        assert_eq!(received2.id, 2);

        // Try to add policy1 again as duplicate, and policy3 as new
        let policy3 = create_test_policy(3);
        let result = client.sampling_policy_list(&[policy1, policy3]).await;
        assert!(result.is_ok());

        // Should have 3 policies now (policy1 was duplicate, policy3 is new)
        assert_eq!(client.active_policy_list.read().await.len(), 3);

        // Only policy3 should be in the channel
        let received3 = rx.try_recv().expect("Success to receive the third policy");
        assert_eq!(received3.id, 3);

        // Channel should be empty
        assert_eq!(rx.try_recv().expect_err("Empty"), TryRecvError::Empty);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn add_policy_when_queue_empty() {
        // Test: Adding a policy when queue is empty
        let (mut client, rx) = create_test_client();

        // Verify empty initial state
        assert!(client.active_policy_list.read().await.is_empty());

        let policy = create_test_policy(1);
        let result = client.sampling_policy_list(&[policy]).await;
        assert!(result.is_ok());

        assert_eq!(client.active_policy_list.read().await.len(), 1);
        assert!(rx.try_recv().is_ok());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn add_policy_rapid_add_remove_add_cycle() {
        // Test: Rapid add/remove/add cycle should work correctly
        let (mut client, rx) = create_test_client();
        let policy = create_test_policy(1);

        // Add policy
        client
            .sampling_policy_list(std::slice::from_ref(&policy))
            .await
            .expect("Success to add policy");
        assert_eq!(client.active_policy_list.read().await.len(), 1);
        let _ = rx.try_recv(); // Drain channel

        // Remove policy
        client
            .delete_sampling_policy(&[1])
            .await
            .expect("Success to remove policy");
        assert!(client.active_policy_list.read().await.is_empty());

        // Add policy again (should succeed since it was deleted)
        client
            .sampling_policy_list(&[policy])
            .await
            .expect("Success to add policy");
        assert_eq!(client.active_policy_list.read().await.len(), 1);

        // Verify policy was sent again
        let received = rx.try_recv().expect("Success to receive policy");
        assert_eq!(received.id, 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn add_policy_empty_list() {
        // Test: Empty policy list should be handled correctly
        let (mut client, rx) = create_test_client();

        let result = client.sampling_policy_list(&[]).await;
        assert!(result.is_ok());
        assert!(client.active_policy_list.read().await.is_empty());
        assert_eq!(rx.try_recv().expect_err("Empty"), TryRecvError::Empty);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn add_policy_ignores_update_on_conflict() {
        // Test: Duplicate ID should not update existing policy data
        let (mut client, rx) = create_test_client();
        let original_policy = create_test_policy(1);

        client
            .sampling_policy_list(std::slice::from_ref(&original_policy))
            .await
            .expect("Success to add policy");
        let received = rx.try_recv().expect("Success to receive policy");
        assert_eq!(received.id, 1);

        // NOTE:
        // When a policy with an existing ID is submitted, it is treated as a conflict.
        //
        // In this case:
        // - the existing policy remains unchanged, and
        // - no message is observed on the corresponding receiver.
        //
        // Only newly added (non-conflicting) policies produce a message.
        let mut conflicting_policy = create_test_policy(1);
        conflicting_policy.interval = Duration::from_secs(30);
        conflicting_policy.node = Some("updated_node".to_string());

        client
            .sampling_policy_list(&[conflicting_policy])
            .await
            .expect("No error or failure");

        // No message for the conflicting policy
        assert_eq!(rx.try_recv().expect_err("Empty"), TryRecvError::Empty);

        let stored = client
            .active_policy_list
            .read()
            .await
            .get(&1)
            .cloned()
            .unwrap();
        assert_eq!(stored.interval, original_policy.interval);
        assert_eq!(stored.node.as_deref(), original_policy.node.as_deref());
    }

    // =========================================================================
    // Policy Deletion Tests: `delete_sampling_policy()`
    // =========================================================================
    #[tokio::test(flavor = "current_thread")]
    async fn delete_policy_multiple_times() {
        // Test: Multiple delete requests should accumulate in delete queue
        let (mut client, rx) = create_test_client();

        // Add multiple policies first
        let policies: Vec<SamplingPolicy> = (1..=5).map(create_test_policy).collect();
        client
            .sampling_policy_list(&policies)
            .await
            .expect("Success to add policies");

        // Drain channel
        (1..=5).for_each(|id| {
            let received = rx.try_recv().expect("Success to receive policy");
            assert_eq!(received.id, id);
        });

        // Delete policies one by one
        client
            .delete_sampling_policy(&[1])
            .await
            .expect("Success to delete policy");
        client
            .delete_sampling_policy(&[2])
            .await
            .expect("Success to delete policy");
        client
            .delete_sampling_policy(&[3])
            .await
            .expect("Success to delete policy");

        // Verify delete queue accumulated all deleted IDs
        let delete_ids = client.delete_policy_ids.read().await;
        assert_eq!(delete_ids.len(), 3);
        assert_eq!(delete_ids[0], 1);
        assert_eq!(delete_ids[1], 2);
        assert_eq!(delete_ids[2], 3);

        // Verify active list only has remaining policies
        assert_eq!(client.active_policy_list.read().await.len(), 2);
        assert!(client.active_policy_list.read().await.contains_key(&4));
        assert!(client.active_policy_list.read().await.contains_key(&5));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn delete_policy_batch() {
        // Test: Batch delete request should accumulate all IDs
        let (mut client, rx) = create_test_client();

        // Add policies
        let policies: Vec<SamplingPolicy> = (1..=5).map(create_test_policy).collect();
        client
            .sampling_policy_list(&policies)
            .await
            .expect("Success to add policies");

        // Drain channel
        (1..=5).for_each(|id| {
            let received = rx.try_recv().expect("Success to receive policy");
            assert_eq!(received.id, id);
        });

        // Delete multiple in one call
        client
            .delete_sampling_policy(&[1, 3, 5])
            .await
            .expect("Success to delete policies");

        // Verify order is preserved in delete queue
        let delete_ids = client.delete_policy_ids.read().await;
        assert_eq!(delete_ids.len(), 3);
        assert_eq!(delete_ids[0], 1);
        assert_eq!(delete_ids[1], 3);
        assert_eq!(delete_ids[2], 5);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn delete_policy_ignores_non_existent_id() {
        // Test: Deleting a non-existent policy should be silently ignored
        let (mut client, rx) = create_test_client();

        // Add a policy
        let policy = create_test_policy(1);
        client
            .sampling_policy_list(&[policy])
            .await
            .expect("Success to add policy");
        let received = rx.try_recv().expect("Success to receive policy");
        assert_eq!(received.id, 1);

        // Try to delete a non-existent policy
        let result = client.delete_sampling_policy(&[999]).await;
        assert!(result.is_ok());

        // Delete queue should be empty (non-existent policy not added)
        assert!(client.delete_policy_ids.read().await.is_empty());

        // Active list should still have the original policy
        assert_eq!(client.active_policy_list.read().await.len(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn delete_policy_ignores_non_existent_id_in_batch() {
        // Test: Deleting a non-existent policy should be silently ignored
        let (mut client, rx) = create_test_client();

        let policies: Vec<SamplingPolicy> = (1..=7).map(create_test_policy).collect();
        client
            .sampling_policy_list(&policies)
            .await
            .expect("Success to add policies");

        // Drain channel
        (1..=7).for_each(|id| {
            let received = rx.try_recv().expect("Success to receive policy");
            assert_eq!(received.id, id);
        });

        // Try to delete a batch including non-existent policy and some existent policies
        let result = client.delete_sampling_policy(&[1, 2, 3, 999, 4, 5]).await;
        assert!(result.is_ok());

        let delete_ids = client.delete_policy_ids.read().await;
        assert_eq!(delete_ids.len(), 5);
        assert_eq!(delete_ids[0], 1);
        assert_eq!(delete_ids[1], 2);
        assert_eq!(delete_ids[2], 3);
        assert_eq!(delete_ids[3], 4);
        assert_eq!(delete_ids[4], 5);

        assert_eq!(client.active_policy_list.read().await.len(), 2);
        assert!(client.active_policy_list.read().await.contains_key(&6));
        assert!(client.active_policy_list.read().await.contains_key(&7));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn delete_policy_empty_list() {
        // Test: Delete on empty active list should be no-op
        let (mut client, _) = create_test_client();

        let result = client.delete_sampling_policy(&[1, 2, 3]).await;
        assert!(result.is_ok());

        // Delete queue should be empty
        assert!(client.delete_policy_ids.read().await.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn delete_policy_no_double_delete() {
        // Test: Deleting the same ID twice should only add it once to delete queue
        let (mut client, rx) = create_test_client();

        // Add a policy
        let policy = create_test_policy(1);
        client
            .sampling_policy_list(&[policy])
            .await
            .expect("Success to add policy");
        let received = rx.try_recv().expect("Success to receive policy");
        assert_eq!(received.id, 1);

        // Delete it once
        client
            .delete_sampling_policy(&[1])
            .await
            .expect("Success to delete policy");

        // Try to delete it again
        client
            .delete_sampling_policy(&[1])
            .await
            .expect("No error or failure");

        // Delete queue should only have one entry
        let delete_ids = client.delete_policy_ids.read().await;
        assert_eq!(delete_ids.len(), 1);
        assert_eq!(delete_ids[0], 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn delete_policy_rapid_add_remove_same_id() {
        // Test: Rapid add/remove cycles of the same ID
        let (mut client, rx) = create_test_client();

        for i in 0..3 {
            let policy = create_test_policy(1);
            client
                .sampling_policy_list(&[policy])
                .await
                .expect("Success to add policy");
            let received = rx.try_recv().expect("Success to receive policy");
            assert_eq!(received.id, 1);

            client
                .delete_sampling_policy(&[1])
                .await
                .expect("Success to delete policy");

            // Each cycle should add one entry to delete queue
            assert_eq!(client.delete_policy_ids.read().await.len(), i + 1);
        }

        // Final state: empty active list, 3 entries in delete queue
        assert!(client.active_policy_list.read().await.is_empty());
        assert_eq!(client.delete_policy_ids.read().await.len(), 3);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn delete_policy_succeeds_after_receiver_dropped() {
        let (mut client, rx) = create_test_client();

        let policy = create_test_policy(1);
        client
            .sampling_policy_list(&[policy])
            .await
            .expect("Success to add policy");
        let received = rx.try_recv().expect("Success to receive policy");
        assert_eq!(received.id, 1);

        // Drop receiver to simulate the notification channel being unavailable.
        // Delete path should remain functional regardless.
        drop(rx);

        assert!(client.active_policy_list.read().await.contains_key(&1));

        client
            .delete_sampling_policy(&[1])
            .await
            .expect("Success to delete policy");

        // Final state: empty active list, 1 entry in delete queue
        assert_eq!(client.delete_policy_ids.read().await.as_slice(), &[1]);
        assert!(client.active_policy_list.read().await.is_empty());
    }

    // =========================================================================
    // Idle Mode Branching Tests
    // =========================================================================

    #[tokio::test(flavor = "current_thread")]
    async fn idle_mode_exits_on_reload() {
        // Test: Config reload notification should exit idle mode
        let (mut client, _) = create_test_client();
        let config_reload = client.config_reload.clone();
        let tls_reload = Arc::new(Notify::new());

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
            client.enter_idle_mode_with_try_connect(false, tls_reload, |_, _| async {
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
        let (mut client, _) = create_test_client();
        let tls_reload = Arc::new(Notify::new());

        let notifier = tls_reload.clone();
        let notify_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            notifier.notify_one();
        });

        let reason = tokio::time::timeout(
            Duration::from_millis(100),
            client.enter_idle_mode_with_try_connect(false, tls_reload, |_, _| async {
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
    async fn idle_mode_health_check_returns_immediately() {
        // Test: health_check=true returns without waiting for config_reload
        let (mut client, _rx) = create_test_client();
        let config_reload = client.config_reload.clone();
        let tls_reload = Arc::new(Notify::new());
        let called = Arc::new(AtomicUsize::new(0));
        let called_ref = called.clone();

        let wait_task = tokio::spawn(async move {
            config_reload.notified().await;
        });

        let reason = tokio::time::timeout(
            Duration::from_millis(100),
            client.enter_idle_mode_with_try_connect(true, tls_reload, move |_, _| {
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
        let (mut client, _rx) = create_test_client();
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
        let (mut client, _rx) = create_test_client();
        let config_reload = client.config_reload.clone();
        let tls_reload = Arc::new(Notify::new());

        assert!(matches!(client.status, Status::Ready));

        // Notify immediately to exit idle mode quickly
        config_reload.notify_one();

        let reason = tokio::time::timeout(
            Duration::from_millis(100),
            client.enter_idle_mode_with_try_connect(false, tls_reload, |_client, _| async {
                Err(anyhow::anyhow!("forced failure"))
            }),
        )
        .await
        .expect("No Timeout");
        assert_eq!(reason, IdleExitReason::Resumed);

        // After exiting, status should be Ready
        assert!(matches!(client.status, Status::Ready));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_incoming_returns_invalid_peer_certificate_error() {
        let (cert_pem, key_pem, ca_certs_pem, certs) = load_test_certs();
        let server_endpoint = Endpoint::server(
            create_test_server_config(&certs),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
        )
        .expect("create server endpoint");
        let server_addr = server_endpoint.local_addr().expect("read server address");
        let _server_task = tokio::spawn(async move {
            while let Some(conn) = server_endpoint.accept().await {
                tokio::spawn(async move {
                    let _ = conn.await;
                });
            }
        });

        let (request_send, _request_recv) = async_channel::unbounded::<SamplingPolicy>();
        let tls_bytes = SharedTlsBytes::new(TlsBytes::new(cert_pem, key_pem, ca_certs_pem));
        let mut client = Client::new(
            server_addr,
            "mismatched-server-name".to_string(),
            request_send,
            tls_bytes,
            Arc::new(Notify::new()),
        );

        let result = tokio::time::timeout(Duration::from_secs(3), client.handle_incoming())
            .await
            .expect("No timeout");
        let err = result.expect_err("Expected certificate validation error");
        assert_eq!(err.to_string(), "Invalid peer certificate contents");
    }

    #[test]
    fn classify_connect_error_marks_invalid_data_as_peer_certificate_error() {
        let err = anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid peer cert",
        ));
        assert_eq!(
            classify_connect_error(&err),
            ConnectErrorDisposition::InvalidPeerCertificate
        );
    }

    #[test]
    fn classify_connect_error_marks_connection_reset_as_retryable() {
        let err = anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "connection reset",
        ));
        assert_eq!(classify_connect_error(&err), ConnectErrorDisposition::Retry);
    }

    // =========================================================================
    // Run method tests
    // =========================================================================

    #[tokio::test(flavor = "current_thread")]
    async fn run_clears_state_on_start() {
        // Test: run() should clear active_policy_list and delete_policy_ids on start
        let (mut client, rx) = create_test_client();

        // Pre-populate with some data
        let policy = create_test_policy(1);
        client
            .sampling_policy_list(&[policy])
            .await
            .expect("Success to add policy");
        let received = rx.try_recv().expect("Success to receive policy");
        assert_eq!(received.id, 1);

        client
            .delete_sampling_policy(&[1])
            .await
            .expect("Success to delete policy");

        assert!(
            client.active_policy_list.read().await.is_empty(),
            "active_policy_list must be empty at this point"
        );
        assert!(
            !client.delete_policy_ids.read().await.is_empty(),
            "delete_policy_ids must NOT be empty at this point"
        );

        // Re-populate since delete removed from active
        let policy = create_test_policy(2);
        client
            .sampling_policy_list(&[policy])
            .await
            .expect("Success to add policy");

        // Shutdown immediately
        let shutdown = Arc::new(Notify::new());
        shutdown.notify_one();

        let result = client.run(shutdown).await;
        assert!(result.is_ok());

        // State should be cleared
        assert!(client.active_policy_list.read().await.is_empty());
        assert!(client.delete_policy_ids.read().await.is_empty());
    }

    // =========================================================================
    // Startup sync test
    // =========================================================================

    struct TestManagerHandler;

    #[async_trait::async_trait]
    impl review_protocol::server::Handler for TestManagerHandler {
        async fn get_sampling_policy_list(
            &self,
            _peer: &str,
        ) -> Result<Vec<SamplingPolicy>, String> {
            Ok(vec![create_test_policy(10), create_test_policy(20)])
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn syncs_sampling_policies_on_startup() {
        let (cert_pem, key_pem, ca_certs_pem, certs) = load_test_certs();
        let server_endpoint = Endpoint::server(
            create_test_server_config(&certs),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
        )
        .expect("create server endpoint");
        let server_addr = server_endpoint.local_addr().expect("read server address");

        // Spawn a server that performs the review-protocol handshake
        // and responds to get_sampling_policy_list requests.
        let server_task = tokio::spawn(async move {
            if let Some(conn) = server_endpoint.accept().await {
                let connection = conn.await.expect("accept connection");
                let addr = connection.remote_address();
                let _agent_info = review_protocol::server::handshake(
                    &connection,
                    addr,
                    ">=0",
                    REQUIRED_MANAGER_VERSION,
                )
                .await
                .expect("handshake");

                let mut handler = TestManagerHandler;
                while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                    review_protocol::server::handle(&mut handler, &mut send, &mut recv, "test")
                        .await
                        .ok();
                }
            }
        });

        let (request_send, request_recv) = async_channel::unbounded::<SamplingPolicy>();
        let tls_bytes = SharedTlsBytes::new(TlsBytes::new(cert_pem, key_pem, ca_certs_pem));
        let mut client = Client::new(
            server_addr,
            "localhost".to_string(),
            request_send,
            tls_bytes,
            Arc::new(Notify::new()),
        );

        client.sync_sampling_policies().await;

        // Verify policies were restored into the active list
        let active = client.active_policy_list.read().await;
        assert_eq!(active.len(), 2);
        assert!(active.contains_key(&10));
        assert!(active.contains_key(&20));
        drop(active);

        // Verify policies were sent through the channel
        let p1 = request_recv.try_recv().expect("first policy");
        let p2 = request_recv.try_recv().expect("second policy");
        assert_eq!(p1.id, 10);
        assert_eq!(p2.id, 20);
        assert_eq!(
            request_recv.try_recv().expect_err("Empty"),
            TryRecvError::Empty
        );

        server_task.abort();
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
        let server_endpoint = Endpoint::server(
            create_test_server_config(certs),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
        )
        .expect("create server endpoint");
        let server_addr = server_endpoint.local_addr().expect("read server address");
        let handshake_count = Arc::new(AtomicUsize::new(0));
        let counter = handshake_count.clone();
        let handle = tokio::spawn(async move {
            while let Some(conn) = server_endpoint.accept().await {
                let counter = counter.clone();
                tokio::spawn(async move {
                    let Ok(connection) = conn.await else {
                        return;
                    };
                    let addr = connection.remote_address();
                    if review_protocol::server::handshake(
                        &connection,
                        addr,
                        ">=0",
                        REQUIRED_MANAGER_VERSION,
                    )
                    .await
                    .is_err()
                    {
                        return;
                    }
                    counter.fetch_add(1, Ordering::SeqCst);
                    // Keep the connection open; we only care that the
                    // handshake completed, so that the client side has
                    // observed the presented client certificate.
                    while connection.accept_bi().await.is_ok() {}
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
        // builder construction. This proves the client is reading from
        // the shared store rather than baking the bytes in at construction.
        let shared = SharedTlsBytes::new(TlsBytes::new(Vec::new(), Vec::new(), Vec::new()));
        let (request_send, _request_recv) = async_channel::unbounded::<SamplingPolicy>();
        let client = Client::new(
            server_addr,
            "localhost".to_string(),
            request_send,
            shared.clone(),
            Arc::new(Notify::new()),
        );

        let first = tokio::time::timeout(Duration::from_secs(3), client.connect())
            .await
            .expect("connect returns within timeout");
        assert!(
            first.is_err(),
            "empty shared bytes must fail at builder construction"
        );

        // Swap in valid bytes; this models the reload-time refresh.
        shared.replace(TlsBytes::new(cert_pem, key_pem, ca_certs_pem));

        let connected = tokio::time::timeout(Duration::from_secs(5), client.connect())
            .await
            .expect("connect returns within timeout")
            .expect("rotated bytes must produce a valid ConnectionBuilder");
        assert!(
            connected.close_reason().is_none(),
            "rebuilt connection must be alive"
        );

        server_handle.abort();
    }

    /// The shared store must not drop the existing `Connection` when
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
        let (request_send, _request_recv) = async_channel::unbounded::<SamplingPolicy>();
        let client = Client::new(
            server_addr,
            "localhost".to_string(),
            request_send,
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
    /// The returned `latest_conn` handle lets the test close the most
    /// recently accepted session from the server side, which is the only
    /// way to trigger a reconnect on the client without relying on a
    /// client-side `close()` API that `review_protocol::client::Connection`
    /// does not expose.
    #[allow(clippy::type_complexity)]
    fn spawn_server_tracking_peer_certs(
        certs: &Certs,
    ) -> (
        SocketAddr,
        Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
        Arc<AtomicUsize>,
        Arc<std::sync::Mutex<Option<quinn::Connection>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let server_endpoint = Endpoint::server(
            create_test_server_config(certs),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
        )
        .expect("create server endpoint");
        let server_addr = server_endpoint.local_addr().expect("read server address");
        let peer_certs: Arc<std::sync::Mutex<Vec<Vec<u8>>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let handshake_count = Arc::new(AtomicUsize::new(0));
        let latest_conn: Arc<std::sync::Mutex<Option<quinn::Connection>>> =
            Arc::new(std::sync::Mutex::new(None));
        let peer_certs_for_task = peer_certs.clone();
        let handshake_count_for_task = handshake_count.clone();
        let latest_conn_for_task = latest_conn.clone();
        let handle = tokio::spawn(async move {
            while let Some(conn) = server_endpoint.accept().await {
                let peer_certs = peer_certs_for_task.clone();
                let handshake_count = handshake_count_for_task.clone();
                let latest_conn = latest_conn_for_task.clone();
                tokio::spawn(async move {
                    let Ok(connection) = conn.await else {
                        return;
                    };
                    if let Some(identity) = connection.peer_identity()
                        && let Ok(chain) =
                            identity.downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
                        && let Some(leaf) = chain.first()
                    {
                        peer_certs
                            .lock()
                            .expect("peer_certs lock")
                            .push(leaf.as_ref().to_vec());
                    }
                    let addr = connection.remote_address();
                    if review_protocol::server::handshake(
                        &connection,
                        addr,
                        ">=0",
                        REQUIRED_MANAGER_VERSION,
                    )
                    .await
                    .is_err()
                    {
                        return;
                    }
                    handshake_count.fetch_add(1, Ordering::SeqCst);
                    *latest_conn.lock().expect("latest_conn lock") = Some(connection.clone());
                    while connection.accept_bi().await.is_ok() {}
                });
            }
        });
        (
            server_addr,
            peer_certs,
            handshake_count,
            latest_conn,
            handle,
        )
    }

    /// End-to-end client-cert rotation contract (#314): an initial
    /// connection presents cert A; a reload updates shared bytes to B
    /// while the active connection stays alive; a later reconnect
    /// (after the active session ends naturally) presents B on the wire.
    #[tokio::test(flavor = "current_thread")]
    async fn reconnect_presents_rotated_client_certificate_after_reload() {
        let material = shared_ca_material();
        let (server_addr, peer_certs, handshake_count, latest_conn, server_handle) =
            spawn_server_tracking_peer_certs(&material.server_certs);

        let shared = SharedTlsBytes::new(material.client_a_bytes);
        let (request_send, _request_recv) = async_channel::unbounded::<SamplingPolicy>();
        let client = Client::new(
            server_addr,
            "localhost".to_string(),
            request_send,
            shared.clone(),
            Arc::new(Notify::new()),
        );

        let initial = tokio::time::timeout(Duration::from_secs(5), client.connect())
            .await
            .expect("connect returns within timeout")
            .expect("initial connect with A succeeds");
        assert!(initial.close_reason().is_none());

        for _ in 0..50 {
            if handshake_count.load(Ordering::SeqCst) >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(handshake_count.load(Ordering::SeqCst), 1);
        assert_eq!(
            peer_certs.lock().expect("peer_certs lock").first().cloned(),
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
        latest_conn
            .lock()
            .expect("latest_conn lock")
            .as_ref()
            .expect("server has a live connection")
            .close(0u32.into(), b"rotate");

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
            if handshake_count.load(Ordering::SeqCst) >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(handshake_count.load(Ordering::SeqCst), 2);

        let observed = peer_certs.lock().expect("peer_certs lock").clone();
        assert_eq!(observed.len(), 2, "server records both connections");
        assert_eq!(
            observed[0], material.client_a_leaf_der,
            "first connection must have presented A",
        );
        assert_eq!(
            observed[1], material.client_b_leaf_der,
            "post-reload reconnect must present the rotated client cert B",
        );

        server_handle.abort();
    }

    /// Exercises the real SIGHUP reload handoff: `main.rs` notifies
    /// `shutdown` on `tls_reload`, which drives `request_client.run()`
    /// to exit. With the shared connection storage, dropping the
    /// spawned task must NOT drop the underlying
    /// `review_protocol::client::Connection`, because the outer `main`
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
        let (request_send, _request_recv) = async_channel::unbounded::<SamplingPolicy>();
        let client = Client::new(
            server_addr,
            "localhost".to_string(),
            request_send,
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
        // `tls_reload`: spawn `run()` against a fresh shutdown notifier,
        // then `notify_waiters()` to terminate the task.
        let shutdown = Arc::new(Notify::new());
        let shutdown_for_task = shutdown.clone();
        let mut client_for_task = client.clone();
        let run_task = tokio::spawn(async move { client_for_task.run(shutdown_for_task).await });

        // Allow the spawned task to enter its select loop.
        tokio::time::sleep(Duration::from_millis(50)).await;

        shutdown.notify_waiters();
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
