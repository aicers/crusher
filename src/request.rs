#[cfg(test)]
use std::future::Future;
use std::{collections::HashMap, io::ErrorKind, net::SocketAddr, process::exit, sync::Arc};

use anyhow::{Context, Result, bail};
use async_channel::Sender;
use async_trait::async_trait;
use review_protocol::{
    client::{Connection, ConnectionBuilder},
    types::{self as protocol_types, SamplingPolicy, Status},
};
use tokio::{
    sync::{Notify, RwLock},
    time::{Duration, sleep},
};
use tracing::{debug, error, info, warn};

use crate::{client::SERVER_RETRY_INTERVAL, info_or_print};

const REQUIRED_MANAGER_VERSION: &str = "0.47.0";
const MAX_RETRIES: u8 = 3;

#[derive(Clone)]
pub(crate) struct Client {
    server_address: SocketAddr,
    server_name: String,
    connection: Option<Connection>,
    request_send: Sender<SamplingPolicy>,
    cert: Vec<u8>,
    key: Vec<u8>,
    ca_certs: Vec<Vec<u8>>,
    config_reload: Arc<Notify>,
    status: Status,
    pub(crate) active_policy_list: Arc<RwLock<HashMap<u32, SamplingPolicy>>>,
    pub(crate) delete_policy_ids: Arc<RwLock<Vec<u32>>>,
}

impl Client {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        server_address: SocketAddr,
        server_name: String,
        request_send: Sender<SamplingPolicy>,
        cert: Vec<u8>,
        key: Vec<u8>,
        ca_certs: Vec<Vec<u8>>,
        config_reload: Arc<Notify>,
    ) -> Self {
        Client {
            server_address,
            server_name,
            connection: None,
            request_send,
            cert,
            key,
            ca_certs,
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
            Err(e) = self.handle_incoming() => {
                bail!(e);
            }
            () = shutdown.notified() => {
                info!("Shutting down request handler");
            }
        };
        Ok(())
    }

    async fn handle_incoming(&mut self) -> Result<()> {
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
                    if let Some(e) = e.downcast_ref::<std::io::Error>() {
                        match e.kind() {
                            ErrorKind::ConnectionAborted
                            | ErrorKind::ConnectionReset
                            | ErrorKind::TimedOut => {
                                warn!(
                                    "Retrying connection to {} in {} seconds",
                                    self.server_address, SERVER_RETRY_INTERVAL,
                                );
                                sleep(Duration::from_secs(SERVER_RETRY_INTERVAL)).await;
                                continue;
                            }
                            ErrorKind::InvalidData => {
                                error!("Invalid peer certificate contents");
                                exit(0);
                            }
                            _ => {}
                        }
                    }
                    bail!("Failed to connect to {}: {:?}", self.server_address, e);
                }
            }
        }
    }

    async fn connect(&mut self) -> Result<&Connection> {
        let needs_reconnect = self
            .connection
            .as_ref()
            .is_none_or(|conn| conn.close_reason().is_some());

        if needs_reconnect {
            let mut conn_builder = ConnectionBuilder::new(
                &self.server_name,
                self.server_address,
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION"),
                REQUIRED_MANAGER_VERSION,
                self.status,
                &self.cert,
                &self.key,
            )?;
            conn_builder.root_certs(&self.ca_certs)?;
            self.connection = Some(conn_builder.connect().await?);
            info!(
                "Connection established to the manager server {}",
                self.server_address
            );
        }

        self.connection
            .as_ref()
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
    pub(crate) async fn enter_idle_mode(&mut self, health_check: bool) {
        info_or_print!("Entering idle mode");
        self.status = Status::Idle;
        let config_reload = self.config_reload.clone();
        tokio::select! {
            () = async {
                loop {
                    match self.try_connect(health_check).await {
                        Ok(()) => {
                            info_or_print!("The Manager server is now online");
                            self.status = Status::Ready;
                            return
                        },
                        Err(e) => {
                            info_or_print!("Connection attempt failed: {e}, retrying");
                            sleep(Duration::from_secs(SERVER_RETRY_INTERVAL)).await;
                        },
                    }
                }} => {},
            () = config_reload.notified() => {
                self.status = Status::Ready;
            }
        }
    }

    #[cfg(test)]
    async fn enter_idle_mode_with_try_connect<F, Fut>(
        &mut self,
        health_check: bool,
        mut try_connect: F,
    ) where
        F: for<'a> FnMut(&'a mut Client, bool) -> Fut,
        Fut: Future<Output = Result<()>> + Send,
    {
        info_or_print!("Entering idle mode");
        self.status = Status::Idle;
        let config_reload = self.config_reload.clone();
        tokio::select! {
            () = async {
                loop {
                    match try_connect(self, health_check).await {
                        Ok(()) => {
                            info_or_print!("The Manager server is now online");
                            self.status = Status::Ready;
                            return
                        },
                        Err(e) => {
                            info_or_print!("Connection attempt failed: {e}, retrying");
                            sleep(Duration::from_secs(SERVER_RETRY_INTERVAL)).await;
                        },
                    }
                }} => {},
            () = config_reload.notified() => {
                self.status = Status::Ready;
            }
        }
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
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;

    use async_channel::TryRecvError;
    use review_protocol::request::Handler;
    use review_protocol::types::{SamplingKind, SamplingPolicy};

    use super::*;

    /// Creates a test client with default configuration.
    /// Returns the client and a receiver for sampling policies.
    fn create_test_client() -> (Client, async_channel::Receiver<SamplingPolicy>) {
        let (tx, rx) = async_channel::unbounded();
        let config_reload = Arc::new(Notify::new());

        let client = Client {
            server_address: "127.0.0.1:8080".parse().unwrap(),
            server_name: "test".to_string(),
            connection: None,
            request_send: tx,
            cert: Vec::new(),
            key: Vec::new(),
            ca_certs: Vec::new(),
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
            interval: Duration::from_secs(60),
            period: Duration::from_secs(3600),
            offset: 0,
            src_ip: None,
            dst_ip: None,
            node: Some("test_node".to_string()),
            column: None,
        }
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

        // Spawn a task to notify config reload after a short delay
        let notify_task = tokio::spawn(async move {
            // Small delay to ensure enter_idle_mode is waiting
            tokio::time::sleep(Duration::from_millis(10)).await;
            config_reload.notify_one();
        });

        // Enter idle mode with health_check = false
        // This should wait for config reload notification
        tokio::time::timeout(
            Duration::from_millis(100),
            client.enter_idle_mode_with_try_connect(false, |_, _| async {
                Err(anyhow::anyhow!("forced failure"))
            }),
        )
        .await
        .expect("No Timeout");

        // Verify status is Ready after exiting idle mode
        assert!(matches!(client.status, Status::Ready));

        notify_task.await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn idle_mode_health_check_returns_immediately() {
        // Test: health_check=true returns without waiting for config_reload
        let (mut client, _rx) = create_test_client();
        let config_reload = client.config_reload.clone();
        let called = Arc::new(AtomicUsize::new(0));
        let called_ref = called.clone();

        let wait_task = tokio::spawn(async move {
            config_reload.notified().await;
        });

        tokio::time::timeout(
            Duration::from_millis(100),
            client.enter_idle_mode_with_try_connect(true, move |_, _| {
                let called_ref = called_ref.clone();
                async move {
                    called_ref.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            }),
        )
        .await
        .expect("No Timeout");

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

        assert!(matches!(client.status, Status::Ready));

        // Notify immediately to exit idle mode quickly
        config_reload.notify_one();

        tokio::time::timeout(
            Duration::from_millis(100),
            client.enter_idle_mode_with_try_connect(false, |_client, _| async {
                Err(anyhow::anyhow!("forced failure"))
            }),
        )
        .await
        .expect("No Timeout");

        // After exiting, status should be Ready
        assert!(matches!(client.status, Status::Ready));
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
