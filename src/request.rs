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

const REQUIRED_MANAGER_VERSION: &str = "0.42.0";
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
        for attempt in 1..=MAX_RETRIES {
            if let Err(e) = roxy::reboot() {
                if attempt == MAX_RETRIES {
                    return Err(format!("cannot restart the system: {e}"));
                }
            } else {
                return Ok(());
            }
        }

        Err(String::from("cannot restart the system"))
    }

    async fn shutdown(&mut self) -> Result<(), String> {
        for attempt in 1..=MAX_RETRIES {
            if let Err(e) = roxy::power_off() {
                if attempt == MAX_RETRIES {
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
            total_disk_space: usg.total_disk_space,
            used_disk_space: usg.used_disk_space,
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
            debug!("Received the Manager Server's policy: {:?}", policy);
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
                debug!("{} deleted from runtime policy list", deleted_policy.id);
                self.delete_policy_ids.write().await.push(id);
            }
        }

        Ok(())
    }

    async fn update_config(&mut self) -> Result<(), String> {
        info!("Start updating configuration");
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
        info!("Start updating configuration");
        self.config_reload.notify_one();
        Ok(())
    }
}
