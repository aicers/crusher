use std::{
    collections::HashMap,
    io::ErrorKind,
    net::{IpAddr, SocketAddr},
    process::exit,
    sync::Arc,
};

use anyhow::{bail, Context, Result};
use async_channel::Sender;
use async_trait::async_trait;
use bincode::Options;
use num_enum::TryFromPrimitive;
use review_protocol::{
    client::{Connection, ConnectionBuilder},
    types as protocol_types,
};
use serde::Deserialize;
use tokio::{
    sync::{Notify, RwLock},
    time::{sleep, Duration},
};
use tracing::{error, info, trace};

use crate::client::SERVER_RETRY_INTERVAL;

const REQUIRED_MANAGER_VERSION: &str = "0.39.0";
const MAX_RETRIES: u8 = 3;

#[derive(Debug, Deserialize, Clone)]
pub struct RequestedPolicy {
    pub id: u32,
    pub kind: RequestedKind,
    pub interval: RequestedInterval,
    pub period: RequestedPeriod,
    pub offset: i32,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub node: Option<String>,
    pub column: Option<u32>,
}

#[derive(Debug, Deserialize, TryFromPrimitive, Clone)]
#[repr(u32)]
pub enum RequestedKind {
    Conn = 0,
    Dns = 1,
    Http = 2,
    Rdp = 3,
    Smtp = 4,
    Ntlm = 5,
    Kerberos = 6,
    Ssh = 7,
    DceRpc = 8,
    Ftp = 9,
    Mqtt = 10,
    Ldap = 11,
    Tls = 12,
    Smb = 13,
    Nfs = 14,
    Bootp = 15,
    Dhcp = 16,
}

#[derive(Debug, Deserialize, TryFromPrimitive, Clone)]
#[repr(u32)]
pub enum RequestedInterval {
    FiveMinutes = 0,
    TenMinutes = 1,
    FifteenMinutes = 2,
    ThirtyMinutes = 3,
    OneHour = 4,
}

#[derive(Clone, Copy, Debug, Deserialize, TryFromPrimitive)]
#[repr(u32)]
pub enum RequestedPeriod {
    SixHours,
    TwelveHours,
    OneDay,
}

#[derive(Clone)]
pub struct Client {
    server_address: SocketAddr,
    server_name: String,
    request_send: Sender<RequestedPolicy>,
    cert: Vec<u8>,
    key: Vec<u8>,
    ca_certs: Vec<Vec<u8>>,
    config_reload: Arc<Notify>,
    pub active_policy_list: Arc<RwLock<HashMap<u32, RequestedPolicy>>>,
    pub delete_policy_ids: Arc<RwLock<Vec<u32>>>,
}

impl Client {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server_address: SocketAddr,
        server_name: String,
        request_send: Sender<RequestedPolicy>,
        cert: Vec<u8>,
        key: Vec<u8>,
        ca_certs: Vec<Vec<u8>>,
        config_reload: Arc<Notify>,
    ) -> Self {
        Client {
            server_address,
            server_name,
            request_send,
            cert,
            key,
            ca_certs,
            config_reload,
            active_policy_list: Arc::new(RwLock::new(HashMap::new())),
            delete_policy_ids: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn run(&mut self, shutdown: Arc<Notify>) -> Result<()> {
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
                        error!("Failed to accept bidirectional stream: {:?}", e);
                    }
                },
                Err(e) => {
                    if let Some(e) = e.downcast_ref::<std::io::Error>() {
                        match e.kind() {
                            ErrorKind::ConnectionAborted
                            | ErrorKind::ConnectionReset
                            | ErrorKind::TimedOut => {
                                error!(
                                    "Retry connection to {} after {} seconds.",
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
                    bail!("Fail to connect to {}: {:?}", self.server_address, e);
                }
            }
        }
    }

    async fn connect(&mut self) -> Result<Connection> {
        let mut conn_builder = ConnectionBuilder::new(
            &self.server_name,
            self.server_address,
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION"),
            REQUIRED_MANAGER_VERSION,
            &self.cert,
            &self.key,
        )?;
        conn_builder.root_certs(&self.ca_certs)?;
        let connection = conn_builder
            .connect()
            .await
            .with_context(|| "Failed to connect to the Manager server")?;
        info!(
            "Connection established to the Manager server {}",
            self.server_address
        );
        Ok(connection)
    }

    pub async fn get_config(&mut self) -> Result<String> {
        info!("Fetching a configuration");
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
    pub async fn enter_idle_mode(&mut self, health_check: bool) {
        println!("Entering idle mode");
        let config_reload = self.config_reload.clone();
        tokio::select! {
            () = async {
                loop {
                    match self.try_connect(health_check).await {
                        Ok(()) => {
                            println!("The Manager server is now online");
                            return
                        },
                        Err(e) => {
                            eprintln!("{e}");
                        },
                    };
                }} => {},
            () = config_reload.notified() => {}
        }
    }

    async fn try_connect(&mut self, health_check: bool) -> Result<()> {
        let connection = self.connect().await?;
        if health_check {
            return Ok(());
        }
        let (mut send, mut recv) = connection.accept_bi().await?;
        let mut update_handler = UpdateHandler {
            config_reload: self.config_reload.clone(),
        };
        review_protocol::request::handle(&mut update_handler, &mut send, &mut recv).await?;
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

    async fn sampling_policy_list(&mut self, policies: &[u8]) -> Result<(), String> {
        let policies = bincode::DefaultOptions::new()
            .deserialize::<Vec<RequestedPolicy>>(policies)
            .map_err(|e| format!("Failed to deserialize policy: {e}"))?;
        for policy in policies {
            if self
                .active_policy_list
                .read()
                .await
                .get(&policy.id)
                .is_some()
            {
                trace!("duplicated policy: {:?}", policy);
                continue;
            }
            self.active_policy_list
                .write()
                .await
                .insert(policy.id, policy.clone());
            trace!("Receive REview's policy: {:?}", policy);
            self.request_send
                .send(policy)
                .await
                .map_err(|e| format!("send fail: {e}"))?;
        }

        Ok(())
    }

    async fn delete_sampling_policy(&mut self, policy_ids: &[u8]) -> Result<(), String> {
        let policy_ids = bincode::DefaultOptions::new()
            .deserialize::<Vec<u32>>(policy_ids)
            .map_err(|e| format!("Failed to deserialize policy id: {e}"))?;
        for id in policy_ids {
            if let Some(deleted_policy) = self.active_policy_list.write().await.remove(&id) {
                trace!("{} Deleted from runtime policy list.", deleted_policy.id);
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

pub struct UpdateHandler {
    config_reload: Arc<Notify>,
}

#[async_trait]
impl review_protocol::request::Handler for UpdateHandler {
    async fn update_config(&mut self) -> Result<(), String> {
        info!("Start updating configuration");
        self.config_reload.notify_one();
        Ok(())
    }
}
