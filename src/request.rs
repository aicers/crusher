use std::{
    collections::HashMap,
    io::ErrorKind,
    net::{IpAddr, SocketAddr},
    process::exit,
    sync::Arc,
};

use anyhow::{bail, Error, Result};
use async_trait::async_trait;
use bincode::Options;
use num_enum::TryFromPrimitive;
use review_protocol::{
    client::{Connection, ConnectionBuilder},
    types as protocol_types,
};
use serde::Deserialize;
use tokio::{
    sync::{broadcast, RwLock},
    time::{sleep, Duration},
};
use tracing::{error, info, trace};

use crate::{
    client::{Certs, SERVER_RETRY_INTERVAL},
    ControlMessage,
};

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

#[derive(Debug, Deserialize, TryFromPrimitive, Clone)]
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
    connection: Option<Connection>,
    request_send: async_channel::Sender<RequestedPolicy>,
    control_send: broadcast::Sender<ControlMessage>,
    certs: Certs,
    active_policy_list: Arc<RwLock<HashMap<u32, RequestedPolicy>>>,
    delete_policy_ids: Arc<RwLock<Vec<u32>>>,
}

impl Client {
    pub fn new(
        server_address: SocketAddr,
        server_name: String,
        request_send: async_channel::Sender<RequestedPolicy>,
        control_send: broadcast::Sender<ControlMessage>,
        certs: Certs,
        active_policy_list: Arc<RwLock<HashMap<u32, RequestedPolicy>>>,
        delete_policy_ids: Arc<RwLock<Vec<u32>>>,
    ) -> Self {
        Client {
            server_address,
            server_name,
            connection: None,
            request_send,
            control_send,
            certs,
            active_policy_list,
            delete_policy_ids,
        }
    }

    pub async fn run(mut self) -> Result<()> {
        loop {
            match self.connect().await {
                Ok(connection) => {
                    info!("Listening for incoming requests");
                    match connection.accept_bi().await {
                        Ok((mut send, mut recv)) => {
                            let mut handler = self.clone();
                            let _ = tokio::spawn(async move {
                                review_protocol::request::handle(&mut handler, &mut send, &mut recv)
                                    .await
                            })
                            .await?;
                        }
                        Err(e) => {
                            // return Err(Error::new(e));
                            error!("Fail to accept connection: {:?}", e);
                        }
                    }
                }
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

    async fn connect(&mut self) -> Result<&Connection> {
        if let Some(ref connection) = self.connection {
            return Ok(connection);
        }
        let mut conn_builder = ConnectionBuilder::new(
            &self.server_name,
            self.server_address,
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION"),
            REQUIRED_MANAGER_VERSION,
            &self.certs.cert_raw,
            &self.certs.key_raw,
        )?;
        conn_builder.root_certs(&self.certs.ca_certs_raw)?;
        self.connection = Some(conn_builder.connect().await?);
        info!(
            "Connection established to the Manager server {}",
            self.server_address
        );
        Ok(self.connection.as_ref().expect("Verified by Some above"))
    }

    pub async fn get_config(&mut self) -> Result<String> {
        self.connect().await?.get_config().await.map_err(Error::new)
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
        info!("Updating configuration");
        match self.get_config().await {
            Ok(config) => {
                self.control_send
                    .send(ControlMessage::UpdateConfig(config))
                    .map_err(|e| format!("Failed to send config: {e}"))?;
            }
            Err(e) => {
                return Err(format!("Failed to get config: {e}"));
            }
        };

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
