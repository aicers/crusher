use std::{
    collections::HashMap,
    fs,
    net::{IpAddr, SocketAddr},
    process::exit,
    sync::Arc,
};

use anyhow::{bail, Error, Result};
use async_channel::Sender;
use async_trait::async_trait;
use bincode::Options;
use num_enum::TryFromPrimitive;
use quinn::{Connection, ConnectionError, Endpoint, RecvStream, SendStream, VarInt};
use review_protocol::{types as protocol_types, HandshakeError};
use serde::Deserialize;
use tokio::{
    sync::{Notify, RwLock},
    time::{sleep, Duration},
};
use tracing::{error, info, trace, warn};

use crate::{
    client::{self, Certs, SERVER_RETRY_INTERVAL},
    TEMP_TOML_POST_FIX,
};

const REVIEW_PROTOCOL_VERSION: &str = "0.27.0";
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

pub struct Client {
    server_address: SocketAddr,
    server_name: String,
    endpoint: Endpoint,
    request_send: Sender<RequestedPolicy>,
}

impl Client {
    pub fn new(
        server_address: SocketAddr,
        server_name: String,
        certs: &Arc<Certs>,
        request_send: Sender<RequestedPolicy>,
    ) -> Self {
        let endpoint =
            client::config(certs).expect("server configuration error with cert, key or ca_certs");
        Client {
            server_address,
            server_name,
            endpoint,
            request_send,
        }
    }

    pub async fn run(
        self,
        active_policy_list: Arc<RwLock<HashMap<u32, RequestedPolicy>>>,
        delete_policy_ids: Arc<RwLock<Vec<u32>>>,
        config_reload: Arc<Notify>,
        wait_shutdown: Arc<Notify>,
        config_path: String,
    ) -> Result<()> {
        loop {
            match connect(
                &self.endpoint,
                self.server_address,
                &self.server_name,
                &self.request_send,
                active_policy_list.clone(),
                delete_policy_ids.clone(),
                config_reload.clone(),
                wait_shutdown.clone(),
                config_path.clone(),
            )
            .await
            {
                Ok(()) => return Ok(()),
                Err(e) => {
                    if let Some(e) = e.downcast_ref::<ConnectionError>() {
                        match e {
                            ConnectionError::ConnectionClosed(_)
                            | ConnectionError::ApplicationClosed(_)
                            | ConnectionError::Reset
                            | ConnectionError::TimedOut => {
                                error!(
                                    "Retry connection to {} after {} seconds.",
                                    self.server_address, SERVER_RETRY_INTERVAL,
                                );
                                sleep(Duration::from_secs(SERVER_RETRY_INTERVAL)).await;
                                continue;
                            }
                            ConnectionError::TransportError(_) => {
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
}

#[allow(clippy::too_many_arguments)]
async fn connect(
    endpoint: &Endpoint,
    server_address: SocketAddr,
    server_name: &str,
    request_send: &Sender<RequestedPolicy>,
    active_policy_list: Arc<RwLock<HashMap<u32, RequestedPolicy>>>,
    delete_policy_ids: Arc<RwLock<Vec<u32>>>,
    config_reload: Arc<Notify>,
    wait_shutdown: Arc<Notify>,
    config_path: String,
) -> Result<()> {
    let connection = endpoint.connect(server_address, server_name)?.await?;

    handshake(&connection, REVIEW_PROTOCOL_VERSION)
        .await
        .map_err(|e| {
            error!("Review handshake failed: {:#}", e);
            Error::new(e)
        })?;

    info!("Connection established to server {}", server_address);

    let request_handler = RequestHandler {
        request_send: request_send.clone(),
        active_policy_list,
        delete_policy_ids,
        config_reload: config_reload.clone(),
        config_path,
    };

    tokio::select! {
        res = handle_incoming(request_handler, &connection) => {
            if let Err(e) = res {
                warn!("control channel failed: {}", e);
                return Err(e);
            }
            Ok(())
        },
        () = wait_shutdown.notified() => {
            info!("Shutting down request channel");
            endpoint.close(0_u32.into(), &[]);
            Ok(())
        }
    }
}

async fn handshake(
    conn: &Connection,
    protocol: &str,
) -> Result<(SendStream, RecvStream), HandshakeError> {
    let (send, recv) = review_protocol::client::handshake(
        conn,
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        protocol,
    )
    .await?;
    Ok((send, recv))
}

async fn handle_incoming(handler: RequestHandler, conn: &Connection) -> Result<()> {
    loop {
        match conn.accept_bi().await {
            Ok((mut send, mut recv)) => {
                let mut hdl = handler.clone();
                tokio::spawn(async move {
                    review_protocol::request::handle(&mut hdl, &mut send, &mut recv).await
                });
            }
            Err(e) => {
                conn.close(VarInt::from_u32(0), b"Lost server connection");
                return Err(Error::new(e));
            }
        }
    }
}

#[derive(Clone)]
struct RequestHandler {
    request_send: Sender<RequestedPolicy>,
    active_policy_list: Arc<RwLock<HashMap<u32, RequestedPolicy>>>,
    delete_policy_ids: Arc<RwLock<Vec<u32>>>,
    config_reload: Arc<Notify>,
    config_path: String,
}

#[async_trait]
impl review_protocol::request::Handler for RequestHandler {
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

    async fn reload_config(&mut self) -> Result<(), String> {
        info!("start reloading configuration");
        self.config_reload.notify_one();
        Ok(())
    }

    async fn get_config(&mut self) -> Result<protocol_types::Config, String> {
        for attempt in 1..=MAX_RETRIES {
            match crate::settings::get_config(&self.config_path) {
                Ok(conf) => return Ok(conf),
                Err(e) => {
                    if attempt == MAX_RETRIES {
                        return Err(format!("failed to get config: {e}"));
                    }
                }
            }
        }

        Err(String::from("failed to get config"))
    }

    async fn set_config(&mut self, conf: protocol_types::Config) -> Result<(), String> {
        info!("start set configuration");
        for attempt in 1..=MAX_RETRIES {
            if let Err(e) = crate::settings::set_config(&conf, &self.config_path) {
                if attempt == MAX_RETRIES {
                    fs::remove_file(format!("{}{TEMP_TOML_POST_FIX}", self.config_path))
                        .unwrap_or_else(|e| error!("failed to remove the temporary file: {e}"));
                    return Err(format!("failed to set config: {e}"));
                }
            } else {
                self.config_reload.notify_one();
                return Ok(());
            }
        }

        Err(String::from("failed to set config"))
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
