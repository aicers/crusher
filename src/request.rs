use crate::client::{config_client, SERVER_RETRY_INTERVAL};
use anyhow::{anyhow, bail, Error, Result};
use async_channel::Sender;
use async_trait::async_trait;
use bincode::Options;
use num_enum::TryFromPrimitive;
use quinn::{Connection, ConnectionError, Endpoint, RecvStream, SendStream};
use rustls::{Certificate, PrivateKey};
use serde::Deserialize;
use std::{
    net::{IpAddr, SocketAddr},
    process::exit,
};
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};

const REVIEW_PROTOCOL_VERSION: &str = "0.13.0-alpha.37";

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize, TryFromPrimitive)]
#[repr(u32)]
pub enum RequestedKind {
    Conn = 0,
    Dns = 1,
    Http = 2,
    Rdp = 3,
}

impl Default for RequestedKind {
    fn default() -> Self {
        Self::Conn
    }
}

#[derive(Debug, Deserialize, TryFromPrimitive)]
#[repr(u32)]
pub enum RequestedInterval {
    FiveMinutes = 0,
    TenMinutes = 1,
    FifteenMinutes = 2,
    ThirtyMinutes = 3,
    OneHour = 4,
}

impl Default for RequestedInterval {
    fn default() -> Self {
        Self::FifteenMinutes
    }
}

#[derive(Debug, Deserialize, TryFromPrimitive)]
#[repr(u32)]
pub enum RequestedPeriod {
    SixHours,
    TwelveHours,
    OneDay,
}

impl Default for RequestedPeriod {
    fn default() -> Self {
        Self::OneDay
    }
}

pub struct Client {
    server_address: SocketAddr,
    server_name: String,
    agent_id: String,
    endpoint: Endpoint,
    request_send: Sender<RequestedPolicy>,
}

impl Client {
    pub fn new(
        server_address: SocketAddr,
        server_name: String,
        agent_id: String,
        certs: Vec<Certificate>,
        key: PrivateKey,
        files: Vec<Vec<u8>>,
        request_send: Sender<RequestedPolicy>,
    ) -> Self {
        let endpoint = config_client(certs, key, files)
            .expect("server configuration error with cert, key or root");
        Client {
            server_address,
            server_name,
            agent_id,
            endpoint,
            request_send,
        }
    }

    pub async fn run(self) -> Result<()> {
        loop {
            match connect(
                &self.endpoint,
                self.server_address,
                &self.server_name,
                &self.agent_id,
            )
            .await
            {
                Ok(conn) => {
                    let request_handler = RequestHandler {
                        request_send: self.request_send,
                    };

                    tokio::select! {
                        res = handle_incoming(request_handler, &conn) => {
                            if let Err(e) = res {
                                warn!("control channel failed: {}", e);
                            } else {
                                return Ok(());
                            }
                        },
                    }
                    return Ok(());
                }
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

async fn connect(
    endpoint: &Endpoint,
    server_address: SocketAddr,
    server_name: &str,
    agent_id: &str,
) -> Result<Connection> {
    let connection = endpoint.connect(server_address, server_name)?.await?;

    handshake(&connection, agent_id, REVIEW_PROTOCOL_VERSION)
        .await
        .map_err(|e| {
            error!("Review handshake failed: {:#}", e);
            Error::new(e)
        })?;

    info!("Connection established to server {}", server_address);

    Ok(connection)
}

async fn handshake(
    conn: &Connection,
    agent_id: &str,
    protocol: &str,
) -> Result<(SendStream, RecvStream), oinq::message::HandshakeError> {
    let (send, recv) = oinq::message::client_handshake(
        conn,
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        protocol,
        agent_id,
    )
    .await?;
    Ok((send, recv))
}

async fn handle_incoming(handler: RequestHandler, conn: &Connection) -> Result<()> {
    loop {
        match conn.accept_bi().await {
            Ok((mut send, mut recv)) => {
                let mut hdl = handler.clone();
                tokio::spawn(
                    async move { oinq::request::handle(&mut hdl, &mut send, &mut recv).await },
                );
            }
            Err(e) => {
                return Err(anyhow!("connection closed: {}", e));
            }
        }
    }
}

#[derive(Clone)]
struct RequestHandler {
    request_send: Sender<RequestedPolicy>,
}

#[async_trait]
impl oinq::request::Handler for RequestHandler {
    async fn reboot(&mut self) -> Result<(), String> {
        roxy::reboot().map_err(|e| format!("cannot restart the system: {}", e))?;
        Ok(())
    }

    async fn resource_usage(&mut self) -> Result<(String, oinq::ResourceUsage), String> {
        let usg = roxy::resource_usage().await;
        let usg = oinq::ResourceUsage {
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
            .map_err(|e| format!("Failed to deserialize policy: {}", e))?;
        for policy in policies {
            self.request_send
                .send(policy)
                .await
                .map_err(|e| format!("send fail: {}", e))?;
        }
        Ok(())
    }
}
