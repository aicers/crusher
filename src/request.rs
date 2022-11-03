use crate::client::{config_client, SERVER_RETRY_INTERVAL};
use anyhow::{bail, Error, Result};
use quinn::{Connection, ConnectionError, Endpoint};
use rustls::{Certificate, PrivateKey};
use std::{net::SocketAddr, process::exit};
use tokio::time::{sleep, Duration};
use tracing::{error, info};

const REVIEW_PROTOCOL_VERSION: &str = "0.13.0-alpha.37";

pub struct Client {
    server_address: SocketAddr,
    server_name: String,
    agent_id: String,
    endpoint: Endpoint,
}

impl Client {
    pub fn new(
        server_address: SocketAddr,
        server_name: String,
        agent_id: String,
        certs: Vec<Certificate>,
        key: PrivateKey,
        files: Vec<Vec<u8>>,
    ) -> Self {
        let endpoint = config_client(certs, key, files)
            .expect("server configuration error with cert, key or root");
        Client {
            server_address,
            server_name,
            agent_id,
            endpoint,
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
                Ok(_) => return Ok(()),
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
) -> Result<()> {
    let conn = endpoint.connect(server_address, server_name)?.await?;
    let connection = conn.connection;

    handshake(&connection, agent_id, REVIEW_PROTOCOL_VERSION)
        .await
        .map_err(|e| {
            error!("Review handshake failed: {:#}", e);
            Error::new(e)
        })?;

    info!("Connection established to server {}", server_address);
    Ok(())
}

async fn handshake(
    conn: &Connection,
    agent_id: &str,
    protocol: &str,
) -> Result<(), oinq::message::HandshakeError> {
    oinq::message::client_handshake(
        conn,
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        protocol,
        agent_id,
    )
    .await?;
    Ok(())
}
