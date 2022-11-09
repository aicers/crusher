use crate::client::{config_client, SERVER_RETRY_INTERVAL};
use anyhow::{bail, Result};
use quinn::{ConnectionError, Endpoint, RecvStream, SendStream};
use rustls::{Certificate, PrivateKey};
use std::{net::SocketAddr, process::exit};
use tokio::time::{sleep, Duration};
use tracing::{error, info};

const INGESTION_PROTOCOL_VERSION: &str = "0.4.0";
const PUBLISH_PROTOCOL_VERSION: &str = "0.4.0";

#[derive(Debug, Clone, Copy)]
enum ServerType {
    Ingestion,
    Publish,
}

pub struct Client {
    ingestion_addr: SocketAddr,
    publish_addr: SocketAddr,
    server_name: String,
    endpoint: Endpoint,
}

impl Client {
    pub fn new(
        ingestion_addr: SocketAddr,
        publish_addr: SocketAddr,
        server_name: String,
        certs: Vec<Certificate>,
        key: PrivateKey,
        files: Vec<Vec<u8>>,
    ) -> Self {
        let endpoint = config_client(certs, key, files)
            .expect("server configuration error with cert, key or root");
        Client {
            ingestion_addr,
            publish_addr,
            server_name,
            endpoint,
        }
    }

    pub async fn run(self) {
        if let Err(e) = tokio::try_join!(
            connection_control(
                ServerType::Ingestion,
                self.ingestion_addr,
                self.server_name.clone(),
                self.endpoint.clone(),
                INGESTION_PROTOCOL_VERSION,
            ),
            connection_control(
                ServerType::Publish,
                self.publish_addr,
                self.server_name,
                self.endpoint,
                PUBLISH_PROTOCOL_VERSION,
            )
        ) {
            error!("giganto connection error occur : {}", e);
        }
    }
}

async fn connection_control(
    server_type: ServerType,
    server_addr: SocketAddr,
    server_name: String,
    endpoint: Endpoint,
    version: &str,
) -> Result<()> {
    loop {
        match connect(server_type, &endpoint, server_addr, &server_name, version).await {
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
                                server_addr, SERVER_RETRY_INTERVAL,
                            );
                            sleep(Duration::from_secs(SERVER_RETRY_INTERVAL)).await;
                            continue;
                        }
                        ConnectionError::TransportError(_) => {
                            error!("Invalid peer certificate contents");
                            exit(0)
                        }
                        _ => {}
                    }
                }
                bail!("Fail to connect to {}: {:?}", server_addr, e);
            }
        }
    }
}

async fn connect(
    _server_type: ServerType,
    endpoint: &Endpoint,
    server_address: SocketAddr,
    server_name: &str,
    version: &str,
) -> Result<()> {
    let conn = endpoint.connect(server_address, server_name)?.await?;
    let (mut send, mut recv) = conn.open_bi().await?;

    if let Err(e) = client_handshake(version, &mut send, &mut recv).await {
        error!("Giganto handshake failed: {:#}", e);
        bail!("{}", e);
    }

    info!("Connection established to server {}", server_address);
    Ok(())
}

async fn client_handshake(
    version: &str,
    send: &mut SendStream,
    recv: &mut RecvStream,
) -> Result<()> {
    let version_len = u64::try_from(version.len())
        .expect("less than u64::MAX")
        .to_le_bytes();

    let mut handshake_buf = Vec::with_capacity(version_len.len() + version.len());
    handshake_buf.extend(version_len);
    handshake_buf.extend(version.as_bytes());
    send.write_all(&handshake_buf).await?;

    let mut resp_len_buf = [0; std::mem::size_of::<u64>()];
    recv.read_exact(&mut resp_len_buf).await?;
    let len = u64::from_le_bytes(resp_len_buf);

    let mut resp_buf = Vec::new();
    resp_buf.resize(len.try_into()?, 0);
    recv.read_exact(resp_buf.as_mut_slice()).await?;

    if bincode::deserialize::<Option<&str>>(&resp_buf)
        .unwrap()
        .is_none()
    {
        bail!("Incompitable version");
    }

    Ok(())
}
