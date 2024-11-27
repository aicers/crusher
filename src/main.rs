mod client;
mod logging;
mod model;
mod request;
mod settings;
mod subscribe;

use std::net::SocketAddr;
use std::str::FromStr;
use std::{collections::HashMap, sync::Arc};

use anyhow::{Context, Result};
use clap::Parser;
use client::Certs;
use settings::Settings;
pub use settings::TEMP_TOML_POST_FIX;
use tokio::sync::RwLock;
use tokio::sync::{broadcast, Notify};
use tracing::{error, warn};

use crate::{request::RequestedPolicy, subscribe::read_last_timestamp};

const REQUESTED_POLICY_CHANNEL_SIZE: usize = 1;
const CONTROL_CHANNEL_SIZE: usize = 1;

#[derive(Debug, Clone)]
pub struct ManagerServer {
    name: String,
    rpc_srv_addr: SocketAddr,
}

impl FromStr for ManagerServer {
    type Err = anyhow::Error;

    fn from_str(manager_server: &str) -> Result<Self> {
        let (name, rpc_srv_addr) = manager_server
            .split_once('@')
            .context("cannot get information of the Manager server")?;
        Ok(ManagerServer {
            name: name.to_string(),
            rpc_srv_addr: rpc_srv_addr
                .parse()
                .context("cannot parse the Manager server address")?,
        })
    }
}

#[derive(Parser, Debug, Clone)]
#[command(version)]
pub struct CmdLineArgs {
    /// Path to the local configuration TOML file.
    #[arg(short, value_name = "CONFIG_PATH")]
    pub config: Option<String>,

    /// Path to the certificate file.
    #[arg(long, value_name = "CERT_PATH")]
    pub cert: String,

    /// Path to the key file.
    #[arg(long, value_name = "KEY_PATH")]
    pub key: String,

    /// Path to the CA certificate files. Multiple paths can be specified by repeating this option.
    #[arg(long, value_name = "CA_CERTS_PATH", required = true)]
    pub ca_certs: Vec<String>,

    /// Address of the Manager server formatted as `<server_name>@<server_ip>:<server_port>`.
    #[arg(value_parser=clap::builder::ValueParser::new(ManagerServer::from_str))]
    pub manager_server: ManagerServer,
}

#[derive(Debug, Clone)]
pub enum ControlMessage {
    UpdateConfig(String),
    RunGiganto(Option<Settings>),
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = CmdLineArgs::parse();

    let mut settings = if args.config.is_some() {
        Some(Settings::from_args(args.clone())?)
    } else {
        None
    };
    let mut log_manager =
        logging::init_tracing(settings.as_ref().and_then(|s| s.log_dir.as_deref()))?;

    let (request_send, request_recv) =
        async_channel::bounded::<RequestedPolicy>(REQUESTED_POLICY_CHANNEL_SIZE);
    let (control_send, mut control_recv) =
        broadcast::channel::<ControlMessage>(CONTROL_CHANNEL_SIZE);
    let certs = Certs::from_args(&args)?;
    let runtime_policy_list = Arc::new(RwLock::new(HashMap::new())); // current sampling_policy value
    let delete_policy_ids = Arc::new(RwLock::new(Vec::new()));

    let mut request_client = request::Client::new(
        args.manager_server.rpc_srv_addr,
        args.manager_server.name.clone(),
        request_send,
        control_send.clone(),
        certs.clone(),
        runtime_policy_list.clone(),
        delete_policy_ids.clone(),
    );

    if args.config.is_none() {
        match request_client.get_config().await {
            Ok(config) => {
                if let Err(e) =
                    Settings::change_from_config(&mut settings, &config, &mut log_manager)
                {
                    error!("Failed to update the configuration: {:?}", e);
                }
            }
            Err(e) => {
                error!(
                    "Failed to fetch configuration from the Manager server: {:?}",
                    e
                );
            }
        }
    }

    tokio::spawn(request_client.run());

    tokio::spawn(run_giganto(
        settings.clone(),
        control_send.subscribe(),
        request_recv.clone(),
        certs.clone(),
        runtime_policy_list.clone(),
        delete_policy_ids.clone(),
    ));

    loop {
        match control_recv.recv().await {
            Ok(ControlMessage::UpdateConfig(config)) => {
                if args.config.is_some() {
                    warn!("Cannot update the configuration from the Manager server when a local configuration file is specified");
                    continue;
                }
                if let Err(e) =
                    Settings::change_from_config(&mut settings, &config, &mut log_manager)
                {
                    error!("Failed to update the configuration: {:?}", e);
                } else {
                    control_send.send(ControlMessage::RunGiganto(settings.clone()))?;
                }
            }
            Err(e) => {
                error!("Error receiving control message: {:?}", e);
            }
            _ => {}
        }
    }
}

async fn run_giganto(
    mut settings: Option<Settings>,
    mut control_recv: broadcast::Receiver<ControlMessage>,
    request_recv: async_channel::Receiver<RequestedPolicy>,
    certs: Certs,
    runtime_policy_list: Arc<RwLock<HashMap<u32, RequestedPolicy>>>,
    delete_policy_ids: Arc<RwLock<Vec<u32>>>,
) -> Result<()> {
    let shutdown = Arc::new(Notify::new());
    loop {
        if let Some(settings) = settings {
            runtime_policy_list.write().await.clear();
            delete_policy_ids.write().await.clear();
            read_last_timestamp(&settings.last_timestamp_data).await?;
            let giganto = subscribe::Client::new(
                settings.giganto_ingest_srv_addr,
                settings.giganto_publish_srv_addr,
                settings.giganto_name.clone(),
                settings.last_timestamp_data.clone(),
                &certs,
                request_recv.clone(),
            );
            tokio::spawn(giganto.run(
                runtime_policy_list.clone(),
                delete_policy_ids.clone(),
                shutdown.clone(),
            ));
        }
        loop {
            match control_recv.recv().await {
                Ok(ControlMessage::RunGiganto(new_settings)) => {
                    settings = new_settings;
                    shutdown.notify_waiters();
                    shutdown.notified().await;
                    break;
                }
                Err(e) => {
                    error!("Error receiving control message: {:?}", e);
                }
                _ => {}
            }
        }
    }
}
