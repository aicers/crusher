mod client;
mod logging;
mod model;
mod request;
mod settings;
mod subscribe;

use std::net::SocketAddr;
use std::str::FromStr;
use std::{collections::HashMap, sync::Arc};

use anyhow::{bail, Context, Result};
use clap::Parser;
use client::Certs;
use logging::init_tracing;
use settings::Settings;
use tokio::{
    sync::{Notify, RwLock},
    task,
};
use tracing::{error, info};

use crate::{request::RequestedPolicy, subscribe::read_last_timestamp};

const REQUESTED_POLICY_CHANNEL_SIZE: usize = 1;

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

impl CmdLineArgs {
    #[must_use]
    pub fn is_local_mode(&self) -> bool {
        self.config.is_some()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = CmdLineArgs::parse();
    let log_dir = args.config.as_deref().and_then(|path| {
        Settings::from_file(path)
            .ok()
            .and_then(|settings| settings.log_dir)
    });
    let _guards = init_tracing(log_dir.as_deref());
    let certs = Certs::from_args(&args)?;
    let (request_send, request_recv) =
        async_channel::bounded::<RequestedPolicy>(REQUESTED_POLICY_CHANNEL_SIZE);
    let runtime_policy_list = Arc::new(RwLock::new(HashMap::new())); // current sampling_policy value
    let delete_policy_ids = Arc::new(RwLock::new(Vec::new()));
    let config_reload = Arc::new(Notify::new());
    let request_client = request::Client::new(
        args.manager_server.rpc_srv_addr,
        args.manager_server.name.clone(),
        request_send,
        config_reload.clone(),
        certs.clone(),
        runtime_policy_list.clone(),
        delete_policy_ids.clone(),
    );

    loop {
        if let Err(e) = run(
            &args,
            &certs,
            request_client.clone(),
            request_recv.clone(),
            config_reload.clone(),
        )
        .await
        {
            if args.is_local_mode() {
                bail!("{e}");
            }
            error!("{e}");
            enter_wait_mode(request_client.clone(), config_reload.clone()).await?;
        }
    }
}

async fn run(
    args: &CmdLineArgs,
    certs: &Certs,
    mut request_client: request::Client,
    request_recv: async_channel::Receiver<RequestedPolicy>,
    config_reload: Arc<Notify>,
) -> Result<()> {
    let settings = if let Some(local_config) = args.config.as_deref() {
        Settings::from_file(local_config)?
    } else {
        Settings::from_str(&request_client.get_config().await?)?
        // TODO(jake): change the log directory based on the remote settings after #128
    };
    let shutdown = Arc::new(Notify::new());
    read_last_timestamp(&settings.last_timestamp_data).await?;
    request_client.active_policy_list.write().await.clear();
    request_client.delete_policy_ids.write().await.clear();
    let subscribe_client = subscribe::Client::new(
        settings.giganto_ingest_srv_addr,
        settings.giganto_publish_srv_addr,
        settings.giganto_name,
        settings.last_timestamp_data,
        certs,
        request_recv,
    );
    task::spawn(subscribe_client.run(
        request_client.active_policy_list.clone(),
        request_client.delete_policy_ids.clone(),
        shutdown.clone(),
    ));
    task::spawn(async move { request_client.run().await });
    if args.is_local_mode() {
        shutdown.notified().await;
    } else {
        config_reload.notified().await;
        shutdown.notify_waiters();
        shutdown.notified().await;
    }
    Ok(())
}

async fn enter_wait_mode(
    mut request_client: request::Client,
    config_reload: Arc<Notify>,
) -> Result<()> {
    info!("Entering wait mode");
    // TODO(jake): change the log directory to stdout after #128
    task::spawn(async move { request_client.run().await });
    config_reload.notified().await;
    Ok(())
}
