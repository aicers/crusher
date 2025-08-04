mod client;
mod logging;
mod request;
mod settings;
mod subscribe;

use std::fs;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::Parser;
use client::Certs;
use logging::init_tracing;
use review_protocol::types::SamplingPolicy;
use settings::Settings;
use subscribe::read_last_timestamp;
use tokio::sync::Notify;
use tracing::info;
use tracing_appender::non_blocking::WorkerGuard;

const REQUESTED_POLICY_CHANNEL_SIZE: usize = 1;

#[derive(Debug, Clone)]
struct ManagerServer {
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
struct CmdLineArgs {
    /// Path to the local configuration TOML file.
    #[arg(short, value_name = "CONFIG_PATH")]
    config: Option<String>,

    /// Path to the certificate file.
    #[arg(long, value_name = "CERT_PATH")]
    cert: String,

    /// Path to the key file.
    #[arg(long, value_name = "KEY_PATH")]
    key: String,

    /// Path to the CA certificate files. Multiple paths can be provided as a comma-separated list.
    #[arg(
        long,
        value_name = "CA_CERTS_PATH",
        required = true,
        value_delimiter = ','
    )]
    ca_certs: Vec<String>,

    /// Address of the Manager server formatted as `<server_name>@<server_ip>:<server_port>`.
    #[arg(value_parser=clap::builder::ValueParser::new(ManagerServer::from_str))]
    manager_server: ManagerServer,
}

impl CmdLineArgs {
    #[must_use]
    fn is_remote_mode(&self) -> bool {
        self.config.is_none()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = CmdLineArgs::parse();
    let cert_pem = fs::read(&args.cert)
        .with_context(|| format!("failed to read certificate file: {}", args.cert))?;
    let key_pem = fs::read(&args.key)
        .with_context(|| format!("failed to read private key file: {}", args.key))?;
    let mut ca_certs_pem = Vec::new();
    for ca_cert in &args.ca_certs {
        let file = fs::read(ca_cert)
            .with_context(|| format!("failed to read CA certificate file: {ca_cert}"))?;
        ca_certs_pem.push(file);
    }
    let certs = Certs::try_new(
        &cert_pem,
        &key_pem,
        &ca_certs_pem.iter().map(Vec::as_slice).collect::<Vec<_>>(),
    )?;
    let (request_send, request_recv) =
        async_channel::bounded::<SamplingPolicy>(REQUESTED_POLICY_CHANNEL_SIZE);
    let config_reload = Arc::new(Notify::new());
    let mut request_client = request::Client::new(
        args.manager_server.rpc_srv_addr,
        args.manager_server.name.clone(),
        request_send,
        cert_pem,
        key_pem,
        ca_certs_pem,
        config_reload.clone(),
    );
    let mut guard = None;

    loop {
        if let Err(e) = run(
            &args,
            &certs,
            request_client.clone(),
            request_recv.clone(),
            config_reload.clone(),
            &mut guard,
        )
        .await
        {
            assert!(args.is_remote_mode(), "{e}");
            error_or_eprint!("Main processing encountered an error: {e}");
            let health_check = e.downcast_ref::<std::io::Error>().is_some_and(|e| {
                matches!(
                    e.kind(),
                    ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset | ErrorKind::TimedOut
                )
            });
            request_client.enter_idle_mode(health_check).await;
        }
    }
}

async fn run(
    args: &CmdLineArgs,
    certs: &Certs,
    mut request_client: request::Client,
    request_recv: async_channel::Receiver<SamplingPolicy>,
    config_reload: Arc<Notify>,
    guard: &mut Option<WorkerGuard>,
) -> Result<()> {
    let (settings, is_local_config) = if let Some(local_config) = args.config.as_deref() {
        (Settings::from_file(local_config)?, true)
    } else {
        (
            Settings::from_str(&request_client.get_config().await?)?,
            false,
        )
    };
    if guard.is_none() {
        *guard = Some(init_tracing(settings.log_path.as_deref())?);
    }
    info!(
        "Time series generator has been configured with {} settings",
        if is_local_config { "local" } else { "remote" }
    );

    read_last_timestamp(&settings.last_timestamp_data).await?;

    let subscribe_client = subscribe::Client::new(
        settings.giganto_ingest_srv_addr,
        settings.giganto_publish_srv_addr,
        settings.giganto_name,
        settings.last_timestamp_data,
        certs,
        request_recv,
    );

    info!("Time series generate started");
    let shutdown = Arc::new(Notify::new());
    tokio::select! {
        Ok(Err(e)) = tokio::spawn(subscribe_client.run(
            request_client.active_policy_list.clone(),
            request_client.delete_policy_ids.clone(),
            shutdown.clone(),
        )) => {
            shutdown.notify_waiters();
            bail!(e);
        }
        Ok(Err(e)) = tokio::spawn({
            let shutdown = shutdown.clone();
            async move {
                request_client.run(shutdown).await
            }
        }) => {
            shutdown.notify_waiters();
            shutdown.notified().await;
            bail!(e);
        }
        () = config_reload.notified(), if args.is_remote_mode() => {
            shutdown.notify_waiters();
            shutdown.notified().await;
            info!("Reloading the configuration");
        },
    };
    Ok(())
}
