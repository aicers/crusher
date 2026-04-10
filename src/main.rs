mod client;
mod logging;
mod policy;
mod request;
mod settings;
mod shutdown;
mod subscribe;

use std::fs;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use client::Certs;
use logging::init_tracing;
use review_protocol::types::SamplingPolicy;
use settings::Settings;
use shutdown::ShutdownCoordinator;
use subscribe::{clear_ingest_channel, ensure_time_data_exists, read_last_timestamp};
use tokio::sync::Notify;
use tracing::{error, info};
use tracing_appender::non_blocking::WorkerGuard;

const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

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
            request_send.clone(),
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
    request_send: async_channel::Sender<SamplingPolicy>,
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

    ensure_time_data_exists(&settings.last_timestamp_data)
        .context("Failed to initialize last timestamp data file")?;
    read_last_timestamp(&settings.last_timestamp_data).await?;

    let giganto_name = settings.resolve_giganto_name()?;
    let subscribe_client = subscribe::Client::new(
        settings.giganto_ingest_srv_addr,
        settings.giganto_publish_srv_addr,
        giganto_name,
        settings.last_timestamp_data,
        certs,
        request_recv,
    );

    info!("Time series generate started");
    let coordinator = ShutdownCoordinator::new();

    // Spawn the policy actor. All policy state mutations go through
    // this handle, ensuring atomicity and cancellation safety.
    let policy_handle = policy::spawn_policy_actor(request_send, &coordinator);
    request_client.set_policy_handle(policy_handle.clone());

    // Spawn top-level tasks with tokio::spawn (NOT tracker.spawn).
    // run() explicitly owns these handles and drives them to
    // completion, while TaskTracker is reserved for child/background
    // tasks spawned inside subscribe and request.
    let mut subscribe_handle =
        tokio::spawn(subscribe_client.run(policy_handle, coordinator.clone()));

    let request_coordinator = coordinator.clone();
    let mut request_handle =
        tokio::spawn(async move { request_client.run(request_coordinator).await });

    let result = tokio::select! {
        biased;
        res = &mut subscribe_handle => {
            coordinator.request_shutdown("subscribe exit");
            match res {
                Ok(Err(e)) => Err(e),
                Ok(Ok(())) => Ok(()),
                Err(e) => Err(anyhow::anyhow!("subscribe task panicked: {e}")),
            }
        }
        res = &mut request_handle => {
            coordinator.request_shutdown("request exit");
            match res {
                Ok(Err(e)) => Err(e),
                Ok(Ok(())) => Ok(()),
                Err(e) => Err(anyhow::anyhow!("request task panicked: {e}")),
            }
        }
        () = config_reload.notified(), if args.is_remote_mode() => {
            coordinator.request_shutdown("config reload");
            info!("Reloading the configuration");
            Ok(())
        },
    };

    // Explicitly drive the remaining top-level tasks to completion.
    // The completed one aborts as a no-op; the live one will see
    // cancelled() and exit cooperatively.
    subscribe_handle.abort();
    request_handle.abort();
    let _ = tokio::join!(subscribe_handle, request_handle);

    // Wait for child/background tasks (tracked by TaskTracker).
    if !coordinator.wait_for_drain(SHUTDOWN_DRAIN_TIMEOUT).await {
        error!(
            "Shutdown drain timed out; aborting to prevent \
             overlapping generations"
        );
        clear_ingest_channel().await;
        std::process::exit(1);
    }

    // Clear stale senders so no previous-run channels leak into a
    // subsequent run (e.g. after a config-reload restart).
    clear_ingest_channel().await;
    result
}
