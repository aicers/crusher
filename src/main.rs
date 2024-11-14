mod client;
mod model;
mod request;
mod settings;
mod subscribe;

use std::fs::{create_dir_all, File, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::{Mutex, PoisonError};
use std::{collections::HashMap, env, fs, sync::Arc};

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use client::Certs;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use settings::Settings;
pub use settings::TEMP_TOML_POST_FIX;
use tokio::{
    sync::{mpsc, Notify, RwLock},
    task,
};
use tracing::metadata::LevelFilter;
use tracing::{error, info, warn};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer,
};

use crate::{request::RequestedPolicy, subscribe::read_last_timestamp};

const REQUESTED_POLICY_CHANNEL_SIZE: usize = 1;
const CONFIG_CHANNEL_SIZE: usize = 1;

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

#[tokio::main]
async fn main() -> Result<()> {
    let args = CmdLineArgs::parse();
    let mut settings = Settings::from_args(args.clone())?;
    let mut log_manager = init_tracing(settings.log_dir.as_deref())?;
    let (config_tx, mut config_rx) = mpsc::channel::<String>(CONFIG_CHANNEL_SIZE);

    loop {
        let notify_shutdown = Arc::new(Notify::new());

        let cert_pem = fs::read(&args.cert)
            .with_context(|| format!("failed to read certificate file: {}", args.cert))?;
        let cert = to_cert_chain(&cert_pem).context("cannot read certificate chain")?;
        assert!(!cert.is_empty());
        let key_pem = fs::read(&args.key)
            .with_context(|| format!("failed to read private key file: {}", args.key))?;
        let key = to_private_key(&key_pem).context("cannot read private key")?;
        let mut ca_certs_pem = Vec::new();
        for ca_cert in &args.ca_certs {
            let file = fs::read(ca_cert)
                .with_context(|| format!("failed to read CA certificate file: {ca_cert}"))?;
            ca_certs_pem.push(file);
        }
        let ca_certs = to_ca_certs(&ca_certs_pem).context("failed to read CA certificates")?;
        let certs = Arc::new(Certs {
            certs: cert.clone(),
            key: key.clone_key(),
            ca_certs: ca_certs.clone(),
        });

        read_last_timestamp(&settings.last_timestamp_data).await?;

        let (request_send, request_recv) =
            async_channel::bounded::<RequestedPolicy>(REQUESTED_POLICY_CHANNEL_SIZE);

        let request_client = request::Client::new(
            args.manager_server.rpc_srv_addr,
            args.manager_server.name.clone(),
            request_send,
            cert_pem,
            key_pem,
            ca_certs_pem,
        );
        let runtime_policy_list = Arc::new(RwLock::new(HashMap::new())); // current sampling_policy value
        let delete_policy_ids = Arc::new(RwLock::new(Vec::new()));
        task::spawn(request_client.run(
            Arc::clone(&runtime_policy_list),
            Arc::clone(&delete_policy_ids),
            notify_shutdown.clone(),
            config_tx.clone(),
        ));

        let subscribe_client = subscribe::Client::new(
            settings.giganto_ingest_srv_addr,
            settings.giganto_publish_srv_addr,
            settings.giganto_name,
            settings.last_timestamp_data,
            &certs,
            request_recv,
        );
        task::spawn(subscribe_client.run(
            runtime_policy_list,
            delete_policy_ids,
            notify_shutdown.clone(),
        ));
        loop {
            if let Some(config) = config_rx.recv().await {
                if args.config.is_some() {
                    warn!("Cannot update the configuration from the Manager server when a local configuration file is specified");
                    continue;
                }
                let Ok(new_settings) = Settings::from_str(&config) else {
                    error!("Failed to parse the configuration from the Manager server");
                    continue;
                };
                log_manager
                    .dynamic_log_file_writer
                    .change_log_dir(settings.log_dir.as_deref(), new_settings.log_dir.as_deref())?;
                settings = new_settings;
                notify_shutdown.notify_waiters();
                notify_shutdown.notified().await;
                info!("Updated the configuration from the Manager server");
                break;
            };
            info!("No new configuration received from the Manager server");
        }
    }
}

fn to_cert_chain(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let certs = rustls_pemfile::certs(&mut &*pem)
        .collect::<Result<_, _>>()
        .context("cannot parse certificate chain")?;
    Ok(certs)
}

fn to_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    match rustls_pemfile::read_one(&mut &*pem)
        .context("cannot parse private key")?
        .ok_or_else(|| anyhow!("empty private key"))?
    {
        rustls_pemfile::Item::Pkcs1Key(key) => Ok(key.into()),
        rustls_pemfile::Item::Pkcs8Key(key) => Ok(key.into()),
        _ => Err(anyhow!("unknown private key format")),
    }
}

fn to_ca_certs(ca_certs_pem: &Vec<Vec<u8>>) -> Result<rustls::RootCertStore> {
    let mut root_cert = rustls::RootCertStore::empty();
    for ca_cert_pem in ca_certs_pem {
        let root_certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut &**ca_cert_pem)
            .collect::<Result<_, _>>()
            .context("invalid PEM-encoded certificate")?;
        if let Some(cert) = root_certs.first() {
            root_cert
                .add(cert.to_owned())
                .context("failed to add CA certificate")?;
        }
    }
    Ok(root_cert)
}

/// Manages the log file and guards.
///
/// `_guards` will flush the logs when they are dropped.
///
/// `dynamic_log_file_writer` wraps the log file to allow changing its path dynamically.
/// If the log file is not provided, logs will be ignored by using `std::io::sink()`.
struct LogManager {
    _guards: Vec<WorkerGuard>,
    dynamic_log_file_writer: DynamicLogFileWriter,
}

#[derive(Clone)]
struct DynamicLogFileWriter {
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
}

impl DynamicLogFileWriter {
    fn try_new(dir_path: Option<&Path>) -> Result<Self> {
        Ok(Self {
            writer: Arc::new(Mutex::new(DynamicLogFileWriter::create_writer(dir_path)?)),
        })
    }

    fn create_log_file(dir_path: &Path) -> Result<File> {
        if let Err(e) = create_dir_all(dir_path) {
            bail!("Cannot create the directory recursively for {dir_path:?}: {e}");
        }

        let file_name = format!("{}.log", env!("CARGO_PKG_NAME"));

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir_path.join(file_name))
            .map_err(|e| anyhow!("Cannot create the log file: {e}"));

        file
    }

    fn create_writer(log_dir: Option<&Path>) -> Result<Box<dyn Write + Send>> {
        match log_dir {
            Some(dir) => Ok(Box::new(DynamicLogFileWriter::create_log_file(dir)?)),
            None => Ok(Box::new(std::io::sink())),
        }
    }

    fn change_log_dir(&mut self, old_dir: Option<&Path>, new_dir: Option<&Path>) -> Result<()> {
        if old_dir.eq(&new_dir) {
            info!("New log directory is the same as the old directory");
            return Ok(());
        }
        if let Some(dir) = new_dir {
            info!("Log directory will change to {}", dir.display());
        }
        let new_writer = DynamicLogFileWriter::create_writer(new_dir)?;
        {
            let mut old_writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
            *old_writer = new_writer;
        }
        if let Some(dir) = old_dir {
            info!("Previous logs are in {}", dir.display());
        }
        Ok(())
    }
}

impl Write for DynamicLogFileWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        writer.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        writer.flush()
    }
}

/// Initializes the tracing subscriber.
///
/// If `log_dir` is `None` or the runtime is in debug mode, logs will be printed to stdout.
fn init_tracing(log_dir: Option<&Path>) -> Result<LogManager> {
    let dynamic_log_file_writer = DynamicLogFileWriter::try_new(log_dir)?;
    let (file_writer, file_guard) = tracing_appender::non_blocking(dynamic_log_file_writer.clone());
    let file_layer = fmt::Layer::default()
        .with_ansi(false)
        .with_target(false)
        .with_writer(file_writer)
        .with_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        );
    let mut guards = vec![file_guard];

    let stdout_layer = if log_dir.is_none() || cfg!(debug_assertions) {
        let (stdout_writer, stdout_guard) = tracing_appender::non_blocking(std::io::stdout());
        guards.push(stdout_guard);
        Some(
            fmt::Layer::default()
                .with_ansi(true)
                .with_writer(stdout_writer)
                .with_filter(EnvFilter::from_default_env()),
        )
    } else {
        None
    };

    tracing_subscriber::Registry::default()
        .with(stdout_layer)
        .with(file_layer)
        .init();
    Ok(LogManager {
        _guards: guards,
        dynamic_log_file_writer,
    })
}
