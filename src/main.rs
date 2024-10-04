mod client;
mod model;
mod request;
mod settings;
mod subscribe;

use std::path::Path;
use std::{collections::HashMap, env, fs, process::exit, sync::Arc};

use anyhow::{anyhow, bail, Context, Result};
use client::Certs;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use settings::Settings;
pub use settings::TEMP_TOML_POST_FIX;
use tokio::{
    sync::{Notify, RwLock},
    task,
};
use tracing::metadata::LevelFilter;
use tracing::{error, warn};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer,
};

use crate::{request::RequestedPolicy, subscribe::read_last_timestamp};

const REQUESTED_POLICY_CHANNEL_SIZE: usize = 1;
const DEFAULT_TOML: &str = "/usr/local/aice/conf/crusher.toml";
const USAGE: &str = "\
USAGE:
    crusher [CONFIG]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

ARG:
    <CONFIG>    A TOML config file
";

#[tokio::main]
async fn main() -> Result<()> {
    let config_filename = parse();
    let (mut settings, config_path) = if let Some(config_filename) = config_filename.clone() {
        (Settings::from_file(&config_filename)?, config_filename)
    } else {
        (Settings::new()?, DEFAULT_TOML.to_string())
    };
    let temp_path = format!("{config_path}{TEMP_TOML_POST_FIX}");

    let _guard = init_tracing(&settings.log_dir)?;

    loop {
        let config_reload = Arc::new(Notify::new());
        let notify_shutdown = Arc::new(Notify::new());

        let cert_pem = fs::read(&settings.cert).with_context(|| {
            format!(
                "failed to read certificate file: {}",
                settings.cert.display()
            )
        })?;
        let cert = to_cert_chain(&cert_pem).context("cannot read certificate chain")?;
        assert!(!cert.is_empty());
        let key_pem = fs::read(&settings.key).with_context(|| {
            format!(
                "failed to read private key file: {}",
                settings.key.display()
            )
        })?;
        let key = to_private_key(&key_pem).context("cannot read private key")?;
        let mut ca_certs_pem = Vec::new();
        for ca_cert in settings.ca_certs {
            let file = fs::read(&ca_cert).with_context(|| {
                format!("failed to read CA certificate file: {}", ca_cert.display())
            })?;
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
            settings.review_rpc_srv_addr,
            settings.review_name,
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
            config_reload.clone(),
            notify_shutdown.clone(),
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
            config_reload.notified().await;
            match Settings::from_file(&temp_path) {
                Ok(new_settings) => {
                    settings = new_settings;
                    notify_shutdown.notify_waiters();
                    notify_shutdown.notified().await;
                    fs::rename(&temp_path, &config_path).unwrap_or_else(|e| {
                        error!("Failed to rename the new configuration file: {e}");
                    });
                    break;
                }
                Err(e) => {
                    error!("Failed to load the new configuration: {:?}", e);
                    warn!("Run Crusher with the previous config");
                    fs::remove_file(&temp_path).unwrap_or_else(|e| {
                        error!("Failed to remove the temporary file: {e}");
                    });
                    continue;
                }
            }
        }
    }
}

/// Parses the command line arguments and returns the first argument.
fn parse() -> Option<String> {
    let mut args = env::args();
    args.next()?;
    let arg = args.next()?;
    if args.next().is_some() {
        eprintln!("Error: too many arguments");
        exit(1);
    }

    if arg == "--help" || arg == "-h" {
        println!("{}", version());
        println!();
        print!("{USAGE}");
        exit(0);
    }
    if arg == "--version" || arg == "-V" {
        println!("{}", version());
        exit(0);
    }
    if arg.starts_with('-') {
        eprintln!("Error: unknown option: {arg}");
        eprintln!("\n{USAGE}");
        exit(1);
    }

    Some(arg)
}

fn version() -> String {
    format!("crusher {}", env!("CARGO_PKG_VERSION"))
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

fn init_tracing(path: &Path) -> Result<WorkerGuard> {
    if !path.exists() {
        bail!("Path not found {path:?}");
    }

    let file_name = format!("{}.log", env!("CARGO_PKG_NAME"));
    if std::fs::File::create(path.join(&file_name)).is_err() {
        bail!("Cannot create file. {}/{file_name}", path.display());
    }

    let file_appender = tracing_appender::rolling::never(path, file_name);
    let (file_writer, guard) = tracing_appender::non_blocking(file_appender);

    let layer_file = fmt::Layer::default()
        .with_ansi(false)
        .with_target(false)
        .with_writer(file_writer)
        .with_filter(EnvFilter::from_default_env().add_directive(LevelFilter::INFO.into()));

    let layered_subscriber = tracing_subscriber::registry().with(layer_file);
    #[cfg(debug_assertions)]
    let layered_subscriber = layered_subscriber.with(
        fmt::Layer::default()
            .with_ansi(true)
            .with_filter(EnvFilter::from_default_env()),
    );
    layered_subscriber.init();

    Ok(guard)
}
