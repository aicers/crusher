mod client;
mod model;
mod request;
mod settings;
mod subscribe;

use crate::{request::RequestedPolicy, subscribe::read_last_timestamp};
use anyhow::{anyhow, bail, Context, Result};
use rustls::{Certificate, PrivateKey};
use settings::Settings;
use std::path::Path;
use std::{collections::HashMap, env, fs, process::exit, sync::Arc};
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

const REQUESTED_POLICY_CHANNEL_SIZE: usize = 1;
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
    let mut settings = if let Some(config_filename) = config_filename.clone() {
        Settings::from_file(&config_filename)?
    } else {
        Settings::new()?
    };

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

        let mut files: Vec<Vec<u8>> = Vec::new();
        for root in &settings.roots {
            let file = fs::read(root).expect("Failed to read file");
            files.push(file);
        }

        read_last_timestamp(&settings.last_timestamp_data).await?;

        let (request_send, request_recv) =
            async_channel::bounded::<RequestedPolicy>(REQUESTED_POLICY_CHANNEL_SIZE);

        let request_client = request::Client::new(
            settings.review_address,
            settings.review_name,
            cert.clone(),
            key.clone(),
            files.clone(),
            request_send,
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
            settings.giganto_ingest_address,
            settings.giganto_publish_address,
            settings.giganto_name,
            settings.last_timestamp_data,
            cert,
            key,
            files,
            request_recv,
        );
        task::spawn(subscribe_client.run(
            runtime_policy_list,
            delete_policy_ids,
            notify_shutdown.clone(),
        ));
        loop {
            config_reload.notified().await;
            if let Some(config_filename) = config_filename.clone() {
                match Settings::from_file(&config_filename) {
                    Ok(new_settings) => {
                        settings = new_settings;
                        notify_shutdown.notify_waiters();
                        notify_shutdown.notified().await;
                        break;
                    }
                    Err(e) => {
                        error!("Failed to load the new configuration: {:?}", e);
                        warn!("Run Crusher with the previous config");
                        continue;
                    }
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

fn to_cert_chain(pem: &[u8]) -> Result<Vec<Certificate>> {
    let certs = rustls_pemfile::certs(&mut &*pem).context("cannot parse certificate chain")?;
    if certs.is_empty() {
        bail!("no certificate found");
    }
    Ok(certs.into_iter().map(Certificate).collect())
}

fn to_private_key(pem: &[u8]) -> Result<PrivateKey> {
    match rustls_pemfile::read_one(&mut &*pem)
        .context("cannot parse private key")?
        .ok_or_else(|| anyhow!("empty private key"))?
    {
        rustls_pemfile::Item::PKCS8Key(key) | rustls_pemfile::Item::RSAKey(key) => {
            Ok(PrivateKey(key))
        }
        _ => Err(anyhow!("unknown private key format")),
    }
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
