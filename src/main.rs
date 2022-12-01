mod client;
mod model;
mod request;
mod settings;
mod subscribe;

use crate::{request::RequestedPolicy, subscribe::read_last_timestamp};
use anyhow::{anyhow, Context, Result};
use rustls::{Certificate, PrivateKey};
use settings::Settings;
use std::{env, fs, process::exit};
use tokio::task;

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
    let settings = if let Some(config_filename) = parse() {
        Settings::from_file(&config_filename)?
    } else {
        Settings::new()?
    };

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

    tracing_subscriber::fmt::init();

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
        settings.agent_id,
        cert.clone(),
        key.clone(),
        files.clone(),
        request_send,
    );
    task::spawn(request_client.run());

    let subscribe_client = subscribe::Client::new(
        settings.giganto_ingestion_address,
        settings.giganto_publish_address,
        settings.giganto_name,
        settings.last_timestamp_data,
        cert,
        key,
        files,
        request_recv,
    );
    subscribe_client.run().await;

    Ok(())
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
        print!("{}", USAGE);
        exit(0);
    }
    if arg == "--version" || arg == "-V" {
        println!("{}", version());
        exit(0);
    }
    if arg.starts_with('-') {
        eprintln!("Error: unknown option: {}", arg);
        eprintln!("\n{}", USAGE);
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
        return Err(anyhow!("no certificate found"));
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
