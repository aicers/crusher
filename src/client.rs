use anyhow::{Context, Result};
use quinn::{ClientConfig, Endpoint, TransportConfig};
use rustls::{Certificate, PrivateKey};
use std::sync::Arc;
use tokio::time::Duration;

pub const KEEP_ALIVE_INTERVAL: Duration = Duration::from_millis(5_000);
pub const SERVER_RETRY_INTERVAL: u64 = 3;

pub fn config(certs: Vec<Certificate>, key: PrivateKey, files: Vec<Vec<u8>>) -> Result<Endpoint> {
    let mut root_store = rustls::RootCertStore::empty();
    for file in files {
        let root_cert: Vec<rustls::Certificate> = rustls_pemfile::certs(&mut &*file)
            .context("invalid PEM-encoded certificate")?
            .into_iter()
            .map(rustls::Certificate)
            .collect();
        if let Some(cert) = root_cert.first() {
            root_store.add(cert)?;
        }
    }

    let tls_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)?;

    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));

    let mut config = ClientConfig::new(Arc::new(tls_config));
    config.transport_config(Arc::new(transport));

    let mut endpoint =
        quinn::Endpoint::client("[::]:0".parse().expect("Failed to parse Endpoint addr"))
            .expect("Failed to create endpoint");
    endpoint.set_default_client_config(config);

    Ok(endpoint)
}
