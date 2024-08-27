use std::sync::Arc;

use anyhow::Result;
use quinn::{crypto::rustls::QuicClientConfig, ClientConfig, Endpoint, TransportConfig};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    RootCertStore,
};
use tokio::time::Duration;

pub const KEEP_ALIVE_INTERVAL: Duration = Duration::from_millis(5_000);
pub const SERVER_RETRY_INTERVAL: u64 = 3;

#[allow(clippy::struct_field_names)]
pub struct Certs {
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    pub root: RootCertStore,
}

impl Clone for Certs {
    fn clone(&self) -> Self {
        Self {
            certs: self.certs.clone(),
            key: self.key.clone_key(),
            root: self.root.clone(),
        }
    }
}

pub fn config(certs: &Arc<Certs>) -> Result<Endpoint> {
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(certs.root.clone())
        .with_client_auth_cert(certs.certs.clone(), certs.key.clone_key())?;

    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));

    let mut config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls_config)?));
    config.transport_config(Arc::new(transport));

    let mut endpoint =
        quinn::Endpoint::client("[::]:0".parse().expect("Failed to parse Endpoint addr"))
            .expect("Failed to create endpoint");
    endpoint.set_default_client_config(config);

    Ok(endpoint)
}
