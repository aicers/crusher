use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use quinn::{crypto::rustls::QuicClientConfig, ClientConfig, Endpoint, TransportConfig};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    RootCertStore,
};
use tokio::time::Duration;

const KEEP_ALIVE_INTERVAL: Duration = Duration::from_millis(5_000);
pub(crate) const SERVER_RETRY_INTERVAL: u64 = 3;

#[allow(clippy::struct_field_names)]
pub(crate) struct Certs {
    pub(crate) certs: Vec<CertificateDer<'static>>,
    pub(crate) key: PrivateKeyDer<'static>,
    pub(crate) ca_certs: RootCertStore,
}

impl Certs {
    pub(crate) fn try_new(cert_pem: &[u8], key_pem: &[u8], ca_certs_pem: &[&[u8]]) -> Result<Self> {
        let certs = Self::to_cert_chain(cert_pem).context("cannot read certificate chain")?;
        assert!(!certs.is_empty());
        let key = Self::to_private_key(key_pem).context("cannot read private key")?;
        let ca_certs = Self::to_ca_certs(ca_certs_pem).context("failed to read CA certificates")?;
        Ok(Self {
            certs,
            key,
            ca_certs,
        })
    }

    pub(crate) fn to_cert_chain(raw: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
        let certs = rustls_pemfile::certs(&mut &*raw)
            .collect::<Result<_, _>>()
            .context("cannot parse certificate chain")?;
        Ok(certs)
    }

    pub(crate) fn to_private_key(raw: &[u8]) -> Result<PrivateKeyDer<'static>> {
        match rustls_pemfile::read_one(&mut &*raw)
            .context("cannot parse private key")?
            .ok_or_else(|| anyhow!("empty private key"))?
        {
            rustls_pemfile::Item::Pkcs1Key(key) => Ok(key.into()),
            rustls_pemfile::Item::Pkcs8Key(key) => Ok(key.into()),
            _ => Err(anyhow!("unknown private key format")),
        }
    }

    pub(crate) fn to_ca_certs(ca_certs_pem: &[&[u8]]) -> Result<rustls::RootCertStore> {
        let mut root_cert = rustls::RootCertStore::empty();
        for &ca_cert_pem in ca_certs_pem {
            let root_certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut &*ca_cert_pem)
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
}

pub(crate) fn config(certs: &Certs) -> Result<Endpoint> {
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(certs.ca_certs.clone())
        .with_client_auth_cert(certs.certs.clone(), certs.key.clone_key())?;

    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));

    let mut config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls_config)?));
    config.transport_config(Arc::new(transport));

    let mut endpoint = quinn::Endpoint::client((std::net::Ipv6Addr::UNSPECIFIED, 0).into())
        .expect("Failed to create endpoint");
    endpoint.set_default_client_config(config);

    Ok(endpoint)
}
