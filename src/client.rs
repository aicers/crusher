use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use quinn::{ClientConfig, Endpoint, TransportConfig, crypto::rustls::QuicClientConfig};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer},
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

    /// Loads CA certificates from PEM-encoded data.
    ///
    /// This function parses CA certificate bundles and adds all certificates found
    /// to a `RootCertStore`. It supports files containing multiple certificates,
    /// which is common in CA bundle files that include root and intermediate CAs.
    ///
    /// # Arguments
    ///
    /// * `ca_certs_pem` - A slice of byte slices, each containing PEM-encoded
    ///   certificate data. Each slice may contain one or more certificates.
    ///
    /// # Returns
    ///
    /// Returns a `RootCertStore` containing all successfully parsed certificates.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * The PEM data cannot be parsed (invalid format, corrupted data)
    /// * A certificate cannot be added to the store (invalid certificate format)
    pub(crate) fn to_ca_certs(ca_certs_pem: &[&[u8]]) -> Result<rustls::RootCertStore> {
        let mut root_cert = rustls::RootCertStore::empty();
        for &ca_cert_pem in ca_certs_pem {
            let root_certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut &*ca_cert_pem)
                .collect::<Result<_, _>>()
                .context("invalid PEM-encoded certificate")?;
            for cert in root_certs {
                root_cert
                    .add(cert)
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

#[cfg(test)]
mod tests {
    use super::*;

    const CERT_PATH: &str = "tests/cert.pem";
    const KEY_PATH: &str = "tests/key.pem";
    const CA_CERT_PATH: &str = "tests/ca_cert.pem";
    const CA_CERT_BUNDLE_PATH: &str = "tests/ca_cert_bundle.pem";

    #[test]
    fn test_try_new_success() {
        let cert_pem = std::fs::read(CERT_PATH).unwrap();
        let key_pem = std::fs::read(KEY_PATH).unwrap();
        let ca_pem = std::fs::read(CA_CERT_PATH).unwrap();
        let ca_certs_pem = &[ca_pem.as_slice()];

        let certs = Certs::try_new(&cert_pem, &key_pem, ca_certs_pem)
            .expect("Certs::try_new should succeed");
        assert!(!certs.certs.is_empty());
    }

    #[test]
    fn test_to_ca_certs_single_certificate() {
        let ca_pem = std::fs::read(CA_CERT_PATH).unwrap();
        let ca_certs_pem = &[ca_pem.as_slice()];

        let root_store =
            Certs::to_ca_certs(ca_certs_pem).expect("should load single CA certificate");
        assert_eq!(
            root_store.len(),
            1,
            "should contain exactly one certificate"
        );
    }

    #[test]
    fn test_to_ca_certs_multiple_certificates() {
        let ca_bundle_pem = std::fs::read(CA_CERT_BUNDLE_PATH).unwrap();
        let ca_certs_pem = &[ca_bundle_pem.as_slice()];

        let root_store =
            Certs::to_ca_certs(ca_certs_pem).expect("should load CA certificate bundle");
        assert_eq!(
            root_store.len(),
            2,
            "should contain all certificates from bundle"
        );
    }

    #[test]
    fn test_to_ca_certs_multiple_files() {
        let ca_pem1 = std::fs::read(CA_CERT_PATH).unwrap();
        let ca_pem2 = std::fs::read(CA_CERT_PATH).unwrap();
        let ca_certs_pem = &[ca_pem1.as_slice(), ca_pem2.as_slice()];

        let root_store = Certs::to_ca_certs(ca_certs_pem)
            .expect("should load CA certificates from multiple files");
        assert_eq!(
            root_store.len(),
            2,
            "should contain certificates from both files"
        );
    }

    #[test]
    fn test_to_ca_certs_empty_input() {
        let ca_certs_pem: &[&[u8]] = &[];

        let root_store = Certs::to_ca_certs(ca_certs_pem).expect("should handle empty input");
        assert_eq!(root_store.len(), 0, "should contain no certificates");
    }
}
