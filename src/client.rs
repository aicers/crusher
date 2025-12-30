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

#[derive(Debug)]
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

#[cfg(test)]
mod tests {
    use super::*;

    const CERT_PATH: &str = "tests/cert.pem";
    const KEY_PATH: &str = "tests/key.pem";
    const CA_CERT_PATH: &str = "tests/ca_cert.pem";

    fn generate_self_signed_cert() -> (Vec<u8>, Vec<u8>) {
        use rcgen::{CertificateParams, KeyPair};

        let key_pair = KeyPair::generate().expect("Failed to generate key pair");
        let params = CertificateParams::default();
        let cert = params
            .self_signed(&key_pair)
            .expect("Failed to generate certificate");

        let cert_pem = cert.pem().into_bytes();
        let key_pem = key_pair.serialize_pem().into_bytes();
        (cert_pem, key_pem)
    }

    fn generate_ca_cert() -> Vec<u8> {
        use rcgen::{CertificateParams, IsCa, KeyPair};

        let key_pair = KeyPair::generate().expect("Failed to generate key pair");
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params
            .self_signed(&key_pair)
            .expect("Failed to generate CA certificate");
        cert.pem().into_bytes()
    }

    // =========================================================================
    // Certificate Chain Parsing Tests
    // =========================================================================

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
    fn test_to_cert_chain_valid_pem() {
        let (cert_pem, _) = generate_self_signed_cert();
        let certs = Certs::to_cert_chain(&cert_pem).expect("Should parse valid certificate");
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn test_to_cert_chain_from_test_file() {
        let cert_pem = std::fs::read(CERT_PATH).unwrap();
        let certs = Certs::to_cert_chain(&cert_pem).expect("Should parse test certificate");
        assert!(!certs.is_empty());
    }

    #[test]
    fn test_to_cert_chain_empty_returns_empty() {
        let certs = Certs::to_cert_chain(b"").expect("Empty input should return empty vec");
        assert!(certs.is_empty());
    }

    #[test]
    fn test_to_cert_chain_invalid_pem_content() {
        let invalid_pem =
            b"-----BEGIN CERTIFICATE-----\nINVALID_BASE64_DATA!!!\n-----END CERTIFICATE-----\n";
        let result = Certs::to_cert_chain(invalid_pem);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("cannot parse certificate chain"),
            "Error message should contain 'cannot parse certificate chain': {err_msg}"
        );
    }

    #[test]
    fn test_to_cert_chain_non_pem_data() {
        let garbage = b"this is not a PEM file at all";
        let certs = Certs::to_cert_chain(garbage).expect("Non-PEM data returns empty vec");
        assert!(certs.is_empty());
    }

    // =========================================================================
    // Private Key Parsing Tests
    // =========================================================================

    #[test]
    fn test_to_private_key_valid_pkcs8() {
        let (_, key_pem) = generate_self_signed_cert();
        let key = Certs::to_private_key(&key_pem).expect("Should parse PKCS8 private key");
        assert!(matches!(key, PrivateKeyDer::Pkcs8(_)));
    }

    #[test]
    fn test_to_private_key_from_test_file() {
        let key_pem = std::fs::read(KEY_PATH).unwrap();
        let key = Certs::to_private_key(&key_pem).expect("Should parse test private key");
        assert!(
            matches!(key, PrivateKeyDer::Pkcs1(_) | PrivateKeyDer::Pkcs8(_)),
            "Key should be PKCS1 or PKCS8 format"
        );
    }

    #[test]
    fn test_to_private_key_empty_input() {
        let result = Certs::to_private_key(b"");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("empty private key"),
            "Error message should contain 'empty private key': {err_msg}"
        );
    }

    #[test]
    fn test_to_private_key_invalid_pem_content() {
        let invalid_key =
            b"-----BEGIN PRIVATE KEY-----\nINVALID_BASE64_DATA!!!\n-----END PRIVATE KEY-----\n";
        let result = Certs::to_private_key(invalid_key);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("cannot parse private key"),
            "Error message should contain 'cannot parse private key': {err_msg}"
        );
    }

    #[test]
    fn test_to_private_key_certificate_instead_of_key() {
        let (cert_pem, _) = generate_self_signed_cert();
        let result = Certs::to_private_key(&cert_pem);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("unknown private key format"),
            "Error message should contain 'unknown private key format': {err_msg}"
        );
    }

    #[test]
    fn test_to_private_key_garbage_data() {
        let garbage = b"this is not a private key";
        let result = Certs::to_private_key(garbage);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("empty private key"),
            "Error message should contain 'empty private key': {err_msg}"
        );
    }

    // =========================================================================
    // CA Certificate Parsing Tests
    // =========================================================================

    #[test]
    fn test_to_ca_certs_valid() {
        let ca_cert = generate_ca_cert();
        let ca_certs_pem: &[&[u8]] = &[&ca_cert];
        let root_store =
            Certs::to_ca_certs(ca_certs_pem).expect("Should parse valid CA certificate");
        assert!(!root_store.is_empty());
    }

    #[test]
    fn test_to_ca_certs_from_test_file() {
        let ca_pem = std::fs::read(CA_CERT_PATH).unwrap();
        let ca_certs_pem: &[&[u8]] = &[&ca_pem];
        let root_store =
            Certs::to_ca_certs(ca_certs_pem).expect("Should parse test CA certificate");
        assert!(!root_store.is_empty());
    }

    #[test]
    fn test_to_ca_certs_multiple_cas() {
        let ca1 = generate_ca_cert();
        let ca2 = generate_ca_cert();
        let ca_certs_pem: &[&[u8]] = &[&ca1, &ca2];
        let root_store =
            Certs::to_ca_certs(ca_certs_pem).expect("Should parse multiple CA certificates");
        assert_eq!(root_store.len(), 2);
    }

    #[test]
    fn test_to_ca_certs_empty_list() {
        let ca_certs_pem: &[&[u8]] = &[];
        let root_store = Certs::to_ca_certs(ca_certs_pem).expect("Empty list should succeed");
        assert!(root_store.is_empty());
    }

    #[test]
    fn test_to_ca_certs_empty_pem() {
        let ca_certs_pem: &[&[u8]] = &[b""];
        let root_store = Certs::to_ca_certs(ca_certs_pem)
            .expect("Empty PEM content should succeed with empty store");
        assert!(root_store.is_empty());
    }

    #[test]
    fn test_to_ca_certs_invalid_pem() {
        let invalid_ca =
            b"-----BEGIN CERTIFICATE-----\nINVALID_BASE64_DATA!!!\n-----END CERTIFICATE-----\n";
        let ca_certs_pem: &[&[u8]] = &[invalid_ca];
        let result = Certs::to_ca_certs(ca_certs_pem);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("invalid PEM-encoded certificate"),
            "Error message should contain 'invalid PEM-encoded certificate': {err_msg}"
        );
    }

    #[test]
    fn test_to_ca_certs_non_pem_data() {
        let garbage: &[u8] = b"this is not a certificate";
        let ca_certs_pem: &[&[u8]] = &[garbage];
        let root_store =
            Certs::to_ca_certs(ca_certs_pem).expect("Non-PEM data should succeed with empty store");
        assert!(root_store.is_empty());
    }

    // =========================================================================
    // Certs::try_new Error Path Tests
    // =========================================================================

    #[test]
    fn test_try_new_invalid_cert() {
        // Use completely invalid base64 that will definitely fail to parse
        let invalid_cert =
            b"-----BEGIN CERTIFICATE-----\n!!NOT_VALID_BASE64!!\n-----END CERTIFICATE-----\n";
        let (_, key_pem) = generate_self_signed_cert();
        let ca_cert = generate_ca_cert();
        let ca_certs_pem: &[&[u8]] = &[&ca_cert];

        let result = Certs::try_new(invalid_cert, &key_pem, ca_certs_pem);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("cannot read certificate chain"),
            "Error message should contain 'cannot read certificate chain': {err_msg}"
        );
    }

    #[test]
    fn test_try_new_invalid_key() {
        let (cert_pem, _) = generate_self_signed_cert();
        // Use completely invalid base64 that will definitely fail to parse
        let invalid_key =
            b"-----BEGIN PRIVATE KEY-----\n!!NOT_VALID_BASE64!!\n-----END PRIVATE KEY-----\n";
        let ca_cert = generate_ca_cert();
        let ca_certs_pem: &[&[u8]] = &[&ca_cert];

        let result = Certs::try_new(&cert_pem, invalid_key, ca_certs_pem);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("cannot read private key"),
            "Error message should contain 'cannot read private key': {err_msg}"
        );
    }

    #[test]
    fn test_try_new_invalid_ca() {
        let (cert_pem, key_pem) = generate_self_signed_cert();
        // Use completely invalid base64 that will definitely fail to parse
        let invalid_ca =
            b"-----BEGIN CERTIFICATE-----\n!!NOT_VALID_BASE64!!\n-----END CERTIFICATE-----\n";
        let ca_certs_pem: &[&[u8]] = &[invalid_ca];

        let result = Certs::try_new(&cert_pem, &key_pem, ca_certs_pem);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("failed to read CA certificates"),
            "Error message should contain 'failed to read CA certificates': {err_msg}"
        );
    }

    #[test]
    fn test_try_new_with_generated_certs() {
        let (cert_pem, key_pem) = generate_self_signed_cert();
        let ca_cert = generate_ca_cert();
        let ca_certs_pem: &[&[u8]] = &[&ca_cert];

        let certs = Certs::try_new(&cert_pem, &key_pem, ca_certs_pem)
            .expect("Should succeed with generated certificates");
        assert_eq!(certs.certs.len(), 1);
        assert!(!certs.ca_certs.is_empty());
    }

    // =========================================================================
    // Quinn Endpoint Configuration Tests
    // =========================================================================

    #[tokio::test]
    async fn test_config_creates_endpoint() {
        let cert_pem = std::fs::read(CERT_PATH).unwrap();
        let key_pem = std::fs::read(KEY_PATH).unwrap();
        let ca_pem = std::fs::read(CA_CERT_PATH).unwrap();
        let ca_certs_pem: &[&[u8]] = &[&ca_pem];

        let certs = Certs::try_new(&cert_pem, &key_pem, ca_certs_pem)
            .expect("Certs::try_new should succeed");
        let endpoint = config(&certs).expect("config should create endpoint successfully");

        assert!(
            endpoint.local_addr().is_ok(),
            "Endpoint should have a local address"
        );
    }

    #[tokio::test]
    async fn test_config_with_generated_certs() {
        let (cert_pem, key_pem) = generate_self_signed_cert();
        let ca_cert = generate_ca_cert();
        let ca_certs_pem: &[&[u8]] = &[&ca_cert];

        let certs = Certs::try_new(&cert_pem, &key_pem, ca_certs_pem)
            .expect("Certs::try_new should succeed");
        let endpoint = config(&certs).expect("config should create endpoint successfully");

        let local_addr = endpoint.local_addr().expect("Should have local address");
        assert!(local_addr.port() > 0, "Endpoint should be bound to a port");
    }

    #[test]
    fn test_keep_alive_interval_constant() {
        assert_eq!(
            KEEP_ALIVE_INTERVAL,
            Duration::from_millis(5_000),
            "Keep-alive interval should be 5 seconds"
        );
    }

    #[test]
    fn test_server_retry_interval_constant() {
        assert_eq!(
            SERVER_RETRY_INTERVAL, 3,
            "Server retry interval should be 3 seconds"
        );
    }

    // =========================================================================
    // Transport Configuration Tests
    // =========================================================================

    #[test]
    fn test_transport_config_keep_alive_can_be_set() {
        let mut transport = TransportConfig::default();
        // Verify that setting keep_alive_interval doesn't panic
        // and returns &mut Self for chaining
        let result = transport.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));
        // The method returns &mut Self for builder pattern
        assert!(
            std::ptr::eq(result, &raw const transport),
            "keep_alive_interval should return &mut Self"
        );
    }

    #[test]
    fn test_transport_config_none_keep_alive() {
        let mut transport = TransportConfig::default();
        // Verify that setting None doesn't panic
        let result = transport.keep_alive_interval(None);
        assert!(
            std::ptr::eq(result, &raw const transport),
            "keep_alive_interval(None) should return &mut Self"
        );
    }

    #[test]
    fn test_transport_config_various_intervals() {
        let mut transport = TransportConfig::default();

        // Test various interval values don't cause issues
        // If any of these panic, the test will fail
        transport.keep_alive_interval(Some(Duration::from_secs(1)));
        transport.keep_alive_interval(Some(Duration::from_secs(10)));
        transport.keep_alive_interval(Some(Duration::from_millis(500)));
        transport.keep_alive_interval(Some(Duration::from_millis(5_000)));
    }

    // =========================================================================
    // TLS Configuration Tests
    // =========================================================================

    #[test]
    fn test_rustls_client_config_creation() {
        let (cert_pem, key_pem) = generate_self_signed_cert();
        let ca_cert = generate_ca_cert();
        let ca_certs_pem: &[&[u8]] = &[&ca_cert];

        let certs = Certs::try_new(&cert_pem, &key_pem, ca_certs_pem)
            .expect("Certs::try_new should succeed");

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(certs.ca_certs.clone())
            .with_client_auth_cert(certs.certs.clone(), certs.key.clone_key());

        assert!(
            tls_config.is_ok(),
            "TLS config should be created successfully"
        );
    }

    #[test]
    fn test_quic_client_config_creation() {
        let (cert_pem, key_pem) = generate_self_signed_cert();
        let ca_cert = generate_ca_cert();
        let ca_certs_pem: &[&[u8]] = &[&ca_cert];

        let certs = Certs::try_new(&cert_pem, &key_pem, ca_certs_pem)
            .expect("Certs::try_new should succeed");

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(certs.ca_certs.clone())
            .with_client_auth_cert(certs.certs.clone(), certs.key.clone_key())
            .expect("TLS config should be created");

        let quic_config = QuicClientConfig::try_from(tls_config);
        assert!(
            quic_config.is_ok(),
            "QUIC client config should be created successfully"
        );
    }

    #[test]
    fn test_client_config_with_transport() {
        let (cert_pem, key_pem) = generate_self_signed_cert();
        let ca_cert = generate_ca_cert();
        let ca_certs_pem: &[&[u8]] = &[&ca_cert];

        let certs = Certs::try_new(&cert_pem, &key_pem, ca_certs_pem)
            .expect("Certs::try_new should succeed");

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(certs.ca_certs.clone())
            .with_client_auth_cert(certs.certs.clone(), certs.key.clone_key())
            .expect("TLS config should be created");

        let mut transport = TransportConfig::default();
        transport.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));

        let mut client_config =
            ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls_config).unwrap()));
        client_config.transport_config(Arc::new(transport));

        // Verify that the client config was created (we can't easily inspect
        // the internal transport config, but creating without panic is success)
        // The fact that we got here means the test passes
        drop(client_config);
    }

    // =========================================================================
    // Tempfile-based Tests (file I/O paths)
    // =========================================================================

    #[test]
    fn test_load_cert_from_tempfile() {
        use std::io::Write;

        use tempfile::NamedTempFile;

        let (cert_pem, _) = generate_self_signed_cert();

        let mut cert_file = NamedTempFile::new().expect("Failed to create temp file");
        cert_file
            .write_all(&cert_pem)
            .expect("Failed to write cert");
        cert_file.flush().expect("Failed to flush");

        let loaded = std::fs::read(cert_file.path()).expect("Failed to read temp file");
        let certs = Certs::to_cert_chain(&loaded).expect("Should parse certificate from temp file");
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn test_load_key_from_tempfile() {
        use std::io::Write;

        use tempfile::NamedTempFile;

        let (_, key_pem) = generate_self_signed_cert();

        let mut key_file = NamedTempFile::new().expect("Failed to create temp file");
        key_file.write_all(&key_pem).expect("Failed to write key");
        key_file.flush().expect("Failed to flush");

        let loaded = std::fs::read(key_file.path()).expect("Failed to read temp file");
        let key = Certs::to_private_key(&loaded).expect("Should parse key from temp file");
        assert!(matches!(key, PrivateKeyDer::Pkcs8(_)));
    }

    #[test]
    fn test_full_cert_loading_from_tempfiles() {
        use std::io::Write;

        use tempfile::NamedTempFile;

        let (cert_pem, key_pem) = generate_self_signed_cert();
        let ca_cert = generate_ca_cert();

        let mut cert_file = NamedTempFile::new().expect("Failed to create temp file");
        cert_file
            .write_all(&cert_pem)
            .expect("Failed to write cert");
        cert_file.flush().expect("Failed to flush");

        let mut key_file = NamedTempFile::new().expect("Failed to create temp file");
        key_file.write_all(&key_pem).expect("Failed to write key");
        key_file.flush().expect("Failed to flush");

        let mut ca_file = NamedTempFile::new().expect("Failed to create temp file");
        ca_file.write_all(&ca_cert).expect("Failed to write CA");
        ca_file.flush().expect("Failed to flush");

        let cert_data = std::fs::read(cert_file.path()).expect("Failed to read cert");
        let key_data = std::fs::read(key_file.path()).expect("Failed to read key");
        let ca_data = std::fs::read(ca_file.path()).expect("Failed to read CA");

        let ca_certs_pem: &[&[u8]] = &[&ca_data];
        let certs = Certs::try_new(&cert_data, &key_data, ca_certs_pem)
            .expect("Should load certs from temp files");

        assert_eq!(certs.certs.len(), 1);
        assert!(!certs.ca_certs.is_empty());
    }
}
