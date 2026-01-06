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
        let key = Self::to_private_key(key_pem).context("cannot read private key")?;
        let ca_certs = Self::to_ca_certs(ca_certs_pem).context("failed to read CA certificates")?;
        Ok(Self {
            certs,
            key,
            ca_certs,
        })
    }

    pub(crate) fn to_cert_chain(raw: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &*raw)
            .collect::<Result<_, _>>()
            .context("cannot parse certificate chain")?;
        if certs.is_empty() {
            return Err(anyhow!("empty certificate chain"));
        }
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
        if root_cert.is_empty() {
            return Err(anyhow!("empty CA certificate store"));
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
    use std::io::Write;

    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
    use rstest::fixture;
    use tempfile::NamedTempFile;

    use super::*;

    const CERT_PATH: &str = "tests/cert.pem";
    const KEY_PATH: &str = "tests/key.pem";
    const CA_CERT_PATH: &str = "tests/ca_cert.pem";

    // =========================================================================
    // Certificate Set Structure and Fixtures
    // =========================================================================

    /// A complete set of PEM-encoded certificates for testing
    #[allow(clippy::struct_field_names)]
    struct CertificateSet {
        /// CA certificate PEM
        ca_cert_pem: Vec<u8>,
        /// Leaf/client certificate PEM (or full chain if applicable)
        cert_pem: Vec<u8>,
        /// Private key PEM for the leaf certificate
        key_pem: Vec<u8>,
    }

    /// Generates a CA certificate and key pair along with its params for signing
    fn generate_ca(cn: &str, days_valid: i64) -> (rcgen::Certificate, CertificateParams, KeyPair) {
        let key_pair = KeyPair::generate().expect("Failed to generate CA key pair");
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, cn.to_string());
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

        if days_valid < 0 {
            // Expired CA: set not_before in the past and not_after also in the past
            let past_end = time::OffsetDateTime::now_utc() - time::Duration::days(1);
            let past_start = past_end - time::Duration::days(-days_valid);
            params.not_before = past_start;
            params.not_after = past_end;
        } else {
            let now = time::OffsetDateTime::now_utc();
            params.not_before = now;
            params.not_after = now + time::Duration::days(days_valid);
        }

        let cert = params
            .clone()
            .self_signed(&key_pair)
            .expect("Failed to generate CA certificate");
        (cert, params, key_pair)
    }

    /// Generates a leaf certificate signed by the given CA
    fn generate_leaf_signed_by_ca(
        cn: &str,
        ca_params: &CertificateParams,
        ca_key: &KeyPair,
        days_valid: i64,
    ) -> (Vec<u8>, Vec<u8>) {
        let key_pair = KeyPair::generate().expect("Failed to generate leaf key pair");
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::NoCa;
        params
            .distinguished_name
            .push(DnType::CommonName, cn.to_string());

        if days_valid < 0 {
            // Expired leaf: set validity in the past
            let past_end = time::OffsetDateTime::now_utc() - time::Duration::days(1);
            let past_start = past_end - time::Duration::days(-days_valid);
            params.not_before = past_start;
            params.not_after = past_end;
        } else {
            let now = time::OffsetDateTime::now_utc();
            params.not_before = now;
            params.not_after = now + time::Duration::days(days_valid);
        }

        // Create issuer from CA params and key
        let issuer = rcgen::Issuer::from_params(ca_params, ca_key);
        let cert = params
            .signed_by(&key_pair, &issuer)
            .expect("Failed to sign leaf certificate");

        let cert_pem = cert.pem().into_bytes();
        let key_pem = key_pair.serialize_pem().into_bytes();
        (cert_pem, key_pem)
    }

    /// Generates a self-signed certificate (not signed by a CA)
    fn generate_self_signed(cn: &str) -> (Vec<u8>, Vec<u8>) {
        let key_pair = KeyPair::generate().expect("Failed to generate key pair");
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, cn.to_string());
        let cert = params
            .self_signed(&key_pair)
            .expect("Failed to generate self-signed certificate");
        let cert_pem = cert.pem().into_bytes();
        let key_pem = key_pair.serialize_pem().into_bytes();
        (cert_pem, key_pem)
    }

    // =========================================================================
    // RSTest Fixtures
    // =========================================================================

    /// Fixture: Valid full-chain certificate set (CA signs leaf, both valid)
    #[fixture]
    fn valid_full_chain() -> CertificateSet {
        let (ca_cert, ca_params, ca_key) = generate_ca("Test CA", 365);
        let ca_cert_pem = ca_cert.pem().into_bytes();
        let (leaf_cert_pem, leaf_key_pem) =
            generate_leaf_signed_by_ca("localhost", &ca_params, &ca_key, 365);

        // Create full chain: leaf + CA
        let mut full_chain = leaf_cert_pem;
        full_chain.extend_from_slice(&ca_cert_pem);

        CertificateSet {
            ca_cert_pem,
            cert_pem: full_chain,
            key_pem: leaf_key_pem,
        }
    }

    /// Fixture: Self-signed certificate (signed by own key, no CA involvement)
    #[fixture]
    fn self_signed_cert() -> CertificateSet {
        let (cert_pem, key_pem) = generate_self_signed("localhost");
        // For self-signed, the cert itself acts as the CA
        CertificateSet {
            ca_cert_pem: cert_pem.clone(),
            cert_pem,
            key_pem,
        }
    }

    /// Fixture: Incomplete chain (leaf only, no CA in chain)
    #[fixture]
    fn incomplete_chain() -> CertificateSet {
        let (ca_cert, ca_params, ca_key) = generate_ca("Test CA", 365);
        let ca_cert_pem = ca_cert.pem().into_bytes();
        let (leaf_cert_pem, leaf_key_pem) =
            generate_leaf_signed_by_ca("localhost", &ca_params, &ca_key, 365);

        // Only leaf cert, not the full chain
        CertificateSet {
            ca_cert_pem,
            cert_pem: leaf_cert_pem,
            key_pem: leaf_key_pem,
        }
    }

    /// Fixture: CN mismatch (CA CN: "Manager", Leaf CN: "localhost")
    #[fixture]
    fn cn_mismatch() -> CertificateSet {
        let (ca_cert, ca_params, ca_key) = generate_ca("Manager", 365);
        let ca_cert_pem = ca_cert.pem().into_bytes();
        let (leaf_cert_pem, leaf_key_pem) =
            generate_leaf_signed_by_ca("localhost", &ca_params, &ca_key, 365);

        let mut full_chain = leaf_cert_pem;
        full_chain.extend_from_slice(&ca_cert_pem);

        CertificateSet {
            ca_cert_pem,
            cert_pem: full_chain,
            key_pem: leaf_key_pem,
        }
    }

    /// Fixture: Expired CA certificate
    #[fixture]
    fn expired_ca() -> CertificateSet {
        let (ca_cert, ca_params, ca_key) = generate_ca("Expired CA", -30); // Expired 30 days ago
        let ca_cert_pem = ca_cert.pem().into_bytes();
        let (leaf_cert_pem, leaf_key_pem) =
            generate_leaf_signed_by_ca("localhost", &ca_params, &ca_key, 365);

        let mut full_chain = leaf_cert_pem;
        full_chain.extend_from_slice(&ca_cert_pem);

        CertificateSet {
            ca_cert_pem,
            cert_pem: full_chain,
            key_pem: leaf_key_pem,
        }
    }

    /// Fixture: Expired leaf certificate (CA is valid)
    #[fixture]
    fn expired_leaf() -> CertificateSet {
        let (ca_cert, ca_params, ca_key) = generate_ca("Test CA", 365);
        let ca_cert_pem = ca_cert.pem().into_bytes();
        let (leaf_cert_pem, leaf_key_pem) =
            generate_leaf_signed_by_ca("localhost", &ca_params, &ca_key, -30); // Expired 30 days ago

        let mut full_chain = leaf_cert_pem;
        full_chain.extend_from_slice(&ca_cert_pem);

        CertificateSet {
            ca_cert_pem,
            cert_pem: full_chain,
            key_pem: leaf_key_pem,
        }
    }

    // =========================================================================
    // Certificate Chain Parsing Tests
    // =========================================================================

    #[test]
    fn test_try_new_success() {
        let cert_pem = std::fs::read(CERT_PATH).expect("Failed to read cert.pem");
        let key_pem = std::fs::read(KEY_PATH).expect("Failed to read key.pem");
        let ca_pem = std::fs::read(CA_CERT_PATH).expect("Failed to read ca_cert.pem");
        let ca_certs_pem = &[ca_pem.as_slice()];

        let certs = Certs::try_new(&cert_pem, &key_pem, ca_certs_pem)
            .expect("Certs::try_new should succeed");
        assert!(!certs.certs.is_empty());
    }

    #[rstest::rstest]
    fn test_to_cert_chain_valid_pem(valid_full_chain: CertificateSet) {
        let certs = Certs::to_cert_chain(&valid_full_chain.cert_pem)
            .expect("Should parse valid certificate");
        assert!(!certs.is_empty());
    }

    #[rstest::rstest]
    fn test_to_cert_chain_self_signed(self_signed_cert: CertificateSet) {
        let certs = Certs::to_cert_chain(&self_signed_cert.cert_pem)
            .expect("Should parse self-signed certificate");
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn test_to_cert_chain_from_test_file() {
        let cert_pem = std::fs::read(CERT_PATH).expect("Failed to read cert.pem");
        let certs = Certs::to_cert_chain(&cert_pem).expect("Should parse test certificate");
        assert!(!certs.is_empty());
    }

    #[test]
    fn test_to_cert_chain_empty_returns_error() {
        let result = Certs::to_cert_chain(b"");
        assert!(result.is_err());
        let err_msg = result.expect_err("Expected error").to_string();
        assert!(
            err_msg.contains("empty certificate chain"),
            "Error message should contain 'empty certificate chain': {err_msg}"
        );
    }

    #[test]
    fn test_to_cert_chain_invalid_pem_content() {
        let invalid_pem =
            b"-----BEGIN CERTIFICATE-----\nINVALID_BASE64_DATA!!!\n-----END CERTIFICATE-----\n";
        let result = Certs::to_cert_chain(invalid_pem);
        assert!(result.is_err());
        let err_msg = result.expect_err("Expected error").to_string();
        assert!(
            err_msg.contains("cannot parse certificate chain"),
            "Error message should contain 'cannot parse certificate chain': {err_msg}"
        );
    }

    #[test]
    fn test_to_cert_chain_non_pem_data_returns_error() {
        let garbage = b"this is not a PEM file at all";
        let result = Certs::to_cert_chain(garbage);
        assert!(result.is_err());
        let err_msg = result.expect_err("Expected error").to_string();
        assert!(
            err_msg.contains("empty certificate chain"),
            "Error message should contain 'empty certificate chain': {err_msg}"
        );
    }

    // =========================================================================
    // Private Key Parsing Tests
    // =========================================================================

    #[rstest::rstest]
    fn test_to_private_key_valid_pkcs8(valid_full_chain: CertificateSet) {
        let key = Certs::to_private_key(&valid_full_chain.key_pem)
            .expect("Should parse PKCS8 private key");
        assert!(matches!(key, PrivateKeyDer::Pkcs8(_)));
    }

    #[test]
    fn test_to_private_key_from_test_file() {
        let key_pem = std::fs::read(KEY_PATH).expect("Failed to read key.pem");
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
        let err_msg = result.expect_err("Expected error").to_string();
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
        let err_msg = result.expect_err("Expected error").to_string();
        assert!(
            err_msg.contains("cannot parse private key"),
            "Error message should contain 'cannot parse private key': {err_msg}"
        );
    }

    #[rstest::rstest]
    fn test_to_private_key_certificate_instead_of_key(self_signed_cert: CertificateSet) {
        let result = Certs::to_private_key(&self_signed_cert.cert_pem);
        assert!(result.is_err());
        let err_msg = result.expect_err("Expected error").to_string();
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
        let err_msg = result.expect_err("Expected error").to_string();
        assert!(
            err_msg.contains("empty private key"),
            "Error message should contain 'empty private key': {err_msg}"
        );
    }

    // =========================================================================
    // CA Certificate Parsing Tests
    // =========================================================================

    #[rstest::rstest]
    fn test_to_ca_certs_valid(valid_full_chain: CertificateSet) {
        let ca_certs_pem: &[&[u8]] = &[&valid_full_chain.ca_cert_pem];
        let root_store =
            Certs::to_ca_certs(ca_certs_pem).expect("Should parse valid CA certificate");
        assert!(!root_store.is_empty());
    }

    #[test]
    fn test_to_ca_certs_from_test_file() {
        let ca_pem = std::fs::read(CA_CERT_PATH).expect("Failed to read ca_cert.pem");
        let ca_certs_pem: &[&[u8]] = &[&ca_pem];
        let root_store =
            Certs::to_ca_certs(ca_certs_pem).expect("Should parse test CA certificate");
        assert!(!root_store.is_empty());
    }

    #[rstest::rstest]
    fn test_to_ca_certs_multiple_cas(
        valid_full_chain: CertificateSet,
        cn_mismatch: CertificateSet,
    ) {
        let ca_certs_pem: &[&[u8]] = &[&valid_full_chain.ca_cert_pem, &cn_mismatch.ca_cert_pem];
        let root_store =
            Certs::to_ca_certs(ca_certs_pem).expect("Should parse multiple CA certificates");
        assert_eq!(root_store.len(), 2);
    }

    #[test]
    fn test_to_ca_certs_empty_list_returns_error() {
        let ca_certs_pem: &[&[u8]] = &[];
        let result = Certs::to_ca_certs(ca_certs_pem);
        assert!(result.is_err());
        let err_msg = result.expect_err("Expected error").to_string();
        assert!(
            err_msg.contains("empty CA certificate store"),
            "Error message should contain 'empty CA certificate store': {err_msg}"
        );
    }

    #[test]
    fn test_to_ca_certs_empty_pem_returns_error() {
        let ca_certs_pem: &[&[u8]] = &[b""];
        let result = Certs::to_ca_certs(ca_certs_pem);
        assert!(result.is_err());
        let err_msg = result.expect_err("Expected error").to_string();
        assert!(
            err_msg.contains("empty CA certificate store"),
            "Error message should contain 'empty CA certificate store': {err_msg}"
        );
    }

    #[test]
    fn test_to_ca_certs_invalid_pem() {
        let invalid_ca =
            b"-----BEGIN CERTIFICATE-----\nINVALID_BASE64_DATA!!!\n-----END CERTIFICATE-----\n";
        let ca_certs_pem: &[&[u8]] = &[invalid_ca];
        let result = Certs::to_ca_certs(ca_certs_pem);
        assert!(result.is_err());
        let err_msg = result.expect_err("Expected error").to_string();
        assert!(
            err_msg.contains("invalid PEM-encoded certificate"),
            "Error message should contain 'invalid PEM-encoded certificate': {err_msg}"
        );
    }

    #[test]
    fn test_to_ca_certs_non_pem_data_returns_error() {
        let garbage: &[u8] = b"this is not a certificate";
        let ca_certs_pem: &[&[u8]] = &[garbage];
        let result = Certs::to_ca_certs(ca_certs_pem);
        assert!(result.is_err());
        let err_msg = result.expect_err("Expected error").to_string();
        assert!(
            err_msg.contains("empty CA certificate store"),
            "Error message should contain 'empty CA certificate store': {err_msg}"
        );
    }

    // =========================================================================
    // Certs::try_new with Fixtures Tests
    // =========================================================================

    #[rstest::rstest]
    fn test_try_new_valid_full_chain(valid_full_chain: CertificateSet) {
        let ca_certs_pem: &[&[u8]] = &[&valid_full_chain.ca_cert_pem];
        let certs = Certs::try_new(
            &valid_full_chain.cert_pem,
            &valid_full_chain.key_pem,
            ca_certs_pem,
        )
        .expect("Should succeed with valid full chain");
        assert!(!certs.certs.is_empty());
        assert!(!certs.ca_certs.is_empty());
    }

    #[rstest::rstest]
    fn test_try_new_self_signed(self_signed_cert: CertificateSet) {
        let ca_certs_pem: &[&[u8]] = &[&self_signed_cert.ca_cert_pem];
        let certs = Certs::try_new(
            &self_signed_cert.cert_pem,
            &self_signed_cert.key_pem,
            ca_certs_pem,
        )
        .expect("Should succeed with self-signed certificate");
        assert_eq!(certs.certs.len(), 1);
    }

    #[rstest::rstest]
    fn test_try_new_incomplete_chain(incomplete_chain: CertificateSet) {
        let ca_certs_pem: &[&[u8]] = &[&incomplete_chain.ca_cert_pem];
        let certs = Certs::try_new(
            &incomplete_chain.cert_pem,
            &incomplete_chain.key_pem,
            ca_certs_pem,
        )
        .expect("Should succeed with incomplete chain (leaf only)");
        assert_eq!(certs.certs.len(), 1);
    }

    #[rstest::rstest]
    fn test_try_new_cn_mismatch(cn_mismatch: CertificateSet) {
        // CN mismatch between CA and leaf is valid for parsing
        // (validation happens at connection time)
        let ca_certs_pem: &[&[u8]] = &[&cn_mismatch.ca_cert_pem];
        let certs = Certs::try_new(&cn_mismatch.cert_pem, &cn_mismatch.key_pem, ca_certs_pem)
            .expect("Should succeed with CN mismatch (parsing only)");
        assert!(!certs.certs.is_empty());
    }

    #[rstest::rstest]
    fn test_try_new_expired_ca(expired_ca: CertificateSet) {
        // Expired CA can still be parsed; expiration is checked at connection time
        let ca_certs_pem: &[&[u8]] = &[&expired_ca.ca_cert_pem];
        let certs = Certs::try_new(&expired_ca.cert_pem, &expired_ca.key_pem, ca_certs_pem)
            .expect("Should succeed parsing expired CA (validation at connect time)");
        assert!(!certs.certs.is_empty());
    }

    #[rstest::rstest]
    fn test_try_new_expired_leaf(expired_leaf: CertificateSet) {
        // Expired leaf can still be parsed; expiration is checked at connection time
        let ca_certs_pem: &[&[u8]] = &[&expired_leaf.ca_cert_pem];
        let certs = Certs::try_new(&expired_leaf.cert_pem, &expired_leaf.key_pem, ca_certs_pem)
            .expect("Should succeed parsing expired leaf (validation at connect time)");
        assert!(!certs.certs.is_empty());
    }

    // =========================================================================
    // Certs::try_new Error Path Tests
    // =========================================================================

    #[rstest::rstest]
    fn test_try_new_invalid_cert(valid_full_chain: CertificateSet) {
        let invalid_cert =
            b"-----BEGIN CERTIFICATE-----\n!!NOT_VALID_BASE64!!\n-----END CERTIFICATE-----\n";
        let ca_certs_pem: &[&[u8]] = &[&valid_full_chain.ca_cert_pem];

        let result = Certs::try_new(invalid_cert, &valid_full_chain.key_pem, ca_certs_pem);
        assert!(result.is_err());
        let err_msg = result.expect_err("Expected error").to_string();
        assert!(
            err_msg.contains("cannot read certificate chain"),
            "Error message should contain 'cannot read certificate chain': {err_msg}"
        );
    }

    #[rstest::rstest]
    fn test_try_new_invalid_key(valid_full_chain: CertificateSet) {
        let invalid_key =
            b"-----BEGIN PRIVATE KEY-----\n!!NOT_VALID_BASE64!!\n-----END PRIVATE KEY-----\n";
        let ca_certs_pem: &[&[u8]] = &[&valid_full_chain.ca_cert_pem];

        let result = Certs::try_new(&valid_full_chain.cert_pem, invalid_key, ca_certs_pem);
        assert!(result.is_err());
        let err_msg = result.expect_err("Expected error").to_string();
        assert!(
            err_msg.contains("cannot read private key"),
            "Error message should contain 'cannot read private key': {err_msg}"
        );
    }

    #[rstest::rstest]
    fn test_try_new_invalid_ca(self_signed_cert: CertificateSet) {
        let invalid_ca =
            b"-----BEGIN CERTIFICATE-----\n!!NOT_VALID_BASE64!!\n-----END CERTIFICATE-----\n";
        let ca_certs_pem: &[&[u8]] = &[invalid_ca];

        let result = Certs::try_new(
            &self_signed_cert.cert_pem,
            &self_signed_cert.key_pem,
            ca_certs_pem,
        );
        assert!(result.is_err());
        let err_msg = result.expect_err("Expected error").to_string();
        assert!(
            err_msg.contains("failed to read CA certificates"),
            "Error message should contain 'failed to read CA certificates': {err_msg}"
        );
    }

    // =========================================================================
    // Quinn Endpoint Configuration Tests
    // =========================================================================

    #[tokio::test]
    async fn test_config_creates_endpoint() {
        let cert_pem = std::fs::read(CERT_PATH).expect("Failed to read cert.pem");
        let key_pem = std::fs::read(KEY_PATH).expect("Failed to read key.pem");
        let ca_pem = std::fs::read(CA_CERT_PATH).expect("Failed to read ca_cert.pem");
        let ca_certs_pem: &[&[u8]] = &[&ca_pem];

        let certs = Certs::try_new(&cert_pem, &key_pem, ca_certs_pem)
            .expect("Certs::try_new should succeed");
        let endpoint = config(&certs).expect("config should create endpoint successfully");

        assert!(
            endpoint.local_addr().is_ok(),
            "Endpoint should have a local address"
        );
    }

    #[rstest::rstest]
    #[tokio::test]
    async fn test_config_with_valid_full_chain(valid_full_chain: CertificateSet) {
        let ca_certs_pem: &[&[u8]] = &[&valid_full_chain.ca_cert_pem];

        let certs = Certs::try_new(
            &valid_full_chain.cert_pem,
            &valid_full_chain.key_pem,
            ca_certs_pem,
        )
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
    // TLS Configuration Tests
    // =========================================================================

    #[rstest::rstest]
    fn test_rustls_client_config_creation(self_signed_cert: CertificateSet) {
        let ca_certs_pem: &[&[u8]] = &[&self_signed_cert.ca_cert_pem];

        let certs = Certs::try_new(
            &self_signed_cert.cert_pem,
            &self_signed_cert.key_pem,
            ca_certs_pem,
        )
        .expect("Certs::try_new should succeed");

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(certs.ca_certs.clone())
            .with_client_auth_cert(certs.certs.clone(), certs.key.clone_key());

        assert!(
            tls_config.is_ok(),
            "TLS config should be created successfully"
        );
    }

    #[rstest::rstest]
    fn test_quic_client_config_creation(self_signed_cert: CertificateSet) {
        let ca_certs_pem: &[&[u8]] = &[&self_signed_cert.ca_cert_pem];

        let certs = Certs::try_new(
            &self_signed_cert.cert_pem,
            &self_signed_cert.key_pem,
            ca_certs_pem,
        )
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

    #[rstest::rstest]
    fn test_client_config_with_transport(self_signed_cert: CertificateSet) {
        let ca_certs_pem: &[&[u8]] = &[&self_signed_cert.ca_cert_pem];

        let certs = Certs::try_new(
            &self_signed_cert.cert_pem,
            &self_signed_cert.key_pem,
            ca_certs_pem,
        )
        .expect("Certs::try_new should succeed");

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(certs.ca_certs.clone())
            .with_client_auth_cert(certs.certs.clone(), certs.key.clone_key())
            .expect("TLS config should be created");

        let mut transport = TransportConfig::default();
        transport.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));

        let quic_config =
            QuicClientConfig::try_from(tls_config).expect("QUIC config should be created");
        let mut client_config = ClientConfig::new(Arc::new(quic_config));
        client_config.transport_config(Arc::new(transport));

        // Verify client config was created without panic
        drop(client_config);
    }

    // =========================================================================
    // Tempfile-based Tests (file I/O paths)
    // =========================================================================

    #[rstest::rstest]
    fn test_load_cert_from_tempfile(self_signed_cert: CertificateSet) {
        let mut cert_file = NamedTempFile::new().expect("Failed to create temp file");
        cert_file
            .write_all(&self_signed_cert.cert_pem)
            .expect("Failed to write cert");
        cert_file.flush().expect("Failed to flush");

        let loaded = std::fs::read(cert_file.path()).expect("Failed to read temp file");
        let certs = Certs::to_cert_chain(&loaded).expect("Should parse certificate from temp file");
        assert_eq!(certs.len(), 1);
    }

    #[rstest::rstest]
    fn test_load_key_from_tempfile(self_signed_cert: CertificateSet) {
        let mut key_file = NamedTempFile::new().expect("Failed to create temp file");
        key_file
            .write_all(&self_signed_cert.key_pem)
            .expect("Failed to write key");
        key_file.flush().expect("Failed to flush");

        let loaded = std::fs::read(key_file.path()).expect("Failed to read temp file");
        let key = Certs::to_private_key(&loaded).expect("Should parse key from temp file");
        assert!(matches!(key, PrivateKeyDer::Pkcs8(_)));
    }

    #[rstest::rstest]
    fn test_full_cert_loading_from_tempfiles(valid_full_chain: CertificateSet) {
        let mut cert_file = NamedTempFile::new().expect("Failed to create temp file");
        cert_file
            .write_all(&valid_full_chain.cert_pem)
            .expect("Failed to write cert");
        cert_file.flush().expect("Failed to flush");

        let mut key_file = NamedTempFile::new().expect("Failed to create temp file");
        key_file
            .write_all(&valid_full_chain.key_pem)
            .expect("Failed to write key");
        key_file.flush().expect("Failed to flush");

        let mut ca_file = NamedTempFile::new().expect("Failed to create temp file");
        ca_file
            .write_all(&valid_full_chain.ca_cert_pem)
            .expect("Failed to write CA");
        ca_file.flush().expect("Failed to flush");

        let cert_data = std::fs::read(cert_file.path()).expect("Failed to read cert");
        let key_data = std::fs::read(key_file.path()).expect("Failed to read key");
        let ca_data = std::fs::read(ca_file.path()).expect("Failed to read CA");

        let ca_certs_pem: &[&[u8]] = &[&ca_data];
        let certs = Certs::try_new(&cert_data, &key_data, ca_certs_pem)
            .expect("Should load certs from temp files");

        assert!(!certs.certs.is_empty());
        assert!(!certs.ca_certs.is_empty());
    }
}
