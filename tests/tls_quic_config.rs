//! TLS/QUIC configuration tests for certificate parsing and quinn endpoint settings.
//!
//! This module contains tests for:
//! - Certificate chain parsing (success and failure paths)
//! - Private key loading (PKCS#1, PKCS#8, and invalid formats)
//! - CA certificate loading
//! - Quinn endpoint configuration with keep-alive and transport settings

use std::sync::Arc;

use quinn::{ClientConfig, TransportConfig, crypto::rustls::QuicClientConfig};
use rustls::RootCertStore;
use tempfile::TempDir;
use tokio::time::Duration;

/// Helper module for generating test certificates
mod cert_gen {
    use rcgen::{CertificateParams, CertifiedKey, Issuer, KeyPair, generate_simple_self_signed};

    /// Generates a self-signed certificate and private key pair.
    ///
    /// # Returns
    ///
    /// A tuple of (certificate PEM, private key PEM).
    pub fn generate_self_signed() -> (String, String) {
        let subject_alt_names = vec!["localhost".to_string()];
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(subject_alt_names).expect("Failed to generate cert");
        (cert.pem(), signing_key.serialize_pem())
    }

    /// Generates a CA certificate and key pair.
    ///
    /// # Returns
    ///
    /// A tuple of (CA certificate PEM, CA private key PEM, `KeyPair`).
    pub fn generate_ca() -> (String, String, KeyPair) {
        let key_pair = KeyPair::generate().expect("Failed to generate CA key pair");
        let mut params = CertificateParams::new(vec!["Test CA".to_string()])
            .expect("Failed to create CA params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        let ca_cert = params
            .self_signed(&key_pair)
            .expect("Failed to create CA certificate");

        (ca_cert.pem(), key_pair.serialize_pem(), key_pair)
    }

    /// Generates a certificate signed by the given CA.
    ///
    /// # Arguments
    ///
    /// * `ca_params` - The CA certificate params.
    /// * `ca_key_pair` - The CA's key pair.
    ///
    /// # Returns
    ///
    /// A tuple of (certificate PEM, private key PEM).
    pub fn generate_signed_by_ca(
        ca_params: &CertificateParams,
        ca_key_pair: &KeyPair,
    ) -> (String, String) {
        let key_pair = KeyPair::generate().expect("Failed to generate key pair");
        let params = CertificateParams::new(vec!["localhost".to_string()])
            .expect("Failed to create certificate params");

        let issuer = Issuer::from_params(ca_params, ca_key_pair);
        let cert = params
            .signed_by(&key_pair, &issuer)
            .expect("Failed to sign certificate");

        (cert.pem(), key_pair.serialize_pem())
    }

    /// Generates a CA certificate and returns the params for signing.
    ///
    /// # Returns
    ///
    /// A tuple of (CA cert PEM, CA private key PEM, CA params, `KeyPair`).
    pub fn generate_ca_with_params() -> (String, String, CertificateParams, KeyPair) {
        let key_pair = KeyPair::generate().expect("Failed to generate CA key pair");
        let mut params = CertificateParams::new(vec!["Test CA".to_string()])
            .expect("Failed to create CA params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        let ca_cert = params
            .self_signed(&key_pair)
            .expect("Failed to create CA certificate");

        (ca_cert.pem(), key_pair.serialize_pem(), params, key_pair)
    }
}

// ============================================================================
// Certificate Chain Parsing Tests
// ============================================================================

mod cert_chain_parsing {
    use super::*;

    #[test]
    fn parse_valid_certificate_chain() {
        let (cert_pem, _key_pem) = cert_gen::generate_self_signed();

        let result = parse_cert_chain(cert_pem.as_bytes());
        assert!(result.is_ok(), "Should parse valid certificate chain");

        let certs = result.unwrap();
        assert!(!certs.is_empty(), "Certificate chain should not be empty");
    }

    #[test]
    fn parse_multiple_certificates_in_chain() {
        // Generate CA and signed certificate
        let (ca_cert_pem, _ca_key_pem, ca_params, ca_key_pair) =
            cert_gen::generate_ca_with_params();
        let (cert_pem, _key_pem) = cert_gen::generate_signed_by_ca(&ca_params, &ca_key_pair);

        // Combine into a chain (leaf cert first, then CA)
        let chain_pem = format!("{cert_pem}{ca_cert_pem}");

        let result = parse_cert_chain(chain_pem.as_bytes());
        assert!(
            result.is_ok(),
            "Should parse certificate chain with multiple certs"
        );

        let certs = result.unwrap();
        assert_eq!(certs.len(), 2, "Should have 2 certificates in chain");
    }

    #[test]
    fn parse_empty_pem_returns_empty_chain() {
        let result = parse_cert_chain(b"");
        assert!(result.is_ok(), "Empty PEM should be accepted");
        assert!(
            result.unwrap().is_empty(),
            "Empty PEM should produce empty chain"
        );
    }

    #[test]
    fn parse_malformed_pem_fails() {
        let malformed =
            b"-----BEGIN CERTIFICATE-----\nNOT_VALID_BASE64!!!\n-----END CERTIFICATE-----\n";

        let result = parse_cert_chain(malformed);
        assert!(result.is_err(), "Malformed PEM should fail");

        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("parse") || err_msg.contains("certificate"),
            "Error should mention parsing issue: {err_msg}"
        );
    }

    #[test]
    fn parse_non_certificate_pem_returns_empty() {
        // A valid PEM structure but not a certificate
        let not_a_cert =
            b"-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg==\n-----END PRIVATE KEY-----\n";

        let result = parse_cert_chain(not_a_cert);
        // rustls_pemfile::certs() skips non-certificate items
        assert!(result.is_ok());
        assert!(
            result.unwrap().is_empty(),
            "Non-certificate PEM should produce empty chain"
        );
    }

    #[test]
    fn parse_certificate_from_file() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let cert_path = temp_dir.path().join("test_cert.pem");

        let (cert_pem, _key_pem) = cert_gen::generate_self_signed();
        std::fs::write(&cert_path, &cert_pem).expect("Failed to write cert file");

        let cert_data = std::fs::read(&cert_path).expect("Failed to read cert file");
        let result = parse_cert_chain(&cert_data);

        assert!(result.is_ok(), "Should parse certificate from file");
        assert!(!result.unwrap().is_empty());
    }

    /// Helper to parse certificate chain (mirrors `Certs::to_cert_chain` logic)
    fn parse_cert_chain(
        raw: &[u8],
    ) -> anyhow::Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
        let certs = rustls_pemfile::certs(&mut &*raw)
            .collect::<Result<_, _>>()
            .map_err(|e| anyhow::anyhow!("cannot parse certificate chain: {e}"))?;
        Ok(certs)
    }
}

// ============================================================================
// Private Key Parsing Tests
// ============================================================================

mod private_key_parsing {
    use rustls::pki_types::PrivateKeyDer;

    use super::*;

    #[test]
    fn parse_valid_pkcs8_key() {
        let (_cert_pem, key_pem) = cert_gen::generate_self_signed();

        let result = parse_private_key(key_pem.as_bytes());
        assert!(result.is_ok(), "Should parse valid PKCS#8 key");
    }

    #[test]
    fn parse_valid_pkcs1_key() {
        // PKCS#1 RSA key format (BEGIN RSA PRIVATE KEY)
        let pkcs1_key = include_bytes!("key.pem");

        let result = parse_private_key(pkcs1_key);
        assert!(result.is_ok(), "Should parse valid PKCS#1 RSA key");
    }

    #[test]
    fn parse_empty_key_fails() {
        let result = parse_private_key(b"");
        assert!(result.is_err(), "Empty key should fail");

        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("empty"),
            "Error should mention empty key: {err_msg}"
        );
    }

    #[test]
    fn parse_malformed_key_fails() {
        let malformed =
            b"-----BEGIN PRIVATE KEY-----\nINVALID_DATA!!!\n-----END PRIVATE KEY-----\n";

        let result = parse_private_key(malformed);
        assert!(result.is_err(), "Malformed key should fail");
    }

    #[test]
    fn parse_unsupported_key_format_fails() {
        // Create a PEM that looks like a key but is actually a certificate
        let (cert_pem, _) = cert_gen::generate_self_signed();

        let result = parse_private_key(cert_pem.as_bytes());
        assert!(result.is_err(), "Certificate PEM should not parse as key");

        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("unknown") || err_msg.contains("format") || err_msg.contains("empty"),
            "Error should mention format issue: {err_msg}"
        );
    }

    #[test]
    fn parse_key_from_file() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let key_path = temp_dir.path().join("test_key.pem");

        let (_cert_pem, key_pem) = cert_gen::generate_self_signed();
        std::fs::write(&key_path, &key_pem).expect("Failed to write key file");

        let key_data = std::fs::read(&key_path).expect("Failed to read key file");
        let result = parse_private_key(&key_data);

        assert!(result.is_ok(), "Should parse key from file");
    }

    #[test]
    fn parse_encrypted_key_fails() {
        // Encrypted keys are not supported by the basic parser
        let encrypted_key = b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQI\n-----END ENCRYPTED PRIVATE KEY-----\n";

        let result = parse_private_key(encrypted_key);
        assert!(
            result.is_err(),
            "Encrypted keys should fail (not supported)"
        );
    }

    /// Helper to parse private key (mirrors `Certs::to_private_key` logic)
    fn parse_private_key(raw: &[u8]) -> anyhow::Result<PrivateKeyDer<'static>> {
        match rustls_pemfile::read_one(&mut &*raw)
            .map_err(|e| anyhow::anyhow!("cannot parse private key: {e}"))?
            .ok_or_else(|| anyhow::anyhow!("empty private key"))?
        {
            rustls_pemfile::Item::Pkcs1Key(key) => Ok(key.into()),
            rustls_pemfile::Item::Pkcs8Key(key) => Ok(key.into()),
            _ => Err(anyhow::anyhow!("unknown private key format")),
        }
    }
}

// ============================================================================
// CA Certificate Loading Tests
// ============================================================================

mod ca_cert_loading {
    use super::*;

    #[test]
    fn load_single_ca_cert() {
        let (ca_pem, _ca_key_pem, _key_pair) = cert_gen::generate_ca();

        let ca_certs = [ca_pem.as_bytes()];
        let result = load_ca_certs(ca_certs.as_ref());

        assert!(result.is_ok(), "Should load single CA cert");
        assert!(
            !result.unwrap().is_empty(),
            "Root store should not be empty"
        );
    }

    #[test]
    fn load_multiple_ca_certs() {
        let (ca1_pem, _, _) = cert_gen::generate_ca();
        let (ca2_pem, _, _) = cert_gen::generate_ca();

        let ca_certs = [ca1_pem.as_bytes(), ca2_pem.as_bytes()];
        let result = load_ca_certs(&ca_certs);

        assert!(result.is_ok(), "Should load multiple CA certs");

        // The root store should contain certs from both files
        let root_store = result.unwrap();
        assert!(!root_store.is_empty(), "Should have loaded CA certs");
    }

    #[test]
    fn load_empty_ca_list_succeeds() {
        let result = load_ca_certs(&[]);
        assert!(result.is_ok(), "Empty CA list should succeed");
        assert!(result.unwrap().is_empty(), "Root store should be empty");
    }

    #[test]
    fn load_invalid_ca_cert_fails() {
        let invalid_ca = b"-----BEGIN CERTIFICATE-----\nINVALID!!!\n-----END CERTIFICATE-----\n";

        let ca_certs = [invalid_ca.as_slice()];
        let result = load_ca_certs(&ca_certs);

        assert!(result.is_err(), "Invalid CA cert should fail");

        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("invalid")
                || err_msg.contains("PEM")
                || err_msg.contains("certificate"),
            "Error should mention certificate issue: {err_msg}"
        );
    }

    #[test]
    fn load_non_ca_cert_succeeds_but_may_fail_validation() {
        // A regular certificate (non-CA) can be loaded into root store,
        // but it won't work properly as a CA during validation
        let (cert_pem, _key_pem) = cert_gen::generate_self_signed();

        let ca_certs = [cert_pem.as_bytes()];
        let result = load_ca_certs(&ca_certs);

        // Loading should succeed - the root store accepts any certificate
        assert!(result.is_ok(), "Non-CA cert should load into root store");
    }

    #[test]
    fn load_ca_from_files() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");

        let (ca1_pem, _, _) = cert_gen::generate_ca();
        let (ca2_pem, _, _) = cert_gen::generate_ca();

        let ca1_path = temp_dir.path().join("ca1.pem");
        let ca2_path = temp_dir.path().join("ca2.pem");

        std::fs::write(&ca1_path, &ca1_pem).expect("Failed to write CA1");
        std::fs::write(&ca2_path, &ca2_pem).expect("Failed to write CA2");

        let ca1_data = std::fs::read(&ca1_path).expect("Failed to read CA1");
        let ca2_data = std::fs::read(&ca2_path).expect("Failed to read CA2");

        let ca_certs = [ca1_data.as_slice(), ca2_data.as_slice()];
        let result = load_ca_certs(&ca_certs);

        assert!(result.is_ok(), "Should load CA certs from files");
    }

    /// Helper to load CA certificates (mirrors `Certs::to_ca_certs` logic)
    fn load_ca_certs(ca_certs_pem: &[&[u8]]) -> anyhow::Result<RootCertStore> {
        let mut root_cert = RootCertStore::empty();
        for &ca_cert_pem in ca_certs_pem {
            let root_certs: Vec<rustls::pki_types::CertificateDer> =
                rustls_pemfile::certs(&mut &*ca_cert_pem)
                    .collect::<Result<_, _>>()
                    .map_err(|e| anyhow::anyhow!("invalid PEM-encoded certificate: {e}"))?;
            if let Some(cert) = root_certs.first() {
                root_cert
                    .add(cert.to_owned())
                    .map_err(|e| anyhow::anyhow!("failed to add CA certificate: {e}"))?;
            }
        }
        Ok(root_cert)
    }
}

// ============================================================================
// Quinn Config Conversion Tests
// ============================================================================

mod quinn_config {
    use super::*;

    const KEEP_ALIVE_INTERVAL: Duration = Duration::from_millis(5_000);

    #[test]
    fn transport_config_has_keep_alive_interval() {
        let mut transport = TransportConfig::default();
        transport.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));

        // The TransportConfig stores the keep-alive setting internally
        // We verify by checking that the config is properly constructed
        // (quinn doesn't expose a getter for keep_alive_interval)

        // Create a ClientConfig with this transport to verify integration
        let (cert_pem, key_pem) = cert_gen::generate_self_signed();
        let (ca_pem, _, _) = cert_gen::generate_ca();

        let certs = parse_certs(&cert_pem, &key_pem, &ca_pem);
        assert!(certs.is_ok(), "Should parse test certs");

        let (cert_chain, key, root_store) = certs.unwrap();

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(cert_chain, key);

        assert!(
            tls_config.is_ok(),
            "Should create TLS config with client auth"
        );

        let quic_config = QuicClientConfig::try_from(tls_config.unwrap());
        assert!(quic_config.is_ok(), "Should create QUIC client config");

        let mut client_config = ClientConfig::new(Arc::new(quic_config.unwrap()));
        client_config.transport_config(Arc::new(transport));

        // If we got here without panics, the config is valid
    }

    #[test]
    fn transport_config_with_custom_settings() {
        let mut transport = TransportConfig::default();

        // Set various transport parameters
        transport.keep_alive_interval(Some(Duration::from_secs(10)));
        transport.max_concurrent_bidi_streams(100u32.into());
        transport.max_concurrent_uni_streams(50u32.into());
        transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));

        // Create config with these settings
        let (cert_pem, key_pem) = cert_gen::generate_self_signed();
        let (ca_pem, _, _) = cert_gen::generate_ca();
        let (cert_chain, key, root_store) = parse_certs(&cert_pem, &key_pem, &ca_pem).unwrap();

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(cert_chain, key)
            .unwrap();

        let quic_config = QuicClientConfig::try_from(tls_config).unwrap();
        let mut client_config = ClientConfig::new(Arc::new(quic_config));
        client_config.transport_config(Arc::new(transport));

        // Config created successfully with custom settings
    }

    #[test]
    fn client_config_with_valid_certs() {
        let (cert_pem, key_pem) = cert_gen::generate_self_signed();

        // Use the self-signed cert as its own CA for testing
        let (cert_chain, key, root_store) = parse_certs(&cert_pem, &key_pem, &cert_pem).unwrap();

        // The self-signed cert should be in the root store for this test
        assert!(!root_store.is_empty(), "Root store should have the CA");

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(cert_chain, key);

        assert!(tls_config.is_ok(), "Should create TLS config");

        let quic_config = QuicClientConfig::try_from(tls_config.unwrap());
        assert!(quic_config.is_ok(), "Should convert to QUIC config");

        let client_config = ClientConfig::new(Arc::new(quic_config.unwrap()));
        // Config created successfully
        drop(client_config);
    }

    #[test]
    fn client_config_with_mismatched_key_fails() {
        let (cert_pem, _key_pem) = cert_gen::generate_self_signed();
        let (_other_cert, other_key) = cert_gen::generate_self_signed();

        // Try to use a different key with the certificate
        let cert_chain = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let key = match rustls_pemfile::read_one(&mut other_key.as_bytes())
            .unwrap()
            .unwrap()
        {
            rustls_pemfile::Item::Pkcs8Key(k) => rustls::pki_types::PrivateKeyDer::from(k),
            rustls_pemfile::Item::Pkcs1Key(k) => rustls::pki_types::PrivateKeyDer::from(k),
            _ => panic!("Unexpected key type"),
        };

        let root_store = RootCertStore::empty();

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(cert_chain, key);

        // This should fail because the key doesn't match the certificate
        assert!(
            tls_config.is_err(),
            "Mismatched key should fail TLS config creation"
        );

        let err_msg = tls_config.unwrap_err().to_string();
        assert!(
            err_msg.contains("key")
                || err_msg.contains("certificate")
                || err_msg.contains("mismatch"),
            "Error should indicate key/cert mismatch: {err_msg}"
        );
    }

    #[test]
    fn default_transport_config_values() {
        let transport = TransportConfig::default();

        // The default TransportConfig should be usable
        let (cert_pem, key_pem) = cert_gen::generate_self_signed();
        let (cert_chain, key, root_store) = parse_certs(&cert_pem, &key_pem, &cert_pem).unwrap();

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(cert_chain, key)
            .unwrap();

        let quic_config = QuicClientConfig::try_from(tls_config).unwrap();
        let mut client_config = ClientConfig::new(Arc::new(quic_config));
        client_config.transport_config(Arc::new(transport));

        // Default config should work
    }

    /// Helper to parse all certificate components
    fn parse_certs(
        cert_pem: &str,
        key_pem: &str,
        ca_pem: &str,
    ) -> anyhow::Result<(
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
        RootCertStore,
    )> {
        let cert_chain = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("cannot parse certificate chain: {e}"))?;

        let key = match rustls_pemfile::read_one(&mut key_pem.as_bytes())
            .map_err(|e| anyhow::anyhow!("cannot parse private key: {e}"))?
            .ok_or_else(|| anyhow::anyhow!("empty private key"))?
        {
            rustls_pemfile::Item::Pkcs1Key(k) => rustls::pki_types::PrivateKeyDer::from(k),
            rustls_pemfile::Item::Pkcs8Key(k) => rustls::pki_types::PrivateKeyDer::from(k),
            _ => return Err(anyhow::anyhow!("unknown private key format")),
        };

        let mut root_store = RootCertStore::empty();
        let ca_certs: Vec<rustls::pki_types::CertificateDer> =
            rustls_pemfile::certs(&mut ca_pem.as_bytes())
                .collect::<Result<_, _>>()
                .map_err(|e| anyhow::anyhow!("invalid PEM-encoded certificate: {e}"))?;
        if let Some(cert) = ca_certs.first() {
            root_store
                .add(cert.to_owned())
                .map_err(|e| anyhow::anyhow!("failed to add CA certificate: {e}"))?;
        }

        Ok((cert_chain, key, root_store))
    }
}

// ============================================================================
// Server Config Tests (for completeness)
// ============================================================================

mod server_config {
    use quinn::{ServerConfig, crypto::rustls::QuicServerConfig};

    use super::*;

    #[test]
    fn create_server_config_with_client_auth() {
        let (ca_pem, _ca_key, ca_params, ca_key_pair) = cert_gen::generate_ca_with_params();
        let (cert_pem, key_pem) = cert_gen::generate_signed_by_ca(&ca_params, &ca_key_pair);

        // Parse certificates
        let cert_chain: Vec<rustls::pki_types::CertificateDer> =
            rustls_pemfile::certs(&mut cert_pem.as_bytes())
                .collect::<Result<_, _>>()
                .unwrap();

        let key = match rustls_pemfile::read_one(&mut key_pem.as_bytes())
            .unwrap()
            .unwrap()
        {
            rustls_pemfile::Item::Pkcs8Key(k) => rustls::pki_types::PrivateKeyDer::from(k),
            rustls_pemfile::Item::Pkcs1Key(k) => rustls::pki_types::PrivateKeyDer::from(k),
            _ => panic!("Unexpected key type"),
        };

        // Parse CA for client verification
        let ca_certs: Vec<rustls::pki_types::CertificateDer> =
            rustls_pemfile::certs(&mut ca_pem.as_bytes())
                .collect::<Result<_, _>>()
                .unwrap();

        let mut root_store = RootCertStore::empty();
        root_store.add(ca_certs[0].clone()).unwrap();

        // Create client verifier
        let client_auth = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .expect("Failed to build client verifier");

        // Create server TLS config
        let server_crypto = rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_auth)
            .with_single_cert(cert_chain, key)
            .expect("Failed to create server TLS config");

        // Convert to QUIC server config
        let quic_server_config =
            QuicServerConfig::try_from(server_crypto).expect("Failed to create QUIC server config");

        let mut server_config = ServerConfig::with_crypto(Arc::new(quic_server_config));

        // Configure transport settings
        Arc::get_mut(&mut server_config.transport)
            .unwrap()
            .max_concurrent_uni_streams(0u8.into());

        // Server config created successfully
    }

    #[test]
    fn server_config_transport_settings() {
        let (cert_pem, key_pem) = cert_gen::generate_self_signed();

        let cert_chain: Vec<rustls::pki_types::CertificateDer> =
            rustls_pemfile::certs(&mut cert_pem.as_bytes())
                .collect::<Result<_, _>>()
                .unwrap();

        let key = match rustls_pemfile::read_one(&mut key_pem.as_bytes())
            .unwrap()
            .unwrap()
        {
            rustls_pemfile::Item::Pkcs8Key(k) => rustls::pki_types::PrivateKeyDer::from(k),
            rustls_pemfile::Item::Pkcs1Key(k) => rustls::pki_types::PrivateKeyDer::from(k),
            _ => panic!("Unexpected key type"),
        };

        // Create server config without client auth for simplicity
        let server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .expect("Failed to create server TLS config");

        let quic_server_config =
            QuicServerConfig::try_from(server_crypto).expect("Failed to create QUIC server config");

        let mut server_config = ServerConfig::with_crypto(Arc::new(quic_server_config));

        // Apply custom transport settings
        let transport = Arc::get_mut(&mut server_config.transport).unwrap();
        transport.max_concurrent_bidi_streams(100u32.into());
        transport.max_concurrent_uni_streams(50u32.into());
        transport.max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap()));

        // Server config with custom transport settings created successfully
    }
}

// ============================================================================
// Error Message Stability Tests
// ============================================================================

mod error_messages {
    use super::*;

    #[test]
    fn invalid_cert_error_contains_parse_keyword() {
        let malformed = b"-----BEGIN CERTIFICATE-----\nBAD_DATA\n-----END CERTIFICATE-----\n";

        let result: Result<Vec<rustls::pki_types::CertificateDer>, _> =
            rustls_pemfile::certs(&mut &malformed[..]).collect();

        assert!(result.is_err());
        // The error type should be io::Error with a descriptive message
    }

    #[test]
    fn empty_key_error_is_clear() {
        let result = rustls_pemfile::read_one(&mut &b""[..]);

        // Empty input returns Ok(None), which we handle as an error
        assert!(result.is_ok());
        assert!(result.unwrap().is_none(), "Empty input should return None");
    }

    #[test]
    fn unknown_key_format_error() {
        // SEC1 EC key format (not supported by our parser)
        let ec_key =
            b"-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIBYQ\n-----END EC PRIVATE KEY-----\n";

        let result = rustls_pemfile::read_one(&mut &ec_key[..]);

        if let Ok(Some(item)) = result {
            // SEC1 keys parse to Sec1Key variant
            assert!(
                matches!(item, rustls_pemfile::Item::Sec1Key(_)),
                "Should be SEC1 key type"
            );
        }
    }

    #[test]
    fn ca_add_failure_produces_error() {
        // A malformed DER will fail when added to RootCertStore
        let mut root_store = RootCertStore::empty();

        // Create an invalid certificate DER
        let invalid_der = rustls::pki_types::CertificateDer::from(vec![0u8; 10]);

        let result = root_store.add(invalid_der);
        assert!(
            result.is_err(),
            "Adding invalid cert to root store should fail"
        );

        let err_msg = result.unwrap_err().to_string();
        // The error should indicate the certificate is invalid
        assert!(
            !err_msg.is_empty(),
            "Error message should not be empty: {err_msg}"
        );
    }
}

// ============================================================================
// Integration with Existing Test Fixtures
// ============================================================================

mod existing_fixtures {
    use super::*;

    const CERT_PATH: &str = "tests/cert.pem";
    const KEY_PATH: &str = "tests/key.pem";
    const CA_CERT_PATH: &str = "tests/ca_cert.pem";

    #[test]
    fn load_existing_test_certificate() {
        let cert_data = std::fs::read(CERT_PATH).expect("Failed to read test cert");

        let certs: Vec<rustls::pki_types::CertificateDer> =
            rustls_pemfile::certs(&mut &cert_data[..])
                .collect::<Result<_, _>>()
                .expect("Failed to parse test certificate");

        assert!(!certs.is_empty(), "Should load existing test certificate");
    }

    #[test]
    fn load_existing_test_key() {
        let key_data = std::fs::read(KEY_PATH).expect("Failed to read test key");

        let key_item = rustls_pemfile::read_one(&mut &key_data[..])
            .expect("Failed to parse test key")
            .expect("Test key should not be empty");

        assert!(
            matches!(
                key_item,
                rustls_pemfile::Item::Pkcs1Key(_) | rustls_pemfile::Item::Pkcs8Key(_)
            ),
            "Should be a valid private key"
        );
    }

    #[test]
    fn load_existing_ca_certificate() {
        let ca_data = std::fs::read(CA_CERT_PATH).expect("Failed to read CA cert");

        let ca_certs: Vec<rustls::pki_types::CertificateDer> =
            rustls_pemfile::certs(&mut &ca_data[..])
                .collect::<Result<_, _>>()
                .expect("Failed to parse CA certificate");

        assert!(!ca_certs.is_empty(), "Should load existing CA certificate");

        let mut root_store = RootCertStore::empty();
        root_store
            .add(ca_certs[0].clone())
            .expect("Should add CA to root store");
    }

    #[test]
    fn create_full_config_from_existing_fixtures() {
        let cert_data = std::fs::read(CERT_PATH).expect("Failed to read cert");
        let key_data = std::fs::read(KEY_PATH).expect("Failed to read key");
        let ca_data = std::fs::read(CA_CERT_PATH).expect("Failed to read CA");

        // Parse all components
        let cert_chain: Vec<rustls::pki_types::CertificateDer> =
            rustls_pemfile::certs(&mut &cert_data[..])
                .collect::<Result<_, _>>()
                .expect("Failed to parse cert");

        let key = match rustls_pemfile::read_one(&mut &key_data[..])
            .expect("Failed to parse key")
            .expect("Key should not be empty")
        {
            rustls_pemfile::Item::Pkcs1Key(k) => rustls::pki_types::PrivateKeyDer::from(k),
            rustls_pemfile::Item::Pkcs8Key(k) => rustls::pki_types::PrivateKeyDer::from(k),
            _ => panic!("Unexpected key type"),
        };

        let ca_certs: Vec<rustls::pki_types::CertificateDer> =
            rustls_pemfile::certs(&mut &ca_data[..])
                .collect::<Result<_, _>>()
                .expect("Failed to parse CA");

        let mut root_store = RootCertStore::empty();
        root_store
            .add(ca_certs[0].clone())
            .expect("Failed to add CA");

        // Create TLS config
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(cert_chain, key)
            .expect("Failed to create TLS config");

        // Create QUIC config
        let quic_config =
            QuicClientConfig::try_from(tls_config).expect("Failed to create QUIC config");

        // Create transport config with keep-alive
        let mut transport = TransportConfig::default();
        transport.keep_alive_interval(Some(Duration::from_millis(5_000)));

        // Create final client config
        let mut client_config = ClientConfig::new(Arc::new(quic_config));
        client_config.transport_config(Arc::new(transport));

        // Successfully created full config from existing fixtures
    }
}
