use std::sync::Arc;

use anyhow::{Context, Result, anyhow, ensure};
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
            .collect::<Result<Vec<_>, _>>()
            .context("cannot parse certificate chain")?;
        ensure!(!certs.is_empty(), "empty certificate chain");
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
    use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

    use anyhow::{Context, Result};
    use giganto_client::connection::{client_handshake, server_handshake};
    use quinn::{Endpoint, ServerConfig, crypto::rustls::QuicServerConfig};
    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
        SanType, string::Ia5String,
    };
    use rstest::*;
    use rustls::server::WebPkiClientVerifier;
    use tokio::sync::oneshot;
    use tokio::task::JoinHandle;

    use super::*;
    use crate::subscribe::REQUIRED_GIGANTO_VERSION;

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    /// Clones a `KeyPair`.
    /// The cloning is intentionally blocked by rcgen, so we implement it for test purpose.
    fn clone_key_pair(key_pair: &KeyPair) -> KeyPair {
        KeyPair::from_pem(&key_pair.serialize_pem()).expect("Assumed to succeed to parse key pair")
    }

    /// A bundle of PEM-encoded TLS certificates and private keys for testing purposes.
    #[derive(Debug)]
    struct TlsBundle {
        fullchain_cert_pem: Vec<u8>,
        key_pem: Vec<u8>,
        ca_cert_pems: Vec<Vec<u8>>,
    }

    impl TlsBundle {
        fn fullchain_cert(&self) -> &[u8] {
            self.fullchain_cert_pem.as_slice()
        }

        fn key(&self) -> &[u8] {
            self.key_pem.as_slice()
        }

        /// Returns the CA certificates as a list of slices.
        ///
        /// Since the underlying storage is `Vec<Vec<u8>>`, the memory layout is not
        /// compatible with `&[&[u8]]` directly. This method constructs a temporary
        /// `Vec<&[u8]>` to bridge that gap.
        ///
        /// **How to use**: Simply borrow it using `&bundle.ca_certs()` when passing to a function
        /// that expects `&[&[u8]]`.
        fn ca_certs(&self) -> Vec<&[u8]> {
            self.ca_cert_pems
                .iter()
                .map(std::vec::Vec::as_slice)
                .collect()
        }
    }

    /// Setup parameters used for generating the Server's endpoint and certificates.
    #[derive(Debug)]
    struct ServerCertsSetup {
        /// The Root CA used to verify client certificates (mTLS).
        /// This creates the trust anchor for the server.
        client_trust_root: Certificate,

        /// The CA certificate used to sign the server's leaf certificate.
        server_issuer_cert: Certificate,

        /// The Private Key of the CA used to sign the server's leaf certificate.
        server_issuer_key: KeyPair,
    }

    fn generate_params(is_ca: bool, cn: &str, sans: &[&str], days_valid: i64) -> CertificateParams {
        let mut params = CertificateParams::default();
        if is_ca {
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        } else {
            params.is_ca = IsCa::NoCa;
            params.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ];
        }
        params
            .distinguished_name
            .push(DnType::CommonName, cn.to_string());
        params.subject_alt_names = sans
            .iter()
            .map(|san| {
                if let Ok(ip) = san.parse::<IpAddr>() {
                    SanType::IpAddress(ip)
                } else {
                    let dns = Ia5String::try_from(*san)
                        .expect("DNS name must be valid ASCII (Ia5String)");
                    SanType::DnsName(dns)
                }
            })
            .collect();

        if days_valid < 0 {
            let past_end = time::OffsetDateTime::now_utc() - time::Duration::days(1);
            let past_start = past_end - time::Duration::days(-days_valid);
            params.not_before = past_start;
            params.not_after = past_end;
        } else {
            let now = time::OffsetDateTime::now_utc();
            params.not_before = now;
            params.not_after = now + time::Duration::days(days_valid);
        }

        params
    }

    /// Generates key pair and a self-signed CA certificate.
    ///
    /// # Arguments
    /// * `cn` - Common Name
    /// * `sans` - List of Subject Alternative Names (supports both DNS names and IP addresses)
    /// * `days_valid` - Validity period in days. If negative, generates an already expired certificate.
    fn generate_key_pair_and_self_signed_cert(
        cn: &str,
        sans: &[&str],
        days_valid: i64,
    ) -> (Certificate, KeyPair) {
        let key_pair = KeyPair::generate().expect("Failed to generate CA key pair");
        let params = generate_params(true, cn, sans, days_valid);

        let cert = params
            .self_signed(&key_pair)
            .expect("Assumed to succeed to generate self-signed CA certificate");

        (cert, key_pair)
    }

    /// Generates a leaf key pair and a certificate signed by the given issuer certificate and key pair
    fn generate_leaf_key_pair_and_signed_cert_by_issuer(
        cn: &str,
        sans: &[&str],
        days_valid: i64,
        issuer_cert: &Certificate,
        issuer_key: &KeyPair,
    ) -> (Certificate, KeyPair) {
        let key_pair = KeyPair::generate().expect("Failed to generate leaf key pair");
        let params = generate_params(false, cn, sans, days_valid);

        let issuer = rcgen::Issuer::from_ca_cert_pem(&issuer_cert.pem(), issuer_key)
            .expect("Assumed to succeed to create certificate issuer");
        let cert = params
            .signed_by(&key_pair, &issuer)
            .expect("Assumed to succeed to sign leaf certificate");

        (cert, key_pair)
    }

    /// Generates a intermediate key pair and a certificate signed by the given isser certificate and key pair.
    /// The generated certificate is CA, which can sign other certificates.
    fn generate_intermediate_key_pair_and_signed_cert_by_issuer(
        cn: &str,
        sans: &[&str],
        days_valid: i64,
        issuer_cert: &Certificate,
        issuer_key: &KeyPair,
    ) -> (Certificate, KeyPair) {
        let key_pair = KeyPair::generate().expect("Failed to generate leaf key pair");
        let params = generate_params(true, cn, sans, days_valid);

        let issuer = rcgen::Issuer::from_ca_cert_pem(&issuer_cert.pem(), issuer_key)
            .expect("Assumed to succeed to create certificate issuer");
        let cert = params
            .signed_by(&key_pair, &issuer)
            .expect("Assumed to succeed to sign leaf certificate");

        (cert, key_pair)
    }

    fn bundle<'a>(
        certs_for_fullchain: impl IntoIterator<Item = &'a Certificate>,
        leaf_key_pair: &KeyPair,
        ca_certs: impl IntoIterator<Item = &'a Certificate>,
    ) -> TlsBundle {
        let fullchain_cert_pem = certs_for_fullchain
            .into_iter()
            .flat_map(|cert| cert.pem().into_bytes())
            .collect::<Vec<_>>();
        let key_pem = leaf_key_pair.serialize_pem().into_bytes();
        let ca_cert_pems = ca_certs
            .into_iter()
            .map(|cert| cert.pem().into_bytes())
            .collect::<Vec<_>>();

        TlsBundle {
            fullchain_cert_pem,
            key_pem,
            ca_cert_pems,
        }
    }

    /// Generates a valid server TLS bundle and server address.
    /// The server address is a random port on the local machine.
    /// The server address is matched with the client certificate SANs.
    fn generate_valid_server_tls_bundle_and_server_address(
        cn: &str,
        sans: &[&str],
        days_valid: i64,
        cert_setup: &ServerCertsSetup,
    ) -> (TlsBundle, SocketAddr) {
        let client_trust_root = &cert_setup.client_trust_root;
        let issuer_cert = &cert_setup.server_issuer_cert;
        let issuer_key_pair = &cert_setup.server_issuer_key;

        let (cert, key_pair) = generate_leaf_key_pair_and_signed_cert_by_issuer(
            cn,
            sans,
            days_valid,
            issuer_cert,
            issuer_key_pair,
        );

        let server_bundle = bundle([&cert, issuer_cert], &key_pair, [client_trust_root]);
        let server_addr = format!("{}:0", sans.first().expect("SANs should not be empty"))
            .to_socket_addrs()
            .expect("Assumed to succeed to parse server address")
            .next()
            .expect("First server address");

        (server_bundle, server_addr)
    }

    fn create_client_endpoint(bundle: &TlsBundle) -> Result<Endpoint> {
        let certs = Certs::try_new(bundle.fullchain_cert(), bundle.key(), &bundle.ca_certs())
            .context("Failed to create client certs")?;

        config(&certs).context("Failed to create client endpoint")
    }

    fn create_server_endpoint(cert_setup: &ServerCertsSetup) -> Result<Endpoint> {
        let (server_bundle, server_addr) = generate_valid_server_tls_bundle_and_server_address(
            "localhost",
            &["localhost"],
            365,
            cert_setup,
        );

        let server_ca_certs = Certs::to_ca_certs(&server_bundle.ca_certs())
            .context("Failed to create server CA store")?;
        let server_chain = Certs::to_cert_chain(server_bundle.fullchain_cert())
            .context("Failed to parse server cert chain")?;
        let server_key =
            Certs::to_private_key(server_bundle.key()).context("Failed to parse server key")?;

        let client_cert_verifier = WebPkiClientVerifier::builder(Arc::new(server_ca_certs.clone()))
            .build()
            .context("Failed to build client certificate verifier")?;
        let server_crypto_config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_cert_verifier)
            .with_single_cert(server_chain, server_key)
            .context("Failed to create server TLS config")?;
        let server_config = ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(server_crypto_config)
                .context("Failed to generate QUIC server config")?,
        ));

        Endpoint::server(server_config, server_addr).context("Failed to create server endpoint")
    }

    async fn handshake(client_bundle: TlsBundle, cert_setup: ServerCertsSetup) -> Result<()> {
        let client_endpoint =
            create_client_endpoint(&client_bundle).context("Failed to create client endpoint")?;
        let server_endpoint =
            create_server_endpoint(&cert_setup).context("Failed to create server endpoint")?;
        let server_local_addr = server_endpoint
            .local_addr()
            .context("Failed to get server local address")?;

        tokio::time::timeout(TEST_TIMEOUT, async move {
            let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
            let server_task: JoinHandle<Result<()>> = tokio::spawn(async move {
                let incoming = server_endpoint
                    .accept()
                    .await
                    .context("Server failed to accept a connection")?;
                let connection = incoming
                    .await
                    .context("Server failed to complete connection")?;
                server_handshake(&connection, REQUIRED_GIGANTO_VERSION)
                    .await
                    .context("Server failed to complete handshake")?;
                let _ = shutdown_rx.await;

                Ok(())
            });

            let connection = client_endpoint
                .connect(server_local_addr, "localhost")
                .context("Failed to create client connection")?
                .await
                .context("Failed to complete client connection")?;

            client_handshake(&connection, REQUIRED_GIGANTO_VERSION)
                .await
                .context("Failed to complete client handshake")?;

            let _ = shutdown_tx.send(());
            server_task
                .await
                .context("Failed to join server task")?
                .context("Server task logic failed")?;
            client_endpoint.close(0u32.into(), &[]);

            Ok::<(), anyhow::Error>(())
        })
        .await
        .context(format!(
            "[TIMEOUT] Test case timed out TEST_TIMEOUT ({TEST_TIMEOUT:?})"
        ))?
        .context("Handshake failed")
    }

    // =========================================================================
    // Test Fixtures: Raw PEMs
    // =========================================================================

    /// An empty PEM file.
    #[fixture]
    fn empty_pem() -> Vec<u8> {
        b"".to_vec()
    }

    /// A PEM file with the wrong format.
    #[fixture]
    fn wrong_format_pem() -> Vec<u8> {
        b"this is not a PEM file at all".to_vec()
    }

    /// An invalid certificate PEM file.
    #[fixture]
    fn invalid_cert_pem() -> Vec<u8> {
        b"-----BEGIN CERTIFICATE-----\nINVALID_BASE64_CERTIFICATE_DATA!!!\n-----END CERTIFICATE-----\n".to_vec()
    }

    /// An invalid private key PEM file.
    #[fixture]
    fn invalid_key_pem() -> Vec<u8> {
        b"-----BEGIN PRIVATE KEY-----\nINVALID_BASE64_PRIVATE_KEY_DATA!!!\n-----END PRIVATE KEY-----\n".to_vec()
    }

    // =========================================================================
    // Test Fixtures: Scenario-based TLS Certificate Bundles
    // =========================================================================

    /// Most-commonly-used valid fullchain certificate bundle.
    #[fixture]
    fn tls_bundle_valid_fullchain() -> (TlsBundle, ServerCertsSetup) {
        let (ca_cert, ca_key_pair) =
            generate_key_pair_and_self_signed_cert("localhost", &["localhost"], 365);
        let (leaf_cert, leaf_key_pair) = generate_leaf_key_pair_and_signed_cert_by_issuer(
            "crusher@localhost",
            &["localhost"],
            365,
            &ca_cert,
            &ca_key_pair,
        );
        let client_bundle = bundle([&leaf_cert, &ca_cert], &leaf_key_pair, [&ca_cert]);
        let cert_setup = ServerCertsSetup {
            client_trust_root: ca_cert.clone(),
            server_issuer_cert: ca_cert.clone(),
            server_issuer_key: ca_key_pair,
        };

        (client_bundle, cert_setup)
    }

    /// A certificate bundle with multiple intermediate certificates.
    ///
    /// ```text
    ///     issues                   issues                   issues
    /// CA --------> Intermediate 2 --------> Intermediate 1 --------> Leaf
    /// ```
    ///
    #[fixture]
    fn tls_bundle_valid_fullchain_multiple_intermediates() -> (TlsBundle, ServerCertsSetup) {
        let (ca_cert, ca_key_pair) = generate_key_pair_and_self_signed_cert("ca", &["ca"], 365);
        let (intermediate_2_cert, intermediate_2_key_pair) =
            generate_intermediate_key_pair_and_signed_cert_by_issuer(
                "intermediate-2",
                &["intermediate-2"],
                365,
                &ca_cert,
                &ca_key_pair,
            );
        let (intermediate_1_cert, intermediate_1_key_pair) =
            generate_intermediate_key_pair_and_signed_cert_by_issuer(
                "intermediate-1",
                &["intermediate-1"],
                365,
                &intermediate_2_cert,
                &intermediate_2_key_pair,
            );
        let (leaf_cert, leaf_key_pair) = generate_leaf_key_pair_and_signed_cert_by_issuer(
            "crusher@localhost",
            &["localhost"],
            365,
            &intermediate_1_cert,
            &intermediate_1_key_pair,
        );
        let client_bundle = bundle(
            [
                &leaf_cert,
                &intermediate_1_cert,
                &intermediate_2_cert,
                &ca_cert,
            ],
            &leaf_key_pair,
            [&ca_cert],
        );
        let cert_setup = ServerCertsSetup {
            client_trust_root: ca_cert.clone(),
            server_issuer_cert: ca_cert.clone(),
            server_issuer_key: ca_key_pair,
        };

        (client_bundle, cert_setup)
    }

    #[fixture]
    fn tls_bundle_valid_fullchain_multiple_leaf_san() -> (TlsBundle, ServerCertsSetup) {
        let (ca_cert, ca_key_pair) =
            generate_key_pair_and_self_signed_cert("localhost", &["localhost"], 365);
        let (leaf_cert, leaf_key_pair) = generate_leaf_key_pair_and_signed_cert_by_issuer(
            "crusher@localhost",
            &["localhost", "127.0.0.1", "::1"],
            365,
            &ca_cert,
            &ca_key_pair,
        );
        let client_bundle = bundle([&leaf_cert, &ca_cert], &leaf_key_pair, [&ca_cert]);
        let cert_setup = ServerCertsSetup {
            client_trust_root: ca_cert.clone(),
            server_issuer_cert: ca_cert.clone(),
            server_issuer_key: ca_key_pair,
        };

        (client_bundle, cert_setup)
    }

    /// A certificate bundle with various leaf Subject Alternative Names.
    ///
    /// Includes:
    /// - DNS name with different case
    /// - Wildcard DNS name
    /// - IPv4 address
    /// - IPv6 address
    /// - Extremely long subdomain name
    #[fixture]
    fn tls_bundle_valid_fullchain_various_leaf_san() -> (TlsBundle, ServerCertsSetup) {
        let (ca_cert, ca_key_pair) =
            generate_key_pair_and_self_signed_cert("example.com", &["example.com"], 365);
        let (leaf_cert, leaf_key_pair) = generate_leaf_key_pair_and_signed_cert_by_issuer(
            "crusher@test.example.com",
            &[
                "ExAmPlE.cOm",
                "*.example.com",
                "10.0.0.1",
                "FE80::1",
                "extremely-long-subdomain-name-for-testing-purpose-abcdef1234567890.example.com",
            ],
            365,
            &ca_cert,
            &ca_key_pair,
        );
        let client_bundle = bundle([&leaf_cert, &ca_cert], &leaf_key_pair, [&ca_cert]);
        let cert_setup = ServerCertsSetup {
            client_trust_root: ca_cert.clone(),
            server_issuer_cert: ca_cert.clone(),
            server_issuer_key: ca_key_pair,
        };

        (client_bundle, cert_setup)
    }

    #[fixture]
    fn tls_bundle_valid_fullchain_different_ca_certs() -> (TlsBundle, ServerCertsSetup) {
        let (ca_cert, ca_key_pair) =
            generate_key_pair_and_self_signed_cert("localhost", &["localhost"], 365);
        let (leaf_cert, leaf_key_pair) = generate_leaf_key_pair_and_signed_cert_by_issuer(
            "crusher@localhost",
            &["localhost"],
            365,
            &ca_cert,
            &ca_key_pair,
        );

        let (other_ca_cert_1, other_ca_key_pair_1) =
            generate_key_pair_and_self_signed_cert("test1", &["127.0.0.1"], 365);
        let (other_ca_cert_2, _) = generate_key_pair_and_self_signed_cert("test2", &["::1"], 365);
        let (other_ca_cert_3, _) =
            generate_key_pair_and_self_signed_cert("test3", &["localhost"], 365);
        let client_bundle = bundle(
            [&leaf_cert, &ca_cert],
            &leaf_key_pair,
            [&other_ca_cert_1, &other_ca_cert_2, &other_ca_cert_3],
        );
        let cert_setup = ServerCertsSetup {
            client_trust_root: ca_cert.clone(),
            server_issuer_cert: other_ca_cert_1.clone(),
            server_issuer_key: other_ca_key_pair_1,
        };

        (client_bundle, cert_setup)
    }

    #[fixture]
    fn tls_bundle_valid_fullchain_short_valid_days() -> (TlsBundle, ServerCertsSetup) {
        let (ca_cert, ca_key_pair) =
            generate_key_pair_and_self_signed_cert("localhost", &["localhost"], 1);
        let (leaf_cert, leaf_key_pair) = generate_leaf_key_pair_and_signed_cert_by_issuer(
            "crusher@localhost",
            &["localhost"],
            1,
            &ca_cert,
            &ca_key_pair,
        );
        let client_bundle = bundle([&leaf_cert, &ca_cert], &leaf_key_pair, [&ca_cert]);
        let cert_setup = ServerCertsSetup {
            client_trust_root: ca_cert.clone(),
            server_issuer_cert: ca_cert.clone(),
            server_issuer_key: ca_key_pair,
        };

        (client_bundle, cert_setup)
    }

    #[fixture]
    fn tls_bundle_expired_leaf_cert() -> (TlsBundle, ServerCertsSetup) {
        let (ca_cert, ca_key_pair) =
            generate_key_pair_and_self_signed_cert("localhost", &["localhost"], 365);
        let (leaf_cert, leaf_key_pair) = generate_leaf_key_pair_and_signed_cert_by_issuer(
            "crusher@localhost",
            &["localhost"],
            -20,
            &ca_cert,
            &ca_key_pair,
        );
        let client_bundle = bundle([&leaf_cert, &ca_cert], &leaf_key_pair, [&ca_cert]);
        let cert_setup = ServerCertsSetup {
            client_trust_root: ca_cert.clone(),
            server_issuer_cert: ca_cert.clone(),
            server_issuer_key: ca_key_pair,
        };

        (client_bundle, cert_setup)
    }

    #[fixture]
    fn tls_bundle_invalid_leaf_cert() -> (TlsBundle, ServerCertsSetup) {
        let (ca_cert, ca_key_pair) =
            generate_key_pair_and_self_signed_cert("localhost", &["localhost"], 365);
        let (_, leaf_key_pair) = generate_leaf_key_pair_and_signed_cert_by_issuer(
            "crusher@localhost",
            &["localhost"],
            365,
            &ca_cert,
            &ca_key_pair,
        );
        let first_ca_key_pair = clone_key_pair(&ca_key_pair);
        let client_bundle = TlsBundle {
            fullchain_cert_pem: invalid_cert_pem(),
            key_pem: leaf_key_pair.serialize_pem().into_bytes(),
            ca_cert_pems: vec![ca_cert.pem().into_bytes()],
        };
        let cert_setup = ServerCertsSetup {
            client_trust_root: ca_cert.clone(),
            server_issuer_cert: ca_cert.clone(),
            server_issuer_key: first_ca_key_pair,
        };

        (client_bundle, cert_setup)
    }

    #[fixture]
    fn tls_bundle_empty_ca_certs() -> (TlsBundle, ServerCertsSetup) {
        let (ca_cert, ca_key_pair) =
            generate_key_pair_and_self_signed_cert("localhost", &["localhost"], 365);
        let (leaf_cert, leaf_key_pair) = generate_leaf_key_pair_and_signed_cert_by_issuer(
            "crusher@localhost",
            &["localhost"],
            365,
            &ca_cert,
            &ca_key_pair,
        );
        let client_bundle = bundle([&leaf_cert, &ca_cert], &leaf_key_pair, []);
        let cert_setup = ServerCertsSetup {
            client_trust_root: ca_cert.clone(),
            server_issuer_cert: ca_cert.clone(),
            server_issuer_key: ca_key_pair,
        };

        (client_bundle, cert_setup)
    }

    #[fixture]
    fn tls_bundle_wrong_chain_order() -> (TlsBundle, ServerCertsSetup) {
        let (ca_cert, ca_key_pair) = generate_key_pair_and_self_signed_cert("ca", &["ca"], 365);
        let (leaf_cert, leaf_key_pair) = generate_leaf_key_pair_and_signed_cert_by_issuer(
            "crusher@localhost",
            &["localhost"],
            365,
            &ca_cert,
            &ca_key_pair,
        );
        let client_bundle = bundle([&ca_cert, &leaf_cert], &leaf_key_pair, [&ca_cert]);
        let cert_setup = ServerCertsSetup {
            client_trust_root: ca_cert.clone(),
            server_issuer_cert: ca_cert.clone(),
            server_issuer_key: ca_key_pair,
        };

        (client_bundle, cert_setup)
    }

    #[fixture]
    fn tls_bundle_leaf_key_not_matching_cert() -> (TlsBundle, ServerCertsSetup) {
        let (ca_cert, ca_key_pair) = generate_key_pair_and_self_signed_cert("ca", &["ca"], 365);
        let (leaf_cert, _) = generate_leaf_key_pair_and_signed_cert_by_issuer(
            "crusher@localhost",
            &["localhost"],
            365,
            &ca_cert,
            &ca_key_pair,
        );
        let unrelated_leaf_key_pair =
            KeyPair::generate().expect("Assumed to succeed to generate key pair");
        let client_bundle = bundle([&leaf_cert, &ca_cert], &unrelated_leaf_key_pair, [&ca_cert]);
        let cert_setup = ServerCertsSetup {
            client_trust_root: ca_cert.clone(),
            server_issuer_cert: ca_cert.clone(),
            server_issuer_key: ca_key_pair,
        };

        (client_bundle, cert_setup)
    }

    // =========================================================================
    // Certificate Chain Parsing Tests
    // =========================================================================

    #[rstest]
    #[case::basic(tls_bundle_valid_fullchain().0.fullchain_cert_pem, 2)]
    #[case::intermediates(tls_bundle_valid_fullchain_multiple_intermediates().0.fullchain_cert_pem, 4)]
    #[case::multi_san(tls_bundle_valid_fullchain_multiple_leaf_san().0.fullchain_cert_pem, 2)]
    #[case::various_san(tls_bundle_valid_fullchain_various_leaf_san().0.fullchain_cert_pem, 2)]
    #[case::diff_ca(tls_bundle_valid_fullchain_different_ca_certs().0.fullchain_cert_pem, 2)]
    #[case::short_days(tls_bundle_valid_fullchain_short_valid_days().0.fullchain_cert_pem, 2)]
    fn to_cert_chain_success(#[case] fullchain_cert_pem: Vec<u8>, #[case] expected_len: usize) {
        let certs =
            Certs::to_cert_chain(&fullchain_cert_pem).expect("Should parse test certificate");

        assert_eq!(certs.len(), expected_len);
    }

    #[rstest]
    #[case::bad_cert(invalid_cert_pem(), "cannot parse certificate chain")]
    #[case::bad_leaf(tls_bundle_invalid_leaf_cert().0.fullchain_cert_pem, "cannot parse certificate chain")]
    #[case::empty(empty_pem(), "empty certificate chain")]
    #[case::wrong_pem(wrong_format_pem(), "empty certificate chain")]
    fn to_cert_chain_failure(
        #[case] invalid_cert_pem: Vec<u8>,
        #[case] part_of_error_message: &str,
    ) {
        let result = Certs::to_cert_chain(&invalid_cert_pem);
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains(part_of_error_message),
            "Error message should contain '{part_of_error_message}': {err_msg}"
        );
    }

    // =========================================================================
    // Private Key Parsing Tests
    // =========================================================================

    #[rstest]
    #[case::basic(tls_bundle_valid_fullchain().0.key_pem)]
    #[case::intermediates(tls_bundle_valid_fullchain_multiple_intermediates().0.key_pem)]
    #[case::multi_san(tls_bundle_valid_fullchain_multiple_leaf_san().0.key_pem)]
    #[case::various_san(tls_bundle_valid_fullchain_various_leaf_san().0.key_pem)]
    #[case::diff_ca(tls_bundle_valid_fullchain_different_ca_certs().0.key_pem)]
    #[case::short_days(tls_bundle_valid_fullchain_short_valid_days().0.key_pem)]
    fn to_private_key_success(#[case] key_pem: Vec<u8>) {
        let key = Certs::to_private_key(&key_pem).expect("Should parse test private key");
        assert!(
            matches!(key, PrivateKeyDer::Pkcs1(_) | PrivateKeyDer::Pkcs8(_)),
            "Key should be PKCS1 or PKCS8 format"
        );
    }

    #[rstest]
    #[case::empty(empty_pem(), "empty private key")]
    #[case::bad_key(invalid_key_pem(), "cannot parse private key")]
    fn to_private_key_failure(#[case] invalid_pem: Vec<u8>, #[case] part_of_error_message: &str) {
        let result = Certs::to_private_key(&invalid_pem);
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains(part_of_error_message),
            "Error message should contain '{part_of_error_message}': {err_msg}"
        );
    }

    // =========================================================================
    // CA Certificate Parsing Tests
    // =========================================================================
    #[rstest]
    #[case::basic(tls_bundle_valid_fullchain().0.ca_cert_pems, 1)]
    #[case::intermediates(tls_bundle_valid_fullchain_multiple_intermediates().0.ca_cert_pems, 1)]
    #[case::multi_san(tls_bundle_valid_fullchain_multiple_leaf_san().0.ca_cert_pems, 1)]
    #[case::various_san(tls_bundle_valid_fullchain_various_leaf_san().0.ca_cert_pems, 1)]
    #[case::diff_ca(tls_bundle_valid_fullchain_different_ca_certs().0.ca_cert_pems, 3)]
    #[case::short_days(tls_bundle_valid_fullchain_short_valid_days().0.ca_cert_pems, 1)]
    fn to_ca_certs_success(#[case] ca_certs_pem: Vec<Vec<u8>>, #[case] expected_len: usize) {
        let root_store = Certs::to_ca_certs(
            &ca_certs_pem
                .iter()
                .map(std::vec::Vec::as_slice)
                .collect::<Vec<_>>(),
        )
        .expect("Should parse CA certificate");

        assert_eq!(root_store.len(), expected_len);
    }

    #[rstest]
    #[case::bad_cert(vec![invalid_cert_pem()], "invalid PEM-encoded certificate")]
    fn to_ca_certs_failure(
        #[case] ca_certs_pem: Vec<Vec<u8>>,
        #[case] part_of_error_message: &str,
    ) {
        let result = Certs::to_ca_certs(
            &ca_certs_pem
                .iter()
                .map(std::vec::Vec::as_slice)
                .collect::<Vec<_>>(),
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains(part_of_error_message),
            "Error message should contain '{part_of_error_message}': {err_msg}"
        );
    }

    // =========================================================================
    // Certs::try_new Error Path Tests
    // =========================================================================

    #[rstest]
    #[case::basic(tls_bundle_valid_fullchain(), 2, 1)]
    #[case::intermediates(tls_bundle_valid_fullchain_multiple_intermediates(), 4, 1)]
    #[case::multi_san(tls_bundle_valid_fullchain_multiple_leaf_san(), 2, 1)]
    #[case::various_san(tls_bundle_valid_fullchain_various_leaf_san(), 2, 1)]
    #[case::diff_ca(tls_bundle_valid_fullchain_different_ca_certs(), 2, 3)]
    #[case::short_days(tls_bundle_valid_fullchain_short_valid_days(), 2, 1)]
    fn try_new_success(
        #[case] (tls_bundle, _): (TlsBundle, ServerCertsSetup),
        #[case] expected_certs_len: usize,
        #[case] expected_ca_certs_len: usize,
    ) {
        let certs = Certs::try_new(
            tls_bundle.fullchain_cert(),
            tls_bundle.key(),
            &tls_bundle.ca_certs(),
        )
        .expect("Should succeed for this case");

        assert_eq!(certs.certs.len(), expected_certs_len);
        assert_eq!(certs.ca_certs.len(), expected_ca_certs_len);
    }

    #[rstest]
    #[case::bad_leaf(tls_bundle_invalid_leaf_cert())]
    fn try_new_failure(#[case] (tls_bundle, _): (TlsBundle, ServerCertsSetup)) {
        let result = Certs::try_new(
            tls_bundle.fullchain_cert(),
            tls_bundle.key(),
            &tls_bundle.ca_certs(),
        );
        assert!(result.is_err());
    }

    // =========================================================================
    // QUIC Endpoint Configuration Tests
    // =========================================================================

    #[tokio::test]
    #[rstest]
    #[case::basic(tls_bundle_valid_fullchain())]
    #[case::intermediates(tls_bundle_valid_fullchain_multiple_intermediates())]
    #[case::multi_san(tls_bundle_valid_fullchain_multiple_leaf_san())]
    #[case::various_san(tls_bundle_valid_fullchain_various_leaf_san())]
    #[case::diff_ca(tls_bundle_valid_fullchain_different_ca_certs())]
    #[case::short_days(tls_bundle_valid_fullchain_short_valid_days())]
    async fn config_creates_endpoint_success(
        #[case] (tls_bundle, _): (TlsBundle, ServerCertsSetup),
    ) {
        let certs = Certs::try_new(
            tls_bundle.fullchain_cert(),
            tls_bundle.key(),
            &tls_bundle.ca_certs(),
        )
        .expect("Should succeed for this case");
        let endpoint = config(&certs).expect("Endpoint should be created successfully");
        let local_addr = endpoint
            .local_addr()
            .expect("Endpoint should have local address");
        assert!(local_addr.port() > 0, "Endpoint should be bound to a port");
    }

    // =========================================================================
    // Handshake Tests
    // =========================================================================
    #[tokio::test]
    #[rstest]
    #[case::basic(tls_bundle_valid_fullchain())]
    #[case::intermediates(tls_bundle_valid_fullchain_multiple_intermediates())]
    #[case::multi_san(tls_bundle_valid_fullchain_multiple_leaf_san())]
    #[case::various_san(tls_bundle_valid_fullchain_various_leaf_san())]
    #[case::diff_ca(tls_bundle_valid_fullchain_different_ca_certs())]
    #[case::short_days(tls_bundle_valid_fullchain_short_valid_days())]
    async fn handshake_success(#[case] (client_bundle, cert_setup): (TlsBundle, ServerCertsSetup)) {
        let result = handshake(client_bundle, cert_setup).await;
        assert!(result.is_ok(), "Handshake result should be successful");
    }

    #[tokio::test]
    #[rstest]
    #[case::expired(tls_bundle_expired_leaf_cert())]
    #[case::bad_leaf(tls_bundle_invalid_leaf_cert())]
    #[case::empty_ca(tls_bundle_empty_ca_certs())]
    #[case::wrong_order(tls_bundle_wrong_chain_order())]
    #[case::key_mismatch(tls_bundle_leaf_key_not_matching_cert())]
    async fn handshake_failure(#[case] (client_bundle, cert_setup): (TlsBundle, ServerCertsSetup)) {
        let result = handshake(client_bundle, cert_setup).await;
        assert!(result.is_err(), "Handshake result should be an error");
    }
}
