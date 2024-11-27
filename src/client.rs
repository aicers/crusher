use std::fs;

use anyhow::{anyhow, Context, Result};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    RootCertStore,
};

use crate::CmdLineArgs;

pub const SERVER_RETRY_INTERVAL: u64 = 3;

#[allow(clippy::struct_field_names)]
pub struct Certs {
    pub cert_raw: Vec<u8>,
    pub key_raw: Vec<u8>,
    pub ca_certs_raw: Vec<Vec<u8>>,
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    pub ca_certs: RootCertStore,
}

impl Clone for Certs {
    fn clone(&self) -> Self {
        Self {
            cert_raw: self.cert_raw.clone(),
            key_raw: self.key_raw.clone(),
            ca_certs_raw: self.ca_certs_raw.clone(),
            certs: self.certs.clone(),
            key: self.key.clone_key(),
            ca_certs: self.ca_certs.clone(),
        }
    }
}

impl Certs {
    pub fn from_args(args: &CmdLineArgs) -> Result<Self> {
        let cert_raw = fs::read(&args.cert)
            .with_context(|| format!("failed to read certificate file: {}", args.cert))?;
        let certs = Self::to_cert_chain(&cert_raw).context("cannot read certificate chain")?;
        assert!(!certs.is_empty());

        let key_raw = fs::read(&args.key)
            .with_context(|| format!("failed to read private key file: {}", args.key))?;
        let key = Self::to_private_key(&key_raw).context("cannot read private key")?;

        let mut ca_certs_raw = Vec::new();
        for ca_cert in &args.ca_certs {
            let file = fs::read(ca_cert)
                .with_context(|| format!("failed to read CA certificate file: {ca_cert}"))?;
            ca_certs_raw.push(file);
        }

        let ca_certs =
            Self::to_ca_certs(&ca_certs_raw).context("failed to read CA certificates")?;

        Ok(Self {
            cert_raw,
            key_raw,
            ca_certs_raw,
            certs,
            key,
            ca_certs,
        })
    }

    pub fn to_cert_chain(raw: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
        let certs = rustls_pemfile::certs(&mut &*raw)
            .collect::<Result<_, _>>()
            .context("cannot parse certificate chain")?;
        Ok(certs)
    }

    pub fn to_private_key(raw: &[u8]) -> Result<PrivateKeyDer<'static>> {
        match rustls_pemfile::read_one(&mut &*raw)
            .context("cannot parse private key")?
            .ok_or_else(|| anyhow!("empty private key"))?
        {
            rustls_pemfile::Item::Pkcs1Key(key) => Ok(key.into()),
            rustls_pemfile::Item::Pkcs8Key(key) => Ok(key.into()),
            _ => Err(anyhow!("unknown private key format")),
        }
    }

    pub fn to_ca_certs(ca_certs_raw: &Vec<Vec<u8>>) -> Result<rustls::RootCertStore> {
        let mut root_cert = rustls::RootCertStore::empty();
        for ca_cert_pem in ca_certs_raw {
            let root_certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut &**ca_cert_pem)
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
