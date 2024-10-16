//! Configurations for the application.
use std::{net::SocketAddr, path::PathBuf};

use anyhow::Result;
use config::{builder::DefaultState, Config as cfg, ConfigBuilder, ConfigError, File};
use serde::{de::Error, Deserialize, Deserializer};

const DEFAULT_GIGANTO_NAME: &str = "localhost";
const DEFAULT_GIGANTO_INGEST_SRV_ADDR: &str = "[::]:38370";
const DEFAULT_GIGANTO_PUBLISH_SRV_ADDR: &str = "[::]:38371";
const DEFAULT_REVIEW_NAME: &str = "localhost";
const DEFAULT_REVIEW_RPC_SRV_ADDR: &str = "[::]:38390";
pub const TEMP_TOML_POST_FIX: &str = ".temp.toml";

/// The application settings.
#[derive(Clone, Debug, Deserialize)]
pub struct Settings {
    pub cert: PathBuf,          // Path to the certificate file
    pub key: PathBuf,           // Path to the private key file
    pub ca_certs: Vec<PathBuf>, // Path to the CA certificate file
    pub giganto_name: String,   // host name to giganto
    #[serde(deserialize_with = "deserialize_socket_addr")]
    pub giganto_ingest_srv_addr: SocketAddr, // IP address & port to giganto
    #[serde(deserialize_with = "deserialize_socket_addr")]
    pub giganto_publish_srv_addr: SocketAddr, // IP address & port to giganto
    pub review_name: String,    // host name to review
    #[serde(deserialize_with = "deserialize_socket_addr")]
    pub review_rpc_srv_addr: SocketAddr, // IP address & port to review
    pub last_timestamp_data: PathBuf, // Path to the last series timestamp data file
    pub log_dir: PathBuf,
}

impl Settings {
    /// Creates a new `Settings` instance, populated from the default
    /// configuration file if it exists.
    pub fn new() -> Result<Self, ConfigError> {
        let dirs = directories::ProjectDirs::from("com", "cluml", "crusher").expect("unreachable");
        let config_path = dirs.config_dir().join("config.toml");
        if config_path.exists() {
            // `config::File` requires a `&str` path, so we can't use `config_path` directly.
            if let Some(path) = config_path.to_str() {
                Self::from_file(path)
            } else {
                Err(ConfigError::Message(
                    "config path must be a valid UTF-8 string".to_string(),
                ))
            }
        } else {
            default_config_builder().build()?.try_deserialize()
        }
    }

    /// Creates a new `Settings` instance, populated from the given
    /// configuration file.
    pub fn from_file(cfg_path: &str) -> Result<Self, ConfigError> {
        let s = default_config_builder()
            .add_source(File::with_name(cfg_path))
            .build()?;

        s.try_deserialize()
    }
}

/// Creates a new `ConfigBuilder` instance with the default configuration.
fn default_config_builder() -> ConfigBuilder<DefaultState> {
    let dirs = directories::ProjectDirs::from("com", "cluml", "crusher").expect("unreachable");
    let config_dir = dirs.config_dir();
    let cert_path = config_dir.join("cert.pem");
    let key_path = config_dir.join("key.pem");
    let last_timestamp_path = config_dir.join("time_data.json");

    cfg::builder()
        .set_default("cert", cert_path.to_str().expect("path to string"))
        .expect("default cert dir")
        .set_default("key", key_path.to_str().expect("path to string"))
        .expect("default key dir")
        .set_default("giganto_name", DEFAULT_GIGANTO_NAME)
        .expect("valid name")
        .set_default("giganto_ingest_srv_addr", DEFAULT_GIGANTO_INGEST_SRV_ADDR)
        .expect("valid address")
        .set_default("giganto_publish_srv_addr", DEFAULT_GIGANTO_PUBLISH_SRV_ADDR)
        .expect("valid address")
        .set_default("review_name", DEFAULT_REVIEW_NAME)
        .expect("valid name")
        .set_default("review_rpc_srv_addr", DEFAULT_REVIEW_RPC_SRV_ADDR)
        .expect("valid address")
        .set_default(
            "last_timestamp_data",
            last_timestamp_path.to_str().expect("path to string"),
        )
        .expect("valid time_data")
}

/// Deserializes a socket address.
///
/// # Errors
///
/// Returns an error if the address is not in the form of 'IP:PORT'.
fn deserialize_socket_addr<'de, D>(deserializer: D) -> Result<SocketAddr, D::Error>
where
    D: Deserializer<'de>,
{
    let addr = String::deserialize(deserializer)?;
    addr.parse()
        .map_err(|e| D::Error::custom(format!("invalid address \"{addr}\": {e}")))
}
