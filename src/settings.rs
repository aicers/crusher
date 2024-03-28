//! Configurations for the application.
use anyhow::{Context, Result};
use config::{builder::DefaultState, Config as cfg, ConfigBuilder, ConfigError, File};
use review_protocol::types::{Config, CrusherConfig};
use serde::{de::Error, Deserialize, Deserializer};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    net::SocketAddr,
    path::PathBuf,
};
use toml_edit::{value, Document};

const DEFAULT_GIGANTO_NAME: &str = "localhost";
const DEFAULT_GIGANTO_INGEST_ADDRESS: &str = "[::]:38370";
const DEFAULT_GIGANTO_PUBLISH_ADDRESS: &str = "[::]:38371";
const DEFAULT_REVIEW_NAME: &str = "localhost";
const DEFAULT_REVIEW_ADDRESS: &str = "[::]:38390";
pub const TEMP_TOML_POST_FIX: &str = ".temp.toml";

/// The application settings.
#[derive(Clone, Debug, Deserialize)]
pub struct Settings {
    pub cert: PathBuf,        // Path to the certificate file
    pub key: PathBuf,         // Path to the private key file
    pub roots: Vec<PathBuf>,  // Path to the rootCA file
    pub giganto_name: String, // host name to giganto
    #[serde(deserialize_with = "deserialize_socket_addr")]
    pub giganto_ingest_address: SocketAddr, // IP address & port to giganto
    #[serde(deserialize_with = "deserialize_socket_addr")]
    pub giganto_publish_address: SocketAddr, // IP address & port to giganto
    pub review_name: String,  // host name to review
    #[serde(deserialize_with = "deserialize_socket_addr")]
    pub review_address: SocketAddr, // IP address & port to review
    pub last_timestamp_data: PathBuf, // Path to the last series timestamp data file
    pub log_dir: PathBuf,
}

impl Settings {
    /// Creates a new `Settings` instance, populated from the default
    /// configuration file if it exists.
    pub fn new() -> Result<Self, ConfigError> {
        let dirs = directories::ProjectDirs::from("com", "einsis", "crusher").expect("unreachable");
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
    let dirs = directories::ProjectDirs::from("com", "einsis", "crusher").expect("unreachable");
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
        .set_default("giganto_ingest_address", DEFAULT_GIGANTO_INGEST_ADDRESS)
        .expect("valid address")
        .set_default("giganto_publish_address", DEFAULT_GIGANTO_PUBLISH_ADDRESS)
        .expect("valid address")
        .set_default("review_name", DEFAULT_REVIEW_NAME)
        .expect("valid name")
        .set_default("review_address", DEFAULT_REVIEW_ADDRESS)
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

pub fn get_config(config_path: &str) -> Result<Config> {
    let toml = fs::read_to_string(config_path).context("toml not found")?;
    let doc = toml.parse::<Document>()?;

    let review_address = doc
        .get("review_address")
        .context("\"review_address\" not found")?
        .to_string()
        .trim_matches('\"')
        .parse::<SocketAddr>()?;
    let giganto_publish_address = doc
        .get("giganto_publish_address")
        .context("\"giganto_publish_address\" not found")?
        .to_string()
        .trim_matches('\"')
        .parse::<SocketAddr>()?;
    let giganto_ingest_address = doc
        .get("giganto_ingest_address")
        .context("\"giganto_ingest_address\" not found")?
        .to_string()
        .trim_matches('\"')
        .parse::<SocketAddr>()?;

    Ok(Config::Crusher(CrusherConfig {
        review_address,
        giganto_publish_address: Some(giganto_publish_address),
        giganto_ingest_address: Some(giganto_ingest_address),
    }))
}

pub fn set_config(config: &Config, config_path: &str) -> Result<()> {
    let tmp_path = format!("{config_path}{TEMP_TOML_POST_FIX}");
    fs::copy(config_path, &tmp_path)?;
    let config_toml = fs::read_to_string(&tmp_path).context("toml not found")?;
    let mut doc = config_toml.parse::<Document>()?;

    if let Config::Crusher(conf) = config {
        doc["review_address"] = value(conf.review_address.to_string());
        if let Some(giganto_ingest_address) = conf.giganto_ingest_address {
            doc["giganto_ingest_address"] = value(giganto_ingest_address.to_string());
        }
        if let Some(giganto_publish_address) = conf.giganto_publish_address {
            doc["giganto_publish_address"] = value(giganto_publish_address.to_string());
        }
    }

    let output = doc.to_string();
    let mut toml_file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&tmp_path)?;
    writeln!(toml_file, "{output}")?;

    Ok(())
}
