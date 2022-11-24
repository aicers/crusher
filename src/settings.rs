//! Configurations for the application.
use config::{builder::DefaultState, Config, ConfigBuilder, ConfigError, File};
use serde::{de::Error, Deserialize, Deserializer};
use std::{net::SocketAddr, path::PathBuf};

const DEFAULT_GIGANTO_NAME: &str = "localhost";
const DEFAULT_GIGANTO_INGESTION_ADDRESS: &str = "[::]:38370";
const DEFAULT_GIGANTO_PUBLISH_ADDRESS: &str = "[::]:38371";
const DEFAULT_REVIEW_NAME: &str = "localhost";
const DEFAULT_REVIEW_ADDRESS: &str = "[::]:38390";
const DEFAULT_AGENT_ID: &str = "cruhser";

/// The application settings.
#[derive(Clone, Debug, Deserialize)]
pub struct Settings {
    pub cert: PathBuf,        // Path to the certificate file
    pub key: PathBuf,         // Path to the private key file
    pub roots: Vec<PathBuf>,  // Path to the rootCA file
    pub giganto_name: String, // host name to giganto
    #[serde(deserialize_with = "deserialize_socket_addr")]
    pub giganto_ingestion_address: SocketAddr, // IP address & port to giganto
    #[serde(deserialize_with = "deserialize_socket_addr")]
    pub giganto_publish_address: SocketAddr, // IP address & port to giganto
    pub review_name: String,  // host name to review
    #[serde(deserialize_with = "deserialize_socket_addr")]
    pub review_address: SocketAddr, // IP address & port to review
    pub agent_id: String,     //unique identifier
    pub last_timestamp_data: PathBuf, // Path to the last series timestamp data file
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

    Config::builder()
        .set_default("cert", cert_path.to_str().expect("path to string"))
        .expect("default cert dir")
        .set_default("key", key_path.to_str().expect("path to string"))
        .expect("default key dir")
        .set_default("giganto_name", DEFAULT_GIGANTO_NAME)
        .expect("valid name")
        .set_default(
            "giganto_ingestion_address",
            DEFAULT_GIGANTO_INGESTION_ADDRESS,
        )
        .expect("valid address")
        .set_default("giganto_publish_address", DEFAULT_GIGANTO_PUBLISH_ADDRESS)
        .expect("valid address")
        .set_default("review_name", DEFAULT_REVIEW_NAME)
        .expect("valid name")
        .set_default("review_address", DEFAULT_REVIEW_ADDRESS)
        .expect("valid address")
        .set_default("agent_id", DEFAULT_AGENT_ID)
        .expect("valid id")
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
        .map_err(|e| D::Error::custom(format!("invalid address \"{}\": {}", addr, e)))
}
