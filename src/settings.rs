//! Configurations for the application.
use std::{net::SocketAddr, path::PathBuf, str::FromStr};

use anyhow::{Context, Result};
use config::{builder::DefaultState, Config as cfg, ConfigBuilder, ConfigError, File};
use serde::{de::Error, Deserialize, Deserializer};

const DEFAULT_GIGANTO_NAME: &str = "localhost";
const DEFAULT_GIGANTO_INGEST_SRV_ADDR: &str = "[::]:38370";
const DEFAULT_GIGANTO_PUBLISH_SRV_ADDR: &str = "[::]:38371";

/// The application settings.
#[derive(Clone, Debug, Deserialize)]
pub(super) struct Settings {
    pub(super) giganto_name: String, // hostname of Giganto
    #[serde(deserialize_with = "deserialize_socket_addr")]
    pub(super) giganto_ingest_srv_addr: SocketAddr, // IP address & port to giganto
    #[serde(deserialize_with = "deserialize_socket_addr")]
    pub(super) giganto_publish_srv_addr: SocketAddr, // IP address & port to giganto
    pub(super) last_timestamp_data: PathBuf, // Path to the last series timestamp data file
    pub(super) log_path: Option<PathBuf>,
}

impl Settings {
    /// Creates a new `Settings` instance, populated from the given
    /// configuration file.
    pub(super) fn from_file(cfg_path: &str) -> Result<Self, ConfigError> {
        let s = default_config_builder()
            .add_source(File::with_name(cfg_path))
            .build()?;

        s.try_deserialize()
    }
}

impl FromStr for Settings {
    type Err = anyhow::Error;

    fn from_str(config_toml: &str) -> Result<Self> {
        default_config_builder()
            .add_source(config::File::from_str(
                config_toml,
                config::FileFormat::Toml,
            ))
            .build()?
            .try_deserialize()
            .context("Failed to parse the configuration string")
    }
}

/// Creates a new `ConfigBuilder` instance with the default configuration.
fn default_config_builder() -> ConfigBuilder<DefaultState> {
    cfg::builder()
        .set_default("giganto_name", DEFAULT_GIGANTO_NAME)
        .expect("verified by const data store's name")
        .set_default("giganto_ingest_srv_addr", DEFAULT_GIGANTO_INGEST_SRV_ADDR)
        .expect("verified by const data store's ingest server address")
        .set_default("giganto_publish_srv_addr", DEFAULT_GIGANTO_PUBLISH_SRV_ADDR)
        .expect("verified by const data store's publish server address")
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
