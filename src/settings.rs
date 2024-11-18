//! Configurations for the application.
use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result};
use config::{builder::DefaultState, Config as cfg, ConfigBuilder, ConfigError, File, FileFormat};
use serde::{de::Error, Deserialize, Deserializer};

use crate::CmdLineArgs;

const DEFAULT_GIGANTO_NAME: &str = "localhost";
const DEFAULT_GIGANTO_INGEST_SRV_ADDR: &str = "[::]:38370";
const DEFAULT_GIGANTO_PUBLISH_SRV_ADDR: &str = "[::]:38371";
pub const TEMP_TOML_POST_FIX: &str = ".temp.toml";

/// The application settings.
#[derive(Clone, Debug, Deserialize)]
pub struct Settings {
    pub giganto_name: String, // hostname of Giganto
    #[serde(deserialize_with = "deserialize_socket_addr")]
    pub giganto_ingest_srv_addr: SocketAddr, // IP address & port to giganto
    #[serde(deserialize_with = "deserialize_socket_addr")]
    pub giganto_publish_srv_addr: SocketAddr, // IP address & port to giganto
    pub last_timestamp_data: PathBuf, // Path to the last series timestamp data file
    pub log_dir: Option<PathBuf>,
}

impl Settings {
    /// Creates a new `Settings` instance, populated from the given
    /// configuration file.
    pub fn from_file(cfg_path: &str) -> Result<Self, ConfigError> {
        let s = default_config_builder()
            .add_source(File::with_name(cfg_path))
            .build()?;

        s.try_deserialize()
    }

    /// Creates a new `Settings` instance from the given command line arguments.
    pub fn from_args(args: CmdLineArgs) -> Result<Self> {
        let mut config_builder = default_config_builder()
            .set_override("cert", args.cert)?
            .set_override("key", args.key)?
            .set_override("ca_certs", args.ca_certs)?;

        if let Some(config) = args.config {
            config_builder = config_builder
                .add_source(config::File::with_name(config.as_str()).format(FileFormat::Toml));
        }
        config_builder
            .build()?
            .try_deserialize()
            .context("failed to parse configuration file")
    }
}

/// Creates a new `ConfigBuilder` instance with the default configuration.
fn default_config_builder() -> ConfigBuilder<DefaultState> {
    cfg::builder()
        .set_default("giganto_name", DEFAULT_GIGANTO_NAME)
        .expect("verified by const datalake name")
        .set_default("giganto_ingest_srv_addr", DEFAULT_GIGANTO_INGEST_SRV_ADDR)
        .expect("verified by const datalake ingest server address")
        .set_default("giganto_publish_srv_addr", DEFAULT_GIGANTO_PUBLISH_SRV_ADDR)
        .expect("verified by const datalake publish server address")
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
