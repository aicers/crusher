//! Configurations for the application.
use std::{net::SocketAddr, path::PathBuf, str::FromStr};

use anyhow::{Context, Result, bail};
use config::{Config as cfg, File};
use serde::{Deserialize, Deserializer, de::Error};

/// The application settings.
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct Settings {
    pub(crate) giganto_name: Option<String>, // hostname of Giganto
    #[serde(deserialize_with = "deserialize_socket_addr")]
    pub(crate) giganto_ingest_srv_addr: SocketAddr, // IP address & port to giganto
    #[serde(deserialize_with = "deserialize_socket_addr")]
    pub(crate) giganto_publish_srv_addr: SocketAddr, // IP address & port to giganto
    pub(crate) last_timestamp_data: PathBuf, // Path to the last series timestamp data file
    pub(crate) log_path: Option<PathBuf>,
}

impl Settings {
    /// Creates a new `Settings` instance, populated from the given
    /// configuration file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed as a valid
    /// settings configuration.
    pub(crate) fn from_file(cfg_path: &str) -> Result<Self> {
        let s = cfg::builder()
            .add_source(File::with_name(cfg_path))
            .build()
            .with_context(|| format!("failed to load configuration file: {cfg_path}"))?;

        s.try_deserialize()
            .context("failed to parse configuration file")
    }

    /// Resolves the Giganto connection target name.
    ///
    /// If `giganto_name` is present (non-empty), it is used. Otherwise,
    /// the IP from `giganto_publish_srv_addr` is used only when it matches
    /// `giganto_ingest_srv_addr`. Returns an error if `giganto_name` is
    /// absent and the two addresses point to different IPs.
    pub(crate) fn resolve_giganto_name(&self) -> Result<String> {
        if let Some(name) = &self.giganto_name
            && !name.trim().is_empty()
        {
            return Ok(name.clone());
        }
        let publish_ip = self.giganto_publish_srv_addr.ip();
        let ingest_ip = self.giganto_ingest_srv_addr.ip();
        if publish_ip != ingest_ip {
            bail!(
                "giganto_name is required when giganto_publish_srv_addr ({publish_ip}) \
                 and giganto_ingest_srv_addr ({ingest_ip}) point to different IPs",
            );
        }
        Ok(publish_ip.to_string())
    }
}

impl FromStr for Settings {
    type Err = anyhow::Error;

    fn from_str(config_toml: &str) -> Result<Self> {
        cfg::builder()
            .add_source(config::File::from_str(
                config_toml,
                config::FileFormat::Toml,
            ))
            .build()?
            .try_deserialize()
            .context("Failed to parse the configuration string")
    }
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

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::{Builder, NamedTempFile};

    use super::*;

    /// Minimal TOML config with only the required fields.
    /// `giganto_name` is absent.
    const MINIMAL_CONFIG: &str = r#"
giganto_ingest_srv_addr = "10.0.0.1:38370"
giganto_publish_srv_addr = "10.0.0.1:38371"
last_timestamp_data = "/tmp/timestamp.dat"
"#;

    /// Full TOML config with all fields explicitly set.
    const FULL_CONFIG: &str = r#"
giganto_name = "custom-host"
giganto_ingest_srv_addr = "192.168.1.100:38370"
giganto_publish_srv_addr = "192.168.1.100:38371"
last_timestamp_data = "/var/lib/crusher/timestamp.dat"
log_path = "/var/log/crusher"
"#;

    /// Config with IPv6 addresses.
    const IPV6_CONFIG: &str = r#"
giganto_name = "ipv6-host"
giganto_ingest_srv_addr = "[::1]:38370"
giganto_publish_srv_addr = "[2001:db8::1]:38371"
last_timestamp_data = "/tmp/timestamp.dat"
"#;

    #[test]
    fn from_str_parses_minimal_config() {
        let settings: Settings = MINIMAL_CONFIG.parse().expect("should parse minimal config");

        assert!(settings.giganto_name.is_none());
        assert_eq!(
            settings.giganto_ingest_srv_addr,
            "10.0.0.1:38370"
                .parse::<SocketAddr>()
                .expect("valid address")
        );
        assert_eq!(
            settings.giganto_publish_srv_addr,
            "10.0.0.1:38371"
                .parse::<SocketAddr>()
                .expect("valid address")
        );
        assert_eq!(
            settings.last_timestamp_data,
            PathBuf::from("/tmp/timestamp.dat")
        );
        assert!(settings.log_path.is_none());
    }

    #[test]
    fn from_str_parses_full_config() {
        let settings: Settings = FULL_CONFIG.parse().expect("should parse full config");

        assert_eq!(settings.giganto_name.as_deref(), Some("custom-host"));
        assert_eq!(
            settings.giganto_ingest_srv_addr,
            "192.168.1.100:38370"
                .parse::<SocketAddr>()
                .expect("valid address")
        );
        assert_eq!(
            settings.giganto_publish_srv_addr,
            "192.168.1.100:38371"
                .parse::<SocketAddr>()
                .expect("valid address")
        );
        assert_eq!(
            settings.last_timestamp_data,
            PathBuf::from("/var/lib/crusher/timestamp.dat")
        );
        assert_eq!(settings.log_path, Some(PathBuf::from("/var/log/crusher")));
    }

    /// Helper to create a temporary file with .toml extension.
    /// The config crate determines file format from the extension.
    fn create_temp_toml_file() -> NamedTempFile {
        Builder::new()
            .suffix(".toml")
            .tempfile()
            .expect("should create temp file")
    }

    #[test]
    fn from_file_reads_and_parses_config() {
        let mut temp_file = create_temp_toml_file();
        temp_file
            .write_all(FULL_CONFIG.as_bytes())
            .expect("should write config");

        let path = temp_file.path().to_str().expect("valid path");
        let settings = Settings::from_file(path).expect("should parse config from file");

        assert_eq!(settings.giganto_name.as_deref(), Some("custom-host"));
        assert_eq!(
            settings.giganto_ingest_srv_addr,
            "192.168.1.100:38370"
                .parse::<SocketAddr>()
                .expect("valid address")
        );
        assert_eq!(
            settings.giganto_publish_srv_addr,
            "192.168.1.100:38371"
                .parse::<SocketAddr>()
                .expect("valid address")
        );
        assert_eq!(
            settings.last_timestamp_data,
            PathBuf::from("/var/lib/crusher/timestamp.dat")
        );
        assert_eq!(settings.log_path, Some(PathBuf::from("/var/log/crusher")));
    }

    #[test]
    fn from_file_with_minimal_config() {
        let mut temp_file = create_temp_toml_file();
        temp_file
            .write_all(MINIMAL_CONFIG.as_bytes())
            .expect("should write config");

        let path = temp_file.path().to_str().expect("valid path");
        let settings = Settings::from_file(path).expect("should parse config from file");

        assert!(settings.giganto_name.is_none());
        assert_eq!(
            settings.giganto_ingest_srv_addr,
            "10.0.0.1:38370"
                .parse::<SocketAddr>()
                .expect("valid address")
        );
        assert_eq!(
            settings.giganto_publish_srv_addr,
            "10.0.0.1:38371"
                .parse::<SocketAddr>()
                .expect("valid address")
        );
    }

    #[test]
    fn from_file_non_existent_file() {
        let file_name = "/non/existent/path/non_existent_file.toml";
        let result = Settings::from_file(file_name);
        let err = result.unwrap_err();
        assert!(err.to_string().contains(file_name));
    }

    #[test]
    fn from_str_ipv4_parsing() {
        // Test IPv4 address parsing with explicit port.
        let config = r#"
giganto_ingest_srv_addr = "127.0.0.1:8080"
giganto_publish_srv_addr = "10.0.0.1:9090"
last_timestamp_data = "/tmp/ts.dat"
"#;
        let settings: Settings = config.parse().expect("should parse IPv4 addresses");

        assert_eq!(
            settings.giganto_ingest_srv_addr,
            "127.0.0.1:8080"
                .parse::<SocketAddr>()
                .expect("valid address")
        );
        assert_eq!(
            settings.giganto_publish_srv_addr,
            "10.0.0.1:9090"
                .parse::<SocketAddr>()
                .expect("valid address")
        );
    }

    #[test]
    fn from_str_ipv6_parsing() {
        // Test IPv6 address parsing with bracketed notation.
        let settings: Settings = IPV6_CONFIG.parse().expect("should parse IPv6 addresses");

        assert_eq!(
            settings.giganto_ingest_srv_addr,
            "[::1]:38370".parse::<SocketAddr>().expect("valid address")
        );
        assert_eq!(
            settings.giganto_publish_srv_addr,
            "[2001:db8::1]:38371"
                .parse::<SocketAddr>()
                .expect("valid address")
        );
    }

    #[test]
    fn from_str_ipv6_all_zeros() {
        // Test the default IPv6 all-zeros address format.
        let config = r#"
giganto_ingest_srv_addr = "[::]:38370"
giganto_publish_srv_addr = "[::]:38371"
last_timestamp_data = "/tmp/ts.dat"
"#;
        let settings: Settings = config.parse().expect("should parse IPv6 all-zeros");

        assert_eq!(
            settings.giganto_ingest_srv_addr,
            "[::]:38370".parse::<SocketAddr>().expect("valid address")
        );
        assert_eq!(
            settings.giganto_publish_srv_addr,
            "[::]:38371".parse::<SocketAddr>().expect("valid address")
        );
    }

    /// Helper to get the full error chain as a string.
    /// The `anyhow::Error` wraps underlying errors, so we need the full chain
    /// to see the detailed error message from `deserialize_socket_addr`.
    fn error_chain_string(err: &anyhow::Error) -> String {
        format!("{err:#}")
    }

    #[test]
    fn deserialize_socket_addr_invalid_ipv6_without_brackets() {
        // IPv6 without brackets when port is present should be rejected.
        // This tests the error message format for invalid addresses.
        let config = r#"
giganto_ingest_srv_addr = "::1:8080"
giganto_publish_srv_addr = "10.0.0.1:38371"
last_timestamp_data = "/tmp/ts.dat"
"#;
        let err = config.parse::<Settings>().expect_err("should fail");
        let err_str = error_chain_string(&err);

        // The error should mention "invalid address" with the problematic value.
        // Using contains() because the exact error format depends on std::net parsing.
        assert!(
            err_str.contains("invalid address"),
            "error should mention 'invalid address': {err_str}"
        );
        assert!(
            err_str.contains("::1:8080"),
            "error should include the invalid address value: {err_str}"
        );
    }

    #[test]
    fn deserialize_socket_addr_missing_port() {
        // Address without port should be rejected.
        let config = r#"
giganto_ingest_srv_addr = "127.0.0.1"
giganto_publish_srv_addr = "10.0.0.1:38371"
last_timestamp_data = "/tmp/ts.dat"
"#;
        let err = config.parse::<Settings>().expect_err("should fail");
        let err_str = error_chain_string(&err);

        assert!(
            err_str.contains("invalid address"),
            "error should mention 'invalid address': {err_str}"
        );
        assert!(
            err_str.contains("127.0.0.1"),
            "error should include the invalid address value: {err_str}"
        );
    }

    #[test]
    fn deserialize_socket_addr_invalid_port_non_numeric() {
        // Non-numeric port should be rejected.
        let config = r#"
giganto_ingest_srv_addr = "127.0.0.1:abc"
giganto_publish_srv_addr = "10.0.0.1:38371"
last_timestamp_data = "/tmp/ts.dat"
"#;
        let err = config.parse::<Settings>().expect_err("should fail");
        let err_str = error_chain_string(&err);

        assert!(
            err_str.contains("invalid address"),
            "error should mention 'invalid address': {err_str}"
        );
        assert!(
            err_str.contains("127.0.0.1:abc"),
            "error should include the invalid address value: {err_str}"
        );
    }

    #[test]
    fn deserialize_socket_addr_port_out_of_range() {
        // Port number > 65535 should be rejected.
        let config = r#"
giganto_ingest_srv_addr = "127.0.0.1:99999"
giganto_publish_srv_addr = "10.0.0.1:38371"
last_timestamp_data = "/tmp/ts.dat"
"#;
        let err = config.parse::<Settings>().expect_err("should fail");
        let err_str = error_chain_string(&err);

        assert!(
            err_str.contains("invalid address"),
            "error should mention 'invalid address': {err_str}"
        );
        assert!(
            err_str.contains("127.0.0.1:99999"),
            "error should include the invalid address value: {err_str}"
        );
    }

    #[test]
    fn deserialize_socket_addr_empty_address() {
        // Empty address should be rejected.
        let config = r#"
giganto_ingest_srv_addr = ""
giganto_publish_srv_addr = "10.0.0.1:38371"
last_timestamp_data = "/tmp/ts.dat"
"#;
        let err = config.parse::<Settings>().expect_err("should fail");
        let err_str = error_chain_string(&err);

        assert!(
            err_str.contains("invalid address"),
            "error should mention 'invalid address': {err_str}"
        );
    }

    #[test]
    fn deserialize_socket_addr_whitespace_only() {
        // Whitespace-only address should be rejected.
        let config = r#"
giganto_ingest_srv_addr = "   "
giganto_publish_srv_addr = "10.0.0.1:38371"
last_timestamp_data = "/tmp/ts.dat"
"#;
        let err = config.parse::<Settings>().expect_err("should fail");
        let err_str = error_chain_string(&err);

        assert!(
            err_str.contains("invalid address"),
            "error should mention 'invalid address': {err_str}"
        );
    }

    #[test]
    fn deserialize_socket_addr_hostname_without_port() {
        // Hostname without port should be rejected (not supported by SocketAddr).
        let config = r#"
giganto_ingest_srv_addr = "localhost"
giganto_publish_srv_addr = "10.0.0.1:38371"
last_timestamp_data = "/tmp/ts.dat"
"#;
        let err = config.parse::<Settings>().expect_err("should fail");
        let err_str = error_chain_string(&err);

        assert!(
            err_str.contains("invalid address"),
            "error should mention 'invalid address': {err_str}"
        );
        assert!(
            err_str.contains("localhost"),
            "error should include the invalid address value: {err_str}"
        );
    }

    #[test]
    fn from_file_missing_path_error() {
        // Test that from_file returns a user-friendly error for non-existent paths.
        let non_existent_path = "/non/existent/path/to/config.toml";
        let err = Settings::from_file(non_existent_path).expect_err("should fail");
        let err_str = err.to_string();

        // The error should indicate that the file was not found and include the path.
        // The config crate wraps the underlying IO error.
        assert!(
            err_str.contains(non_existent_path) || err_str.contains("not found"),
            "error should mention the missing file or 'not found': {err_str}"
        );
    }

    #[test]
    fn from_str_invalid_toml_syntax() {
        // Test that invalid TOML syntax produces a clear error.
        let invalid_toml = r"
this is not valid toml
last_timestamp_data =
";
        let err = invalid_toml.parse::<Settings>().expect_err("should fail");
        let err_str = err.to_string();

        // The error should indicate a parsing problem.
        assert!(
            err_str.contains("Failed to parse")
                || err_str.contains("expected")
                || err_str.contains("TOML"),
            "error should indicate parsing failure: {err_str}"
        );
    }

    #[test]
    fn from_str_missing_required_field() {
        // Test that missing required field produces a clear error.
        // last_timestamp_data has no default, so it's required.
        let missing_required = r#"
giganto_name = "test"
giganto_ingest_srv_addr = "10.0.0.1:38370"
giganto_publish_srv_addr = "10.0.0.1:38371"
"#;
        let err = missing_required
            .parse::<Settings>()
            .expect_err("should fail");
        let err_str = error_chain_string(&err);

        // The error should mention the missing field.
        assert!(
            err_str.contains("last_timestamp_data") || err_str.contains("missing"),
            "error should mention missing field: {err_str}"
        );
    }

    #[test]
    fn resolve_giganto_name_with_name() {
        let config = r#"
giganto_name = "my-giganto"
giganto_ingest_srv_addr = "10.0.0.5:38370"
giganto_publish_srv_addr = "10.0.0.5:38371"
last_timestamp_data = "/tmp/ts.dat"
"#;
        let settings: Settings = config.parse().expect("valid config");
        assert_eq!(
            settings.resolve_giganto_name().expect("should resolve"),
            "my-giganto"
        );
    }

    #[test]
    fn resolve_giganto_name_same_ip() {
        // When giganto_name is absent and both addresses share the same IP,
        // the IP is used as the name.
        let config = r#"
giganto_ingest_srv_addr = "10.0.0.5:38370"
giganto_publish_srv_addr = "10.0.0.5:38371"
last_timestamp_data = "/tmp/ts.dat"
"#;
        let settings: Settings = config.parse().expect("valid config");
        assert_eq!(
            settings.resolve_giganto_name().expect("should resolve"),
            "10.0.0.5"
        );
    }

    #[test]
    fn resolve_giganto_name_preferred_over_addr() {
        let config = r#"
giganto_name = "preferred-name"
giganto_ingest_srv_addr = "10.0.0.1:38370"
giganto_publish_srv_addr = "10.0.0.5:38371"
last_timestamp_data = "/tmp/ts.dat"
"#;
        let settings: Settings = config.parse().expect("valid config");
        assert_eq!(
            settings.resolve_giganto_name().expect("should resolve"),
            "preferred-name"
        );
    }

    #[test]
    fn resolve_giganto_name_different_ips_error() {
        // When giganto_name is absent and IPs differ, an error is returned.
        let config = r#"
giganto_ingest_srv_addr = "10.0.0.1:38370"
giganto_publish_srv_addr = "10.0.0.5:38371"
last_timestamp_data = "/tmp/ts.dat"
"#;
        let settings: Settings = config.parse().expect("valid config");
        let err = settings
            .resolve_giganto_name()
            .expect_err("should fail with different IPs");
        let err_str = err.to_string();
        assert!(
            err_str.contains("giganto_name is required"),
            "error should mention giganto_name is required: {err_str}"
        );
    }

    #[test]
    fn missing_giganto_publish_srv_addr_returns_error() {
        let config = r#"
giganto_ingest_srv_addr = "10.0.0.1:38370"
last_timestamp_data = "/tmp/ts.dat"
"#;
        let err = config.parse::<Settings>().expect_err("should fail");
        let err_str = error_chain_string(&err);
        assert!(
            err_str.contains("giganto_publish_srv_addr") || err_str.contains("missing"),
            "error should mention giganto_publish_srv_addr: {err_str}"
        );
    }

    #[test]
    fn missing_giganto_ingest_srv_addr_returns_error() {
        let config = r#"
giganto_publish_srv_addr = "10.0.0.1:38371"
last_timestamp_data = "/tmp/ts.dat"
"#;
        let err = config.parse::<Settings>().expect_err("should fail");
        let err_str = error_chain_string(&err);
        assert!(
            err_str.contains("giganto_ingest_srv_addr") || err_str.contains("missing"),
            "error should mention giganto_ingest_srv_addr: {err_str}"
        );
    }
}
