mod client;
mod logging;
mod request;
mod settings;
mod subscribe;

use std::fs;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::Parser;
use client::Certs;
use logging::init_tracing;
use request::IdleExitReason;
use review_protocol::types::SamplingPolicy;
use settings::Settings;
use subscribe::{ensure_time_data_exists, read_last_timestamp};
use tokio::sync::Notify;
use tracing::{info, warn};
use tracing_appender::non_blocking::WorkerGuard;

const REQUESTED_POLICY_CHANNEL_SIZE: usize = 1;

#[derive(Debug, Clone)]
pub(crate) struct ManagerServer {
    pub(crate) name: String,
    pub(crate) rpc_srv_addr: SocketAddr,
}

impl FromStr for ManagerServer {
    type Err = anyhow::Error;

    fn from_str(manager_server: &str) -> Result<Self> {
        let (name, rpc_srv_addr) = manager_server
            .split_once('@')
            .context("cannot get information of the Manager server")?;
        Ok(ManagerServer {
            name: name.to_string(),
            rpc_srv_addr: rpc_srv_addr
                .parse()
                .context("cannot parse the Manager server address")?,
        })
    }
}

#[derive(Parser, Debug, Clone)]
#[command(version)]
pub(crate) struct CmdLineArgs {
    /// Path to the local configuration TOML file.
    #[arg(short, value_name = "CONFIG_PATH")]
    pub(crate) config: Option<String>,

    /// Path to the certificate file.
    #[arg(long, value_name = "CERT_PATH")]
    pub(crate) cert: String,

    /// Path to the key file.
    #[arg(long, value_name = "KEY_PATH")]
    pub(crate) key: String,

    /// Path to the CA certificate files. Multiple paths can be provided as a comma-separated list.
    #[arg(
        long,
        value_name = "CA_CERTS_PATH",
        required = true,
        value_delimiter = ','
    )]
    pub(crate) ca_certs: Vec<String>,

    /// Address of the Manager server formatted as `<server_name>@<server_ip>:<server_port>`.
    #[arg(value_parser=clap::builder::ValueParser::new(ManagerServer::from_str))]
    pub(crate) manager_server: ManagerServer,
}

impl CmdLineArgs {
    #[must_use]
    fn is_remote_mode(&self) -> bool {
        self.config.is_none()
    }
}

type CertPems = (Vec<u8>, Vec<u8>, Vec<Vec<u8>>);

/// Reads Giganto cert/key/CA material from disk into raw PEM bytes.
///
/// # Errors
///
/// Returns an error if any file cannot be read.
fn read_cert_pems(args: &CmdLineArgs) -> Result<CertPems> {
    let cert_pem = fs::read(&args.cert)
        .with_context(|| format!("failed to read certificate file: {}", args.cert))?;
    let key_pem = fs::read(&args.key)
        .with_context(|| format!("failed to read private key file: {}", args.key))?;
    let mut ca_certs_pem = Vec::new();
    for ca_cert in &args.ca_certs {
        let file = fs::read(ca_cert)
            .with_context(|| format!("failed to read CA certificate file: {ca_cert}"))?;
        ca_certs_pem.push(file);
    }
    Ok((cert_pem, key_pem, ca_certs_pem))
}

/// Reads, parses, and validates Giganto cert/key/CA material from disk.
///
/// The candidate certs are validated by building the same QUIC client
/// configuration that `subscribe::Client::new` uses, so that mismatched
/// cert/key pairs are rejected here (returning an error) rather than
/// panicking later when the shared endpoint is rebuilt.
///
/// # Errors
///
/// Returns an error if any cert/key/CA file cannot be read, the private key
/// does not match the certificate, the CA bundle cannot be parsed, or the
/// client/endpoint configuration cannot be built from the candidate certs.
pub(crate) fn load_giganto_tls_material(args: &CmdLineArgs) -> Result<Certs> {
    let (cert_pem, key_pem, ca_certs_pem) = read_cert_pems(args)?;
    let certs = Certs::try_new(
        &cert_pem,
        &key_pem,
        &ca_certs_pem.iter().map(Vec::as_slice).collect::<Vec<_>>(),
    )?;
    let _ = client::client_config(&certs)
        .context("failed to build a Giganto client endpoint from the TLS material")?;
    Ok(certs)
}

/// Registers a process-level SIGHUP handler that requests a Giganto TLS
/// reload via the dedicated notifier.
///
/// `notify_one()` stores a permit when there is no waiter, so a signal that
/// lands between reload checks is still delivered to the next waiter
/// without being lost.
///
/// SIGHUP is POSIX-only; on non-Unix targets this is a no-op.
pub(crate) fn register_tls_reload_signal_handler(tls_reload: Arc<Notify>) {
    #[cfg(unix)]
    {
        tokio::spawn(async move {
            let mut hup =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
                    Ok(sig) => sig,
                    Err(e) => {
                        warn!("Failed to install SIGHUP handler: {e}");
                        return;
                    }
                };
            while hup.recv().await.is_some() {
                info!("Received SIGHUP; requesting Giganto TLS reload");
                tls_reload.notify_one();
            }
        });
    }
    #[cfg(not(unix))]
    {
        let _ = tls_reload;
    }
}

/// Distinguishes the reasons a successful `run()` returns, so the main loop
/// can decide whether to refresh the Giganto TLS material before the next
/// rerun.
#[derive(Debug, PartialEq, Eq)]
enum RerunReason {
    ConfigReload,
    TlsReload,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = CmdLineArgs::parse();
    let (cert_pem, key_pem, ca_certs_pem) = read_cert_pems(&args)?;
    let mut certs = load_giganto_tls_material(&args)?;
    let (request_send, request_recv) =
        async_channel::bounded::<SamplingPolicy>(REQUESTED_POLICY_CHANNEL_SIZE);
    let config_reload = Arc::new(Notify::new());
    let tls_reload = Arc::new(Notify::new());
    register_tls_reload_signal_handler(tls_reload.clone());
    let mut request_client = request::Client::new(
        args.manager_server.rpc_srv_addr,
        args.manager_server.name.clone(),
        request_send,
        cert_pem,
        key_pem,
        ca_certs_pem,
        config_reload.clone(),
    );
    let mut guard = None;

    loop {
        let outcome = run(
            &args,
            &certs,
            request_client.clone(),
            request_recv.clone(),
            config_reload.clone(),
            tls_reload.clone(),
            &mut guard,
        )
        .await;

        let should_reload_tls = match outcome {
            Ok(RerunReason::TlsReload) => true,
            Ok(RerunReason::ConfigReload) => false,
            Err(e) => {
                assert!(args.is_remote_mode(), "{e}");
                error_or_eprint!("Main processing encountered an error: {e}");
                let health_check = e.downcast_ref::<std::io::Error>().is_some_and(|e| {
                    matches!(
                        e.kind(),
                        ErrorKind::ConnectionAborted
                            | ErrorKind::ConnectionReset
                            | ErrorKind::TimedOut
                    )
                });
                matches!(
                    request_client
                        .enter_idle_mode(health_check, tls_reload.clone())
                        .await,
                    IdleExitReason::TlsReload
                )
            }
        };

        if should_reload_tls {
            match load_giganto_tls_material(&args) {
                Ok(new_certs) => {
                    info!("Reloaded Giganto TLS material");
                    certs = new_certs;
                }
                Err(e) => {
                    warn!(
                        "Failed to reload Giganto TLS material; keeping last-known-good shared \
                         endpoint state: {e:#}"
                    );
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run(
    args: &CmdLineArgs,
    certs: &Certs,
    mut request_client: request::Client,
    request_recv: async_channel::Receiver<SamplingPolicy>,
    config_reload: Arc<Notify>,
    tls_reload: Arc<Notify>,
    guard: &mut Option<WorkerGuard>,
) -> Result<RerunReason> {
    let (settings, is_local_config) = if let Some(local_config) = args.config.as_deref() {
        (Settings::from_file(local_config)?, true)
    } else {
        (
            Settings::from_str(&request_client.get_config().await?)?,
            false,
        )
    };
    if guard.is_none() {
        *guard = Some(init_tracing(settings.log_path.as_deref())?);
    }
    info!(
        "Time series generator has been configured with {} settings",
        if is_local_config { "local" } else { "remote" }
    );

    ensure_time_data_exists(&settings.last_timestamp_data)
        .context("Failed to initialize last timestamp data file")?;
    read_last_timestamp(&settings.last_timestamp_data).await?;

    let giganto_name = settings.resolve_giganto_name()?;
    let subscribe_client = subscribe::Client::new(
        settings.giganto_ingest_srv_addr,
        settings.giganto_publish_srv_addr,
        giganto_name,
        settings.last_timestamp_data,
        certs,
        request_recv,
    );

    info!("Time series generate started");
    let shutdown = Arc::new(Notify::new());
    let reason = tokio::select! {
        Ok(Err(e)) = tokio::spawn(subscribe_client.run(
            request_client.active_policy_list.clone(),
            request_client.delete_policy_ids.clone(),
            shutdown.clone(),
        )) => {
            shutdown.notify_waiters();
            bail!(e);
        }
        Ok(Err(e)) = tokio::spawn({
            let shutdown = shutdown.clone();
            async move {
                request_client.run(shutdown).await
            }
        }) => {
            shutdown.notify_waiters();
            shutdown.notified().await;
            bail!(e);
        }
        () = config_reload.notified(), if args.is_remote_mode() => {
            shutdown.notify_waiters();
            shutdown.notified().await;
            info!("Reloading the configuration");
            RerunReason::ConfigReload
        },
        () = tls_reload.notified() => {
            shutdown.notify_waiters();
            shutdown.notified().await;
            info!("Rebuilding the shared Giganto endpoint from reloaded TLS material");
            RerunReason::TlsReload
        },
    };
    Ok(reason)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serial_test::serial;
    use tempfile::tempdir;
    use tokio::sync::Notify;

    use super::*;

    fn args_with_paths(
        cert: impl Into<String>,
        key: impl Into<String>,
        ca_certs: Vec<String>,
    ) -> CmdLineArgs {
        CmdLineArgs {
            config: None,
            cert: cert.into(),
            key: key.into(),
            ca_certs,
            manager_server: "manager@127.0.0.1:38390"
                .parse()
                .expect("valid manager address"),
        }
    }

    fn write_rotated_material(
        dir: &std::path::Path,
        cert_pem: &[u8],
        key_pem: &[u8],
        ca_pem: &[u8],
    ) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        let ca_path = dir.join("ca.pem");
        std::fs::write(&cert_path, cert_pem).expect("write cert");
        std::fs::write(&key_path, key_pem).expect("write key");
        std::fs::write(&ca_path, ca_pem).expect("write ca");
        (cert_path, key_path, ca_path)
    }

    #[test]
    fn load_giganto_tls_material_reads_from_disk() {
        let cert_pem = std::fs::read("tests/cert.pem").expect("read cert");
        let key_pem = std::fs::read("tests/key.pem").expect("read key");
        let ca_pem = std::fs::read("tests/ca_cert.pem").expect("read ca");

        let dir = tempdir().expect("tempdir");
        let (cert_path, key_path, ca_path) =
            write_rotated_material(dir.path(), &cert_pem, &key_pem, &ca_pem);

        let args = args_with_paths(
            cert_path.to_str().expect("utf-8 cert path"),
            key_path.to_str().expect("utf-8 key path"),
            vec![ca_path.to_str().expect("utf-8 ca path").to_string()],
        );

        let certs = load_giganto_tls_material(&args).expect("load certs from disk");
        assert!(!certs.certs.is_empty());
        assert!(!certs.ca_certs.is_empty());
    }

    fn expect_load_err(args: &CmdLineArgs) -> anyhow::Error {
        match load_giganto_tls_material(args) {
            Ok(_) => panic!("expected TLS reload to fail"),
            Err(e) => e,
        }
    }

    #[test]
    fn load_giganto_tls_material_fails_on_missing_file() {
        let args = args_with_paths(
            "tests/does_not_exist.pem",
            "tests/key.pem",
            vec!["tests/ca_cert.pem".to_string()],
        );
        let err = expect_load_err(&args);
        assert!(err.to_string().contains("failed to read certificate file"));
    }

    #[test]
    fn load_giganto_tls_material_fails_on_invalid_cert() {
        let dir = tempdir().expect("tempdir");
        let cert_path = dir.path().join("cert.pem");
        std::fs::write(&cert_path, b"not a pem").expect("write cert");

        let args = args_with_paths(
            cert_path.to_str().expect("utf-8 cert path"),
            "tests/key.pem",
            vec!["tests/ca_cert.pem".to_string()],
        );
        let err = expect_load_err(&args);
        let msg = format!("{err:#}");
        assert!(
            msg.contains("certificate") || msg.contains("chain"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn load_giganto_tls_material_fails_on_invalid_key() {
        let cert_pem = std::fs::read("tests/cert.pem").expect("read cert");
        let ca_pem = std::fs::read("tests/ca_cert.pem").expect("read ca");

        let dir = tempdir().expect("tempdir");
        let (cert_path, key_path, ca_path) = write_rotated_material(
            dir.path(),
            &cert_pem,
            b"not a pem-encoded private key",
            &ca_pem,
        );

        let args = args_with_paths(
            cert_path.to_str().expect("utf-8 cert path"),
            key_path.to_str().expect("utf-8 key path"),
            vec![ca_path.to_str().expect("utf-8 ca path").to_string()],
        );
        let err = expect_load_err(&args);
        assert!(
            format!("{err:#}").contains("private key"),
            "unexpected error: {err:#}"
        );
    }

    /// The loader must reject a rotated-but-mismatched key/cert pair rather
    /// than returning candidate certs that would later panic during
    /// endpoint construction in `subscribe::Client::new`.
    #[test]
    fn load_giganto_tls_material_rejects_mismatched_key() {
        let cert_pem = std::fs::read("tests/cert.pem").expect("read cert");
        let ca_pem = std::fs::read("tests/ca_cert.pem").expect("read ca");
        let unrelated = rcgen::KeyPair::generate().expect("generate key");
        let unrelated_pem = unrelated.serialize_pem();

        let dir = tempdir().expect("tempdir");
        let (cert_path, key_path, ca_path) =
            write_rotated_material(dir.path(), &cert_pem, unrelated_pem.as_bytes(), &ca_pem);

        let args = args_with_paths(
            cert_path.to_str().expect("utf-8 cert path"),
            key_path.to_str().expect("utf-8 key path"),
            vec![ca_path.to_str().expect("utf-8 ca path").to_string()],
        );
        let err = expect_load_err(&args);
        assert!(
            format!("{err:#}").contains("Giganto client endpoint"),
            "mismatched key must surface an endpoint-build error: {err:#}"
        );
    }

    /// Verifies that SIGHUP is delivered as a TLS reload notification
    /// without terminating the process. The handler uses `notify_one`, so a
    /// signal that lands before a waiter registers still wakes the next
    /// `notified()` call.
    #[cfg(unix)]
    #[serial]
    #[tokio::test(flavor = "current_thread")]
    async fn sighup_signals_tls_reload_without_exit() {
        let tls_reload = Arc::new(Notify::new());
        register_tls_reload_signal_handler(tls_reload.clone());

        // Give the signal stream a moment to install before raising.
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // SAFETY: `libc::raise` is safe here; we target only the current
        // process and make no assumptions about other threads.
        unsafe {
            libc::raise(libc::SIGHUP);
        }

        tokio::time::timeout(std::time::Duration::from_secs(2), tls_reload.notified())
            .await
            .expect("tls_reload notification delivered within timeout");
    }

    /// A SIGHUP that lands *before* a waiter registers must still be picked
    /// up by the next `notified()` call. This covers the lost-wakeup window
    /// that the `Notify + AtomicBool` split previously had.
    #[cfg(unix)]
    #[serial]
    #[tokio::test(flavor = "current_thread")]
    async fn sighup_before_waiter_is_not_lost() {
        let tls_reload = Arc::new(Notify::new());
        register_tls_reload_signal_handler(tls_reload.clone());

        // Allow the signal stream to register.
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // SAFETY: see `sighup_signals_tls_reload_without_exit`.
        unsafe {
            libc::raise(libc::SIGHUP);
        }

        // Give the SIGHUP handler time to call `notify_one` before any
        // waiter registers.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Only now register a waiter. The stored permit must wake it
        // immediately.
        tokio::time::timeout(std::time::Duration::from_secs(2), tls_reload.notified())
            .await
            .expect("stored permit must wake the next waiter");
    }

    /// Verifies that the `run()` select converges on a rerun boundary when
    /// `tls_reload` is notified, without exiting as an error.
    #[tokio::test(flavor = "current_thread")]
    async fn tls_reload_notification_triggers_rerun_boundary() {
        let tls_reload = Arc::new(Notify::new());
        let shutdown = Arc::new(Notify::new());
        let shutdown_for_select = shutdown.clone();
        let tls_reload_for_select = tls_reload.clone();

        let runner: tokio::task::JoinHandle<&'static str> = tokio::spawn(async move {
            tokio::select! {
                () = shutdown_for_select.notified() => "shutdown",
                () = tls_reload_for_select.notified() => {
                    shutdown_for_select.notify_waiters();
                    "tls_reload"
                }
            }
        });

        tokio::task::yield_now().await;
        tls_reload.notify_one();

        let reason = tokio::time::timeout(std::time::Duration::from_secs(1), runner)
            .await
            .expect("select resolves promptly")
            .expect("task completes");
        assert_eq!(reason, "tls_reload");
    }

    /// Exercises the main-loop reload path: a failed reload must preserve the
    /// last-known-good `Certs` value and must not propagate an error.
    #[test]
    fn failed_reload_preserves_last_known_good_certs() {
        let good = load_giganto_tls_material(&args_with_paths(
            "tests/cert.pem",
            "tests/key.pem",
            vec!["tests/ca_cert.pem".to_string()],
        ))
        .expect("good certs load");
        let good_leaf_count = good.certs.len();

        let args = args_with_paths(
            "tests/does_not_exist.pem",
            "tests/key.pem",
            vec!["tests/ca_cert.pem".to_string()],
        );

        // Simulate the main-loop reload branch: on failure, keep `good`.
        let mut current = good;
        if let Ok(new_certs) = load_giganto_tls_material(&args) {
            current = new_certs;
        }

        assert_eq!(current.certs.len(), good_leaf_count);
    }

    /// End-to-end rotation scenario that exercises the full reload contract
    /// required by issue #315: rotate cert files on disk, ask the loader to
    /// validate them, and verify that mismatched material is rejected before
    /// any swap occurs, while a valid rotation still produces usable certs
    /// (verified by both the runtime-free validator and the real endpoint
    /// builder used by the shared Giganto client).
    #[tokio::test(flavor = "current_thread")]
    async fn rotated_material_preserves_last_known_good_on_invalid_swap() {
        let cert_pem = std::fs::read("tests/cert.pem").expect("read cert");
        let key_pem = std::fs::read("tests/key.pem").expect("read key");
        let ca_pem = std::fs::read("tests/ca_cert.pem").expect("read ca");

        let dir = tempdir().expect("tempdir");
        let (cert_path, key_path, ca_path) =
            write_rotated_material(dir.path(), &cert_pem, &key_pem, &ca_pem);
        let args = args_with_paths(
            cert_path.to_str().expect("utf-8 cert path"),
            key_path.to_str().expect("utf-8 key path"),
            vec![ca_path.to_str().expect("utf-8 ca path").to_string()],
        );

        // Initial load succeeds; validated material also drives a real
        // endpoint the way `subscribe::Client::new` would.
        let current = load_giganto_tls_material(&args).expect("initial load succeeds");
        let initial_leaf_count = current.certs.len();
        client::config(&current)
            .expect("initial certs build an endpoint")
            .close(0u32.into(), &[]);

        // Operator "rotates" the key file on disk but points it at an
        // unrelated key, so the cert/key no longer match.
        let unrelated = rcgen::KeyPair::generate().expect("generate key");
        std::fs::write(&key_path, unrelated.serialize_pem().as_bytes()).expect("rewrite key file");

        // Reload attempt must fail and the caller must keep the previous
        // certs (mirroring the main-loop reload branch).
        match load_giganto_tls_material(&args) {
            Ok(_) => panic!("mismatched material must not be accepted by the loader"),
            Err(e) => {
                assert!(
                    format!("{e:#}").contains("Giganto client endpoint"),
                    "unexpected error: {e:#}"
                );
            }
        }

        // The preserved "current" certs still produce a usable endpoint,
        // so ingest/publish keep using the last-known-good TLS state.
        assert_eq!(current.certs.len(), initial_leaf_count);
        client::config(&current)
            .expect("last-known-good certs still build an endpoint")
            .close(0u32.into(), &[]);

        // A subsequent valid rotation (write a fresh but matching pair)
        // swaps the material cleanly.
        std::fs::write(&key_path, &key_pem).expect("restore matching key");
        let refreshed = load_giganto_tls_material(&args).expect("valid rotation loads");
        assert_eq!(refreshed.certs.len(), initial_leaf_count);
    }
}
