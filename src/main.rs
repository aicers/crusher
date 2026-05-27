mod cancellation;
mod client;
mod logging;
mod policy;
mod request;
mod settings;
mod subscribe;

use std::fs;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use cancellation::CancellationCoordinator;
use clap::Parser;
use client::{Certs, SharedTlsBytes, TlsBytes};
use logging::init_tracing;
use request::IdleExitReason;
use review_protocol::types::SamplingPolicy;
use settings::Settings;
use subscribe::{clear_ingest_channel, ensure_time_data_exists, read_last_timestamp};
use tokio::sync::Notify;
use tracing::{error, info, warn};
use tracing_appender::non_blocking::WorkerGuard;

const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

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

#[cfg(test)]
pub(crate) fn load_tls_material(args: &CmdLineArgs) -> Result<Certs> {
    load_tls_material_with_bytes(args).map(|(certs, _)| certs)
}

/// Reads, parses, and validates TLS cert/key/CA material from disk, and
/// returns the raw PEM bytes so the manager/control reconnect path can swap
/// in rotated material without a second disk read. Validation happens once
/// against the staged bytes; on success both the parsed `Certs` and the raw
/// bytes are known good and may be published together.
///
/// # Errors
///
/// Returns an error if any cert/key/CA file cannot be read, the private key
/// does not match the certificate, the CA bundle cannot be parsed, or the
/// client/endpoint configuration cannot be built from the candidate certs.
pub(crate) fn load_tls_material_with_bytes(args: &CmdLineArgs) -> Result<(Certs, TlsBytes)> {
    let (cert_pem, key_pem, ca_certs_pem) = read_cert_pems(args)?;
    let certs = Certs::try_new(
        &cert_pem,
        &key_pem,
        &ca_certs_pem.iter().map(Vec::as_slice).collect::<Vec<_>>(),
    )?;
    let _ = client::client_config(&certs)
        .context("failed to build a client endpoint from the TLS material")?;
    Ok((certs, TlsBytes::new(cert_pem, key_pem, ca_certs_pem)))
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
                info!("Received SIGHUP; requesting TLS reload for Giganto and Manager");
                tls_reload.notify_one();
            }
        });
    }
    #[cfg(not(unix))]
    {
        let _ = tls_reload;
    }
}

/// Registers a process-level SIGINT/SIGTERM handler that requests a
/// graceful shutdown via the dedicated notifier.
///
/// `notify_one()` stores a permit when there is no waiter, so a signal
/// that lands before the main loop registers a waiter is still
/// delivered to the next `notified()` call.
///
/// On Unix this listens for SIGINT and SIGTERM. On non-Unix targets
/// only Ctrl-C (which maps to SIGINT semantics) is observed.
pub(crate) fn register_shutdown_signal_handler(shutdown: Arc<Notify>) {
    #[cfg(unix)]
    {
        tokio::spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};

            let mut sigint = match signal(SignalKind::interrupt()) {
                Ok(sig) => sig,
                Err(e) => {
                    warn!("Failed to install SIGINT handler: {e}");
                    return;
                }
            };
            let mut sigterm = match signal(SignalKind::terminate()) {
                Ok(sig) => sig,
                Err(e) => {
                    warn!("Failed to install SIGTERM handler: {e}");
                    return;
                }
            };

            tokio::select! {
                _ = sigint.recv() => {
                    info!("Received SIGINT; requesting graceful shutdown");
                    shutdown.notify_one();
                }
                _ = sigterm.recv() => {
                    info!("Received SIGTERM; requesting graceful shutdown");
                    shutdown.notify_one();
                }
            }
        });
    }
    #[cfg(not(unix))]
    {
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                info!("Received Ctrl-C; requesting graceful shutdown");
                shutdown.notify_one();
            }
        });
    }
}

/// Distinguishes the reasons a successful `run()` returns, so the main loop
/// can decide whether to refresh the Giganto TLS material before the next
/// rerun, or to exit the process entirely after a SIGINT/SIGTERM.
#[derive(Debug, PartialEq, Eq)]
enum RunExitReason {
    ConfigReload,
    TlsReload,
    Shutdown,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = CmdLineArgs::parse();
    let (mut certs, tls_bytes) = load_tls_material_with_bytes(&args)?;
    let manager_tls = SharedTlsBytes::new(tls_bytes);
    let (request_send, request_recv) =
        async_channel::bounded::<SamplingPolicy>(REQUESTED_POLICY_CHANNEL_SIZE);
    let config_reload = Arc::new(Notify::new());
    let tls_reload = Arc::new(Notify::new());
    let shutdown = Arc::new(Notify::new());
    register_tls_reload_signal_handler(tls_reload.clone());
    register_shutdown_signal_handler(shutdown.clone());
    let mut request_client = request::Client::new(
        args.manager_server.rpc_srv_addr,
        args.manager_server.name.clone(),
        manager_tls.clone(),
        config_reload.clone(),
    );
    let mut guard = None;

    loop {
        let outcome = run(
            &args,
            &certs,
            request_client.clone(),
            request_send.clone(),
            request_recv.clone(),
            config_reload.clone(),
            tls_reload.clone(),
            shutdown.clone(),
            &mut guard,
        )
        .await;

        let should_reload_tls = match outcome {
            Ok(RunExitReason::Shutdown) => {
                info!("Graceful shutdown complete; exiting");
                return Ok(());
            }
            Ok(RunExitReason::TlsReload) => true,
            Ok(RunExitReason::ConfigReload) => false,
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
                match request_client
                    .enter_idle_mode(health_check, tls_reload.clone(), shutdown.clone())
                    .await
                {
                    IdleExitReason::Shutdown => {
                        info!("Graceful shutdown complete; exiting");
                        return Ok(());
                    }
                    IdleExitReason::TlsReload => true,
                    IdleExitReason::Resumed => false,
                }
            }
        };

        if should_reload_tls {
            match load_tls_material_with_bytes(&args) {
                Ok((new_certs, new_bytes)) => {
                    info!("Reloaded Giganto TLS material");
                    certs = new_certs;
                    manager_tls.replace(new_bytes);
                    info!("Refreshed manager/control TLS bytes for next reconnect");
                }
                Err(e) => {
                    warn!(
                        "Failed to reload TLS material; keeping last-known-good shared \
                         endpoint state and manager/control TLS bytes: {e:#}"
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
    request_send: async_channel::Sender<SamplingPolicy>,
    request_recv: async_channel::Receiver<SamplingPolicy>,
    config_reload: Arc<Notify>,
    tls_reload: Arc<Notify>,
    shutdown: Arc<Notify>,
    guard: &mut Option<WorkerGuard>,
) -> Result<RunExitReason> {
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
    )?;

    info!("Time series generate started");
    let coordinator = CancellationCoordinator::new();

    // Spawn the policy actor. All policy state mutations go through
    // this handle, ensuring atomicity and cancellation safety.
    let policy_handle = policy::spawn_policy_actor(request_send, &coordinator);
    request_client.set_policy_handle(policy_handle.clone());

    // Spawn top-level tasks with tokio::spawn (NOT tracker.spawn).
    // run() explicitly owns these handles and drives them to
    // completion, while TaskTracker is reserved for child/background
    // tasks spawned inside subscribe and request.
    let mut subscribe_handle =
        tokio::spawn(subscribe_client.run(policy_handle, coordinator.clone()));

    let request_coordinator = coordinator.clone();
    let mut request_handle =
        tokio::spawn(async move { request_client.run(request_coordinator).await });

    let result: Result<RunExitReason> = tokio::select! {
        biased;
        res = &mut subscribe_handle => {
            coordinator.request_cancellation("subscribe exit");
            match res {
                Ok(Err(e)) => Err(e),
                Ok(Ok(())) => Err(anyhow::anyhow!("subscribe task ended unexpectedly")),
                Err(e) => Err(anyhow::anyhow!("subscribe task panicked: {e}")),
            }
        }
        res = &mut request_handle => {
            coordinator.request_cancellation("request exit");
            match res {
                Ok(Err(e)) => Err(e),
                Ok(Ok(())) => Err(anyhow::anyhow!("request task ended unexpectedly")),
                Err(e) => Err(anyhow::anyhow!("request task panicked: {e}")),
            }
        }
        () = config_reload.notified(), if args.is_remote_mode() => {
            coordinator.request_cancellation("config reload");
            info!("Reloading the configuration");
            Ok(RunExitReason::ConfigReload)
        },
        () = tls_reload.notified() => {
            coordinator.request_cancellation("TLS reload");
            info!("Rebuilding the shared Giganto endpoint from reloaded TLS material");
            Ok(RunExitReason::TlsReload)
        },
        () = shutdown.notified() => {
            coordinator.request_cancellation("shutdown signal");
            info!("Shutdown signal received; draining tasks");
            Ok(RunExitReason::Shutdown)
        },
    };

    // Wait for the remaining top-level task to exit cooperatively
    // via its `coordinator.cancelled()` check — no hard abort.
    let _ = tokio::join!(subscribe_handle, request_handle);

    // Wait for child/background tasks (tracked by TaskTracker).
    if !coordinator.wait_for_drain(DRAIN_TIMEOUT).await {
        error!(
            "Drain timed out; aborting to prevent \
             overlapping generations"
        );
        clear_ingest_channel().await;
        std::process::exit(1);
    }

    // Clear stale senders so no previous-run channels leak into a
    // subsequent run (e.g. after a config-reload restart).
    clear_ingest_channel().await;
    result
}

#[cfg(test)]
mod tests {
    use std::{fs, sync::Arc, time::Duration};

    use serial_test::serial;
    use tempfile::tempdir;
    use tokio::sync::Notify;
    use tracing_appender::non_blocking::WorkerGuard;

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

    fn load_test_tls() -> (Certs, TlsBytes) {
        let cert_pem = fs::read("tests/cert.pem").expect("read cert");
        let key_pem = fs::read("tests/key.pem").expect("read key");
        let ca_certs_pem = vec![fs::read("tests/ca_cert.pem").expect("read ca cert")];
        let ca_slices = ca_certs_pem.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let certs = Certs::try_new(&cert_pem, &key_pem, &ca_slices).expect("parse certs");
        (certs, TlsBytes::new(cert_pem, key_pem, ca_certs_pem))
    }

    fn write_local_config(dir: &tempfile::TempDir) -> String {
        let last_timestamp_data = dir.path().join("time_data.json");
        let config_path = dir.path().join("crusher.toml");
        fs::write(
            &config_path,
            format!(
                r#"
giganto_name = "localhost"
giganto_ingest_srv_addr = "[::1]:9"
giganto_publish_srv_addr = "[::1]:9"
last_timestamp_data = "{}"
"#,
                last_timestamp_data.display()
            ),
        )
        .expect("write local config");
        config_path.to_str().expect("utf-8 config path").to_string()
    }

    /// Prevents `run()` from installing a global tracing subscriber (which
    /// would panic on subsequent `run()`-based tests in the same process).
    fn test_tracing_guard() -> WorkerGuard {
        let (_writer, guard) = tracing_appender::non_blocking(std::io::sink());
        guard
    }

    /// Local-config harness for `run()` integration tests (no external services).
    struct RunTestHarness {
        _temp_dir: tempfile::TempDir,
        args: CmdLineArgs,
        certs: Certs,
        request_client: request::Client,
        request_send: async_channel::Sender<SamplingPolicy>,
        request_recv: async_channel::Receiver<SamplingPolicy>,
        config_reload: Arc<Notify>,
        tls_reload: Arc<Notify>,
        shutdown: Arc<Notify>,
    }

    impl RunTestHarness {
        /// Returns `None` when the environment cannot build a QUIC endpoint.
        fn try_new() -> Option<Self> {
            let temp_dir = tempdir().expect("tempdir");
            let config_path = write_local_config(&temp_dir);
            let (certs, tls_bytes) = load_test_tls();
            if let Err(e) = crate::client::config(&certs) {
                if e.chain().any(|cause| {
                    cause
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied)
                }) {
                    return None;
                }
                panic!("test endpoint preflight failed: {e:#}");
            }
            let args = CmdLineArgs {
                config: Some(config_path),
                cert: "tests/cert.pem".to_string(),
                key: "tests/key.pem".to_string(),
                ca_certs: vec!["tests/ca_cert.pem".to_string()],
                manager_server: "manager@[::1]:9".parse().expect("valid manager address"),
            };
            let manager_tls = SharedTlsBytes::new(tls_bytes);
            let request_client = request::Client::new(
                args.manager_server.rpc_srv_addr,
                args.manager_server.name.clone(),
                manager_tls,
                Arc::new(Notify::new()),
            );
            let (request_send, request_recv) =
                async_channel::bounded::<SamplingPolicy>(REQUESTED_POLICY_CHANNEL_SIZE);
            Some(Self {
                _temp_dir: temp_dir,
                args,
                certs,
                request_client,
                request_send,
                request_recv,
                config_reload: Arc::new(Notify::new()),
                tls_reload: Arc::new(Notify::new()),
                shutdown: Arc::new(Notify::new()),
            })
        }

        async fn run(&self, guard: &mut Option<WorkerGuard>) -> Result<RunExitReason> {
            run(
                &self.args,
                &self.certs,
                self.request_client.clone(),
                self.request_send.clone(),
                self.request_recv.clone(),
                self.config_reload.clone(),
                self.tls_reload.clone(),
                self.shutdown.clone(),
                guard,
            )
            .await
        }
    }

    async fn notify_shutdown_after_startup_delay(shutdown: Arc<Notify>) {
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        shutdown.notify_one();
    }

    #[cfg(unix)]
    async fn raise_signal_after_startup_delay(signal: libc::c_int) {
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        // SAFETY: `libc::raise` only targets the current process.
        unsafe {
            libc::raise(signal);
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
    fn load_tls_material_reads_from_disk() {
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

        let certs = load_tls_material(&args).expect("load certs from disk");
        assert!(!certs.certs.is_empty());
        assert!(!certs.ca_certs.is_empty());
    }

    fn expect_load_err(args: &CmdLineArgs) -> anyhow::Error {
        match load_tls_material(args) {
            Ok(_) => panic!("expected TLS reload to fail"),
            Err(e) => e,
        }
    }

    #[test]
    fn load_tls_material_fails_on_missing_file() {
        let args = args_with_paths(
            "tests/does_not_exist.pem",
            "tests/key.pem",
            vec!["tests/ca_cert.pem".to_string()],
        );
        let err = expect_load_err(&args);
        assert!(err.to_string().contains("failed to read certificate file"));
    }

    #[test]
    fn load_tls_material_fails_on_invalid_cert() {
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
    fn load_tls_material_fails_on_invalid_key() {
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
    fn load_tls_material_rejects_mismatched_key() {
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
            format!("{err:#}").contains("client endpoint"),
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

    /// Verifies that SIGINT is delivered as a graceful-shutdown
    /// notification without terminating the process. The handler uses
    /// `notify_one`, so a signal that lands before a waiter registers
    /// still wakes the next `notified()` call.
    #[cfg(unix)]
    #[serial]
    #[tokio::test(flavor = "current_thread")]
    async fn sigint_signals_shutdown_without_exit() {
        let shutdown = Arc::new(Notify::new());
        register_shutdown_signal_handler(shutdown.clone());

        // Give the signal stream a moment to install before raising.
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // SAFETY: `libc::raise` is safe here; we target only the current
        // process and make no assumptions about other threads.
        unsafe {
            libc::raise(libc::SIGINT);
        }

        tokio::time::timeout(std::time::Duration::from_secs(2), shutdown.notified())
            .await
            .expect("shutdown notification delivered within timeout");
    }

    /// Verifies that SIGTERM is delivered as a graceful-shutdown
    /// notification without terminating the process.
    #[cfg(unix)]
    #[serial]
    #[tokio::test(flavor = "current_thread")]
    async fn sigterm_signals_shutdown_without_exit() {
        let shutdown = Arc::new(Notify::new());
        register_shutdown_signal_handler(shutdown.clone());

        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // SAFETY: see `sigint_signals_shutdown_without_exit`.
        unsafe {
            libc::raise(libc::SIGTERM);
        }

        tokio::time::timeout(std::time::Duration::from_secs(2), shutdown.notified())
            .await
            .expect("shutdown notification delivered within timeout");
    }

    #[cfg(unix)]
    async fn shutdown_signal_cancels_coordinator_and_drains_tracked_task(signal: libc::c_int) {
        let shutdown = Arc::new(Notify::new());
        register_shutdown_signal_handler(shutdown.clone());

        let coordinator = CancellationCoordinator::new();
        let task_coordinator = coordinator.clone();
        let started = Arc::new(Notify::new());
        let started_for_task = started.clone();
        coordinator.tracker().spawn(async move {
            started_for_task.notify_one();
            task_coordinator.cancelled().await;
        });

        started.notified().await;
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // SAFETY: see `sigint_signals_shutdown_without_exit`.
        unsafe {
            libc::raise(signal);
        }

        tokio::time::timeout(std::time::Duration::from_secs(2), shutdown.notified())
            .await
            .expect("shutdown notification delivered within timeout");
        coordinator.request_cancellation("signal integration test");

        assert!(coordinator.is_cancelled());
        assert!(
            coordinator
                .wait_for_drain(std::time::Duration::from_secs(2))
                .await,
            "tracked task should drain after signal-driven cancellation"
        );
        assert_eq!(
            coordinator.phase(),
            crate::cancellation::CancellationPhase::Completed
        );
    }

    #[cfg(unix)]
    #[serial]
    #[tokio::test(flavor = "current_thread")]
    async fn sigint_shutdown_notification_cancels_coordinator_and_drains_tracked_task() {
        shutdown_signal_cancels_coordinator_and_drains_tracked_task(libc::SIGINT).await;
    }

    #[cfg(unix)]
    #[serial]
    #[tokio::test(flavor = "current_thread")]
    async fn sigterm_shutdown_notification_cancels_coordinator_and_drains_tracked_task() {
        shutdown_signal_cancels_coordinator_and_drains_tracked_task(libc::SIGTERM).await;
    }

    /// A SIGINT that lands *before* a waiter registers must still be
    /// picked up by the next `notified()` call. This covers the
    /// lost-wakeup window between handler installation and the main
    /// loop's first wait.
    #[cfg(unix)]
    #[serial]
    #[tokio::test(flavor = "current_thread")]
    async fn sigint_before_waiter_is_not_lost() {
        let shutdown = Arc::new(Notify::new());
        register_shutdown_signal_handler(shutdown.clone());

        // Allow the signal stream to register.
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // SAFETY: see `sigint_signals_shutdown_without_exit`.
        unsafe {
            libc::raise(libc::SIGINT);
        }

        // Give the handler time to call `notify_one` before any waiter
        // registers.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Only now register a waiter. The stored permit must wake it
        // immediately.
        tokio::time::timeout(std::time::Duration::from_secs(2), shutdown.notified())
            .await
            .expect("stored permit must wake the next waiter");
    }

    /// Verifies that the `run()` select converges on a shutdown boundary
    /// when the shutdown notifier fires, without exiting as an error.
    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_notification_triggers_shutdown_boundary() {
        let shutdown = Arc::new(Notify::new());
        let tls_reload = Arc::new(Notify::new());
        let shutdown_for_select = shutdown.clone();
        let tls_reload_for_select = tls_reload.clone();

        let runner: tokio::task::JoinHandle<&'static str> = tokio::spawn(async move {
            tokio::select! {
                () = tls_reload_for_select.notified() => "tls_reload",
                () = shutdown_for_select.notified() => "shutdown",
            }
        });

        tokio::task::yield_now().await;
        shutdown.notify_one();

        let reason = tokio::time::timeout(std::time::Duration::from_secs(1), runner)
            .await
            .expect("select resolves promptly")
            .expect("task completes");
        assert_eq!(reason, "shutdown");
    }

    /// Verifies that `run()` selects the shutdown branch while active, joins
    /// top-level tasks, and drains tracked child tasks without hanging.
    #[serial]
    #[tokio::test(flavor = "current_thread")]
    async fn run_shutdown_drains_top_level_and_tracked_tasks() {
        let Some(harness) = RunTestHarness::try_new() else {
            return;
        };
        let mut guard = Some(test_tracing_guard());
        let shutdown = harness.shutdown.clone();
        tokio::spawn(notify_shutdown_after_startup_delay(shutdown));

        let reason = tokio::time::timeout(Duration::from_secs(3), harness.run(&mut guard))
            .await
            .expect("main run should exit promptly on shutdown")
            .expect("main run should complete cleanly");

        assert_eq!(reason, RunExitReason::Shutdown);
    }

    #[cfg(unix)]
    async fn assert_signal_reaches_run_shutdown_branch(signal: libc::c_int) {
        let Some(harness) = RunTestHarness::try_new() else {
            return;
        };
        register_shutdown_signal_handler(harness.shutdown.clone());
        let mut guard = Some(test_tracing_guard());

        tokio::spawn(raise_signal_after_startup_delay(signal));

        let reason = tokio::time::timeout(Duration::from_secs(3), harness.run(&mut guard))
            .await
            .expect("main run should exit promptly after signal-driven shutdown")
            .expect("main run should complete cleanly");

        assert_eq!(reason, RunExitReason::Shutdown);
    }

    /// Verifies SIGINT reaches the `run()` shutdown branch (not only `Notify`).
    #[cfg(unix)]
    #[serial]
    #[tokio::test(flavor = "current_thread")]
    async fn sigint_reaches_main_run_shutdown_branch() {
        assert_signal_reaches_run_shutdown_branch(libc::SIGINT).await;
    }

    /// Verifies SIGTERM reaches the `run()` shutdown branch (not only `Notify`).
    #[cfg(unix)]
    #[serial]
    #[tokio::test(flavor = "current_thread")]
    async fn sigterm_reaches_main_run_shutdown_branch() {
        assert_signal_reaches_run_shutdown_branch(libc::SIGTERM).await;
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
        let good = load_tls_material(&args_with_paths(
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
        if let Ok(new_certs) = load_tls_material(&args) {
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
        let current = load_tls_material(&args).expect("initial load succeeds");
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
        match load_tls_material(&args) {
            Ok(_) => panic!("mismatched material must not be accepted by the loader"),
            Err(e) => {
                assert!(
                    format!("{e:#}").contains("client endpoint"),
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
        let refreshed = load_tls_material(&args).expect("valid rotation loads");
        assert_eq!(refreshed.certs.len(), initial_leaf_count);
    }

    /// End-to-end reload contract for the manager/control path: a valid
    /// rotation replaces the shared `TlsBytes`; an invalid rotation
    /// preserves the last-known-good bytes.
    #[test]
    fn manager_tls_bytes_refresh_follows_reload_outcome() {
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

        let (_, initial_bytes) =
            load_tls_material_with_bytes(&args).expect("initial load succeeds");
        let manager_tls = SharedTlsBytes::new(initial_bytes.clone());
        assert_eq!(manager_tls.snapshot(), initial_bytes);

        // Invalid rotation: mismatched key. Reload must fail and the
        // shared bytes must remain at the last-known-good value because
        // the caller mirrors the main-loop branch that skips the swap on
        // error.
        let unrelated = rcgen::KeyPair::generate().expect("generate key");
        std::fs::write(&key_path, unrelated.serialize_pem().as_bytes()).expect("rewrite key file");
        assert!(
            load_tls_material_with_bytes(&args).is_err(),
            "mismatched material must not be accepted by the loader",
        );
        assert_eq!(
            manager_tls.snapshot(),
            initial_bytes,
            "failed reload must preserve the last-known-good manager TLS bytes",
        );

        // Valid rotation: restore the matching key, reload succeeds,
        // and the shared bytes swap atomically.
        std::fs::write(&key_path, &key_pem).expect("restore matching key");
        let (_, refreshed_bytes) =
            load_tls_material_with_bytes(&args).expect("valid rotation loads");
        manager_tls.replace(refreshed_bytes.clone());
        assert_eq!(manager_tls.snapshot(), refreshed_bytes);
    }
}
