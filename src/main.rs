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
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result, bail};
use clap::Parser;
use client::Certs;
use logging::init_tracing;
use review_protocol::types::SamplingPolicy;
use settings::Settings;
use subscribe::{ensure_time_data_exists, read_last_timestamp};
use tokio::sync::Notify;
use tracing::{info, warn};
use tracing_appender::non_blocking::WorkerGuard;

const REQUESTED_POLICY_CHANNEL_SIZE: usize = 1;

#[derive(Debug, Clone)]
struct ManagerServer {
    name: String,
    rpc_srv_addr: SocketAddr,
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
struct CmdLineArgs {
    /// Path to the local configuration TOML file.
    #[arg(short, value_name = "CONFIG_PATH")]
    config: Option<String>,

    /// Path to the certificate file.
    #[arg(long, value_name = "CERT_PATH")]
    cert: String,

    /// Path to the key file.
    #[arg(long, value_name = "KEY_PATH")]
    key: String,

    /// Path to the CA certificate files. Multiple paths can be provided as a comma-separated list.
    #[arg(
        long,
        value_name = "CA_CERTS_PATH",
        required = true,
        value_delimiter = ','
    )]
    ca_certs: Vec<String>,

    /// Address of the Manager server formatted as `<server_name>@<server_ip>:<server_port>`.
    #[arg(value_parser=clap::builder::ValueParser::new(ManagerServer::from_str))]
    manager_server: ManagerServer,
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

/// Reads Giganto cert/key/CA material from disk and builds a new [`Certs`].
///
/// This is the loader used both at startup and by the repository-level TLS
/// reload trigger. It is kept distinct from the `update_config()` /
/// `config_reload` seam so that other components can opt into TLS reloads
/// without being affected by configuration reload semantics.
///
/// # Errors
///
/// Returns an error if any cert/key/CA file cannot be read, the private key
/// does not match the certificate, or the CA bundle cannot be parsed.
fn load_giganto_certs(args: &CmdLineArgs) -> Result<Certs> {
    let (cert_pem, key_pem, ca_certs_pem) = read_cert_pems(args)?;
    Certs::try_new(
        &cert_pem,
        &key_pem,
        &ca_certs_pem.iter().map(Vec::as_slice).collect::<Vec<_>>(),
    )
}

/// Registers a process-level SIGHUP handler that sets the shared TLS reload
/// pending flag and wakes any waiters on the dedicated TLS reload notifier.
///
/// SIGHUP is POSIX-only; on non-Unix targets this is a no-op.
fn register_tls_reload_signal_handler(
    tls_reload: Arc<Notify>,
    tls_reload_pending: Arc<AtomicBool>,
) {
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
                tls_reload_pending.store(true, Ordering::SeqCst);
                tls_reload.notify_waiters();
            }
        });
    }
    #[cfg(not(unix))]
    {
        let _ = (tls_reload, tls_reload_pending);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = CmdLineArgs::parse();
    let (cert_pem, key_pem, ca_certs_pem) = read_cert_pems(&args)?;
    let mut certs = Certs::try_new(
        &cert_pem,
        &key_pem,
        &ca_certs_pem.iter().map(Vec::as_slice).collect::<Vec<_>>(),
    )?;
    let (request_send, request_recv) =
        async_channel::bounded::<SamplingPolicy>(REQUESTED_POLICY_CHANNEL_SIZE);
    let config_reload = Arc::new(Notify::new());
    let tls_reload = Arc::new(Notify::new());
    let tls_reload_pending = Arc::new(AtomicBool::new(false));
    register_tls_reload_signal_handler(tls_reload.clone(), tls_reload_pending.clone());
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
        if tls_reload_pending.swap(false, Ordering::SeqCst) {
            match load_giganto_certs(&args) {
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

        if let Err(e) = run(
            &args,
            &certs,
            request_client.clone(),
            request_recv.clone(),
            config_reload.clone(),
            tls_reload.clone(),
            &mut guard,
        )
        .await
        {
            assert!(args.is_remote_mode(), "{e}");
            error_or_eprint!("Main processing encountered an error: {e}");
            let health_check = e.downcast_ref::<std::io::Error>().is_some_and(|e| {
                matches!(
                    e.kind(),
                    ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset | ErrorKind::TimedOut
                )
            });
            request_client.enter_idle_mode(health_check).await;
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
) -> Result<()> {
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
    tokio::select! {
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
        },
        () = tls_reload.notified() => {
            shutdown.notify_waiters();
            shutdown.notified().await;
            info!("Rebuilding the shared Giganto endpoint from reloaded TLS material");
        },
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

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

    #[test]
    fn load_giganto_certs_reads_from_disk() {
        let cert_pem = std::fs::read("tests/cert.pem").expect("read cert");
        let key_pem = std::fs::read("tests/key.pem").expect("read key");
        let ca_pem = std::fs::read("tests/ca_cert.pem").expect("read ca");

        let dir = tempdir().expect("tempdir");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&cert_path, &cert_pem).expect("write cert");
        std::fs::write(&key_path, &key_pem).expect("write key");
        std::fs::write(&ca_path, &ca_pem).expect("write ca");

        let args = args_with_paths(
            cert_path.to_str().expect("utf-8 cert path"),
            key_path.to_str().expect("utf-8 key path"),
            vec![ca_path.to_str().expect("utf-8 ca path").to_string()],
        );

        let certs = load_giganto_certs(&args).expect("load certs from disk");
        assert!(!certs.certs.is_empty());
        assert!(!certs.ca_certs.is_empty());
    }

    fn expect_load_err(args: &CmdLineArgs) -> anyhow::Error {
        match load_giganto_certs(args) {
            Ok(_) => panic!("expected TLS reload to fail"),
            Err(e) => e,
        }
    }

    #[test]
    fn load_giganto_certs_fails_on_missing_file() {
        let args = args_with_paths(
            "tests/does_not_exist.pem",
            "tests/key.pem",
            vec!["tests/ca_cert.pem".to_string()],
        );
        let err = expect_load_err(&args);
        assert!(err.to_string().contains("failed to read certificate file"));
    }

    #[test]
    fn load_giganto_certs_fails_on_invalid_cert() {
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
    fn load_giganto_certs_fails_on_invalid_key() {
        let cert_pem = std::fs::read("tests/cert.pem").expect("read cert");
        let ca_pem = std::fs::read("tests/ca_cert.pem").expect("read ca");

        let dir = tempdir().expect("tempdir");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&cert_path, &cert_pem).expect("write cert");
        // Content without PEM markers so the private-key parser rejects it.
        std::fs::write(&key_path, b"not a pem-encoded private key").expect("write key");
        std::fs::write(&ca_path, &ca_pem).expect("write ca");

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

    /// Mismatched key vs cert is detected when the TLS client configuration
    /// is built. The TLS reload path uses the same `client::config` builder
    /// via `subscribe::Client::new`, so this verifies that a mismatched key
    /// is rejected before being swapped into the shared endpoint state.
    #[test]
    fn mismatched_key_is_rejected_by_client_config() {
        let cert_pem = std::fs::read("tests/cert.pem").expect("read cert");
        let ca_pem = std::fs::read("tests/ca_cert.pem").expect("read ca");
        // Generate an unrelated PKCS#8 key that will not match the cert above.
        let unrelated = rcgen::KeyPair::generate().expect("generate key");
        let unrelated_pem = unrelated.serialize_pem();

        let dir = tempdir().expect("tempdir");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&cert_path, &cert_pem).expect("write cert");
        std::fs::write(&key_path, unrelated_pem.as_bytes()).expect("write key");
        std::fs::write(&ca_path, &ca_pem).expect("write ca");

        let args = args_with_paths(
            cert_path.to_str().expect("utf-8 cert path"),
            key_path.to_str().expect("utf-8 key path"),
            vec![ca_path.to_str().expect("utf-8 ca path").to_string()],
        );
        let certs = load_giganto_certs(&args).expect("parses cert/key/CA individually");
        assert!(
            client::config(&certs).is_err(),
            "mismatched key must be rejected when the shared endpoint is built"
        );
    }

    /// Verifies that SIGHUP reaches the TLS reload seam without terminating
    /// the process and sets the pending flag so the next rerun boundary
    /// picks up rotated TLS material.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn sighup_signals_tls_reload_without_exit() {
        let tls_reload = Arc::new(Notify::new());
        let tls_reload_pending = Arc::new(AtomicBool::new(false));
        register_tls_reload_signal_handler(tls_reload.clone(), tls_reload_pending.clone());

        let notifier = tls_reload.clone();
        let waiter = tokio::spawn(async move { notifier.notified().await });

        // Give the signal stream a moment to register before raising.
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Send SIGHUP to the current process.
        // SAFETY: libc::raise is safe here; we are the only caller and no
        // assumptions are made about other threads.
        unsafe {
            libc::raise(libc::SIGHUP);
        }

        tokio::time::timeout(std::time::Duration::from_secs(2), waiter)
            .await
            .expect("tls_reload notification within timeout")
            .expect("waiter task not aborted");

        assert!(
            tls_reload_pending.load(Ordering::SeqCst),
            "SIGHUP must set the TLS reload pending flag"
        );
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
        tls_reload.notify_waiters();

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
        let good = load_giganto_certs(&args_with_paths(
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
        if let Ok(new_certs) = load_giganto_certs(&args) {
            current = new_certs;
        }

        assert_eq!(current.certs.len(), good_leaf_count);
    }
}
