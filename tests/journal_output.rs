//! Runs the crusher binary with standard output redirected to a temporary
//! file and checks what it writes under the journal (`JOURNAL_STREAM` naming
//! that file) and elsewhere.

#![cfg(unix)]

use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};

const LOG_PATH_REMOVED: &str =
    "log_path was removed; logs go to standard output (the journal under systemd)";

struct Output {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

/// Runs crusher with `args`, standard output redirected to a temporary file
/// and, if `journal` is `true`, `JOURNAL_STREAM` naming that file.
fn run_crusher(args: &[&str], journal: bool) -> Output {
    let mut stdout_file = tempfile::tempfile().expect("create stdout file");
    let metadata = stdout_file.metadata().expect("stat stdout file");

    let mut command = Command::new(env!("CARGO_BIN_EXE_crusher"));
    command
        .args(args)
        .env_remove("RUST_LOG")
        .stdin(Stdio::null())
        .stdout(stdout_file.try_clone().expect("clone stdout file"))
        .stderr(Stdio::piped());
    if journal {
        command.env(
            "JOURNAL_STREAM",
            format!("{}:{}", metadata.dev(), metadata.ino()),
        );
    } else {
        command.env_remove("JOURNAL_STREAM");
    }
    let output = command.output().expect("run crusher");

    stdout_file
        .seek(SeekFrom::Start(0))
        .expect("rewind stdout file");
    let mut stdout = String::new();
    stdout_file
        .read_to_string(&mut stdout)
        .expect("read stdout file");
    Output {
        status: output.status,
        stdout,
        stderr: String::from_utf8(output.stderr).expect("stderr is UTF-8"),
    }
}

/// Returns crusher's arguments for the configuration file `config`, with the
/// test certificates and an unused Manager address.
fn local_args(config: &Path) -> Vec<String> {
    let tests = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    vec![
        "-c".to_string(),
        config.to_str().expect("UTF-8 config path").to_string(),
        "--cert".to_string(),
        tests
            .join("cert.pem")
            .to_str()
            .expect("UTF-8 path")
            .to_string(),
        "--key".to_string(),
        tests
            .join("key.pem")
            .to_str()
            .expect("UTF-8 path")
            .to_string(),
        "--ca-certs".to_string(),
        tests
            .join("ca_cert.pem")
            .to_str()
            .expect("UTF-8 path")
            .to_string(),
        "name@127.0.0.1:1".to_string(),
    ]
}

fn run_local(config: &Path, journal: bool) -> Output {
    let args = local_args(config);
    run_crusher(
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
        journal,
    )
}

/// Asserts that every line of `stdout` is a journal line, and returns the
/// lines at priority 3 (error).
fn journal_error_lines(stdout: &str) -> Vec<&str> {
    for line in stdout.lines() {
        assert!(
            ["<3>", "<4>", "<6>", "<7>"]
                .iter()
                .any(|prefix| line.starts_with(prefix)),
            "line without a priority prefix: {line:?}\n{stdout}"
        );
        assert!(!line.contains('\x1b'), "ESC in journal line: {line:?}");
    }
    assert!(stdout.is_empty() || stdout.ends_with('\n'));
    stdout
        .lines()
        .filter(|line| line.starts_with("<3>"))
        .collect()
}

#[test]
fn missing_config_file_under_journal_is_one_error_line() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let output = run_local(&dir.path().join("missing.toml"), true);

    assert_eq!(output.status.code(), Some(1), "{}", output.stdout);
    let errors = journal_error_lines(&output.stdout);
    assert_eq!(errors.len(), 1, "{}", output.stdout);
    assert!(
        errors[0].contains("failed to load configuration file"),
        "{}",
        errors[0]
    );
    assert!(output.stderr.is_empty(), "stderr: {}", output.stderr);
}

fn write_log_path_config(dir: &Path) -> std::path::PathBuf {
    let config = dir.join("crusher.toml");
    std::fs::write(
        &config,
        format!(
            r#"
giganto_name = "localhost"
giganto_ingest_srv_addr = "127.0.0.1:1"
giganto_publish_srv_addr = "127.0.0.1:1"
last_timestamp_data = "{}"
log_path = "x"
"#,
            dir.join("time_data.json").display()
        ),
    )
    .expect("write config");
    config
}

#[test]
fn local_config_naming_log_path_under_journal_is_refused() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let config = write_log_path_config(dir.path());
    let output = run_local(&config, true);

    assert_eq!(output.status.code(), Some(1), "{}", output.stdout);
    let errors = journal_error_lines(&output.stdout);
    assert_eq!(errors.len(), 1, "{}", output.stdout);
    assert!(errors[0].ends_with(LOG_PATH_REMOVED), "{}", errors[0]);
    assert!(output.stderr.is_empty(), "stderr: {}", output.stderr);
}

#[test]
fn local_config_naming_log_path_is_refused() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let config = write_log_path_config(dir.path());
    let output = run_local(&config, false);

    assert_eq!(output.status.code(), Some(1), "{}", output.stdout);
    assert_eq!(output.stderr, format!("Error: {LOG_PATH_REMOVED}\n"));
    for line in output.stdout.lines() {
        assert!(!line.starts_with('<'), "priority prefix: {line:?}");
        assert!(!line.contains('\x1b'), "ESC written to a file: {line:?}");
    }
}

#[test]
fn unknown_flag_under_journal_is_one_error_line() {
    let output = run_crusher(&["--no-such-flag"], true);

    assert_eq!(output.status.code(), Some(2), "{}", output.stdout);
    let errors = journal_error_lines(&output.stdout);
    assert_eq!(errors.len(), 1, "{}", output.stdout);
    assert!(
        errors[0].contains("unexpected argument '--no-such-flag' found"),
        "{}",
        errors[0]
    );
    assert!(output.stderr.is_empty(), "stderr: {}", output.stderr);
}

#[test]
fn unknown_flag_outside_journal_is_clap_output() {
    let output = run_crusher(&["--no-such-flag"], false);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty(), "stdout: {}", output.stdout);
    assert!(
        output
            .stderr
            .starts_with("error: unexpected argument '--no-such-flag' found"),
        "stderr: {}",
        output.stderr
    );
}

#[test]
fn help_is_printed_as_clap_prints_it() {
    let output = run_crusher(&["--help"], true);

    assert!(output.status.success());
    assert!(output.stdout.starts_with("Usage: "), "{}", output.stdout);
    assert!(output.stderr.is_empty(), "stderr: {}", output.stderr);
}

/// The reason a fake Manager gives for not supplying a configuration, as the
/// Manager does before the instance is configured.
const UNREGISTERED: &str = "001.crusher unregistered";

struct UnregisteredManager;

#[async_trait::async_trait]
impl review_protocol::server::Handler for UnregisteredManager {
    async fn get_config(&self, _peer: &str) -> Result<String, String> {
        Err(UNREGISTERED.to_string())
    }
}

/// Returns the QUIC configuration of a Manager that authenticates with the
/// test certificates and requires them of its client.
fn manager_server_config() -> quinn::ServerConfig {
    let tests = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let read = |name: &str| std::fs::read(tests.join(name)).expect("read test certificate");
    let certs = rustls_pemfile::certs(&mut read("cert.pem").as_slice())
        .collect::<Result<Vec<_>, _>>()
        .expect("parse certificate");
    let key = rustls_pemfile::private_key(&mut read("key.pem").as_slice())
        .expect("parse key")
        .expect("key is present");
    let mut roots = rustls::RootCertStore::empty();
    for ca in rustls_pemfile::certs(&mut read("ca_cert.pem").as_slice()) {
        roots
            .add(ca.expect("parse CA certificate"))
            .expect("add CA");
    }
    let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        std::sync::Arc::new(roots),
        provider.clone(),
    )
    .build()
    .expect("build client verifier");
    let crypto = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("aws-lc-rs supports the default protocol versions")
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .expect("build server TLS configuration");
    quinn::ServerConfig::with_crypto(std::sync::Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
            .expect("build QUIC server configuration"),
    ))
}

/// Serves every connection with [`UnregisteredManager`].
async fn serve_unregistered_manager(endpoint: quinn::Endpoint) {
    while let Some(connecting) = endpoint.accept().await {
        tokio::spawn(async move {
            let Ok(connection) = connecting.await else {
                return;
            };
            let address = connection.remote_address();
            if review_protocol::server::handshake(&connection, address, ">=0", "0.49.0")
                .await
                .is_err()
            {
                return;
            }
            let mut handler = UnregisteredManager;
            while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                let _ = review_protocol::server::handle(&mut handler, &mut send, &mut recv, "test")
                    .await;
            }
        });
    }
}

/// A Crusher whose Manager has no configuration for it yet logs the wait at
/// WARN with the Manager's reason, logs no error, and enters idle mode.
#[test]
fn unregistered_wait_under_journal_is_one_warning() {
    let runtime = tokio::runtime::Runtime::new().expect("build runtime");
    let endpoint = runtime.block_on(async {
        quinn::Endpoint::server(
            manager_server_config(),
            "[::1]:0".parse().expect("valid address"),
        )
        .expect("bind the fake Manager")
    });
    let manager_addr = endpoint.local_addr().expect("fake Manager address");
    runtime.spawn(serve_unregistered_manager(endpoint));

    let tests = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let path = |name: &str| tests.join(name).to_str().expect("UTF-8 path").to_string();
    let mut stdout_file = tempfile::tempfile().expect("create stdout file");
    let metadata = stdout_file.metadata().expect("stat stdout file");
    let mut child = Command::new(env!("CARGO_BIN_EXE_crusher"))
        .args([
            "--cert",
            &path("cert.pem"),
            "--key",
            &path("key.pem"),
            "--ca-certs",
            &path("ca_cert.pem"),
            &format!("localhost@{manager_addr}"),
        ])
        .env_remove("RUST_LOG")
        .env(
            "JOURNAL_STREAM",
            format!("{}:{}", metadata.dev(), metadata.ino()),
        )
        .stdin(Stdio::null())
        .stdout(stdout_file.try_clone().expect("clone stdout file"))
        .stderr(Stdio::piped())
        .spawn()
        .expect("start crusher");

    let read_stdout = |file: &mut std::fs::File| {
        file.seek(SeekFrom::Start(0)).expect("rewind stdout file");
        let mut stdout = String::new();
        file.read_to_string(&mut stdout).expect("read stdout file");
        stdout
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while !read_stdout(&mut stdout_file).contains("Entering idle mode") {
        if std::time::Instant::now() > deadline || child.try_wait().expect("poll crusher").is_some()
        {
            let _ = child.kill();
            panic!(
                "crusher did not enter idle mode:\n{}",
                read_stdout(&mut stdout_file)
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    // SIGTERM ends idle mode with a graceful shutdown.
    let pid = libc::pid_t::try_from(child.id()).expect("pid fits in pid_t");
    // SAFETY: `kill` only signals the child process this test started.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
    let status = child.wait().expect("wait for crusher");
    let stdout = read_stdout(&mut stdout_file);

    assert!(status.success(), "{stdout}");
    assert!(journal_error_lines(&stdout).is_empty(), "{stdout}");
    let warnings: Vec<&str> = stdout
        .lines()
        .filter(|line| line.starts_with("<4>"))
        .collect();
    assert_eq!(warnings.len(), 1, "{stdout}");
    assert!(
        warnings[0].ends_with(&format!(
            "Waiting for a configuration from the Manager: {UNREGISTERED}"
        )),
        "{}",
        warnings[0]
    );
    drop(runtime);
}
