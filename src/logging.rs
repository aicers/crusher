use std::{fs::OpenOptions, path::Path};

use anyhow::Context;
use tracing::{info, level_filters::LevelFilter};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

/// Initializes the tracing subscriber and returns a vector of `WorkerGuard` that flushes the log
/// when dropped.
///
/// If `log_path` is `None`, logs will be printed to stdout.
///
/// If the runtime is in debug mode, logs will be printed to stdout in addition to the specified
/// `log_path`.
pub(super) fn init_tracing(log_path: Option<&Path>) -> anyhow::Result<Vec<WorkerGuard>> {
    let mut guards = vec![];

    let file_layer = if let Some(log_path) = log_path {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .with_context(|| format!("Failed to open the log file: {}", log_path.display()))?;
        let (non_blocking, file_guard) = tracing_appender::non_blocking(file);
        guards.push(file_guard);
        Some(
            fmt::Layer::default()
                .with_ansi(false)
                .with_target(false)
                .with_writer(non_blocking)
                .with_filter(
                    EnvFilter::builder()
                        .with_default_directive(LevelFilter::INFO.into())
                        .from_env_lossy(),
                ),
        )
    } else {
        None
    };

    let stdout_layer = if file_layer.is_none() || cfg!(debug_assertions) {
        let (stdout_writer, stdout_guard) = tracing_appender::non_blocking(std::io::stdout());
        guards.push(stdout_guard);
        Some(
            fmt::Layer::default()
                .with_ansi(true)
                .with_writer(stdout_writer)
                .with_filter(EnvFilter::from_default_env()),
        )
    } else {
        None
    };

    tracing_subscriber::Registry::default()
        .with(stdout_layer)
        .with(file_layer)
        .init();
    info!("Initialized tracing logger");
    Ok(guards)
}
