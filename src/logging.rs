use std::{fs::OpenOptions, path::Path};

use anyhow::Context;
use tracing::{info, level_filters::LevelFilter};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{EnvFilter, Layer, fmt, layer::SubscriberExt, util::SubscriberInitExt};

/// Initializes the tracing subscriber and returns a `WorkerGuard`.
///
/// Logs will be written to the file specified by `log_path` if provided.
/// If `log_path` is `None`, logs will be printed to stdout.
///
pub(crate) fn init_tracing(log_path: Option<&Path>) -> anyhow::Result<WorkerGuard> {
    let (layer, guard) = if let Some(log_path) = log_path {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .with_context(|| format!("Failed to open the log file: {}", log_path.display()))?;
        let (non_blocking, file_guard) = tracing_appender::non_blocking(file);
        (
            fmt::Layer::default()
                .with_ansi(false)
                .with_target(false)
                .with_writer(non_blocking)
                .with_filter(
                    EnvFilter::builder()
                        .with_default_directive(LevelFilter::INFO.into())
                        .from_env_lossy(),
                ),
            file_guard,
        )
    } else {
        let (stdout_writer, stdout_guard) = tracing_appender::non_blocking(std::io::stdout());
        (
            fmt::Layer::default()
                .with_ansi(true)
                .with_writer(stdout_writer)
                .with_filter(EnvFilter::from_default_env()),
            stdout_guard,
        )
    };

    tracing_subscriber::Registry::default().with(layer).init();
    info!("Initialized tracing logger");
    Ok(guard)
}

#[macro_export]
macro_rules! error_or_eprint {
    ($($args:tt),*) => {
        if tracing::dispatcher::has_been_set() {
            tracing::error!($($args),*);
        } else {
            eprintln!($($args),*);
        }
    }
}

#[macro_export]
macro_rules! info_or_print {
    ($($args:tt),*) => {
        if tracing::dispatcher::has_been_set() {
            tracing::info!($($args),*);
        } else {
            println!($($args),*);
        }
    }
}
