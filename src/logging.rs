use std::path::Path;

use tracing::level_filters::LevelFilter;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

/// Initializes the tracing subscriber.
///
/// If `log_dir` is `None` or the runtime is in debug mode, logs will be printed to stdout.
///
/// Returns a vector of `WorkerGuard` that flushes the log when dropped.
pub fn init_tracing(log_dir: Option<&Path>) -> Vec<WorkerGuard> {
    let mut guards = vec![];
    let subscriber = tracing_subscriber::Registry::default();
    let file_name = format!("{}.log", env!("CARGO_PKG_NAME"));

    let is_valid_file =
        matches!(log_dir, Some(path) if std::fs::File::create(path.join(&file_name)).is_ok());

    let stdout_layer = if !is_valid_file || cfg!(debug_assertions) {
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

    let file_layer = if is_valid_file {
        let file_appender = tracing_appender::rolling::never(
            log_dir.expect("verified by is_valid_file"),
            file_name,
        );
        let (file_writer, file_guard) = tracing_appender::non_blocking(file_appender);
        guards.push(file_guard);
        Some(
            fmt::Layer::default()
                .with_ansi(false)
                .with_target(false)
                .with_writer(file_writer)
                .with_filter(
                    EnvFilter::builder()
                        .with_default_directive(LevelFilter::INFO.into())
                        .from_env_lossy(),
                ),
        )
    } else {
        None
    };

    subscriber.with(stdout_layer).with(file_layer).init();
    guards
}
