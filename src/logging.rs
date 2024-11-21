use std::fs::{create_dir_all, OpenOptions};
use std::path::Path;

use anyhow::{anyhow, bail, Result};
use tracing::info;
use tracing::metadata::LevelFilter;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::reload;
use tracing_subscriber::{
    fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer,
};

type ChangeLogDir = Box<dyn Fn(Option<&Path>, Option<&Path>) -> Result<Option<WorkerGuard>>>;

/// Manages the log file and guard.
///
/// `guard` will flush the logs when it's dropped.
pub struct LogManager {
    pub guard: WorkerGuard,
    pub change_log_dir: ChangeLogDir,
}

/// Creates a writer for the `default_layer`.
///
/// If runtime is in debug mode, `debug_layer` will be used to print logs to stdout. So it returns
/// `std::io::sink()` to avoid duplicated logs in stdout.
fn create_writer(dir_path: Option<&Path>) -> Result<Box<dyn std::io::Write + Send>> {
    let Some(dir_path) = dir_path else {
        if cfg!(debug_assertions) {
            return Ok(Box::new(std::io::sink()));
        }
        return Ok(Box::new(std::io::stdout()));
    };

    if let Err(e) = create_dir_all(dir_path) {
        bail!("Cannot create the directory recursively for {dir_path:?}: {e}");
    }

    OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir_path.join(format!("{}.log", env!("CARGO_PKG_NAME"))))
        .map_err(|e| anyhow!("Cannot create the log file: {e}"))
        .map(|f| Box::new(f) as Box<dyn std::io::Write + Send>)
}

/// Initializes the tracing subscriber.
///
/// If `log_dir` is `None` or the runtime is in debug mode, logs will be printed to stdout.
pub fn init_tracing(log_dir: Option<&Path>) -> Result<LogManager> {
    let debug_layer = if cfg!(debug_assertions) {
        Some(
            fmt::Layer::default()
                .with_ansi(true)
                .with_filter(EnvFilter::from_default_env()),
        )
    } else {
        None
    };

    let (writer, guard) = tracing_appender::non_blocking(create_writer(log_dir)?);
    let (default_layer, reload_handle) = reload::Layer::new(
        fmt::Layer::default()
            .with_ansi(false)
            .with_target(false)
            .with_writer(writer)
            .with_filter(
                EnvFilter::builder()
                    .with_default_directive(LevelFilter::INFO.into())
                    .from_env_lossy(),
            ),
    );

    let change_log_dir: ChangeLogDir =
        Box::new(move |old_dir: Option<&Path>, new_dir: Option<&Path>| {
            if old_dir.eq(&new_dir) {
                info!("New log directory is the same as the old directory");
                return Ok(None);
            }
            let writer = create_writer(new_dir)?;
            if let Some(dir) = new_dir {
                info!("Log directory will change to {}", dir.display());
            }
            let (writer, guard) = tracing_appender::non_blocking(writer);
            reload_handle.modify(|layer| {
                *layer.inner_mut().writer_mut() = writer;
            })?;
            if let Some(dir) = old_dir {
                info!("Previous logs are in {}", dir.display());
            }
            Ok(Some(guard))
        });

    tracing_subscriber::Registry::default()
        .with(debug_layer)
        .with(default_layer)
        .init();
    Ok(LogManager {
        guard,
        change_log_dir,
    })
}
