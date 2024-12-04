use std::fs::{create_dir_all, OpenOptions};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tracing::info;
use tracing::metadata::LevelFilter;
use tracing_appender::non_blocking;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_subscriber::reload;
use tracing_subscriber::{
    fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer,
};

type ChangeLogWriter = Box<dyn Fn(NonBlocking) -> Result<()>>;

pub struct DynamicLogManager {
    /// Flushes the logs when it's dropped.
    guard: WorkerGuard,
    log_dir: Option<PathBuf>,
    change_log_writer: ChangeLogWriter,
}

impl DynamicLogManager {
    /// TODO(jake): remove the `allow` attribute after #113
    ///
    /// This method will be called when a remote configuration is fetched from the Manager server.
    #[allow(dead_code)]
    pub fn change_log_dir(&mut self, new_dir: Option<&Path>) -> Result<()> {
        if self.log_dir.as_deref() == new_dir {
            info!("New log directory is the same as the old directory");
            return Ok(());
        }
        let (writer, guard) = Self::create_writer(new_dir)?;
        if let Some(dir) = new_dir {
            info!("Log directory will change to {}", dir.display());
        }

        (self.change_log_writer)(writer)?;

        self.guard = guard;
        if let Some(dir) = &self.log_dir {
            info!("Previous logs are in {}", dir.display());
        }
        self.log_dir = new_dir.map(Path::to_path_buf);
        Ok(())
    }

    /// Creates a log writer for the `dynamic_layer` of tracing subscriber.
    fn create_writer(dir_path: Option<&Path>) -> Result<(NonBlocking, WorkerGuard)> {
        let Some(dir_path) = dir_path else {
            if cfg!(debug_assertions) {
                // In debug mode, `debug_layer` already acquired stdout.
                return Ok(non_blocking(Box::new(std::io::sink())));
            }
            return Ok(non_blocking(Box::new(std::io::stdout())));
        };

        create_dir_all(dir_path).with_context(|| {
            format!(
                "Cannot create the directory recursively for {}",
                dir_path.display()
            )
        })?;

        let file_path = dir_path.join(format!("{}.log", env!("CARGO_PKG_NAME")));
        Ok(non_blocking(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(&file_path)
                .with_context(|| format!("Cannot open the log file {}", file_path.display()))?,
        ))
    }
}

/// Initializes the tracing subscriber.
///
/// There are two layers: `debug_layer` and `dynamic_layer`.
/// - `debug_layer` is used to write logs to stdout if the runtime is in debug mode.
/// - `dynamic_layer` is used to write logs to a file or stdout dynamically.
///     - It uses stdout if the runtime is **not** in debug mode and no log directory is specified.
pub fn init_tracing(log_dir: Option<&Path>) -> Result<DynamicLogManager> {
    let debug_layer = if cfg!(debug_assertions) {
        Some(
            fmt::Layer::default()
                .with_ansi(true)
                .with_filter(EnvFilter::from_default_env()),
        )
    } else {
        None
    };

    let (writer, guard) = DynamicLogManager::create_writer(log_dir)?;
    let (dynamic_layer, reload_handle) = reload::Layer::new(
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

    let change_log_writer: ChangeLogWriter = Box::new(move |writer: NonBlocking| {
        reload_handle.modify(|layer| {
            *layer.inner_mut().writer_mut() = writer;
        })?;
        Ok(())
    });

    tracing_subscriber::Registry::default()
        .with(debug_layer)
        .with(dynamic_layer)
        .init();
    Ok(DynamicLogManager {
        guard,
        log_dir: log_dir.map(Path::to_path_buf),
        change_log_writer,
    })
}
