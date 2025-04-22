use std::borrow::Cow;
use std::sync::OnceLock;
use std::{fs::OpenOptions, path::Path};

use anyhow::Context;
use tracing::{info, level_filters::LevelFilter};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

pub(super) static DAEMON_ID: OnceLock<Cow<'static, str>> = OnceLock::new();

/// Initializes the tracing subscriber and returns a vector of `WorkerGuard` that flushes the log
/// when dropped.
///
/// If `log_path` is `None`, logs will be printed to stdout.
///
/// If the runtime is in debug mode, logs will be printed to stdout in addition to the specified
/// `log_path`.
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

#[macro_export]
macro_rules! custom_log {
    (
        $level:expr,
        $log_index:expr,
        $account:expr,
        $msg:literal,
        $($arg:expr),+ $(,)?
    ) => {{
        use tracing::{Level, info, warn, error, debug, trace};

        if tracing::enabled!($level) {
            let daemon_id = $crate::logging::DAEMON_ID
                .get()
                .map(|v| v.as_ref())
                .unwrap_or("unknown");

            let formatted_message = format!($msg, $($arg),+);

            let log_line = format!(
                "| {} | {} | {} | {}",
                daemon_id,
                $log_index,
                $account,
                formatted_message
            );

            match $level {
                Level::INFO => info!("{}", log_line),
                Level::WARN => warn!("{}", log_line),
                Level::ERROR => error!("{}", log_line),
                Level::DEBUG => debug!("{}", log_line),
                Level::TRACE => trace!("{}", log_line),
            }
        }
    }};

    (
        $level:expr,
        $log_index:expr,
        $account:expr,
        $msg:literal
    ) => {{
        $crate::custom_log!($level, $log_index, $account, "{}", $msg);
    }};

    (
        $level:expr,
        $log_index:expr,
        $msg:literal,
        $($arg:expr),+ $(,)?
    ) => {{
        $crate::custom_log!(
            $level,
            $log_index,
            "",
            $msg,
            $($arg),+
        );
    }};

    (
        $level:expr,
        $log_index:expr,
        $msg:literal
    ) => {{
        $crate::custom_log!(
            $level,
            $log_index,
            "",
            "{}",
            $msg
        );
    }};
}

#[macro_export]
macro_rules! audit_trace_log {
    ($log_index:expr, $account:expr, $msg:literal $(, $($arg:tt)* )?) => {
        $crate::custom_log!(
            tracing::Level::TRACE,
            $log_index,
            $account,
            $msg $(, $($arg)* )?
        );
    };
    ($log_index:expr, $msg:literal $(, $($arg:tt)* )?) => {
        $crate::custom_log!(
            tracing::Level::TRACE,
            $log_index,
            "",
            $msg $(, $($arg)* )?
        );
    };
}

#[macro_export]
macro_rules! audit_debug_log {
    ($log_index:expr, $account:expr, $msg:literal $(, $($arg:tt)* )?) => {
        $crate::custom_log!(
            tracing::Level::DEBUG,
            $log_index,
            $account,
            $msg $(, $($arg)* )?
        );
    };
    ($log_index:expr, $msg:literal $(, $($arg:tt)* )?) => {
        $crate::custom_log!(
            tracing::Level::DEBUG,
            $log_index,
            "",
            $msg $(, $($arg)* )?
        );
    };
}

#[macro_export]
macro_rules! audit_info_log {
    ($log_index:expr, $account:expr, $msg:literal $(, $($arg:tt)* )?) => {
        $crate::custom_log!(
            tracing::Level::INFO,
            $log_index,
            $account,
            $msg $(, $($arg)* )?
        );
    };
    ($log_index:expr, $msg:literal $(, $($arg:tt)* )?) => {
        $crate::custom_log!(
            tracing::Level::INFO,
            $log_index,
            "",
            $msg $(, $($arg)* )?
        )
    };
}

#[macro_export]
macro_rules! audit_warn_log {
    ($log_index:expr, $account:expr, $msg:literal $(, $($arg:tt)* )?) => {
        $crate::custom_log!(
            tracing::Level::WARN,
            $log_index,
            $account,
            $msg $(, $($arg)* )?
        );
    };
    ($log_index:expr, $msg:literal $(, $($arg:tt)* )?) => {
        $crate::custom_log!(
            tracing::Level::WARN,
            $log_index,
            "",
            $msg $(, $($arg)* )?
        );
    };
}

#[macro_export]
macro_rules! audit_error_log {
    ($log_index:expr, $account:expr, $msg:literal $(, $($arg:tt)* )?) => {
        $crate::custom_log!(
            tracing::Level::ERROR,
            $log_index,
            $account,
            $msg $(, $($arg)* )?
        );
    };
    ($log_index:expr, $msg:literal $(, $($arg:tt)* )?) => {
        $crate::custom_log!(
            tracing::Level::ERROR,
            $log_index,
            "",
            $msg $(, $($arg)* )?
        );
    };
}
