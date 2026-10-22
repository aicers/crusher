//! Logging set-up.
//!
//! Logs always go to standard output. When standard output or standard error
//! is connected to the systemd journal, every event is written as one line
//! that starts with its syslog priority (`<N>`), so the journal stores it at
//! that priority, without a timestamp or ANSI escape codes.

use std::ffi::OsStr;
use std::io::{self, IsTerminal, Write};
#[cfg(unix)]
use std::os::fd::{AsFd, BorrowedFd};

use anyhow::Result;
use tracing::{Level, Metadata, error, info, level_filters::LevelFilter};
use tracing_subscriber::{
    EnvFilter, Layer,
    fmt::{self, MakeWriter},
    layer::SubscriberExt,
    util::SubscriberInitExt,
};

/// The `(st_dev, st_ino)` pair identifying an open file.
#[cfg(unix)]
type FileId = (u64, u64);

/// Returns `true` if the process output is the systemd journal.
///
/// `journal_stream` is the value of the `JOURNAL_STREAM` environment
/// variable, which systemd sets to `<dev>:<ino>` of the stream it connects
/// to standard output and standard error. The output is the journal only if
/// that value matches file descriptor 1 or 2, so output redirected by a
/// wrapper is not mistaken for the journal. On non-Unix targets the output
/// is never the journal.
pub(crate) fn output_is_journal(journal_stream: Option<&OsStr>) -> bool {
    #[cfg(unix)]
    {
        matches_journal_stream(
            journal_stream,
            file_id(io::stdout().as_fd()),
            file_id(io::stderr().as_fd()),
        )
    }
    #[cfg(not(unix))]
    {
        let _ = journal_stream;
        false
    }
}

#[cfg(unix)]
fn file_id(fd: BorrowedFd<'_>) -> Option<FileId> {
    use std::os::unix::fs::MetadataExt;

    let file = std::fs::File::from(fd.try_clone_to_owned().ok()?);
    let metadata = file.metadata().ok()?;
    Some((metadata.dev(), metadata.ino()))
}

#[cfg(unix)]
fn matches_journal_stream(
    journal_stream: Option<&OsStr>,
    stdout: Option<FileId>,
    stderr: Option<FileId>,
) -> bool {
    let Some(stream) = journal_stream.and_then(parse_journal_stream) else {
        return false;
    };
    stdout == Some(stream) || stderr == Some(stream)
}

/// Parses a `JOURNAL_STREAM` value of the form `<dev>:<ino>`.
#[cfg(unix)]
fn parse_journal_stream(value: &OsStr) -> Option<FileId> {
    fn parse_decimal(s: &str) -> Option<u64> {
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        s.parse().ok()
    }

    let (dev, ino) = value.to_str()?.split_once(':')?;
    Some((parse_decimal(dev)?, parse_decimal(ino)?))
}

/// Initializes the tracing subscriber, which writes to standard output.
///
/// If `journal` is `true`, every event is written as one journal line (see
/// [`journal_line`]) and a panic hook that logs a panic as one error event
/// replaces the default one. Otherwise, events are written as `fmt` formats
/// them, with ANSI escape codes only if standard output is a terminal.
///
/// # Errors
///
/// Returns an error if a global subscriber has already been set.
pub(crate) fn init_tracing(journal: bool) -> Result<()> {
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    let layer = if journal {
        fmt::Layer::default()
            .without_time()
            .with_ansi(false)
            .with_writer(JournalWriter)
            .with_filter(filter)
            .boxed()
    } else {
        fmt::Layer::default()
            .with_ansi(io::stdout().is_terminal())
            .with_writer(io::stdout)
            .with_filter(filter)
            .boxed()
    };

    tracing_subscriber::registry().with(layer).try_init()?;
    if journal {
        install_panic_hook();
    }
    info!("Initialized tracing logger");
    Ok(())
}

/// Replaces the default panic hook with one that logs the panic as one error
/// event and writes nothing else.
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let thread = std::thread::current();
        let name = thread.name().unwrap_or("<unnamed>");
        let message = info.payload_as_str().unwrap_or("Box<dyn Any>");
        let location = info.location().map_or_else(
            || "<unknown location>".to_string(),
            |location| {
                format!(
                    "{}:{}:{}",
                    location.file(),
                    location.line(),
                    location.column()
                )
            },
        );
        error!("thread '{name}' panicked at {location}: {message}");
    }));
}

/// A `MakeWriter` that writes each event to standard output as one journal
/// line.
struct JournalWriter;

impl<'a> MakeWriter<'a> for JournalWriter {
    type Writer = JournalEvent;

    fn make_writer(&'a self) -> Self::Writer {
        JournalEvent::new(Level::INFO)
    }

    fn make_writer_for(&'a self, meta: &Metadata<'_>) -> Self::Writer {
        JournalEvent::new(*meta.level())
    }
}

/// Buffers one formatted event and writes it to standard output as one
/// journal line, in a single write, when dropped.
struct JournalEvent {
    level: Level,
    buf: Vec<u8>,
}

impl JournalEvent {
    fn new(level: Level) -> Self {
        Self {
            level,
            buf: Vec::new(),
        }
    }
}

impl Write for JournalEvent {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for JournalEvent {
    fn drop(&mut self) {
        if self.buf.is_empty() {
            return;
        }
        let line = journal_line(self.level, &self.buf);
        let _ = io::stdout().lock().write_all(&line);
    }
}

/// Returns the syslog priority of `level`.
fn syslog_priority(level: Level) -> u8 {
    match level {
        Level::ERROR => 3,
        Level::WARN => 4,
        Level::INFO => 6,
        Level::DEBUG | Level::TRACE => 7,
    }
}

/// Turns one formatted event into one journal line: the syslog priority
/// prefix `<N>`, the event without its final line feed, with every line feed
/// written as `\n` and every NUL as `\0`, and one line feed.
fn journal_line(level: Level, event: &[u8]) -> Vec<u8> {
    let event = event.strip_suffix(b"\n").unwrap_or(event);
    let mut line = format!("<{}>", syslog_priority(level)).into_bytes();
    line.reserve(event.len() + 1);
    for &byte in event {
        match byte {
            b'\n' => line.extend_from_slice(b"\\n"),
            0 => line.extend_from_slice(b"\\0"),
            _ => line.push(byte),
        }
    }
    line.push(b'\n');
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_line_escapes_line_feed_and_nul() {
        let line = journal_line(Level::WARN, b"a\nb\0c\\d\n");
        assert_eq!(line, b"<4>a\\nb\\0c\\d\n");
    }

    #[test]
    fn journal_line_ends_with_exactly_one_line_feed() {
        assert_eq!(journal_line(Level::INFO, b"msg"), b"<6>msg\n");
        assert_eq!(journal_line(Level::INFO, b"msg\n"), b"<6>msg\n");
        assert_eq!(journal_line(Level::INFO, b"msg\n\n"), b"<6>msg\\n\n");
    }

    #[test]
    fn syslog_priorities() {
        assert_eq!(syslog_priority(Level::ERROR), 3);
        assert_eq!(syslog_priority(Level::WARN), 4);
        assert_eq!(syslog_priority(Level::INFO), 6);
        assert_eq!(syslog_priority(Level::DEBUG), 7);
        assert_eq!(syslog_priority(Level::TRACE), 7);
    }

    #[cfg(unix)]
    mod journal_detection {
        use std::ffi::OsStr;

        use super::super::matches_journal_stream;

        const STDOUT: Option<(u64, u64)> = Some((12, 34));
        const STDERR: Option<(u64, u64)> = Some((56, 78));

        fn matches(value: Option<&str>) -> bool {
            matches_journal_stream(value.map(OsStr::new), STDOUT, STDERR)
        }

        #[test]
        fn matching_stdout() {
            assert!(matches(Some("12:34")));
        }

        #[test]
        fn matching_stderr_only() {
            assert!(matches(Some("56:78")));
            assert!(matches_journal_stream(
                Some(OsStr::new("56:78")),
                None,
                STDERR
            ));
        }

        #[test]
        fn mismatch() {
            assert!(!matches(Some("12:78")));
            assert!(!matches(Some("1:1")));
            assert!(!matches_journal_stream(
                Some(OsStr::new("12:34")),
                None,
                None
            ));
        }

        #[test]
        fn malformed() {
            for value in [
                "12", "a:b", "1:2:3", "12:34:", ":34", "12:", "+12:34", " 12:34", "",
            ] {
                assert!(!matches(Some(value)), "{value:?} must not match");
            }
        }

        #[test]
        fn unset() {
            assert!(!matches(None));
        }
    }

    /// Tests that set logging up as `main` does. Each one re-runs this test
    /// binary for itself alone as a child, with standard output redirected to
    /// a temporary file and its own environment, so that this process's
    /// environment, global subscriber and panic hook stay untouched.
    #[cfg(unix)]
    mod child {
        use std::io::{Read, Seek, SeekFrom};
        use std::os::unix::fs::MetadataExt;
        use std::process::{Command, Stdio};

        use tracing::{debug, error, info, warn};

        use super::super::{init_tracing, output_is_journal};

        /// Set in the child's environment; the child sets logging up and
        /// emits events instead of starting another child.
        const CHILD_ENV: &str = "CRUSHER_LOGGING_TEST_CHILD";

        enum JournalStream {
            /// `JOURNAL_STREAM` names the child's standard output.
            Matching,
            /// `JOURNAL_STREAM` names neither standard output nor standard
            /// error.
            NotMatching,
            /// `JOURNAL_STREAM` is not set.
            Unset,
        }

        struct ChildOutput {
            /// Lines the child wrote to standard output, without libtest's.
            log_lines: Vec<String>,
            stderr: Vec<u8>,
        }

        fn in_child() -> bool {
            std::env::var_os(CHILD_ENV).is_some()
        }

        fn init_child_logging() {
            let journal = output_is_journal(std::env::var_os("JOURNAL_STREAM").as_deref());
            init_tracing(journal).expect("no subscriber has been set in the child");
        }

        /// Runs the test `name` of this binary as a child and returns what
        /// it wrote, after asserting that it ran exactly this one test and
        /// passed.
        fn run_child(
            name: &str,
            journal_stream: &JournalStream,
            rust_log: Option<&str>,
        ) -> ChildOutput {
            let mut stdout_file = tempfile::tempfile().expect("create stdout file");
            let metadata = stdout_file.metadata().expect("stat stdout file");

            let mut command = Command::new(std::env::current_exe().expect("current test binary"));
            command
                .args([name, "--exact", "--nocapture", "--test-threads=1"])
                .env(CHILD_ENV, "1")
                .stdin(Stdio::null())
                .stdout(stdout_file.try_clone().expect("clone stdout file"))
                .stderr(Stdio::piped());
            match journal_stream {
                JournalStream::Matching => {
                    command.env(
                        "JOURNAL_STREAM",
                        format!("{}:{}", metadata.dev(), metadata.ino()),
                    );
                }
                JournalStream::NotMatching => {
                    command.env(
                        "JOURNAL_STREAM",
                        format!("{}:{}", metadata.dev(), metadata.ino().wrapping_add(1)),
                    );
                }
                JournalStream::Unset => {
                    command.env_remove("JOURNAL_STREAM");
                }
            }
            match rust_log {
                Some(value) => command.env("RUST_LOG", value),
                None => command.env_remove("RUST_LOG"),
            };
            let output = command.output().expect("run child test");
            stdout_file
                .seek(SeekFrom::Start(0))
                .expect("rewind stdout file");
            let mut stdout = String::new();
            stdout_file
                .read_to_string(&mut stdout)
                .expect("read stdout file");

            assert!(
                output.status.success(),
                "child failed: {}\nstdout:\n{stdout}\nstderr:\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
            let (libtest, log_lines) = split_libtest_lines(&stdout, name);
            assert!(
                libtest.iter().any(|line| line == "running 1 test"),
                "child must run exactly one test:\n{stdout}"
            );
            assert!(
                libtest
                    .iter()
                    .any(|line| line.starts_with("test result: ok. 1 passed; 0 failed;")),
                "child must pass exactly one test:\n{stdout}"
            );
            ChildOutput {
                log_lines,
                stderr: output.stderr,
            }
        }

        /// Splits the child's standard output into libtest's own lines and
        /// the lines logging wrote.
        fn split_libtest_lines(stdout: &str, name: &str) -> (Vec<String>, Vec<String>) {
            let test_line = format!("test {name} ... ");
            let mut libtest = Vec::new();
            let mut log_lines = Vec::new();
            for line in stdout.lines() {
                if line.is_empty()
                    || line.starts_with("running ")
                    || line.starts_with("test result: ")
                    || line == format!("test {name} ... ok")
                {
                    libtest.push(line.to_string());
                } else if let Some(rest) = line.strip_prefix(&test_line) {
                    // libtest writes the test name before running it, so the
                    // first log line follows it on the same line.
                    libtest.push(test_line.trim_end().to_string());
                    log_lines.push(rest.to_string());
                } else if line == "ok" {
                    libtest.push(line.to_string());
                } else {
                    log_lines.push(line.to_string());
                }
            }
            (libtest, log_lines)
        }

        fn emit_each_level() {
            init_child_logging();
            error!("level check error");
            warn!("level check warn");
            info!("level check info");
            debug!("level check debug");
        }

        fn line_with<'a>(lines: &'a [String], needle: &str) -> Option<&'a String> {
            let mut found = lines.iter().filter(|line| line.contains(needle));
            let line = found.next();
            assert!(
                found.next().is_none(),
                "more than one line contains {needle:?}"
            );
            line
        }

        fn assert_journal_lines(lines: &[String]) {
            for line in lines {
                assert!(
                    ["<3>", "<4>", "<6>", "<7>"]
                        .iter()
                        .any(|prefix| line.starts_with(prefix)),
                    "journal line without a priority prefix: {line:?}"
                );
                assert!(!line.contains('\x1b'), "ESC in journal line: {line:?}");
                let after_prefix = &line[3..];
                assert!(
                    !after_prefix.starts_with(|c: char| c.is_ascii_digit()),
                    "timestamp in journal line: {line:?}"
                );
            }
        }

        #[test]
        fn journal_output_prefixes_each_level() {
            if in_child() {
                emit_each_level();
                return;
            }
            let output = run_child(
                "logging::tests::child::journal_output_prefixes_each_level",
                &JournalStream::Matching,
                Some("debug"),
            );
            assert_journal_lines(&output.log_lines);
            for (needle, prefix) in [
                ("level check error", "<3>"),
                ("level check warn", "<4>"),
                ("level check info", "<6>"),
                ("level check debug", "<7>"),
            ] {
                let line = line_with(&output.log_lines, needle)
                    .unwrap_or_else(|| panic!("no line contains {needle:?}"));
                assert!(
                    line.starts_with(prefix),
                    "{needle:?} not at {prefix}: {line:?}"
                );
            }
            assert!(output.stderr.is_empty(), "stderr: {:?}", output.stderr);
        }

        #[test]
        fn info_is_the_default_level() {
            if in_child() {
                emit_each_level();
                return;
            }
            let output = run_child(
                "logging::tests::child::info_is_the_default_level",
                &JournalStream::Matching,
                None,
            );
            assert_journal_lines(&output.log_lines);
            assert!(line_with(&output.log_lines, "level check info").is_some());
            assert!(line_with(&output.log_lines, "level check debug").is_none());
        }

        #[test]
        fn rust_log_overrides_the_level() {
            if in_child() {
                emit_each_level();
                return;
            }
            let output = run_child(
                "logging::tests::child::rust_log_overrides_the_level",
                &JournalStream::Matching,
                Some("warn"),
            );
            assert_journal_lines(&output.log_lines);
            assert!(line_with(&output.log_lines, "level check warn").is_some());
            assert!(line_with(&output.log_lines, "level check info").is_none());
        }

        #[test]
        fn journal_event_is_one_escaped_line() {
            if in_child() {
                init_child_logging();
                info!("first line\nsecond line\0after nul \\ backslash");
                return;
            }
            let output = run_child(
                "logging::tests::child::journal_event_is_one_escaped_line",
                &JournalStream::Matching,
                None,
            );
            assert_journal_lines(&output.log_lines);
            let line = line_with(&output.log_lines, "first line").expect("event line");
            assert!(line.starts_with("<6>"), "{line:?}");
            assert!(
                line.ends_with(r"first line\nsecond line\0after nul \ backslash"),
                "{line:?}"
            );
            assert!(line_with(&output.log_lines, "second line").is_some());
        }

        fn assert_plain_output(journal_stream: &JournalStream, name: &str) {
            let output = run_child(name, journal_stream, None);
            let line = line_with(&output.log_lines, "plain output check").expect("event line");
            assert!(
                !line.starts_with('<'),
                "priority prefix outside the journal: {line:?}"
            );
            assert!(
                line.starts_with(|c: char| c.is_ascii_digit()),
                "timestamp missing outside the journal: {line:?}"
            );
            for line in &output.log_lines {
                assert!(!line.contains('\x1b'), "ESC written to a file: {line:?}");
            }
        }

        #[test]
        fn non_matching_journal_stream_is_plain_output() {
            if in_child() {
                init_child_logging();
                info!("plain output check");
                return;
            }
            assert_plain_output(
                &JournalStream::NotMatching,
                "logging::tests::child::non_matching_journal_stream_is_plain_output",
            );
        }

        #[test]
        fn unset_journal_stream_is_plain_output() {
            if in_child() {
                init_child_logging();
                info!("plain output check");
                return;
            }
            assert_plain_output(
                &JournalStream::Unset,
                "logging::tests::child::unset_journal_stream_is_plain_output",
            );
        }

        #[test]
        fn journal_panic_is_one_error_line() {
            if in_child() {
                init_child_logging();
                let result = std::thread::Builder::new()
                    .name("journal-panic".to_string())
                    .spawn(|| panic!("journal panic message"))
                    .expect("spawn thread")
                    .join();
                assert!(result.is_err(), "the thread must panic");
                return;
            }
            let output = run_child(
                "logging::tests::child::journal_panic_is_one_error_line",
                &JournalStream::Matching,
                None,
            );
            assert_journal_lines(&output.log_lines);
            let line = line_with(&output.log_lines, "journal panic message").expect("panic line");
            assert!(line.starts_with("<3>"), "{line:?}");
            assert!(
                line.contains("'journal-panic'"),
                "thread name missing: {line:?}"
            );
            assert!(
                line.contains(&format!("{}:", file!())),
                "location missing: {line:?}"
            );
            assert!(
                output.stderr.is_empty(),
                "stderr: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
