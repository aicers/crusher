use std::{collections::HashMap, fs::File, io::BufReader, path::Path};

use anyhow::{Context, Result, bail};
use serde_json::Value;
use tracing::info;

/// Atomically writes the timestamp map to the given path by writing
/// to a temporary file in the same directory, flushing to disk, and
/// then renaming over the target path. This prevents partial writes
/// on crash.
pub(super) async fn write_timestamp_file(path: &Path, data: HashMap<String, i64>) -> Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || atomic_write_timestamp_file(&path, &data))
        .await
        .context("timestamp file writer task panicked")?
}

fn atomic_write_timestamp_file(path: &Path, data: &HashMap<String, i64>) -> Result<()> {
    use std::io::Write;

    let dir = path
        .parent()
        .context("timestamp file has no parent directory")?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir)
        .context("Failed to create temporary timestamp file")?;
    serde_json::to_writer(&mut tmp, data)
        .context("Failed to write timestamp data to temporary file")?;
    tmp.as_file_mut()
        .flush()
        .context("Failed to flush temporary timestamp file")?;
    tmp.as_file_mut()
        .sync_all()
        .context("Failed to sync temporary timestamp file")?;
    tmp.persist(path)
        .context("Failed to atomically replace timestamp file")?;
    Ok(())
}

/// Ensures the timestamp data file exists at the given path.
///
/// If the file already exists, this is a no-op. If it is missing, an
/// empty JSON object (`{}`) is written so that subsequent reads and
/// writes succeed.
///
/// # Errors
///
/// Returns an error if the file cannot be created (e.g. the parent
/// directory does not exist or a permission error occurs).
fn ensure_time_data_exists(path: &Path) -> std::io::Result<()> {
    match File::open(path) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            info!(
                "Timestamp data file not found; creating: {}",
                path.display()
            );
            std::fs::write(path, b"{}")
        }
        Err(e) => Err(e),
    }
}

pub(super) fn read_last_timestamp(last_series_time_path: &Path) -> Result<HashMap<String, i64>> {
    ensure_time_data_exists(last_series_time_path)?;
    let file = File::open(last_series_time_path)
        .context("Failed to open last time series timestamp file")?;
    let json: serde_json::Value = serde_json::from_reader(BufReader::new(file))?;
    let Value::Object(map_data) = json else {
        bail!("Failed to parse json data, invalid json format");
    };
    let mut parsed: HashMap<String, i64> = HashMap::with_capacity(map_data.len());
    for (key, val) in map_data {
        let Value::Number(value) = val else {
            bail!("Failed to parse timestamp data, invalid json format");
        };
        let Some(timestamp_nanos) = value.as_i64() else {
            bail!("Failed to convert timestamp data, invalid time data");
        };
        parsed.insert(key, timestamp_nanos);
    }
    Ok(parsed)
}
