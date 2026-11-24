use std::{collections::HashMap, fs::File, io::BufReader, path::Path};

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};
use tracing::info;

/// Every write generation is below this, so that it is exact as an `f64`
/// element of a time series.
pub(super) const GENERATION_LIMIT: u64 = 1 << 53;

const TIMESTAMP_FIELD: &str = "timestamp";
const GENERATION_FIELD: &str = "generation";

/// What the checkpoint file holds for one policy.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct Checkpoint {
    /// The largest acknowledged window start, in Unix nanoseconds: where the
    /// policy's next request resumes.
    pub(super) timestamp: Option<i64>,
    /// The write generation of the policy's latest request, in Unix
    /// milliseconds. Once written it is never removed, so that a later request
    /// always gets a larger one.
    pub(super) generation: Option<u64>,
}

impl Checkpoint {
    pub(super) fn is_empty(&self) -> bool {
        self.timestamp.is_none() && self.generation.is_none()
    }

    fn to_json(self) -> Value {
        let mut fields = Map::new();
        if let Some(timestamp) = self.timestamp {
            fields.insert(TIMESTAMP_FIELD.to_owned(), Value::from(timestamp));
        }
        if let Some(generation) = self.generation {
            fields.insert(GENERATION_FIELD.to_owned(), Value::from(generation));
        }
        Value::Object(fields)
    }

    fn from_json(id: &str, value: &Value) -> Result<Self> {
        let Value::Object(fields) = value else {
            bail!("the checkpoint of policy {id} is not an object");
        };
        let mut checkpoint = Self::default();
        for (field, value) in fields {
            match field.as_str() {
                TIMESTAMP_FIELD => {
                    let Some(timestamp) = value.as_i64() else {
                        bail!("the timestamp of policy {id} is not an integer in the i64 range");
                    };
                    checkpoint.timestamp = Some(timestamp);
                }
                GENERATION_FIELD => {
                    let Some(generation) = value
                        .as_u64()
                        .filter(|generation| *generation < GENERATION_LIMIT)
                    else {
                        bail!(
                            "the generation of policy {id} is not a non-negative integer below \
                             2^53"
                        );
                    };
                    checkpoint.generation = Some(generation);
                }
                _ => bail!("the checkpoint of policy {id} has an unknown field {field:?}"),
            }
        }
        Ok(checkpoint)
    }
}

/// The checkpoint of each policy, by policy id.
pub(super) type Checkpoints = HashMap<String, Checkpoint>;

/// Atomically writes the checkpoints to the given path by writing to a
/// temporary file in the same directory, flushing it to disk, renaming it over
/// the target path, and then flushing the directory. This prevents partial
/// writes on crash, and a written generation is on disk before any row of it
/// is sent.
pub(super) async fn write_timestamp_file(path: &Path, data: &Checkpoints) -> Result<()> {
    let path = path.to_path_buf();
    let json = to_json(data);
    tokio::task::spawn_blocking(move || atomic_write_timestamp_file(&path, &json))
        .await
        .context("timestamp file writer task panicked")?
}

/// Returns the file's JSON: an object of each policy's fields, without the
/// policies that have neither.
fn to_json(data: &Checkpoints) -> Value {
    Value::Object(
        data.iter()
            .filter(|(_, checkpoint)| !checkpoint.is_empty())
            .map(|(id, checkpoint)| (id.clone(), checkpoint.to_json()))
            .collect(),
    )
}

fn atomic_write_timestamp_file(path: &Path, data: &Value) -> Result<()> {
    use std::io::Write;

    let dir = path
        .parent()
        .context("timestamp file has no parent directory")?;
    // A bare file name has an empty parent: the working directory.
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
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
    // The rename is durable only once the directory is. A replacement lost
    // to a power failure after rows of its generation were sent would let a
    // restart with the clock set back fix that generation again.
    File::open(dir)
        .and_then(|dir| dir.sync_all())
        .with_context(|| format!("Failed to sync timestamp file directory {}", dir.display()))?;
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

/// Reads the checkpoint file, creating it as `{}` if it is missing.
///
/// Each policy's value must be an object with at most the fields
/// `timestamp`, an integer in the `i64` range, and `generation`, a
/// non-negative integer below 2^53. A value without either is accepted and
/// dropped.
pub(super) fn read_last_timestamp(last_series_time_path: &Path) -> Result<Checkpoints> {
    ensure_time_data_exists(last_series_time_path)?;
    let file = File::open(last_series_time_path)
        .context("Failed to open last time series timestamp file")?;
    let json: serde_json::Value = serde_json::from_reader(BufReader::new(file))?;
    let Value::Object(map_data) = json else {
        bail!("Failed to parse json data, invalid json format");
    };
    let mut parsed = Checkpoints::with_capacity(map_data.len());
    for (key, val) in map_data {
        let checkpoint = Checkpoint::from_json(&key, &val)
            .context("Failed to parse timestamp data, invalid checkpoint")?;
        if !checkpoint.is_empty() {
            parsed.insert(key, checkpoint);
        }
    }
    Ok(parsed)
}
