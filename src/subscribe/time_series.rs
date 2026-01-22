use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter},
    path::{Path, PathBuf},
    sync::LazyLock,
};

use anyhow::{Context, Result, bail};
use async_channel::{Receiver, Sender};
use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Timelike, Utc};
use review_protocol::types::SamplingPolicy;
use serde::Serialize;
use serde_json::Value;
use tokio::sync::RwLock;

use super::{Event, INGEST_CHANNEL};

const SECOND_TO_NANO: i64 = 1_000_000_000;

// A hashmap for last series timestamp
static LAST_TRANSFER_TIME: LazyLock<RwLock<HashMap<String, i64>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

#[async_trait]
pub(super) trait SamplingPolicyExt {
    async fn start_timestamp(&self) -> Result<i64>;
}

#[async_trait]
impl SamplingPolicyExt for SamplingPolicy {
    async fn start_timestamp(&self) -> Result<i64> {
        let mut start: i64 = 0;
        if let Some(last_time) = LAST_TRANSFER_TIME.read().await.get(&self.id.to_string()) {
            let period = i64::try_from(self.period.as_secs())?;
            let Some(period_nano) = period.checked_mul(SECOND_TO_NANO) else {
                bail!("Failed to convert period to nanoseconds");
            };
            if let Some(last_timestamp) = last_time.checked_add(period_nano) {
                start = last_timestamp;
            }
        }
        Ok(start)
    }
}

#[cfg_attr(test, derive(serde::Deserialize))]
#[derive(Default, Clone, Debug, Serialize)]
pub(super) struct TimeSeries {
    pub(super) sampling_policy_id: String,
    #[serde(skip)]
    pub(super) start: DateTime<Utc>,
    pub(super) series: Vec<f64>,
}

impl TimeSeries {
    pub(super) async fn try_new(policy: &SamplingPolicy) -> Result<Self> {
        let start = Utc.timestamp_nanos(policy.start_timestamp().await?);
        let len = usize::try_from(policy.period.as_secs() / policy.interval.as_secs())?;
        let series = vec![0_f64; len];
        Ok(TimeSeries {
            sampling_policy_id: policy.id.to_string(),
            start,
            series,
        })
    }
    pub(super) async fn fill(
        &mut self,
        policy: &SamplingPolicy,
        time: DateTime<Utc>,
        event: &Event,
        send_channel: &Sender<TimeSeries>,
    ) -> Result<()> {
        let period = i64::try_from(policy.period.as_secs())?;

        if time.timestamp() - self.start.timestamp() > period {
            if let Some(sender) = INGEST_CHANNEL.read().await.get(&self.sampling_policy_id) {
                sender.send(self.clone()).await?;
            } else {
                send_channel.send(self.clone()).await?;
            }
            self.start = start_time(policy, time)?;
            self.series.fill(0_f64);
        }

        let time_slot = time_slot(policy, time)?;
        let Some(value) = self.series.get_mut(time_slot) else {
            bail!("cannot access the time slot");
        };
        *value += event_value(policy.column, event);

        Ok(())
    }
}

fn time_slot(policy: &SamplingPolicy, time: DateTime<Utc>) -> Result<usize> {
    let offset_time = time.timestamp() + i64::from(policy.offset);
    let Some(offset_time) = DateTime::from_timestamp(offset_time, 0) else {
        bail!("failed to create DateTime<Utc> from timestamp");
    };

    let seconds_of_day =
        offset_time.hour() * 3600 + offset_time.minute() * 60 + offset_time.second();
    let interval = u32::try_from(policy.interval.as_secs())?;
    let period = u32::try_from(policy.period.as_secs())?;
    let time_slot = seconds_of_day % period / interval;
    Ok(usize::try_from(time_slot)?)
}

fn event_value(sum_column: Option<u32>, event: &Event) -> f64 {
    let Some(column) = sum_column else {
        return 1_f64; // in order to increase the number of events
    };
    event.column_value(column)
}

fn start_time(policy: &SamplingPolicy, time: DateTime<Utc>) -> Result<DateTime<Utc>> {
    let offset = i64::from(policy.offset);
    let offset_time = time.timestamp() + offset;
    let Some(offset_time) = DateTime::from_timestamp(offset_time, 0) else {
        bail!("failed to create DateTime<Utc> from timestamp");
    };

    let seconds_of_day =
        offset_time.hour() * 3600 + offset_time.minute() * 60 + offset_time.second();
    let timestamp_of_midnight = offset_time.timestamp() - i64::from(seconds_of_day);

    let period = u32::try_from(policy.period.as_secs())?;
    let start_of_period = seconds_of_day / period * period;
    let start_offset_time = timestamp_of_midnight + i64::from(start_of_period);

    let Some(datetime) = DateTime::from_timestamp(start_offset_time - offset, 0) else {
        bail!("failed to create DateTime<Utc> from timestamp");
    };

    Ok(datetime)
}

pub(super) async fn write_last_timestamp(
    last_series_time_path: PathBuf,
    time_receiver: Receiver<(String, i64)>,
) -> Result<()> {
    while let Ok((id, timestamp)) = time_receiver.recv().await {
        LAST_TRANSFER_TIME.write().await.insert(id, timestamp);
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&last_series_time_path)
            .context("Failed to open last time series timestamp file")?;
        serde_json::to_writer(&file, &(*LAST_TRANSFER_TIME.read().await))
            .context("Failed to write last time series timestamp file")?;
    }
    Ok(())
}

pub(super) async fn read_last_timestamp(last_series_time_path: &Path) -> Result<()> {
    if last_series_time_path.exists() {
        let file = File::open(last_series_time_path)
            .context("Failed to open last time series timestamp file")?;
        let json: serde_json::Value = serde_json::from_reader(BufReader::new(file))?;
        let Value::Object(map_data) = json else {
            bail!("Failed to parse json data, invalid json format");
        };
        for (key, val) in map_data {
            let Value::Number(value) = val else {
                bail!("Failed to parse timestamp data, invalid json format");
            };
            let Some(timestamp) = value.as_i64() else {
                bail!("Failed to convert timestamp data, invalid time data");
            };
            LAST_TRANSFER_TIME.write().await.insert(key, timestamp);
        }
    }
    Ok(())
}

pub(super) fn delete_last_timestamp(last_series_time_path: &Path, id: u32) -> Result<()> {
    let file = File::open(last_series_time_path)?;
    let id = format!("{id}");
    let mut json: serde_json::Value = serde_json::from_reader(BufReader::new(file))?;
    if let Value::Object(ref mut map_data) = json {
        map_data.remove(&id);
    }
    let file = File::create(last_series_time_path)?;
    serde_json::to_writer(BufWriter::new(file), &json)?;

    Ok(())
}

#[cfg(test)]
pub(super) async fn clear_last_transfer_time() {
    LAST_TRANSFER_TIME.write().await.clear();
}

#[cfg(test)]
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::float_cmp
)]
mod tests {
    use std::io::Write;
    use std::time::Duration;

    use chrono::NaiveDateTime;
    use review_protocol::types::{SamplingKind, SamplingPolicy};
    use serial_test::serial;
    use tempfile::tempdir;

    use super::*;

    const SECS_PER_MINUTE: u64 = 60;
    const SECS_PER_HOUR: u64 = 3600;
    const SECS_PER_DAY: u64 = 86_400;

    /// Helper to create a `SamplingPolicy` with specified parameters
    fn create_policy(
        id: u32,
        period_secs: u64,
        interval_secs: u64,
        offset: i32,
        column: Option<u32>,
    ) -> SamplingPolicy {
        SamplingPolicy {
            id,
            kind: SamplingKind::Conn,
            interval: Duration::from_secs(interval_secs),
            period: Duration::from_secs(period_secs),
            offset,
            src_ip: None,
            dst_ip: None,
            node: Some("test_node".to_string()),
            column,
        }
    }

    /// Helper to create `DateTime`<Utc> from unix timestamp
    fn datetime_from_timestamp(timestamp: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(timestamp, 0).expect("valid timestamp")
    }

    /// Helper to create `DateTime`<Utc> from a specific UTC date/time string
    fn datetime_from_utc(input: &str) -> DateTime<Utc> {
        let naive = NaiveDateTime::parse_from_str(input, "%Y/%m/%d %H:%M:%S")
            .or_else(|_| NaiveDateTime::parse_from_str(input, "%Y/%-m/%-d %H:%M:%S"))
            .expect("valid datetime");
        DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc)
    }

    // =========================================================================
    // Tests for time_slot function - boundary conditions for period/interval/offset
    // =========================================================================

    #[test]
    fn test_time_slot_basic_1day_period_15min_interval() {
        // Period: 1 day (86400s), Interval: 15 min (900s) => 96 slots
        // Offset: 0
        let policy = create_policy(1, SECS_PER_DAY, 15 * SECS_PER_MINUTE, 0, None);

        // Before midnight => last slot (95)
        let before_midnight = datetime_from_utc("2024/1/14 23:59:59");
        assert_eq!(time_slot(&policy, before_midnight).unwrap(), 95);

        // Midnight UTC => slot 0
        let midnight = datetime_from_utc("2024/1/15 00:00:00");
        assert_eq!(time_slot(&policy, midnight).unwrap(), 0);

        // 00:14:59 => still slot 0
        let just_before_slot_1 = datetime_from_utc("2024/1/15 00:14:59");
        assert_eq!(time_slot(&policy, just_before_slot_1).unwrap(), 0);

        // 00:15:00 => slot 1
        let exactly_slot_1 = datetime_from_utc("2024/1/15 00:15:00");
        assert_eq!(time_slot(&policy, exactly_slot_1).unwrap(), 1);

        // 00:15:01 => still slot 1
        let just_after_slot_1 = datetime_from_utc("2024/1/15 00:15:01");
        assert_eq!(time_slot(&policy, just_after_slot_1).unwrap(), 1);

        // 23:45:00 => slot 95 (last slot)
        let last_slot = datetime_from_utc("2024/1/15 23:45:00");
        assert_eq!(time_slot(&policy, last_slot).unwrap(), 95);

        // 23:59:59 => still slot 95
        let end_of_day = datetime_from_utc("2024/1/15 23:59:59");
        assert_eq!(time_slot(&policy, end_of_day).unwrap(), 95);

        // Next day => slot 0
        let next_day = datetime_from_utc("2024/1/16 00:00:00");
        assert_eq!(time_slot(&policy, next_day).unwrap(), 0);
    }

    #[test]
    fn test_time_slot_with_positive_offset() {
        // Period: 1 day (86400s), Interval: 1 hour (3600s) => 24 slots
        // Offset: +9 hours (32400s) - KST adjustment
        let policy = create_policy(1, SECS_PER_DAY, SECS_PER_HOUR, 32_400, None);
        let kst_midnight_utc = datetime_from_utc("2024/1/14 15:00:00");

        // KST midnight (UTC 15:00) => slot 0
        assert_eq!(time_slot(&policy, kst_midnight_utc).unwrap(), 0);

        // KST 09:00(UTC 00:00) => slot 9
        let kst_9am_utc = datetime_from_utc("2024/1/15 00:00:00");
        assert_eq!(time_slot(&policy, kst_9am_utc).unwrap(), 9);

        // KST 23:59:59(UTC 14:59:59) => slot 23
        let kst_end_of_day_utc = datetime_from_utc("2024/1/15 14:59:59");
        assert_eq!(time_slot(&policy, kst_end_of_day_utc).unwrap(), 23);
    }

    #[test]
    fn test_time_slot_with_negative_offset() {
        // Period: 1 day (86400s), Interval: 1 hour (3600s) => 24 slots
        // Offset: -5 hours (-18000s) - shifts time backward
        let policy = create_policy(1, SECS_PER_DAY, SECS_PER_HOUR, -18_000, None);

        // At midnight UTC, with -5h offset, offset_time = 19:00 (prev day) => slot 19
        let midnight = datetime_from_utc("2024/1/15 00:00:00");
        assert_eq!(time_slot(&policy, midnight).unwrap(), 19);

        // At 05:00 UTC, with -5h offset, offset_time = 00:00 => slot 0
        let utc_5h = datetime_from_utc("2024/1/15 05:00:00");
        assert_eq!(time_slot(&policy, utc_5h).unwrap(), 0);
    }

    #[test]
    fn test_time_slot_interval_equals_period() {
        // Period: 1 hour (3600s), Interval: 1 hour (3600s) => 1 slot
        // All times within the period should map to slot 0
        let policy = create_policy(1, SECS_PER_HOUR, SECS_PER_HOUR, 0, None);

        let midnight = datetime_from_utc("2024/1/15 00:00:00");

        // Any time within the hour should be slot 0
        assert_eq!(time_slot(&policy, midnight).unwrap(), 0);
        assert_eq!(
            time_slot(&policy, datetime_from_utc("2024/1/15 00:30:00")).unwrap(),
            0
        );
        assert_eq!(
            time_slot(&policy, datetime_from_utc("2024/1/15 00:59:59")).unwrap(),
            0
        );
    }

    #[test]
    fn test_time_slot_interval_1second() {
        // Period: 1 minute (60s), Interval: 1 second (1s) => 60 slots
        // Tests minimum interval
        let policy = create_policy(1, SECS_PER_MINUTE, 1, 0, None);

        let midnight = datetime_from_utc("2024/1/15 00:00:00");

        // Each second should be its own slot
        assert_eq!(time_slot(&policy, midnight).unwrap(), 0);
        assert_eq!(
            time_slot(&policy, datetime_from_utc("2024/1/15 00:00:01")).unwrap(),
            1
        );
        assert_eq!(
            time_slot(&policy, datetime_from_utc("2024/1/15 00:00:59")).unwrap(),
            59
        );
    }

    #[test]
    fn test_time_slot_offset_equals_period_minus_one() {
        // Period: 1 hour (3600s), Interval: 15 min (900s) => 4 slots
        // Offset: period - 1 = 3599s
        let policy = create_policy(1, SECS_PER_HOUR, 15 * SECS_PER_MINUTE, 3599, None);

        let midnight = datetime_from_utc("2024/1/15 00:00:00");
        // At midnight UTC, offset_time = 00:59:59 => slot 3 (59*60+59 = 3599s) / 900 = 3
        // Actually: seconds_of_day = 3599, 3599 % 3600 = 3599, 3599 / 900 = 3
        assert_eq!(time_slot(&policy, midnight).unwrap(), 3);
    }

    #[test]
    fn test_time_slot_offset_in_middle_of_period() {
        // Period: 2 hours (7200s), Interval: 30 min (1800s) => 4 slots
        // Offset: 1 hour (3600s) - middle of period
        let policy = create_policy(1, 2 * SECS_PER_HOUR, 30 * SECS_PER_MINUTE, 3600, None);

        let midnight = datetime_from_utc("2024/1/15 00:00:00");
        // At midnight UTC, offset_time = 01:00:00 => seconds_of_day = 3600
        // 3600 % 7200 = 3600, 3600 / 1800 = 2 => slot 2
        assert_eq!(time_slot(&policy, midnight).unwrap(), 2);

        // At 01:00 UTC, offset_time = 02:00:00 => seconds_of_day = 7200
        // 7200 % 7200 = 0, 0 / 1800 = 0 => slot 0
        let utc_1h = datetime_from_utc("2024/1/15 01:00:00");
        assert_eq!(time_slot(&policy, utc_1h).unwrap(), 0);
    }

    // =========================================================================
    // Tests for start_time function
    // =========================================================================

    #[test]
    fn test_start_time_aligns_to_period_boundary() {
        // Period: 1 hour (3600s), Interval: 15 min (900s)
        // Offset: 0
        let policy = create_policy(1, SECS_PER_HOUR, 15 * SECS_PER_MINUTE, 0, None);

        let expected_results = [
            ("2024/1/14 23:59:59", "2024/1/14 23:00:00"),
            ("2024/1/15 00:00:00", "2024/1/15 00:00:00"),
            ("2024/1/15 00:14:59", "2024/1/15 00:00:00"),
            ("2024/1/15 00:15:00", "2024/1/15 00:00:00"),
            ("2024/1/15 00:15:01", "2024/1/15 00:00:00"),
            ("2024/1/15 00:29:59", "2024/1/15 00:00:00"),
            ("2024/1/15 00:30:00", "2024/1/15 00:00:00"),
            ("2024/1/15 00:30:01", "2024/1/15 00:00:00"),
            ("2024/1/15 00:44:59", "2024/1/15 00:00:00"),
            ("2024/1/15 00:45:00", "2024/1/15 00:00:00"),
            ("2024/1/15 00:45:01", "2024/1/15 00:00:00"),
            ("2024/1/15 00:59:59", "2024/1/15 00:00:00"),
            ("2024/1/15 01:00:00", "2024/1/15 01:00:00"),
            ("2024/1/15 01:00:01", "2024/1/15 01:00:00"),
            ("2024/1/15 01:30:00", "2024/1/15 01:00:00"),
        ];

        for (time, expected_period_start_time) in expected_results {
            let time = datetime_from_utc(time);
            let expected_start_time = datetime_from_utc(expected_period_start_time);
            let actual_start_time = start_time(&policy, time).expect("Period Start Time");

            assert_eq!(actual_start_time, expected_start_time);
        }
    }

    #[test]
    fn test_start_time_with_offset() {
        // Period: 1 day (86400s), Interval: 1 hour (3600s)
        // Offset: +9 hours (32400s) - KST adjustment
        let policy = create_policy(1, SECS_PER_DAY, SECS_PER_HOUR, 32_400, None);

        let kst_midnight_utc = datetime_from_utc("2024/1/14 15:00:00");

        // For KST 00:30 (UTC 15:30), start is KST midnight (UTC 15:00)
        let kst_0030_utc = datetime_from_utc("2024/1/14 15:30:00");
        let start = start_time(&policy, kst_0030_utc).unwrap();
        assert_eq!(start.timestamp(), kst_midnight_utc.timestamp());
    }

    // =========================================================================
    // Tests for JSON timestamp persistence (read/write/delete)
    // =========================================================================

    #[tokio::test]
    async fn test_write_last_timestamp_creates_file() {
        let dir = tempdir().expect("Success creating temp dir");
        let file_path = dir.path().join("timestamps.json");

        // Use unique keys with random component to avoid interference
        let unique_id = format!(
            "{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let key1 = format!("write_creates_1_{unique_id}");
        let key2 = format!("write_creates_2_{unique_id}");

        let (sender, receiver) = async_channel::bounded::<(String, i64)>(10);

        // Start the writer task
        let writer_handle = tokio::spawn(write_last_timestamp(file_path.clone(), receiver));

        // Send some timestamps
        sender
            .send((key1.clone(), 1_000_000_000_i64))
            .await
            .unwrap();
        sender
            .send((key2.clone(), 2_000_000_000_i64))
            .await
            .unwrap();

        // Close sender to end the writer task
        drop(sender);
        let _ = writer_handle
            .await
            .expect("Writer task successfully completed");

        // Verify file was created and contains valid JSON
        let contents = std::fs::read_to_string(&file_path).expect("failed to read file");
        let json: serde_json::Value = serde_json::from_str(&contents).expect("invalid JSON");
        assert!(json.is_object());

        // Verify the in-memory state contains our keys with correct values
        let map = LAST_TRANSFER_TIME.read().await;
        assert_eq!(map.get(&key1), Some(&1_000_000_000_i64));
        assert_eq!(map.get(&key2), Some(&2_000_000_000_i64));
        drop(map);

        // Cleanup: remove our keys from the global state
        LAST_TRANSFER_TIME.write().await.remove(&key1);
        LAST_TRANSFER_TIME.write().await.remove(&key2);
    }

    #[serial]
    #[tokio::test]
    async fn test_write_last_timestamp_updates_existing() {
        let dir = tempdir().expect("failed to create temp dir");
        let file_path = dir.path().join("timestamps.json");

        // Use unique key with random component to avoid interference
        let unique_id = format!(
            "{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let key = format!("write_updates_{unique_id}");

        let (sender, receiver) = async_channel::bounded::<(String, i64)>(10);

        let path_clone = file_path.clone();
        let writer_handle =
            tokio::spawn(async move { write_last_timestamp(path_clone, receiver).await });

        // Send initial timestamp
        sender.send((key.clone(), 1_000_000_000_i64)).await.unwrap();

        // Update with new timestamp
        sender.send((key.clone(), 3_000_000_000_i64)).await.unwrap();

        drop(sender);
        let _ = writer_handle.await;

        // Verify file was created and contains valid JSON
        let contents = std::fs::read_to_string(&file_path).expect("failed to read file");
        let json: serde_json::Value = serde_json::from_str(&contents).expect("invalid JSON");
        assert!(json.is_object());

        // Verify the in-memory state contains the updated value
        let map = LAST_TRANSFER_TIME.read().await;
        assert_eq!(map.get(&key), Some(&3_000_000_000_i64));
        drop(map);

        // Cleanup: remove our key from the global state
        LAST_TRANSFER_TIME.write().await.remove(&key);
    }

    #[serial]
    #[tokio::test]
    async fn test_read_last_timestamp_from_file() {
        let dir = tempdir().expect("failed to create temp dir");
        let file_path = dir.path().join("timestamps.json");

        // Use unique keys to avoid interference with other tests
        let key1 = format!("read_test_policy_{}", std::process::id());
        let key2 = format!("read_test_policy2_{}", std::process::id());
        let json_content = format!("{{\"{key1}\": 1234567890, \"{key2}\": 9876543210}}");

        // Pre-write a JSON file with known content
        let mut file = File::create(&file_path).expect("failed to create file");
        file.write_all(json_content.as_bytes())
            .expect("failed to write");
        drop(file);

        // Remove our keys first if they exist from a previous run
        LAST_TRANSFER_TIME.write().await.remove(&key1);
        LAST_TRANSFER_TIME.write().await.remove(&key2);

        // Read the file
        read_last_timestamp(&file_path)
            .await
            .expect("failed to read");

        // Verify the in-memory state contains our keys
        let map = LAST_TRANSFER_TIME.read().await;
        assert_eq!(map.get(&key1), Some(&1_234_567_890_i64));
        assert_eq!(map.get(&key2), Some(&9_876_543_210_i64));

        // Cleanup
        drop(map);
        LAST_TRANSFER_TIME.write().await.remove(&key1);
        LAST_TRANSFER_TIME.write().await.remove(&key2);
    }

    #[serial]
    #[tokio::test]
    async fn test_read_last_timestamp_nonexistent_file() {
        let dir = tempdir().expect("failed to create temp dir");
        let file_path = dir.path().join("nonexistent.json");
        let unique_key = format!(
            "read_nonexistent_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        // Reading a nonexistent file should succeed (no-op) and not modify the map
        let result = read_last_timestamp(&file_path).await;
        assert!(result.is_ok());
        assert!(LAST_TRANSFER_TIME.read().await.get(&unique_key).is_none());
    }

    #[tokio::test]
    async fn test_read_last_timestamp_invalid_json() {
        let dir = tempdir().expect("failed to create temp dir");
        let file_path = dir.path().join("invalid.json");

        // Write invalid JSON
        let mut file = File::create(&file_path).expect("failed to create file");
        file.write_all(b"not valid json").expect("failed to write");
        drop(file);

        // Reading invalid JSON should fail
        let result = read_last_timestamp(&file_path).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_read_last_timestamp_wrong_format() {
        let dir = tempdir().expect("failed to create temp dir");
        let file_path = dir.path().join("wrong_format.json");

        // Write JSON array instead of object
        let mut file = File::create(&file_path).expect("failed to create file");
        file.write_all(b"[1, 2, 3]").expect("failed to write");
        drop(file);

        // Reading wrong format should fail
        let result = read_last_timestamp(&file_path).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_delete_last_timestamp_removes_entry() {
        let dir = tempdir().expect("failed to create temp dir");
        let file_path = dir.path().join("timestamps.json");

        // Pre-write a JSON file with multiple entries
        let mut file = File::create(&file_path).expect("failed to create file");
        file.write_all(b"{\"1\": 1000, \"2\": 2000, \"3\": 3000}")
            .expect("failed to write");
        drop(file);

        // Delete entry with id=2
        delete_last_timestamp(&file_path, 2).expect("failed to delete");

        // Verify the file contents
        let contents = std::fs::read_to_string(&file_path).expect("failed to read file");
        let json: serde_json::Value = serde_json::from_str(&contents).expect("invalid JSON");
        let map = json.as_object().unwrap();

        assert_eq!(map.len(), 2);
        assert!(map.contains_key("1"));
        assert!(!map.contains_key("2"));
        assert!(map.contains_key("3"));
    }

    #[test]
    fn test_delete_last_timestamp_nonexistent_entry() {
        let dir = tempdir().expect("failed to create temp dir");
        let file_path = dir.path().join("timestamps.json");

        // Pre-write a JSON file
        let mut file = File::create(&file_path).expect("failed to create file");
        file.write_all(b"{\"1\": 1000, \"2\": 2000}")
            .expect("failed to write");
        drop(file);

        // Delete entry with id=99 (doesn't exist)
        delete_last_timestamp(&file_path, 99).expect("should succeed even if entry doesn't exist");

        // Verify original entries are still there
        let contents = std::fs::read_to_string(&file_path).expect("failed to read file");
        let json: serde_json::Value = serde_json::from_str(&contents).expect("invalid JSON");
        let map = json.as_object().unwrap();

        assert_eq!(map.len(), 2);
        assert!(map.contains_key("1"));
        assert!(map.contains_key("2"));
    }

    #[test]
    fn test_delete_last_timestamp_nonexistent_file() {
        let dir = tempdir().expect("failed to create temp dir");
        let file_path = dir.path().join("nonexistent.json");

        // Deleting from nonexistent file should fail
        let result = delete_last_timestamp(&file_path, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_delete_last_timestamp_last_entry() {
        let dir = tempdir().expect("failed to create temp dir");
        let file_path = dir.path().join("timestamps.json");

        // Pre-write a JSON file with single entry
        let mut file = File::create(&file_path).expect("failed to create file");
        file.write_all(b"{\"1\": 1000}").expect("failed to write");
        drop(file);

        // Delete the only entry
        delete_last_timestamp(&file_path, 1).expect("failed to delete");

        // Verify the file is now empty object
        let contents = std::fs::read_to_string(&file_path).expect("failed to read file");
        let json: serde_json::Value = serde_json::from_str(&contents).expect("invalid JSON");
        let map = json.as_object().unwrap();

        assert!(map.is_empty());
    }

    // =========================================================================
    // Tests for event_value function
    // =========================================================================

    #[test]
    fn test_event_value_none_column_returns_1() {
        let conn = create_test_conn();
        let event = Event::Conn(conn);

        // When column is None, should return 1.0 (count events)
        let value = event_value(None, &event);
        assert_eq!(value, 1.0);
    }

    #[test]
    fn test_event_value_conn_columns() {
        let conn = giganto_client::ingest::network::Conn {
            orig_addr: "192.168.1.1".parse().unwrap(),
            resp_addr: "192.168.1.2".parse().unwrap(),
            orig_port: 12345,
            resp_port: 80,
            proto: 6,
            conn_state: "SF".to_string(),
            service: "http".to_string(),
            duration: 1_500_000_000, // 1.5 seconds in nanoseconds
            orig_bytes: 1000,
            resp_bytes: 2000,
            orig_pkts: 10,
            resp_pkts: 20,
            orig_l2_bytes: 1100,
            resp_l2_bytes: 2100,
            start_time: 0,
        };
        let event = Event::Conn(conn);

        // Column 5: duration
        assert_eq!(event_value(Some(5), &event), 1_500_000_000.0);

        // Column 7: orig_bytes
        assert_eq!(event_value(Some(7), &event), 1000.0);

        // Column 8: resp_bytes
        assert_eq!(event_value(Some(8), &event), 2000.0);

        // Column 9: orig_pkts
        assert_eq!(event_value(Some(9), &event), 10.0);

        // Column 10: resp_pkts
        assert_eq!(event_value(Some(10), &event), 20.0);

        // Unknown column should return 1.0
        assert_eq!(event_value(Some(99), &event), 1.0);
    }

    #[test]
    fn test_event_value_dns_returns_1() {
        let dns = giganto_client::ingest::network::Dns {
            orig_addr: "192.168.1.1".parse().unwrap(),
            orig_port: 54321,
            resp_addr: "8.8.8.8".parse().unwrap(),
            resp_port: 53,
            proto: 17,
            start_time: 0,
            duration: 50_000_000,
            orig_pkts: 1,
            resp_pkts: 1,
            orig_l2_bytes: 100,
            resp_l2_bytes: 200,
            query: "example.com".to_string(),
            answer: vec!["93.184.216.34".to_string()],
            trans_id: 12345,
            rtt: 50,
            qclass: 1,
            qtype: 1,
            rcode: 0,
            aa_flag: false,
            tc_flag: false,
            rd_flag: true,
            ra_flag: true,
            ttl: vec![300],
        };
        let event = Event::Dns(dns);

        // DNS events always return 1.0 regardless of column
        assert_eq!(event_value(Some(5), &event), 1.0);
        assert_eq!(event_value(Some(7), &event), 1.0);
    }

    /// Helper to create a test Conn event
    fn create_test_conn() -> giganto_client::ingest::network::Conn {
        giganto_client::ingest::network::Conn {
            orig_addr: "192.168.1.1".parse().unwrap(),
            resp_addr: "192.168.1.2".parse().unwrap(),
            orig_port: 12345,
            resp_port: 80,
            proto: 6,
            conn_state: "SF".to_string(),
            service: "http".to_string(),
            duration: 1_000_000_000,
            orig_bytes: 100,
            resp_bytes: 200,
            orig_pkts: 5,
            resp_pkts: 10,
            orig_l2_bytes: 110,
            resp_l2_bytes: 210,
            start_time: 0,
        }
    }

    /// Helper to create a Conn event with specific values for column aggregation tests
    fn create_conn_with_values(
        duration: i64,
        orig_bytes: u64,
        resp_bytes: u64,
        orig_pkts: u64,
        resp_pkts: u64,
    ) -> giganto_client::ingest::network::Conn {
        giganto_client::ingest::network::Conn {
            orig_addr: "192.168.1.1".parse().unwrap(),
            resp_addr: "192.168.1.2".parse().unwrap(),
            orig_port: 12345,
            resp_port: 80,
            proto: 6,
            conn_state: "SF".to_string(),
            service: "http".to_string(),
            duration,
            orig_bytes,
            resp_bytes,
            orig_pkts,
            resp_pkts,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            start_time: 0,
        }
    }

    /// Helper to create a `TimeSeries` for testing fill behavior
    fn create_test_series(policy_id: &str, num_slots: usize, start_timestamp: i64) -> TimeSeries {
        TimeSeries {
            sampling_policy_id: policy_id.to_string(),
            start: datetime_from_timestamp(start_timestamp),
            series: vec![0_f64; num_slots],
        }
    }

    // =========================================================================
    // Tests for TimeSeries::fill and column aggregation
    // =========================================================================

    #[tokio::test]
    async fn test_fill_single_event_counts_as_one() {
        // Period: 1 hour, Interval: 15 min => 4 slots
        // column: None => count events (each event adds 1.0)
        let policy = create_policy(1, SECS_PER_HOUR, 15 * SECS_PER_MINUTE, 0, None);

        // Create a time series starting at midnight
        let midnight = datetime_from_utc("2024/1/15 00:00:00").timestamp();
        let mut series = create_test_series("1", 4, midnight);

        let (sender, _receiver) = async_channel::bounded::<TimeSeries>(10);

        // Event at 00:05:00 => slot 0
        let event_time = datetime_from_utc("2024/1/15 00:05:00");
        let conn = create_test_conn();
        series
            .fill(&policy, event_time, &Event::Conn(conn), &sender)
            .await
            .expect("fill should succeed");

        // Verify slot 0 has value 1.0
        assert_eq!(series.series[0], 1.0);
        assert_eq!(series.series[1], 0.0);
        assert_eq!(series.series[2], 0.0);
        assert_eq!(series.series[3], 0.0);
    }

    #[tokio::test]
    async fn test_fill_multiple_events_same_slot_aggregates() {
        // Period: 1 hour, Interval: 15 min => 4 slots
        // column: None => count events
        let policy = create_policy(1, SECS_PER_HOUR, 15 * SECS_PER_MINUTE, 0, None);

        let midnight = datetime_from_utc("2024/1/15 00:00:00").timestamp();
        let mut series = create_test_series("1", 4, midnight);

        let (sender, _receiver) = async_channel::bounded::<TimeSeries>(10);

        // Three events at different times within slot 0 (00:00 - 00:15)
        let event_times = [
            "2024/1/15 00:01:00",
            "2024/1/15 00:05:00",
            "2024/1/15 00:14:00",
        ];
        for event_time in event_times {
            let event_time = datetime_from_utc(event_time);
            let conn = create_test_conn();
            series
                .fill(&policy, event_time, &Event::Conn(conn), &sender)
                .await
                .expect("fill should succeed");
        }

        // Verify slot 0 has value 3.0 (three events aggregated)
        assert_eq!(series.series[0], 3.0);
    }

    #[tokio::test]
    async fn test_fill_events_in_different_slots() {
        // Period: 1 hour, Interval: 15 min => 4 slots
        let policy = create_policy(1, SECS_PER_HOUR, 15 * SECS_PER_MINUTE, 0, None);

        let midnight = datetime_from_utc("2024/1/15 00:00:00").timestamp();
        let mut series = create_test_series("1", 4, midnight);

        let (sender, _receiver) = async_channel::bounded::<TimeSeries>(10);

        // Events in each slot
        // Slot 0: 00:05:00 (2 events)
        // Slot 1: 00:20:00 (1 event)
        // Slot 2: 00:35:00 (3 events)
        // Slot 3: 00:50:00 (1 event)
        let event_times_per_slot: [&[&str]; 4] = [
            &["2024/1/15 00:05:00", "2024/1/15 00:10:00"], // slot 0
            &["2024/1/15 00:20:00"],                       // slot 1
            &[
                "2024/1/15 00:30:00",
                "2024/1/15 00:35:00",
                "2024/1/15 00:44:00",
            ], // slot 2
            &["2024/1/15 00:50:00"],                       // slot 3
        ];

        for (slot, times) in event_times_per_slot.iter().enumerate() {
            for &event_time in *times {
                let event_time = datetime_from_utc(event_time);
                let conn = create_test_conn();
                series
                    .fill(&policy, event_time, &Event::Conn(conn), &sender)
                    .await
                    .expect("fill should succeed");
            }
            assert_eq!(
                series.series[slot],
                times.len() as f64,
                "slot {} should have {} events",
                slot,
                times.len()
            );
        }
    }

    #[tokio::test]
    async fn test_fill_with_column_aggregation_duration() {
        // Period: 1 hour, Interval: 15 min => 4 slots
        // column: Some(5) => sum duration values
        let policy = create_policy(1, SECS_PER_HOUR, 15 * SECS_PER_MINUTE, 0, Some(5));

        let midnight = datetime_from_utc("2024/1/15 00:00:00").timestamp();
        let mut series = create_test_series("1", 4, midnight);

        let (sender, _receiver) = async_channel::bounded::<TimeSeries>(10);

        // Add events with different durations to slot 0
        let durations = [1_000_000_000_i64, 2_000_000_000, 500_000_000];
        let event_times = [
            "2024/1/15 00:01:00",
            "2024/1/15 00:02:00",
            "2024/1/15 00:03:00",
        ];
        for (&duration, event_time) in durations.iter().zip(event_times) {
            let event_time = datetime_from_utc(event_time);
            let conn = create_conn_with_values(duration, 0, 0, 0, 0);
            series
                .fill(&policy, event_time, &Event::Conn(conn), &sender)
                .await
                .expect("fill should succeed");
        }

        // Verify slot 0 has sum of durations
        let expected_sum: f64 = durations.iter().map(|&d| d as f64).sum();
        assert_eq!(
            series.series[0], expected_sum,
            "expected {} but got {}",
            expected_sum, series.series[0]
        );
    }

    #[tokio::test]
    async fn test_fill_with_column_aggregation_bytes() {
        // Period: 1 hour, Interval: 15 min => 4 slots
        // column: Some(7) => sum orig_bytes values
        let policy = create_policy(1, SECS_PER_HOUR, 15 * SECS_PER_MINUTE, 0, Some(7));

        let midnight = datetime_from_utc("2024/1/15 00:00:00").timestamp();
        let mut series = create_test_series("1", 4, midnight);

        let (sender, _receiver) = async_channel::bounded::<TimeSeries>(10);

        // Add events with different orig_bytes to slot 1 (15-30 minutes)
        let bytes_values = [100_u64, 200, 300, 400];
        let event_times = [
            "2024/1/15 00:16:00",
            "2024/1/15 00:17:00",
            "2024/1/15 00:18:00",
            "2024/1/15 00:19:00",
        ];
        for (&bytes, event_time) in bytes_values.iter().zip(event_times) {
            let event_time = datetime_from_utc(event_time);
            let conn = create_conn_with_values(0, bytes, 0, 0, 0);
            series
                .fill(&policy, event_time, &Event::Conn(conn), &sender)
                .await
                .expect("fill should succeed");
        }

        // Verify slot 0 is empty
        assert_eq!(series.series[0], 0.0);

        // Verify slot 1 has sum of orig_bytes
        let expected_sum: f64 = bytes_values.iter().map(|&b| b as f64).sum();
        assert_eq!(
            series.series[1], expected_sum,
            "expected {} but got {}",
            expected_sum, series.series[1]
        );
    }

    #[tokio::test]
    async fn test_fill_with_column_aggregation_packets() {
        // Period: 1 hour, Interval: 30 min => 2 slots
        // column: Some(9) => sum orig_pkts values
        let policy = create_policy(1, SECS_PER_HOUR, 30 * SECS_PER_MINUTE, 0, Some(9));

        let midnight = datetime_from_utc("2024/1/15 00:00:00").timestamp();
        let mut series = create_test_series("1", 2, midnight);

        let (sender, _receiver) = async_channel::bounded::<TimeSeries>(10);

        // Add events to both slots
        // Slot 0: packets 10, 20, 30
        // Slot 1: packets 5, 15
        let slot_0_events = [
            ("2024/1/15 00:05:00", 10_u64),
            ("2024/1/15 00:10:00", 20_u64),
            ("2024/1/15 00:25:00", 50_u64),
        ];
        for (event_time, packets) in slot_0_events {
            let event_time = datetime_from_utc(event_time);
            let conn = create_conn_with_values(0, 0, 0, packets, 0);
            series
                .fill(&policy, event_time, &Event::Conn(conn), &sender)
                .await
                .expect("fill should succeed");
        }

        // Slot 1: 35 min and 45 min
        let slot_1_events = [("2024/1/15 00:35:00", 2_u64), ("2024/1/15 00:45:00", 7_u64)];
        for (event_time, packets) in slot_1_events {
            let event_time = datetime_from_utc(event_time);
            let conn = create_conn_with_values(0, 0, 0, packets, 0);
            series
                .fill(&policy, event_time, &Event::Conn(conn), &sender)
                .await
                .expect("fill should succeed");
        }

        // Verify slot 0: 10 + 20 + 50 = 80 (minutes 5=>10, 10=>20, 25=>50)
        assert_eq!(
            series.series[0], 80.0,
            "slot 0 expected 80 but got {}",
            series.series[0]
        );

        // Verify slot 1: 2 + 7 = 9 (minutes 35=>2, 45=>7)
        assert_eq!(
            series.series[1], 9.0,
            "slot 1 expected 9 but got {}",
            series.series[1]
        );
    }

    #[tokio::test]
    async fn test_fill_period_boundary_sends_and_resets() {
        // Period: 1 hour, Interval: 15 min => 4 slots
        let policy = create_policy(1, SECS_PER_HOUR, 15 * SECS_PER_MINUTE, 0, None);

        let midnight = datetime_from_utc("2024/1/15 00:00:00").timestamp();
        let mut series = create_test_series("1", 4, midnight);

        let (sender, receiver) = async_channel::bounded::<TimeSeries>(10);

        // Add an event in the first period (slot 0)
        let event_time = datetime_from_utc("2024/1/15 00:05:00");
        let conn = create_test_conn();
        series
            .fill(&policy, event_time, &Event::Conn(conn), &sender)
            .await
            .expect("fill should succeed");

        assert_eq!(series.series[0], 1.0);

        // Add an event beyond the period boundary (> 1 hour later)
        // This should trigger sending the current series and resetting
        let event_time_next_period = datetime_from_utc("2024/1/15 01:01:05");
        let conn = create_test_conn();
        series
            .fill(&policy, event_time_next_period, &Event::Conn(conn), &sender)
            .await
            .expect("fill should succeed");

        // The series should have been reset (slot 0 now has a new event)
        // The old series was sent to the channel
        let sent_series = receiver.try_recv().expect("should have received a series");
        assert_eq!(sent_series.series[0], 1.0);

        // The current series should have the new event
        // The new event at 61:05 falls into slot 0 of the new period
        assert_eq!(series.series[0], 1.0);
        assert_eq!(series.series[1], 0.0);
    }

    #[tokio::test]
    async fn test_fill_with_offset_affects_slot_calculation() {
        // Period: 1 day, Interval: 1 hour => 24 slots
        // Offset: +9 hours (32400s) - KST adjustment
        let policy = create_policy(1, SECS_PER_DAY, SECS_PER_HOUR, 32_400, None);

        let kst_midnight_utc = datetime_from_utc("2024/1/14 15:00:00").timestamp();
        let mut series = create_test_series("1", 24, kst_midnight_utc);

        let (sender, _receiver) = async_channel::bounded::<TimeSeries>(10);

        // KST midnight (UTC 15:00) event maps to slot 0
        let event_time = datetime_from_utc("2024/1/14 15:00:00");
        let conn = create_test_conn();
        series
            .fill(&policy, event_time, &Event::Conn(conn), &sender)
            .await
            .expect("fill should succeed");

        assert_eq!(series.series[0], 1.0);

        // All other slots should be empty
        for (i, &value) in series.series.iter().enumerate() {
            if i != 0 {
                assert_eq!(value, 0.0, "slot {i} should be 0 but is {value}");
            }
        }
    }

    #[tokio::test]
    async fn test_fill_missing_slots_remain_zero() {
        // Period: 1 hour, Interval: 10 min => 6 slots
        let policy = create_policy(1, SECS_PER_HOUR, 10 * SECS_PER_MINUTE, 0, None);

        let midnight = datetime_from_utc("2024/1/15 00:00:00").timestamp();
        let mut series = create_test_series("1", 6, midnight);

        let (sender, _receiver) = async_channel::bounded::<TimeSeries>(10);

        // Only add events to slots 0, 2, and 5 (skip 1, 3, 4)
        let event_times = [
            "2024/1/15 00:05:00",
            "2024/1/15 00:25:00",
            "2024/1/15 00:55:00",
        ];
        for event_time in event_times {
            let event_time = datetime_from_utc(event_time);
            let conn = create_test_conn();
            series
                .fill(&policy, event_time, &Event::Conn(conn), &sender)
                .await
                .expect("fill should succeed");
        }

        // Verify only specific slots have values
        assert_eq!(series.series[0], 1.0);
        assert_eq!(series.series[1], 0.0); // missing
        assert_eq!(series.series[2], 1.0);
        assert_eq!(series.series[3], 0.0); // missing
        assert_eq!(series.series[4], 0.0); // missing
        assert_eq!(series.series[5], 1.0);
    }

    #[tokio::test]
    async fn test_fill_duplicate_timestamps_aggregate() {
        // Period: 1 hour, Interval: 15 min => 4 slots
        let policy = create_policy(1, SECS_PER_HOUR, 15 * SECS_PER_MINUTE, 0, None);

        let midnight = datetime_from_utc("2024/1/15 00:00:00").timestamp();
        let mut series = create_test_series("1", 4, midnight);

        let (sender, _receiver) = async_channel::bounded::<TimeSeries>(10);

        // Add multiple events with exactly the same timestamp
        let event_time = datetime_from_utc("2024/1/15 00:05:00");
        for _ in 0..5 {
            let conn = create_test_conn();
            series
                .fill(&policy, event_time, &Event::Conn(conn), &sender)
                .await
                .expect("fill should succeed");
        }

        // All 5 events should aggregate into slot 0
        assert_eq!(series.series[0], 5.0);
    }

    // =========================================================================
    // Tests for SamplingPolicyExt::start_timestamp
    // =========================================================================

    #[serial]
    #[tokio::test]
    async fn test_start_timestamp_no_last_transmission() {
        // When there is no last transmission timestamp in LAST_TRANSFER_TIME,
        // start_timestamp() should return 0

        // Use a unique policy ID that won't conflict with other tests
        let policy_id = 999_999_u32;
        let policy = SamplingPolicy {
            id: policy_id,
            kind: SamplingKind::Conn,
            interval: Duration::from_secs(60),
            period: Duration::from_secs(3600),
            offset: 0,
            src_ip: None,
            dst_ip: None,
            node: Some("test_start_timestamp_no_last".to_string()),
            column: None,
        };

        // Ensure the key doesn't exist in the global map
        LAST_TRANSFER_TIME
            .write()
            .await
            .remove(&policy_id.to_string());

        // start_timestamp should return 0 when no last timestamp exists
        let start = policy.start_timestamp().await.expect("should succeed");
        assert_eq!(start, 0);
    }

    #[serial]
    #[tokio::test]
    async fn test_start_timestamp_with_last_transmission() {
        // When there is a last transmission timestamp, start_timestamp() should
        // return last_time + period (in nanoseconds)

        // Use a unique policy ID to avoid interference
        let policy_id = 888_888_u32;
        let policy = SamplingPolicy {
            id: policy_id,
            kind: SamplingKind::Conn,
            interval: Duration::from_secs(60),
            period: Duration::from_secs(3600), // 1 hour
            offset: 0,
            src_ip: None,
            dst_ip: None,
            node: Some("test_start_timestamp_with_last".to_string()),
            column: None,
        };

        // Set a known last transmission timestamp (in nanoseconds)
        let last_timestamp_ns: i64 = 1_705_320_000_000_000_000; // 2024-01-15 12:00:00 UTC in nanos
        LAST_TRANSFER_TIME
            .write()
            .await
            .insert(policy_id.to_string(), last_timestamp_ns);

        // start_timestamp should return last_time + period_in_nanos
        // period = 3600 seconds = 3_600_000_000_000 nanoseconds
        let expected = last_timestamp_ns + 3600 * SECOND_TO_NANO;
        let start = policy.start_timestamp().await.expect("should succeed");
        assert_eq!(start, expected);

        // Cleanup
        LAST_TRANSFER_TIME
            .write()
            .await
            .remove(&policy_id.to_string());
    }

    #[serial]
    #[tokio::test]
    async fn test_start_timestamp_period_conversion_overflow() {
        // When the period is too large to convert to nanoseconds (overflow),
        // start_timestamp() should return an error

        // Use a unique policy ID
        let policy_id = 777_777_u32;
        let policy = SamplingPolicy {
            id: policy_id,
            kind: SamplingKind::Conn,
            interval: Duration::from_secs(60),
            // Use a very large period that will overflow when multiplied by SECOND_TO_NANO
            // i64::MAX / SECOND_TO_NANO ≈ 9_223_372_036 seconds
            // So a period larger than this will overflow
            period: Duration::from_secs(10_000_000_000), // ~317 years, will overflow
            offset: 0,
            src_ip: None,
            dst_ip: None,
            node: Some("test_start_timestamp_overflow".to_string()),
            column: None,
        };

        // Set a last transmission timestamp to trigger the overflow path
        let last_timestamp_ns: i64 = 1_000_000_000_000_000_000;
        LAST_TRANSFER_TIME
            .write()
            .await
            .insert(policy_id.to_string(), last_timestamp_ns);

        // start_timestamp should fail due to overflow in period conversion
        let result = policy.start_timestamp().await;
        assert!(
            result.is_err(),
            "Expected error due to period conversion overflow"
        );

        // Cleanup
        LAST_TRANSFER_TIME
            .write()
            .await
            .remove(&policy_id.to_string());
    }
}
