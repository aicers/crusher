use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter},
    path::{Path, PathBuf},
    sync::LazyLock,
};

use anyhow::{bail, Context, Result};
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
