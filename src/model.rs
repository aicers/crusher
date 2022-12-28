use crate::request::{RequestedInterval, RequestedPeriod, RequestedPolicy};

use super::subscribe::{Event, Kind, INGESTION_CHANNEL};
use anyhow::{anyhow, bail, Result};
use async_channel::Sender;
use chrono::{DateTime, NaiveDateTime, TimeZone, Timelike, Utc};
use num_enum::IntoPrimitive;
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

// Interval should be able to devide any of the Period values.
#[derive(Clone, Copy, IntoPrimitive, Deserialize, Debug)]
#[repr(u32)]
pub enum Interval {
    FiveMinutes = 300,
    TenMinutes = 600,
    FifteenMinutes = 900,
    ThirtyMinutes = 1_800,
    OneHour = 3_600,
}

impl From<RequestedInterval> for Interval {
    fn from(i: RequestedInterval) -> Self {
        match i {
            RequestedInterval::FiveMinutes => Self::FiveMinutes,
            RequestedInterval::TenMinutes => Self::TenMinutes,
            RequestedInterval::FifteenMinutes => Self::FifteenMinutes,
            RequestedInterval::ThirtyMinutes => Self::ThirtyMinutes,
            RequestedInterval::OneHour => Self::OneHour,
        }
    }
}

// Period should be able to devide one day.
#[derive(Clone, Copy, IntoPrimitive, Deserialize, Debug)]
#[repr(u32)]
pub enum Period {
    SixHours = 21_600,
    TwelveHours = 43_200,
    OneDay = 86_400,
}

impl From<RequestedPeriod> for Period {
    fn from(p: RequestedPeriod) -> Self {
        match p {
            RequestedPeriod::SixHours => Self::SixHours,
            RequestedPeriod::TwelveHours => Self::TwelveHours,
            RequestedPeriod::OneDay => Self::OneDay,
        }
    }
}

#[allow(dead_code)] // TODO: Since this is in temporary use, remove it later.
#[derive(Deserialize, Debug)]
pub(crate) struct Policy {
    pub id: String,
    pub kind: Kind,
    pub(crate) interval: Interval,
    pub(crate) period: Period,
    pub(crate) offset: i32,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub node: Option<String>,
    pub(crate) column: Option<usize>,
}

impl From<RequestedPolicy> for Policy {
    fn from(p: RequestedPolicy) -> Self {
        Self {
            id: p.id.to_string(),
            kind: Kind::from(p.kind),
            interval: Interval::from(p.interval),
            period: Period::from(p.period),
            offset: p.offset,
            src_ip: p.src_ip,
            dst_ip: p.dst_ip,
            node: p.node,
            column: p.column.map(|c| c as usize),
        }
    }
}

#[derive(Default, Clone, Debug, Serialize)]
pub struct TimeSeries {
    pub(crate) sampling_policy_id: String,
    #[serde(skip)]
    pub(crate) start: DateTime<Utc>,
    pub(crate) series: Vec<f64>,
}

impl TimeSeries {
    fn new(sampling_policy_id: String, start: DateTime<Utc>, len: usize) -> Self {
        Self {
            sampling_policy_id,
            start,
            series: vec![0_f64; len],
        }
    }
}

pub(crate) fn convert_policy(start: i64, req_pol: RequestedPolicy) -> (Policy, TimeSeries) {
    let policy = Policy::from(req_pol);
    let model_id = policy.id.clone();
    let len = (u32::from(policy.period) / u32::from(policy.interval)) as usize;
    (
        policy,
        TimeSeries::new(model_id, Utc.timestamp_nanos(start), len),
    )
}

pub(crate) async fn time_series(
    policy: &Policy,
    series: &mut TimeSeries,
    time: DateTime<Utc>,
    event: &Event,
    send_channel: &Sender<TimeSeries>,
) -> Result<()> {
    let Some(period) = u32::from(policy.period).to_i64() else {
        bail!("failed to convert period")
    };

    if time.timestamp() - series.start.timestamp() > period {
        if let Some(sender) = INGESTION_CHANNEL
            .read()
            .await
            .get(&series.sampling_policy_id)
        {
            sender.send(series.clone()).await?;
        } else {
            send_channel.send(series.clone()).await?;
        }
        series.start = start_time(policy, time)?;
        series.series.fill(0_f64);
    }

    let time_slot = time_slot(policy, time)?;
    let Some(value) = series.series.get_mut(time_slot) else {
                bail!("cannot access the time slot");
            };
    *value += event_value(policy.column, event);

    Ok(())
}

fn time_slot(policy: &Policy, time: DateTime<Utc>) -> Result<usize> {
    let offset_time = time.timestamp()
        + policy
            .offset
            .to_i64()
            .ok_or_else(|| anyhow!("failed to convert offset"))?;
    let Some(offset_time) = NaiveDateTime::from_timestamp_opt(offset_time, 0) else {
        bail!("failed to create NaiveDateTime from timestamp");
    };

    let seconds_of_day =
        offset_time.hour() * 3600 + offset_time.minute() * 60 + offset_time.second();
    let (interval, period) = (u32::from(policy.interval), u32::from(policy.period));
    let time_slot = (seconds_of_day - seconds_of_day / period * period) / interval;

    time_slot
        .to_usize()
        .ok_or_else(|| anyhow!("failed to convert index of time slot"))
}

fn event_value(sum_column: Option<usize>, event: &Event) -> f64 {
    let Some(column) = sum_column else {
        return 1_f64; // in order to increase the number of events
    };
    event.column_value(column)
}

fn start_time(policy: &Policy, time: DateTime<Utc>) -> Result<DateTime<Utc>> {
    let offset = policy
        .offset
        .to_i64()
        .ok_or_else(|| anyhow!("failed to convert offset"))?;
    let offset_time = time.timestamp() + offset;
    let Some(offset_time) = NaiveDateTime::from_timestamp_opt(offset_time, 0) else {
        bail!("failed to create NaiveDateTime from timestamp");
    };

    let seconds_of_day =
        offset_time.hour() * 3600 + offset_time.minute() * 60 + offset_time.second();
    let timestamp_of_midnight = offset_time.timestamp()
        - seconds_of_day
            .to_i64()
            .ok_or_else(|| anyhow!("failed to convert seconds of the day"))?;

    let period = u32::from(policy.period);
    let start_of_period = seconds_of_day / period * period;
    let start_offset_time = timestamp_of_midnight
        + start_of_period
            .to_i64()
            .ok_or_else(|| anyhow!("failed to convert start of the period"))?;

    let Some(datetime) = NaiveDateTime::from_timestamp_opt(start_offset_time - offset, 0) else {
        bail!("failed to create NaiveDateTime from timestamp");
    };

    Ok(DateTime::<Utc>::from_utc(datetime, Utc))
}
