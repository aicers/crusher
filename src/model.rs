use super::subscribe::{Event, MessageCode};
use anyhow::{anyhow, Result};
use chrono::{DateTime, NaiveDateTime, TimeZone, Timelike, Utc};
use num_enum::IntoPrimitive;
use num_traits::ToPrimitive;
use std::net::IpAddr;

// Interval should be able to devide any of the Period values.
#[derive(Clone, Copy, IntoPrimitive)]
#[repr(u32)]
pub enum Interval {
    FiveMinutes = 300,
    TenMinutes = 600,
    FifteenMinutes = 900,
    ThirtyMinutes = 1_800,
    OneHour = 3_600,
}

// Period should be able to devide one day.
#[derive(Clone, Copy, IntoPrimitive)]
#[repr(u32)]
pub enum Period {
    SixHours = 21_600,
    TwelveHours = 43_200,
    OneDay = 86_400,
}

#[allow(dead_code)] // TODO: Since this is in temporary use, remove it later.
pub(crate) struct Model {
    pub id: String,
    pub kind: MessageCode,
    interval: Interval,
    period: Period,
    offset: i32,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub node: Option<String>,
    sum_column: Option<usize>,
}

// This is sent to giganto
#[allow(dead_code)] // TODO: Since this is in temporary use, remove it later.
#[derive(Default, Clone)]
pub(crate) struct TimeSeries {
    model_id: String,
    pub(crate) start: DateTime<Utc>,
    pub(crate) series: Vec<f64>,
}

impl TimeSeries {
    fn new(model_id: String, start: DateTime<Utc>, len: usize) -> Self {
        Self {
            model_id,
            start,
            series: vec![0_f64; len],
        }
    }
}

// TODO: This is temporary. Remove this when fulfilling issues
pub(crate) fn test_conn_model() -> (Model, TimeSeries) {
    (
        Model {
            id: "0".to_string(),
            kind: MessageCode::Conn,
            interval: Interval::FifteenMinutes,
            period: Period::OneDay,
            offset: 32_400,
            src_ip: None,
            dst_ip: None,
            node: Some("einsis".to_string()),
            sum_column: None,
        },
        TimeSeries::new("0".to_string(), Utc.ymd(2022, 11, 17).and_hms(0, 0, 0), 96),
    )
}

pub(crate) fn time_series(
    model: &Model,
    series: &mut TimeSeries,
    time: DateTime<Utc>,
    event: &Event,
) -> Result<()> {
    let Some(period) = u32::from(model.period).to_i64() else {
            return Err(anyhow!("failed to convert period"))
        };

    if time.timestamp() - series.start.timestamp() > period {
        // new period
        // TODO: Send this `series_to_send` to giganto (issue #12)
        let _series_to_send = series.clone();
        series.start = start_time(model, time)?;
        series.series.fill(0_f64);
    }

    let time_slot = time_slot(model, time)?;
    let Some(value) = series.series.get_mut(time_slot) else {
                return Err(anyhow!("cannot access the time slot"));
            };
    *value += event_value(model.sum_column, event);

    Ok(())
}

fn time_slot(model: &Model, time: DateTime<Utc>) -> Result<usize> {
    let offset_time = time.timestamp()
        + model
            .offset
            .to_i64()
            .ok_or_else(|| anyhow!("failed to convert offset"))?;
    let Some(offset_time) = NaiveDateTime::from_timestamp_opt(offset_time, 0) else {
        return Err(anyhow!("failed to create NaiveDateTime from timestamp"));
    };

    let seconds_of_day =
        offset_time.hour() * 3600 + offset_time.minute() * 60 + offset_time.second();
    let (interval, period) = (u32::from(model.interval), u32::from(model.period));
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

fn start_time(model: &Model, time: DateTime<Utc>) -> Result<DateTime<Utc>> {
    let offset = model
        .offset
        .to_i64()
        .ok_or_else(|| anyhow!("failed to convert offset"))?;
    let offset_time = time.timestamp() + offset;
    let Some(offset_time) = NaiveDateTime::from_timestamp_opt(offset_time, 0) else {
        return Err(anyhow!("failed to create NaiveDateTime from timestamp"));
    };

    let seconds_of_day =
        offset_time.hour() * 3600 + offset_time.minute() * 60 + offset_time.second();
    let timestamp_of_midnight = offset_time.timestamp()
        - seconds_of_day
            .to_i64()
            .ok_or_else(|| anyhow!("failed to convert seconds of the day"))?;

    let period = u32::from(model.period);
    let start_of_period = seconds_of_day / period * period;
    let start_offset_time = timestamp_of_midnight
        + start_of_period
            .to_i64()
            .ok_or_else(|| anyhow!("failed to convert start of the period"))?;

    Ok(DateTime::<Utc>::from_utc(
        NaiveDateTime::from_timestamp(start_offset_time - offset, 0),
        Utc,
    ))
}
