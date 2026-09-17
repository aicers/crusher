use anyhow::{Context, Result, bail};
use async_channel::Sender;
use review_protocol::types::SamplingPolicy;
use serde::Serialize;

use super::{Event, INGEST_CHANNEL};

pub(super) const SECOND_TO_NANO: i64 = 1_000_000_000;
const SECONDS_PER_DAY: i64 = 86_400;

#[cfg_attr(test, derive(serde::Deserialize))]
#[derive(Default, Clone, Debug, Serialize)]
pub(super) struct TimeSeries {
    pub(super) sampling_policy_id: String,
    #[serde(skip)]
    pub(super) start_secs: i64,
    pub(super) series: Vec<f64>,
}

impl TimeSeries {
    /// Creates a new `TimeSeries` from the given sampling policy.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The policy's interval is zero.
    /// - The policy's period is zero.
    /// - The policy's period is not a multiple of the interval (i.e.,
    ///   `period % interval != 0`).
    /// - The policy's period is not a divisor of 1 day (86400 seconds).
    /// - The series length overflows `usize`.
    pub(super) fn try_new(policy: &SamplingPolicy, start_timestamp: i64) -> Result<Self> {
        let interval_secs = policy.interval.as_secs();
        let period_secs = policy.period.as_secs();
        if interval_secs == 0 {
            bail!("interval must be greater than 0");
        }
        if period_secs == 0 {
            bail!("period must be greater than 0");
        }
        if !86400_u64.is_multiple_of(period_secs) {
            bail!("period must be a divisor of 1 day (86400 seconds)");
        }
        if !period_secs.is_multiple_of(interval_secs) {
            bail!("period must be a multiple of interval");
        }

        let start_secs = start_timestamp.div_euclid(SECOND_TO_NANO);
        let len = usize::try_from(period_secs / interval_secs)?;
        let series = vec![0_f64; len];
        Ok(TimeSeries {
            sampling_policy_id: policy.id.to_string(),
            start_secs,
            series,
        })
    }

    pub(super) async fn fill(
        &mut self,
        policy: &SamplingPolicy,
        time_secs: i64,
        event: &Event,
        send_channel: &Sender<TimeSeries>,
    ) -> Result<()> {
        let period = i64::try_from(policy.period.as_secs())?;
        let elapsed = time_secs
            .checked_sub(self.start_secs)
            .context("failed to calculate elapsed time")?;

        if elapsed > period {
            // Clone the sender out of the lock to avoid holding the
            // RwLock read guard across an await point.
            let cached_sender = INGEST_CHANNEL
                .read()
                .await
                .get(&self.sampling_policy_id)
                .cloned();
            if let Some(sender) = cached_sender {
                sender.send(self.clone()).await?;
            } else {
                send_channel.send(self.clone()).await?;
            }
            self.start_secs = start_time(policy, time_secs)?;
            self.series.fill(0_f64);
        }

        let time_slot = time_slot(policy, time_secs)?;
        let Some(value) = self.series.get_mut(time_slot) else {
            bail!("cannot access the time slot");
        };
        *value += event_value(policy.column, event);

        Ok(())
    }
}

fn time_slot(policy: &SamplingPolicy, time_secs: i64) -> Result<usize> {
    let Some(offset_time) = time_secs.checked_add(i64::from(policy.offset)) else {
        bail!("failed to apply policy offset to timestamp");
    };
    let seconds_of_day = u64::try_from(offset_time.rem_euclid(SECONDS_PER_DAY))?;
    let interval = policy.interval.as_secs();
    let period = policy.period.as_secs();
    let time_slot = seconds_of_day % period / interval;
    Ok(usize::try_from(time_slot)?)
}

fn event_value(sum_column: Option<u32>, event: &Event) -> f64 {
    let Some(column) = sum_column else {
        return 1_f64; // in order to increase the number of events
    };
    event.column_value(column)
}

fn start_time(policy: &SamplingPolicy, time_secs: i64) -> Result<i64> {
    let offset_secs = i64::from(policy.offset);
    let offset_time = time_secs
        .checked_add(offset_secs)
        .context("failed to apply policy offset to timestamp")?;

    let seconds_of_day = offset_time.rem_euclid(SECONDS_PER_DAY);
    let timestamp_of_midnight = offset_time - seconds_of_day;

    let period = i64::try_from(policy.period.as_secs())?;
    let start_of_period = seconds_of_day - seconds_of_day.rem_euclid(period);
    let start_offset_time = timestamp_of_midnight
        .checked_add(start_of_period)
        .context("failed to calculate period start timestamp")?;
    let start_time = start_offset_time
        .checked_sub(offset_secs)
        .context("failed to convert period start timestamp to UTC")?;

    Ok(start_time)
}

#[cfg(test)]
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::float_cmp
)]
mod tests {
    use std::time::Duration;

    use review_protocol::types::{SamplingKind, SamplingPolicy};
    use serial_test::serial;
    use time::{Date, Month};

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

    fn create_simple_policy(interval_secs: u64, period_secs: u64) -> SamplingPolicy {
        let id = 1;
        let offset = 0;
        let column = None;

        create_policy(id, period_secs, interval_secs, offset, column)
    }

    /// Helper to create a Unix timestamp (seconds) from a specific UTC
    /// date/time string in `YYYY/M/D HH:MM:SS` format.
    ///
    /// Example: `datetime_from_utc("2024/1/15 00:00:00")` returns `1705276800`
    /// (2024-01-15 00:00:00 UTC).
    fn datetime_from_utc(input: &str) -> i64 {
        let (date, time) = input.split_once(' ').expect("datetime contains a space");
        let mut date_parts = date.split('/');
        let year: i32 = date_parts
            .next()
            .expect("year is present")
            .parse()
            .expect("year is valid");
        let month: u8 = date_parts
            .next()
            .expect("month is present")
            .parse()
            .expect("month is valid");
        let day: u8 = date_parts
            .next()
            .expect("day is present")
            .parse()
            .expect("day is valid");

        let mut time_parts = time.split(':');
        let hour: u8 = time_parts
            .next()
            .expect("hour is present")
            .parse()
            .expect("hour is valid");
        let minute: u8 = time_parts
            .next()
            .expect("minute is present")
            .parse()
            .expect("minute is valid");
        let second: u8 = time_parts
            .next()
            .expect("second is present")
            .parse()
            .expect("second is valid");

        let month = Month::try_from(month).expect("month is in range");
        Date::from_calendar_date(year, month, day)
            .expect("date is valid")
            .with_hms(hour, minute, second)
            .expect("time is valid")
            .assume_utc()
            .unix_timestamp()
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
        assert_eq!(start, kst_midnight_utc);
    }

    // =========================================================================
    // Tests for JSON timestamp persistence (read/write/delete)
    // =========================================================================
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
            start_secs: start_timestamp,
            series: vec![0_f64; num_slots],
        }
    }

    async fn reset_ingest_channel() {
        INGEST_CHANNEL.write().await.clear();
    }

    // =========================================================================
    // Tests for TimeSeries::fill and column aggregation
    // =========================================================================

    #[serial]
    #[tokio::test]
    async fn test_fill_single_event_counts_as_one() {
        reset_ingest_channel().await;
        // Period: 1 hour, Interval: 15 min => 4 slots
        // column: None => count events (each event adds 1.0)
        let policy = create_policy(1, SECS_PER_HOUR, 15 * SECS_PER_MINUTE, 0, None);

        // Create a time series starting at midnight
        let midnight = datetime_from_utc("2024/1/15 00:00:00");
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

    #[serial]
    #[tokio::test]
    async fn test_fill_multiple_events_same_slot_aggregates() {
        reset_ingest_channel().await;
        // Period: 1 hour, Interval: 15 min => 4 slots
        // column: None => count events
        let policy = create_policy(1, SECS_PER_HOUR, 15 * SECS_PER_MINUTE, 0, None);

        let midnight = datetime_from_utc("2024/1/15 00:00:00");
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

    #[serial]
    #[tokio::test]
    async fn test_fill_events_in_different_slots() {
        reset_ingest_channel().await;
        // Period: 1 hour, Interval: 15 min => 4 slots
        let policy = create_policy(1, SECS_PER_HOUR, 15 * SECS_PER_MINUTE, 0, None);

        let midnight = datetime_from_utc("2024/1/15 00:00:00");
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

    #[serial]
    #[tokio::test]
    async fn test_fill_with_column_aggregation_duration() {
        reset_ingest_channel().await;
        // Period: 1 hour, Interval: 15 min => 4 slots
        // column: Some(5) => sum duration values
        let policy = create_policy(1, SECS_PER_HOUR, 15 * SECS_PER_MINUTE, 0, Some(5));

        let midnight = datetime_from_utc("2024/1/15 00:00:00");
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

    #[serial]
    #[tokio::test]
    async fn test_fill_with_column_aggregation_bytes() {
        reset_ingest_channel().await;
        // Period: 1 hour, Interval: 15 min => 4 slots
        // column: Some(7) => sum orig_bytes values
        let policy = create_policy(1, SECS_PER_HOUR, 15 * SECS_PER_MINUTE, 0, Some(7));

        let midnight = datetime_from_utc("2024/1/15 00:00:00");
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

    #[serial]
    #[tokio::test]
    async fn test_fill_with_column_aggregation_packets() {
        reset_ingest_channel().await;
        // Period: 1 hour, Interval: 30 min => 2 slots
        // column: Some(9) => sum orig_pkts values
        let policy = create_policy(1, SECS_PER_HOUR, 30 * SECS_PER_MINUTE, 0, Some(9));

        let midnight = datetime_from_utc("2024/1/15 00:00:00");
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

    #[serial]
    #[tokio::test]
    async fn test_fill_period_boundary_sends_and_resets() {
        reset_ingest_channel().await;
        // Period: 1 hour, Interval: 15 min => 4 slots
        let policy = create_policy(1, SECS_PER_HOUR, 15 * SECS_PER_MINUTE, 0, None);

        let midnight = datetime_from_utc("2024/1/15 00:00:00");
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

    #[serial]
    #[tokio::test]
    async fn test_fill_kst_offset_events_aggregate_same_slot() {
        reset_ingest_channel().await;
        // Period: 1 day, Interval: 15 min => 96 slots
        // Offset: +9 hours (KST)
        let policy = create_policy(1, SECS_PER_DAY, 15 * SECS_PER_MINUTE, 32_400, None);
        let midnight = datetime_from_utc("2022/11/17 00:00:00");
        let mut series = create_test_series("1", 96, midnight);
        let (sender, _receiver) = async_channel::bounded::<TimeSeries>(1);

        for event_time in [
            "2022/11/17 00:03:00",
            "2022/11/17 00:06:00",
            "2022/11/17 00:09:00",
        ] {
            let conn = create_test_conn();
            series
                .fill(
                    &policy,
                    datetime_from_utc(event_time),
                    &Event::Conn(conn),
                    &sender,
                )
                .await
                .expect("fill should succeed");
        }

        // UTC 00:03/00:06/00:09 becomes KST 09:03/09:06/09:09, which is slot 36.
        assert_eq!(series.series[36], 3.0);
    }

    #[serial]
    #[tokio::test]
    async fn test_fill_with_offset_affects_slot_calculation() {
        reset_ingest_channel().await;
        // Period: 1 day, Interval: 1 hour => 24 slots
        // Offset: +9 hours (32400s) - KST adjustment
        let policy = create_policy(1, SECS_PER_DAY, SECS_PER_HOUR, 32_400, None);

        let kst_midnight_utc = datetime_from_utc("2024/1/14 15:00:00");
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

    #[serial]
    #[tokio::test]
    async fn test_fill_missing_slots_remain_zero() {
        reset_ingest_channel().await;
        // Period: 1 hour, Interval: 10 min => 6 slots
        let policy = create_policy(1, SECS_PER_HOUR, 10 * SECS_PER_MINUTE, 0, None);

        let midnight = datetime_from_utc("2024/1/15 00:00:00");
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

    #[serial]
    #[tokio::test]
    async fn test_fill_duplicate_timestamps_aggregate() {
        reset_ingest_channel().await;
        // Period: 1 hour, Interval: 15 min => 4 slots
        let policy = create_policy(1, SECS_PER_HOUR, 15 * SECS_PER_MINUTE, 0, None);

        let midnight = datetime_from_utc("2024/1/15 00:00:00");
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
    // Tests for TimeSeries construction
    // =========================================================================
    #[test]
    fn try_new_uses_explicit_resume_timestamp() {
        let policy = create_simple_policy(60, 3600);
        for (nanos, seconds) in [(1_700_003_600_000_000_001, 1_700_003_600), (-1, -1), (0, 0)] {
            let series = TimeSeries::try_new(&policy, nanos).unwrap();
            assert_eq!(series.start_secs, seconds);
            assert_eq!(series.series.len(), 60);
        }
    }

    #[tokio::test]
    async fn try_new_valid_period_interval() {
        // period (3600) is a multiple of interval (60)
        let policy = create_simple_policy(60, 3600);
        let result = TimeSeries::try_new(&policy, 0);
        assert!(result.is_ok());
        let ts = result.unwrap();
        assert_eq!(ts.series.len(), 60); // 3600 / 60 = 60
    }

    #[tokio::test]
    async fn try_new_invalid_period_not_divisor_of_1_day() {
        // period (777) is not a divisor of 1 day (86400 seconds)
        let policy = create_simple_policy(7, 777);
        let result = TimeSeries::try_new(&policy, 0);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("period must be a divisor of 1 day (86400 seconds)"),
            "unexpected error message: {err_msg}"
        );
    }

    #[tokio::test]
    async fn try_new_invalid_period_not_multiple_of_interval() {
        // period (100) is not a multiple of interval (30)
        let policy = create_simple_policy(30, 100);
        let result = TimeSeries::try_new(&policy, 0);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("period must be a multiple of interval"),
            "unexpected error message: {err_msg}"
        );
    }

    #[tokio::test]
    async fn try_new_interval_zero() {
        // interval is 0, should error before division
        let policy = create_simple_policy(0, 3600);
        let result = TimeSeries::try_new(&policy, 0);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("interval must be greater than 0"),
            "unexpected error message: {err_msg}"
        );
    }

    #[tokio::test]
    async fn try_new_period_zero() {
        // period is 0, should error
        let policy = create_simple_policy(60, 0);
        let result = TimeSeries::try_new(&policy, 0);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("period must be greater than 0"),
            "unexpected error message: {err_msg}"
        );
    }
    // time-handling code against a stable baseline. They prefer integer Unix
    // timestamps and literal expected values over runtime-derived ones.
    // =========================================================================
    mod time_handling_contracts {
        use super::*;

        // Reference Unix timestamps used as fixed inputs:
        // - 0                : 1970-01-01T00:00:00Z (Unix epoch)
        // - 1                : 1970-01-01T00:00:01Z (smallest positive)
        // - -1               : 1969-12-31T23:59:59Z (one second before epoch)
        // - 1_700_000_000    : 2023-11-14T22:13:20Z (mid-range)
        // - 253_402_300_799  : 9999-12-31T23:59:59Z (large but safe endpoint)
        const TS_EPOCH: i64 = 0;
        const TS_EPOCH_PLUS_ONE: i64 = 1;
        const TS_EPOCH_MINUS_ONE: i64 = -1;
        const TS_2023_11_14_221320Z: i64 = 1_700_000_000;
        const TS_9999_12_31_235959Z: i64 = 253_402_300_799;

        const TEST_POLICY_ID: u32 = 333;
        const NO_OFFSET: i32 = 0;

        #[test]
        fn time_slot_at_unix_epoch_is_zero() {
            // Period: 1 day, Interval: 1 hour => 24 slots, offset 0.
            let policy =
                create_policy(TEST_POLICY_ID, SECS_PER_DAY, SECS_PER_HOUR, NO_OFFSET, None);
            assert_eq!(time_slot(&policy, TS_EPOCH).unwrap(), 0,);
            // 1 second past epoch is still slot 0.
            assert_eq!(time_slot(&policy, TS_EPOCH_PLUS_ONE).unwrap(), 0,);
        }

        #[test]
        fn time_slot_for_known_rfc3339_midrange() {
            // 2023-11-14T22:13:20Z is 1_700_000_000s after the epoch.
            // With period=86400 (1 day), interval=3600 (1 hour), the expected slot is computed
            // as a literal: 1_700_000_000 % 86400 = 80_000s of day, and
            // 80_000 / 3600 = 22 (integer division).
            let policy =
                create_policy(TEST_POLICY_ID, SECS_PER_DAY, SECS_PER_HOUR, NO_OFFSET, None);
            assert_eq!(time_slot(&policy, TS_2023_11_14_221320Z).unwrap(), 22,);
        }

        #[test]
        fn time_slot_at_year_9999_endpoint() {
            // 9999-12-31T23:59:59Z = 253_402_300_799 seconds.
            // 253_402_300_799 % 86400 = 86_399 (last second of the day),
            // 86_399 / 3600 = 23 => last hour-slot.
            let policy =
                create_policy(TEST_POLICY_ID, SECS_PER_DAY, SECS_PER_HOUR, NO_OFFSET, None);
            assert_eq!(time_slot(&policy, TS_9999_12_31_235959Z).unwrap(), 23,);
        }

        #[test]
        fn time_slot_negative_timestamp_aligns_to_last_hour_slot() {
            // -1s is 1969-12-31T23:59:59Z. With period=86400 (1 day) and interval=3600 (1 hour),
            // that lands in slot 23 (last hour of the day).
            let policy =
                create_policy(TEST_POLICY_ID, SECS_PER_DAY, SECS_PER_HOUR, NO_OFFSET, None);
            assert_eq!(time_slot(&policy, TS_EPOCH_MINUS_ONE).unwrap(), 23,);
        }

        #[test]
        fn pre_epoch_offsets_result_in_negative_unix_timestamp() {
            let policy = create_policy(TEST_POLICY_ID, SECS_PER_DAY, SECS_PER_HOUR, -2, None);

            let aligned =
                start_time(&policy, TS_EPOCH_PLUS_ONE).expect("start_time should succeed");

            // Applying the -2s policy offset to timestamp +1 yields timestamp -1,
            // i.e. 1969-12-31T23:59:59Z in offset-adjusted time.
            //
            // For a 1-day period, the adjusted day starts at timestamp -86_400.
            // `start_time` then converts that boundary back to UTC by subtracting
            // the policy offset: -86_400 - (-2) = -86_398.
            assert_eq!(aligned, -86_398);
        }

        #[test]
        fn start_time_negative_timestamp_aligns_to_negative_3600() {
            // -1s sits in the period [-3600, 0). With period=1h and offset=0
            // start_time must align to -3600
            let policy = create_policy(
                TEST_POLICY_ID,
                SECS_PER_HOUR,
                SECS_PER_MINUTE,
                NO_OFFSET,
                None,
            );
            let aligned =
                start_time(&policy, TS_EPOCH_MINUS_ONE).expect("start_time should succeed");
            assert_eq!(aligned, -i64::try_from(SECS_PER_HOUR).unwrap());
        }

        #[test]
        fn midnight_rollover_kst_consistency() {
            // `time_slot` uses `period` as the modulo window. Use a day-sized period
            // to expose hour-of-day slots: 0..=23.
            let slot_policy =
                create_policy(TEST_POLICY_ID, SECS_PER_DAY, SECS_PER_HOUR, NO_OFFSET, None);

            // `start_time` aligns to `period` boundaries. Use an hour-sized period
            // to pin the start of the current hour.
            let start_policy = create_policy(
                TEST_POLICY_ID,
                SECS_PER_HOUR,
                SECS_PER_HOUR,
                NO_OFFSET,
                None,
            );

            // Choose an instant near the UTC day boundary: 23:30:00 UTC.
            let utc = i64::try_from(SECS_PER_DAY - SECS_PER_MINUTE * 30).unwrap();
            let kst_offset = i64::try_from(9 * SECS_PER_HOUR).unwrap();

            // Same instant expressed as naive local seconds since the Unix epoch.
            // KST is UTC+09:00, so 23:30 UTC becomes next-day 08:30 KST.
            let kst_repr = utc + kst_offset;

            // Pin the concrete arithmetic inputs used by the assertions below.
            assert_eq!(utc, 84_600); // 86400 - 1800
            assert_eq!(kst_offset, 32_400);
            assert_eq!(kst_repr, 117_000);

            // UTC 23:30 belongs to hour slot 23, and its hourly start is 23:00.
            assert_eq!(time_slot(&slot_policy, utc).unwrap(), 23,);
            assert_eq!(
                start_time(&start_policy, utc).expect("start_time should succeed"),
                i64::try_from(23 * SECS_PER_HOUR).unwrap(),
            );

            // The naive KST representation is next-day 08:30. Integer timestamps may
            // exceed one day here, so the hourly start is day 1 + 08:00 = 115_200.
            assert_eq!(time_slot(&slot_policy, kst_repr).unwrap(), 8,);
            assert_eq!(
                start_time(&start_policy, kst_repr).expect("start_time should succeed"),
                i64::try_from(SECS_PER_DAY + 8 * SECS_PER_HOUR).unwrap(),
            );

            // Converting the naive local integer back to UTC by subtracting the KST
            // offset must recover the same UTC slot and hourly start boundary.
            let normalized_utc = kst_repr - kst_offset;
            assert_eq!(normalized_utc, utc);

            assert_eq!(
                time_slot(&slot_policy, normalized_utc).unwrap(),
                time_slot(&slot_policy, utc).unwrap(),
            );
            assert_eq!(
                start_time(&start_policy, normalized_utc)
                    .expect("normalized start_time should succeed"),
                start_time(&start_policy, utc).expect("utc start_time should succeed"),
            );
        }

        #[serial]
        #[tokio::test]
        async fn fill_at_exact_period_boundary_does_not_reset() {
            // The reset condition in `fill` uses `>` (strict), not `>=`. An
            // event at exactly start + period must therefore land in the
            // current series, not trigger a reset. Pin this so any rewrite
            // preserves the inclusive lower / exclusive upper convention.
            reset_ingest_channel().await;
            let policy = create_policy(
                TEST_POLICY_ID,
                SECS_PER_HOUR,
                15 * SECS_PER_MINUTE,
                NO_OFFSET,
                None,
            );

            let start_ts = datetime_from_utc("2024/1/15 00:00:00");
            let mut series = create_test_series(TEST_POLICY_ID.to_string().as_ref(), 4, start_ts);
            let (sender, receiver) = async_channel::bounded::<TimeSeries>(4);

            // time - start = 3600, which is NOT > 3600.
            let boundary = datetime_from_utc("2024/1/15 01:00:00");
            series
                .fill(&policy, boundary, &Event::Conn(create_test_conn()), &sender)
                .await
                .expect("fill should succeed at the exact boundary");

            assert!(
                receiver.try_recv().is_err(),
                "no series should be sent at the exact period boundary",
            );
            assert_eq!(series.start_secs, start_ts);
            assert_eq!(series.series[0], 1.0);

            // One second past the boundary triggers send + reset (3601 > 3600).
            let past = datetime_from_utc("2024/1/15 01:00:01");
            series
                .fill(&policy, past, &Event::Conn(create_test_conn()), &sender)
                .await
                .expect("fill should succeed");
            let sent = receiver
                .try_recv()
                .expect("series should be sent past the boundary");
            assert_eq!(sent.series[0], 1.0);
        }

        #[test]
        fn time_series_bincode_serialization_ignores_start_time() {
            // The `start_secs` field is `#[serde(skip)]`, so the bincode payload
            // must be byte-identical for two TimeSeries that differ only in
            // their start time.
            let series_a = TimeSeries {
                sampling_policy_id: "42".to_string(),
                start_secs: TS_EPOCH,
                series: vec![1.0, 2.0, 3.0, 4.0],
            };
            let series_b = TimeSeries {
                sampling_policy_id: "42".to_string(),
                start_secs: TS_9999_12_31_235959Z,
                series: vec![1.0, 2.0, 3.0, 4.0],
            };

            let bytes_a = bincode::serialize(&series_a).expect("bincode serialize a");
            let bytes_b = bincode::serialize(&series_b).expect("bincode serialize b");

            assert_eq!(
                bytes_a, bytes_b,
                "TimeSeries bincode bytes must not depend on the `start_secs` field",
            );
        }

        #[test]
        fn time_series_bincode_round_trip_preserves_observable_fields() {
            // The id and series payload must round-trip byte-for-byte. The
            // `start_secs` field is skipped on the wire and is not part of the
            // external contract.
            let original = TimeSeries {
                sampling_policy_id: "policy-1".to_string(),
                start_secs: TS_2023_11_14_221320Z,
                series: vec![0.0, 1.5, -2.25, 3.125],
            };
            let bytes = bincode::serialize(&original).expect("bincode serialize");
            let decoded: TimeSeries = bincode::deserialize(&bytes).expect("bincode deserialize");
            assert_eq!(decoded.sampling_policy_id, "policy-1");
            assert_eq!(decoded.series, vec![0.0, 1.5, -2.25, 3.125]);
            assert_eq!(decoded.start_secs, i64::default());
        }
    }
}
