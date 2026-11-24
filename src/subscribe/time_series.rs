use std::borrow::Cow;
use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;

use anyhow::{Context, Result, bail};
use review_protocol::types::{
    CounterpartScope, EndpointRole, GroupByUnit, HostNetworkGroup, Measure,
    TimeSeriesGenerationPolicy,
};
use serde::Serialize;
use tokio::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use tracing::warn;

use super::Event;

pub(super) const SECOND_TO_NANO: i64 = 1_000_000_000;
const SECONDS_PER_DAY: i64 = 86_400;

/// The longest a Sensor holds an event before sending it (piglet 0.23.0
/// `BATCH_INTERVAL`, `src/output/event.rs:39`); events are keyed by
/// completion time, so an event completed just before a window's end arrives
/// up to this long after it.
const SENSOR_BATCH_SECS: i64 = 600;

/// Clock skew between the Sensor and this host.
const CLOSE_SKEW_SECS: i64 = 300;

/// How far past a window's end a stream must be before it has passed the
/// window: by event time, or by the wall clock once it is quiet after its
/// replay end.
///
/// Covers a Sensor batch of up to 600 s (piglet 0.23.0 `BATCH_INTERVAL`) plus
/// 300 s of skew; a shorter batch interval in a later Sensor needs no change,
/// only less latency.
pub(super) const CLOSE_GRACE_SECS: i64 = SENSOR_BATCH_SECS + CLOSE_SKEW_SECS;

/// The most values, one per IP, a grouped policy keeps a series for in one
/// request. A placeholder until a measurement sets it.
const MAX_SERIES_PER_POLICY: usize = 10_000;

#[cfg_attr(test, derive(serde::Deserialize))]
#[derive(Default, Clone, Debug, Serialize)]
pub(super) struct TimeSeries {
    /// The id Giganto stores the series under. The id of a time series, not of
    /// this struct, so the shared prefix is the name it has everywhere else.
    #[allow(clippy::struct_field_names)]
    pub(super) time_series_id: String,
    /// The policy the series belongs to, whose ingest stream writes it and
    /// whose checkpoint its ACK moves. Not part of the record Giganto stores.
    #[serde(skip)]
    pub(super) policy_id: u32,
    #[serde(skip)]
    pub(super) start_secs: i64,
    pub(super) series: Vec<f64>,
}

/// The rows one time-series ingest frame carries: Giganto stores them
/// together, in order, with one write. Never empty.
#[derive(Clone, Debug)]
pub(super) struct IngestFrame {
    policy_id: u32,
    rows: Vec<TimeSeries>,
    /// The policy token of the run that wrote the frame, cancelled once that
    /// run's request is replaced or its policy deleted. `None` for a frame no
    /// run wrote.
    run: Option<CancellationToken>,
}

impl IngestFrame {
    /// Returns the policy whose ingest stream writes the frame.
    pub(super) fn policy_id(&self) -> u32 {
        self.policy_id
    }

    /// Returns the rows of the frame, in the order Giganto stores them.
    pub(super) fn rows(&self) -> &[TimeSeries] {
        &self.rows
    }

    #[cfg(test)]
    pub(super) fn into_rows(self) -> Vec<TimeSeries> {
        self.rows
    }

    /// Returns the frame as written by the run whose policy token is `run`.
    #[must_use]
    pub(super) fn of_run(mut self, run: &CancellationToken) -> Self {
        self.run = Some(run.clone());
        self
    }

    /// Returns whether the run that wrote the frame has stopped, so that the
    /// frame is no longer written.
    pub(super) fn run_stopped(&self) -> bool {
        self.run
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled)
    }

    /// Returns a frame of `row` followed by `then`, both of one policy.
    fn pair(row: TimeSeries, then: TimeSeries) -> Self {
        Self {
            policy_id: row.policy_id,
            rows: vec![row, then],
            run: None,
        }
    }
}

impl From<TimeSeries> for IngestFrame {
    fn from(row: TimeSeries) -> Self {
        Self {
            policy_id: row.policy_id,
            rows: vec![row],
            run: None,
        }
    }
}

/// How one run of a policy starts: where its request resumes and the write
/// generation its rows carry.
#[derive(Clone, Copy, Debug)]
pub(super) struct RunStart {
    /// The request start, in nanoseconds.
    pub(super) start: i64,
    /// Whether `start` is the policy's checkpoint.
    pub(super) resumed: bool,
    /// The run's write generation. A grouped policy needs one; an ungrouped
    /// one ignores it.
    pub(super) generation: Option<u64>,
}

/// The time a policy runner reads when it decides which windows are due.
#[derive(Clone, Copy, Debug)]
pub(super) struct PassClock {
    /// The wall clock, in seconds since the Unix epoch.
    pub(super) wall_secs: i64,
    /// The monotonic time now, against which idle starts are measured.
    pub(super) now: Instant,
    /// How long a stream past its replay end must have been quiet to pass a
    /// window by the wall clock.
    pub(super) idle: Duration,
}

/// What a policy knows of one of its generator streams.
#[derive(Debug, Default)]
struct StreamState {
    opened: bool,
    /// The largest event time received, in nanoseconds, counting every event
    /// the stream delivered, whether or not it was counted.
    watermark: Option<i64>,
    /// The later of the moment the replay-end frame arrived and the moment
    /// the last event after it arrived. `None` until the replay-end frame.
    idle_start: Option<Instant>,
    /// An event too far ahead of the windows being built; the stream reads
    /// nothing more until it is counted.
    held: Option<HeldEvent>,
    /// Set once the stream ended: the bound it had reached, which it keeps.
    ended_bound: Option<i64>,
}

impl StreamState {
    fn replay_ended(&self) -> bool {
        self.idle_start.is_some()
    }

    /// Returns the bound, in nanoseconds, below which this stream has passed
    /// every window's end plus [`CLOSE_GRACE_SECS`]: the stream has passed a
    /// window when that window's end plus the grace is less than this.
    /// `i64::MIN` means it has passed nothing.
    fn bound(&self, clock: &PassClock) -> i64 {
        if let Some(bound) = self.ended_bound {
            return bound;
        }
        if !self.opened {
            return i64::MIN;
        }
        let by_events = self.watermark.unwrap_or(i64::MIN);
        // Passing by the wall clock is "at or past", so it reaches one
        // nanosecond beyond the wall clock's second.
        let by_idle = match self.idle_start {
            Some(idle_start) if clock.now.saturating_duration_since(idle_start) >= clock.idle => {
                clock
                    .wall_secs
                    .saturating_mul(SECOND_TO_NANO)
                    .saturating_add(1)
            }
            _ => i64::MIN,
        };
        by_events.max(by_idle)
    }
}

/// An event a paused stream holds until its window may be counted.
#[derive(Debug)]
struct HeldEvent {
    timestamp: i64,
    window_start: i64,
    key: String,
    value: f64,
}

/// A window that has counted at least one event, or a grouped policy's closed
/// window without any: the values of each of its value keys.
#[derive(Debug)]
struct Window {
    start_secs: i64,
    values: BTreeMap<String, Vec<f64>>,
}

impl Window {
    fn empty(start_secs: i64) -> Self {
        Self {
            start_secs,
            values: BTreeMap::new(),
        }
    }

    fn series(&self, policy_id: u32, key: &str) -> Option<TimeSeries> {
        self.values.get(key).map(|values| TimeSeries {
            time_series_id: key.to_owned(),
            policy_id,
            start_secs: self.start_secs,
            series: values.clone(),
        })
    }
}

/// What an event is counted for: the policy's single series, or, for a
/// grouped policy, the series of the IP at its group side.
#[derive(Clone, Copy, Debug)]
enum Value {
    Policy,
    Ip(IpAddr),
}

/// Builds one policy's windows from the events of all of its generator
/// streams, one per sensor, and decides when each window is closed.
///
/// All windows share one boundary grid. A window is due once every stream has
/// passed it, either by event time or, after its replay end, by being quiet
/// while the wall clock is past the window's end plus [`CLOSE_GRACE_SECS`];
/// windows become due in time order. The last closed window is kept so that an
/// event arriving after its window closed can still be counted there, and the
/// window written again under the same key.
///
/// An ungrouped policy counts every event in one series, keyed by the policy
/// id. A window exists only once an event is counted in it, so a window
/// without events is never written.
///
/// A grouped policy counts an event in the series of the IP at its group side,
/// keyed `P/IP`, if that IP is in the internal network in effect for the
/// event's window and the other endpoint is in the policy's counterpart scope.
/// Every value shares the policy's windows, which close for all values at
/// once. Each IP row ends with the run's write generation, and after the IP
/// rows of a window comes its marker under `P`: the number of IP rows and the
/// generation. A grouped policy closes every window from the request's
/// checkpoint on, or without one from the window of the first event received,
/// even one without IP rows, which gets the marker `[0, generation]`; but such
/// a window closes only once a stream has also passed it by event time.
pub(super) struct WindowBuilder {
    policy: TimeSeriesGenerationPolicy,
    policy_id: String,
    slot_size_secs: i64,
    window_size_secs: i64,
    slots: usize,
    /// The request start, in nanoseconds. Giganto replays the events from
    /// here, so an older event is not part of this request's history.
    request_start: i64,
    streams: Vec<StreamState>,
    /// The start of the earliest window that is not yet due.
    current: i64,
    /// The windows from `current` on that have counted events, by start.
    open: BTreeMap<i64, Window>,
    last_closed: Option<Window>,
    /// Events dropped since the previous close.
    dropped: u64,
    /// The internal network in effect before the first of
    /// [`Self::network_changes`].
    networks: HostNetworkGroup,
    /// The internal network in effect from each boundary (a window start, in
    /// seconds) on, by boundary.
    network_changes: Vec<(i64, HostNetworkGroup)>,
    /// The start of the window of the first event any stream received.
    first_event_window: Option<i64>,
    /// The start of the earliest window not yet warned about as due. A grouped
    /// window can be due long before it closes, so this runs ahead of
    /// [`Self::current`].
    warned: i64,
    /// The IPs a grouped policy keeps a series for in this request.
    accepted: HashSet<IpAddr>,
    /// The most IPs [`Self::accepted`] takes.
    max_series: usize,
    /// The IPs refused for the cap, by the window that reports them once due.
    refused: BTreeMap<i64, HashSet<IpAddr>>,
    /// A grouped policy's write generation, carried by every row of this run.
    /// `None` for an ungrouped policy.
    generation: Option<u64>,
    /// For a grouped policy, the start of the first window that is closed
    /// even without IP rows: the checkpoint's window for a resumed request,
    /// else the window of the first event received. `None` until known.
    marked_from: Option<i64>,
    /// The IP rows of the last closed window corrected or added after its
    /// marker since the previous close, by series id.
    corrected: HashSet<String>,
}

impl WindowBuilder {
    /// Creates a builder for `streams` generator streams of `policy`, all
    /// requested from `run.start` (nanoseconds).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The policy's slot size is zero.
    /// - The policy's window size is zero.
    /// - The policy's window size is not a multiple of the slot size (i.e.,
    ///   `window_size % slot_size != 0`).
    /// - The policy's window size is not a divisor of 1 day (86400 seconds).
    /// - The series length overflows `usize`.
    /// - `streams` is zero.
    /// - The window of the request start overflows.
    /// - The policy groups by a unit other than a single IP.
    /// - The policy is grouped and `run` has no generation.
    pub(super) fn try_new(
        policy: &TimeSeriesGenerationPolicy,
        run: RunStart,
        streams: usize,
    ) -> Result<Self> {
        let request_start = run.start;
        let slot_size_secs = policy.slot_size.as_secs();
        let window_size_secs = policy.window_size.as_secs();
        if slot_size_secs == 0 {
            bail!("slot size must be greater than 0");
        }
        if window_size_secs == 0 {
            bail!("window size must be greater than 0");
        }
        if !86400_u64.is_multiple_of(window_size_secs) {
            bail!("window size must be a divisor of 1 day (86400 seconds)");
        }
        if !window_size_secs.is_multiple_of(slot_size_secs) {
            bail!("window size must be a multiple of slot size");
        }
        if streams == 0 {
            bail!("a policy needs at least one stream");
        }
        if policy.group_by.is_some() && policy.group_by_unit != GroupByUnit::Ip {
            bail!("grouping by {:?} is not supported", policy.group_by_unit);
        }
        let generation = match (policy.group_by, run.generation) {
            (None, _) => None,
            (Some(_), Some(generation)) => Some(generation),
            (Some(_), None) => bail!("a grouped policy's run needs a write generation"),
        };
        let current = start_time(policy, request_start.div_euclid(SECOND_TO_NANO))?;

        Ok(Self {
            policy: policy.clone(),
            policy_id: policy.id.to_string(),
            slot_size_secs: i64::try_from(slot_size_secs)?,
            window_size_secs: i64::try_from(window_size_secs)?,
            slots: usize::try_from(window_size_secs / slot_size_secs)?,
            request_start,
            streams: std::iter::repeat_with(StreamState::default)
                .take(streams)
                .collect(),
            current,
            open: BTreeMap::new(),
            last_closed: None,
            dropped: 0,
            networks: policy.internal_networks.clone(),
            network_changes: Vec::new(),
            first_event_window: None,
            warned: current,
            accepted: HashSet::new(),
            max_series: MAX_SERIES_PER_POLICY,
            refused: BTreeMap::new(),
            generation,
            marked_from: (generation.is_some() && run.resumed).then_some(current),
            corrected: HashSet::new(),
        })
    }

    /// Makes `networks` the policy's internal network from the window after
    /// the one of the latest event any stream has received, or for every
    /// window if no stream has received one. Windows before that boundary keep
    /// the network they had. A network equal to the latest one changes
    /// nothing.
    pub(super) fn change_networks(&mut self, networks: HostNetworkGroup) {
        let latest_network = self
            .network_changes
            .last()
            .map_or(&self.networks, |(_, network)| network);
        if *latest_network == networks {
            return;
        }
        let Some(latest) = self.streams.iter().filter_map(|s| s.watermark).max() else {
            self.networks = networks;
            self.network_changes.clear();
            return;
        };
        let boundary = start_time(&self.policy, latest.div_euclid(SECOND_TO_NANO))
            .map_or(i64::MAX, |start| {
                start.saturating_add(self.window_size_secs)
            });
        match self.network_changes.last_mut() {
            // Watermarks only grow, so a boundary is never before the latest.
            Some((last, network)) if *last >= boundary => *network = networks,
            _ => self.network_changes.push((boundary, networks)),
        }
    }

    /// Binds an inbound stream to the policy and returns its index, or `None`
    /// if every stream of the policy has already opened.
    pub(super) fn open_stream(&mut self) -> Option<usize> {
        let (index, stream) = self
            .streams
            .iter_mut()
            .enumerate()
            .find(|(_, stream)| !stream.opened)?;
        stream.opened = true;
        Some(index)
    }

    /// Records that stream `index` received an event at `timestamp`
    /// (nanoseconds) at the monotonic time `now`, whether or not the event is
    /// then counted.
    pub(super) fn receive(&mut self, index: usize, timestamp: i64, now: Instant) {
        if self.first_event_window.is_none() {
            self.first_event_window =
                start_time(&self.policy, timestamp.div_euclid(SECOND_TO_NANO)).ok();
            if self.generation.is_some() && self.marked_from.is_none() {
                self.marked_from = self.first_event_window;
            }
        }
        let Some(stream) = self.streams.get_mut(index) else {
            return;
        };
        stream.watermark = Some(stream.watermark.map_or(timestamp, |w| w.max(timestamp)));
        if stream.replay_ended() {
            stream.idle_start = Some(now);
        }
    }

    /// Records that stream `index` received its replay-end frame at the
    /// monotonic time `now`. Returns `false`, changing nothing, if the stream
    /// had already received one.
    pub(super) fn replay_end(&mut self, index: usize, now: Instant) -> bool {
        let Some(stream) = self.streams.get_mut(index) else {
            return false;
        };
        if stream.replay_ended() {
            return false;
        }
        stream.idle_start = Some(now);
        true
    }

    /// Records that stream `index` ended: it passes no window it had not
    /// passed by `clock`.
    pub(super) fn end_stream(&mut self, index: usize, clock: &PassClock) {
        if let Some(stream) = self.streams.get_mut(index) {
            stream.ended_bound = Some(stream.bound(clock));
        }
    }

    /// Returns whether stream `index` holds an event and reads nothing more.
    pub(super) fn is_paused(&self, index: usize) -> bool {
        self.streams
            .get(index)
            .is_some_and(|stream| stream.held.is_some())
    }

    /// Returns the number of streams that have not opened and the number of
    /// opened streams that have not received their replay-end frame.
    pub(super) fn stall_counts(&self) -> (usize, usize) {
        let unopened = self.streams.iter().filter(|s| !s.opened).count();
        let replaying = self
            .streams
            .iter()
            .filter(|s| s.opened && !s.replay_ended())
            .count();
        (unopened, replaying)
    }

    /// Counts an event that stream `index` received at `timestamp`
    /// (nanoseconds), and returns the frame to write, if the event was counted
    /// in the last closed window: the corrected row, or for a grouped policy's
    /// IP without a row there, its new row followed by the window's marker.
    ///
    /// The checks run in order. An event rejected by the policy's address
    /// filter, or, for a grouped policy, whose group-side IP is not in the
    /// internal network in effect for its window or whose counterpart is out
    /// of scope, is never counted. An event before the request start, or older
    /// than the earliest window other than one in the last closed window, is
    /// dropped. An IP beyond [`MAX_SERIES_PER_POLICY`] is refused.
    ///
    /// The event is counted in its window when that window is the earliest
    /// one not yet due or the one after it. An event further ahead pauses the
    /// stream (see [`Self::is_paused`]) until enough windows have closed,
    /// unless the stream has not yet passed the earliest window, in which case
    /// it is counted at once (see [`Self::counts_now`]).
    ///
    /// Call [`Self::receive`] and [`Self::close_due`] for the event first.
    ///
    /// # Errors
    ///
    /// Returns an error if the event's window start or slot overflows, or if
    /// the policy sums a Conn field over an event of another kind.
    pub(super) fn add(
        &mut self,
        index: usize,
        timestamp: i64,
        event: &Event,
    ) -> Result<Option<IngestFrame>> {
        let time_secs = timestamp.div_euclid(SECOND_TO_NANO);
        let window_start = start_time(&self.policy, time_secs)?;
        let Some(value) = self.counted_value(event, window_start) else {
            return Ok(None);
        };
        if timestamp < self.request_start {
            self.drop_event();
            return Ok(None);
        }
        let in_last_closed = self
            .last_closed
            .as_ref()
            .is_some_and(|last| last.start_secs == window_start);
        if !in_last_closed && window_start < self.current {
            // Older than the last closed window, or a window that was never
            // written because it had no events when it became due and a
            // grouped policy closes no window there.
            self.drop_event();
            return Ok(None);
        }
        if !self.admit(value, window_start) {
            return Ok(None);
        }
        let measured = event_value(self.policy.measure, event)?;
        let key = value_key(&self.policy_id, value);
        let slot_size_secs = self.slot_size_secs;
        let slots = self.slots;

        if let Some(last) = self.last_closed.as_mut().filter(|_| in_last_closed) {
            let added = !last.values.contains_key(key.as_ref());
            count_in(last, &key, slots, slot_size_secs, time_secs, measured)?;
            let key = key.into_owned();
            return Ok(self.correction(&key, added));
        }
        if self.counts_now(window_start, timestamp) {
            count_open(
                &mut self.open,
                slots,
                slot_size_secs,
                window_start,
                &key,
                time_secs,
                measured,
            )?;
            return Ok(None);
        }
        let held = HeldEvent {
            timestamp,
            window_start,
            key: key.into_owned(),
            value: measured,
        };
        let Some(stream) = self.streams.get_mut(index) else {
            bail!("no stream {index} in policy {}", self.policy_id);
        };
        stream.held = Some(held);
        Ok(None)
    }

    /// Returns the value `event` is counted for in the window starting at
    /// `window_start`, or `None` if the policy does not count it.
    fn counted_value(&self, event: &Event, window_start: i64) -> Option<Value> {
        if !self.accepts(event) {
            return None;
        }
        let Some(side) = self.policy.group_by else {
            return Some(Value::Policy);
        };
        let (ip, counterpart) = match side {
            EndpointRole::Source => (event.orig_addr(), event.resp_addr()),
            EndpointRole::Destination => (event.resp_addr(), event.orig_addr()),
        };
        let network = self.network_at(window_start);
        if !in_network(network, ip) {
            return None;
        }
        let in_scope = match self.policy.counterpart_scope {
            CounterpartScope::Any => true,
            CounterpartScope::Internal => in_network(network, counterpart),
            CounterpartScope::External => !in_network(network, counterpart),
        };
        in_scope.then_some(Value::Ip(ip))
    }

    /// Returns the internal network in effect for the window starting at
    /// `window_start`.
    fn network_at(&self, window_start: i64) -> &HostNetworkGroup {
        let (_, network) = self.network_segment(window_start);
        network
    }

    /// Returns the internal network in effect for the window starting at
    /// `window_start` and the boundary of the next one, or `i64::MAX`.
    fn network_segment(&self, window_start: i64) -> (i64, &HostNetworkGroup) {
        let next = self
            .network_changes
            .partition_point(|(boundary, _)| *boundary <= window_start);
        let network = next
            .checked_sub(1)
            .and_then(|current| self.network_changes.get(current))
            .map_or(&self.networks, |(_, network)| network);
        let next_boundary = self
            .network_changes
            .get(next)
            .map_or(i64::MAX, |(boundary, _)| *boundary);
        (next_boundary, network)
    }

    /// Returns whether `value` may have a series, accepting an IP the cap
    /// still has room for. A refused IP is recorded for the warning of the
    /// window starting at `window_start`, or of the earliest window not yet
    /// warned about as due if that one already is.
    fn admit(&mut self, value: Value, window_start: i64) -> bool {
        let Value::Ip(ip) = value else {
            return true;
        };
        if self.accepted.contains(&ip) {
            return true;
        }
        if self.accepted.len() < self.max_series {
            self.accepted.insert(ip);
            return true;
        }
        self.refused
            .entry(window_start.max(self.warned))
            .or_default()
            .insert(ip);
        false
    }

    /// Closes the windows that every stream has passed by `clock`, in time
    /// order, and returns the frames to write: every value's series of one
    /// window, in ascending byte order of their series ids, each in its own
    /// frame. Held events whose window may now be counted are counted, and
    /// their streams resume.
    ///
    /// An ungrouped policy writes no due window without events. A grouped
    /// policy follows the IP rows of each window with its marker, and closes a
    /// due window without IP rows from [`Self::marked_from`] on with the
    /// marker `[0, generation]`, but only once a stream has passed it by event
    /// time; until then it and every later window stay open.
    ///
    /// A grouped policy warns for each due window in which it refused IPs for
    /// the cap, and for each due window, from the one of the first event any
    /// stream received on, whose internal network is empty, even while that
    /// window cannot close yet.
    pub(super) fn close_due(&mut self, clock: &PassClock) -> Vec<IngestFrame> {
        let mut written = Vec::new();
        loop {
            let due = self
                .streams
                .iter()
                .map(|stream| self.pass_limit(stream, clock))
                .min()
                .unwrap_or(i64::MIN);
            self.warn_due(due);
            let target = self.closable_until(due);
            if target <= self.current {
                break;
            }
            let later = self.open.split_off(&target);
            let closing = std::mem::replace(&mut self.open, later);
            if self.generation.is_some() {
                self.close_grouped(closing, target, &mut written);
            } else {
                for (_, window) in closing {
                    written.extend(self.close(window));
                }
            }
            self.current = target;
            self.release_held();
        }
        written
    }

    /// Returns how far a grouped policy closes windows when every window
    /// before `due` is due: up to the first window from [`Self::marked_from`]
    /// on that has no IP rows and that no stream has passed by event time, or
    /// `due` if there is none. An ungrouped policy closes up to `due`.
    fn closable_until(&self, due: i64) -> i64 {
        if self.generation.is_none() {
            return due;
        }
        let Some(marked_from) = self.marked_from else {
            return due;
        };
        let passed_by_events = self
            .streams
            .iter()
            .map(|stream| self.events_pass_limit(stream))
            .max()
            .unwrap_or(i64::MIN);
        let mut start = self.current.max(marked_from).max(passed_by_events);
        while start < due && self.open.contains_key(&start) {
            start = start.saturating_add(self.window_size_secs);
        }
        start.min(due)
    }

    /// Closes the windows of a grouped policy from the earliest not yet due up
    /// to `target`: those in `closing`, which have IP rows, and every other
    /// one from [`Self::marked_from`] on, in time order.
    fn close_grouped(
        &mut self,
        closing: BTreeMap<i64, Window>,
        target: i64,
        written: &mut Vec<IngestFrame>,
    ) {
        let mut next_empty = self
            .marked_from
            .map_or(target, |marked_from| marked_from.max(self.current));
        for (start, window) in closing {
            while next_empty < start {
                written.extend(self.close(Window::empty(next_empty)));
                next_empty = next_empty.saturating_add(self.window_size_secs);
            }
            written.extend(self.close(window));
            next_empty = next_empty.max(start.saturating_add(self.window_size_secs));
        }
        while next_empty < target {
            written.extend(self.close(Window::empty(next_empty)));
            next_empty = next_empty.saturating_add(self.window_size_secs);
        }
    }

    /// Returns the start of the earliest window `stream` has not passed.
    ///
    /// A stream that holds an event never passes the window before the held
    /// event's window, so that the held event is counted before its window
    /// can close.
    fn pass_limit(&self, stream: &StreamState, clock: &PassClock) -> i64 {
        let bound = stream.bound(clock);
        let limit = if bound == i64::MIN {
            i64::MIN
        } else {
            self.limit_below(bound)
        };
        match &stream.held {
            Some(held) => limit.min(held.window_start.saturating_sub(self.window_size_secs)),
            None => limit,
        }
    }

    /// Returns the start of the earliest window `stream` has not passed by
    /// the events it received, whether or not it has ended.
    fn events_pass_limit(&self, stream: &StreamState) -> i64 {
        stream
            .watermark
            .map_or(i64::MIN, |watermark| self.limit_below(watermark))
    }

    /// Returns the start of the earliest window whose end plus the grace is
    /// not below `bound` (nanoseconds).
    fn limit_below(&self, bound: i64) -> i64 {
        // A window is passed when its end plus the grace is below the bound,
        // so the earliest one not passed is the one containing the bound
        // minus the grace minus one nanosecond.
        let last_passed_end = bound
            .saturating_sub(CLOSE_GRACE_SECS.saturating_mul(SECOND_TO_NANO))
            .saturating_sub(1);
        start_time(&self.policy, last_passed_end.div_euclid(SECOND_TO_NANO)).unwrap_or(i64::MIN)
    }

    /// Returns whether an event at `timestamp` in the window starting at
    /// `window_start`, not older than the earliest window, is counted now
    /// rather than held: its window is the earliest one or the next, or the
    /// event has not passed the earliest window's end plus the grace.
    ///
    /// The second case arises only for windows shorter than the grace. A
    /// stream holding such an event would not have passed the earliest window
    /// by its events, so the window could close only by the wall clock, which
    /// a replaying stream never reaches: holding it could deadlock the policy.
    /// The windows open at once are therefore those starting at or before the
    /// earliest window's end plus the grace: two when a window is longer than
    /// the grace, and `2 + grace / window_size` (rounded down) otherwise.
    fn counts_now(&self, window_start: i64, timestamp: i64) -> bool {
        let next = self.current.saturating_add(self.window_size_secs);
        window_start <= next
            || timestamp
                <= next
                    .saturating_add(CLOSE_GRACE_SECS)
                    .saturating_mul(SECOND_TO_NANO)
    }

    /// Counts every held event whose window may now be counted.
    fn release_held(&mut self) {
        for index in 0..self.streams.len() {
            let Some(held) = self
                .streams
                .get(index)
                .and_then(|stream| stream.held.as_ref())
            else {
                continue;
            };
            if !self.counts_now(held.window_start, held.timestamp) {
                continue;
            }
            let Some(held) = self
                .streams
                .get_mut(index)
                .and_then(|stream| stream.held.take())
            else {
                continue;
            };
            let time_secs = held.timestamp.div_euclid(SECOND_TO_NANO);
            if let Err(e) = count_open(
                &mut self.open,
                self.slots,
                self.slot_size_secs,
                held.window_start,
                &held.key,
                time_secs,
                held.value,
            ) {
                warn!("Failed to generate time series: {e}");
            }
        }
    }

    fn accepts(&self, event: &Event) -> bool {
        self.policy
            .src_ip
            .is_none_or(|src_ip| event.orig_addr() == src_ip)
            && self
                .policy
                .dst_ip
                .is_none_or(|dst_ip| event.resp_addr() == dst_ip)
    }

    fn drop_event(&mut self) {
        self.dropped = self.dropped.saturating_add(1);
    }

    /// Warns once about each window before `due`, which is due whether or not
    /// it can close yet: those that refused IPs for the cap, and, for a
    /// grouped policy from the window of the first event any stream received
    /// on, those whose internal network is empty.
    fn warn_due(&mut self, due: i64) {
        let later = self.refused.split_off(&due);
        for (window_start, refused) in std::mem::replace(&mut self.refused, later) {
            warn!(
                policy_id = %self.policy_id,
                window_start,
                refused = refused.len(),
                max_series = self.max_series,
                "Policy {} refused {} IPs beyond its series cap in a window",
                self.policy_id,
                refused.len()
            );
        }
        let warned = self.warned;
        self.warned = warned.max(due);
        if self.policy.group_by.is_none() {
            return;
        }
        let Some(first) = self.first_event_window else {
            return;
        };
        let mut start = warned.max(first);
        while start < due {
            let (next_boundary, network) = self.network_segment(start);
            let end = due.min(next_boundary);
            if is_empty(network) {
                while start < end {
                    warn!(
                        policy_id = %self.policy_id,
                        window_start = start,
                        "Policy {} has no internal network; its window counts no events",
                        self.policy_id
                    );
                    start = start.saturating_add(self.window_size_secs);
                }
            }
            start = end;
        }
    }

    /// Makes `window` the last closed one and returns its frames for
    /// writing: one per row, and for a grouped policy then its marker.
    fn close(&mut self, window: Window) -> Vec<IngestFrame> {
        if self.dropped > 0 {
            warn!(
                policy_id = %self.policy_id,
                dropped = self.dropped,
                "Dropped late events that neither an open nor the last closed window takes"
            );
            self.dropped = 0;
        }
        if !self.corrected.is_empty() {
            warn!(
                policy_id = %self.policy_id,
                corrected = self.corrected.len(),
                "Policy {} corrected or added {} IP rows of a window after its marker",
                self.policy_id,
                self.corrected.len()
            );
            self.corrected.clear();
        }
        let mut frames: Vec<IngestFrame> = window
            .values
            .keys()
            .filter_map(|key| self.row(&window, key))
            .map(IngestFrame::from)
            .collect();
        frames.extend(self.marker(&window).map(IngestFrame::from));
        self.last_closed = Some(window);
        frames
    }

    /// Returns the frame that writes the `key` row of the last closed window
    /// again after an event was counted there: the row alone, or for a
    /// grouped policy's row `added` after the marker, the row and the
    /// window's new marker.
    fn correction(&mut self, key: &str, added: bool) -> Option<IngestFrame> {
        let last = self.last_closed.as_ref()?;
        let row = self.row(last, key)?;
        let marker = self.marker(last).filter(|_| added);
        if self.generation.is_some() {
            self.corrected.insert(key.to_owned());
        }
        Some(match marker {
            Some(marker) => IngestFrame::pair(row, marker),
            None => IngestFrame::from(row),
        })
    }

    /// Returns the `key` row of `window`: its values, which for a grouped
    /// policy are followed by the run's generation.
    fn row(&self, window: &Window, key: &str) -> Option<TimeSeries> {
        let mut row = window.series(self.policy.id, key)?;
        if let Some(generation) = self.generation {
            row.series.push(generation_value(generation));
        }
        Some(row)
    }

    /// Returns a grouped policy's marker of `window`, under the policy id:
    /// the number of its IP rows and the run's generation. `None` for an
    /// ungrouped policy.
    fn marker(&self, window: &Window) -> Option<TimeSeries> {
        let generation = self.generation?;
        // At most `max_series` IPs have a row.
        let rows = u32::try_from(window.values.len()).unwrap_or(u32::MAX);
        Some(TimeSeries {
            time_series_id: self.policy_id.clone(),
            policy_id: self.policy.id,
            start_secs: window.start_secs,
            series: vec![f64::from(rows), generation_value(generation)],
        })
    }
}

/// Returns `generation` as a time-series element.
// No `From` converts a `u64` to an `f64`. The conversion is exact: the
// policy actor never fixes a generation of 2^53 or more.
#[allow(clippy::cast_precision_loss)]
fn generation_value(generation: u64) -> f64 {
    generation as f64
}

/// Returns the key of the series `value` adds to, given the policy's id: the
/// policy's own id for an ungrouped policy, and `P/IP` for an IP, with the IP
/// in its `Display` form.
fn value_key(policy_id: &str, value: Value) -> Cow<'_, str> {
    match value {
        Value::Policy => Cow::Borrowed(policy_id),
        Value::Ip(ip) => Cow::Owned(format!("{policy_id}/{ip}")),
    }
}

/// Returns whether `ip` is one of the hosts of `network`, or lies in one of
/// its networks or ranges. Addresses are compared as they are: an IPv4
/// address is never in an IPv6 network or range, nor the reverse.
fn in_network(network: &HostNetworkGroup, ip: IpAddr) -> bool {
    network.hosts.contains(&ip)
        || network.networks.iter().any(|net| net.contains(&ip))
        || network.ip_ranges.iter().any(|range| {
            range.start().is_ipv4() == ip.is_ipv4()
                && range.end().is_ipv4() == ip.is_ipv4()
                && range.contains(&ip)
        })
}

/// Returns whether `network` has no host, network or range.
fn is_empty(network: &HostNetworkGroup) -> bool {
    network.hosts.is_empty() && network.networks.is_empty() && network.ip_ranges.is_empty()
}

/// Adds `value` at `time_secs` to the `key` series of the open window
/// starting at `start_secs`, creating the window with its first event.
fn count_open(
    open: &mut BTreeMap<i64, Window>,
    slots: usize,
    slot_size_secs: i64,
    start_secs: i64,
    key: &str,
    time_secs: i64,
    value: f64,
) -> Result<()> {
    let window = open.entry(start_secs).or_insert_with(|| Window {
        start_secs,
        values: BTreeMap::new(),
    });
    count_in(window, key, slots, slot_size_secs, time_secs, value)
}

/// Adds `value` at `time_secs` to the `key` series of `window`, creating the
/// series with `slots` zero slots if it has none.
fn count_in(
    window: &mut Window,
    key: &str,
    slots: usize,
    slot_size_secs: i64,
    time_secs: i64,
    value: f64,
) -> Result<()> {
    let slot = slot(slot_size_secs, window.start_secs, time_secs)?;
    let values = if let Some(values) = window.values.get_mut(key) {
        values
    } else {
        window
            .values
            .entry(key.to_owned())
            .or_insert_with(|| vec![0_f64; slots])
    };
    let Some(slot_value) = values.get_mut(slot) else {
        bail!("cannot access the time slot");
    };
    *slot_value += value;
    Ok(())
}

/// Returns the slot of `time_secs` in the window starting at `window_start`.
fn slot(slot_size_secs: i64, window_start: i64, time_secs: i64) -> Result<usize> {
    let elapsed = time_secs
        .checked_sub(window_start)
        .context("failed to calculate elapsed time")?;
    Ok(usize::try_from(elapsed / slot_size_secs)?)
}

/// Returns what `event` adds to its slot under `measure`.
fn event_value(measure: Measure, event: &Event) -> Result<f64> {
    match measure {
        Measure::Count => Ok(1_f64),
        Measure::Sum(field) => event
            .conn_field(field)
            .with_context(|| format!("Sum({field:?}) is defined only on Conn events")),
    }
}

fn start_time(policy: &TimeSeriesGenerationPolicy, time_secs: i64) -> Result<i64> {
    let offset_secs = i64::from(policy.utc_offset);
    let offset_time = time_secs
        .checked_add(offset_secs)
        .context("failed to apply policy UTC offset to timestamp")?;

    let seconds_of_day = offset_time.rem_euclid(SECONDS_PER_DAY);
    let timestamp_of_midnight = offset_time - seconds_of_day;

    let window_size = i64::try_from(policy.window_size.as_secs())?;
    let start_of_window = seconds_of_day - seconds_of_day.rem_euclid(window_size);
    let start_offset_time = timestamp_of_midnight
        .checked_add(start_of_window)
        .context("failed to calculate window start timestamp")?;
    let start_time = start_offset_time
        .checked_sub(offset_secs)
        .context("failed to convert window start timestamp to UTC")?;

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

    use review_protocol::types::{ConnField, Measure, RawEventKind};
    use time::{Date, Month};

    use super::*;

    const SECS_PER_MINUTE: u64 = 60;
    const SECS_PER_HOUR: u64 = 3600;
    const SECS_PER_DAY: u64 = 86_400;

    /// Helper to create a `TimeSeriesGenerationPolicy` with specified parameters
    fn create_policy(
        id: u32,
        window_size_secs: u64,
        slot_size_secs: u64,
        utc_offset: i32,
        measure: Measure,
    ) -> TimeSeriesGenerationPolicy {
        TimeSeriesGenerationPolicy {
            id,
            raw_event_kind: RawEventKind::Conn,
            measure,
            group_by: None,
            group_by_unit: GroupByUnit::Ip,
            counterpart_scope: CounterpartScope::Any,
            slot_size: Duration::from_secs(slot_size_secs),
            window_size: Duration::from_secs(window_size_secs),
            utc_offset,
            src_ip: None,
            dst_ip: None,
            sensors: vec!["test_node".to_string()],
            time_series_type: None,
            internal_networks: HostNetworkGroup::default(),
        }
    }

    fn create_simple_policy(
        slot_size_secs: u64,
        window_size_secs: u64,
    ) -> TimeSeriesGenerationPolicy {
        let id = 1;
        let utc_offset = 0;

        create_policy(
            id,
            window_size_secs,
            slot_size_secs,
            utc_offset,
            Measure::Count,
        )
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

    /// Returns the slot of `time_secs` in its own window.
    fn time_slot(policy: &TimeSeriesGenerationPolicy, time_secs: i64) -> Result<usize> {
        let slot_size = i64::try_from(policy.slot_size.as_secs())?;
        slot(slot_size, start_time(policy, time_secs)?, time_secs)
    }

    // =========================================================================
    // Tests for time_slot function - boundary conditions for period/interval/offset
    // =========================================================================

    #[test]
    fn test_time_slot_basic_1day_window_15min_slot() {
        // Window: 1 day (86400s), Slot: 15 min (900s) => 96 slots
        // Offset: 0
        let policy = create_policy(1, SECS_PER_DAY, 15 * SECS_PER_MINUTE, 0, Measure::Count);

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
        // Window: 1 day (86400s), Slot: 1 hour (3600s) => 24 slots
        // Offset: +9 hours (32400s) - KST adjustment
        let policy = create_policy(1, SECS_PER_DAY, SECS_PER_HOUR, 32_400, Measure::Count);
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
        // Window: 1 day (86400s), Slot: 1 hour (3600s) => 24 slots
        // Offset: -5 hours (-18000s) - shifts time backward
        let policy = create_policy(1, SECS_PER_DAY, SECS_PER_HOUR, -18_000, Measure::Count);

        // At midnight UTC, with -5h offset, offset_time = 19:00 (prev day) => slot 19
        let midnight = datetime_from_utc("2024/1/15 00:00:00");
        assert_eq!(time_slot(&policy, midnight).unwrap(), 19);

        // At 05:00 UTC, with -5h offset, offset_time = 00:00 => slot 0
        let utc_5h = datetime_from_utc("2024/1/15 05:00:00");
        assert_eq!(time_slot(&policy, utc_5h).unwrap(), 0);
    }

    #[test]
    fn test_time_slot_slot_equals_window() {
        // Window: 1 hour (3600s), Slot: 1 hour (3600s) => 1 slot
        // All times within the period should map to slot 0
        let policy = create_policy(1, SECS_PER_HOUR, SECS_PER_HOUR, 0, Measure::Count);

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
    fn test_time_slot_slot_1second() {
        // Window: 1 minute (60s), Slot: 1 second (1s) => 60 slots
        // Tests minimum interval
        let policy = create_policy(1, SECS_PER_MINUTE, 1, 0, Measure::Count);

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
    fn test_time_slot_offset_equals_window_minus_one() {
        // Window: 1 hour (3600s), Slot: 15 min (900s) => 4 slots
        // Offset: period - 1 = 3599s
        let policy = create_policy(1, SECS_PER_HOUR, 15 * SECS_PER_MINUTE, 3599, Measure::Count);

        let midnight = datetime_from_utc("2024/1/15 00:00:00");
        // At midnight UTC, offset_time = 00:59:59 => slot 3 (59*60+59 = 3599s) / 900 = 3
        // Actually: seconds_of_day = 3599, 3599 % 3600 = 3599, 3599 / 900 = 3
        assert_eq!(time_slot(&policy, midnight).unwrap(), 3);
    }

    #[test]
    fn test_time_slot_offset_in_middle_of_window() {
        // Window: 2 hours (7200s), Slot: 30 min (1800s) => 4 slots
        // Offset: 1 hour (3600s) - middle of period
        let policy = create_policy(
            1,
            2 * SECS_PER_HOUR,
            30 * SECS_PER_MINUTE,
            3600,
            Measure::Count,
        );

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
    fn test_start_time_aligns_to_window_boundary() {
        // Window: 1 hour (3600s), Slot: 15 min (900s)
        // Offset: 0
        let policy = create_policy(1, SECS_PER_HOUR, 15 * SECS_PER_MINUTE, 0, Measure::Count);

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
        // Window: 1 day (86400s), Slot: 1 hour (3600s)
        // Offset: +9 hours (32400s) - KST adjustment
        let policy = create_policy(1, SECS_PER_DAY, SECS_PER_HOUR, 32_400, Measure::Count);

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
    fn test_event_value_count_returns_1() {
        let conn = create_test_conn();
        let event = Event::Conn(conn);

        let value = event_value(Measure::Count, &event).unwrap();
        assert_eq!(value, 1.0);
    }

    #[test]
    fn test_event_value_conn_sum_fields() {
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

        let sum = |field| event_value(Measure::Sum(field), &event).unwrap();
        assert_eq!(sum(ConnField::Duration), 1_500_000_000.0);
        assert_eq!(sum(ConnField::OrigBytes), 1000.0);
        assert_eq!(sum(ConnField::RespBytes), 2000.0);
        assert_eq!(sum(ConnField::OrigPkts), 10.0);
        assert_eq!(sum(ConnField::RespPkts), 20.0);
    }

    #[test]
    fn test_event_value_dns_counts_1_and_has_no_sum() {
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

        assert_eq!(event_value(Measure::Count, &event).unwrap(), 1.0);
        assert!(event_value(Measure::Sum(ConnField::Duration), &event).is_err());
        assert!(event_value(Measure::Sum(ConnField::OrigBytes), &event).is_err());
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

    /// Helper to create a Conn event with specific values for `Sum` aggregation tests
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

    // =========================================================================
    // Tests for WindowBuilder::add and measure aggregation
    // =========================================================================

    #[test]
    fn test_add_single_event_counts_as_one() {
        // Window: 1 hour, Slot: 15 min => 4 slots
        // measure: Count => count events (each event adds 1.0)
        let policy = create_policy(1, SECS_PER_HOUR, 15 * SECS_PER_MINUTE, 0, Measure::Count);

        let mut builder = single(&policy, 0).unwrap();

        // Event at 00:05:00 => slot 0
        let event_time = datetime_from_utc("2024/1/15 00:05:00");
        let conn = create_test_conn();
        builder
            .feed(nanos(event_time), &Event::Conn(conn))
            .expect("add should succeed");

        // Verify slot 0 has value 1.0
        assert_eq!(open(&builder).series[0], 1.0);
        assert_eq!(open(&builder).series[1], 0.0);
        assert_eq!(open(&builder).series[2], 0.0);
        assert_eq!(open(&builder).series[3], 0.0);
    }

    #[test]
    fn test_add_multiple_events_same_slot_aggregates() {
        // Window: 1 hour, Slot: 15 min => 4 slots
        // measure: Count => count events
        let policy = create_policy(1, SECS_PER_HOUR, 15 * SECS_PER_MINUTE, 0, Measure::Count);

        let mut builder = single(&policy, 0).unwrap();

        // Three events at different times within slot 0 (00:00 - 00:15)
        let event_times = [
            "2024/1/15 00:01:00",
            "2024/1/15 00:05:00",
            "2024/1/15 00:14:00",
        ];
        for event_time in event_times {
            let event_time = datetime_from_utc(event_time);
            let conn = create_test_conn();
            builder
                .feed(nanos(event_time), &Event::Conn(conn))
                .expect("add should succeed");
        }

        // Verify slot 0 has value 3.0 (three events aggregated)
        assert_eq!(open(&builder).series[0], 3.0);
    }

    #[test]
    fn test_add_events_in_different_slots() {
        // Window: 1 hour, Slot: 15 min => 4 slots
        let policy = create_policy(1, SECS_PER_HOUR, 15 * SECS_PER_MINUTE, 0, Measure::Count);

        let mut builder = single(&policy, 0).unwrap();

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
                builder
                    .feed(nanos(event_time), &Event::Conn(conn))
                    .expect("add should succeed");
            }
            assert_eq!(
                open(&builder).series[slot],
                times.len() as f64,
                "slot {} should have {} events",
                slot,
                times.len()
            );
        }
    }

    #[test]
    fn test_add_with_sum_duration() {
        // Window: 1 hour, Slot: 15 min => 4 slots
        // measure: Sum(Duration) => sum duration values
        let policy = create_policy(
            1,
            SECS_PER_HOUR,
            15 * SECS_PER_MINUTE,
            0,
            Measure::Sum(ConnField::Duration),
        );

        let mut builder = single(&policy, 0).unwrap();

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
            builder
                .feed(nanos(event_time), &Event::Conn(conn))
                .expect("add should succeed");
        }

        // Verify slot 0 has sum of durations
        let expected_sum: f64 = durations.iter().map(|&d| d as f64).sum();
        assert_eq!(
            open(&builder).series[0],
            expected_sum,
            "expected {} but got {}",
            expected_sum,
            open(&builder).series[0]
        );
    }

    #[test]
    fn test_add_with_sum_orig_bytes() {
        // Window: 1 hour, Slot: 15 min => 4 slots
        // measure: Sum(OrigBytes) => sum orig_bytes values
        let policy = create_policy(
            1,
            SECS_PER_HOUR,
            15 * SECS_PER_MINUTE,
            0,
            Measure::Sum(ConnField::OrigBytes),
        );

        let mut builder = single(&policy, 0).unwrap();

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
            builder
                .feed(nanos(event_time), &Event::Conn(conn))
                .expect("add should succeed");
        }

        // Verify slot 0 is empty
        assert_eq!(open(&builder).series[0], 0.0);

        // Verify slot 1 has sum of orig_bytes
        let expected_sum: f64 = bytes_values.iter().map(|&b| b as f64).sum();
        assert_eq!(
            open(&builder).series[1],
            expected_sum,
            "expected {} but got {}",
            expected_sum,
            open(&builder).series[1]
        );
    }

    #[test]
    fn test_add_with_sum_orig_pkts() {
        // Window: 1 hour, Slot: 30 min => 2 slots
        // measure: Sum(OrigPkts) => sum orig_pkts values
        let policy = create_policy(
            1,
            SECS_PER_HOUR,
            30 * SECS_PER_MINUTE,
            0,
            Measure::Sum(ConnField::OrigPkts),
        );

        let mut builder = single(&policy, 0).unwrap();

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
            builder
                .feed(nanos(event_time), &Event::Conn(conn))
                .expect("add should succeed");
        }

        // Slot 1: 35 min and 45 min
        let slot_1_events = [("2024/1/15 00:35:00", 2_u64), ("2024/1/15 00:45:00", 7_u64)];
        for (event_time, packets) in slot_1_events {
            let event_time = datetime_from_utc(event_time);
            let conn = create_conn_with_values(0, 0, 0, packets, 0);
            builder
                .feed(nanos(event_time), &Event::Conn(conn))
                .expect("add should succeed");
        }

        // Verify slot 0: 10 + 20 + 50 = 80 (minutes 5=>10, 10=>20, 25=>50)
        assert_eq!(
            open(&builder).series[0],
            80.0,
            "slot 0 expected 80 but got {}",
            open(&builder).series[0]
        );

        // Verify slot 1: 2 + 7 = 9 (minutes 35=>2, 45=>7)
        assert_eq!(
            open(&builder).series[1],
            9.0,
            "slot 1 expected 9 but got {}",
            open(&builder).series[1]
        );
    }

    #[test]
    fn test_add_window_boundary_sends_and_resets() {
        // Window: 1 hour, Slot: 15 min => 4 slots
        let policy = create_policy(1, SECS_PER_HOUR, 15 * SECS_PER_MINUTE, 0, Measure::Count);
        let mut builder = single(&policy, 0).unwrap();

        // Add an event in the first period (slot 0)
        let written = add_at(&mut builder, "2024/1/15 00:05:00");
        assert!(written.is_empty());
        assert_eq!(open(&builder).series[0], 1.0);

        // Events of the next period within the first one's grace count there
        // and leave the first open; exactly end + 900 s has not passed it.
        assert!(add_at(&mut builder, "2024/1/15 01:01:05").is_empty());
        assert!(add_at(&mut builder, "2024/1/15 01:15:00").is_empty());
        assert_eq!(open_windows(&builder).len(), 2);

        // An event past the first window's end plus the grace writes it.
        let written = add_at(&mut builder, "2024/1/15 01:15:01");
        assert_eq!(
            starts_and_values(&written),
            [(
                datetime_from_utc("2024/1/15 00:00:00"),
                vec![1.0, 0.0, 0.0, 0.0]
            )]
        );

        // The next period holds the three events after 01:00.
        assert_eq!(
            open(&builder).start_secs,
            datetime_from_utc("2024/1/15 01:00:00")
        );
        assert_eq!(open(&builder).series, [1.0, 2.0, 0.0, 0.0]);
    }

    #[test]
    fn test_add_kst_offset_events_aggregate_same_slot() {
        // Window: 1 day, Slot: 15 min => 96 slots
        // Offset: +9 hours (KST)
        let policy = create_policy(
            1,
            SECS_PER_DAY,
            15 * SECS_PER_MINUTE,
            32_400,
            Measure::Count,
        );
        let mut builder = single(&policy, 0).unwrap();

        for event_time in [
            "2022/11/17 00:03:00",
            "2022/11/17 00:06:00",
            "2022/11/17 00:09:00",
        ] {
            let conn = create_test_conn();
            builder
                .feed(nanos(datetime_from_utc(event_time)), &Event::Conn(conn))
                .expect("add should succeed");
        }

        // UTC 00:03/00:06/00:09 becomes KST 09:03/09:06/09:09, which is slot 36.
        assert_eq!(open(&builder).series[36], 3.0);
    }

    #[test]
    fn test_add_with_offset_affects_slot_calculation() {
        // Window: 1 day, Slot: 1 hour => 24 slots
        // Offset: +9 hours (32400s) - KST adjustment
        let policy = create_policy(1, SECS_PER_DAY, SECS_PER_HOUR, 32_400, Measure::Count);

        let kst_midnight_utc = datetime_from_utc("2024/1/14 15:00:00");
        let mut builder = single(&policy, 0).unwrap();
        // The window opens at its first event's KST midnight.

        // KST midnight (UTC 15:00) event maps to slot 0
        let event_time = datetime_from_utc("2024/1/14 15:00:00");
        let conn = create_test_conn();
        builder
            .feed(nanos(event_time), &Event::Conn(conn))
            .expect("add should succeed");

        assert_eq!(open(&builder).start_secs, kst_midnight_utc);
        assert_eq!(open(&builder).series[0], 1.0);

        // All other slots should be empty
        for (i, &value) in open(&builder).series.iter().enumerate() {
            if i != 0 {
                assert_eq!(value, 0.0, "slot {i} should be 0 but is {value}");
            }
        }
    }

    #[test]
    fn test_add_missing_slots_remain_zero() {
        // Window: 1 hour, Slot: 10 min => 6 slots
        let policy = create_policy(1, SECS_PER_HOUR, 10 * SECS_PER_MINUTE, 0, Measure::Count);

        let mut builder = single(&policy, 0).unwrap();

        // Only add events to slots 0, 2, and 5 (skip 1, 3, 4)
        let event_times = [
            "2024/1/15 00:05:00",
            "2024/1/15 00:25:00",
            "2024/1/15 00:55:00",
        ];
        for event_time in event_times {
            let event_time = datetime_from_utc(event_time);
            let conn = create_test_conn();
            builder
                .feed(nanos(event_time), &Event::Conn(conn))
                .expect("add should succeed");
        }

        // Verify only specific slots have values
        assert_eq!(open(&builder).series[0], 1.0);
        assert_eq!(open(&builder).series[1], 0.0); // missing
        assert_eq!(open(&builder).series[2], 1.0);
        assert_eq!(open(&builder).series[3], 0.0); // missing
        assert_eq!(open(&builder).series[4], 0.0); // missing
        assert_eq!(open(&builder).series[5], 1.0);
    }

    #[test]
    fn test_add_duplicate_timestamps_aggregate() {
        // Window: 1 hour, Slot: 15 min => 4 slots
        let policy = create_policy(1, SECS_PER_HOUR, 15 * SECS_PER_MINUTE, 0, Measure::Count);

        let mut builder = single(&policy, 0).unwrap();

        // Add multiple events with exactly the same timestamp
        let event_time = datetime_from_utc("2024/1/15 00:05:00");
        for _ in 0..5 {
            let conn = create_test_conn();
            builder
                .feed(nanos(event_time), &Event::Conn(conn))
                .expect("add should succeed");
        }

        // All 5 events should aggregate into slot 0
        assert_eq!(open(&builder).series[0], 5.0);
    }

    // =========================================================================
    // Tests for TimeSeries construction
    // =========================================================================
    #[test]
    fn try_new_opens_no_window_at_the_request_start() {
        let policy = create_simple_policy(60, 3600);
        for request_start in [1_700_003_600_000_000_001, -1, 0] {
            let builder = single(&policy, request_start).unwrap();
            assert_eq!(builder.request_start, request_start);
            assert_eq!(
                builder.current,
                start_time(&policy, request_start.div_euclid(SECOND_TO_NANO)).unwrap(),
                "windows become due from the one of the request start"
            );
            assert!(builder.open.is_empty());
            assert!(builder.last_closed.is_none());
        }
    }

    #[test]
    fn try_new_valid_window_and_slot_sizes() {
        // window size (3600) is a multiple of slot size (60)
        let policy = create_simple_policy(60, 3600);
        let result = single(&policy, 0);
        assert!(result.is_ok());
        let ts = result.unwrap();
        assert_eq!(ts.slots, 60); // 3600 / 60 = 60
    }

    #[test]
    fn try_new_invalid_window_not_divisor_of_1_day() {
        // window size (777) is not a divisor of 1 day (86400 seconds)
        let policy = create_simple_policy(7, 777);
        let result = single(&policy, 0);
        let err_msg = result.err().expect("the policy is rejected").to_string();
        assert!(
            err_msg.contains("window size must be a divisor of 1 day (86400 seconds)"),
            "unexpected error message: {err_msg}"
        );
    }

    #[test]
    fn try_new_invalid_window_not_multiple_of_slot() {
        // window size (100) is not a multiple of slot size (30)
        let policy = create_simple_policy(30, 100);
        let result = single(&policy, 0);
        let err_msg = result.err().expect("the policy is rejected").to_string();
        assert!(
            err_msg.contains("window size must be a multiple of slot size"),
            "unexpected error message: {err_msg}"
        );
    }

    #[test]
    fn try_new_slot_size_zero() {
        // slot size is 0, should error before division
        let policy = create_simple_policy(0, 3600);
        let result = single(&policy, 0);
        let err_msg = result.err().expect("the policy is rejected").to_string();
        assert!(
            err_msg.contains("slot size must be greater than 0"),
            "unexpected error message: {err_msg}"
        );
    }

    #[test]
    fn try_new_window_size_zero() {
        // window size is 0, should error
        let policy = create_simple_policy(60, 0);
        let result = single(&policy, 0);
        let err_msg = result.err().expect("the policy is rejected").to_string();
        assert!(
            err_msg.contains("window size must be greater than 0"),
            "unexpected error message: {err_msg}"
        );
    }

    // =========================================================================
    // Tests for window routing, the timer close and the address filter
    // =========================================================================

    fn nanos(secs: i64) -> i64 {
        secs * SECOND_TO_NANO
    }

    /// The write generation of the runs of grouped policies in these tests.
    const GENERATION: u64 = 1_764_000_000_000;

    /// The run of `policy` requested from `request_start`, which is its
    /// checkpoint unless it is 0, with [`GENERATION`] if it is grouped.
    fn run_from(policy: &TimeSeriesGenerationPolicy, request_start: i64) -> RunStart {
        RunStart {
            start: request_start,
            resumed: request_start != 0,
            generation: policy.group_by.map(|_| GENERATION),
        }
    }

    /// A builder for `policy` over one stream, which has opened.
    fn single(policy: &TimeSeriesGenerationPolicy, request_start: i64) -> Result<WindowBuilder> {
        let mut builder = WindowBuilder::try_new(policy, run_from(policy, request_start), 1)?;
        builder.open_stream().expect("the stream opens");
        Ok(builder)
    }

    /// A clock under which no stream passes a window by being quiet.
    fn event_time_only() -> PassClock {
        PassClock {
            wall_secs: i64::MIN,
            now: Instant::now(),
            idle: Duration::from_secs(30),
        }
    }

    /// Returns the rows of `frames`, in order.
    fn flatten(frames: Vec<IngestFrame>) -> Vec<TimeSeries> {
        frames
            .into_iter()
            .flat_map(IngestFrame::into_rows)
            .collect()
    }

    /// Delivers events to a builder as the policy runner does.
    trait Feed {
        /// Delivers an event on stream 0 and returns the rows written.
        fn feed(&mut self, timestamp: i64, event: &Event) -> Result<Vec<TimeSeries>> {
            self.feed_on(0, timestamp, event)
        }

        /// Delivers an event on `stream` and returns the rows written.
        fn feed_on(
            &mut self,
            stream: usize,
            timestamp: i64,
            event: &Event,
        ) -> Result<Vec<TimeSeries>> {
            Ok(flatten(self.frames_on(stream, timestamp, event)?))
        }

        /// Closes the windows due by `clock` and returns the rows written.
        fn close_rows(&mut self, clock: &PassClock) -> Vec<TimeSeries>;

        /// Delivers an event on `stream` and returns the frames written.
        fn frames_on(
            &mut self,
            stream: usize,
            timestamp: i64,
            event: &Event,
        ) -> Result<Vec<IngestFrame>>;
    }

    impl Feed for WindowBuilder {
        fn close_rows(&mut self, clock: &PassClock) -> Vec<TimeSeries> {
            flatten(self.close_due(clock))
        }

        fn frames_on(
            &mut self,
            stream: usize,
            timestamp: i64,
            event: &Event,
        ) -> Result<Vec<IngestFrame>> {
            self.receive(stream, timestamp, Instant::now());
            let mut written = self.close_due(&event_time_only());
            written.extend(self.add(stream, timestamp, event)?);
            Ok(written)
        }
    }

    /// Returns the earliest open window.
    fn open(builder: &WindowBuilder) -> TimeSeries {
        builder
            .open
            .values()
            .next()
            .and_then(|window| window.series(builder.policy.id, &builder.policy_id))
            .expect("a window is open")
    }

    /// Adds a counted event at `datetime` on stream 0 and returns the windows
    /// written.
    fn add_at(builder: &mut WindowBuilder, datetime: &str) -> Vec<TimeSeries> {
        add_on(builder, 0, datetime)
    }

    /// Adds a counted event at `datetime` on stream `stream` and returns the
    /// windows written.
    fn add_on(builder: &mut WindowBuilder, stream: usize, datetime: &str) -> Vec<TimeSeries> {
        builder
            .feed_on(
                stream,
                nanos(datetime_from_utc(datetime)),
                &Event::Conn(create_test_conn()),
            )
            .expect("add should succeed")
    }

    /// Returns the start and the values of every written window.
    fn starts_and_values(written: &[TimeSeries]) -> Vec<(i64, Vec<f64>)> {
        written
            .iter()
            .map(|series| (series.start_secs, series.series.clone()))
            .collect()
    }

    /// Returns the start and the values of every open window.
    fn open_windows(builder: &WindowBuilder) -> Vec<(i64, Vec<f64>)> {
        builder
            .open
            .values()
            .filter_map(|window| window.series(builder.policy.id, &builder.policy_id))
            .map(|series| (series.start_secs, series.series))
            .collect()
    }

    fn last_closed(builder: &WindowBuilder) -> TimeSeries {
        builder
            .last_closed
            .as_ref()
            .and_then(|window| window.series(builder.policy.id, &builder.policy_id))
            .expect("a window was closed")
    }

    /// Returns a clock for `after` past `origin` at the wall clock
    /// `wall_secs`, with the production idle time.
    fn clock_at(origin: Instant, after: Duration, wall_secs: i64) -> PassClock {
        PassClock {
            wall_secs,
            now: origin + after,
            idle: Duration::from_secs(30),
        }
    }

    fn conn_between(orig_addr: &str, resp_addr: &str) -> Event {
        Event::Conn(giganto_client::ingest::network::Conn {
            orig_addr: orig_addr.parse().unwrap(),
            resp_addr: resp_addr.parse().unwrap(),
            ..create_test_conn()
        })
    }

    #[test]
    fn first_event_opens_its_window_and_the_first_close_writes_it() {
        // Window: 1 hour, Slot: 15 min. No checkpoint: the request starts at 0.
        for (offset, window_start, next_event) in [
            (0, "2024/1/15 05:00:00", "2024/1/15 06:20:00"),
            // With offset 13200 (3h40m) an hourly window starts at hh:20.
            (13_200, "2024/1/15 05:20:00", "2024/1/15 06:40:00"),
        ] {
            let policy = create_policy(
                1,
                SECS_PER_HOUR,
                15 * SECS_PER_MINUTE,
                offset,
                Measure::Count,
            );
            let mut builder = single(&policy, 0).unwrap();

            assert!(add_at(&mut builder, "2024/1/15 05:40:00").is_empty());
            assert_eq!(open(&builder).start_secs, datetime_from_utc(window_start));

            let written = add_at(&mut builder, next_event);
            let [written] = written.as_slice() else {
                panic!("the first window is written: {written:?}");
            };
            assert_eq!(written.start_secs, datetime_from_utc(window_start));
            assert_ne!(written.start_secs, 0);
            assert_eq!(written.series.iter().sum::<f64>(), 1.0);
        }
    }

    #[test]
    fn resume_rewrites_the_last_window_and_writes_no_zero_row() {
        // The checkpoint is the start of the last written window, 05:00. The
        // window after it, 06:00, had no events.
        let policy = create_policy(1, SECS_PER_HOUR, 15 * SECS_PER_MINUTE, 0, Measure::Count);
        let checkpoint = datetime_from_utc("2024/1/15 05:00:00");
        let mut builder = single(&policy, nanos(checkpoint)).unwrap();

        let mut written = Vec::new();
        for event in [
            "2024/1/15 05:00:00",
            "2024/1/15 05:20:00",
            "2024/1/15 05:50:00",
            "2024/1/15 07:05:00",
        ] {
            written.extend(add_at(&mut builder, event));
        }

        assert_eq!(written.len(), 1, "{written:?}");
        assert_eq!(written[0].start_secs, checkpoint);
        assert_eq!(written[0].series, [1.0, 1.0, 0.0, 1.0]);
        assert_eq!(
            open(&builder).start_secs,
            datetime_from_utc("2024/1/15 07:00:00")
        );
    }

    #[test]
    fn late_event_for_the_last_closed_window_rewrites_it() {
        let policy = create_policy(1, SECS_PER_HOUR, 15 * SECS_PER_MINUTE, 0, Measure::Count);
        let mut builder = single(&policy, 0).unwrap();
        add_at(&mut builder, "2024/1/15 00:05:00");
        let first = add_at(&mut builder, "2024/1/15 01:20:00");
        let window = datetime_from_utc("2024/1/15 00:00:00");
        assert_eq!(
            starts_and_values(&first),
            [(window, vec![1.0, 0.0, 0.0, 0.0])]
        );

        let rewritten = add_at(&mut builder, "2024/1/15 00:35:00");
        assert_eq!(
            starts_and_values(&rewritten),
            [(window, vec![1.0, 0.0, 1.0, 0.0])]
        );

        // The open window is unchanged.
        assert_eq!(
            open(&builder).start_secs,
            datetime_from_utc("2024/1/15 01:00:00")
        );
        assert_eq!(open(&builder).series, [0.0, 1.0, 0.0, 0.0]);
        assert_eq!(builder.dropped, 0);
    }

    #[test]
    fn event_older_than_the_last_closed_window_is_dropped_and_counted() {
        let policy = create_policy(1, SECS_PER_HOUR, 15 * SECS_PER_MINUTE, 0, Measure::Count);
        let mut builder = single(&policy, 0).unwrap();
        add_at(&mut builder, "2024/1/15 00:05:00");
        assert_eq!(add_at(&mut builder, "2024/1/15 01:20:00").len(), 1, "00:00");
        assert_eq!(add_at(&mut builder, "2024/1/15 02:20:00").len(), 1, "01:00");

        assert!(add_at(&mut builder, "2024/1/15 00:10:00").is_empty());
        assert_eq!(builder.dropped, 1);
        assert_eq!(open(&builder).series, [0.0, 1.0, 0.0, 0.0]);
        assert_eq!(last_closed(&builder).series, [0.0, 1.0, 0.0, 0.0]);

        // A gap window, never written because it had no events when it
        // became due, takes none.
        let written = add_at(&mut builder, "2024/1/15 05:20:00");
        assert_eq!(
            starts_and_values(&written),
            [(
                datetime_from_utc("2024/1/15 02:00:00"),
                vec![0.0, 1.0, 0.0, 0.0]
            )],
            "03:00 and 04:00 are due without events and not written"
        );
        assert_eq!(builder.dropped, 0, "the close reports and resets the count");
        assert!(add_at(&mut builder, "2024/1/15 03:05:00").is_empty());
        assert_eq!(builder.dropped, 1);
    }

    #[test]
    fn event_before_the_request_start_is_dropped_and_opens_no_window() {
        let policy = create_policy(1, SECS_PER_HOUR, 15 * SECS_PER_MINUTE, 0, Measure::Count);
        let request_start = nanos(datetime_from_utc("2024/1/15 05:00:00"));
        let mut builder = single(&policy, request_start).unwrap();

        let written = builder
            .feed(request_start - 1, &Event::Conn(create_test_conn()))
            .unwrap();
        assert!(written.is_empty());
        assert!(builder.open.is_empty());
        assert_eq!(builder.dropped, 1);

        builder
            .feed(request_start, &Event::Conn(create_test_conn()))
            .unwrap();
        assert_eq!(open(&builder).start_secs, request_start / SECOND_TO_NANO);
    }

    #[test]
    fn quiet_stream_passes_after_its_replay_end_idle_and_the_wall_clock() {
        let policy = create_policy(1, SECS_PER_HOUR, 15 * SECS_PER_MINUTE, 0, Measure::Count);
        let mut builder = single(&policy, 0).unwrap();
        add_at(&mut builder, "2024/1/15 00:05:00");
        let end = datetime_from_utc("2024/1/15 01:00:00");
        let origin = Instant::now();
        let at = |after_secs, wall| clock_at(origin, Duration::from_secs(after_secs), wall);

        // Before its replay end a stream never passes by the wall clock,
        // however long it is quiet.
        assert!(builder.close_rows(&at(86_400, end + 86_400)).is_empty());

        assert!(builder.replay_end(0, origin));
        assert_eq!(CLOSE_GRACE_SECS, 900);
        assert!(
            builder.close_rows(&at(29, end + 10_000)).is_empty(),
            "idle 29 s"
        );
        assert!(
            builder.close_rows(&at(30, end + 899)).is_empty(),
            "end + 899 s"
        );
        let written = builder.close_rows(&at(30, end + 900));
        assert_eq!(
            starts_and_values(&written),
            [(
                datetime_from_utc("2024/1/15 00:00:00"),
                vec![1.0, 0.0, 0.0, 0.0]
            )],
            "due at idle 30 s and end + 900 s"
        );
        assert!(builder.open.is_empty());
        assert!(
            builder.close_rows(&at(60, end + 10_000)).is_empty(),
            "written once"
        );

        // A straggler after the close rewrites the window.
        let rewritten = add_at(&mut builder, "2024/1/15 00:50:00");
        assert_eq!(
            starts_and_values(&rewritten),
            [(
                datetime_from_utc("2024/1/15 00:00:00"),
                vec![1.0, 0.0, 0.0, 1.0]
            )]
        );
        assert!(builder.open.is_empty());
    }

    #[test]
    fn idle_start_follows_the_last_event_after_the_replay_end() {
        let policy = create_policy(1, SECS_PER_HOUR, 15 * SECS_PER_MINUTE, 0, Measure::Count);
        let mut builder = single(&policy, 0).unwrap();
        let event = nanos(datetime_from_utc("2024/1/15 00:05:00"));
        let end = datetime_from_utc("2024/1/15 01:00:00");
        let origin = Instant::now();
        let at = |after_secs| clock_at(origin, Duration::from_secs(after_secs), end + 900);

        // An event before the replay end does not start the idle time.
        builder.receive(0, event, origin + Duration::from_secs(100));
        builder
            .add(0, event, &Event::Conn(create_test_conn()))
            .unwrap();
        assert!(builder.replay_end(0, origin));
        // An event after the replay end restarts it.
        builder.receive(0, event, origin + Duration::from_secs(20));
        builder
            .add(0, event, &Event::Conn(create_test_conn()))
            .unwrap();
        assert!(builder.close_rows(&at(49)).is_empty(), "idle since 20 s");
        assert_eq!(builder.close_rows(&at(50)).len(), 1);
    }

    #[test]
    fn second_replay_end_changes_nothing() {
        let policy = create_policy(1, SECS_PER_HOUR, 15 * SECS_PER_MINUTE, 0, Measure::Count);
        let mut builder = single(&policy, 0).unwrap();
        add_at(&mut builder, "2024/1/15 00:05:00");
        let end = datetime_from_utc("2024/1/15 01:00:00");
        let origin = Instant::now();
        let at = |after_secs| clock_at(origin, Duration::from_secs(after_secs), end + 900);

        assert!(builder.replay_end(0, origin));
        assert!(
            !builder.replay_end(0, origin + Duration::from_secs(20)),
            "a second replay end is not a replay end"
        );
        assert_eq!(builder.stall_counts(), (0, 0));
        assert_eq!(
            builder.close_rows(&at(30)).len(),
            1,
            "the idle start is still the first replay end"
        );
    }

    // =========================================================================
    // Tests for a policy over several streams
    // =========================================================================

    /// A builder for `policy` over two streams requested from 2024/1/15 00:00,
    /// both opened.
    fn pair(policy: &TimeSeriesGenerationPolicy) -> WindowBuilder {
        let start = nanos(datetime_from_utc("2024/1/15 00:00:00"));
        let mut builder = WindowBuilder::try_new(policy, run_from(policy, start), 2).unwrap();
        assert_eq!(builder.open_stream(), Some(0));
        assert_eq!(builder.open_stream(), Some(1));
        builder
    }

    fn hourly() -> TimeSeriesGenerationPolicy {
        create_policy(1, SECS_PER_HOUR, 15 * SECS_PER_MINUTE, 0, Measure::Count)
    }

    #[test]
    fn events_of_every_stream_add_into_the_same_window_and_slot() {
        let mut builder = pair(&hourly());
        add_on(&mut builder, 0, "2024/1/15 00:05:00");
        add_on(&mut builder, 1, "2024/1/15 00:06:00");
        add_on(&mut builder, 1, "2024/1/15 00:20:00");
        assert_eq!(
            open_windows(&builder),
            [(
                datetime_from_utc("2024/1/15 00:00:00"),
                vec![2.0, 1.0, 0.0, 0.0]
            )]
        );
        assert_eq!(open(&builder).time_series_id, "1");
    }

    #[test]
    fn window_closes_only_once_every_stream_passed_it() {
        let mut builder = pair(&hourly());
        add_on(&mut builder, 0, "2024/1/15 00:05:00");
        add_on(&mut builder, 1, "2024/1/15 00:10:00");

        // Stream 0 is past 00:00's end plus the grace; stream 1 is not.
        assert!(add_on(&mut builder, 0, "2024/1/15 01:20:00").is_empty());
        // Stream 1's later events still count in 00:00.
        assert!(add_on(&mut builder, 1, "2024/1/15 00:50:00").is_empty());
        assert!(add_on(&mut builder, 1, "2024/1/15 01:15:00").is_empty());

        let written = add_on(&mut builder, 1, "2024/1/15 01:15:01");
        assert_eq!(
            starts_and_values(&written),
            [(
                datetime_from_utc("2024/1/15 00:00:00"),
                vec![2.0, 0.0, 0.0, 1.0]
            )]
        );
        assert_eq!(
            open_windows(&builder),
            [(
                datetime_from_utc("2024/1/15 01:00:00"),
                vec![0.0, 3.0, 0.0, 0.0]
            )]
        );
    }

    #[test]
    fn unopened_stream_holds_every_window_open() {
        let policy = hourly();
        let start = nanos(datetime_from_utc("2024/1/15 00:00:00"));
        let end = datetime_from_utc("2024/1/15 01:00:00");
        let origin = Instant::now();
        let mut builder = WindowBuilder::try_new(&policy, run_from(&policy, start), 2).unwrap();
        assert_eq!(builder.stall_counts(), (2, 0));
        assert_eq!(builder.open_stream(), Some(0));
        assert_eq!(builder.stall_counts(), (1, 1));

        add_on(&mut builder, 0, "2024/1/15 00:05:00");
        assert!(builder.replay_end(0, origin));
        assert_eq!(builder.stall_counts(), (1, 0));
        // Stream 0 is past 00:00 by event time and by the wall clock.
        assert!(add_on(&mut builder, 0, "2024/1/15 01:20:00").is_empty());
        let far = clock_at(origin, Duration::from_hours(24), end + 86_400);
        assert!(builder.close_rows(&far).is_empty());

        // The late stream opens and replays: its events of 00:00 count there.
        assert_eq!(builder.open_stream(), Some(1));
        assert_eq!(builder.open_stream(), None, "only two streams bind");
        assert_eq!(builder.stall_counts(), (0, 1));
        assert!(add_on(&mut builder, 1, "2024/1/15 00:30:00").is_empty());
        let written = add_on(&mut builder, 1, "2024/1/15 01:16:00");
        assert_eq!(
            starts_and_values(&written),
            [(
                datetime_from_utc("2024/1/15 00:00:00"),
                vec![1.0, 0.0, 1.0, 0.0]
            )]
        );
    }

    #[test]
    fn replaying_stream_never_passes_by_idle() {
        let mut builder = pair(&hourly());
        let end = datetime_from_utc("2024/1/15 01:00:00");
        let origin = Instant::now();
        add_on(&mut builder, 0, "2024/1/15 00:05:00");
        add_on(&mut builder, 1, "2024/1/15 00:06:00");
        assert!(builder.replay_end(0, origin));

        // Stream 1 has not reached its replay end: an hour quiet with the wall
        // clock a day past the window's end does not pass it.
        let at = |after_secs| clock_at(origin, Duration::from_secs(after_secs), end + 86_400);
        assert!(builder.close_rows(&at(3600)).is_empty());
        assert_eq!(builder.stall_counts(), (0, 1));

        // Its replay continues into the same window, then ends.
        assert!(add_on(&mut builder, 1, "2024/1/15 00:40:00").is_empty());
        assert!(builder.replay_end(1, origin + Duration::from_secs(3600)));
        assert_eq!(builder.stall_counts(), (0, 0));
        assert!(builder.close_rows(&at(3629)).is_empty());
        let written = builder.close_rows(&at(3630));
        assert_eq!(
            starts_and_values(&written),
            [(
                datetime_from_utc("2024/1/15 00:00:00"),
                vec![2.0, 0.0, 1.0, 0.0]
            )]
        );
    }

    #[test]
    fn stream_with_nothing_to_replay_passes_30_s_after_its_replay_end() {
        let mut builder = pair(&hourly());
        let end = datetime_from_utc("2024/1/15 01:00:00");
        let origin = Instant::now();
        add_on(&mut builder, 0, "2024/1/15 00:05:00");
        assert!(builder.replay_end(0, origin));
        assert!(builder.replay_end(1, origin + Duration::from_secs(100)));

        let at = |after_secs| clock_at(origin, Duration::from_secs(after_secs), end + 900);
        assert!(builder.close_rows(&at(129)).is_empty());
        assert_eq!(builder.close_rows(&at(130)).len(), 1);
    }

    #[test]
    fn event_two_windows_ahead_pauses_its_stream_until_the_window_closes() {
        // No stream has reached its replay end: the window closes by event
        // time alone.
        let mut builder = pair(&hourly());
        add_on(&mut builder, 0, "2024/1/15 00:05:00");
        add_on(&mut builder, 1, "2024/1/15 00:10:00");

        assert!(add_on(&mut builder, 0, "2024/1/15 02:30:00").is_empty());
        assert!(builder.is_paused(0));
        assert!(!builder.is_paused(1));
        assert_eq!(
            open_windows(&builder),
            [(
                datetime_from_utc("2024/1/15 00:00:00"),
                vec![2.0, 0.0, 0.0, 0.0]
            )],
            "the held event is not counted yet"
        );

        // Stream 1 passes 00:00; the held event counts in 02:00.
        let written = add_on(&mut builder, 1, "2024/1/15 01:20:00");
        assert_eq!(
            starts_and_values(&written),
            [(
                datetime_from_utc("2024/1/15 00:00:00"),
                vec![2.0, 0.0, 0.0, 0.0]
            )]
        );
        assert!(!builder.is_paused(0));
        assert_eq!(
            open_windows(&builder),
            [
                (
                    datetime_from_utc("2024/1/15 01:00:00"),
                    vec![0.0, 1.0, 0.0, 0.0]
                ),
                (
                    datetime_from_utc("2024/1/15 02:00:00"),
                    vec![0.0, 0.0, 1.0, 0.0]
                ),
            ]
        );
    }

    #[test]
    fn paused_stream_resumes_once_the_other_passes_by_idle() {
        let mut builder = pair(&hourly());
        let end = datetime_from_utc("2024/1/15 01:00:00");
        let origin = Instant::now();
        add_on(&mut builder, 0, "2024/1/15 00:05:00");
        assert!(add_on(&mut builder, 0, "2024/1/15 02:30:00").is_empty());
        assert!(builder.is_paused(0));
        assert!(builder.replay_end(1, origin));

        let at = |after_secs| clock_at(origin, Duration::from_secs(after_secs), end + 900);
        assert!(builder.close_rows(&at(29)).is_empty());
        assert!(builder.is_paused(0));
        let written = builder.close_rows(&at(30));
        assert_eq!(
            starts_and_values(&written),
            [(
                datetime_from_utc("2024/1/15 00:00:00"),
                vec![1.0, 0.0, 0.0, 0.0]
            )]
        );
        assert!(!builder.is_paused(0));
        assert_eq!(
            open_windows(&builder),
            [(
                datetime_from_utc("2024/1/15 02:00:00"),
                vec![0.0, 0.0, 1.0, 0.0]
            )]
        );
    }

    #[test]
    fn held_event_is_counted_before_its_window_can_close() {
        // Both streams end up far past every window by the wall clock, but
        // the held window still takes the held event.
        let mut builder = pair(&hourly());
        let origin = Instant::now();
        add_on(&mut builder, 0, "2024/1/15 00:05:00");
        assert!(add_on(&mut builder, 0, "2024/1/15 02:30:00").is_empty());
        assert!(builder.replay_end(0, origin));
        assert!(builder.replay_end(1, origin));
        let far = clock_at(
            origin,
            Duration::from_secs(60),
            datetime_from_utc("2024/1/16 00:00:00"),
        );
        let written = builder.close_rows(&far);
        assert_eq!(
            starts_and_values(&written),
            [
                (
                    datetime_from_utc("2024/1/15 00:00:00"),
                    vec![1.0, 0.0, 0.0, 0.0]
                ),
                (
                    datetime_from_utc("2024/1/15 02:00:00"),
                    vec![0.0, 0.0, 1.0, 0.0]
                ),
            ]
        );
    }

    #[test]
    fn streams_replayed_at_different_speeds_lose_no_events() {
        const EVENTS: i64 = 36;
        let mut builder = pair(&hourly());
        let start = datetime_from_utc("2024/1/15 00:00:00");
        // One event every 10 minutes over six hours on each stream. Stream 0
        // is replayed five times as fast as stream 1.
        let mut queues: [std::collections::VecDeque<i64>; 2] =
            std::array::from_fn(|_| (0..EVENTS).map(|i| nanos(start + i * 600)).collect());
        let mut written = Vec::new();
        let mut paused = false;
        while queues.iter().any(|queue| !queue.is_empty()) {
            let mut progressed = false;
            for (stream, batch) in [(0, 5), (1, 1)] {
                for _ in 0..batch {
                    if builder.is_paused(stream) {
                        paused = true;
                        break;
                    }
                    let Some(timestamp) = queues[stream].pop_front() else {
                        break;
                    };
                    progressed = true;
                    written.extend(
                        builder
                            .feed_on(stream, timestamp, &Event::Conn(create_test_conn()))
                            .unwrap(),
                    );
                }
            }
            assert!(progressed, "a pause never deadlocks");
        }
        assert!(paused, "the faster stream pauses");
        let origin = Instant::now();
        assert!(builder.replay_end(0, origin));
        assert!(builder.replay_end(1, origin));
        written.extend(builder.close_rows(&clock_at(
            origin,
            Duration::from_secs(60),
            datetime_from_utc("2024/1/16 00:00:00"),
        )));

        let mut last_values = BTreeMap::new();
        for series in written {
            last_values.insert(series.start_secs, series.series);
        }
        assert_eq!(last_values.len(), 6);
        for (window_start, values) in &last_values {
            // Per stream: 00 and 10 in slot 0, 20 in 1, 30 and 40 in 2, 50 in 3.
            assert_eq!(values, &[4.0, 2.0, 4.0, 2.0], "{window_start}");
        }
        assert_eq!(builder.dropped, 0);
    }

    #[test]
    fn event_not_past_the_earliest_windows_grace_is_counted_not_held() {
        // With 1-minute windows an event two windows ahead is still within
        // the earliest window's grace; its stream has not passed that window,
        // so holding it could never resume.
        let policy = create_policy(1, SECS_PER_MINUTE, SECS_PER_MINUTE, 0, Measure::Count);
        let mut builder = pair(&policy);
        add_on(&mut builder, 0, "2024/1/15 00:00:10");
        add_on(&mut builder, 0, "2024/1/15 00:02:10");
        add_on(&mut builder, 0, "2024/1/15 00:15:30");
        assert!(!builder.is_paused(0));
        assert_eq!(open_windows(&builder).len(), 3);

        // Past the earliest window's grace, an event two windows ahead holds.
        assert!(add_on(&mut builder, 0, "2024/1/15 00:16:30").is_empty());
        assert!(builder.is_paused(0));
        let written = add_on(&mut builder, 1, "2024/1/15 00:16:01");
        assert_eq!(written.len(), 1, "00:00 closes");
        assert!(!builder.is_paused(0));
    }

    #[test]
    fn ended_stream_passes_no_further_window() {
        let mut builder = pair(&hourly());
        let end = datetime_from_utc("2024/1/15 01:00:00");
        let origin = Instant::now();
        add_on(&mut builder, 0, "2024/1/15 00:05:00");
        add_on(&mut builder, 1, "2024/1/15 00:06:00");
        assert!(builder.replay_end(1, origin));
        builder.end_stream(1, &clock_at(origin, Duration::ZERO, end));
        assert!(add_on(&mut builder, 0, "2024/1/15 01:20:00").is_empty());
        assert!(builder.replay_end(0, origin));
        let far = clock_at(origin, Duration::from_secs(3600), end + 86_400);
        assert!(builder.close_rows(&far).is_empty());
    }

    #[test]
    fn filter_rejected_event_passes_windows_but_neither_opens_nor_counts() {
        let mut policy = create_policy(1, SECS_PER_HOUR, 15 * SECS_PER_MINUTE, 0, Measure::Count);
        policy.src_ip = Some("10.0.0.1".parse().unwrap());
        let mut builder = single(&policy, 0).unwrap();
        let accepted = conn_between("10.0.0.1", "10.0.0.9");
        let rejected = conn_between("10.0.0.2", "10.0.0.9");
        let at = |datetime| nanos(datetime_from_utc(datetime));

        // A rejected event neither opens a window nor counts.
        assert!(
            builder
                .feed(at("2024/1/15 00:01:00"), &rejected)
                .unwrap()
                .is_empty()
        );
        assert!(builder.open.is_empty());
        builder.feed(at("2024/1/15 00:05:00"), &accepted).unwrap();
        builder.feed(at("2024/1/15 00:06:00"), &rejected).unwrap();
        assert_eq!(open(&builder).series, [1.0, 0.0, 0.0, 0.0]);

        // A rejected event past the open window's end plus the grace passes
        // it, so the window is written.
        let written = builder.feed(at("2024/1/15 01:20:00"), &rejected).unwrap();
        assert_eq!(
            starts_and_values(&written),
            [(
                datetime_from_utc("2024/1/15 00:00:00"),
                vec![1.0, 0.0, 0.0, 0.0]
            )]
        );
        assert!(builder.open.is_empty());

        // It does not rewrite the last closed window either.
        assert!(
            builder
                .feed(at("2024/1/15 00:30:00"), &rejected)
                .unwrap()
                .is_empty()
        );
        assert_eq!(last_closed(&builder).series, [1.0, 0.0, 0.0, 0.0]);
        assert_eq!(builder.dropped, 0);

        builder.feed(at("2024/1/15 01:10:00"), &accepted).unwrap();
        assert_eq!(
            open(&builder).start_secs,
            datetime_from_utc("2024/1/15 01:00:00")
        );
        assert_eq!(open(&builder).series, [1.0, 0.0, 0.0, 0.0]);
    }

    #[test]
    fn address_filter_truth_table() {
        const SRC: &str = "10.0.0.1";
        const DST: &str = "10.0.0.2";
        const OTHER: &str = "10.0.0.3";
        let events = [
            ("src→dst", conn_between(SRC, DST)),
            ("src→other", conn_between(SRC, OTHER)),
            ("other→dst", conn_between(OTHER, DST)),
            ("other→other", conn_between(OTHER, OTHER)),
            // The filter is directional: a reversed flow does not match.
            ("dst→src", conn_between(DST, SRC)),
        ];
        let cases: [(Option<&str>, Option<&str>, [bool; 5]); 4] = [
            (None, None, [true, true, true, true, true]),
            (Some(SRC), None, [true, true, false, false, false]),
            (None, Some(DST), [true, false, true, false, false]),
            (Some(SRC), Some(DST), [true, false, false, false, false]),
        ];
        for (src_ip, dst_ip, expected) in cases {
            let mut policy = create_simple_policy(60, 3600);
            policy.src_ip = src_ip.map(|ip| ip.parse().unwrap());
            policy.dst_ip = dst_ip.map(|ip| ip.parse().unwrap());
            let builder = single(&policy, 0).unwrap();
            for ((name, event), expected) in events.iter().zip(expected) {
                assert_eq!(
                    builder.accepts(event),
                    expected,
                    "src_ip {src_ip:?}, dst_ip {dst_ip:?}, event {name}"
                );
            }
        }
    }

    // =========================================================================
    // Tests for grouped policies
    // =========================================================================

    const GROUPED_ID: u32 = 42;
    const EXTERNAL: &str = "8.8.8.8";

    /// An hourly policy with 15-minute slots grouped by `side`.
    fn grouped(
        side: EndpointRole,
        scope: CounterpartScope,
        networks: HostNetworkGroup,
    ) -> TimeSeriesGenerationPolicy {
        let mut policy = create_policy(
            GROUPED_ID,
            SECS_PER_HOUR,
            15 * SECS_PER_MINUTE,
            0,
            Measure::Count,
        );
        policy.group_by = Some(side);
        policy.counterpart_scope = scope;
        policy.internal_networks = networks;
        policy
    }

    /// A grouped-by-source policy over every counterpart whose internal
    /// network is `hosts`.
    fn by_source(hosts: &[&str]) -> TimeSeriesGenerationPolicy {
        grouped(EndpointRole::Source, CounterpartScope::Any, of_hosts(hosts))
    }

    fn of_hosts(hosts: &[&str]) -> HostNetworkGroup {
        HostNetworkGroup {
            hosts: hosts.iter().map(|host| host.parse().unwrap()).collect(),
            networks: Vec::new(),
            ip_ranges: Vec::new(),
        }
    }

    /// Delivers a Conn event from `orig` to `resp` at `datetime` on `stream`
    /// and returns the series written.
    fn conn_on(
        builder: &mut WindowBuilder,
        stream: usize,
        datetime: &str,
        orig: &str,
        resp: &str,
    ) -> Vec<TimeSeries> {
        builder
            .feed_on(
                stream,
                nanos(datetime_from_utc(datetime)),
                &conn_between(orig, resp),
            )
            .expect("add should succeed")
    }

    /// Delivers a Conn event from `orig` to an external IP on stream 0.
    fn from_ip(builder: &mut WindowBuilder, datetime: &str, orig: &str) -> Vec<TimeSeries> {
        conn_on(builder, 0, datetime, orig, EXTERNAL)
    }

    /// Returns the id, the start and the values of every written series.
    fn rows(written: &[TimeSeries]) -> Vec<(String, i64, Vec<f64>)> {
        written
            .iter()
            .map(|series| {
                assert_eq!(series.policy_id, GROUPED_ID, "{series:?}");
                (
                    series.time_series_id.clone(),
                    series.start_secs,
                    series.series.clone(),
                )
            })
            .collect()
    }

    /// Returns the IP row `id` of the window starting at `datetime`: its four
    /// slot values followed by [`GENERATION`].
    fn row(id: &str, datetime: &str, values: [f64; 4]) -> (String, i64, Vec<f64>) {
        let mut data = values.to_vec();
        data.push(GENERATION as f64);
        (id.to_owned(), datetime_from_utc(datetime), data)
    }

    /// Returns the marker of the window starting at `datetime` with `rows` IP
    /// rows.
    fn marker(datetime: &str, rows: u32) -> (String, i64, Vec<f64>) {
        (
            GROUPED_ID.to_string(),
            datetime_from_utc(datetime),
            vec![f64::from(rows), GENERATION as f64],
        )
    }

    /// Runs `f` and returns its result with the lines it logged.
    fn logged<T>(f: impl FnOnce() -> T) -> (T, Vec<String>) {
        #[derive(Clone, Default)]
        struct Lines(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Lines {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let lines = Lines::default();
        let writer = lines.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        let result = tracing::subscriber::with_default(subscriber, f);
        let text = String::from_utf8(lines.0.lock().unwrap().clone()).unwrap();
        (result, text.lines().map(str::to_owned).collect())
    }

    fn containing<'a>(lines: &'a [String], text: &str) -> Vec<&'a String> {
        lines.iter().filter(|line| line.contains(text)).collect()
    }

    #[test]
    fn grouped_series_id_is_the_policy_and_the_group_side_ip() {
        let internal = of_hosts(&["10.100.0.5", "2001:db8::1"]);
        for (side, orig, resp, id) in [
            (
                EndpointRole::Source,
                "10.100.0.5",
                EXTERNAL,
                "42/10.100.0.5",
            ),
            (
                EndpointRole::Destination,
                EXTERNAL,
                "10.100.0.5",
                "42/10.100.0.5",
            ),
            (
                EndpointRole::Source,
                "2001:db8::1",
                "2001:db8::99",
                "42/2001:db8::1",
            ),
            (
                EndpointRole::Destination,
                "2001:db8::99",
                "2001:db8::1",
                "42/2001:db8::1",
            ),
        ] {
            let policy = grouped(side, CounterpartScope::Any, internal.clone());
            let mut builder = single(&policy, 0).unwrap();
            assert!(conn_on(&mut builder, 0, "2024/1/15 00:05:00", orig, resp).is_empty());
            // Both endpoints external: not counted, but it passes 00:00.
            let written = conn_on(&mut builder, 0, "2024/1/15 01:20:00", EXTERNAL, EXTERNAL);
            assert_eq!(
                rows(&written),
                [
                    row(id, "2024/1/15 00:00:00", [1.0, 0.0, 0.0, 0.0]),
                    marker("2024/1/15 00:00:00", 1),
                ],
                "{side:?} {orig} → {resp}"
            );
            assert!(builder.open.is_empty(), "the external event opens nothing");
        }

        // An ungrouped policy writes under its own id.
        let mut builder = single(&create_simple_policy(900, 3600), 0).unwrap();
        add_at(&mut builder, "2024/1/15 00:05:00");
        let written = add_at(&mut builder, "2024/1/15 01:20:00");
        let ids: Vec<&str> = written.iter().map(|s| s.time_series_id.as_str()).collect();
        assert_eq!(ids, ["1"]);
        assert_eq!(written[0].policy_id, 1);
    }

    #[test]
    fn target_ip_is_internal_by_host_network_or_range() {
        let internal = HostNetworkGroup {
            hosts: vec!["10.0.0.1".parse().unwrap(), "2001:db8::1".parse().unwrap()],
            networks: vec![
                "192.168.0.0/16".parse().unwrap(),
                "2001:db8:1::/48".parse().unwrap(),
            ],
            ip_ranges: vec![
                "172.16.0.10".parse().unwrap()..="172.16.0.20".parse().unwrap(),
                "2001:db8:2::10".parse().unwrap()..="2001:db8:2::20".parse().unwrap(),
            ],
        };
        let policy = grouped(EndpointRole::Source, CounterpartScope::Any, internal);
        let builder = single(&policy, 0).unwrap();
        for (ip, expected) in [
            ("10.0.0.1", true),
            ("10.0.0.2", false),
            ("2001:db8::1", true),
            ("192.168.200.7", true),
            ("192.169.0.1", false),
            ("2001:db8:1:ffff::1", true),
            ("172.16.0.10", true),
            ("172.16.0.15", true),
            ("172.16.0.20", true),
            ("172.16.0.9", false),
            ("172.16.0.21", false),
            ("2001:db8:2::15", true),
            ("2001:db8:2::21", false),
            // An IPv4-mapped IPv6 address is not an IPv4 address.
            ("::ffff:10.0.0.1", false),
            ("::ffff:192.168.0.1", false),
            ("::ffff:172.16.0.15", false),
        ] {
            assert_eq!(
                builder
                    .counted_value(&conn_between(ip, EXTERNAL), 0)
                    .is_some(),
                expected,
                "{ip}"
            );
        }
    }

    #[test]
    fn counterpart_scope_filters_by_the_other_endpoint() {
        const IN_A: &str = "10.0.0.1";
        const IN_B: &str = "10.0.0.2";
        const OUT_A: &str = "8.8.8.8";
        const OUT_B: &str = "1.1.1.1";
        let events = [
            ("internal→internal", conn_between(IN_A, IN_B)),
            ("internal→external", conn_between(IN_A, OUT_A)),
            ("external→internal", conn_between(OUT_A, IN_B)),
            ("external→external", conn_between(OUT_A, OUT_B)),
        ];
        let internal = HostNetworkGroup {
            hosts: Vec::new(),
            networks: vec!["10.0.0.0/8".parse().unwrap()],
            ip_ranges: Vec::new(),
        };
        let cases = [
            (
                EndpointRole::Source,
                CounterpartScope::Any,
                [Some(IN_A), Some(IN_A), None, None],
            ),
            (
                EndpointRole::Source,
                CounterpartScope::Internal,
                [Some(IN_A), None, None, None],
            ),
            (
                EndpointRole::Source,
                CounterpartScope::External,
                [None, Some(IN_A), None, None],
            ),
            (
                EndpointRole::Destination,
                CounterpartScope::Any,
                [Some(IN_B), None, Some(IN_B), None],
            ),
            (
                EndpointRole::Destination,
                CounterpartScope::Internal,
                [Some(IN_B), None, None, None],
            ),
            (
                EndpointRole::Destination,
                CounterpartScope::External,
                [None, None, Some(IN_B), None],
            ),
        ];
        for (side, scope, expected) in cases {
            let builder = single(&grouped(side, scope, internal.clone()), 0).unwrap();
            for ((name, event), expected) in events.iter().zip(expected) {
                let counted = match builder.counted_value(event, 0) {
                    Some(Value::Ip(ip)) => Some(ip),
                    Some(Value::Policy) => panic!("a grouped policy counts IPs"),
                    None => None,
                };
                assert_eq!(
                    counted,
                    expected.map(|ip| ip.parse().unwrap()),
                    "{side:?} {scope:?} {name}"
                );
            }
        }
    }

    #[test]
    fn counted_or_not_every_event_moves_the_watermark() {
        let mut builder = single(&by_source(&["10.0.0.1"]), 0).unwrap();
        from_ip(&mut builder, "2024/1/15 00:05:00", "10.0.0.1");
        from_ip(&mut builder, "2024/1/15 00:50:00", "10.0.0.7");
        assert_eq!(
            builder.streams[0].watermark,
            Some(nanos(datetime_from_utc("2024/1/15 00:50:00")))
        );
        let keys: Vec<&String> = builder
            .open
            .values()
            .flat_map(|window| window.values.keys())
            .collect();
        assert_eq!(keys, ["42/10.0.0.1"]);
    }

    #[test]
    fn two_streams_add_the_same_ip_into_the_same_slot() {
        let mut builder = pair(&by_source(&["10.0.0.1", "10.0.0.2"]));
        conn_on(&mut builder, 0, "2024/1/15 00:05:00", "10.0.0.1", EXTERNAL);
        conn_on(&mut builder, 1, "2024/1/15 00:06:00", "10.0.0.1", EXTERNAL);
        conn_on(&mut builder, 1, "2024/1/15 00:07:00", "10.0.0.2", EXTERNAL);
        conn_on(&mut builder, 0, "2024/1/15 01:20:00", EXTERNAL, EXTERNAL);
        let written = conn_on(&mut builder, 1, "2024/1/15 01:20:00", EXTERNAL, EXTERNAL);
        assert_eq!(
            rows(&written),
            [
                row("42/10.0.0.1", "2024/1/15 00:00:00", [2.0, 0.0, 0.0, 0.0]),
                row("42/10.0.0.2", "2024/1/15 00:00:00", [1.0, 0.0, 0.0, 0.0]),
                marker("2024/1/15 00:00:00", 2),
            ]
        );
    }

    #[test]
    fn every_ip_of_a_window_closes_together_in_series_id_order() {
        let mut builder = single(&by_source(&["10.0.0.1", "10.0.0.9", "10.0.0.10"]), 0).unwrap();
        // 10.0.0.9 falls quiet after one event.
        from_ip(&mut builder, "2024/1/15 00:05:00", "10.0.0.9");
        from_ip(&mut builder, "2024/1/15 00:10:00", "10.0.0.10");
        from_ip(&mut builder, "2024/1/15 00:20:00", "10.0.0.1");
        assert!(from_ip(&mut builder, "2024/1/15 01:10:00", "10.0.0.1").is_empty());
        // The busy IP's event passes 00:00, which closes for every IP.
        let written = from_ip(&mut builder, "2024/1/15 01:20:00", "10.0.0.1");
        assert_eq!(
            rows(&written),
            [
                row("42/10.0.0.1", "2024/1/15 00:00:00", [0.0, 1.0, 0.0, 0.0]),
                row("42/10.0.0.10", "2024/1/15 00:00:00", [1.0, 0.0, 0.0, 0.0]),
                row("42/10.0.0.9", "2024/1/15 00:00:00", [1.0, 0.0, 0.0, 0.0]),
                marker("2024/1/15 00:00:00", 3),
            ],
            "ascending byte order of the series ids, then the marker"
        );
        assert!(builder.open.values().all(|window| {
            window.values.keys().eq(["42/10.0.0.1"])
                && window.start_secs == datetime_from_utc("2024/1/15 01:00:00")
        }));
    }

    /// Delivers a Conn event from `orig` to an external IP at `datetime` on
    /// stream 0 and returns the rows of each frame written.
    fn frames_from_ip(
        builder: &mut WindowBuilder,
        datetime: &str,
        orig: &str,
    ) -> Vec<Vec<(String, i64, Vec<f64>)>> {
        builder
            .frames_on(
                0,
                nanos(datetime_from_utc(datetime)),
                &conn_between(orig, EXTERNAL),
            )
            .expect("add should succeed")
            .iter()
            .map(|frame| rows(frame.rows()))
            .collect()
    }

    /// After the marker of the last closed window, an IP that has a row there
    /// gets its corrected row alone, and an IP without one gets its new row
    /// and the marker counting it in one frame, both with the run's
    /// generation. The next close warns with the number of distinct rows
    /// corrected or added; an older event is dropped.
    #[test]
    fn late_event_rewrites_or_adds_an_ip_row_and_an_older_one_is_dropped() {
        let mut builder = single(&by_source(&["10.0.0.1", "10.0.0.5", "10.0.0.9"]), 0).unwrap();
        from_ip(&mut builder, "2024/1/15 00:05:00", "10.0.0.1");
        from_ip(&mut builder, "2024/1/15 00:06:00", "10.0.0.9");
        assert_eq!(
            frames_from_ip(&mut builder, "2024/1/15 01:20:00", "10.0.0.1"),
            [
                vec![row(
                    "42/10.0.0.1",
                    "2024/1/15 00:00:00",
                    [1.0, 0.0, 0.0, 0.0]
                )],
                vec![row(
                    "42/10.0.0.9",
                    "2024/1/15 00:00:00",
                    [1.0, 0.0, 0.0, 0.0]
                )],
                vec![marker("2024/1/15 00:00:00", 2)],
            ],
            "one row per frame at the close"
        );

        let rewritten = frames_from_ip(&mut builder, "2024/1/15 00:40:00", "10.0.0.9");
        assert_eq!(
            rewritten,
            [vec![row(
                "42/10.0.0.9",
                "2024/1/15 00:00:00",
                [1.0, 0.0, 1.0, 0.0]
            )]],
            "no marker for a corrected row"
        );
        let rewritten = frames_from_ip(&mut builder, "2024/1/15 00:41:00", "10.0.0.9");
        assert_eq!(
            rewritten,
            [vec![row(
                "42/10.0.0.9",
                "2024/1/15 00:00:00",
                [1.0, 0.0, 2.0, 0.0]
            )]]
        );
        let added = frames_from_ip(&mut builder, "2024/1/15 00:50:00", "10.0.0.5");
        assert_eq!(
            added,
            [vec![
                row("42/10.0.0.5", "2024/1/15 00:00:00", [0.0, 0.0, 0.0, 1.0]),
                marker("2024/1/15 00:00:00", 3),
            ]],
            "the new row and the marker in one frame"
        );
        assert_eq!(builder.dropped, 0);

        let (written, lines) = logged(|| from_ip(&mut builder, "2024/1/15 02:20:00", "10.0.0.1"));
        assert_eq!(
            rows(&written),
            [
                row("42/10.0.0.1", "2024/1/15 01:00:00", [0.0, 1.0, 0.0, 0.0]),
                marker("2024/1/15 01:00:00", 1),
            ]
        );
        let warnings = containing(&lines, "after its marker");
        assert_eq!(warnings.len(), 1, "{lines:?}");
        assert!(warnings[0].contains("WARN"), "{warnings:?}");
        assert!(warnings[0].contains("policy_id=42"), "{warnings:?}");
        assert!(
            warnings[0].contains("corrected=2"),
            "a row corrected twice counts once: {warnings:?}"
        );
        assert!(from_ip(&mut builder, "2024/1/15 00:30:00", "10.0.0.9").is_empty());
        assert!(from_ip(&mut builder, "2024/1/15 00:30:00", "10.0.0.6").is_empty());
        assert_eq!(builder.dropped, 1, "only the counted IP's event is dropped");

        // Without corrections since the previous close, a close warns
        // nothing about them.
        let (_, lines) = logged(|| from_ip(&mut builder, "2024/1/15 03:20:00", "10.0.0.1"));
        assert_eq!(containing(&lines, "after its marker").len(), 0, "{lines:?}");
        assert_eq!(
            containing(&lines, "Dropped late events").len(),
            1,
            "{lines:?}"
        );
    }

    /// An ungrouped policy's late correction rewrites its row alone, with no
    /// generation, and logs no correction warning.
    #[test]
    fn ungrouped_late_correction_writes_no_marker_and_warns_nothing() {
        let mut builder = single(&create_simple_policy(900, 3600), 0).unwrap();
        add_at(&mut builder, "2024/1/15 00:05:00");
        let written = add_at(&mut builder, "2024/1/15 01:20:00");
        assert_eq!(
            starts_and_values(&written),
            [(
                datetime_from_utc("2024/1/15 00:00:00"),
                vec![1.0, 0.0, 0.0, 0.0]
            )]
        );
        let frames = builder
            .frames_on(
                0,
                nanos(datetime_from_utc("2024/1/15 00:40:00")),
                &Event::Conn(create_test_conn()),
            )
            .unwrap();
        let [frame] = frames.as_slice() else {
            panic!("one frame: {frames:?}");
        };
        assert_eq!(
            starts_and_values(frame.rows()),
            [(
                datetime_from_utc("2024/1/15 00:00:00"),
                vec![1.0, 0.0, 1.0, 0.0]
            )]
        );
        assert_eq!(frame.rows()[0].time_series_id, "1");
        let (written, lines) = logged(|| add_at(&mut builder, "2024/1/15 02:20:00"));
        assert_eq!(
            starts_and_values(&written),
            [(
                datetime_from_utc("2024/1/15 01:00:00"),
                vec![0.0, 1.0, 0.0, 0.0]
            )]
        );
        assert_eq!(containing(&lines, "after its marker").len(), 0, "{lines:?}");
    }

    #[test]
    fn network_change_applies_from_the_window_after_the_latest_event() {
        let mut builder = single(&by_source(&["10.0.0.1"]), 0).unwrap();
        from_ip(&mut builder, "2024/1/15 00:05:00", "10.0.0.1");
        from_ip(&mut builder, "2024/1/15 00:10:00", "10.0.0.2");
        builder.change_networks(of_hosts(&["10.0.0.2"]));
        assert_eq!(
            builder.network_changes,
            [(
                datetime_from_utc("2024/1/15 01:00:00"),
                of_hosts(&["10.0.0.2"])
            )]
        );

        // 00:00 keeps the previous network.
        from_ip(&mut builder, "2024/1/15 00:20:00", "10.0.0.2");
        from_ip(&mut builder, "2024/1/15 00:30:00", "10.0.0.1");
        // From 01:00 on the new one: the removed IP gets no window.
        from_ip(&mut builder, "2024/1/15 01:05:00", "10.0.0.2");
        from_ip(&mut builder, "2024/1/15 01:06:00", "10.0.0.1");
        let written = from_ip(&mut builder, "2024/1/15 02:20:00", EXTERNAL);
        assert_eq!(
            rows(&written),
            [
                row("42/10.0.0.1", "2024/1/15 00:00:00", [1.0, 0.0, 1.0, 0.0]),
                marker("2024/1/15 00:00:00", 1),
                row("42/10.0.0.2", "2024/1/15 01:00:00", [1.0, 0.0, 0.0, 0.0]),
                marker("2024/1/15 01:00:00", 1),
            ]
        );
    }

    #[test]
    fn each_network_change_applies_from_its_own_boundary() {
        let mut builder = single(&by_source(&["10.0.0.1"]), 0).unwrap();
        from_ip(&mut builder, "2024/1/15 00:05:00", "10.0.0.1");
        builder.change_networks(of_hosts(&["10.0.0.2"]));
        from_ip(&mut builder, "2024/1/15 01:05:00", "10.0.0.2");
        builder.change_networks(of_hosts(&["10.0.0.9"]));
        // A later change at the same latest event replaces it.
        builder.change_networks(of_hosts(&["10.0.0.3"]));
        // A resend of the network in effect adds no boundary.
        builder.change_networks(of_hosts(&["10.0.0.3"]));
        assert_eq!(builder.network_changes.len(), 2);

        let mut written = Vec::new();
        for (datetime, ip) in [
            ("2024/1/15 00:40:00", "10.0.0.1"),
            ("2024/1/15 01:30:00", "10.0.0.2"),
            ("2024/1/15 01:40:00", "10.0.0.3"),
            ("2024/1/15 02:05:00", "10.0.0.3"),
            ("2024/1/15 02:06:00", "10.0.0.2"),
            ("2024/1/15 03:20:00", EXTERNAL),
        ] {
            written.extend(from_ip(&mut builder, datetime, ip));
        }
        assert_eq!(
            rows(&written),
            [
                row("42/10.0.0.1", "2024/1/15 00:00:00", [1.0, 0.0, 1.0, 0.0]),
                marker("2024/1/15 00:00:00", 1),
                row("42/10.0.0.2", "2024/1/15 01:00:00", [1.0, 0.0, 1.0, 0.0]),
                marker("2024/1/15 01:00:00", 1),
                row("42/10.0.0.3", "2024/1/15 02:00:00", [1.0, 0.0, 0.0, 0.0]),
                marker("2024/1/15 02:00:00", 1),
            ]
        );
    }

    #[test]
    fn network_change_before_any_event_applies_to_every_window() {
        let mut builder = single(&by_source(&["10.0.0.1"]), 0).unwrap();
        builder.change_networks(of_hosts(&["10.0.0.2"]));
        assert_eq!(builder.network_changes, []);
        from_ip(&mut builder, "2024/1/15 00:05:00", "10.0.0.1");
        from_ip(&mut builder, "2024/1/15 00:06:00", "10.0.0.2");
        let written = from_ip(&mut builder, "2024/1/15 01:20:00", EXTERNAL);
        assert_eq!(
            rows(&written),
            [
                row("42/10.0.0.2", "2024/1/15 00:00:00", [1.0, 0.0, 0.0, 0.0]),
                marker("2024/1/15 00:00:00", 1),
            ]
        );
    }

    #[test]
    fn empty_network_warns_at_each_due_window_from_the_first_event_on() {
        // Requested from 0: the first close passes every window since 1970,
        // and those before the first event get no marker.
        let mut builder = single(&by_source(&[]), 0).unwrap();
        let (written, lines) = logged(|| {
            let mut written = from_ip(&mut builder, "2024/1/15 00:05:00", "10.0.0.1");
            written.extend(from_ip(&mut builder, "2024/1/15 03:20:00", "10.0.0.1"));
            written
        });
        assert_eq!(
            rows(&written),
            [
                marker("2024/1/15 00:00:00", 0),
                marker("2024/1/15 01:00:00", 0),
                marker("2024/1/15 02:00:00", 0),
            ]
        );
        assert!(builder.open.is_empty(), "no window opens");
        let warnings = containing(&lines, "Policy 42 has no internal network");
        assert_eq!(warnings.len(), 3, "00:00, 01:00 and 02:00: {lines:?}");
        for (warning, window) in warnings.iter().zip(["00:00", "01:00", "02:00"]) {
            let start = datetime_from_utc(&format!("2024/1/15 {window}:00"));
            assert!(
                warning.contains(&format!("window_start={start}")),
                "{warning}"
            );
            assert!(warning.contains("WARN"), "{warning}");
        }

        // An ungrouped policy does not look at its internal network.
        let mut builder = single(&create_simple_policy(900, 3600), 0).unwrap();
        let ((), lines) = logged(|| {
            add_at(&mut builder, "2024/1/15 00:05:00");
            add_at(&mut builder, "2024/1/15 03:20:00");
        });
        assert_eq!(containing(&lines, "no internal network").len(), 0);
    }

    #[test]
    fn network_that_becomes_empty_warns_from_its_boundary() {
        let mut builder = single(&by_source(&["10.0.0.1"]), 0).unwrap();
        from_ip(&mut builder, "2024/1/15 00:05:00", "10.0.0.1");
        builder.change_networks(HostNetworkGroup::default());
        let (written, lines) = logged(|| from_ip(&mut builder, "2024/1/15 03:20:00", "10.0.0.1"));
        assert_eq!(
            rows(&written),
            [
                row("42/10.0.0.1", "2024/1/15 00:00:00", [1.0, 0.0, 0.0, 0.0]),
                marker("2024/1/15 00:00:00", 1),
                marker("2024/1/15 01:00:00", 0),
                marker("2024/1/15 02:00:00", 0),
            ]
        );
        assert!(builder.open.is_empty(), "no new window opens");
        assert_eq!(
            containing(&lines, "Policy 42 has no internal network").len(),
            2,
            "01:00 and 02:00: {lines:?}"
        );
    }

    #[test]
    fn ips_beyond_the_cap_are_refused_and_counted_per_window() {
        assert_eq!(MAX_SERIES_PER_POLICY, 10_000);
        let internal = HostNetworkGroup {
            hosts: Vec::new(),
            networks: vec!["10.0.0.0/8".parse().unwrap()],
            ip_ranges: Vec::new(),
        };
        let policy = grouped(EndpointRole::Source, CounterpartScope::Any, internal);
        let mut builder = single(&policy, 0).unwrap();
        builder.max_series = 2;
        from_ip(&mut builder, "2024/1/15 00:05:00", "10.0.0.1");
        from_ip(&mut builder, "2024/1/15 00:10:00", "10.0.0.2");
        from_ip(&mut builder, "2024/1/15 00:15:00", "10.0.0.3");
        from_ip(&mut builder, "2024/1/15 00:16:00", "10.0.0.3");
        from_ip(&mut builder, "2024/1/15 00:20:00", "10.0.0.4");
        from_ip(&mut builder, "2024/1/15 00:25:00", "10.0.0.1");
        let refused = "IPs beyond its series cap";

        let (written, lines) = logged(|| from_ip(&mut builder, "2024/1/15 01:20:00", EXTERNAL));
        assert_eq!(
            rows(&written),
            [
                row("42/10.0.0.1", "2024/1/15 00:00:00", [1.0, 1.0, 0.0, 0.0]),
                row("42/10.0.0.2", "2024/1/15 00:00:00", [1.0, 0.0, 0.0, 0.0]),
                marker("2024/1/15 00:00:00", 2),
            ],
            "the accepted IPs keep counting"
        );
        let warnings = containing(&lines, refused);
        assert_eq!(warnings.len(), 1, "{lines:?}");
        assert!(warnings[0].contains("refused=2"), "{warnings:?}");
        assert!(warnings[0].contains("policy_id=42"), "{warnings:?}");

        // A window in which every event was refused holds no rows: it closes
        // with an empty marker and warns.
        from_ip(&mut builder, "2024/1/15 01:30:00", "10.0.0.5");
        let (written, lines) = logged(|| from_ip(&mut builder, "2024/1/15 02:20:00", EXTERNAL));
        assert_eq!(rows(&written), [marker("2024/1/15 01:00:00", 0)]);
        assert_eq!(containing(&lines, "refused=1").len(), 1, "{lines:?}");

        // 01:00 is now the last closed window. A refusal there is reported
        // by the next close; an accepted IP's late event there writes its new
        // row and the marker together; 00:00 drops its events.
        assert!(from_ip(&mut builder, "2024/1/15 01:40:00", "10.0.0.6").is_empty());
        assert_eq!(
            builder.refused.keys().copied().collect::<Vec<_>>(),
            [datetime_from_utc("2024/1/15 02:00:00")]
        );
        let frames = builder
            .frames_on(
                0,
                nanos(datetime_from_utc("2024/1/15 01:41:00")),
                &conn_between("10.0.0.1", EXTERNAL),
            )
            .unwrap();
        let [frame] = frames.as_slice() else {
            panic!("one frame: {frames:?}");
        };
        assert_eq!(
            rows(frame.rows()),
            [
                row("42/10.0.0.1", "2024/1/15 01:00:00", [0.0, 0.0, 1.0, 0.0]),
                marker("2024/1/15 01:00:00", 1),
            ]
        );
        assert!(from_ip(&mut builder, "2024/1/15 00:41:00", "10.0.0.2").is_empty());
        assert_eq!(builder.dropped, 1, "00:00 is no longer the last closed");
        let (written, lines) = logged(|| from_ip(&mut builder, "2024/1/15 03:20:00", EXTERNAL));
        assert_eq!(rows(&written), [marker("2024/1/15 02:00:00", 0)]);
        let warnings = containing(&lines, refused);
        assert_eq!(warnings.len(), 1, "{lines:?}");
        assert!(warnings[0].contains("refused=1"), "{warnings:?}");
        assert!(
            warnings[0].contains(&format!(
                "window_start={}",
                datetime_from_utc("2024/1/15 02:00:00")
            )),
            "{warnings:?}"
        );

        // A new request starts with an empty accepted set, which the replay
        // refills.
        let mut builder = single(&policy, 0).unwrap();
        builder.max_series = 2;
        from_ip(&mut builder, "2024/1/15 00:05:00", "10.0.0.3");
        from_ip(&mut builder, "2024/1/15 00:06:00", "10.0.0.4");
        from_ip(&mut builder, "2024/1/15 00:07:00", "10.0.0.1");
        let written = from_ip(&mut builder, "2024/1/15 01:20:00", EXTERNAL);
        let ids: Vec<&str> = written.iter().map(|s| s.time_series_id.as_str()).collect();
        assert_eq!(ids, ["42/10.0.0.3", "42/10.0.0.4", "42"]);
    }

    /// Delivers a Conn event from `orig` to an external IP at `datetime` on
    /// `stream` as the policy runner does under `clock`, and returns the rows
    /// written.
    fn deliver(
        builder: &mut WindowBuilder,
        stream: usize,
        datetime: &str,
        orig: &str,
        clock: &PassClock,
    ) -> Vec<(String, i64, Vec<f64>)> {
        let timestamp = nanos(datetime_from_utc(datetime));
        builder.receive(stream, timestamp, clock.now);
        let mut written = builder.close_due(clock);
        written.extend(
            builder
                .add(stream, timestamp, &conn_between(orig, EXTERNAL))
                .expect("add should succeed"),
        );
        rows(&flatten(written))
    }

    /// A grouped window without IP rows is due by the idle rule, but closes
    /// only once its stream passes it by event time; until then a later
    /// window with IP rows waits behind it. The event that passes them closes
    /// them in order, each empty one with `[0, generation]`.
    #[test]
    fn empty_window_closes_only_once_a_stream_passes_it_by_event_time() {
        let start = nanos(datetime_from_utc("2024/1/15 00:00:00"));
        let mut builder = single(&by_source(&["10.0.0.1"]), start).unwrap();
        let origin = Instant::now();
        let far = datetime_from_utc("2024/1/17 00:00:00");
        let at = |after_secs| clock_at(origin, Duration::from_secs(after_secs), far);

        // 00:00 counts nothing; 01:00 counts 10.0.0.1. Neither event passes
        // 00:00 by event time.
        assert_eq!(
            deliver(&mut builder, 0, "2024/1/15 00:20:00", EXTERNAL, &at(0)).len(),
            0
        );
        assert_eq!(
            deliver(&mut builder, 0, "2024/1/15 01:05:00", "10.0.0.1", &at(0)).len(),
            0
        );
        assert!(builder.replay_end(0, origin));
        assert!(
            builder.close_rows(&at(3600)).is_empty(),
            "past the replay end, quiet and the wall clock past: not passed by event time"
        );
        assert_eq!(
            builder.open.keys().copied().collect::<Vec<_>>(),
            [datetime_from_utc("2024/1/15 01:00:00")],
            "the window with IP rows waits"
        );

        let written = deliver(&mut builder, 0, "2024/1/15 03:20:00", EXTERNAL, &at(3600));
        assert_eq!(
            written,
            [
                marker("2024/1/15 00:00:00", 0),
                row("42/10.0.0.1", "2024/1/15 01:00:00", [1.0, 0.0, 0.0, 0.0]),
                marker("2024/1/15 01:00:00", 1),
                marker("2024/1/15 02:00:00", 0),
            ]
        );
        assert_eq!(
            builder.last_closed.as_ref().map(|window| window.start_secs),
            Some(datetime_from_utc("2024/1/15 02:00:00")),
            "an empty window becomes the last closed window"
        );
        assert!(
            builder.close_rows(&at(7200)).is_empty(),
            "03:00 is due by the idle rule only"
        );
    }

    /// With two streams, a window without IP rows stays open while both pass
    /// it only by the idle rule, and closes once one of them passes it by
    /// event time.
    #[test]
    fn empty_window_closes_once_one_of_two_streams_passes_it_by_event_time() {
        let mut builder = pair(&by_source(&["10.0.0.1"]));
        let origin = Instant::now();
        let far = datetime_from_utc("2024/1/17 00:00:00");
        let at = |after_secs| clock_at(origin, Duration::from_secs(after_secs), far);
        assert_eq!(
            deliver(&mut builder, 0, "2024/1/15 00:20:00", EXTERNAL, &at(0)).len(),
            0
        );
        assert_eq!(
            deliver(&mut builder, 1, "2024/1/15 00:30:00", EXTERNAL, &at(0)).len(),
            0
        );
        assert!(builder.replay_end(0, origin));
        assert!(builder.replay_end(1, origin));
        assert!(
            builder.close_rows(&at(3600)).is_empty(),
            "both streams pass it only by the idle rule"
        );

        let written = deliver(&mut builder, 0, "2024/1/15 01:20:00", EXTERNAL, &at(3600));
        assert_eq!(written, [marker("2024/1/15 00:00:00", 0)]);
    }

    /// A late event counted in a closed window without IP rows writes its row
    /// and the marker `[1, generation]` in one frame.
    #[test]
    fn late_event_in_an_empty_closed_window_writes_its_row_and_the_marker_together() {
        let start = nanos(datetime_from_utc("2024/1/15 00:00:00"));
        let mut builder = single(&by_source(&["10.0.0.1"]), start).unwrap();
        assert_eq!(
            rows(&from_ip(&mut builder, "2024/1/15 01:20:00", EXTERNAL)),
            [marker("2024/1/15 00:00:00", 0)]
        );
        let frames = frames_from_ip(&mut builder, "2024/1/15 00:30:00", "10.0.0.1");
        assert_eq!(
            frames,
            [vec![
                row("42/10.0.0.1", "2024/1/15 00:00:00", [0.0, 0.0, 1.0, 0.0]),
                marker("2024/1/15 00:00:00", 1),
            ]]
        );
    }

    /// A request resumed from its checkpoint closes every window from it on,
    /// even before the first event; an empty internal network warns only from
    /// the window of the first event on.
    #[test]
    fn resumed_empty_network_writes_markers_from_the_checkpoint_and_warns_from_the_first_event() {
        let start = nanos(datetime_from_utc("2024/1/15 00:00:00"));
        let mut builder = single(&by_source(&[]), start).unwrap();
        let (written, lines) = logged(|| {
            let mut written = from_ip(&mut builder, "2024/1/15 02:05:00", "10.0.0.1");
            written.extend(from_ip(&mut builder, "2024/1/15 04:20:00", "10.0.0.1"));
            written
        });
        assert_eq!(
            rows(&written),
            [
                marker("2024/1/15 00:00:00", 0),
                marker("2024/1/15 01:00:00", 0),
                marker("2024/1/15 02:00:00", 0),
                marker("2024/1/15 03:00:00", 0),
            ]
        );
        let warnings = containing(&lines, "Policy 42 has no internal network");
        assert_eq!(warnings.len(), 2, "02:00 and 03:00: {lines:?}");
        for (warning, window) in warnings.iter().zip(["02:00", "03:00"]) {
            let start = datetime_from_utc(&format!("2024/1/15 {window}:00"));
            assert!(
                warning.contains(&format!("window_start={start}")),
                "{warning}"
            );
        }
    }

    /// A window whose internal network is empty is warned about once, when it
    /// becomes due, even when it becomes due by the idle rule alone and so
    /// cannot close yet. Closing it later warns no more.
    #[test]
    fn empty_network_warns_when_a_window_is_due_by_idle_before_it_closes() {
        let start = nanos(datetime_from_utc("2024/1/15 00:00:00"));
        let mut builder = single(&by_source(&[]), start).unwrap();
        let origin = Instant::now();
        let wall = datetime_from_utc("2024/1/15 01:20:00");
        let at = |after_secs| clock_at(origin, Duration::from_secs(after_secs), wall);
        let warning = "Policy 42 has no internal network";

        let (written, lines) =
            logged(|| deliver(&mut builder, 0, "2024/1/15 00:20:00", "10.0.0.1", &at(0)));
        assert_eq!(written.len(), 0, "{written:?}");
        assert!(containing(&lines, warning).is_empty(), "{lines:?}");
        assert!(builder.replay_end(0, origin));

        let (written, lines) = logged(|| {
            let mut written = builder.close_rows(&at(60));
            written.extend(builder.close_rows(&at(120)));
            written
        });
        assert_eq!(written.len(), 0, "due by the idle rule only: {written:?}");
        let warnings = containing(&lines, warning);
        assert_eq!(warnings.len(), 1, "00:00 once: {lines:?}");
        assert!(
            warnings[0].contains(&format!(
                "window_start={}",
                datetime_from_utc("2024/1/15 00:00:00")
            )),
            "{warnings:?}"
        );

        let (written, lines) =
            logged(|| deliver(&mut builder, 0, "2024/1/15 01:20:00", "10.0.0.1", &at(180)));
        assert_eq!(written, [marker("2024/1/15 00:00:00", 0)]);
        assert!(containing(&lines, warning).is_empty(), "{lines:?}");
    }

    /// Without a checkpoint, no marker is written for a window before the
    /// one of the first event received, even one that event passes.
    #[test]
    fn unresumed_request_writes_no_marker_before_the_first_event() {
        let mut builder = single(&by_source(&["10.0.0.1"]), 0).unwrap();
        // Uncounted, so 05:00 has no IP rows, and it passes every window
        // since 1970 up to 03:00.
        let written = from_ip(&mut builder, "2024/1/15 05:20:00", EXTERNAL);
        assert_eq!(written.len(), 0, "{written:?}");
        let written = from_ip(&mut builder, "2024/1/15 06:20:00", EXTERNAL);
        assert_eq!(rows(&written), [marker("2024/1/15 05:00:00", 0)]);
    }

    /// Each run writes its rows with its own generation. A run resumed from
    /// the window written before rewrites it with the IPs its network counts
    /// now, and with none of them only the marker `[0, generation]`.
    #[test]
    fn resumed_run_rewrites_its_checkpoint_window_with_its_generation() {
        let window = "2024/1/15 00:00:00";
        let run = |hosts: &[&str], generation: u64| {
            let policy = by_source(hosts);
            let run = RunStart {
                start: nanos(datetime_from_utc(window)),
                resumed: true,
                generation: Some(generation),
            };
            let mut builder = WindowBuilder::try_new(&policy, run, 1).unwrap();
            builder.open_stream().unwrap();
            for ip in ["10.0.0.1", "10.0.0.2", "10.0.0.3"] {
                from_ip(&mut builder, "2024/1/15 00:05:00", ip);
            }
            rows(&from_ip(&mut builder, "2024/1/15 01:20:00", EXTERNAL))
        };
        let with = |id: &str, generation: u64| {
            (
                id.to_owned(),
                datetime_from_utc(window),
                vec![1.0, 0.0, 0.0, 0.0, generation as f64],
            )
        };
        let marker_of = |rows: u32, generation: u64| {
            (
                "42".to_owned(),
                datetime_from_utc(window),
                vec![f64::from(rows), generation as f64],
            )
        };

        assert_eq!(
            run(&["10.0.0.1", "10.0.0.2"], 100),
            [
                with("42/10.0.0.1", 100),
                with("42/10.0.0.2", 100),
                marker_of(2, 100)
            ]
        );
        assert_eq!(
            run(&["10.0.0.2", "10.0.0.3"], 101),
            [
                with("42/10.0.0.2", 101),
                with("42/10.0.0.3", 101),
                marker_of(2, 101)
            ]
        );
        assert_eq!(run(&[], 102), [marker_of(0, 102)]);
        // A rewrite stopped before its close is done again by the next run.
        assert_eq!(run(&[], 103), [marker_of(0, 103)]);
    }

    /// A run stopped with checkpoint W while W+1 is open and W's row is being
    /// corrected: the next run, resumed from W, rewrites W with its own
    /// generation, correction included. Once W+1 has closed, an event for W
    /// is dropped and counted in the drop warning of the next close.
    #[test]
    fn stop_during_a_correction_rewrites_it_and_drops_it_after_the_next_close() {
        let w = "2024/1/15 00:00:00";
        let next = "2024/1/15 01:00:00";
        let with = |datetime: &str, values: [f64; 4], generation: u64| {
            let mut data = values.to_vec();
            data.push(generation as f64);
            ("42/10.0.0.1".to_owned(), datetime_from_utc(datetime), data)
        };
        let marker_of = |datetime: &str, generation: u64| {
            (
                "42".to_owned(),
                datetime_from_utc(datetime),
                vec![1.0, generation as f64],
            )
        };
        let policy = by_source(&["10.0.0.1"]);
        let builder_for = |run: RunStart| {
            let mut builder = WindowBuilder::try_new(&policy, run, 1).unwrap();
            builder.open_stream().unwrap();
            builder
        };

        let mut first = builder_for(RunStart {
            start: 0,
            resumed: false,
            generation: Some(100),
        });
        from_ip(&mut first, "2024/1/15 00:05:00", "10.0.0.1");
        assert_eq!(
            rows(&from_ip(&mut first, "2024/1/15 01:20:00", "10.0.0.1")),
            [with(w, [1.0, 0.0, 0.0, 0.0], 100), marker_of(w, 100)]
        );
        assert_eq!(
            rows(&from_ip(&mut first, "2024/1/15 00:40:00", "10.0.0.1")),
            [with(w, [1.0, 0.0, 1.0, 0.0], 100)],
            "the correction under way when the run stops"
        );
        drop(first);

        // The restart requests from W, whose window was acknowledged.
        let mut second = builder_for(RunStart {
            start: nanos(datetime_from_utc(w)),
            resumed: true,
            generation: Some(101),
        });
        from_ip(&mut second, "2024/1/15 00:05:00", "10.0.0.1");
        from_ip(&mut second, "2024/1/15 00:40:00", "10.0.0.1");
        assert_eq!(
            rows(&from_ip(&mut second, "2024/1/15 01:20:00", "10.0.0.1")),
            [with(w, [1.0, 0.0, 1.0, 0.0], 101), marker_of(w, 101)],
            "W rewritten with the new generation"
        );
        assert_eq!(
            rows(&from_ip(&mut second, "2024/1/15 02:20:00", "10.0.0.1")),
            [with(next, [0.0, 1.0, 0.0, 0.0], 101), marker_of(next, 101)]
        );
        assert!(from_ip(&mut second, "2024/1/15 00:50:00", "10.0.0.1").is_empty());
        assert_eq!(second.dropped, 1);
        let (_, lines) = logged(|| from_ip(&mut second, "2024/1/15 03:20:00", "10.0.0.1"));
        let warnings = containing(&lines, "Dropped late events");
        assert_eq!(warnings.len(), 1, "{lines:?}");
        assert!(warnings[0].contains("policy_id=42"), "{warnings:?}");
    }

    #[test]
    fn grouped_run_needs_a_generation_and_an_ungrouped_one_ignores_it() {
        let run = RunStart {
            start: 0,
            resumed: false,
            generation: None,
        };
        assert!(WindowBuilder::try_new(&by_source(&["10.0.0.1"]), run, 1).is_err());
        let ungrouped = create_simple_policy(900, 3600);
        let run = RunStart {
            generation: Some(GENERATION),
            ..run
        };
        let mut builder = WindowBuilder::try_new(&ungrouped, run, 1).unwrap();
        builder.open_stream().unwrap();
        add_at(&mut builder, "2024/1/15 00:05:00");
        let written = add_at(&mut builder, "2024/1/15 01:20:00");
        assert_eq!(
            starts_and_values(&written),
            [(
                datetime_from_utc("2024/1/15 00:00:00"),
                vec![1.0, 0.0, 0.0, 0.0]
            )],
            "no generation and no marker"
        );
    }

    #[test]
    fn grouping_by_owned_network_is_rejected() {
        let mut policy = by_source(&["10.0.0.1"]);
        policy.group_by_unit = GroupByUnit::OwnedNetwork;
        assert!(single(&policy, 0).is_err());
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
            // Window: 1 day, Slot: 1 hour => 24 slots, offset 0.
            let policy = create_policy(
                TEST_POLICY_ID,
                SECS_PER_DAY,
                SECS_PER_HOUR,
                NO_OFFSET,
                Measure::Count,
            );
            assert_eq!(time_slot(&policy, TS_EPOCH).unwrap(), 0,);
            // 1 second past epoch is still slot 0.
            assert_eq!(time_slot(&policy, TS_EPOCH_PLUS_ONE).unwrap(), 0,);
        }

        #[test]
        fn time_slot_for_known_rfc3339_midrange() {
            // 2023-11-14T22:13:20Z is 1_700_000_000s after the epoch.
            // With window_size=86400 (1 day), slot_size=3600 (1 hour), the expected slot is computed
            // as a literal: 1_700_000_000 % 86400 = 80_000s of day, and
            // 80_000 / 3600 = 22 (integer division).
            let policy = create_policy(
                TEST_POLICY_ID,
                SECS_PER_DAY,
                SECS_PER_HOUR,
                NO_OFFSET,
                Measure::Count,
            );
            assert_eq!(time_slot(&policy, TS_2023_11_14_221320Z).unwrap(), 22,);
        }

        #[test]
        fn time_slot_at_year_9999_endpoint() {
            // 9999-12-31T23:59:59Z = 253_402_300_799 seconds.
            // 253_402_300_799 % 86400 = 86_399 (last second of the day),
            // 86_399 / 3600 = 23 => last hour-slot.
            let policy = create_policy(
                TEST_POLICY_ID,
                SECS_PER_DAY,
                SECS_PER_HOUR,
                NO_OFFSET,
                Measure::Count,
            );
            assert_eq!(time_slot(&policy, TS_9999_12_31_235959Z).unwrap(), 23,);
        }

        #[test]
        fn time_slot_negative_timestamp_aligns_to_last_hour_slot() {
            // -1s is 1969-12-31T23:59:59Z. With window_size=86400 (1 day) and slot_size=3600 (1 hour),
            // that lands in slot 23 (last hour of the day).
            let policy = create_policy(
                TEST_POLICY_ID,
                SECS_PER_DAY,
                SECS_PER_HOUR,
                NO_OFFSET,
                Measure::Count,
            );
            assert_eq!(time_slot(&policy, TS_EPOCH_MINUS_ONE).unwrap(), 23,);
        }

        #[test]
        fn pre_epoch_offsets_result_in_negative_unix_timestamp() {
            let policy = create_policy(
                TEST_POLICY_ID,
                SECS_PER_DAY,
                SECS_PER_HOUR,
                -2,
                Measure::Count,
            );

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
            // -1s sits in the period [-3600, 0). With window_size=1h and offset=0
            // start_time must align to -3600
            let policy = create_policy(
                TEST_POLICY_ID,
                SECS_PER_HOUR,
                SECS_PER_MINUTE,
                NO_OFFSET,
                Measure::Count,
            );
            let aligned =
                start_time(&policy, TS_EPOCH_MINUS_ONE).expect("start_time should succeed");
            assert_eq!(aligned, -i64::try_from(SECS_PER_HOUR).unwrap());
        }

        #[test]
        fn midnight_rollover_kst_consistency() {
            // `time_slot` uses `period` as the modulo window. Use a day-sized period
            // to expose hour-of-day slots: 0..=23.
            let slot_policy = create_policy(
                TEST_POLICY_ID,
                SECS_PER_DAY,
                SECS_PER_HOUR,
                NO_OFFSET,
                Measure::Count,
            );

            // `start_time` aligns to `period` boundaries. Use an hour-sized period
            // to pin the start of the current hour.
            let start_policy = create_policy(
                TEST_POLICY_ID,
                SECS_PER_HOUR,
                SECS_PER_HOUR,
                NO_OFFSET,
                Measure::Count,
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

        #[test]
        fn event_at_exact_window_end_opens_the_next_window() {
            // Windows are [start, start + period). An event at exactly
            // start + period belongs to the next window, so it opens the next
            // one, and the current one stays open for its grace.
            let policy = create_policy(
                TEST_POLICY_ID,
                SECS_PER_HOUR,
                15 * SECS_PER_MINUTE,
                NO_OFFSET,
                Measure::Count,
            );
            let mut builder = single(&policy, 0).unwrap();

            let start_ts = datetime_from_utc("2024/1/15 00:00:00");
            assert!(add_at(&mut builder, "2024/1/15 00:59:59").is_empty());
            assert_eq!(open(&builder).start_secs, start_ts);
            assert_eq!(open(&builder).series, [0.0, 0.0, 0.0, 1.0]);

            let boundary = datetime_from_utc("2024/1/15 01:00:00");
            assert!(add_at(&mut builder, "2024/1/15 01:00:00").is_empty());
            assert_eq!(
                open_windows(&builder),
                [
                    (start_ts, vec![0.0, 0.0, 0.0, 1.0]),
                    (boundary, vec![1.0, 0.0, 0.0, 0.0]),
                ]
            );
        }

        #[test]
        fn time_series_bincode_serialization_ignores_start_time() {
            // The `policy_id` and `start_secs` fields are `#[serde(skip)]`, so
            // the bincode payload must be byte-identical for two TimeSeries
            // that differ only in them.
            let series_a = TimeSeries {
                time_series_id: "42".to_string(),
                policy_id: 42,
                start_secs: TS_EPOCH,
                series: vec![1.0, 2.0, 3.0, 4.0],
            };
            let series_b = TimeSeries {
                time_series_id: "42".to_string(),
                policy_id: 7,
                start_secs: TS_9999_12_31_235959Z,
                series: vec![1.0, 2.0, 3.0, 4.0],
            };

            let bytes_a = bincode::serialize(&series_a).expect("bincode serialize a");
            let bytes_b = bincode::serialize(&series_b).expect("bincode serialize b");

            assert_eq!(
                bytes_a, bytes_b,
                "TimeSeries bincode bytes must not depend on the skipped fields",
            );
        }

        #[test]
        fn time_series_bincode_round_trip_preserves_observable_fields() {
            // The id and series payload must round-trip byte-for-byte. The
            // `policy_id` and `start_secs` fields are skipped on the wire and
            // are not part of the external contract.
            let original = TimeSeries {
                time_series_id: "1/10.0.0.1".to_string(),
                policy_id: 1,
                start_secs: TS_2023_11_14_221320Z,
                series: vec![0.0, 1.5, -2.25, 3.125],
            };
            let bytes = bincode::serialize(&original).expect("bincode serialize");
            let decoded: TimeSeries = bincode::deserialize(&bytes).expect("bincode deserialize");
            assert_eq!(decoded.time_series_id, "1/10.0.0.1");
            assert_eq!(decoded.policy_id, u32::default());
            assert_eq!(decoded.series, vec![0.0, 1.5, -2.25, 3.125]);
            assert_eq!(decoded.start_secs, i64::default());
        }
    }
}
