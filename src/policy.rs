mod checkpoint;

use std::{
    collections::{HashMap, hash_map::Entry},
    path::PathBuf,
};

use anyhow::{Context, Result};
use review_protocol::types::{CounterpartScope, TimeSeriesGenerationPolicy};
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::cancellation::CancellationCoordinator;

const POLICY_COMMAND_CHANNEL_SIZE: usize = 32;

enum PolicyCommand {
    ReplacePolicies {
        policies: Vec<TimeSeriesGenerationPolicy>,
        reply: oneshot::Sender<Result<(), String>>,
    },
    DeletePolicies {
        ids: Vec<u32>,
        reply: oneshot::Sender<Result<(), String>>,
    },
    GetPolicy {
        id: u32,
        reply: oneshot::Sender<Result<Option<StreamPolicy>, String>>,
    },
    RecordAck {
        id: u32,
        timestamp: i64,
    },
}

struct PolicyEntry {
    policy: TimeSeriesGenerationPolicy,
    token: CancellationToken,
}

/// A consistent view of the policy, its cancellation signal and resume position.
#[derive(Clone)]
pub(crate) struct StreamPolicy {
    pub(crate) policy: TimeSeriesGenerationPolicy,
    pub(crate) token: CancellationToken,
    pub(crate) start: i64,
}

/// Commands and ACKs share one owner. Dropping the last handle lets that owner
/// drain accepted commands and persist its final state before it finishes.
#[derive(Clone)]
pub(crate) struct PolicyHandle {
    tx: mpsc::Sender<PolicyCommand>,
    policy_ids: watch::Receiver<Vec<u32>>,
}

impl PolicyHandle {
    /// Makes `policies` the complete active set. Success means any checkpoint
    /// removed for changed content was persisted.
    pub(crate) async fn replace_policies(
        &self,
        policies: Vec<TimeSeriesGenerationPolicy>,
    ) -> Result<(), String> {
        let (reply, received) = oneshot::channel();
        self.tx
            .send(PolicyCommand::ReplacePolicies { policies, reply })
            .await
            .map_err(|_| "policy actor closed".to_string())?;
        received
            .await
            .map_err(|_| "policy actor dropped reply".to_string())?
    }

    /// Success means both the active policy and its saved timestamp were removed.
    /// This does not depend on a policy runner existing or observing cancellation.
    pub(crate) async fn delete_policies(&self, ids: Vec<u32>) -> Result<(), String> {
        let (reply, received) = oneshot::channel();
        self.tx
            .send(PolicyCommand::DeletePolicies { ids, reply })
            .await
            .map_err(|_| "policy actor closed".to_string())?;
        received
            .await
            .map_err(|_| "policy actor dropped reply".to_string())?
    }

    /// Watches active policy IDs; fetch current details through `stream_policy`.
    pub(crate) fn subscribe(&self) -> watch::Receiver<Vec<u32>> {
        self.policy_ids.clone()
    }

    pub(crate) async fn stream_policy(&self, id: u32) -> Result<Option<StreamPolicy>> {
        let (reply, received) = oneshot::channel();
        self.tx
            .send(PolicyCommand::GetPolicy { id, reply })
            .await
            .map_err(|_| anyhow::anyhow!("policy actor closed"))?;
        received
            .await
            .context("policy actor dropped reply")?
            .map_err(anyhow::Error::msg)
    }

    pub(crate) async fn get_policy_with_token(
        &self,
        id: u32,
    ) -> Option<(TimeSeriesGenerationPolicy, CancellationToken)> {
        self.stream_policy(id)
            .await
            .ok()
            .flatten()
            .map(|state| (state.policy, state.token))
    }

    pub(crate) async fn record_ack(&self, id: u32, timestamp: i64) -> Result<()> {
        self.tx
            .send(PolicyCommand::RecordAck { id, timestamp })
            .await
            .map_err(|_| anyhow::anyhow!("policy actor closed while recording an ACK"))
    }

    #[cfg(test)]
    pub(crate) async fn get_policy(&self, id: u32) -> Option<TimeSeriesGenerationPolicy> {
        self.get_policy_with_token(id)
            .await
            .map(|(policy, _)| policy)
    }

    #[cfg(test)]
    pub(crate) async fn get_policy_token(&self, id: u32) -> Option<CancellationToken> {
        self.get_policy_with_token(id).await.map(|(_, token)| token)
    }

    #[cfg(test)]
    pub(crate) fn get_all_policy_ids(&self) -> Vec<u32> {
        self.policy_ids.borrow().clone()
    }
}

/// Restores checkpoints before accepting Review policies. Missing active policies
/// during startup are not deletions: Review has not supplied its policy list yet.
pub(crate) async fn spawn_policy_actor(
    path: PathBuf,
    coordinator: &CancellationCoordinator,
) -> Result<(PolicyHandle, JoinHandle<Result<()>>)> {
    let load_path = path.clone();
    let timestamps =
        tokio::task::spawn_blocking(move || checkpoint::read_last_timestamp(&load_path))
            .await
            .context("timestamp loader task panicked")??;
    let (tx, rx) = mpsc::channel(POLICY_COMMAND_CHANNEL_SIZE);
    let (policy_ids, snapshot) = watch::channel(Vec::new());
    let task = coordinator
        .tracker()
        .spawn(run_actor(path, timestamps, rx, policy_ids));
    Ok((
        PolicyHandle {
            tx,
            policy_ids: snapshot,
        },
        task,
    ))
}

async fn run_actor(
    path: PathBuf,
    mut timestamps: HashMap<String, i64>,
    mut commands: mpsc::Receiver<PolicyCommand>,
    policy_ids: watch::Sender<Vec<u32>>,
) -> Result<()> {
    let mut active: HashMap<u32, PolicyEntry> = HashMap::new();
    // Global cancellation stops producers first. Keep accepting final ACKs until
    // every producer has released its handle, then drain and flush before exit.
    while let Some(command) = commands.recv().await {
        match command {
            PolicyCommand::ReplacePolicies { policies, reply } => {
                let outcome = replace_policies(&mut active, &mut timestamps, policies);
                if outcome.changed {
                    policy_ids.send_replace(active.keys().copied().collect());
                }
                let result = if outcome.checkpoint_removed {
                    checkpoint::write_timestamp_file(&path, timestamps.clone()).await
                } else {
                    Ok(())
                };
                let _ = reply.send(
                    result
                        .as_ref()
                        .copied()
                        .map_err(|error| format!("{error:#}")),
                );
                result?;
            }
            PolicyCommand::DeletePolicies { ids, reply } => {
                for id in ids {
                    if let Some(entry) = active.remove(&id) {
                        entry.token.cancel();
                    }
                    timestamps.remove(&id.to_string());
                }
                policy_ids.send_replace(active.keys().copied().collect());
                let result = checkpoint::write_timestamp_file(&path, timestamps.clone()).await;
                let _ = reply.send(
                    result
                        .as_ref()
                        .copied()
                        .map_err(|error| format!("{error:#}")),
                );
                result?;
            }
            PolicyCommand::GetPolicy { id, reply } => {
                let state = active.get(&id).map(|entry| StreamPolicy {
                    start: start_timestamp(timestamps.get(&id.to_string()).copied()),
                    policy: entry.policy.clone(),
                    token: entry.token.clone(),
                });
                let _ = reply.send(Ok(state));
            }
            PolicyCommand::RecordAck { id, timestamp } => {
                // A late ACK cannot recreate the checkpoint of an inactive policy.
                if active.contains_key(&id) && record_ack(&mut timestamps, id, timestamp) {
                    checkpoint::write_timestamp_file(&path, timestamps.clone()).await?;
                }
            }
        }
    }
    checkpoint::write_timestamp_file(&path, timestamps).await?;
    info!("Policy actor flushed timestamps and shutting down");
    Ok(())
}

struct ReplaceOutcome {
    changed: bool,
    checkpoint_removed: bool,
}

/// Applies a complete policy list to the active set.
///
/// An absent ID is stopped but keeps its checkpoint: the Central Manager never
/// gives a deleted policy's ID to another policy, so the entry is inert, and a
/// policy that returns resumes from its last written window instead of
/// rebuilding windows whose raw events may be gone. An ID whose content changed
/// is restarted from the beginning, because the old checkpoint describes the
/// old content's windows.
fn replace_policies(
    active: &mut HashMap<u32, PolicyEntry>,
    timestamps: &mut HashMap<String, i64>,
    policies: Vec<TimeSeriesGenerationPolicy>,
) -> ReplaceOutcome {
    let mut received: HashMap<u32, TimeSeriesGenerationPolicy> =
        HashMap::with_capacity(policies.len());
    for policy in policies {
        if let Some(reason) = skip_reason(&policy) {
            warn!(
                "Skipping time-series generation policy {}: {reason}",
                policy.id
            );
            continue;
        }
        match received.entry(policy.id) {
            Entry::Vacant(entry) => {
                entry.insert(policy);
            }
            Entry::Occupied(entry) => {
                if !same_content(entry.get(), &policy) {
                    warn!(
                        "Ignoring a second, different time-series generation policy {} in \
                         one list",
                        policy.id
                    );
                }
            }
        }
    }

    let mut outcome = ReplaceOutcome {
        changed: false,
        checkpoint_removed: false,
    };
    active.retain(|id, entry| {
        if received.contains_key(id) {
            return true;
        }
        info!("Stopping time-series generation policy {id}, which is no longer assigned");
        entry.token.cancel();
        outcome.changed = true;
        false
    });
    for (id, policy) in received {
        match active.entry(id) {
            Entry::Vacant(entry) => {
                entry.insert(PolicyEntry {
                    policy,
                    token: CancellationToken::new(),
                });
                outcome.changed = true;
            }
            Entry::Occupied(mut entry) => {
                if same_content(&entry.get().policy, &policy) {
                    continue;
                }
                warn!(
                    "Time-series generation policy {id} changed; restarting it without its \
                     checkpoint"
                );
                entry.get().token.cancel();
                entry.insert(PolicyEntry {
                    policy,
                    token: CancellationToken::new(),
                });
                if timestamps.remove(&id.to_string()).is_some() {
                    outcome.checkpoint_removed = true;
                }
                outcome.changed = true;
            }
        }
    }
    outcome
}

/// Returns why the policy cannot be run, or `None` if it can.
///
/// Only an ungrouped policy over at least one sensor and every counterpart is
/// generated yet, and only of a network kind with a measure defined on it. Any
/// other policy is treated as absent from the list: it is not started, a
/// running one is stopped, and its checkpoint is kept.
fn skip_reason(policy: &TimeSeriesGenerationPolicy) -> Option<String> {
    if let Some(role) = policy.group_by {
        return Some(format!("grouping by {role:?} is not supported yet"));
    }
    if policy.sensors.is_empty() {
        return Some("no sensor is assigned".to_string());
    }
    if policy.counterpart_scope != CounterpartScope::Any {
        return Some(format!(
            "counterpart scope {:?} is not supported yet",
            policy.counterpart_scope
        ));
    }
    crate::subscribe::check_generation_spec(policy)
        .err()
        .map(|e| format!("{e:#}"))
}

/// Compares every field of the generation spec, which shapes a policy's
/// series. `internal_networks` is not part of the spec, so a change to it alone
/// keeps the running policy and its checkpoint.
fn same_content(a: &TimeSeriesGenerationPolicy, b: &TimeSeriesGenerationPolicy) -> bool {
    a.raw_event_kind == b.raw_event_kind
        && a.measure == b.measure
        && a.group_by == b.group_by
        && a.group_by_unit == b.group_by_unit
        && a.counterpart_scope == b.counterpart_scope
        && a.slot_size == b.slot_size
        && a.window_size == b.window_size
        && a.utc_offset == b.utc_offset
        && a.src_ip == b.src_ip
        && a.dst_ip == b.dst_ip
        && a.sensors == b.sensors
        && a.time_series_type == b.time_series_type
}

/// Returns where a policy's stream resumes: the start of its last written
/// window, which the replay writes again, or 0 for a policy without one, which
/// is built over every stored event.
fn start_timestamp(last: Option<i64>) -> i64 {
    last.unwrap_or(0)
}

/// Keeps the later of the saved and the acknowledged window start, and returns
/// whether the checkpoint changed. A window corrected by a late event is
/// acknowledged after a newer one, and must not move the checkpoint back.
fn record_ack(timestamps: &mut HashMap<String, i64>, id: u32, timestamp: i64) -> bool {
    match timestamps.entry(id.to_string()) {
        Entry::Vacant(entry) => {
            entry.insert(timestamp);
            true
        }
        Entry::Occupied(mut entry) => {
            if *entry.get() >= timestamp {
                return false;
            }
            entry.insert(timestamp);
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use review_protocol::types::{
        ConnField, EndpointRole, GroupByUnit, HostNetworkGroup, Measure, RawEventKind,
        TimeSeriesTypeRef,
    };
    use tempfile::TempDir;
    use tokio::time::timeout;

    use super::*;

    const TEST_TIMEOUT: Duration = Duration::from_secs(10);

    // Bound the entire case as well as teardown so a missing actor reply cannot
    // leave CI waiting indefinitely. This deadline is not a performance assertion.
    async fn run_test(future: impl std::future::Future<Output = ()>) {
        timeout(Duration::from_secs(30), future)
            .await
            .expect("policy test completes within its deadline");
    }

    async fn join_actor(mut task: JoinHandle<Result<()>>) -> Result<()> {
        if let Ok(result) = timeout(TEST_TIMEOUT, &mut task).await {
            result.expect("policy actor must not panic")
        } else {
            task.abort();
            panic!("policy actor did not finish within {TEST_TIMEOUT:?}");
        }
    }

    fn policy(id: u32) -> TimeSeriesGenerationPolicy {
        TimeSeriesGenerationPolicy {
            id,
            raw_event_kind: RawEventKind::Conn,
            measure: Measure::Count,
            group_by: None,
            group_by_unit: GroupByUnit::Ip,
            counterpart_scope: CounterpartScope::Any,
            slot_size: Duration::from_secs(60),
            window_size: Duration::from_secs(3600),
            utc_offset: 0,
            src_ip: None,
            dst_ip: None,
            sensors: vec!["test".into()],
            time_series_type: None,
            internal_networks: HostNetworkGroup::default(),
        }
    }

    type Change = (&'static str, fn(&mut TimeSeriesGenerationPolicy));

    /// Changes that make a policy one this generator does not run.
    const UNSUPPORTED: [Change; 7] = [
        ("group_by", |p| p.group_by = Some(EndpointRole::Source)),
        ("internal scope", |p| {
            p.counterpart_scope = CounterpartScope::Internal;
        }),
        ("external scope", |p| {
            p.counterpart_scope = CounterpartScope::External;
        }),
        ("no sensor", |p| p.sensors.clear()),
        ("process create", |p| {
            p.raw_event_kind = RawEventKind::ProcessCreate;
        }),
        ("netflow5", |p| p.raw_event_kind = RawEventKind::Netflow5),
        ("sum on dns", |p| {
            p.raw_event_kind = RawEventKind::Dns;
            p.measure = Measure::Sum(ConnField::OrigBytes);
        }),
    ];

    /// Collects formatted log lines for a test that runs synchronously under
    /// [`tracing::subscriber::with_default`].
    #[derive(Clone, Default)]
    struct LogCapture(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for LogCapture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl LogCapture {
        fn run<T>(&self, f: impl FnOnce() -> T) -> T {
            let writer = self.clone();
            let subscriber = tracing_subscriber::fmt()
                .with_writer(move || writer.clone())
                .with_ansi(false)
                .finish();
            tracing::subscriber::with_default(subscriber, f)
        }

        fn lines(&self) -> Vec<String> {
            String::from_utf8(self.0.lock().unwrap().clone())
                .unwrap()
                .lines()
                .map(str::to_owned)
                .collect()
        }
    }

    struct Harness {
        handle: PolicyHandle,
        task: JoinHandle<Result<()>>,
        coordinator: CancellationCoordinator,
        path: PathBuf,
        _dir: TempDir,
    }

    impl Harness {
        async fn new(contents: &str) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("timestamps.json");
            std::fs::write(&path, contents).unwrap();
            let coordinator = CancellationCoordinator::new();
            let (handle, task) = spawn_policy_actor(path.clone(), &coordinator)
                .await
                .unwrap();
            Self {
                handle,
                task,
                coordinator,
                path,
                _dir: dir,
            }
        }

        fn saved(&self) -> HashMap<String, i64> {
            serde_json::from_slice(&std::fs::read(&self.path).unwrap()).unwrap()
        }

        async fn finish(self) {
            drop(self.handle);
            join_actor(self.task).await.unwrap();
            self.coordinator.request_cancellation("test finished");
            assert!(self.coordinator.wait_for_drain(TEST_TIMEOUT).await);
        }
    }

    #[tokio::test]
    async fn replace_publishes_latest_policy_ids_without_a_relay() {
        run_test(async {
            let h = Harness::new("{}").await;
            let mut snapshot = h.handle.subscribe();
            assert!(snapshot.borrow().is_empty());
            h.handle
                .replace_policies(vec![policy(1), policy(2)])
                .await
                .unwrap();
            assert!(snapshot.has_changed().unwrap());
            let mut ids = snapshot.borrow_and_update().clone();
            ids.sort_unstable();
            assert_eq!(ids, [1, 2]);
            h.handle
                .replace_policies(vec![policy(2), policy(1)])
                .await
                .unwrap();
            assert!(!snapshot.has_changed().unwrap());
            h.handle
                .replace_policies(vec![policy(2), policy(3)])
                .await
                .unwrap();
            assert!(snapshot.has_changed().unwrap());
            let mut ids = snapshot.borrow_and_update().clone();
            ids.sort_unstable();
            assert_eq!(ids, [2, 3]);
            h.finish().await;
        })
        .await;
    }

    #[tokio::test]
    async fn absent_policy_stops_but_keeps_checkpoint_and_resumes_when_it_returns() {
        run_test(async {
            let h = Harness::new(r#"{"42":100,"7":200}"#).await;
            h.handle
                .replace_policies(vec![policy(42), policy(7)])
                .await
                .unwrap();
            let token = h.handle.get_policy_token(42).await.unwrap();
            let kept = h.handle.get_policy_token(7).await.unwrap();
            h.handle.replace_policies(vec![policy(7)]).await.unwrap();
            assert!(token.is_cancelled());
            assert!(!kept.is_cancelled());
            assert!(h.handle.stream_policy(42).await.unwrap().is_none());
            assert_eq!(h.handle.get_all_policy_ids(), [7]);
            assert_eq!(
                h.saved(),
                HashMap::from([("42".into(), 100), ("7".into(), 200)])
            );
            // An ACK of the stopped policy cannot move its kept checkpoint.
            h.handle.record_ack(42, 999).await.unwrap();
            h.handle
                .replace_policies(vec![policy(42), policy(7)])
                .await
                .unwrap();
            let state = h.handle.stream_policy(42).await.unwrap().unwrap();
            assert_eq!(state.start, 100);
            assert!(!state.token.is_cancelled());
            assert!(!kept.is_cancelled());
            h.finish().await;
        })
        .await;
    }

    #[tokio::test]
    async fn empty_list_stops_every_policy_and_keeps_every_checkpoint() {
        run_test(async {
            let h = Harness::new(r#"{"42":100,"7":200,"99":300}"#).await;
            h.handle
                .replace_policies(vec![policy(42), policy(7)])
                .await
                .unwrap();
            let tokens = [
                h.handle.get_policy_token(42).await.unwrap(),
                h.handle.get_policy_token(7).await.unwrap(),
            ];
            let mut snapshot = h.handle.subscribe();
            snapshot.borrow_and_update();
            h.handle.replace_policies(Vec::new()).await.unwrap();
            assert!(snapshot.has_changed().unwrap());
            assert!(snapshot.borrow_and_update().is_empty());
            assert!(tokens.iter().all(CancellationToken::is_cancelled));
            assert_eq!(
                h.saved(),
                HashMap::from([("42".into(), 100), ("7".into(), 200), ("99".into(), 300)])
            );
            h.finish().await;
        })
        .await;
    }

    #[tokio::test]
    async fn changed_content_restarts_policy_without_its_checkpoint() {
        // Every spec field whose change leaves the policy runnable. `group_by`
        // and `counterpart_scope` have no other runnable value; changing them
        // skips the policy, as `change_to_unsupported_policy_*` tests.
        let changes: [Change; 10] = [
            ("raw_event_kind", |p| p.raw_event_kind = RawEventKind::Dns),
            ("measure", |p| {
                p.measure = Measure::Sum(ConnField::OrigBytes);
            }),
            ("group_by_unit", |p| {
                p.group_by_unit = GroupByUnit::OwnedNetwork;
            }),
            ("slot_size", |p| p.slot_size = Duration::from_secs(30)),
            ("window_size", |p| p.window_size = Duration::from_hours(24)),
            ("utc_offset", |p| p.utc_offset = 32_400),
            ("src_ip", |p| p.src_ip = Some("10.0.0.1".parse().unwrap())),
            ("dst_ip", |p| p.dst_ip = Some("10.0.0.2".parse().unwrap())),
            ("sensors", |p| p.sensors = vec!["other".into()]),
            ("time_series_type", |p| {
                p.time_series_type = Some(TimeSeriesTypeRef {
                    id: "conn_count".into(),
                    version: 1,
                });
            }),
        ];
        run_test(async {
            for (field, change) in changes {
                let h = Harness::new(r#"{"42":100,"7":200}"#).await;
                h.handle
                    .replace_policies(vec![policy(42), policy(7)])
                    .await
                    .unwrap();
                let old = h.handle.get_policy_token(42).await.unwrap();
                let kept = h.handle.get_policy_token(7).await.unwrap();
                let mut snapshot = h.handle.subscribe();
                snapshot.borrow_and_update();
                let mut replacement = policy(42);
                change(&mut replacement);
                h.handle
                    .replace_policies(vec![replacement, policy(7)])
                    .await
                    .unwrap();
                assert!(old.is_cancelled(), "{field}: old worker stops");
                assert!(!kept.is_cancelled(), "{field}: other policy runs on");
                // The ID set is unchanged, but Publish must observe the update.
                assert!(snapshot.has_changed().unwrap(), "{field}: publish notified");
                assert_eq!(
                    h.saved(),
                    HashMap::from([("7".into(), 200)]),
                    "{field}: checkpoint removed and persisted"
                );
                let state = h.handle.stream_policy(42).await.unwrap().unwrap();
                assert_eq!(state.start, 0, "{field}: restarts from 0");
                assert!(!state.token.is_cancelled(), "{field}: fresh token");
                h.finish().await;
            }
        })
        .await;
    }

    #[tokio::test]
    async fn identical_content_changes_nothing() {
        run_test(async {
            let h = Harness::new(r#"{"42":100}"#).await;
            h.handle.replace_policies(vec![policy(42)]).await.unwrap();
            let token = h.handle.get_policy_token(42).await.unwrap();
            let mut snapshot = h.handle.subscribe();
            snapshot.borrow_and_update();
            h.handle.replace_policies(vec![policy(42)]).await.unwrap();
            assert!(!snapshot.has_changed().unwrap());
            assert!(!token.is_cancelled());
            assert_eq!(h.saved(), HashMap::from([("42".into(), 100)]));
            assert_eq!(
                h.handle.stream_policy(42).await.unwrap().unwrap().start,
                100
            );
            h.finish().await;
        })
        .await;
    }

    #[tokio::test]
    async fn internal_networks_change_keeps_policy_and_checkpoint() {
        run_test(async {
            let h = Harness::new(r#"{"42":100}"#).await;
            h.handle.replace_policies(vec![policy(42)]).await.unwrap();
            let token = h.handle.get_policy_token(42).await.unwrap();
            let mut snapshot = h.handle.subscribe();
            snapshot.borrow_and_update();
            let mut changed = policy(42);
            changed.internal_networks = HostNetworkGroup {
                hosts: vec!["10.0.0.1".parse().unwrap()],
                networks: vec!["192.168.0.0/16".parse().unwrap()],
                ip_ranges: Vec::new(),
            };
            h.handle.replace_policies(vec![changed]).await.unwrap();
            assert!(!snapshot.has_changed().unwrap());
            assert!(!token.is_cancelled());
            assert_eq!(h.saved(), HashMap::from([("42".into(), 100)]));
            assert_eq!(
                h.handle.stream_policy(42).await.unwrap().unwrap().start,
                100
            );
            h.finish().await;
        })
        .await;
    }

    #[test]
    fn unsupported_policy_is_skipped_with_a_warning_naming_it() {
        for (what, change) in UNSUPPORTED {
            let mut unsupported = policy(42);
            change(&mut unsupported);
            let mut active = HashMap::new();
            let mut timestamps = HashMap::new();
            let logs = LogCapture::default();
            let outcome = logs.run(|| {
                replace_policies(
                    &mut active,
                    &mut timestamps,
                    vec![unsupported.clone(), policy(7)],
                )
            });
            assert!(outcome.changed, "{what}: the runnable policy starts");
            let mut ids: Vec<u32> = active.keys().copied().collect();
            ids.sort_unstable();
            assert_eq!(ids, [7], "{what}: only the runnable policy runs");
            let warnings: Vec<String> = logs
                .lines()
                .into_iter()
                .filter(|line| line.contains("WARN"))
                .collect();
            assert_eq!(warnings.len(), 1, "{what}: {warnings:?}");
            assert!(
                warnings[0].contains("Skipping time-series generation policy 42:"),
                "{what}: {warnings:?}"
            );
        }
    }

    #[test]
    fn skip_reasons_name_the_unsupported_setting() {
        let reasons: Vec<String> = UNSUPPORTED
            .iter()
            .map(|(_, change)| {
                let mut p = policy(42);
                change(&mut p);
                skip_reason(&p).expect("unsupported policy has a reason")
            })
            .collect();
        assert_eq!(
            reasons,
            [
                "grouping by Source is not supported yet",
                "counterpart scope Internal is not supported yet",
                "counterpart scope External is not supported yet",
                "no sensor is assigned",
                "ProcessCreate is not a network raw event kind",
                "Netflow5 is not a network raw event kind",
                "Sum(OrigBytes) is defined only on Conn, not on Dns",
            ]
        );
        assert_eq!(skip_reason(&policy(42)), None);
        let mut two_sensors = policy(42);
        two_sensors.sensors.push("other".into());
        assert_eq!(skip_reason(&two_sensors), None, "a sensor bundle runs");
    }

    #[tokio::test]
    async fn unsupported_policy_writes_nothing_and_is_skipped() {
        run_test(async {
            for (what, change) in UNSUPPORTED {
                let h = Harness::new(r#"{"42":100}"#).await;
                let mut unsupported = policy(42);
                change(&mut unsupported);
                h.handle
                    .replace_policies(vec![unsupported, policy(7)])
                    .await
                    .unwrap();
                assert_eq!(h.handle.get_all_policy_ids(), [7], "{what}");
                assert!(
                    h.handle.stream_policy(42).await.unwrap().is_none(),
                    "{what}"
                );
                assert!(h.handle.stream_policy(7).await.unwrap().is_some(), "{what}");
                assert_eq!(h.saved(), HashMap::from([("42".into(), 100)]), "{what}");
                h.finish().await;
            }
        })
        .await;
    }

    #[tokio::test]
    async fn change_to_unsupported_policy_stops_it_and_keeps_its_checkpoint() {
        run_test(async {
            for (what, change) in UNSUPPORTED {
                let h = Harness::new(r#"{"42":100,"7":200}"#).await;
                h.handle
                    .replace_policies(vec![policy(42), policy(7)])
                    .await
                    .unwrap();
                let token = h.handle.get_policy_token(42).await.unwrap();
                let kept = h.handle.get_policy_token(7).await.unwrap();
                let mut unsupported = policy(42);
                change(&mut unsupported);
                h.handle
                    .replace_policies(vec![unsupported, policy(7)])
                    .await
                    .unwrap();
                assert!(token.is_cancelled(), "{what}: stopped");
                assert!(!kept.is_cancelled(), "{what}: other policy runs on");
                assert_eq!(h.handle.get_all_policy_ids(), [7], "{what}");
                assert_eq!(
                    h.saved(),
                    HashMap::from([("42".into(), 100), ("7".into(), 200)]),
                    "{what}: checkpoint kept"
                );
                // Changed back, the policy resumes from its kept checkpoint.
                h.handle
                    .replace_policies(vec![policy(42), policy(7)])
                    .await
                    .unwrap();
                assert_eq!(
                    h.handle.stream_policy(42).await.unwrap().unwrap().start,
                    100,
                    "{what}: resumes"
                );
                h.finish().await;
            }
        })
        .await;
    }

    #[tokio::test]
    async fn duplicate_id_in_one_list_keeps_the_first() {
        run_test(async {
            let h = Harness::new("{}").await;
            let mut second = policy(42);
            second.sensors = vec!["second".into()];
            h.handle
                .replace_policies(vec![policy(42), second])
                .await
                .unwrap();
            assert_eq!(h.handle.get_all_policy_ids(), [42]);
            assert_eq!(h.handle.get_policy(42).await.unwrap().sensors, ["test"]);
            h.finish().await;
        })
        .await;
    }

    #[tokio::test]
    async fn slow_publish_observes_only_current_policies() {
        run_test(async {
            let h = Harness::new("{}").await;
            let mut snapshot = h.handle.subscribe();
            // Publish has not consumed any notification, as during a Giganto outage.
            h.handle
                .replace_policies((0..3).map(policy).collect())
                .await
                .unwrap();
            h.handle.delete_policies((0..2).collect()).await.unwrap();
            assert!(snapshot.has_changed().unwrap());
            assert_eq!(*snapshot.borrow_and_update(), [2]);
            assert!(h.handle.stream_policy(0).await.unwrap().is_none());
            h.handle.delete_policies(vec![2]).await.unwrap();
            assert!(snapshot.has_changed().unwrap());
            assert!(snapshot.borrow().is_empty());
            h.finish().await;
        })
        .await;
    }

    #[tokio::test]
    async fn deletion_before_any_worker_persists_before_success() {
        run_test(async {
            let h = Harness::new(r#"{"42":1700000000000000000,"99":123}"#).await;
            h.handle.replace_policies(vec![policy(42)]).await.unwrap();
            let token = h.handle.get_policy_token(42).await.unwrap();
            h.handle.delete_policies(vec![42]).await.unwrap();
            assert!(token.is_cancelled());
            assert!(h.handle.get_policy(42).await.is_none());
            assert_eq!(h.saved(), HashMap::from([("99".into(), 123)]));
            h.finish().await;
        })
        .await;
    }

    #[tokio::test]
    async fn explicit_delete_removes_checkpoint_even_before_review_restores_policy() {
        run_test(async {
            let h = Harness::new(r#"{"42":10,"7":20}"#).await;
            h.handle.delete_policies(vec![42, 42, 999]).await.unwrap();
            assert_eq!(h.saved(), HashMap::from([("7".into(), 20)]));
            h.finish().await;
        })
        .await;
    }

    #[tokio::test]
    async fn late_ack_after_delete_cannot_restore_checkpoint() {
        run_test(async {
            let h = Harness::new("{}").await;
            h.handle
                .replace_policies(vec![policy(42), policy(7)])
                .await
                .unwrap();
            h.handle.record_ack(42, 100).await.unwrap();
            h.handle.record_ack(7, 200).await.unwrap();
            h.handle.delete_policies(vec![42]).await.unwrap();
            h.handle.record_ack(42, 999).await.unwrap();
            h.handle.record_ack(888, 999).await.unwrap();
            // A following query is a barrier for preceding commands on the same handle.
            assert!(h.handle.stream_policy(42).await.unwrap().is_none());
            assert_eq!(h.saved(), HashMap::from([("7".into(), 200)]));
            h.finish().await;
        })
        .await;
    }

    #[tokio::test]
    async fn readd_after_completed_delete_starts_from_zero_and_accepts_new_ack() {
        run_test(async {
            let h = Harness::new(r#"{"42":123}"#).await;
            h.handle.replace_policies(vec![policy(42)]).await.unwrap();
            let mut snapshot = h.handle.subscribe();
            assert_eq!(*snapshot.borrow_and_update(), [42]);
            let old = h.handle.get_policy_token(42).await.unwrap();
            h.handle.delete_policies(vec![42]).await.unwrap();
            let mut replacement = policy(42);
            replacement.sensors = vec!["replacement".into()];
            h.handle.replace_policies(vec![replacement]).await.unwrap();
            // The final ID list is unchanged, but Publish must still observe the update
            // and use the actor's new policy and token after the completed deletion.
            assert!(snapshot.has_changed().unwrap());
            assert_eq!(*snapshot.borrow_and_update(), [42]);
            let state = h.handle.stream_policy(42).await.unwrap().unwrap();
            assert_eq!(state.start, 0);
            assert_eq!(state.policy.sensors, ["replacement"]);
            assert!(old.is_cancelled());
            assert!(!state.token.is_cancelled());
            h.handle.record_ack(42, 456).await.unwrap();
            assert_eq!(
                h.handle.stream_policy(42).await.unwrap().unwrap().start,
                456
            );
            assert_eq!(h.saved()["42"], 456);
            h.finish().await;
        })
        .await;
    }

    #[tokio::test]
    async fn startup_preserves_saved_timestamps_until_review_policy_restore() {
        run_test(async {
            let h = Harness::new(r#"{"42":1700000000000000000}"#).await;
            assert_eq!(h.handle.get_all_policy_ids(), [] as [u32; 0]);
            assert!(h.handle.stream_policy(42).await.unwrap().is_none());
            h.handle.replace_policies(vec![policy(42)]).await.unwrap();
            assert_eq!(
                h.handle.stream_policy(42).await.unwrap().unwrap().start,
                1_700_000_000_000_000_000
            );
            h.finish().await;
        })
        .await;
    }

    #[tokio::test]
    async fn restart_restores_survivors_but_does_not_restore_deleted_timestamp() {
        run_test(async {
            let h = Harness::new(r#"{"42":100,"7":200}"#).await;
            h.handle
                .replace_policies(vec![policy(42), policy(7)])
                .await
                .unwrap();
            h.handle.delete_policies(vec![42]).await.unwrap();
            drop(h.handle);
            join_actor(h.task).await.unwrap();
            let (handle, task) = spawn_policy_actor(h.path.clone(), &h.coordinator)
                .await
                .unwrap();
            handle
                .replace_policies(vec![policy(42), policy(7)])
                .await
                .unwrap();
            assert_eq!(handle.stream_policy(42).await.unwrap().unwrap().start, 0);
            assert_eq!(handle.stream_policy(7).await.unwrap().unwrap().start, 200);
            drop(handle);
            join_actor(task).await.unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn cancellation_keeps_actor_alive_for_final_ack_and_delete() {
        run_test(async {
            let h = Harness::new(r#"{"42":100}"#).await;
            h.handle
                .replace_policies(vec![policy(42), policy(7)])
                .await
                .unwrap();
            h.coordinator
                .request_cancellation("shutdown during deletion");
            h.handle.delete_policies(vec![42]).await.unwrap();
            assert!(!h.task.is_finished());
            h.handle.record_ack(7, 999).await.unwrap();
            h.handle.record_ack(42, 777).await.unwrap();
            let path = h.path.clone();
            drop(h.handle);
            join_actor(h.task).await.unwrap();
            let saved: HashMap<String, i64> =
                serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
            assert_eq!(saved, HashMap::from([("7".into(), 999)]));
        })
        .await;
    }

    #[tokio::test]
    async fn cancelled_delete_caller_does_not_cancel_accepted_deletion() {
        run_test(async {
            let h = Harness::new(r#"{"42":100}"#).await;
            h.handle.replace_policies(vec![policy(42)]).await.unwrap();
            let (reply, received) = oneshot::channel();
            h.handle
                .tx
                .send(PolicyCommand::DeletePolicies {
                    ids: vec![42],
                    reply,
                })
                .await
                .unwrap();
            drop(received);
            assert!(h.handle.stream_policy(42).await.unwrap().is_none());
            assert!(h.saved().is_empty());
            h.finish().await;
        })
        .await;
    }

    #[tokio::test]
    async fn cancelled_add_caller_does_not_cancel_accepted_addition() {
        run_test(async {
            let h = Harness::new("{}").await;
            let (reply, received) = oneshot::channel();
            h.handle
                .tx
                .send(PolicyCommand::ReplacePolicies {
                    policies: vec![policy(42)],
                    reply,
                })
                .await
                .unwrap();
            drop(received);
            assert!(h.handle.stream_policy(42).await.unwrap().is_some());
            h.finish().await;
        })
        .await;
    }

    #[tokio::test]
    async fn delete_write_failure_is_returned_and_actor_fails() {
        run_test(async {
            let h = Harness::new(r#"{"42":100}"#).await;
            h.handle.replace_policies(vec![policy(42)]).await.unwrap();
            // Replacing the target with a directory deterministically fails rename,
            // including when tests run with elevated filesystem permissions.
            std::fs::remove_file(&h.path).unwrap();
            std::fs::create_dir(&h.path).unwrap();
            assert!(h.handle.delete_policies(vec![42]).await.is_err());
            assert!(join_actor(h.task).await.is_err());
            assert!(h.handle.replace_policies(vec![policy(7)]).await.is_err());
            assert!(h.handle.delete_policies(vec![7]).await.is_err());
            assert!(h.handle.record_ack(7, 1).await.is_err());
            assert!(h.handle.stream_policy(7).await.is_err());
        })
        .await;
    }

    #[tokio::test]
    async fn changed_content_write_failure_is_returned_and_actor_fails() {
        run_test(async {
            let h = Harness::new(r#"{"42":100}"#).await;
            h.handle.replace_policies(vec![policy(42)]).await.unwrap();
            std::fs::remove_file(&h.path).unwrap();
            std::fs::create_dir(&h.path).unwrap();
            let mut changed = policy(42);
            changed.slot_size = Duration::from_secs(30);
            assert!(h.handle.replace_policies(vec![changed]).await.is_err());
            assert!(join_actor(h.task).await.is_err());
        })
        .await;
    }

    #[tokio::test]
    async fn ack_write_failure_is_reported_by_actor_task() {
        run_test(async {
            let h = Harness::new("{}").await;
            h.handle.replace_policies(vec![policy(42)]).await.unwrap();
            std::fs::remove_file(&h.path).unwrap();
            std::fs::create_dir(&h.path).unwrap();
            h.handle.record_ack(42, 100).await.unwrap();
            assert!(join_actor(h.task).await.is_err());
        })
        .await;
    }

    #[test]
    fn resume_timestamp_is_the_checkpoint_itself() {
        assert_eq!(start_timestamp(None), 0);
        for checkpoint in [0, 1, -1, 1_700_000_000_000_000_001, i64::MIN, i64::MAX] {
            assert_eq!(start_timestamp(Some(checkpoint)), checkpoint);
        }
    }

    #[tokio::test]
    async fn ack_older_than_the_checkpoint_does_not_lower_it() {
        run_test(async {
            let h = Harness::new(r#"{"42":200}"#).await;
            h.handle.replace_policies(vec![policy(42)]).await.unwrap();
            // A window corrected by a late event is acknowledged after a newer one.
            h.handle.record_ack(42, 100).await.unwrap();
            assert_eq!(
                h.handle.stream_policy(42).await.unwrap().unwrap().start,
                200
            );
            assert_eq!(h.saved()["42"], 200);
            h.handle.record_ack(42, 200).await.unwrap();
            h.handle.record_ack(42, 300).await.unwrap();
            assert_eq!(
                h.handle.stream_policy(42).await.unwrap().unwrap().start,
                300
            );
            assert_eq!(h.saved()["42"], 300);
            h.finish().await;
        })
        .await;
    }

    #[tokio::test]
    async fn checkpoint_round_trip_preserves_integer_boundaries_and_updates() {
        run_test(async {
            let h = Harness::new("{}").await;
            let values = [0, 1, -1, 1_700_000_000_000_000_001, i64::MIN, i64::MAX];
            h.handle
                .replace_policies((0..6).map(policy).collect())
                .await
                .unwrap();
            for (id, value) in (0..6).zip(values) {
                h.handle.record_ack(id, value).await.unwrap();
            }
            h.handle.record_ack(0, 42).await.unwrap();
            let _ = h.handle.stream_policy(0).await.unwrap();
            let saved = h.saved();
            assert_eq!(saved["0"], 42);
            for (id, value) in (1..6).zip(values.into_iter().skip(1)) {
                assert_eq!(saved[&id.to_string()], value);
            }
            h.finish().await;
        })
        .await;
    }

    #[tokio::test]
    async fn invalid_checkpoint_is_rejected_without_overwriting_it() {
        run_test(async {
            for contents in [
                "not json",
                "[]",
                "null",
                r#"{"1":1.5}"#,
                r#"{"1":"date"}"#,
                r#"{"1":true}"#,
                r#"{"1":9223372036854775808}"#,
            ] {
                let dir = tempfile::tempdir().unwrap();
                let path = dir.path().join("timestamps.json");
                std::fs::write(&path, contents).unwrap();
                let coordinator = CancellationCoordinator::new();
                assert!(
                    spawn_policy_actor(path.clone(), &coordinator)
                        .await
                        .is_err()
                );
                assert_eq!(std::fs::read_to_string(path).unwrap(), contents);
                assert_eq!(coordinator.tracker().active_count(), 0);
            }
        })
        .await;
    }

    #[tokio::test]
    async fn missing_checkpoint_is_created_but_missing_parent_is_an_error() {
        run_test(async {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("timestamps.json");
            let coordinator = CancellationCoordinator::new();
            let (handle, task) = spawn_policy_actor(path.clone(), &coordinator)
                .await
                .unwrap();
            assert_eq!(std::fs::read_to_string(&path).unwrap(), "{}");
            drop(handle);
            join_actor(task).await.unwrap();
            assert!(
                spawn_policy_actor(dir.path().join("absent/file.json"), &coordinator)
                    .await
                    .is_err()
            );
        })
        .await;
    }
}
