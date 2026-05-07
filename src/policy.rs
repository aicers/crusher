use std::collections::HashMap;

use async_channel::Sender;
use review_protocol::types::SamplingPolicy;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::cancellation::CancellationCoordinator;

const POLICY_COMMAND_CHANNEL_SIZE: usize = 32;

enum PolicyCommand {
    AddPolicies {
        policies: Vec<SamplingPolicy>,
        reply: oneshot::Sender<Result<(), String>>,
    },
    DeletePolicies {
        ids: Vec<u32>,
        reply: oneshot::Sender<Result<(), String>>,
    },
    #[cfg(test)]
    GetPolicy {
        id: u32,
        reply: oneshot::Sender<Option<SamplingPolicy>>,
    },
    GetAllPolicies {
        reply: oneshot::Sender<Vec<SamplingPolicy>>,
    },
    #[cfg(test)]
    GetPolicyToken {
        id: u32,
        reply: oneshot::Sender<Option<CancellationToken>>,
    },
    GetPolicyWithToken {
        id: u32,
        reply: oneshot::Sender<Option<(SamplingPolicy, CancellationToken)>>,
    },
}

/// A cloneable handle to the policy actor. All policy state mutations
/// go through this handle, ensuring atomicity and cancellation safety.
#[derive(Clone)]
pub(crate) struct PolicyHandle {
    tx: mpsc::Sender<PolicyCommand>,
}

impl PolicyHandle {
    /// Adds policies to the active set and enqueues each new policy
    /// for delivery to the subscribe side. Duplicate policy IDs are
    /// silently skipped. The handoff to the subscribe channel is done
    /// through an internal unbounded queue drained by a relay task, so
    /// this call never blocks on subscribe-side backpressure.
    pub(crate) async fn add_policies(&self, policies: Vec<SamplingPolicy>) -> Result<(), String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(PolicyCommand::AddPolicies {
                policies,
                reply: reply_tx,
            })
            .await
            .map_err(|_| "policy actor closed".to_string())?;
        reply_rx
            .await
            .map_err(|_| "policy actor dropped reply".to_string())?
    }

    /// Marks policies for deletion. Removes them from the active set
    /// and queues their IDs for the subscribe side to consume.
    pub(crate) async fn delete_policies(&self, ids: Vec<u32>) -> Result<(), String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(PolicyCommand::DeletePolicies {
                ids,
                reply: reply_tx,
            })
            .await
            .map_err(|_| "policy actor closed".to_string())?;
        reply_rx
            .await
            .map_err(|_| "policy actor dropped reply".to_string())?
    }

    /// Returns a clone of the policy with the given ID, if it exists.
    #[cfg(test)]
    pub(crate) async fn get_policy(&self, id: u32) -> Option<SamplingPolicy> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self
            .tx
            .send(PolicyCommand::GetPolicy {
                id,
                reply: reply_tx,
            })
            .await;
        reply_rx.await.ok().flatten()
    }

    /// Returns a snapshot of all currently active policies.
    pub(crate) async fn get_all_policies(&self) -> Vec<SamplingPolicy> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self
            .tx
            .send(PolicyCommand::GetAllPolicies { reply: reply_tx })
            .await;
        reply_rx.await.unwrap_or_default()
    }

    /// Returns the `CancellationToken` for the given policy ID. Used
    /// by tests to observe per-policy cancellation directly; production
    /// code uses [`Self::get_policy_with_token`] for atomic lookup.
    #[cfg(test)]
    pub(crate) async fn get_policy_token(&self, id: u32) -> Option<CancellationToken> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self
            .tx
            .send(PolicyCommand::GetPolicyToken {
                id,
                reply: reply_tx,
            })
            .await;
        reply_rx.await.ok().flatten()
    }

    /// Atomically returns both the policy and its `CancellationToken`
    /// for the given ID. Returns `None` if the policy is not active.
    /// Used by the inbound stream dispatcher to bind a freshly accepted
    /// stream to its current policy state in a single actor command,
    /// preventing a delete from slipping between separate lookups.
    pub(crate) async fn get_policy_with_token(
        &self,
        id: u32,
    ) -> Option<(SamplingPolicy, CancellationToken)> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self
            .tx
            .send(PolicyCommand::GetPolicyWithToken {
                id,
                reply: reply_tx,
            })
            .await;
        reply_rx.await.ok().flatten()
    }
}

/// Spawns the policy actor as a tracked task. The actor owns all
/// policy state and processes commands sequentially, preventing
/// partial-state updates on cancellation.
///
/// The actor exits when all [`PolicyHandle`] clones are dropped
/// (the command channel closes) or when cancellation is requested.
pub(crate) fn spawn_policy_actor(
    policy_send: Sender<SamplingPolicy>,
    coordinator: &CancellationCoordinator,
) -> PolicyHandle {
    let (tx, mut rx) = mpsc::channel::<PolicyCommand>(POLICY_COMMAND_CHANNEL_SIZE);

    // Internal unbounded queue for forwarding newly added policies to
    // the subscribe side. Keeping the forward out of the actor body
    // ensures the actor is never blocked by external backpressure on
    // `policy_send`: during startup restore the subscribe side
    // awaits `get_all_policies()` before it starts draining
    // `policy_send`, so a bounded in-actor send would deadlock the
    // actor and every other command queued behind it.
    let (relay_tx, mut relay_rx) = mpsc::unbounded_channel::<SamplingPolicy>();
    let relay_coord = coordinator.clone();
    coordinator.tracker().spawn(async move {
        loop {
            let policy = tokio::select! {
                biased;
                () = relay_coord.cancelled() => break,
                msg = relay_rx.recv() => match msg {
                    Some(p) => p,
                    None => break,
                },
            };
            if let Err(e) = policy_send.send(policy).await {
                warn!("Policy relay to subscribe side failed: {e}");
                break;
            }
        }
    });

    let coord = coordinator.clone();
    coordinator.tracker().spawn(async move {
        let mut active_policies: HashMap<u32, SamplingPolicy> = HashMap::new();
        let mut policy_tokens: HashMap<u32, CancellationToken> = HashMap::new();

        loop {
            let cmd = tokio::select! {
                biased;
                () = coord.cancelled() => break,
                cmd = rx.recv() => {
                    match cmd {
                        Some(cmd) => cmd,
                        None => break,
                    }
                }
            };
            match cmd {
                PolicyCommand::AddPolicies { policies, reply } => {
                    for policy in policies {
                        if active_policies.contains_key(&policy.id) {
                            debug!("Duplicated policy: {:?}", policy);
                            continue;
                        }
                        let id = policy.id;
                        active_policies.insert(id, policy.clone());
                        policy_tokens.insert(id, CancellationToken::new());
                        info!("Received request to update time series policy list");
                        if relay_tx.send(policy).is_err() {
                            warn!("Policy relay closed; forward skipped");
                        }
                    }
                    let _ = reply.send(Ok(()));
                }
                PolicyCommand::DeletePolicies { ids, reply } => {
                    for &id in &ids {
                        if let Some(deleted) = active_policies.remove(&id) {
                            info!(
                                "Received request to delete time series policy {}",
                                deleted.id
                            );
                            if let Some(token) = policy_tokens.remove(&id) {
                                token.cancel();
                            }
                        }
                    }
                    let _ = reply.send(Ok(()));
                }
                #[cfg(test)]
                PolicyCommand::GetPolicy { id, reply } => {
                    let _ = reply.send(active_policies.get(&id).cloned());
                }
                PolicyCommand::GetAllPolicies { reply } => {
                    let _ = reply.send(active_policies.values().cloned().collect());
                }
                #[cfg(test)]
                PolicyCommand::GetPolicyToken { id, reply } => {
                    let _ = reply.send(policy_tokens.get(&id).cloned());
                }
                PolicyCommand::GetPolicyWithToken { id, reply } => {
                    let combined = active_policies
                        .get(&id)
                        .cloned()
                        .and_then(|p| policy_tokens.get(&id).cloned().map(|token| (p, token)));
                    let _ = reply.send(combined);
                }
            }
        }
    });

    PolicyHandle { tx }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use review_protocol::types::{SamplingKind, SamplingPolicy};

    use super::*;
    use crate::cancellation::CancellationCoordinator;

    fn test_policy(id: u32) -> SamplingPolicy {
        SamplingPolicy {
            id,
            kind: SamplingKind::Conn,
            interval: Duration::from_mins(1),
            period: Duration::from_hours(1),
            offset: 0,
            src_ip: None,
            dst_ip: None,
            node: Some("test".to_string()),
            column: None,
        }
    }

    #[tokio::test]
    async fn add_and_get_policies() {
        let coordinator = CancellationCoordinator::new();
        let (policy_tx, policy_rx) = async_channel::bounded::<SamplingPolicy>(10);
        let handle = spawn_policy_actor(policy_tx, &coordinator);

        let p1 = test_policy(1);
        let p2 = test_policy(2);
        handle.add_policies(vec![p1, p2]).await.unwrap();

        assert!(handle.get_policy(1).await.is_some());
        assert!(handle.get_policy(2).await.is_some());
        assert!(handle.get_policy(99).await.is_none());

        let all = handle.get_all_policies().await;
        assert_eq!(all.len(), 2);

        // Policies were forwarded to the subscribe channel.
        assert_eq!(policy_rx.len(), 2);
    }

    #[tokio::test]
    async fn duplicate_policies_are_skipped() {
        let coordinator = CancellationCoordinator::new();
        let (policy_tx, policy_rx) = async_channel::bounded::<SamplingPolicy>(10);
        let handle = spawn_policy_actor(policy_tx, &coordinator);

        let p = test_policy(1);
        handle.add_policies(vec![p.clone()]).await.unwrap();
        handle.add_policies(vec![p]).await.unwrap();

        assert_eq!(handle.get_all_policies().await.len(), 1);
        // Only one was forwarded.
        assert_eq!(policy_rx.len(), 1);
    }

    #[tokio::test]
    async fn delete_cancels_token() {
        let coordinator = CancellationCoordinator::new();
        let (policy_tx, _policy_rx) = async_channel::bounded::<SamplingPolicy>(10);
        let handle = spawn_policy_actor(policy_tx, &coordinator);

        handle.add_policies(vec![test_policy(1)]).await.unwrap();
        assert!(handle.get_policy(1).await.is_some());

        let token = handle.get_policy_token(1).await.unwrap();
        assert!(!token.is_cancelled());

        handle.delete_policies(vec![1]).await.unwrap();
        assert!(handle.get_policy(1).await.is_none());
        assert!(token.is_cancelled());
        assert!(handle.get_policy_token(1).await.is_none());
    }

    /// Cancelling the caller of `add_policies` must not leave the
    /// actor in an inconsistent state. The actor processes commands
    /// sequentially, so either the full command completes or nothing
    /// happens (the command was never received).
    #[tokio::test]
    async fn cancel_caller_during_add_does_not_corrupt_state() {
        let coordinator = CancellationCoordinator::new();
        let (policy_tx, _policy_rx) = async_channel::bounded::<SamplingPolicy>(10);
        let handle = spawn_policy_actor(policy_tx, &coordinator);

        let handle_clone = handle.clone();
        let add_task = tokio::spawn(async move {
            handle_clone
                .add_policies(vec![test_policy(1), test_policy(2)])
                .await
        });

        // Cancel the caller immediately — it may or may not have
        // received the reply yet.
        add_task.abort();
        let _ = add_task.await;

        // Give the actor a moment to finish processing.
        tokio::task::yield_now().await;

        // The actor is still alive and consistent. The command was
        // processed atomically regardless of caller cancellation.
        let all = handle.get_all_policies().await;
        // Whatever state we're in, a fresh add must succeed.
        handle.add_policies(vec![test_policy(3)]).await.unwrap();
        assert!(handle.get_policy(3).await.is_some());

        // State must be monotonically consistent — no half-committed
        // batches.
        let final_count = handle.get_all_policies().await.len();
        assert!(
            final_count >= all.len(),
            "actor state must be monotonically consistent"
        );
    }

    /// Cancelling the caller of `delete_policies` must not leave
    /// partial state (e.g., removed from active but token not
    /// cancelled).
    #[tokio::test]
    async fn cancel_caller_during_delete_is_safe() {
        let coordinator = CancellationCoordinator::new();
        let (policy_tx, _policy_rx) = async_channel::bounded::<SamplingPolicy>(10);
        let handle = spawn_policy_actor(policy_tx, &coordinator);

        handle
            .add_policies(vec![test_policy(1), test_policy(2)])
            .await
            .unwrap();

        let token1 = handle.get_policy_token(1).await.unwrap();
        let token2 = handle.get_policy_token(2).await.unwrap();

        let handle_clone = handle.clone();
        let delete_task =
            tokio::spawn(async move { handle_clone.delete_policies(vec![1, 2]).await });

        delete_task.abort();
        let _ = delete_task.await;

        for (id, token) in [(1, &token1), (2, &token2)] {
            let active = handle.get_policy(id).await.is_some();
            let cancelled = token.is_cancelled();
            assert!(
                active || cancelled,
                "policy {id} must be active or have its token cancelled"
            );
        }
    }

    /// `get_policy_with_token` returns the policy and its token together
    /// atomically. This prevents a delete from slipping between separate
    /// lookups of the policy and its token.
    #[tokio::test]
    async fn get_policy_with_token_returns_combined_view() {
        let coordinator = CancellationCoordinator::new();
        let (policy_tx, _policy_rx) = async_channel::bounded::<SamplingPolicy>(10);
        let handle = spawn_policy_actor(policy_tx, &coordinator);

        // Returns None for non-existent policy.
        assert!(handle.get_policy_with_token(99).await.is_none());

        handle.add_policies(vec![test_policy(1)]).await.unwrap();

        let result = handle.get_policy_with_token(1).await;
        assert!(result.is_some());
        let (policy, token) = result.unwrap();
        assert_eq!(policy.id, 1);
        assert!(!token.is_cancelled());

        // After deletion, returns None.
        handle.delete_policies(vec![1]).await.unwrap();
        assert!(handle.get_policy_with_token(1).await.is_none());
    }

    /// Cancelling the coordinator must drain both the relay task and the
    /// actor task cleanly within the drain timeout.
    #[tokio::test]
    async fn coordinator_cancellation_shuts_down_relay_and_actor() {
        let coordinator = CancellationCoordinator::new();
        let (policy_tx, _policy_rx) = async_channel::bounded::<SamplingPolicy>(10);
        let handle = spawn_policy_actor(policy_tx, &coordinator);

        handle.add_policies(vec![test_policy(1)]).await.unwrap();

        coordinator.request_cancellation("test shutdown");
        let completed = coordinator.wait_for_drain(Duration::from_secs(5)).await;
        assert!(completed);
        assert_eq!(coordinator.tracker().active_count(), 0);
    }

    /// Once the actor has exited (coordinator cancelled + drained),
    /// `add_policies` must return an error rather than hanging forever.
    #[tokio::test]
    async fn handle_returns_error_after_actor_exits() {
        let coordinator = CancellationCoordinator::new();
        let (policy_tx, _policy_rx) = async_channel::bounded::<SamplingPolicy>(10);
        let handle = spawn_policy_actor(policy_tx, &coordinator);

        coordinator.request_cancellation("shutdown");
        let drained = coordinator.wait_for_drain(Duration::from_secs(5)).await;
        assert!(drained, "tasks must drain within timeout");

        // With the actor gone its rx has been dropped, so any new send
        // fails with a closed-channel error.
        let result = handle.add_policies(vec![test_policy(1)]).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "policy actor closed");
    }

    /// Startup restore regression test: even when the downstream
    /// bounded channel has capacity 1 and no consumer is draining, the
    /// actor must remain responsive to other commands. A prior design
    /// that awaited `policy_send.send()` inside the actor loop would
    /// deadlock here — the actor would be stuck sending the second
    /// policy while `get_all_policies` queued behind it.
    #[tokio::test]
    async fn add_policies_does_not_block_on_full_channel() {
        let coordinator = CancellationCoordinator::new();
        let (policy_tx, policy_rx) = async_channel::bounded::<SamplingPolicy>(1);
        let handle = spawn_policy_actor(policy_tx, &coordinator);

        // Three policies into a size-1 channel with nobody draining.
        // `add_policies` must return promptly — commit to the active
        // set and enqueue to the internal relay, not block.
        tokio::time::timeout(
            Duration::from_millis(500),
            handle.add_policies(vec![test_policy(1), test_policy(2), test_policy(3)]),
        )
        .await
        .expect("add_policies must not block on downstream backpressure")
        .expect("add_policies should succeed");

        // The actor must answer other commands while the relay is
        // still pushing into the full channel.
        let all = tokio::time::timeout(Duration::from_millis(500), handle.get_all_policies())
            .await
            .expect("actor must remain responsive while relay is blocked");
        assert_eq!(all.len(), 3);

        // Drain the bounded channel and confirm all three arrive.
        let mut received = Vec::new();
        for _ in 0..3 {
            let p = tokio::time::timeout(Duration::from_secs(1), policy_rx.recv())
                .await
                .expect("relay must deliver once receiver drains")
                .expect("channel open");
            received.push(p.id);
        }
        received.sort_unstable();
        assert_eq!(received, vec![1, 2, 3]);
    }
}
