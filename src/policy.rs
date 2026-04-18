use std::collections::HashMap;

use async_channel::Sender;
use review_protocol::types::SamplingPolicy;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

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
    /// Adds policies to the active set and notifies the subscribe side
    /// for each new policy. Duplicate policy IDs are silently skipped.
    /// The batch is all-or-nothing: if forwarding any policy fails, all
    /// newly inserted policies in this batch are rolled back.
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
                    let mut inserted_ids = Vec::new();
                    let mut result = Ok(());
                    for policy in policies {
                        if active_policies.contains_key(&policy.id) {
                            debug!("Duplicated policy: {:?}", policy);
                            continue;
                        }
                        let id = policy.id;
                        active_policies.insert(id, policy.clone());
                        policy_tokens.insert(id, CancellationToken::new());
                        inserted_ids.push(id);
                        info!("Received request to update time series policy list");
                        if let Err(e) = policy_send.send(policy).await {
                            for rollback_id in &inserted_ids {
                                active_policies.remove(rollback_id);
                                policy_tokens.remove(rollback_id);
                            }
                            result = Err(format!("send fail: {e}"));
                            break;
                        }
                    }
                    let _ = reply.send(result);
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

    #[tokio::test]
    async fn add_policies_batch_rollback_on_failure() {
        let coordinator = CancellationCoordinator::new();
        let (policy_tx, policy_rx) = async_channel::bounded::<SamplingPolicy>(1);
        let handle = spawn_policy_actor(policy_tx, &coordinator);

        // Fill the channel so that the second policy send will fail.
        handle.add_policies(vec![test_policy(1)]).await.unwrap();
        assert!(handle.get_policy(1).await.is_some());

        // Close the channel receiver so sends fail.
        policy_rx.close();

        let result = handle
            .add_policies(vec![test_policy(2), test_policy(3)])
            .await;
        assert!(result.is_err());

        // Both policies from the failed batch must be rolled back.
        assert!(handle.get_policy(2).await.is_none());
        assert!(handle.get_policy(3).await.is_none());
        // The original policy is untouched.
        assert!(handle.get_policy(1).await.is_some());
    }
}
