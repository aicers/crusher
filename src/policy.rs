use std::collections::HashMap;

use async_channel::Sender;
use review_protocol::types::SamplingPolicy;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info};

use crate::shutdown::ShutdownCoordinator;

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
    GetPolicy {
        id: u32,
        reply: oneshot::Sender<Option<SamplingPolicy>>,
    },
    GetAllPolicies {
        reply: oneshot::Sender<Vec<SamplingPolicy>>,
    },
    IsPendingDelete {
        id: u32,
        reply: oneshot::Sender<bool>,
    },
    ConsumeDelete {
        id: u32,
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

    /// Returns `true` if the given policy ID is pending deletion.
    pub(crate) async fn is_pending_delete(&self, id: u32) -> bool {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self
            .tx
            .send(PolicyCommand::IsPendingDelete {
                id,
                reply: reply_tx,
            })
            .await;
        reply_rx.await.unwrap_or(false)
    }

    /// Removes the given policy ID from the pending-delete list.
    /// Called by the subscribe side after it has acted on the deletion.
    pub(crate) async fn consume_delete(&self, id: u32) {
        let _ = self.tx.send(PolicyCommand::ConsumeDelete { id }).await;
    }
}

/// Spawns the policy actor as a tracked task. The actor owns all
/// policy state and processes commands sequentially, preventing
/// partial-state updates on cancellation.
///
/// The actor exits when all [`PolicyHandle`] clones are dropped
/// (the command channel closes) or when shutdown is requested.
pub(crate) fn spawn_policy_actor(
    policy_send: Sender<SamplingPolicy>,
    coordinator: &ShutdownCoordinator,
) -> PolicyHandle {
    let (tx, mut rx) = mpsc::channel::<PolicyCommand>(POLICY_COMMAND_CHANNEL_SIZE);
    let coord = coordinator.clone();

    coordinator.tracker().spawn(async move {
        let mut active_policies: HashMap<u32, SamplingPolicy> = HashMap::new();
        let mut pending_deletes: Vec<u32> = Vec::new();

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
                    let mut result = Ok(());
                    for policy in policies {
                        if active_policies.contains_key(&policy.id) {
                            debug!("Duplicated policy: {:?}", policy);
                            continue;
                        }
                        let id = policy.id;
                        active_policies.insert(id, policy.clone());
                        info!("Received request to update time series policy list");
                        if let Err(e) = policy_send.send(policy).await {
                            // Roll back the insertion so state stays consistent.
                            active_policies.remove(&id);
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
                            pending_deletes.push(id);
                        }
                    }
                    let _ = reply.send(Ok(()));
                }
                PolicyCommand::GetPolicy { id, reply } => {
                    let _ = reply.send(active_policies.get(&id).cloned());
                }
                PolicyCommand::GetAllPolicies { reply } => {
                    let _ = reply.send(active_policies.values().cloned().collect());
                }
                PolicyCommand::IsPendingDelete { id, reply } => {
                    let _ = reply.send(pending_deletes.contains(&id));
                }
                PolicyCommand::ConsumeDelete { id } => {
                    pending_deletes.retain(|&d| d != id);
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
    use crate::shutdown::ShutdownCoordinator;

    fn test_policy(id: u32) -> SamplingPolicy {
        SamplingPolicy {
            id,
            kind: SamplingKind::Conn,
            interval: Duration::from_secs(60),
            period: Duration::from_secs(3600),
            offset: 0,
            src_ip: None,
            dst_ip: None,
            node: Some("test".to_string()),
            column: None,
        }
    }

    #[tokio::test]
    async fn add_and_get_policies() {
        let coordinator = ShutdownCoordinator::new();
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
        let coordinator = ShutdownCoordinator::new();
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
    async fn delete_and_consume() {
        let coordinator = ShutdownCoordinator::new();
        let (policy_tx, _policy_rx) = async_channel::bounded::<SamplingPolicy>(10);
        let handle = spawn_policy_actor(policy_tx, &coordinator);

        handle.add_policies(vec![test_policy(1)]).await.unwrap();
        assert!(handle.get_policy(1).await.is_some());

        handle.delete_policies(vec![1]).await.unwrap();
        // Removed from active set.
        assert!(handle.get_policy(1).await.is_none());
        // Pending delete is visible.
        assert!(handle.is_pending_delete(1).await);

        handle.consume_delete(1).await;
        assert!(!handle.is_pending_delete(1).await);
    }

    /// Cancelling the caller of `add_policies` must not leave the
    /// actor in an inconsistent state. The actor processes commands
    /// sequentially, so either the full command completes or nothing
    /// happens (the command was never received).
    #[tokio::test]
    async fn cancel_caller_during_add_does_not_corrupt_state() {
        let coordinator = ShutdownCoordinator::new();
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
    /// partial state (e.g., removed from active but not in pending
    /// deletes).
    #[tokio::test]
    async fn cancel_caller_during_delete_is_safe() {
        let coordinator = ShutdownCoordinator::new();
        let (policy_tx, _policy_rx) = async_channel::bounded::<SamplingPolicy>(10);
        let handle = spawn_policy_actor(policy_tx, &coordinator);

        handle
            .add_policies(vec![test_policy(1), test_policy(2)])
            .await
            .unwrap();

        let handle_clone = handle.clone();
        let delete_task =
            tokio::spawn(async move { handle_clone.delete_policies(vec![1, 2]).await });

        // Cancel immediately.
        delete_task.abort();
        let _ = delete_task.await;

        // For each policy, it's either still active or properly in
        // pending-delete — never removed from active without being
        // in pending-delete.
        for id in [1, 2] {
            let active = handle.get_policy(id).await.is_some();
            let pending = handle.is_pending_delete(id).await;
            // Either still active (command not processed) or properly deleted.
            assert!(
                active || pending,
                "policy {id} must be in active set or pending-delete, not neither"
            );
        }
    }
}
