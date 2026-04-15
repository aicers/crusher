use std::sync::Arc;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// Tracks active child tasks and allows waiting for all of them to
/// complete during drain.
#[derive(Clone)]
pub(crate) struct TaskTracker {
    inner: tokio_util::task::TaskTracker,
}

impl TaskTracker {
    fn new() -> Self {
        Self {
            inner: tokio_util::task::TaskTracker::new(),
        }
    }

    /// Spawns a tracked task. The task is registered so that
    /// [`Self::close_and_wait`] can be used to wait for it to complete.
    pub(crate) fn spawn<F>(&self, future: F) -> JoinHandle<F::Output>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.inner.spawn(future)
    }

    /// Returns the number of currently active tracked tasks.
    pub(crate) fn active_count(&self) -> usize {
        self.inner.len()
    }

    /// Closes the tracker (no new tasks can be spawned) and waits for
    /// all tracked tasks to complete.
    async fn close_and_wait(&self) {
        self.inner.close();
        self.inner.wait().await;
    }
}

/// Cancellation phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CancellationPhase {
    Running,
    Draining,
    Completed,
}

/// Coordinates async task cancellation across the application. Owns a
/// [`CancellationToken`] and a [`TaskTracker`].
#[derive(Clone)]
pub(crate) struct CancellationCoordinator {
    token: CancellationToken,
    tracker: TaskTracker,
    phase: Arc<std::sync::Mutex<CancellationPhase>>,
}

impl CancellationCoordinator {
    /// Creates a new coordinator in the `Running` phase.
    pub(crate) fn new() -> Self {
        Self {
            token: CancellationToken::new(),
            tracker: TaskTracker::new(),
            phase: Arc::new(std::sync::Mutex::new(CancellationPhase::Running)),
        }
    }

    /// Returns a reference to the task tracker.
    pub(crate) fn tracker(&self) -> &TaskTracker {
        &self.tracker
    }

    /// Requests cancellation by cancelling the token.
    pub(crate) fn request_cancellation(&self, reason: &str) {
        let mut phase = self.phase.lock().expect("phase lock poisoned");
        if *phase == CancellationPhase::Running {
            info!(%reason, "Cancellation requested");
            *phase = CancellationPhase::Draining;
            self.token.cancel();
        }
    }

    /// Returns `true` if cancellation has been requested.
    #[cfg(test)]
    pub(crate) fn is_cancelled(&self) -> bool {
        self.token.is_cancelled()
    }

    /// Waits until the cancellation token is cancelled.
    pub(crate) async fn cancelled(&self) {
        self.token.cancelled().await;
    }

    /// Waits for all tracked tasks to complete after cancellation has
    /// been requested. Returns `true` if drain completed within the
    /// timeout, `false` if timed out.
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    pub(crate) async fn wait_for_drain(&self, timeout: std::time::Duration) -> bool {
        let drain = self.tracker.close_and_wait();
        let completed = tokio::time::timeout(timeout, drain).await.is_ok();
        let mut phase = self.phase.lock().expect("phase lock poisoned");
        if completed {
            *phase = CancellationPhase::Completed;
            info!("Drain completed");
        } else {
            warn!(
                remaining = self.tracker.active_count(),
                "Drain timed out"
            );
        }
        completed
    }

    /// Returns the current cancellation phase.
    #[cfg(test)]
    pub(crate) fn phase(&self) -> CancellationPhase {
        *self.phase.lock().expect("phase lock poisoned")
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::sync::Notify;

    use super::*;

    #[tokio::test]
    async fn cancellation_token_propagates() {
        let coord = CancellationCoordinator::new();
        assert!(!coord.is_cancelled());
        assert_eq!(coord.phase(), CancellationPhase::Running);

        coord.request_cancellation("test");
        assert!(coord.is_cancelled());
        assert_eq!(coord.phase(), CancellationPhase::Draining);
    }

    #[tokio::test]
    async fn task_tracker_counts_tasks() {
        let coord = CancellationCoordinator::new();
        let tracker = coord.tracker().clone();

        let notify = Arc::new(Notify::new());
        let n = notify.clone();

        assert_eq!(tracker.active_count(), 0);

        let _h = tracker.spawn(async move {
            n.notified().await;
        });

        // Give the task a moment to register.
        tokio::task::yield_now().await;
        assert_eq!(tracker.active_count(), 1);

        notify.notify_one();
        // Wait for task to finish.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(tracker.active_count(), 0);
    }

    #[tokio::test]
    async fn drain_completes_when_tasks_finish() {
        let coord = CancellationCoordinator::new();
        let tracker = coord.tracker().clone();
        let notify = Arc::new(Notify::new());
        let n = notify.clone();

        tracker.spawn(async move {
            n.notified().await;
        });

        coord.request_cancellation("test drain");

        // Release the blocked task.
        notify.notify_one();

        let completed = coord.wait_for_drain(Duration::from_secs(5)).await;
        assert!(completed);
        assert_eq!(coord.phase(), CancellationPhase::Completed);
        assert_eq!(tracker.active_count(), 0);
    }

    #[tokio::test]
    async fn drain_times_out_with_stuck_task() {
        let coord = CancellationCoordinator::new();
        let tracker = coord.tracker().clone();

        tracker.spawn(async {
            // Never finishes.
            std::future::pending::<()>().await;
        });

        coord.request_cancellation("timeout test");
        let completed = coord.wait_for_drain(Duration::from_millis(50)).await;
        assert!(!completed);
        assert_eq!(coord.phase(), CancellationPhase::Draining);
    }

    #[tokio::test]
    async fn panicking_task_is_tracked_correctly() {
        let coord = CancellationCoordinator::new();
        let tracker = coord.tracker().clone();

        let h = tracker.spawn(async {
            panic!("intentional panic");
        });

        // Wait for the panic to propagate.
        let _ = h.await;
        assert_eq!(tracker.active_count(), 0);

        coord.request_cancellation("panic test");
        let completed = coord.wait_for_drain(Duration::from_secs(1)).await;
        assert!(completed);
    }

    #[tokio::test]
    async fn multiple_cancellation_requests_are_idempotent() {
        let coord = CancellationCoordinator::new();
        coord.request_cancellation("first");
        coord.request_cancellation("second");
        assert!(coord.is_cancelled());
        assert_eq!(coord.phase(), CancellationPhase::Draining);
    }

    /// Drain timeout must leave the coordinator in `Draining` phase,
    /// proving the state is not clean enough for a new generation.
    /// The caller (`run()` in main.rs) treats this as fatal by calling
    /// `process::exit(1)`, preventing re-entry into a new run cycle.
    #[tokio::test]
    async fn drain_timeout_prevents_reentry() {
        let coord = CancellationCoordinator::new();
        let tracker = coord.tracker().clone();

        // Spawn a task that never finishes.
        tracker.spawn(async {
            std::future::pending::<()>().await;
        });

        coord.request_cancellation("reentry test");
        let completed = coord.wait_for_drain(Duration::from_millis(50)).await;

        // Drain timed out — phase must NOT be Completed.
        assert!(!completed);
        assert_eq!(coord.phase(), CancellationPhase::Draining);
        // Active tasks are still alive — a new generation must not
        // start because it would overlap with stuck tasks.
        assert!(
            coord.tracker().active_count() > 0,
            "stuck tasks must still be tracked"
        );
    }
}
