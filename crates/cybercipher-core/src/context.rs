//! Execution context: cancellation, deadlines, and budgets shared by all
//! operations within a single run.

use crate::error::{ErrorKind, OpResult, OperationError};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Context handed to every operation invocation. Cheap to clone; the
/// cancellation flag is shared.
#[derive(Clone, Default)]
pub struct ExecutionContext {
    cancel: Option<Arc<AtomicBool>>,
    deadline: Option<Instant>,
    started: Option<Instant>,
}

impl ExecutionContext {
    pub fn new() -> Self {
        ExecutionContext::default()
    }

    /// Attach a shared cancellation flag.
    pub fn with_cancel(mut self, flag: Arc<AtomicBool>) -> Self {
        self.cancel = Some(flag);
        self
    }

    /// Attach a deadline after which checks fail with `BudgetExceeded`.
    pub fn with_deadline(mut self, deadline: Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }

    /// Record the run start time (used for progress reporting).
    pub fn with_start(mut self, started: Instant) -> Self {
        self.started = Some(started);
        self
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel
            .as_ref()
            .is_some_and(|f| f.load(Ordering::Relaxed))
    }

    pub fn cancel(&self) {
        if let Some(f) = &self.cancel {
            f.store(true, Ordering::Relaxed);
        }
    }

    pub fn started(&self) -> Instant {
        self.started.unwrap_or_else(Instant::now)
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// Fail fast if the run has been cancelled or has blown its deadline.
    /// Long-running operations should call this periodically.
    pub fn check(&self) -> OpResult<()> {
        if self.is_cancelled() {
            return Err(OperationError::cancelled());
        }
        if let Some(d) = self.deadline {
            if Instant::now() >= d {
                return Err(OperationError::new(
                    ErrorKind::BudgetExceeded,
                    "Execution deadline exceeded",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_propagates() {
        let flag = Arc::new(AtomicBool::new(false));
        let ctx = ExecutionContext::new().with_cancel(flag.clone());
        assert!(ctx.check().is_ok());
        flag.store(true, Ordering::Relaxed);
        let err = ctx.check().unwrap_err();
        assert_eq!(err.kind, ErrorKind::Cancelled);
    }
}
