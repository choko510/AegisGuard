//! Time and cancellation budget shared by analyzers. Analyzers poll it between
//! bounded work units and record an incomplete reason instead of running on.
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static CANCELLED: AtomicBool = AtomicBool::new(false);

/// Request cooperative cancellation of the running scan (e.g. from Ctrl-C).
pub fn cancel() {
    CANCELLED.store(true, Ordering::SeqCst);
}

pub fn cancelled() -> bool {
    CANCELLED.load(Ordering::SeqCst)
}

#[derive(Debug, Clone, Copy)]
pub struct Budget {
    /// `None` only when the limit is too large to represent.
    deadline: Option<Instant>,
}

impl Budget {
    pub fn new(limit: Duration) -> Self {
        Self {
            deadline: Instant::now().checked_add(limit),
        }
    }

    /// The incomplete reason when work must stop, or `None` to continue.
    pub fn exceeded(&self) -> Option<&'static str> {
        if cancelled() {
            Some("scan_cancelled")
        } else if self.deadline.is_some_and(|d| Instant::now() >= d) {
            Some("analysis_time_limit")
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_budget_is_immediately_exceeded() {
        assert_eq!(
            Budget::new(Duration::ZERO).exceeded(),
            Some("analysis_time_limit")
        );
        assert_eq!(Budget::new(Duration::from_secs(60)).exceeded(), None);
    }

    #[test]
    fn huge_budget_does_not_overflow() {
        assert_eq!(Budget::new(Duration::MAX).exceeded(), None);
    }
}
