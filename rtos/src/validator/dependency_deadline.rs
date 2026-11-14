// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Native validation dependencies share the caller's absolute deadline, as in
//! TOS/TON ValidateQuery. Offline and collator callers keep their own budgets.

use crate::error::NodeError;
use rtos_block::{error, Result};

#[derive(Clone, Copy, Default)]
pub(super) struct DependencyDeadline(Option<tokio::time::Instant>);

impl DependencyDeadline {
    pub fn at(deadline: tokio::time::Instant) -> Self {
        Self(Some(deadline))
    }

    pub fn timeout_ms(self, fallback: Option<u64>) -> Result<Option<u64>> {
        let Some(deadline) = self.0 else {
            return Ok(fallback);
        };
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| NodeError::Timeout("Validation dependency deadline expired".into()))?;
        // Round up only for the engine's millisecond interface. The outer
        // timeout_at still enforces the exact original absolute deadline.
        let millis = u64::try_from(remaining.as_nanos().div_ceil(1_000_000))
            .map_err(|_| error!("Validation dependency deadline exceeds millisecond range"))?;
        Ok(Some(millis))
    }
}

#[cfg(test)]
#[path = "tests/test_dependency_deadline.rs"]
mod tests;
