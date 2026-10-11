// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Cumulative configuration derivation admission. Charges requested storage,
//! not allocator metadata/RSS. Shared dictionary paths are charged on every visit.
use crate::{error, Result};
use std::mem::size_of;
pub trait ConfigReadBudget: Send + Sync {
    fn step(&self) -> Result<()>;
    fn workspace(&self, bytes: usize) -> Result<()>;
}
pub fn steps(budget: &dyn ConfigReadBudget, count: usize) -> Result<()> {
    for _ in 0..count {
        budget.step()?;
    }
    Ok(())
}
pub fn vector<T>(budget: &dyn ConfigReadBudget, count: usize) -> Result<Vec<T>> {
    budget.workspace(
        count.checked_mul(size_of::<T>()).ok_or_else(|| error!("Config size overflow"))?,
    )?;
    let mut result = Vec::new();
    result.try_reserve_exact(count)?;
    Ok(result)
}
/// A fixed-width hashmap lookup visits at most bits+1 edges. Keys, slices and
/// builders are inline (up to 128 bytes); there is no allocated path stack.
/// LabelReader's same-bit label allocates len/8+1 scratch bytes before rejecting
/// an invalid encoded len. Charge the entire encoded integer range, not just
/// valid lengths, on each potential edge. No shared-cell deduplication.
pub fn lookup(budget: &dyn ConfigReadBudget, bits: usize) -> Result<()> {
    steps(budget, bits + 1)?;
    let encoded_max = bits
        .checked_add(1)
        .and_then(usize::checked_next_power_of_two)
        .and_then(|n| n.checked_sub(1))
        .ok_or_else(|| error!("Config path overflow"))?;
    budget.workspace(
        (bits + 1)
            .checked_mul(encoded_max / 8 + 1)
            .ok_or_else(|| error!("Config path overflow"))?,
    )
}
