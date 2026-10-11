// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Request-owned, cumulative admission for bounded Merkle work. Byte charges
//! describe requested Rust storage, not allocator metadata or process RSS.
use crate::{error, Cell, Result, UInt256};
use std::{
    hash::{BuildHasher, Hash, Hasher},
    mem::size_of,
};

pub trait MerkleApplyBudget: Send + Sync {
    fn step(&self) -> Result<()>;
    fn workspace(&self, bytes: usize) -> Result<()>;
    fn new_cell(&self, allocation_upper_bound: usize) -> Result<()>;
    fn max_depth(&self) -> u16;
}

#[derive(Clone, Copy, Debug)]
pub struct MerkleApplyLimits {
    pub max_entries: usize,
    pub max_depth: u16,
}

#[derive(Debug)]
pub struct MerkleApplyLimitExceeded(pub &'static str);
impl std::fmt::Display for MerkleApplyLimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Bounded Merkle work rejected: {}", self.0)
    }
}
impl std::error::Error for MerkleApplyLimitExceeded {}

pub fn require_materialized(cell: &Cell) -> Result<()> {
    if !cell.is_materialized_data_cell() {
        return Err(MerkleApplyLimitExceeded("cell has external storage or loader").into());
    }
    Ok(())
}

/// A cell has at most 128 data bytes, four 34-byte hashes/depths, four
/// references and an aligned refcount header. Includes builder scratch.
/// Workspace frames and containers are charged separately.
pub const NEW_CELL_ALLOCATION: usize = 1024;

/// Open addressing in explicitly allocated slots: no library hash table can
/// grow without budget admission. Rehash work and simultaneous old/new storage
/// are charged before growth. Tables never exceed a half-full load factor.
pub struct BudgetMap<V> {
    slots: Vec<Option<(UInt256, V)>>,
    len: usize,
    limit: usize,
    hasher: ahash::RandomState,
}
fn budget_hasher() -> ahash::RandomState {
    #[cfg(test)]
    {
        ahash::RandomState::with_seeds(0x52544f53, 1, 2, 3)
    }
    #[cfg(not(test))]
    {
        ahash::RandomState::new()
    }
}

impl<V> BudgetMap<V> {
    pub fn new(limit: usize) -> Self {
        Self { slots: Vec::new(), len: 0, limit, hasher: budget_hasher() }
    }
    pub fn len(&self) -> usize {
        self.len
    }
    fn start(&self, key: &UInt256, capacity: usize) -> usize {
        let mut hash = self.hasher.build_hasher();
        key.hash(&mut hash);
        hash.finish() as usize & (capacity - 1)
    }
    fn index(&self, key: &UInt256, budget: &dyn MerkleApplyBudget) -> Result<Option<usize>> {
        if self.slots.is_empty() {
            return Ok(None);
        }
        let mut index = self.start(key, self.slots.len());
        for _ in 0..self.slots.len() {
            budget.step()?;
            match &self.slots[index] {
                Some((stored, _)) if stored == key => return Ok(Some(index)),
                None => return Ok(None),
                _ => index = (index + 1) & (self.slots.len() - 1),
            }
        }
        Err(MerkleApplyLimitExceeded("hash table probe").into())
    }
    pub fn get(&self, key: &UInt256, budget: &dyn MerkleApplyBudget) -> Result<Option<&V>> {
        Ok(self.index(key, budget)?.map(|i| &self.slots[i].as_ref().unwrap().1))
    }
    pub fn get_mut(
        &mut self,
        key: &UInt256,
        budget: &dyn MerkleApplyBudget,
    ) -> Result<Option<&mut V>> {
        let index = self.index(key, budget)?;
        Ok(index.map(|i| &mut self.slots[i].as_mut().unwrap().1))
    }
    pub fn insert(
        &mut self,
        key: UInt256,
        value: V,
        budget: &dyn MerkleApplyBudget,
    ) -> Result<bool> {
        if let Some(index) = self.index(&key, budget)? {
            self.slots[index] = Some((key, value));
            return Ok(false);
        }
        if self.len >= self.limit {
            return Err(MerkleApplyLimitExceeded("table entries").into());
        }
        if self.len >= self.slots.len() / 2 {
            let capacity = self.slots.len().checked_mul(2).unwrap_or(0).max(8);
            if capacity <= self.slots.len() {
                return Err(MerkleApplyLimitExceeded("table capacity overflow").into());
            }
            let bytes = capacity
                .checked_mul(size_of::<Option<(UInt256, V)>>())
                .ok_or(MerkleApplyLimitExceeded("table bytes overflow"))?;
            budget.workspace(bytes)?;
            let mut slots = Vec::new();
            slots
                .try_reserve_exact(capacity)
                .map_err(|e| error!("Bounded table allocation: {e}"))?;
            slots.resize_with(capacity, || None);
            // Rehash into a replacement before releasing the old allocation.
            // Failure consumes this request and drops both bounded containers.
            for position in 0..self.slots.len() {
                budget.step()?;
                if let Some((key, value)) = self.slots[position].take() {
                    let mut index = self.start(&key, capacity);
                    while slots[index].is_some() {
                        budget.step()?;
                        index = (index + 1) & (capacity - 1);
                    }
                    slots[index] = Some((key, value));
                }
            }
            self.slots = slots;
        }
        let mut index = self.start(&key, self.slots.len());
        while self.slots[index].is_some() {
            budget.step()?;
            index = (index + 1) & (self.slots.len() - 1);
        }
        self.slots[index] = Some((key, value));
        self.len += 1;
        Ok(true)
    }
    pub fn iter(&self) -> impl Iterator<Item = (&UInt256, &V)> {
        self.slots.iter().filter_map(|slot| slot.as_ref().map(|(key, value)| (key, value)))
    }
}

pub struct BudgetStack<T> {
    values: Vec<T>,
    limit: usize,
}
impl<T> BudgetStack<T> {
    pub fn new(limit: usize) -> Self {
        Self { values: Vec::new(), limit }
    }
    pub fn push(&mut self, value: T, budget: &dyn MerkleApplyBudget) -> Result<()> {
        if self.values.len() >= self.limit {
            return Err(MerkleApplyLimitExceeded("traversal stack").into());
        }
        if self.values.len() == self.values.capacity() {
            let capacity =
                self.values.capacity().checked_mul(2).unwrap_or(0).max(4).min(self.limit);
            let bytes = capacity
                .checked_mul(size_of::<T>())
                .ok_or(MerkleApplyLimitExceeded("stack bytes overflow"))?;
            budget.workspace(bytes)?;
            self.values
                .try_reserve_exact(capacity - self.values.len())
                .map_err(|e| error!("Bounded stack allocation: {e}"))?;
        }
        self.values.push(value);
        Ok(())
    }
    pub fn pop(&mut self) -> Option<T> {
        self.values.pop()
    }
    pub fn last_mut(&mut self) -> Option<&mut T> {
        self.values.last_mut()
    }
}

#[cfg(test)]
#[path = "tests/test_bounded_merkle_apply.rs"]
mod tests;

#[cfg(test)]
thread_local! { static REVERSE_DFS_TEST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }

pub(crate) fn dfs_push_index(count: usize, position: usize) -> usize {
    #[cfg(test)]
    if REVERSE_DFS_TEST.with(std::cell::Cell::get) {
        return position;
    }
    count - 1 - position
}

#[cfg(test)]
pub(crate) fn with_reversed_dfs_for_test<T>(run: impl FnOnce() -> T) -> T {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            REVERSE_DFS_TEST.with(|flag| flag.set(self.0));
        }
    }
    let _restore = Restore(REVERSE_DFS_TEST.with(|flag| flag.replace(true)));
    run()
}
