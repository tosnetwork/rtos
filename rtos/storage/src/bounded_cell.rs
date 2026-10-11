// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Per-request admission before cell decoding. Native RocksDB block-cache IO is
//! shared infrastructure; these limits bound Rust graph materialization.
use rtos_block::{Cell, Result, UInt256};

pub trait CellReadBudget: Send + Sync {
    /// Includes raw scratch, final cell, hash maps and traversal entries.
    fn admit_cell(&self, hash: &UInt256, allocation_bytes: usize, depth: usize) -> Result<()>;
    fn complete_cell(&self, cell: &Cell) -> Result<()>;
    fn step(&self) -> Result<()>;
    fn metadata(&self, bytes: usize) -> Result<()>;
    fn max_depth(&self) -> u16;
}
// Conservative fixed upper bound for two standard representations, both hash
// maps and <=4 traversal edges. Ordinary cells have at most 1023 bits/4 refs.
pub const CELL_READ_ALLOCATION: usize = 4096;

#[derive(Debug)]
pub struct InvalidBoundedState(pub &'static str);
impl std::fmt::Display for InvalidBoundedState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid bounded state: {}", self.0)
    }
}
impl std::error::Error for InvalidBoundedState {}
