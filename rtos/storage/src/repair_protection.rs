// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Logical dependency protection shared by registration and actual deletion.
//! No authority can be minted by this storage predicate.
use rtos_block::{error, BlockIdExt, Result};
use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock};

#[derive(Default)]
struct Protected {
    states: HashSet<BlockIdExt>,
    artifacts: HashSet<BlockIdExt>,
    poisoned: bool,
}
pub struct RepairProtection {
    gate: Arc<RwLock<()>>,
    protected: Mutex<Protected>,
}
impl Default for RepairProtection {
    fn default() -> Self {
        Self { gate: Arc::new(RwLock::new(())), protected: Mutex::new(Protected::default()) }
    }
}
impl RepairProtection {
    /// Retained by the real authenticated operation, not its observer.
    pub async fn authentication(&self) -> Result<OwnedRwLockReadGuard<()>> {
        let guard = self.gate.clone().read_owned().await;
        if self.protected.lock().map_err(|_| error!("Repair protection poisoned"))?.poisoned {
            return Err(error!("Repair protection requires cold recovery"));
        }
        Ok(guard)
    }
    pub async fn deletion(&self) -> OwnedRwLockWriteGuard<()> {
        self.gate.clone().write_owned().await
    }
    /// A synchronous GC worker must skip rather than wait behind authentication.
    pub fn try_deletion(&self) -> Option<OwnedRwLockWriteGuard<()>> {
        self.gate.clone().try_write_owned().ok()
    }
    pub fn poison(&self) {
        self.protected.lock().unwrap().poisoned = true;
    }
    pub fn protect(
        &self,
        states: impl IntoIterator<Item = BlockIdExt>,
        artifacts: impl IntoIterator<Item = BlockIdExt>,
    ) {
        let mut guard = self.protected.lock().unwrap();
        guard.states.extend(states);
        guard.artifacts.extend(artifacts);
    }
    pub fn state(&self, id: &BlockIdExt) -> bool {
        self.protected.lock().map(|g| g.poisoned || g.states.contains(id)).unwrap_or(true)
    }
    pub fn artifact(&self, id: &BlockIdExt) -> bool {
        self.protected.lock().map(|g| g.poisoned || g.artifacts.contains(id)).unwrap_or(true)
    }
    /// Packages cover half-open MC ranges. Logical identities survive packing.
    pub fn archive_range(&self, start: u32, end: Option<u32>) -> bool {
        self.protected
            .lock()
            .map(|g| {
                g.poisoned
                    || g.artifacts
                        .iter()
                        .any(|id| id.seq_no() >= start && end.is_none_or(|e| id.seq_no() < e))
            })
            .unwrap_or(true)
    }
    pub fn artifact_position(&self, shard: &rtos_block::ShardIdent, seqno: u32) -> bool {
        self.protected
            .lock()
            .map(|g| {
                g.poisoned
                    || g.artifacts.iter().any(|id| id.shard() == shard && id.seq_no() == seqno)
            })
            .unwrap_or(true)
    }
}
