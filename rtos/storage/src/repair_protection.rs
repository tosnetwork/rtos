// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Logical dependency protection shared by registration and actual deletion.
//! No authority can be minted by this storage predicate.
use rtos_block::{error, BlockIdExt, Result};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
};
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock};

/// What one lease protects. Registered and released exactly once per lease
/// generation; the reference counts below are derived from these.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LeaseProtection {
    pub states: Vec<BlockIdExt>,
    pub artifacts: Vec<BlockIdExt>,
    pub digests: Vec<(BlockIdExt, String, rtos_block::UInt256)>,
}

#[derive(Default)]
struct Protected {
    states: HashMap<BlockIdExt, u32>,
    artifacts: HashMap<BlockIdExt, u32>,
    /// (id, kind) -> (committed digest, references).
    artifact_digests: HashMap<(BlockIdExt, String), (rtos_block::UInt256, u32)>,
    leases: BTreeMap<u64, LeaseProtection>,
    poisoned: bool,
}

fn add(count: &mut HashMap<BlockIdExt, u32>, id: &BlockIdExt) -> Option<()> {
    let slot = count.entry(id.clone()).or_insert(0);
    *slot = slot.checked_add(1)?;
    Some(())
}

fn sub(count: &mut HashMap<BlockIdExt, u32>, id: &BlockIdExt) -> Option<()> {
    let slot = count.get_mut(id)?;
    *slot = slot.checked_sub(1)?;
    if *slot == 0 {
        count.remove(id);
    }
    Some(())
}

pub struct RepairProtection {
    gate: Arc<RwLock<()>>,
    writes: Arc<RwLock<()>>,
    protected: Mutex<Protected>,
}
impl Default for RepairProtection {
    fn default() -> Self {
        Self {
            gate: Arc::new(RwLock::new(())),
            writes: Arc::new(RwLock::new(())),
            protected: Mutex::new(Protected::default()),
        }
    }
}
impl RepairProtection {
    /// Retained by the real authenticated operation, not its observer.
    pub async fn artifact_mutation(&self) -> OwnedRwLockReadGuard<()> {
        self.writes.clone().read_owned().await
    }
    /// Registration refuses a concurrent physical write instead of waiting
    /// while an async caller may own IO. The node keeps its original record.
    pub fn registration(&self) -> Result<OwnedRwLockWriteGuard<()>> {
        self.writes
            .clone()
            .try_write_owned()
            .map_err(|_| error!("Repair artifact registration busy"))
    }
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
    /// Registers what lease `generation` protects. The whole set is validated
    /// first (digests against existing commitments and within the set, and
    /// every count against overflow), then committed at once, so a refusal
    /// changes no count. Registering the same set again is a no-op; a
    /// different set for a registered generation is refused.
    pub fn register(&self, generation: u64, protection: LeaseProtection) -> Result<()> {
        let mut guard = self.protected.lock().map_err(|_| error!("Repair protection poisoned"))?;
        match guard.leases.get(&generation) {
            Some(existing) if existing == &protection => return Ok(()),
            Some(_) => return Err(error!("Repair lease {generation} protection changed")),
            None => {}
        }
        let mut within: HashMap<(BlockIdExt, String), &rtos_block::UInt256> = HashMap::new();
        for (id, kind, digest) in &protection.digests {
            let key = (id.clone(), kind.clone());
            let committed = guard.artifact_digests.get(&key).map(|(d, _)| d);
            let previous = within.insert(key, digest);
            if committed.is_some_and(|old| old != digest)
                || previous.is_some_and(|old| old != digest)
            {
                // A conflicting durable commitment requires cold recovery.
                guard.poisoned = true;
                return Err(error!("Conflicting durable artifact commitments"));
            }
        }
        let mut staged = Protected {
            states: HashMap::new(),
            artifacts: HashMap::new(),
            artifact_digests: HashMap::new(),
            leases: BTreeMap::new(),
            poisoned: false,
        };
        for id in &protection.states {
            let current = guard.states.get(id).copied().unwrap_or(0);
            let slot = staged.states.entry(id.clone()).or_insert(current);
            *slot =
                slot.checked_add(1).ok_or_else(|| error!("Repair protection count exhausted"))?;
        }
        for id in &protection.artifacts {
            let current = guard.artifacts.get(id).copied().unwrap_or(0);
            let slot = staged.artifacts.entry(id.clone()).or_insert(current);
            *slot =
                slot.checked_add(1).ok_or_else(|| error!("Repair protection count exhausted"))?;
        }
        for (id, kind, digest) in &protection.digests {
            let key = (id.clone(), kind.clone());
            let current = guard.artifact_digests.get(&key).map_or(0, |(_, n)| *n);
            let slot = staged.artifact_digests.entry(key).or_insert((digest.clone(), current));
            slot.1 =
                slot.1.checked_add(1).ok_or_else(|| error!("Repair protection count exhausted"))?;
        }
        guard.states.extend(staged.states);
        guard.artifacts.extend(staged.artifacts);
        guard.artifact_digests.extend(staged.artifact_digests);
        guard.leases.insert(generation, protection);
        Ok(())
    }
    /// Releases exactly what lease `generation` registered. False when it was
    /// not registered. A count that cannot be decremented is a broken
    /// invariant: protection is poisoned and stays total.
    pub fn unregister(&self, generation: u64) -> Result<bool> {
        let mut guard = self.protected.lock().map_err(|_| error!("Repair protection poisoned"))?;
        let Some(protection) = guard.leases.remove(&generation) else {
            return Ok(false);
        };
        let mut intact = true;
        for id in &protection.states {
            intact &= sub(&mut guard.states, id).is_some();
        }
        for id in &protection.artifacts {
            intact &= sub(&mut guard.artifacts, id).is_some();
        }
        for (id, kind, _) in &protection.digests {
            let key = (id.clone(), kind.clone());
            match guard.artifact_digests.get_mut(&key) {
                Some((_, count)) if *count > 1 => *count -= 1,
                Some(_) => {
                    guard.artifact_digests.remove(&key);
                }
                None => intact = false,
            }
        }
        if !intact {
            guard.poisoned = true;
            return Err(error!("Repair protection counts are inconsistent"));
        }
        Ok(true)
    }
    /// (state, artifact) reference counts of `id`; saturated when poisoned.
    pub fn references(&self, id: &BlockIdExt) -> (u32, u32) {
        self.protected
            .lock()
            .map(|g| {
                (g.states.get(id).copied().unwrap_or(0), g.artifacts.get(id).copied().unwrap_or(0))
            })
            .unwrap_or((u32::MAX, u32::MAX))
    }
    pub fn check_artifact_write(&self, id: &BlockIdExt, kind: &str, bytes: &[u8]) -> Result<()> {
        let guard = self.protected.lock().map_err(|_| error!("Repair protection poisoned"))?;
        if guard.poisoned {
            return Err(error!("Repair protection requires cold recovery"));
        }
        if let Some((expected, _)) = guard.artifact_digests.get(&(id.clone(), kind.to_owned())) {
            if expected != &rtos_block::UInt256::calc_file_hash(bytes) {
                return Err(error!("Artifact replacement conflicts with repair custody"));
            }
        }
        Ok(())
    }
    pub fn state(&self, id: &BlockIdExt) -> bool {
        self.protected.lock().map(|g| g.poisoned || g.states.contains_key(id)).unwrap_or(true)
    }
    pub fn artifact(&self, id: &BlockIdExt) -> bool {
        self.protected.lock().map(|g| g.poisoned || g.artifacts.contains_key(id)).unwrap_or(true)
    }
    /// Packages cover half-open MC ranges. Logical identities survive packing.
    pub fn archive_range(&self, start: u32, end: Option<u32>) -> bool {
        self.protected
            .lock()
            .map(|g| {
                g.poisoned
                    || g.artifacts
                        .keys()
                        .any(|id| id.seq_no() >= start && end.is_none_or(|e| id.seq_no() < e))
            })
            .unwrap_or(true)
    }
    pub fn artifact_position(&self, shard: &rtos_block::ShardIdent, seqno: u32) -> bool {
        self.protected
            .lock()
            .map(|g| {
                g.poisoned
                    || g.artifacts.keys().any(|id| id.shard() == shard && id.seq_no() == seqno)
            })
            .unwrap_or(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtos_block::{ShardIdent, UInt256};

    fn id(seq: u32) -> BlockIdExt {
        BlockIdExt::with_params(
            ShardIdent::masterchain(),
            seq,
            UInt256::from([seq as u8; 32]),
            UInt256::from([seq as u8 + 1; 32]),
        )
    }
    fn artifact(seq: u32, digest: u8) -> LeaseProtection {
        LeaseProtection {
            artifacts: vec![id(seq)],
            digests: vec![(id(seq), "proof".into(), UInt256::from([digest; 32]))],
            ..Default::default()
        }
    }

    #[test]
    fn protection_is_counted_per_lease_and_released_exactly() {
        let protection = RepairProtection::default();
        protection.register(1, artifact(7, 1)).unwrap();
        protection.register(2, artifact(7, 1)).unwrap();
        assert_eq!(protection.references(&id(7)), (0, 2));
        // A retry of the same generation registers nothing more.
        protection.register(1, artifact(7, 1)).unwrap();
        assert_eq!(protection.references(&id(7)), (0, 2));
        // A different set for a registered generation is refused.
        assert!(protection.register(1, artifact(8, 1)).is_err());
        assert!(protection.unregister(1).unwrap());
        assert!(protection.artifact(&id(7)), "the shared artifact stays protected");
        assert!(!protection.unregister(1).unwrap(), "a repeated release changes nothing");
        assert!(protection.unregister(2).unwrap());
        assert!(!protection.artifact(&id(7)));
        assert!(protection.check_artifact_write(&id(7), "proof", b"anything").is_ok());
    }

    #[test]
    fn a_conflict_on_a_later_dependency_changes_no_count() {
        let protection = RepairProtection::default();
        protection.register(1, artifact(9, 1)).unwrap();
        let mixed = LeaseProtection {
            states: vec![id(3)],
            artifacts: vec![id(4), id(9)],
            digests: vec![
                (id(4), "proof".into(), UInt256::from([2; 32])),
                (id(9), "proof".into(), UInt256::from([3; 32])),
            ],
        };
        assert!(protection.register(2, mixed).is_err());
        assert_eq!(protection.references(&id(3)), (0, 0));
        assert_eq!(protection.references(&id(4)), (0, 0));
        assert_eq!(protection.references(&id(9)), (0, 1));
        // A conflicting commitment still requires cold recovery.
        assert!(protection.state(&id(100)), "conflicting commitments poison the predicate");
    }

    #[test]
    fn an_inconsistent_release_poisons_protection() {
        let protection = RepairProtection::default();
        protection.register(1, artifact(5, 1)).unwrap();
        protection.protected.lock().unwrap().artifacts.clear();
        assert!(protection.unregister(1).is_err());
        assert!(protection.artifact(&id(200)), "poisoned protection protects everything");
    }
}
