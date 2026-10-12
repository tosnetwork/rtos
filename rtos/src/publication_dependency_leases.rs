// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Persistent protection is monotone. Disk records are untrusted recovery data,
//! never durable custody capabilities. No retirement transition is implemented.
use crate::{
    repair_lease_binding::RepairLeaseBinding,
    repair_provenance::{Dependency, MAX_DEPENDENCIES},
};
use rtos_block::{error, fail, BlockIdExt, Result, UInt256};
use serde_derive::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use storage::{
    db::rocksdb::{RocksDb, RocksDbTable},
    repair_protection::RepairProtection,
};

const CF: &str = "repair_dependency_leases_v1";
const MAX_LEASES: usize = 8192;
const MAX_RECORD_BYTES: usize = 256 << 10;
const MAX_TOTAL_BYTES: usize = 64 << 20;
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum LeaseState {
    Protecting,
    DurableCustody,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LeaseRecord {
    schema: u32,
    pub generation: u64,
    pub binding: Vec<u8>,
    pub dependencies: Vec<Dependency>,
    pub dependency_digest: String,
    pub state: LeaseState,
}
#[derive(Default)]
struct Memory {
    next: u64,
    bytes: usize,
    records: BTreeMap<u64, LeaseRecord>,
    identities: BTreeMap<(u64, u64), u64>,
    poisoned: bool,
}
pub(crate) struct DependencyLeases {
    table: RocksDbTable<String>,
    protection: Arc<RepairProtection>,
    memory: Mutex<Memory>,
    #[cfg(test)]
    observer: Mutex<storage::durability::SyncObservation>,
    #[cfg(test)]
    commit_hook: Mutex<Option<Arc<dyn Fn(&LeaseRecord) + Send + Sync>>>,
}
impl LeaseRecord {
    #[cfg(test)]
    pub(crate) fn for_test(
        generation: u64,
        binding: &RepairLeaseBinding,
        dependency_digest: &UInt256,
    ) -> Result<Self> {
        Ok(Self {
            schema: 1,
            generation,
            binding: binding.encode()?,
            dependencies: Vec::new(),
            dependency_digest: format!("{dependency_digest:x}"),
            state: LeaseState::DurableCustody,
        })
    }
    pub(crate) fn binding(&self) -> Result<RepairLeaseBinding> {
        RepairLeaseBinding::decode(&self.binding)
    }
    fn validate(&self) -> Result<()> {
        if self.schema != 1
            || self.generation == 0
            || self.dependencies.is_empty()
            || self.dependencies.len() > MAX_DEPENDENCIES
        {
            fail!("Invalid repair ledger record");
        }
        self.binding()?;
        for dep in &self.dependencies {
            dep.validate()?;
        }
        if self.dependencies.windows(2).any(|pair| {
            pair[0] >= pair[1] || (pair[0].kind == pair[1].kind && pair[0].id == pair[1].id)
        }) {
            fail!("Repair dependencies must be unique and ordered");
        }
        if self.dependency_digest != format!("{:x}", dependency_digest(&self.dependencies)?) {
            fail!("Repair dependency digest mismatch");
        }
        Ok(())
    }
    fn protect(&self, protection: &RepairProtection) -> Result<()> {
        let mut states = Vec::new();
        let mut artifacts = Vec::new();
        for d in &self.dependencies {
            let id = d.validate()?;
            match d.kind.as_str() {
                "state" | "capsule-state" => states.push(id),
                _ => {
                    protection.protect_artifact_digest(id.clone(), &d.kind, d.digest.parse()?)?;
                    artifacts.push(id);
                }
            }
        }
        protection.protect(states, artifacts);
        Ok(())
    }
}
pub(crate) fn dependency_digest(dependencies: &[Dependency]) -> Result<UInt256> {
    if dependencies.len() > MAX_DEPENDENCIES {
        fail!("Repair dependency count");
    }
    Ok(UInt256::calc_file_hash(&serde_json::to_vec(dependencies)?))
}
impl DependencyLeases {
    /// Called before opening archive slices or starting any state/archival GC.
    pub(crate) fn open(db: Arc<RocksDb>, can_create: bool) -> Result<Arc<Self>> {
        let protection = db.repair_protection().clone();
        let outcome = (|| {
            let table = db.table::<String>(CF, can_create)?;
            let mut memory = Memory::default();
            table.for_each(&mut |key, raw| {
                if key == b"next" {
                    if raw.len() != 8 {
                        fail!("Repair ledger generation length");
                    }
                    memory.next = u64::from_le_bytes(raw[..].try_into().unwrap());
                    return Ok(true);
                }
                if raw.len() > MAX_RECORD_BYTES || memory.records.len() >= MAX_LEASES {
                    fail!("Repair ledger capacity exceeded");
                }
                memory.bytes = memory
                    .bytes
                    .checked_add(raw.len())
                    .ok_or_else(|| error!("Repair ledger size overflow"))?;
                if memory.bytes > MAX_TOTAL_BYTES {
                    fail!("Repair ledger byte capacity exceeded");
                }
                let record: LeaseRecord = serde_json::from_slice(raw)?;
                record.validate()?;
                if key != format!("lease/{:020}", record.generation).as_bytes()
                    || memory.records.insert(record.generation, record).is_some()
                {
                    fail!("Repair ledger key/generation mismatch");
                }
                Ok(true)
            })?;
            if memory.records.keys().next_back().is_some_and(|last| *last > memory.next) {
                fail!("Repair ledger generation regressed");
            }
            let mut domain = None;
            for record in memory.records.values() {
                let b = record.binding()?;
                if memory
                    .identities
                    .insert((b.record_id, b.close_generation), record.generation)
                    .is_some()
                {
                    fail!("Duplicate repair event generation");
                }
                let coordinates = (b.domain.zerostate, b.domain.global_id, b.domain.history_init);
                if domain.as_ref().is_some_and(|d| d != &coordinates) {
                    fail!("Mixed repair ledger domain");
                }
                domain = Some(coordinates);
                record.protect(&protection)?;
            }
            Ok(Arc::new(Self {
                table,
                protection: protection.clone(),
                memory: Mutex::new(memory),
                #[cfg(test)]
                observer: Mutex::new(None),
                #[cfg(test)]
                commit_hook: Mutex::new(None),
            }))
        })();
        if outcome.is_err() {
            protection.poison();
        }
        outcome
    }
    pub(crate) fn poison(&self) {
        self.memory.lock().unwrap().poisoned = true;
        self.protection.poison();
    }
    pub(crate) fn protection(&self) -> &Arc<RepairProtection> {
        &self.protection
    }
    pub(crate) fn verify_domain(&self, zero: &BlockIdExt, init: &BlockIdExt) -> Result<()> {
        let memory = self.memory.lock().map_err(|_| error!("Repair ledger poisoned"))?;
        for record in memory.records.values() {
            let binding = record.binding()?;
            if &binding.domain.zerostate != zero || &binding.domain.history_init != init {
                self.protection.poison();
                fail!("Repair ledger belongs to another Engine domain");
            }
        }
        Ok(())
    }
    /// Every lease record, read under the ledger lock, for a cleanup
    /// projection.
    pub(crate) fn records_snapshot(&self) -> Result<Vec<LeaseRecord>> {
        let memory = self.memory.lock().map_err(|_| error!("Repair ledger poisoned"))?;
        if memory.poisoned {
            fail!("Repair ledger requires cold recovery");
        }
        Ok(memory.records.values().cloned().collect())
    }

    pub(crate) fn lookup(
        &self,
        generation: u64,
        budget: &crate::history_read_budget::HistoryReadBudget,
    ) -> Result<LeaseRecord> {
        use storage::bounded_cell::CellReadBudget;
        budget.metadata(MAX_RECORD_BYTES)?;
        let memory = self.memory.lock().map_err(|_| error!("Repair ledger poisoned"))?;
        if memory.poisoned {
            fail!("Repair ledger requires cold recovery");
        }
        memory.records.get(&generation).cloned().ok_or_else(|| error!("Unknown repair lease"))
    }
    /// Instance-local observation after the actual WAL sync has succeeded.
    /// Production constructors and persistence semantics are unchanged.
    #[cfg(test)]
    pub(crate) fn set_commit_hook(&self, hook: Arc<dyn Fn(&LeaseRecord) + Send + Sync>) {
        *self.commit_hook.lock().unwrap() = Some(hook);
    }
    pub(crate) fn begin(
        &self,
        binding: &RepairLeaseBinding,
        dependencies: Vec<Dependency>,
        budget: &crate::history_read_budget::HistoryReadBudget,
    ) -> Result<u64> {
        use storage::bounded_cell::CellReadBudget;
        budget.metadata(MAX_RECORD_BYTES)?;
        let mut memory = self.memory.lock().map_err(|_| error!("Repair ledger poisoned"))?;
        if memory.poisoned {
            fail!("Repair ledger requires cold recovery");
        }
        let encoded = binding.encode()?;
        if let Some(generation) =
            memory.identities.get(&(binding.record_id, binding.close_generation))
        {
            let record = memory
                .records
                .get(generation)
                .ok_or_else(|| error!("Repair lease index corrupt"))?;
            if record.binding != encoded || record.dependencies != dependencies {
                fail!("Conflicting repair lease generation");
            }
            return Ok(*generation);
        }
        if memory.records.len() >= MAX_LEASES {
            fail!("Repair lease history capacity exhausted");
        }
        let generation =
            memory.next.checked_add(1).ok_or_else(|| error!("Repair generation exhausted"))?;
        let record = LeaseRecord {
            schema: 1,
            generation,
            binding: encoded,
            dependency_digest: format!("{:x}", dependency_digest(&dependencies)?),
            dependencies,
            state: LeaseState::Protecting,
        };
        record.validate()?;
        self.commit(&mut memory, record)?;
        Ok(generation)
    }
    pub(crate) fn durable(
        &self,
        generation: u64,
        budget: &crate::history_read_budget::HistoryReadBudget,
    ) -> Result<LeaseRecord> {
        use storage::bounded_cell::CellReadBudget;
        budget.metadata(MAX_RECORD_BYTES)?;
        let mut memory = self.memory.lock().map_err(|_| error!("Repair ledger poisoned"))?;
        if memory.poisoned {
            fail!("Repair ledger requires cold recovery");
        }
        let mut record = memory
            .records
            .get(&generation)
            .cloned()
            .ok_or_else(|| error!("Unknown repair lease"))?;
        record.state = LeaseState::DurableCustody;
        self.commit(&mut memory, record.clone())?;
        Ok(record)
    }
    fn commit(&self, memory: &mut Memory, record: LeaseRecord) -> Result<()> {
        let bytes = serde_json::to_vec(&record)?;
        if bytes.len() > MAX_RECORD_BYTES {
            fail!("Repair lease record too large");
        }
        let previous = memory
            .records
            .get(&record.generation)
            .map(serde_json::to_vec)
            .transpose()?
            .map_or(0, |b| b.len());
        let total = memory.bytes - previous + bytes.len();
        if total > MAX_TOTAL_BYTES {
            fail!("Repair lease capacity exhausted");
        }
        // Authentication owns the shared read gate. Protection is installed
        // before the first write, so an uncertain write can only overprotect.
        let _registration = self.protection.registration()?;
        record.protect(&self.protection)?;
        let next = memory.next.max(record.generation);
        let result = (|| {
            let mut batch = self.table.begin_transaction()?;
            batch.put_raw(format!("lease/{:020}", record.generation).as_bytes(), &bytes)?;
            batch.put_raw(b"next", &next.to_le_bytes())?;
            batch.commit()?;
            #[cfg(test)]
            let observer = self.observer.lock().unwrap().clone();
            #[cfg(not(test))]
            let observer: storage::durability::SyncObservation = None;
            self.table.sync_wal_observed(observer.as_deref())
        })();
        if let Err(e) = result {
            memory.poisoned = true;
            self.protection.poison();
            return Err(e);
        }
        #[cfg(test)]
        if let Some(hook) = self.commit_hook.lock().unwrap().clone() {
            hook(&record);
        }
        memory.next = next;
        memory.bytes = total;
        let binding = record.binding()?;
        memory.identities.insert((binding.record_id, binding.close_generation), record.generation);
        memory.records.insert(record.generation, record);
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/test_persistent_repair_ledger.rs"]
mod tests;
