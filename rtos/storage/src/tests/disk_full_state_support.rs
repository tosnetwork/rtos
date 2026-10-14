// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Shared fixtures for real state-store WAL ENOSPC; no blockchain authentication.
use crate::{
    db::{
        node::{CELLSCOUNTERS_CF_NAME, CELLS_CF_NAME},
        rocksdb::RocksDb,
    },
    shardstate_db_async::{CellsDbConfig, DbEntry},
    traits::Serializable,
    types::serialize_stored_cell,
};
use rtos_block::{
    error, fail,
    merkle_apply_budget::{MerkleApplyBudget, MerkleApplyLimits},
    BlockIdExt, BuilderData, Cell, Result, ShardIdent, UInt256,
};
use std::{
    io::Write,
    ops::Deref,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

pub const LIMITS: MerkleApplyLimits = MerkleApplyLimits { max_entries: 64, max_depth: 128 };
pub struct Budget(AtomicUsize);
impl Budget {
    pub fn new() -> Arc<Self> {
        Arc::new(Self(AtomicUsize::new(0)))
    }
}
impl MerkleApplyBudget for Budget {
    fn step(&self) -> Result<()> {
        Ok(())
    }
    fn workspace(&self, bytes: usize) -> Result<()> {
        self.0
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |old| {
                old.checked_add(bytes).filter(|next| *next <= 1 << 20)
            })
            .map_err(|_| error!("state ENOSPC fixture workspace exhausted"))?;
        Ok(())
    }
    fn new_cell(&self, _: usize) -> Result<()> {
        fail!("writer must use materialized cells")
    }
    fn max_depth(&self) -> u16 {
        128
    }
}
pub fn config() -> CellsDbConfig {
    let mut config = CellsDbConfig::default();
    config.cells_lru_cache_capacity = 64;
    config.counters_lru_cache_capacity = 64;
    config.cells_cache_size_bytes = 1 << 20;
    config.counters_cache_size_bytes = 1 << 20;
    config
}
pub fn child() -> Cell {
    BuilderData::with_raw(vec![7], 8).unwrap().into_cell().unwrap()
}
pub fn graph(seq: u8) -> (BlockIdExt, Cell) {
    let mut builder = BuilderData::with_raw(vec![7 + seq], 8).unwrap();
    builder.checked_append_reference(child()).unwrap();
    builder.checked_append_reference(child()).unwrap();
    let root = builder.into_cell().unwrap();
    let id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        u32::from(seq),
        root.repr_hash().clone(),
        UInt256::from([seq; 32]),
    );
    (id, root)
}
pub fn root(case: &str) -> PathBuf {
    PathBuf::from(std::env::var_os("RTOS_ENOSPC_ROOT").expect("run inside tmpfs harness"))
        .join(case)
}
pub fn control() -> bool {
    std::env::var("RTOS_ENOSPC_CONTROL").as_deref() == Ok("1")
}
pub fn fill(path: &Path) -> PathBuf {
    let filler = path.join("enospc-filler");
    let mut file = std::fs::File::create(&filler).unwrap();
    for size in [65536, 4096] {
        loop {
            match file.write_all(&vec![0; size]) {
                Ok(()) => (),
                Err(error) => {
                    assert_eq!(error.raw_os_error(), Some(28));
                    break;
                }
            }
        }
    }
    filler
}
pub fn flush(db: &Arc<RocksDb>) {
    let raw = db.as_ref().deref();
    for name in rocksdb::DB::list_cf(&rocksdb::Options::default(), db.path()).unwrap() {
        if name == "default" {
            raw.flush().unwrap();
        } else {
            raw.flush_cf(&raw.cf_handle(&name).expect("named state CF must be open")).unwrap();
        }
    }
    db.sync_wal().unwrap();
}
pub fn raw_cell(db: &Arc<RocksDb>, cell: &Cell) -> Option<Vec<u8>> {
    db.clone()
        .table::<UInt256>(CELLS_CF_NAME, false)
        .unwrap()
        .try_get_raw(cell.repr_hash().as_slice())
        .unwrap()
        .map(|raw| raw.to_vec())
}
pub fn check_cell(db: &Arc<RocksDb>, cell: &Cell) {
    assert_eq!(
        raw_cell(db, cell),
        Some(serialize_stored_cell(cell).unwrap().to_vec()),
        "raw cell bytes must match materialized graph"
    );
}
pub fn check_counts(db: &Arc<RocksDb>, present: &[bool; 3]) {
    let table = db.clone().table::<UInt256>(CELLSCOUNTERS_CF_NAME, false).unwrap();
    let read = |cell: &Cell| {
        table
            .try_get_raw(cell.repr_hash().as_slice())
            .unwrap()
            .map(|bytes| u32::from_le_bytes(bytes.as_ref().try_into().unwrap()))
    };
    for (index, exists) in present.iter().enumerate() {
        assert_eq!(
            read(&graph(index as u8 + 1).1),
            if *exists { Some(1) } else { None },
            "root reference multiplicity"
        );
    }
    assert_eq!(
        read(&child()),
        Some(2 * present.iter().filter(|exists| **exists).count() as u32),
        "shared child reference multiplicity"
    );
}
pub fn check_index(raw: &[u8], id: &BlockIdExt, cell: &Cell) {
    assert_eq!(raw.len(), DbEntry::SIZE, "partial state index");
    let entry = DbEntry::deserialize(raw).unwrap();
    assert_eq!(&entry.block_id, id, "state index identity");
    assert_eq!(&entry.cell_id, cell.repr_hash(), "state index root");
}
pub fn check_enospc(error: &anyhow::Error) {
    let message = format!("{error:#}");
    assert!(message.contains("No space left") || message.contains("ENOSPC"), "{message}");
}
