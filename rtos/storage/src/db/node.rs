// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Physical node DB options independent of the state backend selected at startup.
use super::rocksdb::{AccessType, RocksDb, NODE_DB_NAME};
use crate::{dynamic_boc_rc_db::DynamicBocDb, shardstate_db_async::CellsDbConfig};
use rtos_block::Result;
use std::{collections::HashMap, path::Path, sync::Arc};

pub const CELLS_CF_NAME: &str = "cells_db_v6";
pub const CELLSCOUNTERS_CF_NAME: &str = "cells_db_v6_counters";

/// Restore options for existing dynamic CFs before replaying the WAL, even if
/// the caller uses archive state storage. A missing merge operator can make
/// point-in-time WAL recovery stop early while successfully opening the DB.
/// This does not create dynamic CFs in a fresh archive-only database.
pub fn open_node_db(
    root: impl AsRef<Path>,
    config: &CellsDbConfig,
    access: AccessType,
) -> Result<Arc<RocksDb>> {
    let path = root.as_ref().join(NODE_DB_NAME);
    // A listing failure on an existing DB must never silently remove the
    // counter merge operator. Only a missing or empty directory is a new DB.
    let families = if !path.try_exists()? || std::fs::read_dir(&path)?.next().is_none() {
        Vec::new()
    } else {
        rocksdb::DB::list_cf(&rocksdb::Options::default(), &path)?
    };
    let mut options = HashMap::new();
    let mut caches = Vec::new();
    if families.iter().any(|name| name == CELLS_CF_NAME) {
        let (opts, cache) = DynamicBocDb::build_cells_cf_options(config);
        options.insert(CELLS_CF_NAME.to_owned(), opts);
        caches.push(cache);
    }
    if families.iter().any(|name| name == CELLSCOUNTERS_CF_NAME) {
        let (opts, cache) = DynamicBocDb::build_counters_cf_options(config);
        options.insert(CELLSCOUNTERS_CF_NAME.to_owned(), opts);
        caches.push(cache);
    }
    let db = RocksDb::new(root, NODE_DB_NAME, options, access)?;
    for cache in caches {
        db.register_cache(cache);
    }
    Ok(db)
}
