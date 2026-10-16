// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Physical node DB options independent of the state backend selected at startup.
use super::rocksdb::{AccessType, RocksDb, NODE_DB_NAME};
use crate::{dynamic_boc_rc_db::DynamicBocDb, shardstate_db_async::CellsDbConfig};
use rtos_block::{error, fail, sha256_digest, Result};
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
    Ok(open_physical(root.as_ref(), config, access, false)?.0)
}

/// Holds the opened main provider while the caller validates and reconstructs
/// its durable dependency protection. No ordinary service may start before
/// finish succeeds; a pending root must first be reconciled by its worker.
pub struct NodeDbBootstrap {
    db: Arc<RocksDb>,
    pending: Option<crate::archives::recovery_root::RootHeader>,
    recovery_started: bool,
    recovery_complete: bool,
    providers: Option<crate::archives::recovery_providers::RecoveryProviders>,
}
impl NodeDbBootstrap {
    pub fn database(&self) -> &Arc<RocksDb> { &self.db }
    pub fn requires_recovery(&self) -> bool { self.pending.is_some() }
    /// Called after the node has loaded its existing durable protection. This
    /// inspects and retains all managed providers; it performs no root replay.
    pub async fn inspect_recovery_providers(
        &mut self, config: Option<&crate::archives::epoch::ArchivalModeConfig>,
        protection: &Arc<crate::repair_protection::RepairProtection>,
    ) -> Result<()> {
        let root = self.pending.as_ref().ok_or_else(|| error!("No pending node recovery"))?;
        if self.providers.is_some() { fail!("Recovery providers already inspected"); }
        let expected = root.encode()?;
        if self.db.db().get_pinned(crate::archives::recovery_root::ROOT_KEY)?.as_deref() != Some(expected.as_slice()) {
            fail!("Archive root changed during node bootstrap");
        }
        self.providers = Some(crate::archives::recovery_providers::RecoveryProviders::inspect(
            self.db.clone(), root, config, protection,
        ).await?);
        Ok(())
    }
    /// Existing durable protection must have been rebuilt before this call.
    pub async fn recover_pending(&mut self) -> Result<()> {
        if self.recovery_started { fail!("Bootstrap recovery already started; reopen after failure or cancellation"); }
        let root = self.pending.clone().ok_or_else(|| error!("No pending node recovery"))?;
        if root.state != crate::archives::recovery_root::State::Cleaned {
            fail!("Archive recovery state is not implemented yet: {:?}", root.state);
        }
        #[cfg(not(target_os = "linux"))]
        { fail!("Archive bootstrap recovery requires Linux"); }
        #[cfg(target_os = "linux")]
        {
            let providers = self.providers.take().ok_or_else(|| error!("Recovery providers have not been validated"))?;
            self.recovery_started = true;
            let protection = providers.protection.clone();
            let deletion = protection.deletion().await;
            let mutation = protection.artifact_mutation().await;
            tokio::task::spawn_blocking(move || {
                let _guards = (mutation, deletion);
                crate::archives::recovery_worker::recover_cleaned(providers, root)
            }).await.map_err(|e| error!("Native bootstrap recovery failed: {e}"))??;
            self.recovery_complete = true;
            self.pending = None;
            Ok(())
        }
    }
    pub fn finish(self) -> Result<Arc<RocksDb>> {
        if self.recovery_started && !self.recovery_complete {
            fail!("Bootstrap recovery has no successful completion receipt");
        }
        if self.pending.is_some() {
            crate::archives::recovery_guard::ensure_open_provider_clear(
                self.db.db(), self.db.db().path().parent().expect("node DB has a parent"),
            )?;
        }
        Ok(self.db)
    }
}

pub fn open_node_db_for_bootstrap(
    root: impl AsRef<Path>, config: &CellsDbConfig, access: AccessType,
) -> Result<NodeDbBootstrap> {
    use crate::archives::recovery_root::{FactoryMode, RootHeader, ROOT_KEY, PARTICIPANT_KEY};
    let writable = access == AccessType::ReadWrite;
    let (mut db, deferred_cleanup) = open_physical(root.as_ref(), config, access, true)?;
    let pending = db.db().get_pinned(ROOT_KEY)?.map(|bytes| RootHeader::decode(&bytes)).transpose()?;
    if let Some(header) = &pending {
        if !writable { fail!("Pending archive root requires writable recovery bootstrap"); }
        Arc::get_mut(&mut db).ok_or_else(|| error!("Main bootstrap provider shared before root inspection"))?
            .require_strict_recovery_path()?;
        header.policy.check_environment(FactoryMode::Node, db.db().cf_handle("repair_dependency_leases_v1").is_some())?;
        let identity = db.db().get_db_identity()?;
        if header.database_identity_bytes != identity.len() as u64
            || header.database_identity_digest != sha256_digest(&identity) {
            fail!("Archive root belongs to another native main database");
        }
    } else {
        if db.db().get_pinned(PARTICIPANT_KEY)?.is_some() {
            fail!("Orphan archive recovery participant on main database");
        }
        crate::archives::recovery_guard::ensure_root_controls_clear(db.db())?;
        if deferred_cleanup { db.finish_ordinary_bootstrap()?; }
    }
    Ok(NodeDbBootstrap { db, pending, providers: None, recovery_started: false, recovery_complete: false })
}

fn open_physical(
    root: &Path, config: &CellsDbConfig, access: AccessType, bootstrap: bool,
) -> Result<(Arc<RocksDb>, bool)> {
    let path = root.join(NODE_DB_NAME);
    let existing = path.try_exists()? && std::fs::read_dir(&path)?.next().is_some();
    // Acquire the existing-only owner before CF inspection, so option selection
    // and native opening share the same managed provider reservation.
    let owner = if bootstrap && existing && access == AccessType::ReadWrite {
        Some(super::provider_reservation::ProviderReservation::inspect_existing(&path)?)
    } else { None };
    let families = if existing {
        rocksdb::DB::list_cf(&rocksdb::Options::default(), &path)?
    } else { Vec::new() };
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
    let deferred_cleanup = owner.is_some();
    let db = if let Some(owner) = owner {
        RocksDb::open_existing_for_bootstrap(owner, options)?
    } else { RocksDb::new(root, NODE_DB_NAME, options, access)? };
    for cache in caches { db.register_cache(cache); }
    Ok((db, deferred_cleanup))
}

#[cfg(test)]
#[path = "../tests/test_node_bootstrap.rs"]
mod tests;
