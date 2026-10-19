/*
 * RTOS project modifications (2026-10-10): project and crate naming.
 * Copyright (C) 2019-2024 EverX. All Rights Reserved.
 * Modifications Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This file has been modified from its original version.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::engine_traits::EngineOperations;
use adnl::common::add_unbound_object_to_map_with_update;
use rtos_block::{fail, BlockIdExt, Result, ShardIdent};
use std::{
    collections::{HashMap, HashSet},
    sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
};
use storage::shardstate_db_async::AllowStateGcResolver;

pub struct AllowStateGcSmartResolver {
    last_processed_block: AtomicU32,
    min_ref_mc_block: AtomicU32,
    min_actual_ss: lockfree::map::Map<ShardIdent, AtomicU32>,
    life_time_sec: u64,
    repair_protection: Option<std::sync::Arc<storage::repair_protection::RepairProtection>>,
    pinned_roots: parking_lot::RwLock<HashMap<BlockIdExt, u32>>,
    // When set, deletion decisions use `committed` only: the progress staged
    // before a barrier that made its prerequisite pointer writes durable.
    durable_gate: AtomicBool,
    next_ticket: AtomicU64,
    staged: parking_lot::Mutex<Option<(u64, GcProgress)>>,
    committed: parking_lot::RwLock<GcProgress>,
    #[cfg(test)]
    test_expired: std::sync::atomic::AtomicBool,
}

/// GC boundaries derived from masterchain progress.
#[derive(Clone, Debug, Default, PartialEq)]
struct GcProgress {
    min_ref_mc_block: u32,
    min_actual_ss: HashMap<ShardIdent, u32>,
}

impl AllowStateGcSmartResolver {
    /// Moves the masterchain boundary as if that progress had been committed
    /// after a durability barrier.
    #[cfg(test)]
    pub(crate) fn test_advance_expired_mc_boundary(&self, min: u32) {
        self.test_advance_live_mc_boundary(min);
        self.committed.write().min_ref_mc_block = min;
    }

    /// Moves only the live boundary; a gated resolver ignores it until a GC
    /// cycle commits it.
    #[cfg(test)]
    pub(crate) fn test_advance_live_mc_boundary(&self, min: u32) {
        self.min_ref_mc_block.store(min, Ordering::Release);
        self.test_expired.store(true, Ordering::Release);
    }

    pub fn new(life_time_sec: u64) -> Self {
        Self {
            last_processed_block: AtomicU32::new(0),
            min_ref_mc_block: AtomicU32::new(0),
            min_actual_ss: lockfree::map::Map::new(),
            life_time_sec,
            repair_protection: None,
            pinned_roots: parking_lot::RwLock::new(HashMap::new()),
            durable_gate: AtomicBool::new(false),
            next_ticket: AtomicU64::new(0),
            staged: parking_lot::Mutex::new(None),
            committed: parking_lot::RwLock::new(GcProgress::default()),
            #[cfg(test)]
            test_expired: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn live_progress(&self) -> GcProgress {
        GcProgress {
            min_ref_mc_block: self.min_ref_mc_block.load(Ordering::Acquire),
            min_actual_ss: self
                .min_actual_ss
                .iter()
                .map(|kv| (kv.key().clone(), kv.val().load(Ordering::Acquire)))
                .collect(),
        }
    }

    pub(crate) fn with_repair_protection(
        life_time_sec: u64,
        protection: std::sync::Arc<storage::repair_protection::RepairProtection>,
    ) -> Self {
        let mut resolver = Self::new(life_time_sec);
        resolver.repair_protection = Some(protection);
        resolver
    }

    pub async fn advance(
        &self,
        mc_block_id: &BlockIdExt,
        engine: &dyn EngineOperations,
    ) -> Result<bool> {
        let seqno = mc_block_id.seq_no();
        if seqno <= self.last_processed_block.fetch_max(seqno, Ordering::Relaxed) {
            return Ok(false);
        }

        let mc_state = engine.load_state(mc_block_id).await?;
        let new_min_ref_mc_seqno = mc_state.state()?.min_ref_mc_seqno();
        let old_min_ref_mc_seqno =
            self.min_ref_mc_block.fetch_max(new_min_ref_mc_seqno, Ordering::Relaxed);

        log::trace!(
            "AllowStateGcSmartResolver::advance:  new_min_ref_mc_seqno {}  old_min_ref_mc_seqno {}",
            new_min_ref_mc_seqno,
            old_min_ref_mc_seqno,
        );

        if new_min_ref_mc_seqno > old_min_ref_mc_seqno {
            log::debug!(
                "AllowStateGcSmartResolver::advance: updated min_ref_mc_block {} -> {}, mc_block_id: {}",
                old_min_ref_mc_seqno, new_min_ref_mc_seqno, mc_block_id,
            );

            let min_mc_state =
                engine.load_state(&mc_state.find_block_id(new_min_ref_mc_seqno)?).await?;
            let top_blocks = min_mc_state.shard_hashes()?.top_blocks_all()?;
            let mut actual_shardes = HashSet::new();
            for id in top_blocks {
                add_unbound_object_to_map_with_update(
                    &self.min_actual_ss,
                    id.shard().clone(),
                    |found| {
                        if let Some(a) = found {
                            let old_val = a.fetch_max(id.seq_no(), Ordering::Relaxed);
                            if old_val != id.seq_no() {
                                log::debug!(
                                "AllowStateGcSmartResolver::advance: updated min actual state for shard {}: {} -> {}",
                                id.shard(), old_val, id.seq_no()
                            );
                            }
                            Ok(None)
                        } else {
                            log::debug!(
                            "AllowStateGcSmartResolver::advance: added min actual state for shard {}: {}",
                            id.shard(), id.seq_no()
                        );
                            Ok(Some(AtomicU32::new(id.seq_no())))
                        }
                    },
                )?;
                actual_shardes.insert(id.shard().clone());
            }

            for kv in self.min_actual_ss.iter() {
                if !actual_shardes.contains(kv.key()) {
                    self.min_actual_ss.remove(kv.key());
                    log::debug!("AllowStateGcSmartResolver::advance: removed shard {}", kv.key());
                }
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn pin_state(&self, block_id: &BlockIdExt, saved_at: u64, gc_utime: u64) -> Result<bool> {
        let mut pinned_roots = self.pinned_roots.write();
        // Transfer an existing live pin (including a repair reservation) without
        // manufacturing a new GC exemption after eligibility has advanced.
        if let Some(count) = pinned_roots.get_mut(block_id) {
            *count =
                count.checked_add(1).ok_or_else(|| rtos_block::error!("State pin overflow"))?;
            return Ok(true);
        }
        let allow = AllowStateGcSmartResolver::allow_state_gc(self, block_id, saved_at, gc_utime)?;
        if allow {
            return Ok(false);
        }
        pinned_roots
            .entry(block_id.clone())
            .and_modify(|e| {
                log::trace!(
                    "AllowStateGcSmartResolver::pin_state: increment pin counter for {}",
                    block_id
                );
                *e += 1;
            })
            .or_insert_with(|| {
                log::trace!("AllowStateGcSmartResolver::pin_state: pinned {}", block_id);
                1
            });
        Ok(true)
    }

    /// Private repair reservation after authenticated candidate construction.
    /// Caller holds the storage write/GC gate and has proved index absence.
    pub(crate) fn reserve_absent_repair_state(&self, id: &BlockIdExt) -> Result<()> {
        let mut pins = self.pinned_roots.write();
        let count = pins.entry(id.clone()).or_insert(0);
        *count = count.checked_add(1).ok_or_else(|| rtos_block::error!("Repair pin overflow"))?;
        Ok(())
    }

    pub fn add_pin_for_state(&self, block_id: &BlockIdExt) -> Result<()> {
        if let Some(counter) = self.pinned_roots.write().get_mut(block_id) {
            *counter += 1;
            log::trace!("AllowStateGcSmartResolver::pin_state: added pin for {}", block_id);
        } else {
            fail!("Can't add pin for state {block_id} - it is not pinned");
        }
        Ok(())
    }

    pub fn unpin_state(&self, block_id: &BlockIdExt) -> Result<()> {
        let mut pinned_roots = self.pinned_roots.write();
        let counter = if let Some(counter) = pinned_roots.get_mut(block_id) {
            *counter -= 1;
            *counter
        } else {
            fail!("Can't unpin state - it is not pinned");
        };
        if counter == 0 {
            pinned_roots.remove(block_id);
            log::trace!("AllowStateGcSmartResolver::unpin_state: unpinned {}", block_id);
        } else {
            log::trace!(
                "AllowStateGcSmartResolver::unpin_state: decrement pin counter for {}",
                block_id
            );
        }
        Ok(())
    }

    fn allow_state_gc(&self, block_id: &BlockIdExt, saved_at: u64, gc_utime: u64) -> Result<bool> {
        if self.repair_protection.as_ref().is_some_and(|p| p.state(block_id)) {
            return Ok(false);
        }
        let recent = gc_utime > saved_at && gc_utime - saved_at < self.life_time_sec;
        #[cfg(test)]
        let recent = recent && !self.test_expired.load(Ordering::Acquire);
        if recent {
            return Ok(false);
        }
        if self.durable_gate.load(Ordering::Acquire) {
            return Ok(Self::progress_allows(&self.committed.read(), block_id));
        }
        Ok(Self::progress_allows(&self.live_progress(), block_id))
    }

    fn progress_allows(progress: &GcProgress, block_id: &BlockIdExt) -> bool {
        if block_id.shard().is_masterchain() {
            // The zerostate is always needed.
            return block_id.seq_no() != 0 && block_id.seq_no() < progress.min_ref_mc_block;
        }
        if let Some(min_actual) = progress.min_actual_ss.get(block_id.shard()) {
            return block_id.seq_no() < *min_actual;
        }
        for (shard, min_actual) in &progress.min_actual_ss {
            if block_id.shard().intersect_with(shard) {
                return block_id.seq_no() < *min_actual;
            }
        }
        false
    }
}

impl AllowStateGcResolver for AllowStateGcSmartResolver {
    fn allow_state_gc(&self, block_id: &BlockIdExt, saved_at: u64, gc_utime: u64) -> Result<bool> {
        let old = AllowStateGcSmartResolver::allow_state_gc(self, block_id, saved_at, gc_utime)?;
        let pinned = self.pinned_roots.read().get(block_id).map(|c| *c > 0).unwrap_or(false);
        Ok(old && !pinned)
    }

    fn stage_gc_progress(&self) -> Option<u64> {
        if !self.durable_gate.load(Ordering::Acquire) {
            return None;
        }
        let ticket = self.next_ticket.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
        *self.staged.lock() = Some((ticket, self.live_progress()));
        Some(ticket)
    }

    fn commit_gc_progress(&self, ticket: u64) {
        let mut staged = self.staged.lock();
        if staged.as_ref().is_some_and(|(staged_ticket, _)| *staged_ticket == ticket) {
            if let Some((_, progress)) = staged.take() {
                *self.committed.write() = progress;
            }
        }
    }

    fn require_durable_progress(&self) {
        self.durable_gate.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod durable_progress_tests {
    use super::*;

    fn mc(seq_no: u32) -> BlockIdExt {
        BlockIdExt::with_params(
            ShardIdent::masterchain(),
            seq_no,
            Default::default(),
            Default::default(),
        )
    }

    /// Gated decisions use only committed progress, and commit installs the
    /// progress captured at staging, not progress advanced afterwards.
    #[test]
    fn gated_resolver_uses_only_committed_progress() {
        let resolver = AllowStateGcSmartResolver::new(0);
        resolver.test_advance_live_mc_boundary(10);
        assert!(AllowStateGcResolver::allow_state_gc(&resolver, &mc(5), 0, 0).unwrap());
        resolver.require_durable_progress();
        assert!(
            !AllowStateGcResolver::allow_state_gc(&resolver, &mc(5), 0, 0).unwrap(),
            "live progress must not authorize deletion once gated"
        );
        let ticket = resolver.stage_gc_progress().unwrap();
        resolver.test_advance_live_mc_boundary(20);
        resolver.commit_gc_progress(ticket);
        assert!(AllowStateGcResolver::allow_state_gc(&resolver, &mc(5), 0, 0).unwrap());
        assert!(
            !AllowStateGcResolver::allow_state_gc(&resolver, &mc(15), 0, 0).unwrap(),
            "progress advanced after staging was committed"
        );
        // A stale ticket does not install anything.
        let current = resolver.stage_gc_progress().unwrap();
        resolver.commit_gc_progress(current.wrapping_sub(1));
        assert!(!AllowStateGcResolver::allow_state_gc(&resolver, &mc(15), 0, 0).unwrap());
        resolver.commit_gc_progress(current);
        assert!(AllowStateGcResolver::allow_state_gc(&resolver, &mc(15), 0, 0).unwrap());
        // The zerostate is never eligible, and pins still hold.
        assert!(!AllowStateGcResolver::allow_state_gc(&resolver, &mc(0), 0, 0).unwrap());
        resolver.reserve_absent_repair_state(&mc(5)).unwrap();
        assert!(!AllowStateGcResolver::allow_state_gc(&resolver, &mc(5), 0, 0).unwrap());
    }

    #[test]
    fn ungated_resolver_keeps_live_decisions() {
        let resolver = AllowStateGcSmartResolver::new(0);
        assert_eq!(resolver.stage_gc_progress(), None);
        resolver.test_advance_live_mc_boundary(10);
        assert!(AllowStateGcResolver::allow_state_gc(&resolver, &mc(5), 0, 0).unwrap());
    }
}

#[cfg(test)]
mod repair_pin_tests {
    use super::*;
    #[test]
    fn repair_target_pin_transfers_without_relaxing_ordinary_gc() {
        let resolver = AllowStateGcSmartResolver::new(0);
        let id = BlockIdExt::with_params(
            ShardIdent::masterchain(),
            7,
            Default::default(),
            Default::default(),
        );
        resolver.test_advance_expired_mc_boundary(8);
        assert!(!resolver.pin_state(&id, 0, 0).unwrap());
        assert!(AllowStateGcResolver::allow_state_gc(&resolver, &id, 0, 0).unwrap());
        resolver.reserve_absent_repair_state(&id).unwrap();
        assert!(resolver.pin_state(&id, 0, 0).unwrap(), "transfer existing reservation");
        resolver.unpin_state(&id).unwrap();
        assert!(!AllowStateGcResolver::allow_state_gc(&resolver, &id, 0, 0).unwrap());
        resolver.unpin_state(&id).unwrap();
        assert!(AllowStateGcResolver::allow_state_gc(&resolver, &id, 0, 0).unwrap());
        assert!(!resolver.pin_state(&id, 0, 0).unwrap(), "no permanent GC exception");
    }
}
