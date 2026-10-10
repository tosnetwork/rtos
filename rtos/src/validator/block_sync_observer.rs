/*
 * RTOS project modifications (2026-10-10): project and crate naming; typed Simplex protocol and membership admission.
 * Copyright (C) 2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
//! Block-sync overlay observer: passive listener that caches inbound candidates
//!
//! C++ ref: `block-sync-overlay.cpp` `BlockSyncObserver` (off-shard / non-validator path)
//!
//! Differences from the validator-side block-sync wiring: no consensus private overlay,
//! no simplex stack, same precheck callback. Created per (shard, session_id) by
//! `validator_manager` and stopped on session end or role transition

use crate::engine_traits::EngineOperations;
use adnl::{BroadcastCheck, OverlayNode, OverlayParams, PrivateOverlayShortId};
use consensus_common::{BlockSyncCheck, BlockSyncOverlayParams, BlockSyncRole, BlockSyncStats};
use rtos_api::{
    deserialize_boxed,
    ton::consensus::{candidatedata::Block as ConsensusBlock, CandidateData},
};
use rtos_block::{
    error, fail, BlockIdExt, CryptoSignaturePair, KeyId, KeyOption, Result, ShardIdent, UInt256,
};
use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, Weak,
    },
};

const LOG_TARGET: &str = "block_sync_observer";

/// Read-only subscriber of a per-session block-sync overlay. Drops received
/// candidates into the engine's block-candidate cache. See module-level doc
pub struct BlockSyncObserver {
    overlay_node: Arc<OverlayNode>,
    overlay_short_id: Arc<PrivateOverlayShortId>,
    shard: ShardIdent,
    session_id: UInt256,
    local_adnl_key: Arc<dyn KeyOption>,
    engine: Arc<dyn EngineOperations>,
    stop_requested: Arc<AtomicBool>,
    runtime_handle: tokio::runtime::Handle,
    /// Post-reassembly sender check, parallel to the precheck callback
    authorized: HashSet<Arc<KeyId>>,
    max_candidate_size: usize,
    proto_version: u32,
    stats: Arc<BlockSyncStats>,
    /// Owned worker handles. stop_and_wait confirms their terminal result
    /// before the manager replaces an observer with the same overlay ID.
    listener_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
    ticker_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
    cancellation: tokio_util::sync::CancellationToken,
    teardown_drained: Arc<AtomicBool>,
    #[cfg(test)]
    listener_exit_gate: Mutex<Option<Arc<lifecycle_tests::ListenerExitGate>>>,
    stop_completion:
        Mutex<Option<tokio::sync::watch::Receiver<Option<std::result::Result<(), String>>>>>,
}

impl BlockSyncObserver {
    /// Create and start a new observer; `Err` if our ADNL key is not in `params.members`
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        runtime_handle: tokio::runtime::Handle,
        overlay_node: Arc<OverlayNode>,
        local_adnl_key: Arc<dyn KeyOption>,
        params: BlockSyncOverlayParams,
        session_id: UInt256,
        shard: ShardIdent,
        engine: Arc<dyn EngineOperations>,
        use_quic: bool,
        broadcast_hops: Option<u8>,
        proto_version: u32,
    ) -> Result<Arc<Self>> {
        let membership = params.membership()?;
        if membership.role(local_adnl_key.id())?
            != consensus_common::simplex_protocol::OverlayMemberRole::Observer
        {
            fail!("BlockSyncObserver: current session validator cannot start an observer instance");
        }
        let overlay_short_id = simplex::utils::compute_block_sync_overlay_short_id(&session_id)?;

        let stats = BlockSyncStats::new(
            overlay_short_id.clone(),
            BlockSyncRole::Observer,
            Some(shard.clone()),
            Some(session_id.clone()),
        );

        let authorized: HashSet<Arc<KeyId>> = params.authorized_keys.keys().cloned().collect();
        let check: Arc<dyn BroadcastCheck> = Arc::new(BlockSyncCheck {
            overlay_id: overlay_short_id.clone(),
            authorized: authorized.clone(),
            max_payload_size: params.max_broadcast_size,
            current_set: params.current_set.clone(),
            slots_per_leader_window: params.slots_per_leader_window,
            stats: Some(stats.clone()),
        });

        let overlay_params = OverlayParams {
            flags: 0,
            hops: broadcast_hops,
            overlay_id: &overlay_short_id,
            runtime: Some(runtime_handle.clone()),
        };
        let added = overlay_node.add_private_overlay(
            overlay_params,
            &local_adnl_key,
            &params.members,
            use_quic,
            Some(check),
        )?;
        if !added {
            fail!(
                "BlockSyncObserver: overlay {overlay_short_id} already registered \
                 (session={session_id:x}); refusing to attach observer to a stale overlay"
            );
        }

        log::info!(
            target: LOG_TARGET,
            "created observer for shard={shard} session={:x} overlay={overlay_short_id} \
             (members={}, authorized={}, leader_window={})",
            session_id,
            params.members.len(),
            authorized.len(),
            params.slots_per_leader_window,
        );

        let observer = Arc::new(Self {
            overlay_node,
            overlay_short_id,
            shard,
            session_id,
            local_adnl_key,
            engine,
            stop_requested: Arc::new(AtomicBool::new(false)),
            runtime_handle: runtime_handle.clone(),
            authorized,
            max_candidate_size: params.max_broadcast_size as usize,
            proto_version,
            stats: stats.clone(),
            listener_handle: Mutex::new(None),
            ticker_handle: Mutex::new(None),
            cancellation: tokio_util::sync::CancellationToken::new(),
            teardown_drained: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            listener_exit_gate: Mutex::new(None),
            stop_completion: Mutex::new(None),
        });
        let cancellation = observer.cancellation.clone();
        let ticker = runtime_handle.spawn(async move {
            let mut interval =
                tokio::time::interval(consensus_common::BLOCK_SYNC_STATS_LOG_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval.tick().await;
            loop {
                tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => break,
                    _ = interval.tick() => stats.dump(),
                }
            }
        });
        *observer.ticker_handle.lock().expect("ticker handle poisoned") = Some(ticker);
        let handle = observer.clone().run_listener();
        *observer.listener_handle.lock().expect("listener_handle poisoned") = Some(handle);
        Ok(observer)
    }

    /// Request cancellation. Call stop_and_wait before reusing this overlay ID.
    pub fn stop(&self) {
        let mut completion = self.stop_completion.lock().expect("stop completion poisoned");
        if completion.is_some() {
            return;
        }
        self.stop_requested.store(true, Ordering::Release);
        self.cancellation.cancel();
        self.stats.dump();
        let deletion = self
            .overlay_node
            .delete_private_overlay(&self.overlay_short_id)
            .map(|_| ())
            .map_err(|e| e.to_string());
        let listener = self.listener_handle.lock().expect("listener handle poisoned").take();
        let ticker = self.ticker_handle.lock().expect("ticker handle poisoned").take();
        let (tx, rx) = tokio::sync::watch::channel(None);
        *completion = Some(rx);
        let drained = self.teardown_drained.clone();
        self.runtime_handle.spawn(async move {
            let mut errors = Vec::new();
            if let Err(error) = deletion {
                errors.push(format!("overlay deletion failed: {error}"));
            }
            for (name, task) in [("listener", listener), ("ticker", ticker)] {
                if let Some(task) = task {
                    if let Err(error) = task.await {
                        errors.push(format!("observer task join failed ({name}): {error}"));
                    }
                }
            }
            drained.store(true, Ordering::Release);
            tx.send_replace(Some(if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) }));
        });
    }

    pub(super) fn teardown_drained(&self) -> bool {
        self.teardown_drained.load(Ordering::Acquire)
    }

    /// Shared terminal result; cancellation of a waiter cannot detach cleanup.
    pub async fn stop_and_wait(&self) -> Result<()> {
        self.stop();
        let mut completion = self
            .stop_completion
            .lock()
            .expect("stop completion poisoned")
            .as_ref()
            .expect("stop installs completion")
            .clone();
        loop {
            if let Some(result) = completion.borrow().clone() {
                return result.map_err(|e| error!("{}", e));
            }
            completion.changed().await.map_err(|_| error!("observer teardown completion lost"))?;
        }
    }

    pub fn shard(&self) -> &ShardIdent {
        &self.shard
    }

    fn run_listener(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let weak: Weak<Self> = Arc::downgrade(&self);
        let overlay_node = self.overlay_node.clone();
        let overlay_short_id = self.overlay_short_id.clone();
        let stop_requested = self.stop_requested.clone();
        let shard = self.shard.clone();
        let cancellation = self.cancellation.clone();
        self.runtime_handle.spawn(async move {
            log::trace!(
                target: LOG_TARGET,
                "observer shard={shard}: broadcast listener started on {overlay_short_id}"
            );
            loop {
                if stop_requested.load(Ordering::Relaxed) {
                    break;
                }
                let received = tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => break,
                    received = overlay_node.wait_for_broadcast(&overlay_short_id) => received,
                };
                if stop_requested.load(Ordering::Acquire) {
                    break;
                }
                match received {
                    Ok(Some(message)) => {
                        let Some(this) = weak.upgrade() else { return };
                        this.process_inbound(message.recv_from, message.data);
                    }
                    Ok(None) => break,
                    Err(e) => {
                        log::error!(
                            target: LOG_TARGET,
                            "observer shard={shard}: wait_for_broadcast error: {e}"
                        );
                    }
                }
            }
            #[cfg(test)]
            if let Some(this) = weak.upgrade() {
                let gate = this.listener_exit_gate.lock().unwrap().take();
                if let Some(gate) = gate {
                    gate.entered.add_permits(1);
                    gate.release.acquire().await.unwrap().forget();
                }
            }
            log::trace!(
                target: LOG_TARGET,
                "observer shard={shard}: broadcast listener stopped"
            );
        })
    }

    fn process_inbound(&self, recv_from: Arc<KeyId>, data: Vec<u8>) {
        if recv_from == *self.local_adnl_key.id() {
            return;
        }
        // Post-reassembly sender check; the precheck callback gates earlier
        if !self.authorized.contains(&recv_from) {
            self.stats.bump_auth_drop();
            log::warn!(
                target: LOG_TARGET,
                "observer shard={}: dropping broadcast from non-validator {recv_from}",
                self.shard
            );
            return;
        }
        self.stats.bump_recv();
        // Parse as consensus.CandidateData
        let obj = match deserialize_boxed(&data) {
            Ok(o) => o,
            Err(e) => {
                log::warn!(
                    target: LOG_TARGET,
                    "observer shard={}: failed to deserialize broadcast: {e}",
                    self.shard
                );
                return;
            }
        };
        let cand: CandidateData = match obj.downcast() {
            Ok(c) => c,
            Err(_) => {
                log::warn!(
                    target: LOG_TARGET,
                    "observer shard={}: non-CandidateData payload on block-sync overlay (dropped)",
                    self.shard
                );
                return;
            }
        };
        let block: ConsensusBlock = match cand {
            CandidateData::Consensus_Block(b) => b,
            // Empty candidates carry no body to cache; skip silently
            CandidateData::Consensus_Empty(_) => return,
        };
        if let Err(e) = self.cache_candidate(&block) {
            log::warn!(
                target: LOG_TARGET,
                "observer shard={}: cache_candidate failed: {e}",
                self.shard
            );
        }
    }

    fn cache_candidate(&self, block: &ConsensusBlock) -> Result<()> {
        let info = simplex::utils::extract_block_info_from_candidate(
            &block.candidate,
            &self.shard,
            self.max_candidate_size,
            self.proto_version,
        )?;
        let Some(info) = info else {
            // Empty candidate body inside consensus.block (shouldn't normally
            // happen for non-empty candidates; bail quietly)
            return Ok(());
        };
        let block_id: BlockIdExt = info.block_id;
        let block_data = info.data;
        log::trace!(
            target: LOG_TARGET,
            "observer shard={}: caching candidate {block_id} ({} bytes)",
            self.shard, block_data.len(),
        );
        // The EngineOperations trait impl ignores cc_seqno/validator_set_hash/
        // signature and delegates to the inner Engine::cache_block_candidate
        // (id + block_data + file_hash check). Dummy zeros are safe here
        self.engine.cache_block_candidate(
            &block_id,
            /*cc_seqno*/ 0,
            /*validator_set_hash*/ 0,
            CryptoSignaturePair::default(),
            block_data,
        )?;
        Ok(())
    }
}

impl Drop for BlockSyncObserver {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
#[path = "tests/test_observer_lifecycle.rs"]
pub(super) mod lifecycle_tests;
