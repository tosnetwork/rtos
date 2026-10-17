// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Engine-owned served state, matching fixed C++ validator/manager.cpp.
use crate::{engine_traits::EngineOperations, shard_states_keeper::PinnedShardStateGuard};
use rtos_block::{error, Result};

#[derive(Default)]
pub struct ServedMasterchain {
    pub(crate) state: tokio::sync::Mutex<Option<PinnedShardStateGuard>>,
}

impl ServedMasterchain {
    /// C++ update_shard_client_block_handle: retire the old cached lease as
    /// soon as shard progress advances, even when there are no RPC requests.
    pub async fn observe_shard_progress<E: EngineOperations + ?Sized>(
        &self,
        engine: &E,
        id: &rtos_block::BlockIdExt,
    ) -> Result<()> {
        let mut served = self.state.lock().await;
        if served.as_ref().is_none_or(|old| old.state().block_id().seq_no() < id.seq_no()) {
            *served = Some(engine.load_and_pin_state(id).await?);
        }
        Ok(())
    }

    pub async fn load(&self, engine: &dyn EngineOperations) -> Result<PinnedShardStateGuard> {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs_f64();
        self.load_at(engine, now).await
    }

    pub(crate) async fn load_at(
        &self,
        engine: &dyn EngineOperations,
        now: f64,
    ) -> Result<PinnedShardStateGuard> {
        // Serialize selection and pin acquisition. A later request cannot
        // reinstall an older snapshot after a concurrent request advanced it.
        let mut served = self.state.lock().await;
        let head = engine
            .load_last_applied_mc_block_id()?
            .ok_or_else(|| error!("Cannot load last applied mc block id"))?;
        // C++ update_shard_client_block_handle advances only to a higher
        // shard-client state. Observe the same persisted progress here before
        // evaluating the request; a lower shard pointer cannot undo fallback.
        if let Some(shard) = engine.load_shard_client_mc_block_id()? {
            if served.as_ref().is_none_or(|old| old.state().block_id().seq_no() < shard.seq_no()) {
                *served = Some(engine.load_and_pin_state(&shard).await?);
            }
        }
        if served.is_none() {
            *served = Some(engine.load_and_pin_state(&head).await?);
        }
        let current = served.as_ref().unwrap();
        // The two persisted pointers may advance between reads. C++ reads
        // them in one actor turn; an older head snapshot must likewise never
        // move a newly observed shard-client state backwards here.
        if current.state().block_id().seq_no() < head.seq_no() {
            let head_state = engine.load_and_pin_state(&head).await?;
            let head_time = head_state.state().state()?.gen_time();
            let served_time = current.state().state()?.gen_time();
            let blocks = head.seq_no().wrapping_sub(current.state().block_id().seq_no());
            let time_per_block =
                (f64::from(head_time.wrapping_sub(served_time)) / f64::from(blocks)).max(2.0);
            if now - f64::from(served_time) > (time_per_block * 8.0).min(180.0) {
                *served = Some(head_state);
            }
        }
        Ok(served.as_ref().unwrap().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        collator_test_bundle::create_engine_allocated,
        internal_db::state_gc_resolver::AllowStateGcSmartResolver, shard_state::ShardStateStuff,
    };
    use rtos_block::{BlockIdExt, ShardIdent, ShardStateUnsplit, UInt256};
    use std::{
        collections::HashMap,
        sync::{Arc, RwLock},
    };
    use storage::shardstate_db_async::AllowStateGcResolver;

    struct Fixture {
        cache: ServedMasterchain,
        heads: RwLock<(Option<u32>, Option<u32>)>,
        states: HashMap<u32, Arc<ShardStateStuff>>,
        gc: Arc<AllowStateGcSmartResolver>,
        pin_gate:
            tokio::sync::Mutex<Option<(u32, Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>>,
    }
    impl Fixture {
        fn new(states: &[(u32, u32)], head: Option<u32>, shard: Option<u32>) -> Self {
            let allocated = create_engine_allocated();
            #[cfg(feature = "telemetry")]
            let telemetry = crate::collator_test_bundle::create_engine_telemetry();
            let states = states
                .iter()
                .map(|&(seqno, time)| {
                    let mut state = ShardStateUnsplit::with_ident(ShardIdent::masterchain());
                    state.set_seq_no(seqno);
                    state.set_gen_time(time);
                    let hash = UInt256::calc_file_hash(&seqno.to_le_bytes());
                    let id = BlockIdExt::with_params(
                        ShardIdent::masterchain(),
                        seqno,
                        hash.clone(),
                        hash,
                    );
                    let state = ShardStateStuff::from_state(
                        id,
                        state,
                        #[cfg(feature = "telemetry")]
                        &telemetry,
                        &allocated,
                    )
                    .unwrap();
                    (seqno, state)
                })
                .collect();
            Self {
                cache: Default::default(),
                heads: RwLock::new((head, shard)),
                states,
                gc: Arc::new(AllowStateGcSmartResolver::new(u64::MAX)),
                pin_gate: Default::default(),
            }
        }
        fn advance(&self, head: u32, shard: Option<u32>) {
            *self.heads.write().unwrap() = (Some(head), shard);
        }
        async fn selected(&self, now: f64) -> u32 {
            self.cache.load_at(self, now).await.unwrap().state().block_id().seq_no()
        }
    }
    #[async_trait::async_trait]
    impl EngineOperations for Fixture {
        fn served_masterchain_cache(&self) -> Option<&ServedMasterchain> {
            Some(&self.cache)
        }
        fn load_last_applied_mc_block_id(&self) -> Result<Option<Arc<BlockIdExt>>> {
            Ok(self.heads.read().unwrap().0.map(|i| Arc::new(self.states[&i].block_id().clone())))
        }
        fn load_shard_client_mc_block_id(&self) -> Result<Option<Arc<BlockIdExt>>> {
            Ok(self.heads.read().unwrap().1.map(|i| Arc::new(self.states[&i].block_id().clone())))
        }
        async fn load_and_pin_state(&self, id: &BlockIdExt) -> Result<PinnedShardStateGuard> {
            let gate = {
                let mut gate = self.pin_gate.lock().await;
                if gate.as_ref().is_some_and(|entry| entry.0 == id.seq_no()) {
                    gate.take()
                } else {
                    None
                }
            };
            if let Some((_, entered, resume)) = gate {
                entered.notify_one();
                resume.notified().await;
            }
            PinnedShardStateGuard::new(self.states[&id.seq_no()].clone(), self.gc.clone())
        }
    }

    #[tokio::test]
    async fn served_masterchain_time_limit_matches_cpp_strict_boundary_and_minimum_rate() {
        let engine = Fixture::new(
            &[(100, 1000), (120, 1020), (121, 1021), (122, 1022)],
            Some(120),
            Some(100),
        );
        assert_eq!(
            engine.selected(1016.0).await,
            100,
            "20 blocks alone are not C++'s time predicate"
        );
        assert_eq!(engine.selected(1016.001).await, 120);
        engine.advance(122, Some(121));
        assert_eq!(engine.selected(1030.0).await, 121, "new shard progress advances the cache");
    }

    #[tokio::test]
    async fn served_masterchain_slow_blocks_and_180_second_cap_match_cpp() {
        let slow = Fixture::new(&[(100, 1000), (110, 1200)], Some(110), Some(100));
        assert_eq!(slow.selected(1160.0).await, 100);
        assert_eq!(slow.selected(1160.001).await, 110);
        let capped = Fixture::new(&[(100, 1000), (102, 5000)], Some(102), Some(100));
        assert_eq!(capped.selected(1180.0).await, 100);
        assert_eq!(capped.selected(1180.001).await, 102);
    }

    #[tokio::test]
    async fn served_masterchain_snapshot_cannot_regress_from_258_to_251() {
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
                as u32;
        let engine = Arc::new(Fixture::new(
            &[(240, now - 30), (251, now - 7), (258, now - 3), (259, now - 2)],
            Some(258),
            Some(240),
        ));
        assert_eq!(engine.selected(f64::from(now)).await, 258);
        engine.advance(259, Some(251));
        let api: Arc<dyn EngineOperations> = engine.clone();
        let served = crate::block::get_last_liteserver_state(&api).await.unwrap();
        assert_eq!(served.state().block_id(), engine.states[&258].block_id());
        assert_eq!(served.state().find_block_id(258).unwrap(), *engine.states[&258].block_id());
        assert_eq!(
            crate::block::get_last_liteserver_state_block(&api).await.unwrap().as_ref(),
            engine.states[&258].block_id()
        );
        assert_eq!(engine.selected(f64::from(now)).await, 258);
    }

    #[tokio::test]
    async fn served_masterchain_newer_shard_observation_wins_over_stale_head_snapshot() {
        let engine = Fixture::new(&[(251, 1000), (258, 1007)], Some(251), Some(258));
        assert_eq!(engine.selected(2000.0).await, 258);
    }

    #[tokio::test]
    async fn served_masterchain_bootstrap_requires_head_and_is_owned_per_engine() {
        let missing = Fixture::new(&[(251, 1000)], None, Some(251));
        assert!(missing.cache.load_at(&missing, 1000.0).await.is_err());
        assert!(missing.cache.state.lock().await.is_none());
        let first = Fixture::new(&[(258, 1000)], Some(258), None);
        let second = Fixture::new(&[(251, 1000)], Some(251), None);
        assert_eq!(first.selected(1000.0).await, 258);
        assert_eq!(second.selected(1000.0).await, 251);
    }

    #[tokio::test]
    async fn served_masterchain_concurrent_old_read_cannot_overwrite_newer_selection() {
        let engine = Arc::new(Fixture::new(&[(243, 1000), (258, 1015)], Some(243), None));
        let entered = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        *engine.pin_gate.lock().await = Some((243, entered.clone(), resume.clone()));
        let first_engine = engine.clone();
        let first = tokio::spawn(async move { first_engine.selected(1000.0).await });
        entered.notified().await;
        engine.advance(258, None);
        let second_engine = engine.clone();
        let second = tokio::spawn(async move { second_engine.selected(1020.0).await });
        for _ in 0..3 {
            tokio::task::yield_now().await;
        }
        assert!(!second.is_finished(), "selection waits for the admitted older state read");
        resume.notify_one();
        assert_eq!(first.await.unwrap(), 243);
        assert_eq!(second.await.unwrap(), 258);
        assert_eq!(engine.selected(1020.0).await, 258);
    }

    #[tokio::test]
    async fn served_masterchain_shard_callback_advances_and_releases_without_queries() {
        let engine = Fixture::new(&[(243, 1000), (258, 1015)], Some(243), Some(243));
        let old = engine.states[&243].block_id();
        let current = engine.states[&258].block_id();
        engine.observe_served_shard_progress(old).await.unwrap();
        engine.advance(258, Some(258));
        engine.observe_served_shard_progress(current).await.unwrap();
        engine.gc.test_advance_expired_mc_boundary(400);
        assert!(AllowStateGcResolver::allow_state_gc(engine.gc.as_ref(), old, 0, u64::MAX).unwrap());
        assert!(!AllowStateGcResolver::allow_state_gc(engine.gc.as_ref(), current, 0, u64::MAX)
            .unwrap());
        engine.observe_served_shard_progress(old).await.unwrap();
        assert_eq!(engine.cache.state.lock().await.as_ref().unwrap().state().block_id(), current);
        engine.cache.state.lock().await.take();
        assert!(
            AllowStateGcResolver::allow_state_gc(engine.gc.as_ref(), current, 0, u64::MAX).unwrap()
        );
    }

    #[tokio::test]
    async fn served_masterchain_retains_physical_state_until_cache_and_reader_release() {
        let engine = Fixture::new(&[(243, 1000), (258, 1015)], Some(243), None);
        let reader = engine.cache.load_at(&engine, 1000.0).await.unwrap();
        engine.advance(258, None);
        assert_eq!(engine.selected(1020.0).await, 258);
        engine.gc.test_advance_expired_mc_boundary(400);
        let old = engine.states[&243].block_id();
        let current = engine.states[&258].block_id();
        assert!(
            !AllowStateGcResolver::allow_state_gc(engine.gc.as_ref(), old, 0, u64::MAX).unwrap()
        );
        drop(reader);
        assert!(AllowStateGcResolver::allow_state_gc(engine.gc.as_ref(), old, 0, u64::MAX).unwrap());
        assert!(!AllowStateGcResolver::allow_state_gc(engine.gc.as_ref(), current, 0, u64::MAX)
            .unwrap());
        engine.cache.state.lock().await.take();
        assert!(
            AllowStateGcResolver::allow_state_gc(engine.gc.as_ref(), current, 0, u64::MAX).unwrap()
        );
    }
}
