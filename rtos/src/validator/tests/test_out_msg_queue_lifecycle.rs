// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{engine_traits::EngineAlloc, shard_state::ShardStateStuff};
use std::sync::atomic::{AtomicBool, AtomicUsize};

struct QueueEngine {
    allocated: Arc<EngineAlloc>,
    #[cfg(feature = "telemetry")]
    telemetry: Arc<crate::engine_traits::EngineTelemetry>,
    initial_read: tokio::sync::Notify,
    release_read: tokio::sync::Semaphore,
    hold_read: bool,
    worker_reads: AtomicUsize,
    worker_entered: tokio::sync::Notify,
    panic_worker: AtomicBool,
}

impl QueueEngine {
    fn new(hold_read: bool) -> Arc<Self> {
        Arc::new(Self {
            allocated: crate::collator_test_bundle::create_engine_allocated(),
            #[cfg(feature = "telemetry")]
            telemetry: crate::collator_test_bundle::create_engine_telemetry(),
            initial_read: tokio::sync::Notify::new(),
            release_read: tokio::sync::Semaphore::new(0),
            hold_read,
            worker_reads: AtomicUsize::new(0),
            worker_entered: tokio::sync::Notify::new(),
            panic_worker: AtomicBool::new(false),
        })
    }
}

#[async_trait::async_trait]
impl EngineOperations for QueueEngine {
    fn engine_allocated(&self) -> &Arc<EngineAlloc> {
        &self.allocated
    }
    #[cfg(feature = "telemetry")]
    fn engine_telemetry(&self) -> &Arc<crate::engine_traits::EngineTelemetry> {
        &self.telemetry
    }
    fn check_stop(&self) -> bool {
        false
    }
    async fn load_last_applied_mc_state(&self) -> Result<Arc<ShardStateStuff>> {
        self.initial_read.notify_one();
        if self.hold_read {
            self.release_read.acquire().await.unwrap().forget();
        }
        let bytes = include_bytes!("../../tests/static/zerostate.boc");
        let root = rtos_block::read_single_root_boc(bytes)?;
        let state = ShardStateUnsplit::construct_from_cell(root.clone())?;
        let id = BlockIdExt::with_params(
            state.shard().clone(),
            0,
            root.repr_hash().clone(),
            rtos_block::UInt256::calc_file_hash(bytes),
        );
        ShardStateStuff::deserialize_zerostate(
            id,
            bytes,
            #[cfg(feature = "telemetry")]
            &self.telemetry,
            &self.allocated,
        )
    }
    fn load_last_applied_mc_block_id(&self) -> Result<Option<Arc<BlockIdExt>>> {
        self.worker_reads.fetch_add(1, Ordering::Relaxed);
        self.worker_entered.notify_one();
        assert!(!self.panic_worker.load(Ordering::Relaxed), "controlled cleaner read panic");
        fail!("controlled initial cleaner read failure")
    }
}

#[tokio::test]
async fn queue_owned_drain_cancels_real_initial_state_load() {
    let engine = QueueEngine::new(true);
    let manager = OutMsgQueueManager::create(engine.clone());
    let starting = manager.clone();
    let join = tokio::spawn(async move { starting.initialize().await });
    engine.initial_read.notified().await;
    tokio::time::timeout(Duration::from_millis(500), manager.stop_and_wait())
        .await
        .unwrap()
        .unwrap();
    assert!(join.await.unwrap().is_err());
    assert_eq!(engine.worker_reads.load(Ordering::Relaxed), 0);
    assert!(manager.initialize().await.is_err());
    let weak = Arc::downgrade(&manager);
    drop(manager);
    assert!(weak.upgrade().is_none());
    assert_eq!(Arc::strong_count(&engine), 1);
}

#[tokio::test]
async fn queue_owned_drain_cancels_initial_read_failure_backoff_and_preserves_panic() {
    for panic in [false, true] {
        let engine = QueueEngine::new(false);
        engine.panic_worker.store(panic, Ordering::Relaxed);
        let manager = OutMsgQueueManager::create(engine.clone());
        manager.initialize().await.unwrap();
        engine.worker_entered.notified().await;
        let result = tokio::time::timeout(Duration::from_millis(500), manager.stop_and_wait())
            .await
            .unwrap();
        assert_eq!(result.is_err(), panic);
        if panic {
            assert!(result.unwrap_err().to_string().contains("out-message queue cache cleaner"));
        }
        assert_eq!(engine.worker_reads.load(Ordering::Relaxed), 1);
        let weak = Arc::downgrade(&manager);
        drop(manager);
        assert!(weak.upgrade().is_none());
        assert_eq!(Arc::strong_count(&engine), 1);
    }
}
