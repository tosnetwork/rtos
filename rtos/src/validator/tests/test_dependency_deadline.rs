// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use crate::{
    collator_test_bundle::create_engine_allocated,
    engine_traits::EngineOperations,
    shard_state::ShardStateStuff,
    validator::{dependency_deadline::DependencyDeadline, out_msg_queue::StatesManager},
};
use rtos_block::{error, BlockIdExt, Result, ShardIdent, ShardStateUnsplit, UInt256};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::time::Instant;

struct DelayedStates {
    states: HashMap<BlockIdExt, Arc<ShardStateStuff>>,
    delay: Duration,
    budgets: Mutex<Vec<Option<u64>>>,
    active: Arc<AtomicUsize>,
}

struct ActiveWait(Arc<AtomicUsize>);
impl Drop for ActiveWait {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl EngineOperations for DelayedStates {
    async fn wait_state(
        self: Arc<Self>,
        id: &BlockIdExt,
        timeout_ms: Option<u64>,
        download: bool,
    ) -> Result<Arc<ShardStateStuff>> {
        assert!(download);
        self.budgets.lock().unwrap().push(timeout_ms);
        self.active.fetch_add(1, Ordering::SeqCst);
        let _active = ActiveWait(self.active.clone());
        let ready = tokio::time::sleep(self.delay);
        if let Some(ms) = timeout_ms {
            tokio::time::timeout(Duration::from_millis(ms), ready)
                .await
                .map_err(|_| error!("controlled dependency timeout"))?;
        } else {
            ready.await;
        }
        Ok(self.states.get(id).expect("declared state").clone())
    }
}

fn engine(delay_ms: u64) -> (Arc<DelayedStates>, Vec<BlockIdExt>) {
    let mut states = HashMap::new();
    let mut ids = Vec::new();
    for seq in 1..=2 {
        let shard = ShardIdent::with_workchain_id(0).unwrap();
        let id = BlockIdExt::with_params(
            shard.clone(),
            seq,
            UInt256::from([seq as u8; 32]),
            UInt256::default(),
        );
        let mut state = ShardStateUnsplit::with_ident(shard);
        state.set_seq_no(seq);
        let state = ShardStateStuff::from_state(
            id.clone(),
            state,
            #[cfg(feature = "telemetry")]
            &crate::collator_test_bundle::create_engine_telemetry(),
            &create_engine_allocated(),
        )
        .unwrap();
        states.insert(id.clone(), state);
        ids.push(id);
    }
    (
        Arc::new(DelayedStates {
            states,
            delay: Duration::from_millis(delay_ms),
            budgets: Mutex::new(Vec::new()),
            active: Arc::new(AtomicUsize::new(0)),
        }),
        ids,
    )
}

#[tokio::test(start_paused = true)]
async fn validation_dependency_after_one_second_uses_remaining_total_budget() {
    let (engine, ids) = engine(1500);
    // The pre-fix validator path used this exact caller-supplied 1000ms budget.
    let mut old = StatesManager::with_validator_data(engine.clone());
    assert!(old
        .get_state(&ids[0], Some(1000))
        .await
        .err()
        .expect("expected failure")
        .to_string()
        .contains("controlled dependency timeout"));
    let mut fixed = StatesManager::with_validator_data(engine.clone())
        .with_dependency_deadline(DependencyDeadline::at(Instant::now() + Duration::from_secs(5)));
    let state = fixed.get_state(&ids[0], Some(1000)).await.unwrap();
    assert_eq!(state.block_id(), &ids[0]);
    assert_eq!(*engine.budgets.lock().unwrap(), vec![Some(1000), Some(5000)]);
    assert_eq!(engine.active.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn validation_dependency_budget_does_not_restart_for_each_state() {
    let (engine, ids) = engine(1500);
    let deadline = Instant::now() + Duration::from_millis(2500);
    let mut manager = StatesManager::with_validator_data(engine.clone())
        .with_dependency_deadline(DependencyDeadline::at(deadline));
    manager.get_state(&ids[0], Some(1000)).await.unwrap();
    let second = tokio::time::timeout_at(deadline, manager.get_state(&ids[1], Some(1000))).await;
    assert!(!matches!(second, Ok(Ok(_))));
    assert_eq!(*engine.budgets.lock().unwrap(), vec![Some(2500), Some(1000)]);
    assert_eq!(engine.active.load(Ordering::SeqCst), 0);
    let calls = engine.budgets.lock().unwrap().len();
    assert!(manager
        .get_state(&ids[1], Some(1000))
        .await
        .err()
        .expect("expected failure")
        .to_string()
        .contains("deadline expired"));
    assert_eq!(engine.budgets.lock().unwrap().len(), calls);
}

#[tokio::test(start_paused = true)]
async fn validation_dependency_drop_cancels_inflight_wait() {
    let (engine, ids) = engine(4000);
    let mut manager = StatesManager::with_validator_data(engine.clone())
        .with_dependency_deadline(DependencyDeadline::at(Instant::now() + Duration::from_secs(5)));
    let mut wait = Box::pin(manager.get_state(&ids[0], Some(1000)));
    tokio::select! {
        _ = &mut wait => panic!("unexpected early completion"),
        _ = tokio::time::sleep(Duration::from_millis(500)) => {},
    }
    assert_eq!(engine.active.load(Ordering::SeqCst), 1);
    drop(wait);
    assert_eq!(engine.active.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn validation_dependency_rounding_and_nonvalidation_budget() {
    assert_eq!(DependencyDeadline::default().timeout_ms(None).unwrap(), None);
    assert_eq!(DependencyDeadline::default().timeout_ms(Some(17)).unwrap(), Some(17));
    assert_eq!(
        DependencyDeadline::at(Instant::now() + Duration::from_micros(1500))
            .timeout_ms(Some(1000))
            .unwrap(),
        Some(2)
    );
    let expired = DependencyDeadline::at(Instant::now()).timeout_ms(None).unwrap_err();
    assert!(matches!(
        expired.downcast_ref::<crate::error::NodeError>(),
        Some(crate::error::NodeError::Timeout(_))
    ));
}
