// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use super::*;
use crate::validator::validator_manager::emulator_network_bootstrap::EmulatorNetworkBootstrap;
use std::collections::BTreeMap;
use tokio::sync::{Notify, Semaphore};

pub(crate) struct ApplyGate {
    pub(crate) seen: std::sync::Mutex<BTreeMap<u32, BlockIdExt>>,
    changed: Notify,
    pub(crate) release: Semaphore,
    cancel_at: std::sync::Mutex<
        Option<(u32, tokio::sync::oneshot::Sender<()>, tokio::sync::oneshot::Sender<()>)>,
    >,
}
impl ApplyGate {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            seen: Default::default(),
            changed: Notify::new(),
            release: Semaphore::new(0),
            cancel_at: Default::default(),
        })
    }
    pub(crate) async fn target(&self, seqno: u32) -> BlockIdExt {
        loop {
            let changed = self.changed.notified();
            if let Some(id) = self.seen.lock().unwrap().get(&seqno).cloned() {
                return id;
            }
            changed.await;
        }
    }
}
impl Engine {
    pub(crate) async fn hold_owned_parent_apply_for_test(&self, id: &BlockIdExt) {
        let gate = self.parent_apply_test_gate.lock().unwrap().clone();
        let Some(gate) = gate else { return };
        let held = {
            let mut slot = gate.cancel_at.lock().unwrap();
            if slot.as_ref().is_some_and(|(seq, _, _)| *seq == id.seq_no) {
                slot.take()
            } else {
                None
            }
        };
        if let Some((_, entered, dropped)) = held {
            struct OnDrop(Option<tokio::sync::oneshot::Sender<()>>);
            impl Drop for OnDrop {
                fn drop(&mut self) {
                    if let Some(tx) = self.0.take() {
                        let _ = tx.send(());
                    }
                }
            }
            let _dropped = OnDrop(Some(dropped));
            let _ = entered.send(());
            std::future::pending::<()>().await;
        }
    }

    pub(crate) async fn hold_parent_apply_for_test(&self, id: &BlockIdExt, depth: u32) {
        if depth != 0 || !id.is_masterchain() || id.seq_no == 0 {
            return;
        }
        let gate = self.parent_apply_test_gate.lock().unwrap().clone();
        if let Some(gate) = gate {
            gate.seen.lock().unwrap().insert(id.seq_no, id.clone());
            gate.changed.notify_waiters();
            let _ = gate.release.acquire().await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parent_apply_stored_chain_probe() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();
    let bootstrap = EmulatorNetworkBootstrap::build(4)?;
    let stopper = Arc::new(Stopper::new());
    let flags =
        EngineFlags { initial_sync_disabled: true, force_check_db: false, truncate_db: None };
    let (engine, join) = run(
        bootstrap.load_node_config().await?,
        bootstrap.config_dir().to_str(),
        tokio::runtime::Handle::current(),
        tokio::runtime::Handle::current(),
        flags,
        stopper.clone(),
        None,
    )
    .await?;
    let gate = ApplyGate::new();
    *engine.parent_apply_test_gate.lock().unwrap() = Some(gate.clone());
    let result = async {
        let id = tokio::time::timeout(Duration::from_secs(60), gate.target(12)).await?;
        for seq in 1..=12 {
            let parent = gate.target(seq).await;
            let handle = engine.load_block_handle(&parent)?.unwrap();
            assert!(handle.has_data() && handle.has_proof());
            assert!(!handle.is_applied());
            let block = engine.load_block(&handle).await?;
            let proof = engine.load_block_proof(&handle, false).await?;
            crate::block_proof::check_block_proof_pair(engine.as_ref(), &parent, &block, &proof).await?;
        }
        eprintln!("PARENT_APPLY_PROBE authenticated stored unapplied chain 1..=12; invoking production worker");
        let too_deep = crate::full_node::apply_block::MAX_RECURSION_DEPTH - 12 + 1;
        let error = engine.clone().download_and_apply_block_worker(&id, id.seq_no, false, too_deep)
            .await.unwrap_err();
        assert!(error.to_string().contains("too deep recursion"), "{error}");
        for parent in gate.seen.lock().unwrap().values() {
            assert!(!engine.load_block_handle(parent)?.unwrap().is_applied());
        }
        // Cancel a real recursive application while block 6 owns its awaiter,
        // then retry the same tip after all ancestor tasks have been dropped.
        let (entered, ready) = tokio::sync::oneshot::channel();
        let (dropped, stopped) = tokio::sync::oneshot::channel();
        *gate.cancel_at.lock().unwrap() = Some((6, entered, dropped));
        let cancel_engine = engine.clone();
        let cancel_id = id.clone();
        let cancelled = tokio::spawn(async move {
            cancel_engine.download_and_apply_block_worker(&cancel_id, cancel_id.seq_no, false, 0).await
        });
        tokio::time::timeout(Duration::from_secs(10), ready).await??;
        cancelled.abort();
        assert!(cancelled.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(10), stopped).await??;
        let replay_engine = engine.clone();
        let replay_id = id.clone();
        let mut replay = tokio::task::JoinSet::new();
        replay.spawn(async move {
            loop {
                match replay_engine.clone().download_and_apply_block_worker(&replay_id, replay_id.seq_no, false, 0).await {
                    // An aborted child may still be finishing its synchronous
                    // drop on another worker. Its old waiters receive an explicit
                    // cancellation; a subsequent request must acquire ownership.
                    Err(err) if err.to_string().contains("operation cancelled") => tokio::task::yield_now().await,
                    result => return result,
                }
            }
        });
        tokio::time::timeout(Duration::from_secs(10), replay.join_next()).await?.unwrap()??;
        assert!(engine.load_block_handle(&id)?.unwrap().is_applied());
        Ok::<(), anyhow::Error>(())
    }.await;
    gate.release.close();
    *engine.parent_apply_test_gate.lock().unwrap() = None;
    stopper.set_stop();
    let _ = tokio::time::timeout(Duration::from_secs(10), join).await;
    engine.wait_stop().await?;
    result
}
