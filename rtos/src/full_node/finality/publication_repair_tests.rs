// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::publication_repair::{repair_mc_final, McFinalRepairRequest};
use consensus_common::session_runtime::SessionNetworkPin;
use storage::archives::package_entry_id::{GetFileName, PackageEntryId};

async fn request(pair: &Pair) -> McFinalRepairRequest {
    let context = pair
        .receiver
        .historical_pq_publication_context(pair.master.id(), pair.master.block().unwrap())
        .await
        .unwrap();
    McFinalRepairRequest {
        pin: SessionNetworkPin {
            zerostate: context.zerostate().clone(),
            global_id: context.global_id(),
        },
        history_init: context.history_init().clone(),
        block_id: pair.master.id().clone(),
        session_id: context.verifier().expected_session_id().clone(),
        profile: context.profile().clone(),
        protocol: context.protocol(),
        carrier_version: context.carrier_version(),
        wire_profile: WireProfile::T0,
    }
}

async fn reconnect(pair: &Pair) {
    for (local, remote) in [(&pair.receiver, &pair.provider), (&pair.provider, &pair.receiver)] {
        let local_adnl = &local.network().context().stack.adnl;
        let remote_adnl = &remote.network().context().stack.adnl;
        let local_key = local_adnl.key_by_tag(NodeNetwork::TAG_OVERLAY_KEY).unwrap();
        let remote_key = remote_adnl.key_by_tag(NodeNetwork::TAG_OVERLAY_KEY).unwrap();
        local_adnl
            .add_peer(local_key.id(), remote_adnl.ip_address_adnl(), None, &remote_key)
            .unwrap();
        local
            .network()
            .context()
            .stack
            .quic
            .as_ref()
            .unwrap()
            .add_peer_key(remote_key.id().clone(), remote.network().context().quic_address.unwrap())
            .unwrap();
    }
    pair.receiver.set_test_chain_time(Some(1002));
    pair.receiver.initialize_test_full_node_overlays().await.unwrap();
    for (local, remote) in [(&pair.receiver, &pair.provider), (&pair.provider, &pair.receiver)] {
        let remote_adnl = &remote.network().context().stack.adnl;
        let remote_key = remote_adnl.key_by_tag(NodeNetwork::TAG_OVERLAY_KEY).unwrap();
        let client = local.overlay_client(pair.master.id().shard()).await.unwrap();
        client.overlay_client().neighbours().add(remote_key.id().clone()).unwrap();
        let id = adnl::OverlayShortId::from_data(*client.overlay_client().id().data());
        let advertised =
            remote.network().context().stack.overlay.get_signed_node(&id, false).unwrap();
        local
            .network()
            .context()
            .stack
            .overlay
            .add_public_peer(remote_adnl.ip_address_adnl(), &advertised, &id)
            .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mc_live_repair_real_peer_restores_missing_artifacts_and_reopens() {
    for loss_mode in [0, 1, 2] {
        let mut pair = Pair::with_propagation_profile("included", false, true).await;
        let result = std::panic::AssertUnwindSafe(async {
            let (master, shards) = pair.apply_by_normal_clients().await;
            let expected = request(&pair).await;
            let root = std::path::PathBuf::from(pair.receiver.db_root_dir().unwrap());
            pair.receiver.clone().wait_stop().await.unwrap();
            master.await.unwrap();
            shards.await.unwrap();
            let path = root.join("archive/unapplied").join(if loss_mode != 0 {
                PackageEntryId::Proof(pair.master.id()).filename_short()
            } else {
                PackageEntryId::Block(pair.master.id()).filename_short()
            });
            // Normal MC apply archives its artifacts. Withdraw real package
            // files after join, leaving the database's archived/applied flags.
            // This is an explicit storage-loss simulation, not a GC claim.
            let mut pending = vec![root.join("archive/packages")];
            let mut removed = 0;
            while let Some(dir) = pending.pop() {
                for entry in std::fs::read_dir(dir).unwrap() {
                    let path = entry.unwrap().path();
                    if path.is_dir() {
                        pending.push(path);
                    } else if path.extension().is_some_and(|ext| ext == "pack") {
                        std::fs::rename(&path, path.with_extension("withdrawn")).unwrap();
                        removed += 1;
                    }
                }
            }
            assert!(removed > 0, "must withdraw actual archived files");
            drop(std::mem::replace(&mut pair.receiver, pair.provider.clone()));
            pair.receiver = open_engine(&pair._dir.path().join("receiver")).await;
            reconnect(&pair).await;
            let handle = pair.receiver.load_block_handle(pair.master.id()).unwrap().unwrap();
            assert!(handle.is_applied() && handle.has_data() && handle.has_proof());
            let before = pair.provider.overlays_router().unwrap().test_block_download_queries();
            let custody = repair_mc_final(pair.receiver.clone(), expected.clone()).await.unwrap();
            assert_eq!(custody.block_id(), pair.master.id());
            assert_eq!(custody.state_root(), &pair.master_state_root);
            assert_eq!(custody.parent_id(), &pair.anchor);
            assert_ne!(custody.proof_digest(), UInt256::default());
            assert!(path.is_file());
            assert!(
                pair.provider.overlays_router().unwrap().test_block_download_queries() > before,
                "must fetch through a real peer, never through spool fallback"
            );
            assert!(
                repair_mc_final(pair.receiver.clone(), expected.clone()).await.is_err(),
                "live same-ID lease excludes another worker"
            );
            drop(custody);
            pair.receiver.clone().wait_stop().await.unwrap();
            // The first repair durably rewrote unarchived files. Now exercise
            // loss of exactly one artifact with stale flags across a cold open.
            if loss_mode == 2 {
                let original = BlockProofStuff::deserialize(
                    pair.master.id(),
                    std::fs::read(&path).unwrap(),
                    false,
                )
                .unwrap();
                let BlockSignaturesVariant::SimplexPq(mut carrier) =
                    original.drain_signatures().unwrap()
                else {
                    panic!("PQ fixture required")
                };
                carrier.signatures[0].signature[0] ^= 1;
                let bad = full_proof(&pair.master, carrier);
                bad.check_proof_as_link().unwrap();
                std::fs::write(&path, bad.data()).unwrap();
            } else {
                std::fs::remove_file(&path).unwrap();
            }
            drop(std::mem::replace(&mut pair.receiver, pair.provider.clone()));
            pair.receiver = open_engine(&pair._dir.path().join("receiver")).await;
            reconnect(&pair).await;
            let before = pair.provider.overlays_router().unwrap().test_block_download_queries();
            let repaired = repair_mc_final(pair.receiver.clone(), expected).await.unwrap();
            assert!(
                pair.provider.overlays_router().unwrap().test_block_download_queries() > before
            );
            drop(repaired);
            pair.receiver.clone().wait_stop().await.unwrap();
            drop(std::mem::replace(&mut pair.receiver, pair.provider.clone()));
            pair.receiver = open_engine(&pair._dir.path().join("receiver")).await;
            let handle = pair.receiver.load_block_handle(pair.master.id()).unwrap().unwrap();
            assert_eq!(pair.receiver.load_block_raw(&handle).await.unwrap(), pair.master.data());
            pair.receiver
                .load_block_proof(&handle, false)
                .await
                .unwrap()
                .check_proof(pair.receiver.as_ref())
                .await
                .unwrap();
            assert_eq!(
                pair.receiver.load_state(pair.master.id()).await.unwrap().root_cell().repr_hash(),
                &pair.master_state_root
            );
        })
        .catch_unwind()
        .await;
        pair.receiver.clone().wait_stop().await.unwrap();
        pair.provider.clone().wait_stop().await.unwrap();
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mc_live_repair_rejects_unknown_unapplied_and_wrong_domain_without_network() {
    let pair = Pair::with_propagation_profile("included", false, true).await;
    let result = std::panic::AssertUnwindSafe(async {
        let expected = request(&pair).await;
        let before = pair.provider.overlays_router().unwrap().test_block_download_queries();
        assert!(repair_mc_final(pair.receiver.clone(), expected.clone()).await.is_err());
        let proof = pair
            .provider
            .load_block_proof(
                &pair.provider.load_block_handle(pair.master.id()).unwrap().unwrap(),
                false,
            )
            .await
            .unwrap();
        let handle = pair.receiver.store_block(&pair.master).await.unwrap().to_any();
        pair.receiver
            .store_block_proof(pair.master.id(), Some(handle.clone()), &proof)
            .await
            .unwrap();
        assert!(!handle.is_applied());
        assert!(repair_mc_final(pair.receiver.clone(), expected.clone()).await.is_err());
        let mut wrong = expected.clone();
        wrong.pin.zerostate.root_hash = UInt256::default();
        assert!(repair_mc_final(pair.receiver.clone(), wrong).await.is_err());
        let mut wrong = expected;
        wrong.block_id = pair.shard.id().clone();
        assert!(repair_mc_final(pair.receiver.clone(), wrong).await.is_err());
        assert_eq!(pair.provider.overlays_router().unwrap().test_block_download_queries(), before);
    })
    .catch_unwind()
    .await;
    pair.receiver.clone().wait_stop().await.unwrap();
    pair.provider.clone().wait_stop().await.unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mc_live_repair_canceled_waiter_remains_owned_until_real_barrier_finishes() {
    let pair = Pair::with_propagation_profile("included", false, true).await;
    let gate = crate::publication_repair::install_test_gate(&pair.receiver);
    let result = std::panic::AssertUnwindSafe(async {
        let (master, shards) = pair.apply_by_normal_clients().await;
        let expected = request(&pair).await;
        let waiter = tokio::spawn(repair_mc_final(pair.receiver.clone(), expected));
        tokio::time::timeout(Duration::from_secs(15), gate.entered.acquire())
            .await
            .unwrap()
            .unwrap()
            .forget();
        waiter.abort();
        assert!(matches!(waiter.await, Err(error) if error.is_cancelled()));
        let stop = tokio::spawn(pair.receiver.clone().wait_stop());
        tokio::time::sleep(Duration::from_millis(100)).await;
        let retained = !stop.is_finished();
        gate.release.add_permits(1);
        tokio::time::timeout(Duration::from_secs(30), stop).await.unwrap().unwrap().unwrap();
        master.await.unwrap();
        shards.await.unwrap();
        assert!(
            retained,
            "Engine shutdown must join the real accepted repair, even after waiter abort"
        );
    })
    .catch_unwind()
    .await;
    gate.release.add_permits(1);
    pair.receiver.clone().wait_stop().await.unwrap();
    pair.provider.clone().wait_stop().await.unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mc_live_repair_guard_excludes_actual_state_gc_until_drop() {
    let pair = Pair::with_propagation_profile("included", false, true).await;
    let result = std::panic::AssertUnwindSafe(async {
        let (master, shards) = pair.apply_by_normal_clients().await;
        let custody = repair_mc_final(pair.receiver.clone(), request(&pair).await).await.unwrap();
        let keeper = pair.receiver.shard_states_keeper();
        keeper.test_retire_history_state(pair.master.id());
        let parent_protected = !keeper.allow_state_gc(&pair.anchor).unwrap();
        let target_protected = !keeper.allow_state_gc(pair.master.id()).unwrap();
        drop(custody);
        let target_released = keeper.allow_state_gc(pair.master.id()).unwrap();
        pair.receiver.clone().wait_stop().await.unwrap();
        master.await.unwrap();
        shards.await.unwrap();
        assert!(parent_protected && target_protected, "actual resolver must honor live state pins");
        assert!(target_released, "guard Drop must release target GC pin");
    })
    .catch_unwind()
    .await;
    pair.receiver.clone().wait_stop().await.unwrap();
    pair.provider.clone().wait_stop().await.unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mc_live_repair_missing_root_preflights_budget_before_rebuilding_durable_state() {
    let mut pair = Pair::with_propagation_profile("included", false, true).await;
    let result = std::panic::AssertUnwindSafe(async {
        let (master, shards) = pair.apply_by_normal_clients().await;
        let expected = request(&pair).await;
        // Real GC removes the target dynamic state; the zerostate parent remains.
        pair.receiver.shard_states_keeper().test_retire_history_state(pair.master.id());
        tokio::time::timeout(Duration::from_secs(15), async {
            while pair.receiver.db().test_contains_dynamic_state_record(pair.master.id()).unwrap() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("real GC must remove target state record");
        pair.receiver.clone().wait_stop().await.unwrap();
        master.await.unwrap();
        shards.await.unwrap();
        drop(std::mem::replace(&mut pair.receiver, pair.provider.clone()));
        pair.receiver = open_engine(&pair._dir.path().join("receiver")).await;
        // Local body/fullproof still exist, so no network setup is needed here.
        assert!(!pair.receiver.db().test_contains_dynamic_state_record(pair.master.id()).unwrap());
        crate::publication_repair::limit_next_candidate_for_test(&pair.receiver, 0);
        let failure = repair_mc_final(pair.receiver.clone(), expected.clone()).await;
        assert!(
            matches!(failure, Err(ref error) if error.to_string().contains("cell/byte budget"))
        );
        assert!(
            !pair.receiver.db().test_contains_dynamic_state_record(pair.master.id()).unwrap(),
            "over-budget candidate must not create a durable target state"
        );
        let custody = repair_mc_final(pair.receiver.clone(), expected).await.unwrap();
        assert_eq!(custody.state_root(), &pair.master_state_root);
        assert!(pair.receiver.db().test_contains_dynamic_state_record(pair.master.id()).unwrap());
        drop(custody);
        pair.receiver.clone().wait_stop().await.unwrap();
        drop(std::mem::replace(&mut pair.receiver, pair.provider.clone()));
        pair.receiver = open_engine(&pair._dir.path().join("receiver")).await;
        assert_eq!(
            pair.receiver.load_state(pair.master.id()).await.unwrap().root_cell().repr_hash(),
            &pair.master_state_root
        );
    })
    .catch_unwind()
    .await;
    pair.receiver.clone().wait_stop().await.unwrap();
    pair.provider.clone().wait_stop().await.unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
