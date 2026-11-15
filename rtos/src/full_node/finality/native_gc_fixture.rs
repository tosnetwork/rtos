// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Authenticated future states for tests of GC below an already established floor.
//! This fixture does not exercise the driver's 1024-block advancement condition.
use super::*;

fn history() -> serde_json::Value {
    serde_json::from_str(include_str!("testdata/native-gc-history.json")).unwrap()
}

fn zero_id(bytes: &[u8]) -> BlockIdExt {
    let root = read_single_root_boc(bytes).unwrap();
    let state = ShardStateUnsplit::construct_from_cell(root.clone()).unwrap();
    BlockIdExt::with_params(
        state.shard().clone(),
        0,
        root.repr_hash().clone(),
        UInt256::calc_file_hash(bytes),
    )
}

fn wc_row(row: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "block_boc": row["wc_block_boc"], "candidate": row["wc_candidate"],
        "session": row["wc_session"], "subset_hash": row["wc_subset_hash"],
        "signatures": row["wc_signatures"],
    })
}

pub(super) async fn pair() -> Pair {
    let _ = env_logger::builder().is_test(true).try_init();
    let data = history();
    assert_eq!(
        data["reference_commit"],
        include_str!("../../../../ci/conformance/REFERENCE").trim()
    );
    let rows = data["cases"].as_array().unwrap();
    assert_eq!(rows.len(), 4);
    let mc_bytes = decode(&data["zerostate"]);
    let wc_bytes = decode(&data["wc_zerostate"]);
    let anchor = zero_id(&mc_bytes);
    let mc_root = read_single_root_boc(&mc_bytes).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let receiver_dir = dir.path().join("receiver");
    let provider_dir = dir.path().join("provider");
    for (path, seed) in [(&provider_dir, 0x60), (&receiver_dir, 0x70)] {
        write_recovery_config(path, &anchor, true);
        configure_fixture_transport(path, seed, &mc_root);
        let file = path.join("config.json");
        let mut config: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        config["gc"] = serde_json::json!({"enable_for_archives": false,
            "enable_for_shard_state_persistent": false,
            "cells_gc_config": {"gc_interval_sec": 1, "cells_lifetime_sec": 0}});
        std::fs::write(file, serde_json::to_vec(&config).unwrap()).unwrap();
    }
    let receiver = open_engine(&receiver_dir).await;
    let provider = open_engine(&provider_dir).await;
    let result = std::panic::AssertUnwindSafe(async {
        for engine in [&receiver, &provider] {
            for bytes in [&mc_bytes, &wc_bytes] {
                let id = zero_id(bytes);
                let state = ShardStateStuff::from_root_cell(
                    id,
                    read_single_root_boc(bytes).unwrap(),
                    #[cfg(feature = "telemetry")]
                    engine.engine_telemetry(),
                    engine.engine_allocated(),
                )
                .unwrap();
                let (_, handle) = engine.store_zerostate(state, bytes).await.unwrap();
                engine.set_applied(&handle, 0).await.unwrap();
            }
            engine.save_last_applied_mc_block_id(&anchor).unwrap();
            engine.save_shard_client_mc_block_id(&anchor).unwrap();
            engine.set_test_chain_time(Some(1005));
        }
        // Supply transport reachability before normal applied-config activation.
        for (local, remote) in [(&receiver, &provider), (&provider, &receiver)] {
            let adnl = &local.network().context().stack.adnl;
            let peer = &remote.network().context().stack.adnl;
            let key = adnl.key_by_tag(NodeNetwork::TAG_OVERLAY_KEY).unwrap();
            let remote_key = peer.key_by_tag(NodeNetwork::TAG_OVERLAY_KEY).unwrap();
            adnl.add_peer(key.id(), peer.ip_address_adnl(), None, &remote_key).unwrap();
            local
                .network()
                .context()
                .stack
                .quic
                .as_ref()
                .unwrap()
                .add_peer_key(
                    remote_key.id().clone(),
                    remote.network().context().quic_address.unwrap(),
                )
                .unwrap();
        }
        for engine in [&receiver, &provider] {
            engine.initialize_test_full_node_overlays().await.unwrap();
            assert!(crate::network::check_sync_for_listen_bcasts(engine.as_ref()));
            engine.overlays_router().unwrap().refresh_fast_sync_from_applied_state().await.unwrap();
        }
        let mut previous_mc = anchor.clone();
        let mut previous_wc = zero_id(&wc_bytes);
        for row in rows {
            for (block, proof, previous) in [
                {
                    let block = fixture_block(row);
                    let proof = full_proof(&block, fixture_carrier(row));
                    (block, proof, &mut previous_mc)
                },
                {
                    let block = fixture_block(&wc_row(row));
                    let proof =
                        crate::validator::accept_block::create_new_proof_link(&block).unwrap();
                    (block, proof, &mut previous_wc)
                },
            ] {
                let handle = provider.store_block(&block).await.unwrap().to_any();
                provider.store_block_proof(block.id(), Some(handle), &proof).await.unwrap();
                let parent = provider.load_block_handle(previous).unwrap().unwrap();
                provider.store_block_next1(&parent, block.id()).unwrap();
                *previous = block.id().clone();
            }
        }
        for (local, remote) in [(&receiver, &provider), (&provider, &receiver)] {
            let peer = remote
                .network()
                .context()
                .stack
                .adnl
                .key_by_tag(NodeNetwork::TAG_OVERLAY_KEY)
                .unwrap();
            for shard in
                [ShardIdent::masterchain(), ShardIdent::with_tagged_prefix(0, SHARD_FULL).unwrap()]
            {
                local
                    .overlay_client(&shard)
                    .await
                    .unwrap()
                    .overlay_client()
                    .neighbours()
                    .add(peer.id().clone())
                    .unwrap();
            }
        }
        refresh_fixture_public_advertisements(
            &[&receiver, &provider],
            &[&ShardIdent::masterchain(), &ShardIdent::with_tagged_prefix(0, SHARD_FULL).unwrap()],
        )
        .await;
    })
    .catch_unwind()
    .await;
    if let Err(panic) = result {
        stop_fixture_engines(vec![receiver.clone(), provider.clone()]).await;
        std::panic::resume_unwind(panic);
    }
    Pair {
        _dir: dir,
        receiver,
        provider,
        observer: None,
        anchor,
        shard: fixture_block(&wc_row(&rows[1])),
        shard_carrier: fixture_carrier(&wc_row(&rows[1])),
        shard_state_root: read_single_root_boc(&decode(&rows[1]["wc_state_boc"]))
            .unwrap()
            .repr_hash()
            .clone(),
        master: fixture_block(&rows[1]),
        master_state_root: read_single_root_boc(&decode(&rows[1]["state_boc"]))
            .unwrap()
            .repr_hash()
            .clone(),
        applied_through: Some(fixture_block(&rows[3]).id().clone()),
    }
}

/// Model an existing native floor from boot at MC3 followed by application of
/// MC4. All blocks/states were received and authenticated by normal clients.
/// This is a controlled GC boundary, not natural floor advancement on 4 blocks.
pub(super) fn establish_floor(engine: &Arc<Engine>) {
    let data = history();
    let rows = data["cases"].as_array().unwrap();
    let floor = fixture_block(&rows[2]);
    let head = fixture_block(&rows[3]);
    assert_eq!(engine.load_last_applied_mc_block_id().unwrap().as_deref(), Some(head.id()));
    assert_eq!(engine.load_shard_client_mc_block_id().unwrap().as_deref(), Some(head.id()));
    for (row, block) in [(&rows[2], &floor), (&rows[3], &head)] {
        let handle = engine.load_block_handle(block.id()).unwrap().unwrap();
        assert!(handle.is_applied() && handle.has_data() && handle.has_proof());
        let state = engine.db().load_shard_state_dynamic(block.id()).unwrap();
        assert_eq!(
            state.root_cell().repr_hash(),
            read_single_root_boc(&decode(&row["state_boc"])).unwrap().repr_hash()
        );
    }
    let state = engine.db().load_shard_state_dynamic(head.id()).unwrap();
    assert!(state.has_prev_block(floor.id()).unwrap());
    let keeper = engine.shard_states_keeper();
    let guard = keeper.pin_cleanup_candidate(floor.id()).unwrap();
    keeper.adopt_cleanup_floor(floor.id(), guard, keeper.cleanup_floor_epoch()).unwrap();
    assert_eq!(keeper.cleanup_floor().unwrap().0, *floor.id());
}
