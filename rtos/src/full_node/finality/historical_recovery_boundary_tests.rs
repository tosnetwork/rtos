// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Real Engine boundary branches. The short replay fixture exercises the same
//! production loop with a lower instance-only limit, not a 128/129-block chain.
use super::*;
use crate::historical_recovery::Request;

fn source_files(engine: &Engine) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
    let path = Path::new(engine.db_root_dir().unwrap()).join("catchains");
    if path.exists() {
        retained_source_bytes(&path)
    } else {
        Default::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "actual Engine checkpoint boundary; RTOS_PUBLIC_FIXTURE_SIGNER required"]
async fn historical_recovery_real_init_pin_rejects_earlier_anchor() {
    let signer = std::env::var("RTOS_PUBLIC_FIXTURE_SIGNER").unwrap();
    let recovery: serde_json::Value =
        serde_json::from_str(include_str!("testdata/v2-propagation-recovery.json")).unwrap();
    let zero_bytes = decode(&recovery["state_boc"]);
    let zero_root = read_single_root_boc(&zero_bytes).unwrap();
    let zero = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        0,
        zero_root.repr_hash().clone(),
        UInt256::calc_file_hash(&zero_bytes),
    );
    let state = ShardStateUnsplit::construct_from_cell(zero_root.clone()).unwrap();
    let extra = state.read_custom().unwrap().unwrap();
    let creator = extra.config.validator_set().unwrap().list()[0].validator_id().unwrap();
    let (init, init_root, row) = chain::successor(
        &signer,
        &zero,
        &zero_root,
        true,
        0,
        extra.validator_info.catchain_seqno,
        &creator,
    );
    let dir = tempfile::tempdir().unwrap();
    write_recovery_config(dir.path(), &zero, false);
    let path = dir.path().join("global.json");
    let mut global: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    global["validator"]["init_block"] = serde_json::json!({"workchain":-1,"shard":init.shard().shard_prefix_with_tag() as i64,"seqno":init.seq_no(),"root_hash":base64_encode(init.root_hash.as_slice()),"file_hash":base64_encode(init.file_hash.as_slice())});
    std::fs::write(path, serde_json::to_vec(&global).unwrap()).unwrap();
    let path = dir.path().join("config.json");
    let mut config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    config["boot_from_zerostate"] = false.into();
    std::fs::write(path, serde_json::to_vec(&config).unwrap()).unwrap();
    let engine = open_engine(dir.path()).await;
    let result = std::panic::AssertUnwindSafe(async {
        assert_eq!(engine.init_mc_block_id(), &init);
        assert_eq!(engine.zerostate_id(), &zero);
        let block = fixture_block(&row);
        let proof = BlockProofStuff::deserialize(&init, decode(&row["proof_boc"]), false).unwrap();
        let handle = engine.store_block(&block).await.unwrap().to_any();
        engine.store_block_proof(&init, Some(handle.clone()), &proof).await.unwrap();
        let init_state = ShardStateStuff::from_root_cell(
            init.clone(),
            init_root.clone(),
            #[cfg(feature = "telemetry")]
            engine.engine_telemetry(),
            engine.engine_allocated(),
        )
        .unwrap();
        engine.store_state(&handle, init_state).await.unwrap();
        tokio::time::timeout(Duration::from_secs(60), async {
            while !handle.has_saved_state()
                || !engine.db().test_contains_dynamic_state_record(&init).unwrap()
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("pinned state must finish physical persistence before bounded load");
        let head = engine.load_last_applied_mc_block_id().unwrap();
        let source = source_files(engine.as_ref());
        let capsule = Path::new(engine.db_root_dir().unwrap()).join("retired-history-v1");
        assert!(!capsule.exists());
        let request = Request::new(engine.clone()).await.unwrap();
        let error =
            request.prepare(&zero).await.err().expect("actual before-init request must fail");
        assert_eq!(error.to_string(), "Historical recovery outside exact pinned masterchain");
        assert!(request.verified(&zero).unwrap().is_none());
        assert!(!capsule.exists());
        assert_eq!(source_files(engine.as_ref()), source);
        assert_eq!(engine.load_last_applied_mc_block_id().unwrap(), head);
        // The same request admits and authentically checks the exact pinned key block.
        let accepted = request.prepare(&init).await.unwrap();
        assert_eq!(accepted.state().root_cell().repr_hash(), init_root.repr_hash());
        assert_eq!(accepted.state().block_id(), &init);
        assert_eq!(engine.load_last_applied_mc_block_id().unwrap(), head);
        assert_eq!(source_files(engine.as_ref()), source);
        assert!(!capsule.exists());
    })
    .catch_unwind()
    .await;
    stop_fixture_engines(vec![engine]).await;
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "actual Engine/network short-chain replay boundary; RTOS_PUBLIC_FIXTURE_SIGNER required"]
async fn historical_recovery_real_short_chain_replay_limit_then_default_success() {
    let signer = std::env::var("RTOS_PUBLIC_FIXTURE_SIGNER").unwrap();
    let pair = Pair::with_source_options("included", false, true, true, true).await;
    let result = std::panic::AssertUnwindSafe(async {
        let engine = &pair.provider;
        engine.clone().download_and_apply_block(pair.master.id(), 1, false).await.unwrap();
        let first = engine.load_state(pair.master.id()).await.unwrap();
        let first_bytes = rtos_block::write_boc(first.root_cell()).unwrap();
        let first_root = read_single_root_boc(&first_bytes).unwrap();
        let config = first.config_params().unwrap();
        let creator = config.validator_set().unwrap().list()[0].validator_id().unwrap();
        let cc = pair.master.block().unwrap().read_info().unwrap().gen_catchain_seqno();
        let mut target = pair.master.id().clone();
        let mut target_root = first_root;
        let mut middle = None;
        for peer in [&pair.receiver, pair.observer.as_ref().unwrap()] {
            peer.clone().download_and_apply_block(pair.master.id(), 1, false).await.unwrap();
            let handle = peer.load_block_handle(pair.master.id()).unwrap().unwrap();
            peer.db().store_shard_state_persistent_raw(&handle, &first_bytes, None).await.unwrap();
        }
        for _ in 0..2 {
            let (id, root, row) =
                chain::successor(&signer, &target, &target_root, false, 0, cc, &creator);
            let block = fixture_block(&row);
            let proof =
                BlockProofStuff::deserialize(&id, decode(&row["proof_boc"]), false).unwrap();
            for peer in [&pair.receiver, pair.observer.as_ref().unwrap()] {
                let handle = peer.store_block(&block).await.unwrap().to_any();
                peer.store_block_proof(&id, Some(handle), &proof).await.unwrap();
                peer.clone().download_and_apply_block(&id, id.seq_no(), false).await.unwrap();
            }
            if id.seq_no() == 2 {
                middle = Some(id.clone());
            }
            target = id;
            target_root = root;
        }
        assert_eq!(target.seq_no(), 3);
        assert_eq!(engine.init_mc_block_id().seq_no(), 0);
        assert!(!engine.db().has_repair_state_index(&target).unwrap());
        assert!(!engine.db().test_contains_dynamic_state_record(&target).unwrap());
        let head = engine.load_last_applied_mc_block_id().unwrap();
        let source = source_files(engine.as_ref());
        let capsule = Path::new(engine.db_root_dir().unwrap()).join("retired-history-v1");
        assert!(!capsule.exists());
        let middle = middle.unwrap();
        let peers = [&pair.receiver, pair.observer.as_ref().unwrap()];
        let starts: Vec<_> = peers
            .iter()
            .map(|peer| peer.overlays_router().unwrap().test_pss_observations().len())
            .collect();
        let before_pairs: usize =
            peers.iter().map(|peer| peer.overlays_router().unwrap().test_bounded_queries()).sum();
        let request = Request::test_with_replay_limit(engine.clone(), 1).await.unwrap();
        let budget = request.budget().clone();
        let error =
            request.prepare(&target).await.err().expect("actual ancestry loop must hit its bound");
        assert_eq!(error.to_string(), "No available snapshot within bounded historical ancestry");
        let observed: Vec<_> = peers
            .iter()
            .enumerate()
            .flat_map(|(index, peer)| {
                peer.overlays_router()
                    .unwrap()
                    .test_pss_observations()
                    .into_iter()
                    .skip(starts[index])
            })
            .collect();
        assert!(observed.iter().any(|(id, offset, _)| id == &target && offset.is_none()));
        assert!(
            observed.iter().any(|(id, offset, _)| id == &middle && offset.is_none()),
            "must reach MC2 after fetching the real MC3 pair"
        );
        assert!(
            !observed.iter().any(|(id, _, _)| id == pair.master.id()),
            "limit1 must stop before the MC1 snapshot"
        );
        let after_pairs: usize =
            peers.iter().map(|peer| peer.overlays_router().unwrap().test_bounded_queries()).sum();
        assert!(after_pairs > before_pairs, "actual remote successor pair must be consumed");
        assert!(Arc::ptr_eq(&budget, request.budget()));
        assert!(request.verified(&target).unwrap().is_none());
        assert!(!capsule.exists());
        assert_eq!(engine.load_last_applied_mc_block_id().unwrap(), head);
        assert_eq!(source_files(engine.as_ref()), source);
        drop(request);
        // Same actual peers and complete chain, unchanged production default (128).
        let normal = Request::new(engine.clone()).await.unwrap();
        let recovered = normal.prepare(&target).await.unwrap();
        assert!(
            peers
                .iter()
                .flat_map(|peer| peer.overlays_router().unwrap().test_pss_observations())
                .any(|(id, offset, size)| &id == pair.master.id()
                    && offset == Some(0)
                    && size.is_some()),
            "default recovery must read the real MC1 snapshot"
        );
        assert_eq!(recovered.state().block_id(), &target);
        assert_eq!(recovered.state().root_cell().repr_hash(), target_root.repr_hash());
        assert_eq!(engine.load_last_applied_mc_block_id().unwrap(), head);
        assert_eq!(source_files(engine.as_ref()), source);
        assert!(!capsule.exists(), "prepare alone cannot mint durable source admission");
        assert!(!engine.db().has_repair_state_index(&target).unwrap());
        assert!(!engine.db().test_contains_dynamic_state_record(&target).unwrap());
    })
    .catch_unwind()
    .await;
    let mut engines = vec![pair.provider.clone(), pair.receiver.clone()];
    if let Some(observer) = &pair.observer {
        engines.push(observer.clone());
    }
    stop_fixture_engines(engines).await;
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
