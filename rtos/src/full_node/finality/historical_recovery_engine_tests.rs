// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Actual source certificate debt and exact ancestor PSS replay. These fixtures
//! never construct historical admission or authenticated state capabilities.
use super::*;

async fn recover_source(remote_successor: bool) {
    let signer = std::env::var("RTOS_PUBLIC_FIXTURE_SIGNER").unwrap();
    let pair = Pair::with_source_options("included", false, true, true, true).await;
    let run = std::panic::AssertUnwindSafe(async {
        let engine = &pair.provider;
        engine.clone().download_and_apply_block(pair.master.id(), 1, false).await.unwrap();
        let first = engine.load_state(pair.master.id()).await.unwrap();
        let config = first.config_params().unwrap();
        let cc = pair.master.block().unwrap().read_info().unwrap().gen_catchain_seqno();
        let creator = config.validator_set().unwrap().list()[0].validator_id().unwrap();
        let (target, target_root, row) =
            chain::successor(&signer, pair.master.id(), first.root_cell(), false, 0, cc, &creator);
        let block = fixture_block(&row);
        let proof =
            BlockProofStuff::deserialize(&target, decode(&row["proof_boc"]), false).unwrap();
        for owner in [&pair.provider, &pair.receiver, pair.observer.as_ref().unwrap()] {
            owner.clone().download_and_apply_block(pair.master.id(), 1, false).await.unwrap();
            let handle = owner.store_block(&block).await.unwrap().to_any();
            owner.store_block_proof(&target, Some(handle), &proof).await.unwrap();
            owner.clone().download_and_apply_block(&target, 2, false).await.unwrap();
        }
        // Only MC1 has a persistent snapshot on the peer. MC2 must be replayed.
        for peer in [&pair.receiver, pair.observer.as_ref().unwrap()] {
            peer.clone().download_and_apply_block(pair.master.id(), 1, false).await.unwrap();
            let handle = peer.load_block_handle(pair.master.id()).unwrap().unwrap();
            peer.db()
                .store_shard_state_persistent_raw(
                    &handle,
                    &rtos_block::write_boc(first.root_cell()).unwrap(),
                    None,
                )
                .await
                .unwrap();
        }
        let (committee, _) = config
            .validator_set()
            .unwrap()
            .calc_subset(&config.catchain_config().unwrap(), SHARD_FULL, -1, cc)
            .unwrap();
        let local = engine
            .network()
            .context()
            .stack
            .adnl
            .key_by_tag(NodeNetwork::TAG_OVERLAY_KEY)
            .unwrap()
            .id()
            .clone();
        let runtime = Arc::new(
            AuthenticatedSessionRuntime::from_authenticated_config(
                SessionNetworkPin { global_id: -239, zerostate: pair.anchor.clone() },
                config,
                rtos_api::session_identity::SessionCoordinates {
                    shard: target.shard(),
                    catchain_seqno: cc,
                    vertical_seqno: 0,
                    last_key_block_seqno: 0,
                    new_catchain_ids: false,
                },
                committee,
                local,
            )
            .unwrap()
            .bind_recovery_anchor(target.clone())
            .unwrap(),
        );
        let namespace = PathBuf::from(
            runtime
                .runtime_directory(
                    Path::new(engine.db_root_dir().unwrap()).join("catchains").to_str().unwrap(),
                )
                .unwrap(),
        );
        let (next, _, row) =
            chain::successor(&signer, &target, &target_root, false, 0, cc, &creator);
        let next_block = fixture_block(&row);
        let next_proof =
            BlockProofStuff::deserialize(&next, decode(&row["proof_boc"]), false).unwrap();
        let draft = FinalizedDeliveryDraft {
            block_id: next.clone(),
            source_info: BlockSourceInfo {
                source: ValidatorIdentity::from_descriptor(&runtime.committee()[0]).unwrap(),
                priority: BlockCandidatePriority {
                    round: next.seq_no(),
                    first_block_round: 0,
                    priority: 0,
                },
            },
            data: ConsensusCommonFactory::create_block_payload(next_block.data().to_vec()),
            finality: SessionFinality::Carrier(next_proof.drain_signatures().unwrap()),
            last_mc_finalized_seqno: 0,
            candidate_already_sent: false,
            created_at_unix_secs: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        let sink = engine.clone().durable_finality_sink(runtime.clone()).await.unwrap();
        let confirm =
            engine.ensure_publication_worker().await.unwrap().delivered_sink(runtime.clone());
        let driver =
            FinalityDeliveryTestDriver::open(runtime.clone(), &namespace, sink, confirm).unwrap();
        driver.prepare_intents(false).unwrap();
        driver.bind_start(target.clone()).unwrap();
        driver.retain_final_cert(&draft, &[target.clone()]).unwrap();
        drop(driver);
        let record = simplex::finality_recovery::scan_finality_recovery_namespace(&namespace)
            .unwrap()
            .expect("real retained FinalCert provides exact recovery locator");
        let head = engine.load_last_applied_mc_block_id().unwrap();
        assert!(crate::retired_history::authenticate_capsule_with_budget(
            engine.as_ref(),
            &target,
            None
        )
        .await
        .unwrap()
        .is_none());
        engine.shard_states_keeper().test_retire_history_state(&target);
        tokio::time::timeout(Duration::from_secs(20), async {
            while engine.db().test_contains_dynamic_state_record(&target).unwrap() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("real GC must remove historical target before recovery");
        if remote_successor {
            engine.db().test_remove_archived_artifacts(&target).await.unwrap();
            let handle = engine.load_block_handle(&target).unwrap().unwrap();
            assert!(handle.has_data() && handle.has_proof() && handle.is_archived());
            let error = crate::publication_repair::read_pair(
                engine.as_ref(),
                &target,
                &crate::history_read_budget::HistoryReadBudget::new(Default::default()),
            )
            .await
            .err()
            .expect("actual archived entry absence must be observable");
            assert!(
                error
                    .downcast_ref::<storage::archives::bounded_read::ArchiveArtifactMissing>()
                    .is_some(),
                "{error:#}"
            );
        }
        let authenticated =
            engine.clone().authenticate_retired_source_with_history(record.clone()).await.unwrap();
        assert_eq!(authenticated.runtime().session_id(), runtime.session_id());
        assert_eq!(engine.load_last_applied_mc_block_id().unwrap(), head);
        assert!(
            !engine.db().test_contains_dynamic_state_record(&target).unwrap(),
            "detached recovery must not rewrite ordinary state storage"
        );
        assert_eq!(
            crate::retired_history::authenticate_capsule_with_budget(
                engine.as_ref(),
                &target,
                None
            )
            .await
            .unwrap()
            .unwrap()
            .state()
            .root_cell()
            .repr_hash(),
            target_root.repr_hash()
        );
        (record, target, target_root.repr_hash().clone())
    })
    .catch_unwind()
    .await;
    pair.stop_all().await;
    let (record, target, expected) = run.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    let Pair { _dir: directory, receiver, provider, observer, .. } = pair;
    drop(receiver);
    drop(provider);
    drop(observer);
    // No peer is reopened: this must authenticate solely from durable capsule.
    let cold = open_engine(&directory.path().join("provider")).await;
    let result = std::panic::AssertUnwindSafe(async {
        assert!(!cold.db().test_contains_dynamic_state_record(&target).unwrap());
        cold.clone().authenticate_retired_source_with_history(record).await.unwrap();
        assert_eq!(
            crate::retired_history::authenticate_state(cold.as_ref(), &target)
                .await
                .unwrap()
                .state()
                .root_cell()
                .repr_hash(),
            &expected
        );
    })
    .catch_unwind()
    .await;
    cold.clone().wait_stop().await.unwrap();
    drop(cold);
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real Engine/network historical replay; RTOS_PUBLIC_FIXTURE_SIGNER required"]
async fn historical_recovery_source_remote_ancestor_replay_and_cold_capsule() {
    recover_source(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real Engine/network historical replay; RTOS_PUBLIC_FIXTURE_SIGNER required"]
async fn historical_recovery_source_remote_successor_missing_local_entries() {
    recover_source(true).await;
}
