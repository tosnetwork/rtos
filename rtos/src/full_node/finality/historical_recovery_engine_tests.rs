// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Actual source certificate debt and exact ancestor PSS replay. These fixtures
//! never construct historical admission or authenticated state capabilities.
use super::*;

fn retained_source_bytes(namespace: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
    let mut result = std::collections::BTreeMap::new();
    let mut dirs = vec![namespace.to_owned()];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            } else {
                result.insert(path.clone(), std::fs::read(path).unwrap());
            }
        }
    }
    result
}

async fn recover_source(mode: u8) {
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
        if mode == 3 {
            tokio::time::timeout(Duration::from_secs(60), async {
                loop {
                    if driver.poll(draft.clone()).unwrap() && driver.counts().unwrap().1 == 1 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("real node WAL ACK must precede full-canonical recovery");
        }
        drop(driver);
        let closing = if mode == 3 {
            let locators =
                simplex::finality_delivery::scan_finality_closures_namespace(&namespace).unwrap();
            assert_eq!(locators.len(), 1);
            Some(locators[0].request().unwrap())
        } else {
            None
        };
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
        if mode == 1 || mode == 2 {
            if mode == 1 {
                engine.db().test_remove_archived_artifacts(&target).await.unwrap();
            } else {
                use storage::archives::{package_id::PackageId, ARCHIVE_SLICE_SIZE};
                engine.db().archive_block(&target, None).await.unwrap();
                let pack = PackageId::for_block(0)
                    .full_path(Path::new(engine.db_root_dir().unwrap()), target.shard())
                    .unwrap();
                assert!(pack.exists(), "real applied MC1/MC2 must occupy the GC control package");
                let cutoff = BlockIdExt::with_params(
                    ShardIdent::masterchain(),
                    ARCHIVE_SLICE_SIZE + 3,
                    UInt256::default(),
                    UInt256::default(),
                );
                engine.db().archive_gc(&cutoff).await.unwrap();
                assert!(!pack.exists(), "actual archive GC must remove local historical package");
            }
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
        if let Some(request) = &closing {
            let worker = engine.ensure_publication_worker().await.unwrap();
            for altered in 0..2 {
                let mut bad = request.clone();
                if altered == 0 {
                    bad.source_digest = UInt256::default();
                } else {
                    bad.domain.pin.global_id += 1;
                }
                assert!(worker
                    .authorize_closing_history_debt(
                        bad,
                        runtime.clone(),
                        crate::history_read_budget::HistoryReadBudget::new(Default::default())
                    )
                    .await
                    .is_err());
                assert!(crate::retired_history::authenticate_capsule_with_budget(
                    engine.as_ref(),
                    &target,
                    None
                )
                .await
                .unwrap()
                .is_none());
            }
            // Only the actual store's exact full canonical debt can authorize
            // persistence. Pending effects are deliberately not marked complete.
            let authenticated = engine
                .clone()
                .authenticate_closing_source_with_history(request.clone(), namespace.clone())
                .await
                .unwrap();
            assert_eq!(authenticated.session_id(), runtime.session_id());
            let domain = OutboxDomain {
                zerostate: pair.anchor.clone(),
                global_id: -239,
                wire_profile: WireProfile::T0,
            };
            let (entries, closes) = inspect_closure_progress(engine.db(), &domain).unwrap();
            assert!(!entries.is_empty(), "history recovery does not release full canonical debt");
            assert!(closes.is_empty(), "history storage must not mint close/custody authority");
        } else {
            if mode == 4 {
                use crate::historical_recovery::test_hooks;
                let before = retained_source_bytes(&namespace);
                let baseline = test_hooks::available_requests();
                let mut control = test_hooks::install(engine.as_ref(), true, false);
                let owner = engine.clone();
                let source = record.clone();
                let observer = tokio::spawn(async move {
                    owner.authenticate_retired_source_with_history(source).await
                });
                tokio::time::timeout(Duration::from_secs(60), control.entered.take().unwrap())
                    .await
                    .expect("actual commit owner must reach gate")
                    .unwrap();
                observer.abort();
                assert!(observer.await.unwrap_err().is_cancelled());
                assert_eq!(
                    test_hooks::available_requests() + 1,
                    baseline,
                    "cancelled observer must not return live request admission"
                );
                assert!(
                    simplex::finality_recovery::scan_finality_recovery_namespace(&namespace)
                        .unwrap()
                        .is_none(),
                    "real source owner remains locked until actual IO completes"
                );
                assert_eq!(retained_source_bytes(&namespace), before);
                control.release();
                tokio::time::timeout(Duration::from_secs(60), control.completed())
                    .await
                    .expect("cancelled observer's actual owned commit must finish");
                assert_eq!(test_hooks::available_requests(), baseline);
                assert!(simplex::finality_recovery::scan_finality_recovery_namespace(&namespace)
                    .unwrap()
                    .is_some());
                assert_eq!(control.syncs(), 1);
                assert_eq!(retained_source_bytes(&namespace), before);
            }
            if mode == 5 {
                let before = retained_source_bytes(&namespace);
                let control =
                    crate::historical_recovery::test_hooks::install(engine.as_ref(), false, true);
                let error = engine
                    .clone()
                    .authenticate_retired_source_with_history(record.clone())
                    .await
                    .err()
                    .expect("uncertain capsule sync must refuse success");
                assert_eq!(
                    error.downcast_ref::<std::io::Error>().and_then(|e| e.raw_os_error()),
                    Some(5)
                );
                assert_eq!(control.syncs(), 1);
                assert_eq!(retained_source_bytes(&namespace), before);
                // The first attempt genuinely persisted bytes before the
                // application-visible EIO. Reading them is not durability ACK:
                // retry must execute the same real file/directory barriers.
                engine
                    .clone()
                    .authenticate_retired_source_with_history(record.clone())
                    .await
                    .unwrap();
                assert_eq!(control.syncs(), 2);
                assert_eq!(retained_source_bytes(&namespace), before);
            }
            let authenticated = engine
                .clone()
                .authenticate_retired_source_with_history(record.clone())
                .await
                .unwrap();
            assert_eq!(authenticated.runtime().session_id(), runtime.session_id());
        }
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
        (record, target, target_root.repr_hash().clone(), closing, namespace)
    })
    .catch_unwind()
    .await;
    pair.stop_all().await;
    let (record, target, expected, closing, namespace) =
        run.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    let Pair { _dir: directory, receiver, provider, observer, .. } = pair;
    drop(receiver);
    drop(provider);
    drop(observer);
    // No peer is reopened: this must authenticate solely from durable capsule.
    let cold = open_engine(&directory.path().join("provider")).await;
    let result = std::panic::AssertUnwindSafe(async {
        assert!(!cold.db().test_contains_dynamic_state_record(&target).unwrap());
        if let Some(request) = closing {
            cold.clone()
                .authenticate_closing_source_with_history(request, namespace)
                .await
                .unwrap();
        } else {
            cold.clone().authenticate_retired_source_with_history(record).await.unwrap();
        }
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
    recover_source(0).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real Engine/network historical replay; RTOS_PUBLIC_FIXTURE_SIGNER required"]
async fn historical_recovery_source_remote_successor_missing_local_entries() {
    recover_source(1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real Engine/network/archive GC; RTOS_PUBLIC_FIXTURE_SIGNER required"]
async fn historical_recovery_source_actual_pack_gc_remote_replay_and_cold_capsule() {
    recover_source(2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real node WAL/full canonical authorization; RTOS_PUBLIC_FIXTURE_SIGNER required"]
async fn historical_recovery_full_canonical_exact_debt_and_domain_controls() {
    recover_source(3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real owned historical commit cancellation; RTOS_PUBLIC_FIXTURE_SIGNER required"]
async fn historical_recovery_cancelled_observer_retains_source_and_budget_until_commit() {
    recover_source(4).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "actual capsule sync boundary uncertainty; RTOS_PUBLIC_FIXTURE_SIGNER required"]
async fn historical_recovery_uncertain_sync_preserves_debt_and_rebarriers_before_retry() {
    recover_source(5).await;
}
