// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! First cold closing-owner recovery with full canonical debt, no source FinalCert
//! locator and no prebuilt history capsule. Runtime is never supplied on reopen.
use super::*;

fn capsule_manifests(engine: &Engine) -> usize {
    let root = PathBuf::from(engine.db_root_dir().unwrap()).join("retired-history-v1");
    let entries = match std::fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return 0,
        Err(error) => panic!("capsule directory {}: {error}", root.display()),
    };
    entries
        .filter_map(|entry| {
            let path = entry.unwrap().path();
            (path.extension().and_then(|s| s.to_str()) == Some("json")).then_some(path)
        })
        .count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "first-cold actual closing owner and remote history; RTOS_PUBLIC_FIXTURE_SIGNER required"]
async fn historical_closing_first_cold_full_canonical_recovers_without_source_runtime() {
    let signer = std::env::var("RTOS_PUBLIC_FIXTURE_SIGNER").unwrap();
    let pair = Pair::with_source_options("included", false, true, true, true).await;
    let prepared = std::panic::AssertUnwindSafe(async {
        let engine = &pair.provider;
        for peer in [&pair.provider, &pair.receiver, pair.observer.as_ref().unwrap()] {
            peer.clone().download_and_apply_block(pair.master.id(), 1, false).await.unwrap();
        }
        let first = engine.load_state(pair.master.id()).await.unwrap();
        let config = first.config_params().unwrap();
        let cc = pair.master.block().unwrap().read_info().unwrap().gen_catchain_seqno();
        let creator = config.validator_set().unwrap().list()[0].validator_id().unwrap();
        let (target, target_root, row) =
            chain::successor(&signer, pair.master.id(), first.root_cell(), false, 0, cc, &creator);
        let target_block = fixture_block(&row);
        let target_proof =
            BlockProofStuff::deserialize(&target, decode(&row["proof_boc"]), false).unwrap();
        let (head, _, row) =
            chain::successor(&signer, &target, &target_root, false, 0, cc, &creator);
        let head_block = fixture_block(&row);
        let head_proof =
            BlockProofStuff::deserialize(&head, decode(&row["proof_boc"]), false).unwrap();
        for peer in [&pair.provider, &pair.receiver, pair.observer.as_ref().unwrap()] {
            for (block, proof) in [(&target_block, &target_proof), (&head_block, &head_proof)] {
                let handle = peer.store_block(block).await.unwrap().to_any();
                peer.store_block_proof(block.id(), Some(handle), proof).await.unwrap();
                peer.clone()
                    .download_and_apply_block(block.id(), block.id().seq_no(), false)
                    .await
                    .unwrap();
            }
        }
        // A healthy applied MC3 remains available when the cold publication
        // worker loads its domain; only historical MC2 will be collected.
        assert_eq!(engine.load_last_applied_mc_block_id().unwrap().unwrap().as_ref(), &head);
        let snapshot = rtos_block::write_boc(first.root_cell()).unwrap();
        for peer in [&pair.receiver, pair.observer.as_ref().unwrap()] {
            let handle = peer.load_block_handle(pair.master.id()).unwrap().unwrap();
            peer.db().store_shard_state_persistent_raw(&handle, &snapshot, None).await.unwrap();
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
        let draft = FinalizedDeliveryDraft {
            block_id: head.clone(),
            source_info: BlockSourceInfo {
                source: ValidatorIdentity::from_descriptor(&runtime.committee()[0]).unwrap(),
                priority: BlockCandidatePriority {
                    round: head.seq_no(),
                    first_block_round: 0,
                    priority: 0,
                },
            },
            data: ConsensusCommonFactory::create_block_payload(head_block.data().to_vec()),
            finality: SessionFinality::Carrier(head_proof.clone().drain_signatures().unwrap()),
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
        let source =
            FinalityDeliveryTestDriver::open(runtime.clone(), &namespace, sink, confirm).unwrap();
        // Same prepared empty intent directory as the real closure crash fixture.
        // Poll owns actual carrier verification, ACK sync and canonical retention.
        // No unresolved FinalCert is installed to divert startup into source recovery.
        source.prepare_intents(false).unwrap();
        source.bind_start(target.clone()).unwrap();
        tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                if source.poll(draft.clone()).unwrap() && source.counts().unwrap().1 == 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("actual durable ACK and reference must precede shutdown");
        drop(source);
        assert!(simplex::finality_recovery::scan_finality_recovery_namespace(&namespace)
            .unwrap()
            .is_none());
        let locators =
            simplex::finality_delivery::scan_finality_closures_namespace(&namespace).unwrap();
        assert_eq!(locators.len(), 1);
        let original_close = locators[0].request().unwrap();
        assert_eq!(
            original_close.domain.recovery_binding.as_ref().unwrap().governing_masterchain,
            target
        );
        drop(locators);
        let domain = OutboxDomain {
            zerostate: pair.anchor.clone(),
            global_id: -239,
            wire_profile: rtos_api::WireProfile::T0,
        };
        let (entries, closes) = inspect_closure_progress(engine.db(), &domain).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(closes.is_empty(), "full canonical evidence must not already be compact custody");
        assert_eq!(capsule_manifests(engine), 0, "warm setup must never admit historical capsules");
        // Normal apply may return while its PutState is queued. Establish real
        // MC2/MC3 persistence before collecting MC2, so absence proves GC and
        // MC3 stays a healthy ordinary head throughout cold recovery.
        for id in [&target, &head] {
            let handle = engine.load_block_handle(id).unwrap().unwrap();
            tokio::time::timeout(Duration::from_secs(60), async {
                while !handle.has_saved_state()
                    || !engine.db().test_contains_dynamic_state_record(id).unwrap()
                {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .unwrap_or_else(|_| panic!(
                "ordinary state must finish persistence before GC: {id}; saved={}, contains={:?}",
                handle.has_saved_state(), engine.db().test_contains_dynamic_state_record(id)
            ));
            assert!(engine.db().test_contains_dynamic_state_record(id).unwrap());
        }
        engine.shard_states_keeper().test_retire_history_state(&target);
        tokio::time::timeout(Duration::from_secs(20), async {
            while engine.db().test_contains_dynamic_state_record(&target).unwrap() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("historical state must actually be GC'd before first reopen");
        engine.db().test_remove_archived_artifacts(&target).await.unwrap();
        let missing = crate::publication_repair::read_pair(
            engine.as_ref(),
            &target,
            &crate::history_read_budget::HistoryReadBudget::new(Default::default()),
        )
        .await
        .err()
        .expect("removed exact archive artifact must not remain available");
        assert!(
            missing
                .downcast_ref::<storage::archives::bounded_read::ArchiveArtifactMissing>()
                .is_some(),
            "{missing:#}"
        );
        assert_eq!(engine.load_last_applied_mc_block_id().unwrap().unwrap().as_ref(), &head);
        (
            target,
            target_root.repr_hash().clone(),
            head,
            namespace,
            domain,
            original_close,
            entries[0].record.as_ref().clone(),
        )
    })
    .catch_unwind()
    .await;
    if prepared.is_err() {
        pair.stop_all().await;
        std::panic::resume_unwind(prepared.err().unwrap());
    }
    pair.provider.clone().wait_stop().await.unwrap();
    let (target, expected, head, namespace, domain, original_close, original_record) =
        prepared.unwrap();
    let Pair { _dir: directory, receiver, provider, observer, master, .. } = pair;
    let ancestor = master.id().clone();
    drop(provider);
    let peers = [&receiver, observer.as_ref().unwrap()];
    let query_count = || {
        peers
            .iter()
            .map(|peer| peer.overlays_router().unwrap().test_bounded_queries())
            .sum::<usize>()
    };
    let queries_before = query_count();
    let cold = open_engine(&directory.path().join("provider")).await;
    let recovered = std::panic::AssertUnwindSafe(async {
        assert_eq!(capsule_manifests(&cold), 0);
        assert!(!cold.db().test_contains_dynamic_state_record(&target).unwrap());
        assert!(simplex::finality_recovery::scan_finality_recovery_namespace(&namespace)
            .unwrap()
            .is_none());
        assert_eq!(inspect_closure_progress(cold.db(), &domain).unwrap().0.len(), 1);
        initialize_cold_history_network(&cold, &peers).await;
        assert_eq!(capsule_manifests(&cold), 0, "network startup cannot prebuild history");
        assert!(!cold.db().test_contains_dynamic_state_record(&target).unwrap());
        // The sole recovery driver receives neither locator nor runtime.
        let observed = crate::historical_recovery::test_hooks::install(cold.as_ref(), false, false);
        let service = cold.ensure_retired_session_recovery().await.unwrap();
        tokio::time::timeout(Duration::from_secs(90), async {
            while capsule_manifests(&cold) == 0 || observed.syncs() == 0 {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap_or_else(|error| {
            let observations: Vec<_> = peers.iter().map(|peer| {
                let router = peer.overlays_router().unwrap();
                (router.test_bounded_queries(), router.test_pss_observations())
            }).collect();
            panic!("first-cold closing recovery: {error}; {:?}; router_ready={}; peers={observations:?}",
                service.snapshot(), cold.overlays_router().is_ok())
        });
        let verified =
            crate::retired_history::authenticate_capsule_with_budget(cold.as_ref(), &target, None)
                .await
                .unwrap()
                .expect("background closing owner committed exact capsule");
        assert_eq!(verified.state().root_cell().repr_hash(), &expected);
        assert!(!cold.db().test_contains_dynamic_state_record(&target).unwrap());
        assert_eq!(cold.load_last_applied_mc_block_id().unwrap().unwrap().as_ref(), &head);
        assert!(
            query_count() > queries_before,
            "actual remote proof retrieval must occur after reopening"
        );
        let observations: Vec<_> = peers
            .iter()
            .flat_map(|peer| peer.overlays_router().unwrap().test_pss_observations())
            .collect();
        assert!(
            observations
                .iter()
                .any(|(id, offset, size)| id == &ancestor && *offset == Some(0) && size.is_some()),
            "remote authenticated ancestor snapshot must actually be read"
        );
        let (entries, closes) = inspect_closure_progress(cold.db(), &domain).unwrap();
        assert_eq!(entries.len(), 1, "history admission does not discharge pending effects");
        assert_eq!(
            entries[0].record.as_ref(), &original_record,
            "history recovery cannot change canonical bytes or original age"
        );
        assert!(closes.is_empty(), "history admission cannot mint compact custody");
    })
    .catch_unwind()
    .await;
    cold.clone().wait_stop().await.unwrap();
    drop(cold);
    let (a, b) =
        tokio::join!(receiver.clone().wait_stop(), observer.as_ref().unwrap().clone().wait_stop());
    a.unwrap();
    b.unwrap();
    recovered.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    // Release every peer before the second cold startup. Only durable private
    // evidence can authenticate this exact old anchor now.
    drop(observer);
    drop(receiver);
    let offline = open_engine(&directory.path().join("provider")).await;
    let checked = std::panic::AssertUnwindSafe(async {
        assert!(!offline.db().test_contains_dynamic_state_record(&target).unwrap());
        assert_eq!(offline.load_last_applied_mc_block_id().unwrap().unwrap().as_ref(), &head);
        let locators =
            simplex::finality_delivery::scan_finality_closures_namespace(&namespace).unwrap();
        assert_eq!(locators.len(), 1);
        assert_eq!(locators[0].request().unwrap(), original_close);
        drop(locators);
        assert_eq!(
            inspect_closure_progress(offline.db(), &domain).unwrap().0[0].record.as_ref(),
            &original_record
        );
        let observed =
            crate::historical_recovery::test_hooks::install(offline.as_ref(), false, false);
        let service = offline.ensure_retired_session_recovery().await.unwrap();
        tokio::time::timeout(Duration::from_secs(30), async {
            while observed.syncs() == 0 {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap_or_else(|error| {
            panic!(
                "offline closing owner did not rebarrier its capsule: {error}; {:?}",
                service.snapshot()
            )
        });
        // In addition to observing the autonomous owner's real rebarrier,
        // require the public closing API to return the derived historical runtime.
        // This second-cold check supplies only the original durable locator.
        let runtime = offline
            .clone()
            .authenticate_closing_source_with_history(original_close.clone(), namespace.clone())
            .await
            .unwrap();
        assert_eq!(runtime.recovery_binding(), original_close.domain.recovery_binding.as_ref());
        assert_eq!(runtime.session_id(), &original_close.domain.session_id);
        let verified = crate::retired_history::authenticate_capsule_with_budget(
            offline.as_ref(),
            &target,
            None,
        )
        .await
        .unwrap()
        .expect("second cold recovery must use the durable capsule");
        assert_eq!(verified.state().root_cell().repr_hash(), &expected);
        assert_eq!(offline.load_last_applied_mc_block_id().unwrap().unwrap().as_ref(), &head);
    })
    .catch_unwind()
    .await;
    offline.clone().wait_stop().await.unwrap();
    checked.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}
