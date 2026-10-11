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

fn pss_fault(pair: &Pair, id: &BlockIdExt, bytes: &[u8]) {
    pss_fault_at(pair, id, 0, bytes);
}
fn pss_fault_at(pair: &Pair, id: &BlockIdExt, offset: i64, bytes: &[u8]) {
    let requester = pair
        .provider
        .network()
        .context()
        .stack
        .adnl
        .key_by_tag(NodeNetwork::TAG_OVERLAY_KEY)
        .unwrap()
        .id()
        .clone();
    for peer in [&pair.receiver, pair.observer.as_ref().unwrap()] {
        peer.overlays_router().unwrap().test_pss_reply(
            requester.clone(),
            rtos_api::ton::ton_node::persistentstateidv2::PersistentStateIdV2 {
                block: id.clone(),
                masterchain_block: id.clone(),
                effective_shard: 0,
            },
            Some(offset),
            bytes.to_vec(),
        );
    }
}
fn clear_faults(pair: &Pair) {
    for peer in [&pair.receiver, pair.observer.as_ref().unwrap()] {
        peer.overlays_router().unwrap().test_clear_history_replies();
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RecoveryScenario {
    Existing(u8),
    DirectTargetSnapshot,
    MissingTailAfterFullPart,
    AutonomousColdStartup,
    QuotaSecondAnchor,
    CorruptExistingCapsule,
    CorruptOrdinaryState,
    WrongRemoteDomain,
    WrongRemoteParent,
    MissingSourceCertificate,
    InsufficientSourceQuorum,
    WrongSessionCertificate,
}

async fn recover_source(mode: u8) {
    recover_scenario(RecoveryScenario::Existing(mode)).await;
}

async fn recover_scenario(scenario: RecoveryScenario) {
    let mode = match scenario {
        RecoveryScenario::Existing(mode) => mode,
        RecoveryScenario::QuotaSecondAnchor => 6,
        _ => 0,
    };

    let signer = std::env::var("RTOS_PUBLIC_FIXTURE_SIGNER").unwrap();
    let pair = Pair::with_source_options("included", false, true, true, true).await;
    let run = std::panic::AssertUnwindSafe(async {
        let engine = &pair.provider;
        engine.clone().download_and_apply_block(pair.master.id(), 1, false).await.unwrap();
        let first = engine.load_state(pair.master.id()).await.unwrap();
        let config = first.config_params().unwrap();
        let cc = pair.master.block().unwrap().read_info().unwrap().gen_catchain_seqno();
        let creator = config.validator_set().unwrap().list()[0].validator_id().unwrap();
        let (mut target, mut target_root, row) =
            chain::successor_with_state_transform(&signer, pair.master.id(), first.root_cell(), false, 0, cc, &creator, |state| {
                if scenario == RecoveryScenario::MissingTailAfterFullPart {
                    // Real state data, not peer-advertised padding: every leaf is
                    // unique, and the resulting block/state update is signed.
                    let mut level: Vec<_> = (0u32..18_000).map(|index| {
                        let mut bytes = vec![0x59; 127];
                        bytes[..4].copy_from_slice(&index.to_be_bytes());
                        rtos_block::BuilderData::with_raw(bytes, 1016).unwrap().into_cell().unwrap()
                    }).collect();
                    while level.len() > 1 {
                        level = level.chunks(2).map(|children| {
                            let mut cell = rtos_block::BuilderData::new();
                            for child in children { cell.checked_append_reference(child.clone()).unwrap(); }
                            cell.into_cell().unwrap()
                        }).collect();
                    }
                    let mut extra = state.read_custom().unwrap().unwrap();
                    extra.config.set_config(rtos_block::ConfigParamEnum::ConfigParamAny(1000, level.pop().unwrap())).unwrap();
                    state.write_custom(Some(&extra)).unwrap();
                }
            });
        let block = fixture_block(&row);
        let proof =
            BlockProofStuff::deserialize(&target, decode(&row["proof_boc"]), false).unwrap();
        for owner in [&pair.provider, &pair.receiver, pair.observer.as_ref().unwrap()] {
            owner.clone().download_and_apply_block(pair.master.id(), 1, false).await.unwrap();
            let handle = owner.store_block(&block).await.unwrap().to_any();
            owner.store_block_proof(&target, Some(handle), &proof).await.unwrap();
            owner.clone().download_and_apply_block(&target, 2, false).await.unwrap();
        }
        let hole = if mode == 10 {
            let middle = target.clone();
            let (id, root, row) = chain::successor(&signer, &target, &target_root, false, 0, cc, &creator);
            let block = fixture_block(&row);
            let proof = BlockProofStuff::deserialize(&id, decode(&row["proof_boc"]), false).unwrap();
            for owner in [&pair.provider, &pair.receiver, pair.observer.as_ref().unwrap()] {
                let handle = owner.store_block(&block).await.unwrap().to_any();
                owner.store_block_proof(&id, Some(handle), &proof).await.unwrap();
                owner.clone().download_and_apply_block(&id, id.seq_no(), false).await.unwrap();
            }
            target = id;
            target_root = root;
            Some(middle)
        } else { None };
        // Legacy scenarios require MC1 replay; the named direct/part scenarios
        // publish the exact target snapshot instead.
        let target_snapshot = matches!(scenario, RecoveryScenario::DirectTargetSnapshot | RecoveryScenario::MissingTailAfterFullPart);
        let snapshot_id = if target_snapshot { &target } else { pair.master.id() };
        let snapshot_root = if target_snapshot { &target_root } else { first.root_cell() };
        let snapshot_bytes = rtos_block::write_boc(snapshot_root).unwrap();
        if scenario == RecoveryScenario::MissingTailAfterFullPart {
            assert!(snapshot_bytes.len() > 2 << 20);
        }
        for peer in [&pair.receiver, pair.observer.as_ref().unwrap()] {
            peer.clone().download_and_apply_block(pair.master.id(), 1, false).await.unwrap();
            let handle = peer.load_block_handle(snapshot_id).unwrap().unwrap();
            peer.db()
                .store_shard_state_persistent_raw(
                    &handle,
                    &snapshot_bytes,
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
            .bind_recovery_anchor(if mode == 6 { pair.master.id().clone() } else { target.clone() })
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
            finality: SessionFinality::Carrier(next_proof.clone().drain_signatures().unwrap()),
            last_mc_finalized_seqno: 0,
            candidate_already_sent: false,
            created_at_unix_secs: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        if scenario == RecoveryScenario::CorruptOrdinaryState {
            // Keep the damaged historical target behind a healthy applied head,
            // so startup does not need its root before the recovery call.
            for owner in [&pair.provider, &pair.receiver, pair.observer.as_ref().unwrap()] {
                let handle = owner.store_block(&next_block).await.unwrap().to_any();
                owner.store_block_proof(&next, Some(handle), &next_proof).await.unwrap();
                owner.clone().download_and_apply_block(&next, next.seq_no(), false).await.unwrap();
            }
        }
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
        if scenario == RecoveryScenario::CorruptOrdinaryState {
            assert!(engine.db().test_contains_dynamic_state_record(&target).unwrap());
            return (record, target, target_root.repr_hash().clone(), closing, namespace);
        }
        engine.shard_states_keeper().test_retire_history_state(&target);
        tokio::time::timeout(Duration::from_secs(20), async {
            while engine.db().test_contains_dynamic_state_record(&target).unwrap() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("real GC must remove historical target before recovery");
        if mode == 6 {
            engine.shard_states_keeper().test_retire_history_state(pair.master.id());
            tokio::time::timeout(Duration::from_secs(20), async {
                while engine.db().test_contains_dynamic_state_record(pair.master.id()).unwrap() {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }).await.expect("both distinct governing/start anchors must actually be GC'd");
        }
        if let Some(middle) = &hole {
            engine.shard_states_keeper().test_retire_history_state(middle);
            tokio::time::timeout(Duration::from_secs(20), async {
                while engine.db().test_contains_dynamic_state_record(middle).unwrap() {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }).await.expect("actual intermediate state GC must precede chain-hole test");
        }
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
        if scenario == RecoveryScenario::AutonomousColdStartup {
            // Leave absent capsule/ordinary state and genuine source certificate
            // on disk. The cold process receives no record or runtime argument.
            return (record, target, target_root.repr_hash().clone(), closing, namespace);
        }
        if scenario == RecoveryScenario::QuotaSecondAnchor {
            let before = retained_source_bytes(&namespace);
            let guard = crate::retired_history::test_recovered_capsule_limits(
                Path::new(engine.db_root_dir().unwrap()),
                crate::retired_history::Limits { anchors: 1, ..Default::default() });
            let error = engine.clone().authenticate_retired_source_with_history(record.clone()).await.err()
                .expect("second authenticated anchor must hit actual Store quota branch");
            assert!(format!("{error:#}").contains("Retained history anchor quota exhausted"), "{error:#}");
            assert!(crate::retired_history::authenticate_capsule_with_budget(engine.as_ref(), pair.master.id(), None).await.unwrap().is_some());
            assert!(crate::retired_history::authenticate_capsule_with_budget(engine.as_ref(), &target, None).await.unwrap().is_none());
            assert_eq!(retained_source_bytes(&namespace), before);
            drop(guard); // Restore production capacity; no data is removed to make space.
            return (record, target, target_root.repr_hash().clone(), closing, namespace);
        }
        if matches!(scenario, RecoveryScenario::WrongRemoteDomain | RecoveryScenario::WrongRemoteParent) {
            use rtos_api::IntoBoxed;
            let before = retained_source_bytes(&namespace);
            engine.db().test_remove_archived_artifacts(&target).await.unwrap();
            let mut wrong_parent = pair.master.id().clone();
            if scenario == RecoveryScenario::WrongRemoteParent {
                wrong_parent.file_hash = UInt256::calc_file_hash(b"another exact parent");
            }
            let (wrong_id, _, wrong_row) = chain::successor_in_domain(
                &signer, &wrong_parent, first.root_cell(), false, 0, cc, &creator,
                if scenario == RecoveryScenario::WrongRemoteDomain { -238 } else { -239 }, |_| {});
            assert_ne!(wrong_id, target);
            let reply = WireProfile::T0.serialize(&rtos_api::ton::ton_node::datafull::DataFull {
                id: wrong_id, block: decode(&wrong_row["block_boc"]), proof: decode(&wrong_row["proof_boc"]), is_link: false.into(),
            }.into_boxed()).unwrap();
            let requester = engine.network().context().stack.adnl.key_by_tag(NodeNetwork::TAG_OVERLAY_KEY).unwrap().id().clone();
            let count = || [&pair.receiver, pair.observer.as_ref().unwrap()].iter()
                .map(|peer| peer.overlays_router().unwrap().test_bounded_queries()).sum::<usize>();
            let before_count = count();
            for peer in [&pair.receiver, pair.observer.as_ref().unwrap()] {
                peer.overlays_router().unwrap().test_bounded_reply(requester.clone(), target.clone(), true, reply.clone());
            }
            let error = engine.clone().authenticate_retired_source_with_history(record.clone()).await.err()
                .expect("valid signed foreign response must not replace the requested full block identity");
            assert!(count() > before_count, "must consume a real foreign peer reply");
            assert!(format!("{error:#}").contains("Block with another id was received"), "{error:#}");
            assert_eq!(retained_source_bytes(&namespace), before);
            assert_eq!(engine.load_last_applied_mc_block_id().unwrap(), head);
            assert!(crate::retired_history::authenticate_capsule_with_budget(engine.as_ref(), &target, None).await.unwrap().is_none());
            clear_faults(&pair);
            // The subsequent normal recovery downloads the genuine target.
        }
        if scenario == RecoveryScenario::MissingTailAfterFullPart {
            const PART: usize = 2 << 20;
            let before = retained_source_bytes(&namespace);
            pss_fault_at(&pair, &target, PART as i64, &[]);
            let error = engine.clone().authenticate_retired_source_with_history(record.clone()).await.err()
                .expect("missing second part must not authenticate a truncated snapshot");
            assert!(format!("{error:#}").contains("Historical snapshot part is missing or short"), "{error:#}");
            let observations: Vec<_> = [&pair.receiver, pair.observer.as_ref().unwrap()].iter()
                .flat_map(|peer| peer.overlays_router().unwrap().test_pss_observations()).collect();
            assert!(observations.iter().any(|(id, offset, size)| id == &target && *offset == Some(0) && *size == Some(PART)),
                "first part must come from the real persistent-state file: {observations:?}");
            assert!(observations.iter().any(|(id, offset, size)| id == &target && *offset == Some(PART as i64) && *size == Some(0)));
            assert_eq!(retained_source_bytes(&namespace), before);
            assert_eq!(engine.load_last_applied_mc_block_id().unwrap(), head);
            assert!(crate::retired_history::authenticate_capsule_with_budget(engine.as_ref(), &target, None).await.unwrap().is_none());
            clear_faults(&pair);
        }
        if mode == 8 || mode == 9 {
            let before = retained_source_bytes(&namespace);
            let bytes = if mode == 8 {
                let mut state = first.state().unwrap().clone();
                state.set_gen_time(state.gen_time() + 1);
                let bytes = rtos_block::write_boc(&state.serialize().unwrap()).unwrap();
                assert_eq!(bytes.len(), rtos_block::write_boc(first.root_cell()).unwrap().len(),
                    "wrong root must pass exact part-length admission");
                bytes
            } else { Vec::new() };
            pss_fault(&pair, pair.master.id(), &bytes);
            let error = engine.clone().authenticate_retired_source_with_history(record.clone())
                .await.err().expect("remote malformed historical snapshot must be rejected");
            clear_faults(&pair);
            let expected = if mode == 8 { "Snapshot root differs from authenticated block state root" }
                else { "Historical snapshot part is missing or short" };
            assert!(format!("{error:#}").contains(expected), "{error:#}");
            assert_eq!(retained_source_bytes(&namespace), before);
            assert_eq!(engine.load_last_applied_mc_block_id().unwrap(), head);
            assert!(!engine.db().test_contains_dynamic_state_record(&target).unwrap());
            assert!(crate::retired_history::authenticate_capsule_with_budget(engine.as_ref(), &target, None)
                .await.unwrap().is_none());
        }
        if let Some(middle) = &hole {
            let before = retained_source_bytes(&namespace);
            engine.db().test_remove_archived_artifacts(middle).await.unwrap();
            let requester = engine.network().context().stack.adnl
                .key_by_tag(NodeNetwork::TAG_OVERLAY_KEY).unwrap().id().clone();
            let missing = WireProfile::T0.serialize(&rtos_api::ton::ton_node::DataFull::TonNode_DataFullEmpty).unwrap();
            let mut count_before = 0;
            for peer in [&pair.receiver, pair.observer.as_ref().unwrap()] {
                count_before += peer.overlays_router().unwrap().test_bounded_queries();
                peer.overlays_router().unwrap().test_bounded_reply(requester.clone(), middle.clone(), true, missing.clone());
            }
            let error = engine.clone().authenticate_retired_source_with_history(record.clone())
                .await.err().expect("real missing intermediate successor must stop replay");
            let count_after: usize = [&pair.receiver, pair.observer.as_ref().unwrap()].iter()
                .map(|p| p.overlays_router().unwrap().test_bounded_queries()).sum();
            clear_faults(&pair);
            assert!(count_after > count_before, "chain-hole refusal must consume a real peer reply");
            assert!(format!("{error:#}").contains("DownloadBlockFull returned DataFullEmpty"), "{error:#}");
            assert_eq!(retained_source_bytes(&namespace), before);
            assert_eq!(engine.load_last_applied_mc_block_id().unwrap(), head);
            assert!(crate::retired_history::authenticate_capsule_with_budget(engine.as_ref(), &target, None)
                .await.unwrap().is_none());
        }
        if mode == 11 || mode == 12 {
            let before = retained_source_bytes(&namespace);
            let bytes = rtos_block::write_boc(first.root_cell()).unwrap();
            let mut limits = crate::history_read_budget::HistoryReadLimits::default();
            if mode == 11 { limits.state_boc_bytes = bytes.len() * 2 - 1; }
            else { limits.depth = first.root_cell().repr_depth().checked_sub(1).unwrap(); }
            let request = crate::historical_recovery::Request::test_with_limits(engine.clone(), limits).await.unwrap();
            if mode == 11 {
                let received = request.test_snapshot(pair.master.id()).await.unwrap().unwrap();
                assert_eq!(received.root_cell().repr_hash(), first.root_cell().repr_hash(),
                    "first actual remote snapshot must fit before cumulative rejection");
            }
            for _ in 0..2 {
                let error = request.test_snapshot(pair.master.id()).await.err().unwrap();
                assert!(crate::history_read_budget::stops_fallback(&error), "{error:#}");
            }
            drop(request);
            assert_eq!(retained_source_bytes(&namespace), before);
            assert_eq!(engine.load_last_applied_mc_block_id().unwrap(), head);
            assert!(crate::retired_history::authenticate_capsule_with_budget(engine.as_ref(), &target, None)
                .await.unwrap().is_none());
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
            if (mode == 5 || mode == 6) && scenario != RecoveryScenario::QuotaSecondAnchor {
                let before = retained_source_bytes(&namespace);
                let control =
                    crate::historical_recovery::test_hooks::install(engine.as_ref(), false, mode == 5);
                if mode == 6 { control.fail_on_sync(2); }
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
                assert_eq!(control.syncs(), if mode == 6 { 2 } else { 1 });
                if mode == 6 {
                    assert!(crate::retired_history::authenticate_capsule_with_budget(
                        engine.as_ref(), pair.master.id(), None).await.unwrap().is_some(),
                        "first authorized anchor must survive second-anchor uncertainty");
                }
                assert_eq!(retained_source_bytes(&namespace), before);
                // The first attempt genuinely persisted bytes before the
                // application-visible EIO. Reading them is not durability ACK:
                // retry must execute the same real file/directory barriers.
                engine
                    .clone()
                    .authenticate_retired_source_with_history(record.clone())
                    .await
                    .unwrap();
                assert_eq!(control.syncs(), if mode == 6 { 4 } else { 2 });
                assert_eq!(retained_source_bytes(&namespace), before);
            }
            if matches!(scenario, RecoveryScenario::MissingSourceCertificate | RecoveryScenario::InsufficientSourceQuorum | RecoveryScenario::WrongSessionCertificate) {
                let files = retained_source_bytes(&namespace);
                let (path, original) = files.iter().find(|(_, bytes)| {
                    serde_json::from_slice::<serde_json::Value>(bytes).ok()
                        .is_some_and(|value| value["certificate"].is_string())
                }).expect("actual retained FinalCert");
                let capsule_root = Path::new(engine.db_root_dir().unwrap()).join("retired-history-v1");
                let manifests = || {
                    let entries = match std::fs::read_dir(&capsule_root) {
                        Ok(entries) => entries,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                            return std::collections::BTreeMap::new();
                        }
                        Err(error) => panic!("read capsule manifests {}: {error}", capsule_root.display()),
                    };
                    entries.filter_map(|entry| { let path = entry.unwrap().path();
                        (path.extension().and_then(|v| v.to_str()) == Some("json"))
                            .then(|| (path.clone(), std::fs::read(path).unwrap()))
                    }).collect::<std::collections::BTreeMap<_, _>>()
                };
                let before_capsules = manifests();
                let variants: &[usize] = if scenario == RecoveryScenario::InsufficientSourceQuorum { &[0, 1] } else { &[0] };
                for &votes_to_keep in variants {
                    let withdrawn = pair._dir.path().join("withdrawn-original-source-certificate");
                    let expected_error;
                    if scenario == RecoveryScenario::MissingSourceCertificate {
                        std::fs::rename(path, &withdrawn).unwrap();
                        expected_error = "Source history has no retained certificate";
                    } else {
                        let mut disk: serde_json::Value = serde_json::from_slice(original).unwrap();
                        let mut wire: rtos_api::ton::consensus::simplex::Certificate = WireProfile::T0
                            .deserialize_value_bounded(&hex::decode(disk["certificate"].as_str().unwrap()).unwrap(), original.len()).unwrap();
                        if scenario == RecoveryScenario::InsufficientSourceQuorum {
                            let rtos_api::ton::consensus::simplex::Certificate::Consensus_Simplex_Certificate(ref mut cert) = wire;
                            let rtos_api::ton::consensus::simplex::VoteSignatureSet::Consensus_Simplex_VoteSignatureSet(ref mut signatures) = cert.signatures;
                            let mut retained = signatures.votes.to_vec(); retained.truncate(votes_to_keep);
                            signatures.votes = retained.into();
                            expected_error = "Not enough signatures in certificate";
                        } else {
                            let (committee, _) = config.validator_set().unwrap().calc_subset(&config.catchain_config().unwrap(), SHARD_FULL, -1, cc).unwrap();
                            let alternate = AuthenticatedSessionRuntime::from_authenticated_config(
                                runtime.pin().clone(), config,
                                rtos_api::session_identity::SessionCoordinates { shard: target.shard(), catchain_seqno: cc, vertical_seqno: 1, last_key_block_seqno: 0, new_catchain_ids: false },
                                committee, runtime.local_adnl().clone()).unwrap();
                            assert_ne!(alternate.session_id(), runtime.session_id());
                            resign_source_certificate(&signer, &alternate, &mut wire);
                            expected_error = "Invalid vote signature for validator";
                        }
                        disk["certificate"] = hex::encode(WireProfile::T0.serialize(&wire).unwrap()).into();
                        std::fs::write(path, serde_json::to_vec(&disk).unwrap()).unwrap();
                    }
                    let negative_source = retained_source_bytes(&namespace);
                    let failed = std::panic::AssertUnwindSafe(async {
                        let error = engine.clone().authenticate_retired_source_with_history(record.clone()).await.err()
                            .expect("invalid source evidence must not authorize capsule commit");
                        assert!(format!("{error:#}").contains(expected_error), "{error:#}");
                        assert_eq!(manifests(), before_capsules, "neither governing nor start capsule may be persisted");
                        assert_eq!(retained_source_bytes(&namespace), negative_source, "no source ACK/repair/rewriting on refusal");
                        assert_eq!(engine.load_last_applied_mc_block_id().unwrap(), head);
                        assert!(!engine.db().test_contains_dynamic_state_record(&target).unwrap());
                    }).catch_unwind().await;
                    if scenario == RecoveryScenario::MissingSourceCertificate {
                        std::fs::rename(&withdrawn, path).unwrap();
                    } else { std::fs::write(path, original).unwrap(); }
                    assert_eq!(retained_source_bytes(&namespace), files);
                    failed.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
                }
            }
            if mode == 7 {
                let files = retained_source_bytes(&namespace);
                let (path, original) = files.iter().find(|(_, bytes)| {
                    serde_json::from_slice::<serde_json::Value>(bytes).ok()
                        .is_some_and(|value| value["certificate"].is_string())
                }).expect("production retain_intent must store a genuine FinalCert");
                let mut disk: serde_json::Value = serde_json::from_slice(original).unwrap();
                let mut raw = hex::decode(disk["certificate"].as_str().unwrap()).unwrap();
                let wire: rtos_api::ton::consensus::simplex::Certificate =
                    WireProfile::T0.deserialize_value_bounded(&raw, raw.len()).unwrap();
                let signature = wire.signatures().votes()[0].signature();
                let offset = raw.windows(signature.len()).position(|v| v == signature.as_slice()).unwrap();
                raw[offset] ^= 1;
                disk["certificate"] = hex::encode(raw).into();
                let invalid = serde_json::to_vec(&disk).unwrap();
                std::fs::write(path, &invalid).unwrap();
                assert!(engine.clone().authenticate_retired_source_with_history(record.clone()).await.is_err(),
                    "publicly derivable historical identity must not authorize a bad retained certificate");
                assert_eq!(std::fs::read(path).unwrap(), invalid, "failed authentication must preserve source debt");
                assert!(crate::retired_history::authenticate_capsule_with_budget(engine.as_ref(), &target, None)
                    .await.unwrap().is_none(), "bad certificate must not consume durable anchor quota");
                std::fs::write(path, original).unwrap();
            }
            let authenticated = engine
                .clone()
                .authenticate_retired_source_with_history(record.clone())
                .await
                .unwrap();
            assert_eq!(authenticated.runtime().session_id(), runtime.session_id());
        }
        if scenario == RecoveryScenario::CorruptExistingCapsule {
            let before = retained_source_bytes(&namespace);
            let root = Path::new(engine.db_root_dir().unwrap()).join("retired-history-v1");
            let manifest = std::fs::read_dir(&root).unwrap().filter_map(|entry| {
                let path = entry.unwrap().path();
                if path.extension().and_then(|v| v.to_str()) != Some("json") { return None; }
                let value: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                (value["id"].as_str() == Some(target.to_string().as_str())).then_some(value)
            }).next().expect("actual authorized capsule manifest");
            let blob = root.join(format!("{}.blob", manifest["state"].as_str().unwrap()));
            let original = std::fs::read(&blob).unwrap();
            let mut damaged = original.clone(); damaged[0] ^= 1;
            std::fs::write(&blob, &damaged).unwrap();
            let queries = || [&pair.receiver, pair.observer.as_ref().unwrap()].iter().map(|peer| {
                let router = peer.overlays_router().unwrap();
                (router.test_pss_observations().len(), router.test_bounded_queries())
            }).collect::<Vec<_>>();
            let before_queries = queries();
            let error = engine.clone().authenticate_retired_source_with_history(record.clone()).await.err()
                .expect("corrupt existing capsule must not fall back to available peer");
            assert!(format!("{error:#}").contains("History blob checksum mismatch"), "{error:#}");
            assert_eq!(queries(), before_queries, "corrupt established evidence must cause zero remote fetch");
            assert_eq!(std::fs::read(&blob).unwrap(), damaged);
            assert_eq!(retained_source_bytes(&namespace), before);
            std::fs::write(&blob, original).unwrap();
        }
        if target_snapshot {
            let observations: Vec<_> = [&pair.receiver, pair.observer.as_ref().unwrap()].iter()
                .flat_map(|peer| peer.overlays_router().unwrap().test_pss_observations()).collect();
            assert!(observations.iter().any(|(id, offset, size)| id == &target && *offset == Some(0) && size.is_some()));
            assert!(observations.iter().all(|(id, _, _)| id == &target),
                "direct snapshot must not silently fall back to an ancestor: {observations:?}");
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
    if matches!(
        scenario,
        RecoveryScenario::AutonomousColdStartup
            | RecoveryScenario::QuotaSecondAnchor
            | RecoveryScenario::CorruptOrdinaryState
    ) && run.is_ok()
    {
        pair.provider.clone().wait_stop().await.unwrap();
    } else {
        pair.stop_all().await;
    }
    let (record, target, expected, closing, namespace) =
        run.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    let Pair { _dir: directory, receiver, provider, observer, .. } = pair;
    drop(provider);
    if scenario == RecoveryScenario::CorruptOrdinaryState {
        let checked = std::panic::AssertUnwindSafe(ordinary_corruption_cold_check(
            &directory.path().join("provider"),
            &receiver,
            observer.as_ref().unwrap(),
            &record,
            &target,
            &expected,
            &namespace,
        ))
        .catch_unwind()
        .await;
        if let Err(panic) = checked {
            let (a, b) = tokio::join!(
                receiver.clone().wait_stop(),
                observer.as_ref().unwrap().clone().wait_stop()
            );
            a.unwrap();
            b.unwrap();
            std::panic::resume_unwind(panic);
        }
    }
    // Cold startup/quota/ordinary-fault scenarios retain live peers for the
    // first reopen. All remaining cases already joined peers; the final reopen
    // below joins every peer and verifies offline evidence.
    let cold = open_engine(&directory.path().join("provider")).await;
    let result = std::panic::AssertUnwindSafe(async {
        assert_eq!(
            cold.db().test_contains_dynamic_state_record(&target).unwrap(),
            scenario == RecoveryScenario::CorruptOrdinaryState
        );
        if scenario == RecoveryScenario::AutonomousColdStartup {
            let service = cold.ensure_retired_session_recovery().await.unwrap();
            tokio::time::timeout(Duration::from_secs(90), async {
                loop {
                    match crate::retired_history::authenticate_capsule_with_budget(
                        cold.as_ref(),
                        &target,
                        None,
                    )
                    .await
                    {
                        Ok(Some(_)) => break,
                        Ok(None) => {}
                        Err(error) if crate::retired_history::is_retryable(&error) => {}
                        Err(error) => panic!("cold capsule authentication: {error:#}"),
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .unwrap_or_else(|_| {
                panic!("autonomous capsule recovery timed out: {:?}", service.snapshot())
            });
        } else if let Some(request) = closing.clone() {
            cold.clone()
                .authenticate_closing_source_with_history(request, namespace)
                .await
                .unwrap();
        } else {
            cold.clone().authenticate_retired_source_with_history(record.clone()).await.unwrap();
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
    if matches!(
        scenario,
        RecoveryScenario::AutonomousColdStartup
            | RecoveryScenario::QuotaSecondAnchor
            | RecoveryScenario::CorruptOrdinaryState
    ) {
        let (a, b) = tokio::join!(receiver.clone().wait_stop(), async {
            if let Some(peer) = observer.as_ref() {
                peer.clone().wait_stop().await
            } else {
                Ok(())
            }
        });
        a.unwrap();
        b.unwrap();
    }
    drop(receiver);
    drop(observer);
    if result.is_ok()
        && matches!(
            scenario,
            RecoveryScenario::AutonomousColdStartup
                | RecoveryScenario::QuotaSecondAnchor
                | RecoveryScenario::CorruptOrdinaryState
        )
    {
        let offline = open_engine(&directory.path().join("provider")).await;
        let check = offline.clone().authenticate_retired_source_with_history(record).await;
        offline.clone().wait_stop().await.unwrap();
        check.unwrap();
    }
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "two actual capsule commits with second unknown sync; RTOS_PUBLIC_FIXTURE_SIGNER required"]
async fn historical_recovery_second_anchor_uncertainty_keeps_first_and_source_debt() {
    recover_source(6).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real source certificate PQ failure and restored control; RTOS_PUBLIC_FIXTURE_SIGNER required"]
async fn historical_recovery_valid_identity_bad_source_pq_cannot_commit_capsule() {
    recover_source(7).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real remote state-root rejection; RTOS_PUBLIC_FIXTURE_SIGNER required"]
async fn historical_recovery_remote_wrong_root_preserves_source_and_no_capsule() {
    recover_source(8).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real missing PSS part rejection; RTOS_PUBLIC_FIXTURE_SIGNER required"]
async fn historical_recovery_remote_short_part_preserves_source_and_no_capsule() {
    recover_source(9).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "actual repeated remote PSS cumulative budget; RTOS_PUBLIC_FIXTURE_SIGNER required"]
async fn historical_recovery_remote_cumulative_bytes_do_not_reset() {
    recover_source(11).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "actual remote PSS depth limit; RTOS_PUBLIC_FIXTURE_SIGNER required"]
async fn historical_recovery_remote_depth_limit_stays_failed_on_same_request() {
    recover_source(12).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real absent intermediate state/body and peer hole; RTOS_PUBLIC_FIXTURE_SIGNER required"]
async fn historical_recovery_missing_intermediate_successor_refuses_replay() {
    recover_source(10).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real exact target snapshot; RTOS_PUBLIC_FIXTURE_SIGNER required"]
async fn historical_recovery_direct_target_snapshot_and_peer_off_cold() {
    recover_scenario(RecoveryScenario::DirectTargetSnapshot).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real two-part PSS missing tail; RTOS_PUBLIC_FIXTURE_SIGNER required"]
async fn historical_recovery_missing_tail_after_real_first_part() {
    recover_scenario(RecoveryScenario::MissingTailAfterFullPart).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real cold autonomous source scanner; RTOS_PUBLIC_FIXTURE_SIGNER required"]
async fn historical_recovery_autonomous_cold_startup_without_record_input() {
    recover_scenario(RecoveryScenario::AutonomousColdStartup).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real Store quota branch with per-DB reduced limit; RTOS_PUBLIC_FIXTURE_SIGNER required"]
async fn historical_recovery_second_anchor_quota_preserves_first_and_source() {
    recover_scenario(RecoveryScenario::QuotaSecondAnchor).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "actual corrupted capsule rejects without peer fallback; RTOS_PUBLIC_FIXTURE_SIGNER required"]
async fn historical_recovery_corrupt_existing_capsule_never_fetches_remote() {
    recover_scenario(RecoveryScenario::CorruptExistingCapsule).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real signed foreign-domain peer block; RTOS_PUBLIC_FIXTURE_SIGNER required"]
async fn historical_recovery_foreign_domain_response_cannot_replace_exact_target() {
    recover_scenario(RecoveryScenario::WrongRemoteDomain).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real signed different-parent peer block; RTOS_PUBLIC_FIXTURE_SIGNER required"]
async fn historical_recovery_foreign_parent_response_cannot_replace_exact_target() {
    recover_scenario(RecoveryScenario::WrongRemoteParent).await;
}

async fn ordinary_corruption_cold_check(
    root: &Path,
    receiver: &Arc<Engine>,
    observer: &Arc<Engine>,
    record: &simplex::finality_recovery::SessionRecoveryRecord,
    target: &BlockIdExt,
    target_root: &UInt256,
    namespace: &Path,
) {
    use storage::{
        db::{
            node::{open_node_db, CELLS_CF_NAME},
            rocksdb::AccessType,
        },
        shardstate_db_async::CellsDbConfig,
    };
    let open_raw = || open_node_db(root, &CellsDbConfig::default(), AccessType::ReadWrite).unwrap();
    let db = open_raw();
    let index =
        db.clone().table::<BlockIdExt>(crate::internal_db::SHARDSTATE_DB_NAME, false).unwrap();
    let cells = db.clone().table::<UInt256>(CELLS_CF_NAME, false).unwrap();
    let original_index = index.try_get(target).unwrap().unwrap().to_vec();
    let original_raw = cells.try_get(target_root).unwrap().unwrap().to_vec();
    cells.put_raw_sync(target_root.as_slice(), &[0]).unwrap();
    db.sync_wal().unwrap();
    drop(cells);
    drop(index);
    drop(db);
    let before_source = retained_source_bytes(namespace);
    let queries = || {
        [receiver, observer]
            .iter()
            .map(|peer| {
                let router = peer.overlays_router().unwrap();
                (router.test_pss_observations().len(), router.test_bounded_queries())
            })
            .collect::<Vec<_>>()
    };
    let engine = open_engine(root).await;
    let run = std::panic::AssertUnwindSafe(async {
        assert!(engine.db().test_contains_dynamic_state_record(target).unwrap());
        let head = engine.load_last_applied_mc_block_id().unwrap();
        let before_queries = queries();
        let error = engine
            .clone()
            .authenticate_retired_source_with_history(record.clone())
            .await
            .err()
            .expect(
                "existing malformed ordinary graph must not fall back to available history peers",
            );
        assert_eq!(
            error.root_cause().to_string(),
            "Invalid stored cell record length",
            "{error:#}"
        );
        assert!(crate::history_read_budget::stops_fallback(&error), "{error:#}");
        assert_eq!(
            queries(),
            before_queries,
            "corrupt existing ordinary state must perform zero remote reads"
        );
        assert_eq!(retained_source_bytes(namespace), before_source);
        assert_eq!(engine.load_last_applied_mc_block_id().unwrap(), head);
        assert!(crate::retired_history::authenticate_capsule_with_budget(
            engine.as_ref(),
            target,
            None
        )
        .await
        .unwrap()
        .is_none());
    })
    .catch_unwind()
    .await;
    engine.clone().wait_stop().await.unwrap();
    drop(engine);
    let db = open_raw();
    let index =
        db.clone().table::<BlockIdExt>(crate::internal_db::SHARDSTATE_DB_NAME, false).unwrap();
    let cells = db.clone().table::<UInt256>(CELLS_CF_NAME, false).unwrap();
    assert_eq!(index.try_get(target).unwrap().unwrap().as_ref(), original_index.as_slice());
    assert_eq!(cells.try_get(target_root).unwrap().unwrap().as_ref(), &[0]);
    cells.put_raw_sync(target_root.as_slice(), &original_raw).unwrap();
    db.sync_wal().unwrap();
    drop(cells);
    drop(index);
    drop(db);
    if let Err(panic) = run {
        let (a, b) = tokio::join!(receiver.clone().wait_stop(), observer.clone().wait_stop());
        a.unwrap();
        b.unwrap();
        std::panic::resume_unwind(panic);
    }
    // Caller cold-opens again, invokes the same real authentication, joins all
    // peers, and finally repeats offline. No index or authority was fabricated.
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real cold ordinary graph corruption and exact restoration; RTOS_PUBLIC_FIXTURE_SIGNER required"]
async fn historical_recovery_corrupt_ordinary_index_never_fetches_remote() {
    recover_scenario(RecoveryScenario::CorruptOrdinaryState).await;
}

// Re-sign the unchanged Finalize vote for another real derived session. Every
// signature is checked against that session before it is used as a negative.
fn resign_source_certificate(
    signer: &str,
    runtime: &AuthenticatedSessionRuntime,
    wire: &mut rtos_api::ton::consensus::simplex::Certificate,
) {
    let data = simplex::utils::create_data_to_sign(
        runtime.session_id(),
        &simplex::utils::serialize_unsigned_vote(wire.vote()),
    );
    let rtos_api::ton::consensus::simplex::Certificate::Consensus_Simplex_Certificate(
        ref mut certificate,
    ) = wire;
    let rtos_api::ton::consensus::simplex::VoteSignatureSet::Consensus_Simplex_VoteSignatureSet(
        ref mut signatures,
    ) = certificate.signatures;
    let mut votes = signatures.votes.to_vec();
    let mut weight = 0u64;
    for vote in &mut votes {
        let rtos_api::ton::consensus::simplex::VoteSignature::Consensus_Simplex_VoteSignature(
            ref mut value,
        ) = vote;
        let member = &runtime.committee()[usize::try_from(value.who).unwrap()];
        let mut signed = None;
        for index in 0..3 {
            let output = std::process::Command::new(signer)
                .args([
                    index.to_string(),
                    hex::encode(&data),
                    hex::encode(b"TOS-CONSENSUS-SIMPLEX-v1"),
                ])
                .output()
                .unwrap();
            assert!(output.status.success());
            let text = String::from_utf8(output.stdout).unwrap();
            let mut lines = text.lines();
            let public = hex::decode(lines.next().unwrap()).unwrap();
            let signature = hex::decode(lines.next().unwrap()).unwrap();
            if public == member.pq_key().unwrap().public_key {
                signed = Some(signature);
                break;
            }
        }
        let signature = signed.expect("public fixture signer matches committee");
        ValidatorIdentity::from_descriptor(member)
            .unwrap()
            .verify_simplex(&data, &signature)
            .unwrap();
        value.signature = signature;
        weight += member.weight;
    }
    let total: u64 = runtime.committee().iter().map(|member| member.weight).sum();
    assert!(weight * 3 > total * 2, "foreign certificate must retain genuine quorum");
    signatures.votes = votes.into();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real source absence cannot authorize capsule; RTOS_PUBLIC_FIXTURE_SIGNER required"]
async fn historical_recovery_missing_retained_certificate_preserves_all_capsules() {
    recover_scenario(RecoveryScenario::MissingSourceCertificate).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real empty and insufficient valid source quorum; RTOS_PUBLIC_FIXTURE_SIGNER required"]
async fn historical_recovery_empty_and_insufficient_source_quorum_preserves_all_capsules() {
    recover_scenario(RecoveryScenario::InsufficientSourceQuorum).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real differently signed session cert; RTOS_PUBLIC_FIXTURE_SIGNER required"]
async fn historical_recovery_wrong_signed_session_preserves_all_capsules() {
    recover_scenario(RecoveryScenario::WrongSessionCertificate).await;
}
