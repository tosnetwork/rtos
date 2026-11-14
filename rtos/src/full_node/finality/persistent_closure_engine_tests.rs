// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Real source store -> Engine acceptance/effects -> durable dependency custody
//! -> source Delivered -> atomic node Released. No writable snapshot fixture.
use super::*;
use crate::propagation_outbox::{inspect_closure_progress, OutboxDomain};
use consensus_common::{
    finality_delivery::FinalizedDeliveryDraft,
    session_runtime::{AuthenticatedSessionRuntime, SessionNetworkPin},
    BlockCandidatePriority, BlockSourceInfo, ConsensusCommonFactory, SessionFinality,
    ValidatorIdentity,
};
use simplex::finality_delivery::FinalityDeliveryTestDriver;
use std::path::{Path, PathBuf};

#[path = "persistent_closure_chain.rs"]
mod chain;
#[path = "retirement_preparation_engine_tests.rs"]
mod retirement_preparation;
#[path = "validator_cleanup_v2_engine_tests.rs"]
mod validator_cleanup_v2;

// Source circulation must begin with a chain whose catchain schedule agrees
// with its authenticated recovery anchor. Legacy propagation fixtures use a
// standalone carrier round and are not valid source-recovery session fixtures.
pub(super) fn source_bootstrap(
    anchor: &BlockIdExt,
    root: &Cell,
) -> (BlockStuff, BlockProofStuff, UInt256) {
    let signer = std::env::var("RTOS_PUBLIC_FIXTURE_SIGNER").unwrap();
    let state = ShardStateUnsplit::construct_from_cell(root.clone()).unwrap();
    let extra = state.read_custom().unwrap().unwrap();
    let cc = extra.validator_info.catchain_seqno;
    let creator = extra.config.validator_set().unwrap().list()[0].validator_id().unwrap();
    let (id, state, row) = chain::successor(&signer, anchor, root, false, 0, cc, &creator);
    let block = fixture_block(&row);
    assert_eq!(block.id(), &id);
    let proof = BlockProofStuff::deserialize(&id, decode(&row["proof_boc"]), false).unwrap();
    (block, proof, state.repr_hash().clone())
}

fn source_directory(namespace: &Path) -> PathBuf {
    namespace.join("finality-pending")
}
fn reference_backup(namespace: &Path) -> Option<(PathBuf, Vec<u8>)> {
    let directory = source_directory(namespace).join("references-v1");
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|x| x.to_str()) == Some("reference") {
            return Some((path.clone(), std::fs::read(path).unwrap()));
        }
    }
    None
}

async fn circulation(events: usize) {
    circulation_with_close_demand(events, false).await;
}

async fn circulation_with_close_demand(events: usize, close_demand: bool) {
    circulation_with_retry_turn(events, close_demand, false).await;
}

async fn circulation_with_retry_turn(events: usize, close_demand: bool, single_retry: bool) {
    let signer = std::env::var("RTOS_PUBLIC_FIXTURE_SIGNER")
        .expect("set RTOS_PUBLIC_FIXTURE_SIGNER to the archived public-only fixture signer");
    assert!(Path::new(&signer).is_file());
    let pair = Pair::with_source_transport("included").await;
    let mut certified_receivers = Vec::new();
    let run = std::panic::AssertUnwindSafe(async {
        let engine = &pair.provider;
        let observer = pair.observer.as_ref().expect("source fixture includes a public observer");
        let issuer = engine.network().context().stack.adnl
            .key_by_tag(NodeNetwork::TAG_OVERLAY_KEY).unwrap();
        let certified = observer.overlays_router().unwrap()
            .test_certified_fast_sync_recipient(ShardIdent::MASTERCHAIN, &issuer).await.unwrap();
        certified_receivers.push(certified.clone());
        let certified_id = adnl::OverlayShortId::from_data(*certified.id().data());
        // There is no external DHT in this isolated network. Exchange fresh
        // signed advertisements through the same membership-verification API
        // used for public fixture peers, before emitting the finite source set.
        // This also advertises each root's normal original-sender flags.
        for root in [engine, &pair.receiver] {
            for (local, remote) in [(root, observer), (observer, root)] {
                let advertised = remote.network().context().stack.overlay
                    .get_signed_node(&certified_id, true).unwrap();
                local.network().context().stack.overlay.add_public_peer(
                    remote.network().context().stack.adnl.ip_address_adnl(),
                    &advertised,
                    &certified_id,
                ).unwrap();
            }
        }
        // Bootstrap MC1 uses the real existing proof and application path;
        // every subsequent event is first admitted by the actual source driver.
        engine.clone().download_and_apply_block(pair.master.id(), 1, false).await.unwrap();
        let zero = engine.load_state(&pair.anchor).await.unwrap();
        let config = zero.config_params().unwrap();
        let cc = pair.master.block().unwrap().read_info().unwrap().gen_catchain_seqno();
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
                    shard: pair.anchor.shard(),
                    catchain_seqno: cc,
                    vertical_seqno: 0,
                    last_key_block_seqno: 0,
                    new_catchain_ids: false,
                },
                committee,
                local,
            )
            .unwrap()
            .bind_recovery_anchor(pair.anchor.clone())
            .unwrap(),
        );
        let creator = runtime.committee()[0].validator_id().unwrap();
        let namespace = PathBuf::from(
            runtime
                .runtime_directory(
                    Path::new(engine.db_root_dir().unwrap()).join("catchains").to_str().unwrap(),
                )
                .unwrap(),
        );
        let domain = OutboxDomain {
            zerostate: pair.anchor.clone(),
            global_id: -239,
            wire_profile: WireProfile::T0,
        };
        let sink = engine.clone().durable_finality_sink(runtime.clone()).await.unwrap();
        let worker = engine.ensure_publication_worker().await.unwrap();
        if close_demand { worker.test_pause_background(true); }
        let confirm =
            engine.ensure_publication_worker().await.unwrap().delivered_sink(runtime.clone());
        let driver =
            FinalityDeliveryTestDriver::open(runtime.clone(), &namespace, sink, confirm).unwrap();
        driver.prepare_intents(false).unwrap();
        engine.enable_publication_worker().await.unwrap();
        let mut parent = pair.master.id().clone();
        let mut root = engine.load_state(&parent).await.unwrap().root_cell().clone();
        let mut first = None;
        let mut backup = None;
        let mut generations = std::collections::HashSet::new();
        for index in 0..events {
            // A long run must keep normal signed discovery advertisements fresh;
            // successful historical publication does not exempt peers from TTL.
            pair.refresh_public_advertisements().await;
            let (id, expected, row) =
                chain::successor(&signer, &parent, &root, false, 0, cc, &creator);
            let block = fixture_block(&row);
            assert_eq!(block.id(), &id);
            assert!(
                engine.load_block_handle(&id).unwrap().is_none(),
                "event must not be pre-applied"
            );
            let proof =
                BlockProofStuff::deserialize(&id, decode(&row["proof_boc"]), false).unwrap();
            let finality = SessionFinality::Carrier(proof.drain_signatures().unwrap());
            let draft = FinalizedDeliveryDraft {
                block_id: id.clone(),
                source_info: BlockSourceInfo {
                    source: ValidatorIdentity::from_descriptor(&runtime.committee()[0]).unwrap(),
                    priority: BlockCandidatePriority {
                        round: id.seq_no(),
                        first_block_round: 0,
                        priority: 0,
                    },
                },
                data: ConsensusCommonFactory::create_block_payload(block.data().to_vec()),
                finality,
                last_mc_finalized_seqno: 0,
                candidate_already_sent: false,
                created_at_unix_secs: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            };
            engine.set_test_chain_time(Some(1002 + id.seq_no()));
            pair.receiver.set_test_chain_time(Some(1002 + id.seq_no()));
            observer.set_test_chain_time(Some(1002 + id.seq_no()));
            // Wait for the real source WAL ACK/reference first. Do not maintain
            // closing until the first pre-Delivered backup has been captured.
            tokio::time::timeout(Duration::from_secs(60), async {
                loop {
                    let acknowledged = driver.poll(draft.clone()).unwrap();
                    if acknowledged && driver.counts().unwrap().1 == 1 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("actual source/node retention did not produce reference");
            if first.is_none() {
                backup = reference_backup(&namespace);
                assert!(backup.is_some(), "save an actual pre-Delivered reference");
                first = Some(draft.clone());
            }
            if close_demand {
                let before = worker.test_actual_acceptance_runs();
                tokio::time::timeout(Duration::from_secs(10), async {
                    loop {
                        driver.maintain().unwrap();
                        let (active, closed) = inspect_closure_progress(engine.db(), &domain).unwrap();
                        assert!(closed.is_empty(), "pending transport cannot yield a close offer");
                        if let Some(entry) = active.iter().find(|entry|
                            entry.record.block_id == id
                                && entry.stage == crate::propagation_outbox::PublicationStage::Ready)
                        {
                            assert!(!entry.pending.is_empty(), "real effects must remain pending");
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                }).await.expect("authenticated close demand did not drive actual acceptance/routing");
                assert_eq!(worker.test_actual_acceptance_runs(), before + 1);
                if single_retry {
                    let (active, _) = inspect_closure_progress(engine.db(), &domain).unwrap();
                    let entry = active.iter().find(|entry| entry.record.block_id == id)
                        .expect("the original publication must still precede source closure");
                    let original = entry.record.effects.clone();
                    assert_eq!(entry.pending, original);
                    assert!(original.len() > 1, "fixture must retain its complete multi-target plan");
                    let digest = crate::propagation_outbox::effects_digest(&original).unwrap();
                    tokio::time::timeout(Duration::from_secs(30), async {
                        loop {
                            worker.test_retry_background().await.unwrap();
                            let (active, closed) = inspect_closure_progress(engine.db(), &domain).unwrap();
                            if let Some(entry) = active.iter().find(|entry| entry.record.block_id == id) {
                                if entry.pending.len() == original.len() {
                                    // Cold verification, discovery or a target's
                                    // original backoff may precede any real send.
                                    tokio::time::sleep(Duration::from_millis(20)).await;
                                    continue;
                                }
                                assert!(entry.stage == crate::propagation_outbox::PublicationStage::Completed
                                    && entry.pending.is_empty(),
                                    "first successful retry turn split the original frozen effects: stage={:?}, pending={}",
                                    entry.stage, entry.pending.len());
                            } else {
                                let closed = closed.iter().find(|entry| entry.binding.canonical.block_id == id)
                                    .expect("original record disappeared without a real closed source");
                                assert!(closed.released);
                                assert_eq!(closed.binding.effects_digest, digest);
                            }
                            break;
                        }
                    }).await.expect("no successful real publication retry before fixture deadline");
                }
                worker.test_pause_background(false);
            }
            // Inspect the actual worker's completed checkpoint before allowing
            // source closure. Both FastSync effects must really remain in the
            // fixed plan and have no outstanding receipt debt.
            tokio::time::timeout(Duration::from_secs(90), async {
                loop {
                    // The explicit retry above already witnessed all original
                    // effects complete, including any resulting Released close.
                    if single_retry { break; }
                    let (active, _) = inspect_closure_progress(engine.db(), &domain).unwrap();
                    if let Some(entry) = active.iter().find(|e| {
                        e.record.block_id == id
                            && e.stage == crate::propagation_outbox::PublicationStage::Completed
                    }) {
                        use crate::propagation_outbox::{PublicationKind, PublicationTarget};
                        assert!(entry.pending.is_empty());
                        for kind in [PublicationKind::Candidate, PublicationKind::Finality] {
                            assert!(
                                entry.record.effects.iter().any(|effect| effect.kind == kind
                                    && effect.target == PublicationTarget::FastSync),
                                "real FastSync effect was removed from the completed plan"
                            );
                        }
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("real worker FastSync/Public effects did not complete");
            let closed = tokio::time::timeout(Duration::from_secs(90), async {
                loop {
                    driver.maintain().unwrap();
                    let (active, closed) = inspect_closure_progress(engine.db(), &domain).unwrap();
                    assert!(active.len() <= 1, "per-event active capacity was not reclaimed");
                    if closed.len() == index + 1
                        && closed.iter().all(|x| x.released)
                        && driver.counts().unwrap() == (0, 0, index + 1)
                    {
                        assert!(active.is_empty(), "Released retains the large canonical record");
                        break closed;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("real network effects/custody/Delivered/Released did not finish");
            // The certified observer receives both transports. Finality's
            // shared Engine handler may deduplicate the second arrival; require
            // actual FastSync ingress and successful finality handling, without
            // requiring the same evidence to be accepted twice.
            tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    if observer.test_finality_received_ids.lock().unwrap().contains(&id)
                        && observer.try_get_cached_block_candidate(&id).is_some()
                        && certified.received_candidate_and_finality_ingress(&id)
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("public and certified FastSync observers did not process the exact candidate and finality");
            // Keep the real receiving frontier current AFTER ingress checks.
            observer.clone().download_and_apply_block(&id, id.seq_no(), false).await.unwrap();
            assert_eq!(
                observer.load_state(&id).await.unwrap().root_cell().repr_hash(),
                expected.repr_hash()
            );
            let entry = closed.iter().find(|x| x.binding.canonical.block_id == id).unwrap();
            assert_eq!(&entry.binding.domain.session_id, runtime.session_id());
            assert_eq!(entry.binding.canonical.source_validator, creator);
            assert_ne!(
                entry.binding.effects_digest,
                crate::propagation_outbox::effects_digest(&[]).unwrap(),
                "the test must actually complete publication effects"
            );
            if index == 0 {
                let before = crate::propagation_outbox::export_rows(engine.db()).unwrap();
                let worker = engine.ensure_publication_worker().await.unwrap();
                assert!(
                    worker
                        .authorize_closing_history_debt(
                            entry.offer().request,
                            runtime.clone(),
                            crate::history_read_budget::HistoryReadBudget::new(Default::default())
                        )
                        .await
                        .is_err(),
                    "real compact Released record must not mint new history admission"
                );
                let after = crate::propagation_outbox::export_rows(engine.db()).unwrap();
                assert_eq!(after, before, "failed compact admission mutated durable outbox");
            }
            assert!(generations.insert(entry.lease_generation));
            assert!(engine.load_block_handle(&id).unwrap().unwrap().is_applied());
            assert_eq!(
                engine.load_state(&id).await.unwrap().root_cell().repr_hash(),
                expected.repr_hash()
            );
            parent = id;
            root = expected;
        }
        assert_eq!(generations.len(), events);
        drop(driver); // one source owner/session for the complete active run
        (runtime, namespace, domain, first.unwrap(), backup.unwrap())
    })
    .catch_unwind()
    .await;
    for receiver in certified_receivers {
        receiver.stop_and_wait().await.unwrap();
    }
    pair.stop_all().await;
    let (runtime, namespace, domain, first, (old_path, old_bytes)) =
        run.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    let Pair { _dir: dir, provider, receiver, .. } = pair;
    drop(provider);
    drop(receiver);
    // Restore a real pre-Delivered backup after all node/source owners stopped.
    // It must upgrade via Released, never restage/refresh the original event.
    std::fs::write(&old_path, old_bytes).unwrap();
    let engine = open_engine(&dir.path().join("provider")).await;
    let run = std::panic::AssertUnwindSafe(async {
        let before = inspect_closure_progress(engine.db(), &domain).unwrap();
        assert!(before.0.is_empty());
        assert_eq!(before.1.len(), events);
        let sink = engine.clone().durable_finality_sink(runtime.clone()).await.unwrap();
        let confirm =
            engine.ensure_publication_worker().await.unwrap().delivered_sink(runtime.clone());
        let driver = FinalityDeliveryTestDriver::open(runtime, &namespace, sink, confirm).unwrap();
        tokio::time::timeout(Duration::from_secs(90), async {
            loop {
                driver.poll(first.clone()).unwrap();
                driver.maintain().unwrap();
                if !old_path.exists() && driver.counts().unwrap() == (0, 0, events) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("old source backup must reconcile against real cold custody and Released");
        let after = inspect_closure_progress(engine.db(), &domain).unwrap();
        assert!(after.0.is_empty(), "old backup resurrected active canonical quota");
        assert_eq!(
            after.1, before.1,
            "old backup changed generation/original timestamp or evidence"
        );
        drop(driver);
    })
    .catch_unwind()
    .await;
    engine.wait_stop().await.unwrap();
    run.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit public fixture signer and real multi-Engine network/WAL"]
async fn persistent_closure_engine_real_source_smoke_and_cold_backup() {
    circulation(2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "explicit public signer and real source/Engine/transport required"]
async fn persistent_closure_authenticated_demand_drives_acceptance_before_offer() {
    circulation_with_close_demand(1, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "explicit public signer and real source/Engine/transport required"]
async fn persistent_closure_single_retry_completes_original_effect_plan() {
    circulation_with_retry_turn(1, true, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "long real 1025-event source/Engine/network/WAL capacity acceptance; public signer required"]
async fn persistent_closure_engine_single_active_session_over_1024() {
    circulation(1025).await;
}

#[path = "persistent_closure_crash_tests.rs"]
mod persistent_closure_crash_tests;

#[path = "persistent_closure_write_failure_tests.rs"]
mod persistent_closure_write_failure_tests;

#[path = "historical_recovery_engine_tests.rs"]
mod historical_recovery_engine_tests;

#[path = "historical_closing_cold_tests.rs"]
mod historical_closing_cold_tests;
