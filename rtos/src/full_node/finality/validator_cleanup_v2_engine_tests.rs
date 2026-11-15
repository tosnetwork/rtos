// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Journaled deletion of a retired authenticated namespace that holds one
//! real Released close and its durable custody lease: the fresh path, a stop
//! or restart at every boundary, custody refusals on resume, a busy or
//! uncertain lease release, and uncertain journal writes.
use super::{
    retirement_preparation::{pin_floor, store_synthetic_mc_state},
    *,
};
use crate::{
    propagation_outbox::closing::ClosingRecord,
    publication_dependency_leases::LeaseBinding,
    validator::{
        consensus::ConsensusOptions,
        validator_cleanup_gc::{
            CleanupPoint, CleanupTestHook, CLEANUP_TEST_HOOK, CLEANUP_WRITE_FAULT,
        },
        validator_group::ValidatorGroup,
        validator_manager::CleanupHarness,
        validator_utils::GeneralSessionInfo,
    },
};
use consensus_common::validator_cleanup::{
    candidate_claim_key, CleanupJournal, NamespaceLayout, PendingValidatorCleanup,
};

/// A retired authenticated session whose namespace holds one real Released
/// close, with the floor pinned past its retirement.
struct Retired {
    session: UInt256,
    v2_ns: String,
    v2_dir: PathBuf,
    domain: OutboxDomain,
    close: ClosingRecord,
    floor: BlockIdExt,
}

/// Clears the global test controls on every exit.
struct Controls;
impl Controls {
    fn stop_at(namespace: &str, point: CleanupPoint) -> Self {
        let namespace = namespace.to_owned();
        let hook: CleanupTestHook =
            Arc::new(move |at, reached| at == namespace && reached == point);
        *CLEANUP_TEST_HOOK.lock().unwrap() = Some(hook);
        Self
    }
    fn none() -> Self {
        *CLEANUP_TEST_HOOK.lock().unwrap() = None;
        *CLEANUP_WRITE_FAULT.lock().unwrap() = None;
        Self
    }
}
impl Drop for Controls {
    fn drop(&mut self) {
        if let Ok(mut hook) = CLEANUP_TEST_HOOK.lock() {
            *hook = None;
        }
        if let Ok(mut fault) = CLEANUP_WRITE_FAULT.lock() {
            *fault = None;
        }
    }
}

fn signer() -> String {
    let signer = std::env::var("RTOS_PUBLIC_FIXTURE_SIGNER")
        .expect("set RTOS_PUBLIC_FIXTURE_SIGNER to the archived public-only fixture signer");
    assert!(Path::new(&signer).is_file());
    signer
}

/// Circulates one masterchain event of a real authenticated session to a
/// Released close with durable custody, retires the session through the
/// manager and pins a floor that makes its namespace eligible.
async fn retire_one_released_event(pair: &Pair, signer: &str) -> (CleanupHarness, Retired) {
    let engine = &pair.provider;
    engine.clone().download_and_apply_block(pair.master.id(), 1, false).await.unwrap();
    let zero = engine.load_state(&pair.anchor).await.unwrap();
    let config = zero.config_params().unwrap();
    let cc = pair.master.block().unwrap().read_info().unwrap().gen_catchain_seqno();
    let (committee, _) = config
        .validator_set()
        .unwrap()
        .calc_subset(&config.catchain_config().unwrap(), SHARD_FULL, -1, cc)
        .unwrap();
    let local_key =
        engine.network().context().stack.adnl.key_by_tag(NodeNetwork::TAG_OVERLAY_KEY).unwrap();
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
            committee.clone(),
            local_key.id().clone(),
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
    let confirm = engine.ensure_publication_worker().await.unwrap().delivered_sink(runtime.clone());
    FinalityDeliveryTestDriver::provision_validator_namespace(&runtime, &namespace).unwrap();
    let driver =
        FinalityDeliveryTestDriver::open(runtime.clone(), &namespace, sink, confirm).unwrap();
    driver.prepare_intents(false).unwrap();
    engine.enable_publication_worker().await.unwrap();
    let parent = pair.master.id().clone();
    driver.bind_start(parent.clone()).unwrap();
    let root = engine.load_state(&parent).await.unwrap().root_cell().clone();
    pair.refresh_public_advertisements().await;
    let (id, _, row) = chain::successor(signer, &parent, &root, false, 0, cc, &creator);
    let block = fixture_block(&row);
    let proof = BlockProofStuff::deserialize(&id, decode(&row["proof_boc"]), false).unwrap();
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
        finality: SessionFinality::Carrier(proof.drain_signatures().unwrap()),
        last_mc_finalized_seqno: 0,
        candidate_already_sent: false,
        created_at_unix_secs: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    engine.set_test_chain_time(Some(1002 + id.seq_no()));
    pair.receiver.set_test_chain_time(Some(1002 + id.seq_no()));
    if let Some(observer) = &pair.observer {
        observer.set_test_chain_time(Some(1002 + id.seq_no()));
    }
    // The session's finalization walk retains the FinalCert and seals its
    // trigger's outputs before delivery completes, as a running session does.
    driver.retain_final_cert(&draft, &[parent.clone()]).unwrap();
    driver.seal_final_output(&draft).unwrap();
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if driver.poll(draft.clone()).unwrap() && driver.counts().unwrap().1 == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the real source did not retain the event");
    let close = tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            driver.maintain().unwrap();
            let (active, closed) = inspect_closure_progress(engine.db(), &domain).unwrap();
            if active.is_empty()
                && closed.len() == 1
                && closed[0].released
                && driver.counts().unwrap() == (0, 0, 1)
            {
                break closed[0].clone();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the real event did not reach a Released close");
    assert_eq!(close.binding.canonical.block_id, id);
    drop(driver);

    // Retire the session through the production path.
    let options = crate::validator::validator_manager::build_historical_simplex_options(
        &zero.config_params().unwrap(),
        &pair.anchor.shard(),
    )
    .unwrap();
    let info = Arc::new(GeneralSessionInfo {
        shard: pair.anchor.shard().clone(),
        opts_hash: UInt256::default(),
        catchain_seqno: cc,
        key_seqno: 0,
        max_vertical_seqno: 0,
    });
    let set = ValidatorSet::with_cc_seqno(
        0,
        u32::MAX,
        u16::try_from(committee.len()).unwrap(),
        cc,
        committee.clone(),
    )
    .unwrap();
    let session = runtime.session_id().clone();
    let group = Arc::new(
        ValidatorGroup::new(
            info,
            local_key.clone(),
            session.clone(),
            UInt256::default(),
            set,
            0,
            ConsensusOptions::Simplex(options),
            engine.clone(),
            false,
            None,
        )
        .with_authenticated_runtime(runtime.clone())
        .unwrap(),
    );
    let mut manager = CleanupHarness::new(engine.clone());
    manager.retire(session.clone(), group.clone()).await.unwrap();
    let terminal = group.clone().stop(tokio::runtime::Handle::current(), false).await;
    log::info!("retired group teardown: {terminal:?}");
    drop(group);
    let record = engine
        .load_validator_cleanup_page("", 256)
        .unwrap()
        .records
        .into_iter()
        .find(|record| record.session_id == session)
        .expect("retirement persisted the record");
    assert!(record.identity.is_some());
    let v2_ns = record.namespace.clone();
    let v2_dir =
        PathBuf::from(engine.db_root_dir().unwrap()).join("catchains/consensus").join(&v2_ns);
    assert_eq!(v2_dir, namespace, "the record names the namespace the event lives in");
    // A floor past the retirement checkpoint at a later catchain.
    let floor = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        5001,
        UInt256::from([0x52; 32]),
        UInt256::from([0x53; 32]),
    );
    store_synthetic_mc_state(engine, &floor, cc + 10, &[&record.retirement_checkpoint], None).await;
    pin_floor(engine, &floor).await;
    let retired = Retired { session, v2_ns, v2_dir, domain, close, floor };
    (manager, retired)
}

fn lease(engine: &Arc<Engine>, close: &ClosingRecord) -> LeaseBinding {
    engine
        .db()
        .repair_leases()
        .binding_for(
            close.lease_generation,
            &UInt256::calc_file_hash(&close.binding.encode().unwrap()),
            &close.dependency_digest,
        )
        .unwrap()
}

fn close_present(engine: &Arc<Engine>, retired: &Retired) -> bool {
    inspect_closure_progress(engine.db(), &retired.domain)
        .unwrap()
        .1
        .iter()
        .any(|close| close.binding.delivery_id == retired.close.binding.delivery_id)
}

fn journal(engine: &Arc<Engine>, retired: &Retired) -> Option<PendingValidatorCleanup> {
    engine.load_validator_cleanup_record(&retired.v2_ns).unwrap()
}

/// Both reservations of the namespace are held by someone.
fn owned(engine: &Arc<Engine>, retired: &Retired) -> bool {
    let admission = engine
        .finality_recovery_registry()
        .reserve_cleanup(&retired.session, &NamespaceLayout::V2Validator)
        .unwrap();
    let held = admission.is_none();
    if let Some(admission) = admission {
        admission.release();
    }
    held
}

/// The durable and physical state a journal state implies.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Physical {
    journal: &'static str,
    associations: usize,
    directory: bool,
    close: bool,
    lease: &'static str,
}

fn physical(engine: &Arc<Engine>, retired: &Retired) -> Physical {
    let record = journal(engine, retired);
    Physical {
        journal: match record.as_ref().map(|record| &record.journal) {
            None => "erased",
            Some(CleanupJournal::Pending) => "pending",
            Some(CleanupJournal::Deleting(_)) => "deleting",
            Some(CleanupJournal::Deleted(_)) => "deleted",
            Some(CleanupJournal::Releasing(_)) => "releasing",
        },
        associations: record
            .as_ref()
            .and_then(|record| record.journal.payload())
            .map_or(0, |payload| payload.associations.len()),
        directory: retired.v2_dir.exists(),
        close: close_present(engine, retired),
        lease: match lease(engine, &retired.close) {
            LeaseBinding::Absent => "absent",
            LeaseBinding::Matched(_) => "matched",
            LeaseBinding::Mismatch => "mismatch",
        },
    }
}

fn gone(engine: &Arc<Engine>, retired: &Retired) {
    assert_eq!(
        physical(engine, retired),
        Physical {
            journal: "erased",
            associations: 0,
            directory: false,
            close: false,
            lease: "absent"
        }
    );
    assert!(engine
        .db()
        .load_validator_state_key_bounded(&candidate_claim_key(&retired.session), 512)
        .unwrap()
        .is_some());
}

/// Runs `body` on a fresh source fixture, stopping every engine even when
/// it panics.
async fn with_pair(
    body: impl for<'a> FnOnce(&'a Pair, &'a str) -> futures::future::BoxFuture<'a, ()>,
) {
    let signer = signer();
    let pair = Pair::with_source_transport("included").await;
    let _controls = Controls::none();
    let run = std::panic::AssertUnwindSafe(body(&pair, &signer)).catch_unwind().await;
    pair.stop_all().await;
    run.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

/// Runs `before` on a fresh source fixture, stops every engine, reopens the
/// provider on the same database with a fresh manager and the floor
/// re-pinned, and runs `after` on it.
async fn across_restart(
    before: impl for<'a> FnOnce(&'a Pair, &'a str) -> futures::future::BoxFuture<'a, Retired>,
    after: impl for<'a> FnOnce(
        &'a Arc<Engine>,
        &'a mut CleanupHarness,
        &'a Retired,
    ) -> futures::future::BoxFuture<'a, ()>,
) {
    let signer = signer();
    let pair = Pair::with_source_transport("included").await;
    let _controls = Controls::none();
    let run = std::panic::AssertUnwindSafe(before(&pair, &signer)).catch_unwind().await;
    pair.stop_all().await;
    let retired = run.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    let Pair { _dir: dir, provider, receiver, observer, .. } = pair;
    drop((provider, receiver, observer));
    let engine = open_engine(&dir.path().join("provider")).await;
    let run = std::panic::AssertUnwindSafe(async {
        // The keeper restores the persisted floor itself on a same-DB restart.
        engine.maintain_validator_cleanup_floor().await.unwrap();
        assert_eq!(
            engine.validator_cleanup_floor().map(|(id, _)| id),
            Some(retired.floor.clone()),
            "the floor survives the restart"
        );
        let mut manager = CleanupHarness::new(engine.clone());
        after(&engine, &mut manager, &retired).await;
    })
    .catch_unwind()
    .await;
    engine.clone().wait_stop().await.unwrap();
    run.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit public fixture signer and real multi-Engine network/WAL"]
async fn validator_cleanup_v2_real_association_fresh_path_releases_close_and_lease() {
    with_pair(|pair, signer| {
        Box::pin(async move {
            let (mut manager, retired) = retire_one_released_event(pair, signer).await;
            let engine = pair.provider.clone();
            assert_eq!(physical(&engine, &retired), state("pending", 0, true, true, "matched"));
            manager.tick().await;
            assert_eq!(manager.v2_outcome(&retired.v2_ns).as_deref(), Some("gone"));
            gone(&engine, &retired);
            assert!(!owned(&engine, &retired), "released after the erase ack");
            assert!(!manager.delete_in_flight(&retired.session));
        })
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit public fixture signer and real multi-Engine network/WAL"]
async fn validator_cleanup_v2_real_association_resumes_in_process_after_b0() {
    with_pair(|pair, signer| {
        Box::pin(async move {
            let (mut manager, retired) = retire_one_released_event(pair, signer).await;
            let engine = pair.provider.clone();
            {
                let _stop = Controls::stop_at(&retired.v2_ns, CleanupPoint::AfterB0);
                manager.tick().await;
            }
            assert_eq!(
                manager.v2_outcome(&retired.v2_ns).as_deref(),
                Some("retained: test stop after B0")
            );
            assert_eq!(physical(&engine, &retired), state("deleting", 1, true, true, "matched"));
            let record = journal(&engine, &retired).unwrap();
            let association = record.journal.payload().unwrap().associations[0].clone();
            assert_eq!(association.delivery_id, retired.close.binding.delivery_id);
            assert_eq!(association.lease_generation, retired.close.lease_generation);
            assert_eq!(association.close_generation, retired.close.binding.close_generation);
            assert!(owned(&engine, &retired) && manager.delete_in_flight(&retired.session));
            // The next tick resumes under the same reservation: re-authenticate,
            // reopen custody, verify the close, then finish.
            manager.tick().await;
            assert_eq!(manager.v2_outcome(&retired.v2_ns).as_deref(), Some("gone"));
            gone(&engine, &retired);
            assert!(!owned(&engine, &retired));
        })
    })
    .await;
}

fn state(
    journal: &'static str,
    associations: usize,
    directory: bool,
    close: bool,
    lease: &'static str,
) -> Physical {
    Physical { journal, associations, directory, close, lease }
}

/// Stops the attempt at `point`, checks the durable and physical state it
/// left, restarts the node and checks that a fresh manager takes the
/// journal over (re-stamped with its own attempt) and finishes.
async fn restart_after(point: CleanupPoint, expected: Physical) {
    let expected_after = expected.clone();
    across_restart(
        move |pair, signer| {
            Box::pin(async move {
                let (mut manager, retired) = retire_one_released_event(pair, signer).await;
                let engine = pair.provider.clone();
                let _stop = Controls::stop_at(&retired.v2_ns, point);
                manager.tick().await;
                assert!(manager
                    .v2_outcome(&retired.v2_ns)
                    .is_some_and(|outcome| outcome.starts_with("retained: test stop after")));
                assert_eq!(physical(&engine, &retired), expected);
                assert!(owned(&engine, &retired) && manager.delete_in_flight(&retired.session));
                retired
            })
        },
        move |engine, manager, retired| {
            Box::pin(async move {
                // The journal names the previous process's attempt; this
                // process first re-stamps it with its own, changing nothing
                // else, before acting on it.
                let before = journal(engine, retired).unwrap();
                let old = before.journal.payload().unwrap().clone();
                assert_eq!(old.attempt >> 32, 1, "written by the first incarnation");
                {
                    let _stop = Controls::stop_at(&retired.v2_ns, CleanupPoint::AfterTakeover);
                    manager.tick().await;
                }
                assert_eq!(
                    manager.v2_outcome(&retired.v2_ns).as_deref(),
                    Some("retained: test stop after takeover")
                );
                let after = journal(engine, retired).unwrap();
                let new = after.journal.payload().unwrap().clone();
                assert_eq!(new.attempt >> 32, 2, "this process's incarnation");
                assert_ne!((new.generation, new.attempt), (old.generation, old.attempt));
                let restamped = consensus_common::validator_cleanup::JournalPayload {
                    attempt: old.attempt,
                    generation: old.generation,
                    ..new.clone()
                };
                assert_eq!(restamped, old, "only the token changed");
                assert_eq!(
                    std::mem::discriminant(&after.journal),
                    std::mem::discriminant(&before.journal)
                );
                assert_eq!(physical(engine, retired), expected_after);
                manager.tick().await;
                assert_eq!(manager.v2_outcome(&retired.v2_ns).as_deref(), Some("gone"));
                gone(engine, retired);
                assert!(!owned(engine, retired));
            })
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit public fixture signer and real multi-Engine network/WAL"]
async fn validator_cleanup_v2_real_association_restart_after_b0() {
    restart_after(CleanupPoint::AfterB0, state("deleting", 1, true, true, "matched")).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit public fixture signer and real multi-Engine network/WAL"]
async fn validator_cleanup_v2_real_association_restart_after_b1() {
    restart_after(CleanupPoint::AfterB1, state("deleting", 1, false, true, "matched")).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit public fixture signer and real multi-Engine network/WAL"]
async fn validator_cleanup_v2_real_association_restart_after_b1_prime() {
    restart_after(CleanupPoint::AfterB1Prime, state("deleted", 1, false, true, "matched")).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit public fixture signer and real multi-Engine network/WAL"]
async fn validator_cleanup_v2_real_association_restart_after_b2() {
    restart_after(CleanupPoint::AfterB2, state("releasing", 1, false, false, "matched")).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit public fixture signer and real multi-Engine network/WAL"]
async fn validator_cleanup_v2_real_association_restart_after_b3() {
    restart_after(CleanupPoint::AfterB3, state("releasing", 1, false, false, "absent")).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit public fixture signer and real multi-Engine network/WAL"]
async fn validator_cleanup_v2_real_association_busy_lease_release_is_retained_then_retried() {
    with_pair(|pair, signer| {
        Box::pin(async move {
            let (mut manager, retired) = retire_one_released_event(pair, signer).await;
            let engine = pair.provider.clone();
            {
                let _stop = Controls::stop_at(&retired.v2_ns, CleanupPoint::AfterB2);
                manager.tick().await;
            }
            let leases = engine.db().repair_leases().clone();
            let gate = leases.protection().try_deletion().expect("no other gate holder");
            manager.tick().await;
            assert_eq!(
                manager.v2_outcome(&retired.v2_ns).as_deref(),
                Some("retained: lease release busy")
            );
            assert_eq!(physical(&engine, &retired), state("releasing", 1, false, false, "matched"));
            assert!(owned(&engine, &retired) && manager.delete_in_flight(&retired.session));
            drop(gate);
            manager.tick().await;
            assert_eq!(manager.v2_outcome(&retired.v2_ns).as_deref(), Some("gone"));
            gone(&engine, &retired);
        })
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit public fixture signer and real multi-Engine network/WAL"]
async fn validator_cleanup_v2_real_association_lease_delete_applied_sync_failed_then_restart() {
    across_restart(
        |pair, signer| {
            Box::pin(async move {
                let (mut manager, retired) = retire_one_released_event(pair, signer).await;
                let engine = pair.provider.clone();
                {
                    let _stop = Controls::stop_at(&retired.v2_ns, CleanupPoint::AfterB2);
                    manager.tick().await;
                }
                // The lease delete commits; its WAL sync then reports an error.
                let leases = engine.db().repair_leases().clone();
                leases.set_sync_observer(Some(Arc::new(|point, _| {
                    if point == storage::durability::SyncPoint::Wal {
                        rtos_block::fail!("injected lease WAL sync failure");
                    }
                    Ok(())
                })));
                manager.tick().await;
                leases.set_sync_observer(None);
                let outcome = manager.v2_outcome(&retired.v2_ns).unwrap();
                assert!(outcome.starts_with("retained: "), "{outcome}");
                assert!(outcome.contains("injected lease WAL sync failure"), "{outcome}");
                assert_eq!(
                    journal(&engine, &retired).map(|r| r.journal.payload().is_some()),
                    Some(true)
                );
                assert!(owned(&engine, &retired) && manager.delete_in_flight(&retired.session));
                // The poisoned ledger refuses everything until a reopen.
                assert!(leases
                    .binding_for(
                        retired.close.lease_generation,
                        &UInt256::default(),
                        &UInt256::default()
                    )
                    .is_err());
                retired
            })
        },
        |engine, manager, retired| {
            Box::pin(async move {
                assert_eq!(
                    physical(engine, retired),
                    state("releasing", 1, false, false, "absent")
                );
                manager.tick().await;
                assert_eq!(manager.v2_outcome(&retired.v2_ns).as_deref(), Some("gone"));
                gone(engine, retired);
            })
        },
    )
    .await;
}

/// An injected fault on the journal write at `point`, applied or not: the
/// attempt is uncertain, keeps everything, confirms the exact durable state
/// with a synced re-write and finishes.
async fn uncertain_journal_write(point: CleanupPoint, applied: bool, durable: Physical) {
    with_pair(move |pair, signer| {
        Box::pin(async move {
            let (mut manager, retired) = retire_one_released_event(pair, signer).await;
            let engine = pair.provider.clone();
            *CLEANUP_WRITE_FAULT.lock().unwrap() = Some((retired.v2_ns.clone(), point, applied));
            manager.tick().await;
            assert_eq!(
                manager.v2_outcome(&retired.v2_ns).as_deref(),
                Some("uncertain: injected journal write fault")
            );
            assert!(CLEANUP_WRITE_FAULT.lock().unwrap().is_none(), "the fault fired");
            assert_eq!(physical(&engine, &retired), durable);
            assert!(owned(&engine, &retired) && manager.delete_in_flight(&retired.session));
            manager.tick().await;
            assert_eq!(manager.v2_outcome(&retired.v2_ns).as_deref(), Some("gone"));
            gone(&engine, &retired);
            assert!(!owned(&engine, &retired));
        })
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit public fixture signer and real multi-Engine network/WAL"]
async fn validator_cleanup_v2_real_association_uncertain_b0_not_applied() {
    uncertain_journal_write(
        CleanupPoint::AfterB0,
        false,
        state("pending", 0, true, true, "matched"),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit public fixture signer and real multi-Engine network/WAL"]
async fn validator_cleanup_v2_real_association_uncertain_b0_applied() {
    uncertain_journal_write(
        CleanupPoint::AfterB0,
        true,
        state("deleting", 1, true, true, "matched"),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit public fixture signer and real multi-Engine network/WAL"]
async fn validator_cleanup_v2_real_association_uncertain_b1_prime_not_applied() {
    uncertain_journal_write(
        CleanupPoint::AfterB1Prime,
        false,
        state("deleting", 1, false, true, "matched"),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit public fixture signer and real multi-Engine network/WAL"]
async fn validator_cleanup_v2_real_association_uncertain_b1_prime_applied() {
    uncertain_journal_write(
        CleanupPoint::AfterB1Prime,
        true,
        state("deleted", 1, false, true, "matched"),
    )
    .await;
}

/// B2's single outbox batch fails before writing or after its sync: the
/// attempt is uncertain and the outbox requires a reopen; after a restart
/// the journal is taken over and finished.
async fn uncertain_b2(boundary: crate::internal_db::OutboxSyncBoundary, durable: Physical) {
    across_restart(
        move |pair, signer| {
            Box::pin(async move {
                let (mut manager, retired) = retire_one_released_event(pair, signer).await;
                let engine = pair.provider.clone();
                {
                    let _stop = Controls::stop_at(&retired.v2_ns, CleanupPoint::AfterB1Prime);
                    manager.tick().await;
                }
                engine.db().set_outbox_sync_observer(Some(Arc::new(move |at, _, _| {
                    if at == boundary {
                        rtos_block::fail!("injected outbox batch failure");
                    }
                    Ok(())
                })));
                manager.tick().await;
                engine.db().set_outbox_sync_observer(None);
                let outcome = manager.v2_outcome(&retired.v2_ns).unwrap();
                assert!(outcome.starts_with("uncertain: "), "{outcome}");
                assert_eq!(physical(&engine, &retired), durable);
                assert!(owned(&engine, &retired) && manager.delete_in_flight(&retired.session));
                // The failed outbox refuses until reopened: still not done.
                manager.tick().await;
                assert!(journal(&engine, &retired).is_some());
                assert!(owned(&engine, &retired));
                retired
            })
        },
        |engine, manager, retired| {
            Box::pin(async move {
                assert_eq!(physical(engine, retired), durable_after_reopen(retired, engine));
                manager.tick().await;
                assert_eq!(manager.v2_outcome(&retired.v2_ns).as_deref(), Some("gone"));
                gone(engine, retired);
            })
        },
    )
    .await;
}

/// The reopened state equals the state before the restart (re-read).
fn durable_after_reopen(retired: &Retired, engine: &Arc<Engine>) -> Physical {
    physical(engine, retired)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit public fixture signer and real multi-Engine network/WAL"]
async fn validator_cleanup_v2_real_association_uncertain_b2_not_applied() {
    uncertain_b2(
        crate::internal_db::OutboxSyncBoundary::BeforeWrite,
        state("deleted", 1, false, true, "matched"),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit public fixture signer and real multi-Engine network/WAL"]
async fn validator_cleanup_v2_real_association_uncertain_b2_applied() {
    uncertain_b2(
        crate::internal_db::OutboxSyncBoundary::AfterSuccessfulSync,
        state("releasing", 1, false, false, "matched"),
    )
    .await;
}

/// The archive package file that holds `bytes`, and their offset in it.
fn package_holding(root: &Path, bytes: &[u8]) -> (PathBuf, usize) {
    let mut stack = vec![root.join("archive")];
    while let Some(directory) = stack.pop() {
        for entry in std::fs::read_dir(&directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(content) = std::fs::read(&path) {
                if let Some(offset) =
                    content.windows(bytes.len()).position(|window| window == bytes)
                {
                    return (path, offset);
                }
            }
        }
    }
    panic!("no archive package holds the dependency");
}

/// Physical damage to the custody's proof dependency, with the lease and
/// close metadata untouched, before resumed B1 (stop after B0) or before B2
/// (stop after B1′): the resume refuses custody and keeps ownership,
/// removes nothing and leaves the journal unchanged; once restored, it
/// finishes.
async fn damaged_custody(point: CleanupPoint, missing: bool, expected: Physical) {
    with_pair(move |pair, signer| {
        Box::pin(async move {
            let (mut manager, retired) = retire_one_released_event(pair, signer).await;
            let engine = pair.provider.clone();
            {
                let _stop = Controls::stop_at(&retired.v2_ns, point);
                manager.tick().await;
            }
            let record = engine
                .db()
                .repair_leases()
                .lookup(
                    retired.close.lease_generation,
                    &crate::history_read_budget::HistoryReadBudget::new(Default::default()),
                )
                .unwrap();
            let proof_id = record
                .dependencies
                .iter()
                .find(|dependency| dependency.kind == "proof")
                .expect("the custody depends on a proof")
                .validate()
                .unwrap();
            let handle = engine.load_block_handle(&proof_id).unwrap().unwrap();
            let proof = engine.load_block_proof(&handle, false).await.unwrap().data().to_vec();
            let (package, offset) =
                package_holding(Path::new(engine.db_root_dir().unwrap()), &proof);
            let original = std::fs::read(&package).unwrap();
            if missing {
                std::fs::remove_file(&package).unwrap();
            } else {
                let mut damaged = original.clone();
                damaged[offset + proof.len() / 2] ^= 1;
                std::fs::write(&package, damaged).unwrap();
            }
            let journal_before = journal(&engine, &retired);
            manager.tick().await;
            let outcome = manager.v2_outcome(&retired.v2_ns).unwrap_or_default();
            // Restore the physical evidence before asserting.
            std::fs::write(&package, &original).unwrap();
            assert!(outcome.starts_with("retained: custody: "), "{outcome}");
            assert_eq!(journal(&engine, &retired), journal_before, "the journal is unchanged");
            assert_eq!(physical(&engine, &retired), expected, "nothing further was removed");
            assert!(owned(&engine, &retired) && manager.delete_in_flight(&retired.session));
            manager.tick().await;
            assert_eq!(manager.v2_outcome(&retired.v2_ns).as_deref(), Some("gone"));
            gone(&engine, &retired);
        })
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit public fixture signer and real multi-Engine network/WAL"]
async fn validator_cleanup_v2_real_association_missing_custody_file_before_b1() {
    damaged_custody(CleanupPoint::AfterB0, true, state("deleting", 1, true, true, "matched")).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit public fixture signer and real multi-Engine network/WAL"]
async fn validator_cleanup_v2_real_association_corrupt_custody_file_before_b1() {
    damaged_custody(CleanupPoint::AfterB0, false, state("deleting", 1, true, true, "matched"))
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit public fixture signer and real multi-Engine network/WAL"]
async fn validator_cleanup_v2_real_association_missing_custody_file_before_b2() {
    damaged_custody(CleanupPoint::AfterB1Prime, true, state("deleted", 1, false, true, "matched"))
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit public fixture signer and real multi-Engine network/WAL"]
async fn validator_cleanup_v2_real_association_corrupt_custody_file_before_b2() {
    damaged_custody(CleanupPoint::AfterB1Prime, false, state("deleted", 1, false, true, "matched"))
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit public fixture signer and real multi-Engine network/WAL"]
async fn validator_cleanup_v2_real_association_journal_naming_another_namespaces_lease_never_releases_it(
) {
    across_restart(
        |pair, signer| {
            Box::pin(async move {
                // B: the real validator namespace, stopped after B2 with its
                // close removed and its lease still live.
                let (mut manager, retired) = retire_one_released_event(pair, signer).await;
                let engine = pair.provider.clone();
                let _stop = Controls::stop_at(&retired.v2_ns, CleanupPoint::AfterB2);
                manager.tick().await;
                assert_eq!(
                    physical(&engine, &retired),
                    state("releasing", 1, false, false, "matched")
                );
                retired
            })
        },
        |engine, manager, retired| {
            Box::pin(async move {
                // B is held elsewhere, so only A is attempted.
                let hold_b = engine
                    .finality_recovery_registry()
                    .reserve_cleanup(&retired.session, &NamespaceLayout::V2Validator)
                    .unwrap()
                    .expect("B is not held after the restart");
                // A: an observer namespace of the same session (another local
                // identity) whose Releasing journal names B's live lease.
                let b = journal(engine, retired).unwrap();
                let identity = b.identity.clone().unwrap();
                let other = UInt256::from([0x77; 32]);
                let mut a = consensus_common::validator_cleanup::make_record(
                    &retired.session,
                    &NamespaceLayout::V2Observer(other.clone()),
                    &identity.binding.coordinates.shard,
                    identity.binding.coordinates.catchain_seqno,
                    &b.retirement_checkpoint,
                )
                .unwrap()
                .with_identity(consensus_common::validator_cleanup::CleanupIdentity {
                    local_adnl: other,
                    ..identity
                })
                .unwrap();
                a.journal = b.journal.clone();
                engine.rewrite_validator_cleanup_record(&a).unwrap();
                manager.tick().await;
                let outcome = manager.v2_outcome(&a.namespace).unwrap_or_default();
                assert!(
                    outcome.starts_with("retained: lease ") && outcome.contains("Vetoed"),
                    "{outcome}"
                );
                assert_eq!(lease_name(engine, retired), "matched", "B's lease is not released");
                assert!(engine
                    .load_validator_cleanup_record(&a.namespace)
                    .unwrap()
                    .is_some_and(|record| matches!(record.journal, CleanupJournal::Releasing(_))));
                assert!(manager.delete_in_flight(&retired.session));
                // B, once free, still releases its own lease.
                hold_b.release();
                manager.tick().await;
                assert_eq!(manager.v2_outcome(&retired.v2_ns).as_deref(), Some("gone"));
                assert_eq!(lease_name(engine, retired), "absent");
            })
        },
    )
    .await;
}

fn lease_name(engine: &Arc<Engine>, retired: &Retired) -> &'static str {
    match lease(engine, &retired.close) {
        LeaseBinding::Absent => "absent",
        LeaseBinding::Matched(_) => "matched",
        LeaseBinding::Mismatch => "mismatch",
    }
}

/// At `point`, once, saves the durable record and rewrites it with an
/// altered manifest digest, as a foreign writer would; the attempt goes on.
fn alter_durable_at(
    engine: &Arc<Engine>,
    namespace: &str,
    point: CleanupPoint,
) -> (Controls, Arc<std::sync::Mutex<Option<PendingValidatorCleanup>>>) {
    let engine = engine.clone();
    let namespace = namespace.to_owned();
    let original = Arc::new(std::sync::Mutex::new(None));
    let saved = original.clone();
    let hook: CleanupTestHook = Arc::new(move |at, reached| {
        let mut saved = saved.lock().unwrap();
        if at == namespace && reached == point && saved.is_none() {
            let record = engine.load_validator_cleanup_record(&namespace).unwrap().unwrap();
            let mut altered = record.clone();
            match &mut altered.journal {
                CleanupJournal::Deleting(payload)
                | CleanupJournal::Deleted(payload)
                | CleanupJournal::Releasing(payload) => {
                    payload.manifest_digest = UInt256::from([0xee; 32])
                }
                CleanupJournal::Pending => panic!("altered before B0"),
            }
            engine.rewrite_validator_cleanup_record(&altered).unwrap();
            *saved = Some(record);
        }
        false
    });
    *CLEANUP_TEST_HOOK.lock().unwrap() = Some(hook);
    (Controls, original)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit public fixture signer and real multi-Engine network/WAL"]
async fn validator_cleanup_v2_real_association_journal_writes_refuse_a_changed_durable_record() {
    with_pair(|pair, signer| {
        Box::pin(async move {
            let (mut manager, retired) = retire_one_released_event(pair, signer).await;
            let engine = pair.provider.clone();
            // B1′ refuses to write over a record changed after B1.
            let original = {
                let (_alter, original) =
                    alter_durable_at(&engine, &retired.v2_ns, CleanupPoint::AfterB1);
                manager.tick().await;
                let saved = original.lock().unwrap().clone();
                saved.expect("the record was altered")
            };
            let outcome = manager.v2_outcome(&retired.v2_ns).unwrap_or_default();
            assert!(outcome.contains("journal changed under the attempt"), "{outcome}");
            assert_ne!(journal(&engine, &retired), Some(original.clone()), "B1′ not written");
            assert_eq!(physical(&engine, &retired), state("deleting", 1, false, true, "matched"));
            assert!(owned(&engine, &retired) && manager.delete_in_flight(&retired.session));
            // Restored exactly, the attempt resumes; B2 then refuses to write
            // over a record changed after B1′.
            engine.rewrite_validator_cleanup_record(&original).unwrap();
            {
                let (_alter, original) =
                    alter_durable_at(&engine, &retired.v2_ns, CleanupPoint::AfterB1Prime);
                manager.tick().await;
                let altered = original.lock().unwrap().is_some();
                assert!(altered, "the record was altered");
            }
            let outcome = manager.v2_outcome(&retired.v2_ns).unwrap_or_default();
            assert!(outcome.contains("journal changed under the attempt"), "{outcome}");
            assert_eq!(physical(&engine, &retired), state("deleted", 1, false, true, "matched"));
            assert!(owned(&engine, &retired) && manager.delete_in_flight(&retired.session));
        })
    })
    .await;
}
