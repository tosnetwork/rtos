// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Retirement preparation through the production group path: a real source
//! circulates one masterchain event through the real node, and real
//! authenticated groups, built by `pre_create_engine` with a real engine
//! reservation and durable sink, are stopped for retirement preparation.
use super::*;
use crate::validator::{
    consensus::ConsensusOptions, retirement_preparation::RetirementOutcome,
    validator_group::ValidatorGroup, validator_utils::GeneralSessionInfo,
};
use consensus_common::finality_delivery::{
    CanonicalFinalityCompletion, CanonicalFinalityRequest, CloseFinalityRequest,
    DurableFinalitySink, DurableFinalitySinkPtr, FinalityCloseCompletion,
    FinalityTerminalCompletion, FinalityTerminalLookup, FinalizedDeliveryCompletion,
};

type LookupResult = rtos_block::Result<FinalityTerminalLookup>;

/// Holding state, changed only under one lock so draining can never miss a
/// lookup admitted or answered concurrently.
struct Held {
    /// The next lookup is held; cleared once one is held or on drain.
    armed: bool,
    /// Draining: every answer goes straight to its real completion.
    forward: bool,
    answer: Option<LookupResult>,
    completion: Option<FinalityTerminalCompletion>,
}

/// Forwards every call to the real engine sink. The first `lookup_terminal`
/// is answered by the real node, but its delivery to the caller is held until
/// the test releases or drains it. No completion is ever fabricated.
struct HoldingSink {
    inner: DurableFinalitySinkPtr,
    held: Arc<std::sync::Mutex<Held>>,
}
impl HoldingSink {
    fn new(inner: DurableFinalitySinkPtr) -> Arc<Self> {
        Arc::new(Self {
            inner,
            held: Arc::new(std::sync::Mutex::new(Held {
                armed: true,
                forward: false,
                answer: None,
                completion: None,
            })),
        })
    }
    /// True once a caller's lookup is admitted and the node has answered it.
    fn holding(&self) -> bool {
        let held = self.held.lock().unwrap();
        held.completion.is_some() && held.answer.is_some()
    }
    /// Delivers the held answer to the caller.
    fn release(&self) {
        let (answer, completion) = {
            let mut held = self.held.lock().unwrap();
            (held.answer.take(), held.completion.take())
        };
        completion.expect("a held lookup")(answer.expect("the node answered the held lookup"));
    }
    /// Cleanup on every path: stop holding, deliver an answer already
    /// received, and let any answer still in flight reach its completion.
    fn drain(&self) {
        let delivery = {
            let mut held = self.held.lock().unwrap();
            held.armed = false;
            held.forward = true;
            if held.answer.is_some() {
                held.answer.take().zip(held.completion.take())
            } else {
                None
            }
        };
        if let Some((answer, completion)) = delivery {
            completion(answer);
        }
    }
    async fn wait_holding(&self) {
        tokio::time::timeout(Duration::from_secs(60), async {
            while !self.holding() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("no lookup reached the group's sink");
    }
}
impl DurableFinalitySink for HoldingSink {
    fn stage(
        &self,
        draft: FinalizedDeliveryDraft,
        completion: FinalizedDeliveryCompletion,
    ) -> Result<()> {
        self.inner.stage(draft, completion)
    }
    fn retain_canonical(
        &self,
        request: CanonicalFinalityRequest,
        completion: CanonicalFinalityCompletion,
    ) -> Result<()> {
        self.inner.retain_canonical(request, completion)
    }
    fn offer_close(
        &self,
        request: CloseFinalityRequest,
        completion: FinalityCloseCompletion,
    ) -> Result<()> {
        self.inner.offer_close(request, completion)
    }
    fn lookup_terminal(
        &self,
        request: CloseFinalityRequest,
        completion: FinalityTerminalCompletion,
    ) -> Result<()> {
        {
            let mut held = self.held.lock().unwrap();
            if !held.armed {
                drop(held);
                return self.inner.lookup_terminal(request, completion);
            }
            held.armed = false;
            held.completion = Some(completion);
        }
        let held = self.held.clone();
        let admitted = self.inner.lookup_terminal(
            request,
            Box::new(move |answer| {
                let delivery = {
                    let mut state = held.lock().unwrap();
                    if state.forward {
                        state.completion.take().map(|completion| (completion, answer))
                    } else {
                        state.answer = Some(answer);
                        None
                    }
                };
                if let Some((completion, answer)) = delivery {
                    completion(answer);
                }
            }),
        );
        if admitted.is_err() {
            // Not admitted: the caller's completion must never run.
            self.held.lock().unwrap().completion = None;
        }
        admitted
    }
}

/// A taken retirement outcome that is abandoned on every exit path, including
/// an assertion failure, so its lease and locks never outlive the test.
struct Taken(Option<RetirementOutcome>);
impl Taken {
    fn from(group: &ValidatorGroup) -> Self {
        Self(group.take_retirement_outcome().unwrap())
    }
    fn prepared(&self) -> &crate::validator::retirement_preparation::RetirementPreparationOwner {
        match &self.0 {
            Some(RetirementOutcome::Prepared(owner)) => owner,
            Some(RetirementOutcome::Refused(refused)) => {
                panic!("expected a preparation, refused: {}", refused.refusal())
            }
            None => panic!("retirement stop produced no outcome"),
        }
    }
    fn refused(&self) -> &crate::validator::retirement_preparation::RetirementRefusalOwner {
        match &self.0 {
            Some(RetirementOutcome::Refused(refused)) => refused,
            Some(RetirementOutcome::Prepared(_)) => panic!("expected a refusal, got a preparation"),
            None => panic!("retirement stop produced no outcome"),
        }
    }
    fn is_prepared(&self) -> bool {
        matches!(self.0, Some(RetirementOutcome::Prepared(_)))
    }
    /// Explicit abandon; true when the lease was released.
    fn abandon(mut self) -> bool {
        Self::release(self.0.take())
    }
    fn release(outcome: Option<RetirementOutcome>) -> bool {
        match outcome {
            Some(RetirementOutcome::Prepared(owner)) => {
                owner.abandon();
                true
            }
            Some(RetirementOutcome::Refused(refused)) => refused.abandon().is_ok(),
            None => false,
        }
    }
}
impl Drop for Taken {
    fn drop(&mut self) {
        Self::release(self.0.take());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit public fixture signer and real multi-Engine network/WAL"]
async fn retirement_preparation_real_group_handoff_and_refusals() {
    let signer = std::env::var("RTOS_PUBLIC_FIXTURE_SIGNER")
        .expect("set RTOS_PUBLIC_FIXTURE_SIGNER to the archived public-only fixture signer");
    assert!(Path::new(&signer).is_file());
    let pair = Pair::with_source_transport("included").await;
    // Held completions and stop tasks are drained on every path before the
    // engines stop, including assertion failures.
    let pending: std::sync::Mutex<(Vec<Arc<HoldingSink>>, Vec<Arc<ValidatorGroup>>)> =
        Default::default();
    let run = std::panic::AssertUnwindSafe(async {
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
        assert!(
            matches!(
                runtime.local_role(),
                consensus_common::session_runtime::LocalRole::Validator(_)
            ),
            "the included provider must be a committee member"
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
        let open_driver = || async {
            let sink = engine.clone().durable_finality_sink(runtime.clone()).await.unwrap();
            let confirm =
                engine.ensure_publication_worker().await.unwrap().delivered_sink(runtime.clone());
            FinalityDeliveryTestDriver::open(runtime.clone(), &namespace, sink, confirm)
        };
        let source_locked = || async { open_driver().await.is_err() };
        // Probing admission must not occupy the namespace: release any lease won.
        let lease_held = || match engine.reserve_normal_session_namespace(&runtime).unwrap() {
            Some(probe) => {
                probe.release();
                false
            }
            None => true,
        };
        let make_group = || {
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
            let group = Arc::new(
                ValidatorGroup::new(
                    info,
                    local_key.clone(),
                    runtime.session_id().clone(),
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
            pending.lock().unwrap().1.push(group.clone());
            group
        };
        let holding_group = || async {
            let group = make_group();
            let sink = HoldingSink::new(
                engine.clone().durable_finality_sink(runtime.clone()).await.unwrap(),
            );
            assert!(group.install_durable_finality_sink_for_test(sink.clone()));
            pending.lock().unwrap().0.push(sink.clone());
            (group, sink)
        };
        let stop = |group: Arc<ValidatorGroup>| async move {
            let rt = tokio::runtime::Handle::current();
            tokio::time::timeout(
                Duration::from_secs(60),
                group.stop_for_retirement_preparation(rt),
            )
            .await
            .expect("retirement stop did not finish")
            .unwrap();
        };

        // A preexisting validator namespace, as a running session leaves it.
        FinalityDeliveryTestDriver::provision_validator_namespace(&runtime, &namespace).unwrap();
        let driver = open_driver().await.unwrap();
        driver.prepare_intents(false).unwrap();
        engine.enable_publication_worker().await.unwrap();
        let parent = pair.master.id().clone();
        driver.bind_start(parent.clone()).unwrap();
        let root = engine.load_state(&parent).await.unwrap().root_cell().clone();
        pair.refresh_public_advertisements().await;
        let (id, _, row) = chain::successor(&signer, &parent, &root, false, 0, cc, &creator);
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
        if let Some(observer) = pair.observer.as_ref() {
            observer.set_test_chain_time(Some(1002 + id.seq_no()));
        }
        // The session's finalization walk retains the FinalCert and seals its
        // trigger's outputs before delivery completes.
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
        .expect("actual source/node retention did not produce reference");
        // Stop at the canonical reference: no closing maintenance yet.
        drop(driver);

        // (a) The group's own session admits a closing lookup at startup; its
        // delivery is held across the retirement stop.
        let (group, sink) = holding_group().await;
        group.clone().pre_create_engine().await.unwrap();
        assert!(group.has_session_for_test().await, "production construction created a session");
        group
            .clone()
            .start_session(
                vec![parent.clone()],
                parent.clone(),
                std::time::SystemTime::now(),
                tokio::runtime::Handle::current(),
            )
            .await
            .unwrap();
        sink.wait_holding().await;
        assert!(lease_held(), "the group holds the engine lease");
        let stopping = tokio::spawn(stop(group.clone()));
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(!stopping.is_finished(), "stop waits for the admitted source callback");
        assert_eq!(group.retirement_scans_started_for_test(), 0, "no scan while it is held");
        assert!(lease_held(), "the lease stays registered through the held callback");
        sink.release();
        tokio::time::timeout(Duration::from_secs(60), stopping)
            .await
            .expect("stop finished after the callback drained")
            .unwrap();
        let outcome = Taken::from(&group);
        if !outcome.is_prepared() {
            let refused = outcome.refused();
            assert!(refused.drained(), "the callback drained before the proof: {}", refused.refusal());
            assert!(refused.holds_reservation());
        }
        assert!(lease_held());
        drop(group);
        assert!(outcome.abandon(), "a drained outcome releases its lease");
        assert!(!lease_held(), "abandon released the lease");

        // Finish the event to node Released through the real source.
        let driver = open_driver().await.unwrap();
        let closed = tokio::time::timeout(Duration::from_secs(120), async {
            loop {
                driver.maintain().unwrap();
                let (_, closed) = inspect_closure_progress(engine.db(), &domain).unwrap();
                if closed.len() == 1 && closed[0].released && driver.counts().unwrap() == (0, 0, 1)
                {
                    break closed;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("real custody/Delivered/Released did not finish");
        let offer = closed[0].offer();
        drop(driver);

        // (b) Prepared, with the first waiter cancelled while the reconciling
        // lookup is held: the shared teardown task completes the handoff.
        let (group, sink) = holding_group().await;
        group.clone().pre_create_engine().await.unwrap();
        let first = tokio::spawn(stop(group.clone()));
        sink.wait_holding().await;
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        assert!(source_locked().await, "the pending scan holds the source store lock");
        assert!(lease_held());
        sink.release();
        stop(group.clone()).await;
        let outcome = Taken::from(&group);
        let preparation = outcome.prepared().preparation().unwrap();
        assert_eq!(preparation.inventory().len(), 1);
        assert_eq!(preparation.inventory()[0].offer, offer);
        assert!(lease_held(), "a prepared namespace stays closed to new sessions");
        assert!(source_locked().await, "the preparation holds the source store lock");
        drop(group);
        assert!(outcome.abandon());
        assert!(!source_locked().await, "abandon released the source store lock");
        assert!(!lease_held());

        // A preparation that panics after a verified drain keeps the lease in
        // its stable owner; the drained refusal may then release it.
        let group = make_group();
        group.clone().pre_create_engine().await.unwrap();
        group.inject_retirement_panic_for_test();
        stop(group.clone()).await;
        let outcome = Taken::from(&group);
        let refused = outcome.refused();
        assert!(refused.refusal().to_string().contains("panicked"), "{}", refused.refusal());
        assert!(refused.drained(), "the drain was verified before the panic");
        assert!(refused.holds_reservation(), "the stable owner kept the lease through the panic");
        assert!(lease_held());
        drop(group);
        assert!(outcome.abandon());
        assert!(!lease_held());

        // (c) Corrupt node custody: every lookup reopens custody and rereads
        // the dependency proofs, so a damaged proof makes the real lookup
        // fail. The refusal keeps the scan with its locks and the lease.
        use storage::archives::package_entry_id::{GetFileName, PackageEntryId};
        let lease = engine
            .db()
            .repair_leases()
            .lookup(
                closed[0].lease_generation,
                &crate::history_read_budget::HistoryReadBudget::new(Default::default()),
            )
            .unwrap();
        let root_dir = PathBuf::from(engine.db_root_dir().unwrap());
        let proof_path = lease
            .dependencies
            .iter()
            .filter_map(|dependency| {
                let id = dependency.validate().ok()?;
                let name = match dependency.kind.as_str() {
                    "proof" => PackageEntryId::Proof(&id).filename_short(),
                    "proof-link" => PackageEntryId::ProofLink(&id).filename_short(),
                    _ => return None,
                };
                Some(root_dir.join("archive/unapplied").join(name))
            })
            .find(|path| path.exists())
            .expect("a loose dependency proof of the custody lease");
        let original = std::fs::read(&proof_path).unwrap();
        let mut damaged = original.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 0xff;
        let group = make_group();
        group.clone().pre_create_engine().await.unwrap();
        std::fs::write(&proof_path, &damaged).unwrap();
        let stopped = tokio::time::timeout(
            Duration::from_secs(60),
            group.clone().stop_for_retirement_preparation(tokio::runtime::Handle::current()),
        )
        .await;
        // Restore the exact evidence before any assertion.
        std::fs::write(&proof_path, &original).unwrap();
        stopped.expect("retirement stop did not finish").unwrap();
        let outcome = Taken::from(&group);
        let refused = outcome.refused();
        assert!(
            matches!(
                refused.refusal(),
                simplex::finality_delivery::source_retirement::RetirementRefusal::CustodyUnverified { .. }
            ),
            "{}",
            refused.refusal()
        );
        assert!(refused.drained());
        assert!(refused.holds_scan(), "the refused scan is retained");
        assert!(source_locked().await, "with its source store lock");
        assert!(lease_held());
        drop(group);
        assert!(outcome.abandon());
        assert!(!source_locked().await);
        assert!(!lease_held());
    })
    .catch_unwind()
    .await;
    let (sinks, groups) = std::mem::take(&mut *pending.lock().unwrap());
    for sink in sinks {
        sink.drain();
    }
    // Joining a started stop means awaiting its shared teardown to its
    // terminal result; outcomes not taken by the body are abandoned here.
    for group in groups {
        let rt = tokio::runtime::Handle::current();
        let terminal = group.clone().stop_for_retirement_preparation(rt).await;
        log::info!("retirement cleanup teardown result: {terminal:?}");
        drop(Taken::from(&group));
    }
    pair.stop_all().await;
    run.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

/// Stores a synthetic masterchain state with its handle in the real engine.
/// F0/F1 are synthetic: they exercise the real keeper, storage, oracles and
/// deleter, not authenticated-chain coverage.
async fn store_synthetic_mc_state(
    engine: &Arc<Engine>,
    id: &BlockIdExt,
    catchain_seqno: u32,
    prev: Option<&BlockIdExt>,
    shards: Option<rtos_block::ShardHashes>,
) -> Arc<crate::shard_state::ShardStateStuff> {
    use rtos_block::{ExtBlkRef, HashmapAugType, KeyExtBlkRef, KeyMaxLt, McStateExtra};
    let mut header = rtos_block::ShardStateUnsplit::with_ident(ShardIdent::masterchain());
    header.set_seq_no(id.seq_no());
    let mut extra = McStateExtra::default();
    extra.validator_info.catchain_seqno = catchain_seqno;
    if let Some(shards) = shards {
        extra.shards = shards;
    }
    if let Some(prev) = prev {
        let reference = KeyExtBlkRef {
            key: false,
            blk_ref: ExtBlkRef {
                end_lt: 0,
                seq_no: prev.seq_no(),
                root_hash: prev.root_hash().clone(),
                file_hash: prev.file_hash().clone(),
            },
        };
        extra
            .prev_blocks
            .set(&prev.seq_no(), &reference, &KeyMaxLt { key: false, max_end_lt: 0 })
            .unwrap();
    }
    header.write_custom(Some(&extra)).unwrap();
    let keeper = engine.shard_states_keeper();
    let state = crate::shard_state::ShardStateStuff::from_state(
        id.clone(),
        header,
        #[cfg(feature = "telemetry")]
        &crate::collator_test_bundle::create_engine_telemetry(),
        &crate::collator_test_bundle::create_engine_allocated(),
    )
    .unwrap();
    let handle = engine.db().create_test_block_handle(id).unwrap();
    keeper.store_state(&handle, state, None, true).await.unwrap();
    engine.load_state(id).await.unwrap()
}

async fn pin_floor(engine: &Arc<Engine>, id: &BlockIdExt) {
    let keeper = engine.shard_states_keeper();
    let guard = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match keeper.pin_cleanup_candidate(id) {
                Ok(guard) => break guard,
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await
    .expect("the stored state can be pinned");
    keeper.adopt_cleanup_floor(id, guard).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit public fixture signer and real multi-Engine network/WAL"]
async fn validator_cleanup_real_engine_keeps_until_the_floor_passes_then_deletes() {
    use crate::validator::{
        validator_cleanup_gc::{ancestor_or_equal, shard_catchain_seqno},
        validator_manager::CleanupHarness,
    };
    use consensus_common::validator_cleanup::{make_record, NamespaceLayout};
    let signer = std::env::var("RTOS_PUBLIC_FIXTURE_SIGNER")
        .expect("set RTOS_PUBLIC_FIXTURE_SIGNER to the archived public-only fixture signer");
    assert!(Path::new(&signer).is_file());
    let pair = Pair::with_source_transport("included").await;
    let groups: std::sync::Mutex<Vec<Arc<ValidatorGroup>>> = Default::default();
    let run = std::panic::AssertUnwindSafe(async {
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
        let v2_session = runtime.session_id().clone();
        let group = Arc::new(
            ValidatorGroup::new(
                info,
                local_key.clone(),
                v2_session.clone(),
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
        groups.lock().unwrap().push(group.clone());

        // (a) Production retirement through the manager on the real engine:
        // fence and an authenticated record, synced in the real DB.
        let mut manager = CleanupHarness::new(engine.clone());
        manager.retire(v2_session.clone(), group).await.unwrap();
        let v2_record = engine.load_validator_cleanup_record(&v2_session).unwrap();
        assert!(v2_record.is_some(), "retirement persisted the record");
        assert!(engine.load_destroyed_session_ids().unwrap().contains(&v2_session));

        // (b) A retired V1 namespace on the same real DB: a real storage
        // instance opened and cleanly torn down, and a real candidate table.
        let (f0, f1) = (
            BlockIdExt::with_params(
                ShardIdent::masterchain(),
                5000,
                UInt256::from([0x50; 32]),
                UInt256::from([0x51; 32]),
            ),
            BlockIdExt::with_params(
                ShardIdent::masterchain(),
                5001,
                UInt256::from([0x52; 32]),
                UInt256::from([0x53; 32]),
            ),
        );
        let v1_session = UInt256::from([0xa1; 32]);
        let v1 = make_record(&v1_session, &NamespaceLayout::V1, &ShardIdent::masterchain(), 5, &f1)
            .unwrap();
        let mut fence: std::collections::HashSet<UInt256> =
            engine.load_destroyed_session_ids().unwrap().into_iter().collect();
        fence.insert(v1_session.clone());
        engine.persist_validator_retirement(&fence, std::slice::from_ref(&v1)).unwrap();
        let root = PathBuf::from(engine.db_root_dir().unwrap());
        let namespace = root.join("catchains/consensus").join(&v1.namespace);
        let candidates = root.join("catchains").join(format!("candidates{:x}", v1_session));
        drop(
            consensus_common::ConsensusCommonFactory::create_async_key_value_storage(
                &namespace,
                &v1_session.to_hex_string(),
                consensus_common::AsyncKeyValueStorageOptions { use_callback_thread: false },
            )
            .unwrap(),
        );
        drop(engine.get_candidate_table(&v1_session).unwrap());
        assert!(namespace.is_dir() && candidates.is_dir());

        // (c) Synthetic states in the real engine: F0 at catchain 5, F1 at 10
        // recording F0, with a split workchain 0 for the oracle checks.
        let mut shards = rtos_block::ShardHashes::default();
        shards.add_workchain(0, 0, UInt256::from([1; 32]), UInt256::from([2; 32])).unwrap();
        let full = ShardIdent::full(0);
        shards
            .split_shard(&full, |mut left| {
                left.next_catchain_seqno = 7;
                let mut right = left.clone();
                right.next_catchain_seqno = 9;
                Ok((left, right))
            })
            .unwrap();
        store_synthetic_mc_state(engine, &f0, 5, None, None).await;
        let f1_state = store_synthetic_mc_state(engine, &f1, 10, Some(&f0), Some(shards)).await;

        // (d) Oracles on the stored F1 state.
        assert!(ancestor_or_equal(&f1_state, &f1));
        assert!(ancestor_or_equal(&f1_state, &f0));
        let fork = BlockIdExt::with_params(
            ShardIdent::masterchain(),
            5000,
            UInt256::from([0x60; 32]),
            UInt256::from([0x61; 32]),
        );
        assert!(!ancestor_or_equal(&f1_state, &fork), "a fork at F0's seqno is not an ancestor");
        let (left, right) = full.split().unwrap();
        assert_eq!(shard_catchain_seqno(&f1_state, &ShardIdent::masterchain()), Some(10));
        assert_eq!(shard_catchain_seqno(&f1_state, &left), Some(7));
        assert_eq!(shard_catchain_seqno(&f1_state, &right), Some(9));
        assert_eq!(shard_catchain_seqno(&f1_state, &left.split().unwrap().0), Some(7));
        assert_eq!(shard_catchain_seqno(&f1_state, &full), Some(10), "a merge is max + 1");
        assert_eq!(shard_catchain_seqno(&f1_state, &ShardIdent::full(5)), None);

        // (e) Floor at F0: the checkpoint is not ancestor-or-equal and 5 is
        // not below 5, so the record is kept and nothing is deleted.
        pin_floor(engine, &f0).await;
        manager.tick().await;
        assert!(namespace.is_dir() && candidates.is_dir(), "kept before eligibility");
        assert!(engine.load_validator_cleanup_record(&v1_session).unwrap().is_some());
        assert!(!manager.delete_in_flight(&v1_session));

        // (f) Floor at F1: deleted through the real deleter, record erased,
        // fence untouched, the authenticated record still kept.
        pin_floor(engine, &f1).await;
        manager.tick().await;
        assert!(!namespace.exists() && !candidates.exists(), "deleted after eligibility");
        assert!(engine.load_validator_cleanup_record(&v1_session).unwrap().is_none());
        assert!(!manager.delete_in_flight(&v1_session));
        let fence_now = engine.load_destroyed_session_ids().unwrap();
        assert!(fence_now.contains(&v1_session) && fence_now.contains(&v2_session));
        assert!(engine.load_validator_cleanup_record(&v2_session).unwrap().is_some());
    })
    .catch_unwind()
    .await;
    for group in std::mem::take(&mut *groups.lock().unwrap()) {
        let terminal = group.clone().stop(tokio::runtime::Handle::current(), false).await;
        log::info!("cleanup test group teardown: {terminal:?}");
    }
    pair.stop_all().await;
    run.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}
