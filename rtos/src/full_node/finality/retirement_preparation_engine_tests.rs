// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Retirement preparation through the production group path: a real source
//! circulates one masterchain event to node Released, then a real
//! authenticated group, built by `pre_create_engine` with a real engine
//! reservation and durable sink, is stopped for retirement preparation.
use super::*;
use crate::validator::{
    consensus::ConsensusOptions, retirement_preparation::RetirementOutcome,
    validator_group::ValidatorGroup, validator_utils::GeneralSessionInfo,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit public fixture signer and real multi-Engine network/WAL"]
async fn retirement_preparation_real_group_prepares_and_survives_panic() {
    let signer = std::env::var("RTOS_PUBLIC_FIXTURE_SIGNER")
        .expect("set RTOS_PUBLIC_FIXTURE_SIGNER to the archived public-only fixture signer");
    assert!(Path::new(&signer).is_file());
    let pair = Pair::with_source_transport("included").await;
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
        // A preexisting validator namespace, as a running session leaves it.
        FinalityDeliveryTestDriver::provision_validator_namespace(&runtime, &namespace).unwrap();
        let sink = engine.clone().durable_finality_sink(runtime.clone()).await.unwrap();
        let confirm =
            engine.ensure_publication_worker().await.unwrap().delivered_sink(runtime.clone());
        let driver =
            FinalityDeliveryTestDriver::open(runtime.clone(), &namespace, sink, confirm).unwrap();
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

        // The production group path: options from the same config, real
        // reservation, real durable sink and a real authenticated session.
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
            Arc::new(
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
            )
        };
        let source_locked = || async {
            let sink = engine.clone().durable_finality_sink(runtime.clone()).await.unwrap();
            let confirm =
                engine.ensure_publication_worker().await.unwrap().delivered_sink(runtime.clone());
            FinalityDeliveryTestDriver::open(runtime.clone(), &namespace, sink, confirm).is_err()
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

        let group = make_group();
        group.clone().pre_create_engine().await.unwrap();
        assert!(group.has_session_for_test().await, "production construction created a session");
        assert!(
            engine.reserve_normal_session_namespace(&runtime).unwrap().is_none(),
            "the group holds the engine lease"
        );
        stop(group.clone()).await;
        let owner = match group.take_retirement_outcome().unwrap() {
            Some(RetirementOutcome::Prepared(owner)) => owner,
            Some(RetirementOutcome::Refused(refused)) => {
                panic!("real released namespace refused: {}", refused.refusal())
            }
            None => panic!("retirement stop produced no outcome"),
        };
        let preparation = owner.preparation().unwrap();
        assert_eq!(preparation.inventory().len(), 1);
        assert_eq!(preparation.inventory()[0].offer, offer);
        assert!(
            engine.reserve_normal_session_namespace(&runtime).unwrap().is_none(),
            "a prepared namespace stays closed to new sessions"
        );
        assert!(source_locked().await, "the preparation holds the source store lock");
        drop(group);
        owner.abandon();
        assert!(!source_locked().await, "abandon released the source store lock");

        // A preparation that panics after a verified drain keeps the lease in
        // its stable owner; the drained refusal may then release it.
        let group = make_group();
        group.clone().pre_create_engine().await.unwrap();
        assert!(group.has_session_for_test().await);
        group.inject_retirement_panic_for_test();
        stop(group.clone()).await;
        let refused = match group.take_retirement_outcome().unwrap() {
            Some(RetirementOutcome::Refused(refused)) => refused,
            Some(RetirementOutcome::Prepared(_)) => {
                panic!("an injected panic issued a preparation")
            }
            None => panic!("retirement stop produced no outcome"),
        };
        assert!(refused.refusal().to_string().contains("panicked"), "{}", refused.refusal());
        assert!(refused.drained(), "the drain was verified before the panic");
        assert!(refused.holds_reservation(), "the stable owner kept the lease through the panic");
        assert!(engine.reserve_normal_session_namespace(&runtime).unwrap().is_none());
        drop(group);
        assert!(refused.abandon().is_ok());
        let lease = engine
            .reserve_normal_session_namespace(&runtime)
            .unwrap()
            .expect("abandoning a drained refusal releases the lease");
        lease.release();
    })
    .catch_unwind()
    .await;
    pair.stop_all().await;
    run.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}
