// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Actual Engine lookup and source-store lock across a later admission panic.
use super::*;
use consensus_common::{
    finality_delivery::FinalizedDeliveryDraft, session_runtime::AuthenticatedSessionRuntime,
    BlockCandidatePriority, BlockSourceInfo, ConsensusCommonFactory, SessionFinality,
    ValidatorIdentity,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn source_closing_service_panic_drains_held_actual_source_completion() {
    actual_source_completion_case(false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn source_closing_service_release_before_actual_lookup_never_strands_source() {
    actual_source_completion_case(true).await;
}
async fn actual_source_completion_case(release_before_register: bool) {
    let fixture = fixture(false).await;
    let engine = fixture.engine.clone();
    let run = std::panic::AssertUnwindSafe(async {
        let anchor = fixture.request.pin.zerostate.clone();
        let zero = engine.load_state(&anchor).await.unwrap();
        let config = zero.config_params().unwrap();
        let cc = fixture.parent.block().unwrap().read_info().unwrap().gen_catchain_seqno();
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
            .key_by_tag(crate::network::node_network::NodeNetwork::TAG_OVERLAY_KEY)
            .unwrap()
            .id()
            .clone();
        let runtime = Arc::new(
            AuthenticatedSessionRuntime::from_authenticated_config(
                fixture.request.pin.clone(),
                config,
                rtos_api::session_identity::SessionCoordinates {
                    shard: anchor.shard(),
                    catchain_seqno: cc,
                    vertical_seqno: 0,
                    last_key_block_seqno: 0,
                    new_catchain_ids: false,
                },
                committee,
                local,
            )
            .unwrap()
            .bind_recovery_anchor(anchor)
            .unwrap(),
        );
        let namespace = PathBuf::from(
            runtime
                .runtime_directory(
                    Path::new(engine.db_root_dir().unwrap()).join("catchains").to_str().unwrap(),
                )
                .unwrap(),
        );
        let worker = engine.ensure_publication_worker().await.unwrap();
        let source = simplex::finality_delivery::FinalityDeliveryTestDriver::open(
            runtime.clone(),
            &namespace,
            worker.sink(runtime.clone()),
            worker.delivered_sink(runtime.clone()),
        )
        .unwrap();
        for block in [&fixture.parent, &fixture.target] {
            let handle = engine.load_block_handle(block.id()).unwrap().unwrap();
            let proof = engine.load_block_proof(&handle, false).await.unwrap();
            let creator = block.block().unwrap().read_extra().unwrap().created_by().clone();
            let member = runtime
                .committee()
                .iter()
                .find(|member| member.validator_id().unwrap() == creator)
                .unwrap();
            let draft = FinalizedDeliveryDraft {
                block_id: block.id().clone(),
                source_info: BlockSourceInfo {
                    source: ValidatorIdentity::from_descriptor(member).unwrap(),
                    priority: BlockCandidatePriority {
                        round: 0,
                        priority: 0,
                        first_block_round: 0,
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
            tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    if source.poll(draft.clone()).unwrap() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("actual source handoff must reach node WAL");
        }
        tokio::time::timeout(Duration::from_secs(10), async {
            while source.counts().unwrap() != (0, 2, 0) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("two actual canonical retention completions must sync source references");
        // No close maintenance: each source reference still owes terminal lookup.
        drop(source);
        crate::validator::retired_session_service::test_admission_panic_drains_real_source(
            engine.clone(),
            namespace,
            runtime,
            release_before_register,
        )
        .await;
    })
    .catch_unwind()
    .await;
    // The injected admission panic is intentionally recorded as a service error;
    // even that error must arrive only after all actual owners finish.
    let stopped = tokio::time::timeout(Duration::from_secs(30), engine.clone().wait_stop()).await;
    assert!(stopped.is_ok(), "Engine stop must not detach or hang on the held source callback");
    run.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    assert!(stopped.unwrap().is_err(), "injected service panic must remain visible to shutdown");
}
