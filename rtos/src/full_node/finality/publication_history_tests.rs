// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Real Engine WAL boundary with nonzero historical authority. Ordinary proof
//! unavailability and a lagging index are explicit fixture inputs, not GC claims.
use super::*;
use crate::propagation_outbox::{
    delivery_id, inspect_delivery, OutboxDomain, PublicationRecord, StoredCarrier,
};
use consensus_common::session_runtime::{AuthenticatedSessionRuntime, SessionNetworkPin};
use simplex::finality_delivery::{
    retain_pending_finality, scan_pending_finality, PendingFinalityRecord,
};
use storage::archives::package_entry_id::{GetFileName, PackageEntryId};

async fn history_fixture() -> (SpoolFixture, BlockIdExt) {
    let mut fixture = SpoolFixture::new(0).await;
    let input: serde_json::Value =
        serde_json::from_str(include_str!("testdata/v2-publication-history.json")).unwrap();
    let setup = std::panic::AssertUnwindSafe(async {
        let key_id: BlockIdExt = input["key_id"].as_str().unwrap().parse().unwrap();
        let zero: BlockIdExt = input["zero"].as_str().unwrap().parse().unwrap();
        assert_eq!(fixture.engine.zerostate_id(), &zero);
        let key = BlockStuff::deserialize_block_checked(
            key_id.clone(),
            Arc::new(decode(&input["key_block_boc"])),
        )
        .unwrap();
        let proof =
            BlockProofStuff::deserialize(&key_id, decode(&input["key_proof_boc"]), false).unwrap();
        let handle = fixture.engine.store_block(&key).await.unwrap().to_any();
        fixture.engine.store_block_proof(&key_id, Some(handle.clone()), &proof).await.unwrap();
        let state = ShardStateStuff::from_root_cell(
            key_id.clone(),
            read_single_root_boc(&decode(&input["key_state_boc"])).unwrap(),
            #[cfg(feature = "telemetry")]
            fixture.engine.engine_telemetry(),
            fixture.engine.engine_allocated(),
        )
        .unwrap();
        fixture.engine.store_state(&handle, state.clone()).await.unwrap();
        // We do not assert MC execution from this stored fixture. The actual
        // proof chain authenticates the state independently during prepare.
        assert!(!handle.is_applied());
        assert_eq!(fixture.engine.load_last_applied_mc_state().await.unwrap().block_id(), &zero);
        assert!(fixture
            .engine
            .load_last_applied_mc_state()
            .await
            .unwrap()
            .find_block_id(1)
            .is_err());
        let row = input["rows"][0].clone();
        let block = fixture_block(&row);
        assert_eq!(block.block().unwrap().read_info().unwrap().prev_key_block_seqno(), 1);
        let config = state.config_params().unwrap();
        let (committee, _) = config
            .validator_set()
            .unwrap()
            .calc_subset(&config.catchain_config().unwrap(), SHARD_FULL, 0, 7)
            .unwrap();
        let runtime = Arc::new(
            AuthenticatedSessionRuntime::from_authenticated_config(
                SessionNetworkPin { global_id: -239, zerostate: zero },
                config,
                rtos_api::session_identity::SessionCoordinates {
                    shard: block.id().shard(),
                    catchain_seqno: 7,
                    vertical_seqno: 0,
                    last_key_block_seqno: 1,
                    new_catchain_ids: false,
                },
                committee,
                fixture.runtime.local_adnl().clone(),
            )
            .unwrap()
            .bind_recovery_anchor(key_id.clone())
            .unwrap(),
        );
        assert_eq!(runtime.session_id(), &UInt256::from_slice(&decode(&row["session"])));
        crate::retired_history::prepare(fixture.engine.clone(), runtime.clone(), key_id.clone())
            .await
            .unwrap();
        (runtime, block, row, key_id)
    })
    .catch_unwind()
    .await;
    match setup {
        Ok((runtime, block, row, key_id)) => {
            fixture.runtime = runtime;
            fixture.block = block;
            fixture.row = row;
            (fixture, key_id)
        }
        Err(panic) => {
            fixture.engine.clone().wait_stop().await.unwrap();
            std::panic::resume_unwind(panic)
        }
    }
}

fn pending_record(
    runtime: &AuthenticatedSessionRuntime,
    draft: &FinalizedDeliveryDraft,
) -> PendingFinalityRecord {
    let signatures = match &draft.finality {
        SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(carrier)) => {
            rtos_api::pq_finality::PqNetworkSignatureSet::from_final_fields(carrier).unwrap()
        }
        SessionFinality::PqApproval(carrier) => {
            rtos_api::pq_finality::PqNetworkSignatureSet::from_approval(carrier).unwrap()
        }
        _ => unreachable!(),
    };
    PendingFinalityRecord {
        pin: runtime.pin().clone(),
        protocol: runtime.protocol(),
        carrier_version: runtime.carrier_version(),
        wire_profile: runtime.wire_profile(),
        profile: runtime.profile().clone(),
        session_id: runtime.session_id().clone(),
        block_id: draft.block_id.clone(),
        local_adnl: UInt256::from(*runtime.local_adnl().data()),
        local_validator_index: match runtime.local_role() {
            LocalRole::Validator(i) => Some(i),
            LocalRole::Observer => None,
        },
        source_validator: UInt256::from(*draft.source_info.source.id().data()),
        data: draft.data.data().to_vec(),
        signature_set: runtime
            .wire_profile()
            .serialize(&signatures.to_node().into_boxed())
            .unwrap(),
        is_final: signatures.is_final(),
        last_mc_finalized_seqno: draft.last_mc_finalized_seqno,
        candidate_already_sent: draft.candidate_already_sent,
        created_at_unix_secs: draft.created_at_unix_secs,
    }
}
fn expected_publication(source: &PendingFinalityRecord, block: &BlockStuff) -> PublicationRecord {
    PublicationRecord {
        domain: OutboxDomain {
            zerostate: source.pin.zerostate.clone(),
            global_id: source.pin.global_id,
            wire_profile: source.wire_profile,
        },
        protocol: source.protocol,
        profile: source.profile.clone(),
        session_id: source.session_id.clone(),
        block_id: source.block_id.clone(),
        block_data: source.data.clone(),
        proof_data: None,
        prev: vec![block.construct_prev_id().unwrap().0],
        carrier: if source.is_final {
            StoredCarrier::Final(source.signature_set.clone())
        } else {
            StoredCarrier::Approval(source.signature_set.clone())
        },
        locally_generated: true,
        created_at_unix_secs: source.created_at_unix_secs,
        expires_at_unix_secs: source.created_at_unix_secs + Limits::default().max_retention_secs,
        effects: Vec::new(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publication_history_capsule_real_engine_wal_reopen_and_revocation() {
    for (final_role, interrupted_retention) in
        [(false, false), (true, false), (false, true), (true, true)]
    {
        let (fixture, key_id) = history_fixture().await;
        let recovery = locator(&fixture);
        let input = draft(&fixture, final_role);
        let source = pending_record(&fixture.runtime, &input);
        let publication = expected_publication(&source, &fixture.block);
        let expected_id = delivery_id(&publication).unwrap();
        let SpoolFixture { dir, engine, block, state_root, .. } = fixture;
        let actual_root = std::path::PathBuf::from(engine.db_root_dir().unwrap());
        engine.clone().wait_stop().await.unwrap();
        drop(engine);
        // Read the configured root from Engine; mutate files only after join.
        let ordinary = actual_root
            .join("archive/unapplied")
            .join(PackageEntryId::Proof(&key_id).filename_short());
        assert!(ordinary.is_file(), "expected actual ordinary proof file before simulation");
        std::fs::rename(&ordinary, dir.path().join("unavailable-key-proof")).unwrap();
        retain_pending_finality(&recovery.namespace, &source).unwrap();
        let source_path = recovery.namespace.join("finality-pending")
            .join(format!("{}.json", source.id().unwrap().to_hex_string()));
        let original_source = std::fs::read(&source_path).unwrap();
        if interrupted_retention {
            // Same bytes as an interrupted retain before its commit rename.
            std::fs::rename(&source_path, source_path.with_extension("tmp")).unwrap();
        }
        let source_root = actual_root.join("catchains");
        let capsule = actual_root.join("retired-history-v1");
        let withdrawn = dir.path().join("withdrawn-capsule");
        let reopened = open_engine(dir.path()).await;
        let result = std::panic::AssertUnwindSafe(async {
            let handle = reopened.load_block_handle(&key_id).unwrap().unwrap();
            assert!(handle.has_proof());
            assert!(
                reopened.load_block_proof(&handle, false).await.is_err(),
                "ordinary proof unexpectedly available"
            );
            assert_eq!(reopened.load_last_applied_mc_state().await.unwrap().block_id().seq_no(), 0);
            // This authenticates runtime from the retained signed state without
            // warming the independent Engine publication authority cache.
            let receipt = authenticate_retired_session(reopened.as_ref(), &recovery).await.unwrap();
            let sink = reopened
                .ensure_publication_worker()
                .await
                .unwrap()
                .historical_sink(&receipt)
                .unwrap();
            std::fs::rename(&capsule, &withdrawn).unwrap();
            assert!(
                stage(&sink, input.clone()).await.is_err(),
                "session receipt bypassed missing per-block history"
            );
            assert!(inspect_delivery(
                reopened.db(),
                &publication.domain,
                &Limits::default(),
                &expected_id
            )
            .unwrap()
            .is_none());
            assert!(reopened.load_block_handle(block.id()).unwrap().is_none());
            let mut pending = scan_pending_finality(&source_root).unwrap();
            assert_eq!(pending.len(), 1, "failed node custody ACKed source debt");
            let source_owner = pending.pop().unwrap();
            assert_eq!(source_owner.record().id().unwrap(), source.id().unwrap());
            assert_eq!(source_owner.record().data, source.data);
            if interrupted_retention {
                assert!(!source_path.exists());
                assert!(!source_path.with_extension("acked").exists());
                assert_eq!(std::fs::read(source_path.with_extension("tmp")).unwrap(), original_source);
            }
            std::fs::rename(&withdrawn, &capsule).unwrap();
            let id = stage(&sink, input.clone()).await.unwrap();
            assert_eq!(id, expected_id);
            assert_eq!(stage(&sink, input).await.unwrap(), id, "repeat changed stable receipt");
            // This is the real source store ACK operation, strictly after the
            // actual sink's WAL completion. It is not a fabricated Sent receipt.
            source_owner.acknowledge(id.clone()).unwrap();
            assert!(!source_path.with_extension("tmp").exists());
            assert!(scan_pending_finality(&source_root).unwrap().is_empty());
            let accepted = tokio::time::timeout(
                Duration::from_secs(20),
                reopened.clone().await_publication(id.clone()),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(accepted.block(), &block);
            assert_eq!(accepted.is_final(), final_role);
            assert_eq!(accepted.phase(), AcceptancePhase::Preapplied);
            assert_eq!(
                reopened.load_state(block.id()).await.unwrap().root_cell().repr_hash(),
                &state_root
            );
            id
        })
        .catch_unwind()
        .await;
        reopened.clone().wait_stop().await.unwrap();
        drop(reopened);
        if withdrawn.exists() {
            std::fs::rename(&withdrawn, &capsule).unwrap();
        }
        let id = result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
        let reopened = open_engine(dir.path()).await;
        let result = std::panic::AssertUnwindSafe(async {
            assert!(!ordinary.exists(), "ordinary proof was secretly repaired by fixture");
            let ledger = PropagationOutbox::open(
                reopened.db().clone(),
                publication.domain.clone(),
                Limits::default(),
            )
            .unwrap();
            let (_, entry) = ledger.delivery(&id).unwrap().unwrap();
            assert_eq!(entry.stage, PublicationStage::AcceptedDraft);
            assert_eq!(entry.record.block_data, block.data());
            assert_eq!(entry.record.carrier, publication.carrier);
            assert!(entry.pending.is_empty() && entry.record.effects.is_empty());
            assert_eq!(ledger.pending().unwrap().len(), 1);
            let handle = reopened.load_block_handle(block.id()).unwrap().unwrap();
            assert!(!handle.is_applied());
            assert_eq!(reopened.load_block(&handle).await.unwrap(), block);
            assert_eq!(
                reopened.load_state(block.id()).await.unwrap().root_cell().repr_hash(),
                &state_root
            );
            assert!(scan_pending_finality(&source_root).unwrap().is_empty());
        })
        .catch_unwind()
        .await;
        reopened.clone().wait_stop().await.unwrap();
        drop(reopened);
        result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    }
}
