// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Real Engine canonical custody: callbacks certify the original durable evidence.
use super::*;
use consensus_common::finality_delivery::{
    CanonicalFinalityRecord, CanonicalFinalityRequest, DurableFinalitySinkPtr, FinalityDeliveryRole,
};

async fn retain(
    sink: &DurableFinalitySinkPtr,
    request: CanonicalFinalityRequest,
) -> Result<CanonicalFinalityRecord> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    sink.retain_canonical(
        request,
        Box::new(move |result| {
            let _ = tx.send(result);
        }),
    )?;
    tokio::time::timeout(Duration::from_secs(15), rx)
        .await
        .map_err(|_| rtos_block::error!("canonical completion timeout"))?
        .map_err(|_| rtos_block::error!("canonical completion dropped"))?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publication_canonical_retention_preserves_evidence_and_rejects_foreign_requests() {
    for final_role in [false, true] {
        let SpoolFixture { dir, engine, runtime, block, row, .. } = SpoolFixture::new(1).await;
        let mut draft = spool_draft(&runtime, &block, &row, final_role);
        draft.last_mc_finalized_seqno = 17;
        draft.candidate_already_sent = true;
        draft.created_at_unix_secs -= 11;
        let original = spool_pending_record(&runtime, &draft);
        let sink = engine.clone().durable_finality_sink(runtime.clone()).await.unwrap();
        let result = std::panic::AssertUnwindSafe(async {
            let id = stage_spool(&sink, draft.clone()).await.unwrap();
            let request = CanonicalFinalityRequest {
                node_receipt: id,
                block_id: block.id().clone(),
                role: if final_role { FinalityDeliveryRole::Final } else { FinalityDeliveryRole::Approval },
                local_adnl: original.local_adnl.clone(),
                local_validator_index: original.local_validator_index,
                source_validator: original.source_validator.clone(),
            };
            let mut bad = Vec::new();
            let mut value = request.clone(); value.role = if final_role { FinalityDeliveryRole::Approval } else { FinalityDeliveryRole::Final }; bad.push(value);
            let mut value = request.clone(); value.node_receipt = UInt256::from([0xA1;32]); bad.push(value);
            let mut value = request.clone(); value.block_id.file_hash = UInt256::from([0xA2;32]); bad.push(value);
            let mut value = request.clone(); value.local_adnl = UInt256::from([0xA3;32]); bad.push(value);
            let mut value = request.clone(); value.local_validator_index = None; bad.push(value);
            let mut value = request.clone(); value.source_validator = UInt256::from([0xA4;32]); bad.push(value);
            for value in bad { assert!(retain(&sink, value).await.is_err()); }
            // Same real transport, but different authenticated routing coordinates.
            let fixture: serde_json::Value = serde_json::from_str(
                include_str!("testdata/v2-publication-spool.json"),
            ).unwrap();
            let config = ConfigParams::construct_from_cell(
                read_single_root_boc(&decode(&fixture["config_boc"])).unwrap(),
            ).unwrap();
            for foreign_domain in [false, true] {
                let mut pin = runtime.pin().clone();
                if foreign_domain { pin.global_id += 1; }
                let foreign = Arc::new(consensus_common::session_runtime::AuthenticatedSessionRuntime::from_authenticated_config(
                    pin, &config,
                    rtos_api::session_identity::SessionCoordinates {
                        shard: block.id().shard(),
                        catchain_seqno: if foreign_domain { 7 } else { 8 },
                        vertical_seqno: 0, last_key_block_seqno: 0, new_catchain_ids: false,
                    },
                    runtime.committee().to_vec(), runtime.local_adnl().clone(),
                ).unwrap());
                match engine.clone().durable_finality_sink(foreign).await {
                    Ok(foreign_sink) => assert!(retain(&foreign_sink, request.clone()).await.is_err()),
                    Err(_) => {}, // Domain rejection at sink construction also precedes custody.
                }
            }
            let canonical = retain(&sink, request.clone()).await.unwrap();
            assert_eq!(canonical.request, request);
            assert_canonical(&runtime, &original, &draft, canonical);
            request
        }).catch_unwind().await;
        engine.clone().wait_stop().await.unwrap();
        let request = result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
        // Rejected admission must not run the supplied completion.
        let (tx, rx) = tokio::sync::oneshot::channel();
        assert!(sink
            .retain_canonical(
                request.clone(),
                Box::new(move |r| {
                    let _ = tx.send(r);
                })
            )
            .is_err());
        assert!(rx.await.is_err());
        drop(sink);
        drop(engine);
        let reopened = open_engine(dir.path()).await;
        let result = std::panic::AssertUnwindSafe(async {
            let sink = reopened.clone().durable_finality_sink(runtime.clone()).await.unwrap();
            let canonical = retain(&sink, request.clone()).await.unwrap();
            assert_eq!(canonical.request, request);
            assert_canonical(&runtime, &original, &draft, canonical);
        })
        .catch_unwind()
        .await;
        reopened.clone().wait_stop().await.unwrap();
        result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    }
}

fn assert_canonical(
    runtime: &consensus_common::session_runtime::AuthenticatedSessionRuntime,
    original: &simplex::finality_delivery::PendingFinalityRecord,
    draft: &consensus_common::finality_delivery::FinalizedDeliveryDraft,
    canonical: CanonicalFinalityRecord,
) {
    let mut restored = draft.clone();
    restored.data = canonical.data;
    restored.finality = canonical.finality;
    restored.created_at_unix_secs = canonical.created_at_unix_secs;
    restored.last_mc_finalized_seqno = canonical.last_mc_finalized_seqno;
    restored.candidate_already_sent = canonical.candidate_already_sent;
    let restored = spool_pending_record(runtime, &restored);
    assert_eq!(restored.data, original.data);
    assert_eq!(restored.signature_set, original.signature_set);
    assert_eq!(restored.is_final, original.is_final);
    assert_eq!(restored.created_at_unix_secs, original.created_at_unix_secs);
    assert_eq!(restored.last_mc_finalized_seqno, original.last_mc_finalized_seqno);
    assert_eq!(restored.candidate_already_sent, original.candidate_already_sent);
}
