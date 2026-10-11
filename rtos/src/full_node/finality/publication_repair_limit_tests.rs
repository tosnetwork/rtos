// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::publication_repair::limit_next_artifact_for_test;
use storage::archives::bounded_read::ArchiveReadLimitExceeded;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mc_live_repair_local_limits_reject_before_peer_fallback() {
    let pair = Pair::with_propagation_profile("included", false, true).await;
    let result = std::panic::AssertUnwindSafe(async {
        let (master, shards) = pair.apply_by_normal_clients().await;
        let expected = request(&pair).await;
        let handle = pair.receiver.load_block_handle(pair.master.id()).unwrap().unwrap();
        let proof = pair.receiver.load_block_proof(&handle, false).await.unwrap();
        let body_bytes = pair.master.data().len();
        assert!(proof.data().len() > body_bytes, "fixture must distinguish proof from body limit");
        assert!(handle.is_applied() && handle.has_data() && handle.has_proof());
        let before = pair.provider.overlays_router().unwrap().test_block_download_queries();
        // First reject the body, then admit the body but reject the actual
        // larger PQ proof. Both traverse real archive package headers.
        for limit in [1, body_bytes] {
            limit_next_artifact_for_test(&pair.receiver, limit);
            let error = repair_mc_final(pair.receiver.clone(), expected.clone())
                .await
                .err()
                .expect("physical artifact limit must reject custody");
            let budget = error
                .downcast_ref::<ArchiveReadLimitExceeded>()
                .expect("limit error must survive repair routing");
            assert_eq!(budget.resource, "data");
            assert_eq!(budget.limit, limit);
            assert!(budget.requested > limit as u64);
            assert_eq!(
                pair.provider.overlays_router().unwrap().test_block_download_queries(),
                before
            );
            assert!(handle.is_applied() && handle.has_data() && handle.has_proof());
        }
        // A failed admission releases its owner; unchanged legitimate artifacts
        // remain usable under the ordinary production allowance.
        let custody = repair_mc_final(pair.receiver.clone(), expected).await.unwrap();
        assert_eq!(custody.state_root(), &pair.master_state_root);
        assert_eq!(pair.provider.overlays_router().unwrap().test_block_download_queries(), before);
        drop(custody);
        pair.receiver.clone().wait_stop().await.unwrap();
        master.await.unwrap();
        shards.await.unwrap();
    })
    .catch_unwind()
    .await;
    pair.receiver.clone().wait_stop().await.unwrap();
    pair.provider.clone().wait_stop().await.unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
