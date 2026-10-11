// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Real peer/overlay/RLDP responses. Injection replaces only a scoped peer reply,
//! never the downloader, budget checker, decoder, or transport.
use super::*;
use crate::history_read_budget::{HistoryBudgetExceeded, HistoryReadBudget, HistoryReadLimits};
use crate::network::full_node_overlay_client::NetworkDownloadLimits;
use rtos_api::{
    ton::ton_node::datafull::{DataFull, DataFullCompressed},
    WireProfile,
};
use rtos_block::{BocReader, BocWriter};

fn limits(proof: usize, block: usize) -> NetworkDownloadLimits {
    NetworkDownloadLimits {
        wire_bytes: 1 << 20,
        response_bytes: 1 << 20,
        expanded_bytes: 1 << 20,
        block_bytes: block,
        proof_bytes: proof,
        boc_cells: 100_000,
        boc_depth: 4096,
    }
}
async fn artifacts(pair: &Pair) -> (Vec<u8>, Vec<u8>) {
    let handle = pair.provider.load_block_handle(pair.master.id()).unwrap().unwrap();
    (
        pair.provider.load_block_raw(&handle).await.unwrap(),
        pair.provider.load_block_proof_raw(&handle, false).await.unwrap(),
    )
}
fn inject(pair: &Pair, bytes: Vec<u8>) {
    let peer = pair
        .receiver
        .network()
        .context()
        .stack
        .adnl
        .key_by_tag(NodeNetwork::TAG_OVERLAY_KEY)
        .unwrap()
        .id()
        .clone();
    pair.provider.overlays_router().unwrap().test_bounded_reply(
        peer,
        pair.master.id().clone(),
        true,
        bytes,
    );
}
fn count(pair: &Pair) -> usize {
    pair.provider.overlays_router().unwrap().test_bounded_queries()
}
async fn finish(pair: &Pair, outcome: std::result::Result<(), Box<dyn std::any::Any + Send>>) {
    pair.receiver.clone().wait_stop().await.unwrap();
    pair.provider.clone().wait_stop().await.unwrap();
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}
fn full_bytes(pair: &Pair, block: Vec<u8>, proof: Vec<u8>) -> Vec<u8> {
    WireProfile::T0
        .serialize(
            &DataFull { id: pair.master.id().clone(), block, proof, is_link: false.into() }
                .into_boxed(),
        )
        .unwrap()
}
fn compressed_bytes(pair: &Pair, block: &[u8], proof: &[u8]) -> (Vec<u8>, usize) {
    let mut boc = Vec::new();
    BocWriter::with_roots([
        read_single_root_boc(proof).unwrap(),
        read_single_root_boc(block).unwrap(),
    ])
    .unwrap()
    .write(&mut boc)
    .unwrap();
    let bytes = WireProfile::T0
        .serialize(
            &DataFullCompressed {
                id: pair.master.id().clone(),
                compressed: rtos_block::lz4_compress(&boc, false).unwrap(),
                is_link: false.into(),
            }
            .into_boxed(),
        )
        .unwrap();
    (bytes, boc.len())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bounded_download_e2e_full_proof_and_compressed_exact_limits() {
    let pair = Pair::with_propagation_profile("included", false, true).await;
    let outcome = std::panic::AssertUnwindSafe(async {
        let (block, proof) = artifacts(&pair).await;
        let client = pair.receiver.overlay_client(pair.master.id().shard()).await.unwrap();
        let before = count(&pair);
        let (actual_block, actual_proof) = client
            .download_block_full_bounded(pair.master.id(), false, limits(proof.len(), block.len()))
            .await
            .unwrap();
        assert_eq!(actual_block.data(), block.as_slice());
        assert_eq!(actual_proof.data(), proof.as_slice());
        assert_eq!(count(&pair), before + 1);
        let actual = client
            .download_block_proof_bounded(
                pair.master.id(),
                false,
                false,
                NetworkDownloadLimits::proof(proof.len(), 100_000, 4096),
            )
            .await
            .unwrap();
        assert_eq!(actual.data(), proof.as_slice());
        assert_eq!(count(&pair), before + 2);
        let (compressed, expanded) = compressed_bytes(&pair, &block, &proof);
        inject(&pair, compressed.clone());
        let mut cap = limits(proof.len(), block.len());
        cap.expanded_bytes = expanded;
        let (actual, _) =
            client.download_block_full_bounded(pair.master.id(), false, cap).await.unwrap();
        assert_eq!(actual.id(), pair.master.id());
        inject(&pair, compressed);
        cap.expanded_bytes -= 1;
        let start = count(&pair);
        let error =
            client.download_block_full_bounded(pair.master.id(), false, cap).await.err().unwrap();
        assert!(error.downcast_ref::<adnl::ResponseLimitExceeded>().is_some(), "{error:#}");
        assert_eq!(count(&pair), start + 1, "limit rejection must not retry another response");
    })
    .catch_unwind()
    .await;
    finish(&pair, outcome).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bounded_download_e2e_declared_wire_and_graph_rejection() {
    let pair = Pair::with_propagation_profile("included", false, true).await;
    let outcome = std::panic::AssertUnwindSafe(async {
        let (block, proof) = artifacts(&pair).await;
        let client = pair.receiver.overlay_client(pair.master.id().shard()).await.unwrap();
        let valid = full_bytes(&pair, block.clone(), proof.clone());
        let field = 4 + rtos_api::serialize_bare(pair.master.id()).unwrap().len();
        let mut malicious = valid[..field].to_vec();
        malicious.extend_from_slice(&[254, 0xff, 0xff, 0x7f]);
        inject(&pair, malicious);
        let before = count(&pair);
        let error = client
            .download_block_full_bounded(pair.master.id(), false, limits(proof.len(), block.len()))
            .await
            .err()
            .unwrap();
        let error = error.downcast_ref::<adnl::ResponseLimitExceeded>().unwrap();
        assert_eq!(error.actual, 0x7fffff);
        assert_eq!(count(&pair), before + 1);
        inject(&pair, valid.clone());
        let (header, _) = BocReader::new().read_header(&mut std::io::Cursor::new(&block)).unwrap();
        assert!(header.cells_count > 1);
        let mut cap = limits(proof.len(), block.len());
        cap.boc_cells = header.cells_count - 1;
        let error =
            client.download_block_full_bounded(pair.master.id(), false, cap).await.err().unwrap();
        assert!(error.downcast_ref::<adnl::ResponseLimitExceeded>().is_some());
        inject(&pair, valid);
        client
            .download_block_full_bounded(pair.master.id(), false, limits(proof.len(), block.len()))
            .await
            .unwrap();
    })
    .catch_unwind()
    .await;
    finish(&pair, outcome).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bounded_download_e2e_missing_local_proof_exact_history_budget() {
    let pair = Pair::with_propagation_profile("included", false, true).await;
    let outcome = std::panic::AssertUnwindSafe(async {
        let (_, proof) = artifacts(&pair).await;
        let local = pair.receiver.store_block(&pair.master).await.unwrap().to_any();
        assert!(local.has_data() && !local.has_proof() && !local.is_applied());
        let missing = pair
            .receiver
            .db()
            .load_block_proof_raw_bounded(
                &local,
                false,
                storage::archives::bounded_read::ArchiveReadLimits {
                    data_bytes: proof.len(),
                    filename_bytes: 1024,
                },
            )
            .await
            .err()
            .expect("physical local proof must be absent");
        assert!(missing
            .downcast_ref::<storage::archives::bounded_read::ArchiveReadNotStarted>()
            .is_some_and(|e| e.is_not_found()));
        assert!(crate::retired_history::load_proof(
            pair.receiver.as_ref(),
            pair.master.id(),
            false
        )
        .await
        .unwrap()
        .is_none());
        // The peer emits a real compressed RLDP answer, so one-less *decoded*
        // proof allowance reaches our checker instead of being dropped remotely.
        for engine in [&pair.receiver, &pair.provider] {
            engine
                .network()
                .context()
                .stack
                .adnl
                .set_options(adnl::node::AdnlNode::OPTION_FORCE_COMPRESSION);
        }
        assert!(adnl::node::DataCompression::compress_raw(&proof).unwrap().len() < proof.len() - 1);
        let budget = |bytes| {
            HistoryReadBudget::new(HistoryReadLimits {
                proof_bytes: bytes,
                single_proof_bytes: bytes,
                proof_count: 1,
                ..HistoryReadLimits::default()
            })
        };
        let before = count(&pair);
        let error = crate::boot::load_history_proof_with_budget(
            pair.receiver.as_ref(),
            pair.master.id(),
            false,
            false,
            Some(&budget(proof.len() - 1)),
        )
        .await
        .err()
        .unwrap();
        assert!(error.downcast_ref::<HistoryBudgetExceeded>().is_some(), "{error:#}");
        assert_eq!(count(&pair), before + 1);
        let actual = crate::boot::load_history_proof_with_budget(
            pair.receiver.as_ref(),
            pair.master.id(),
            false,
            false,
            Some(&budget(proof.len())),
        )
        .await
        .unwrap();
        assert_eq!(actual.data(), proof.as_slice());
        assert_eq!(count(&pair), before + 2);
        assert!(
            !local.is_applied() && !local.has_proof(),
            "read-only history download must not silently apply/store target proof"
        );
    })
    .catch_unwind()
    .await;
    finish(&pair, outcome).await;
}
