// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Real overlay/RLDP PSS messages; scoped provider payloads exercise hostile peers.
//! No state publication or authenticated-state claim is made by these raw tests.
use super::*;
use rtos_api::{
    ton::ton_node::{
        persistentstateidv2::PersistentStateIdV2, persistentstatesize::PersistentStateSize,
    },
    IntoBoxed, WireProfile,
};
use storage::types::PersistentStatePartId;

fn inject(pair: &Pair, offset: Option<i64>, bytes: Vec<u8>) {
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
    pair.provider.overlays_router().unwrap().test_pss_reply(
        peer,
        PersistentStateIdV2 {
            block: pair.master.id().clone(),
            masterchain_block: pair.master.id().clone(),
            effective_shard: 0,
        },
        offset,
        bytes,
    );
}
fn size(pair: &Pair, n: i64) {
    inject(
        pair,
        None,
        WireProfile::T0.serialize(&PersistentStateSize { size: n }.into_boxed()).unwrap(),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bounded_pss_real_peer_exact_parts_and_missing_tail() {
    let pair = Pair::with_propagation_profile("included", false, true).await;
    let outcome = std::panic::AssertUnwindSafe(async {
        let client = pair.receiver.overlay_client(pair.master.id().shard()).await.unwrap();
        let id = PersistentStatePartId::WholeState(pair.master.id().clone());
        size(&pair, 96);
        let (peer, total) = client
            .check_persistent_state_bounded(&id, pair.master.id(), 96)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(total, 96);
        let mut body = Vec::new();
        for (offset, bytes) in [(0, vec![0x31; 64]), (64, vec![0x32; 32])] {
            inject(&pair, Some(offset), bytes.clone());
            let actual = client
                .download_persistent_state_part_bounded(
                    &id,
                    pair.master.id(),
                    offset as usize,
                    bytes.len(),
                    &peer,
                    0,
                    adnl::QueryResponseLimits::from_payload_limit(bytes.len()),
                )
                .await
                .unwrap();
            assert_eq!(actual, bytes);
            body.extend(actual);
        }
        assert_eq!(body.len(), total);
        // A peer advertising 96 bytes but returning an empty last slice must
        // not be represented as a filled buffer or silently retried.
        inject(&pair, Some(64), Vec::new());
        let missing = client
            .download_persistent_state_part_bounded(
                &id,
                pair.master.id(),
                64,
                32,
                &peer,
                0,
                adnl::QueryResponseLimits::from_payload_limit(32),
            )
            .await
            .unwrap();
        assert!(missing.is_empty());
        assert_ne!(64 + missing.len(), total, "caller must reject premature EOF");
        // Real provider has no such persistent snapshot; no injected reply.
        assert!(client
            .check_persistent_state_bounded(&id, pair.master.id(), 96)
            .await
            .unwrap()
            .is_none());
    })
    .catch_unwind()
    .await;
    pair.stop_all().await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

// These injections enter the real subscriber response path. The ordinary
// responder checks its advertised maximum before sending any RLDP answer, so
// an oversized response produces no answer, not a client-side decode error.
fn assert_provider_refused_answer(
    pair: &Pair,
    observation_start: usize,
    offset: Option<i64>,
    size: usize,
    error: &anyhow::Error,
) {
    let observations = pair.provider.overlays_router().unwrap().test_pss_observations();
    assert!(
        observations[observation_start..].iter().any(|(id, at, bytes)| {
            id == pair.master.id() && *at == offset && *bytes == Some(size)
        }),
        "real provider must consume the exact oversize injection: {observations:?}"
    );
    assert!(error.downcast_ref::<adnl::RldpQueryTimeout>().is_some(), "{error:#}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bounded_pss_real_peer_rejects_wire_size_and_signed_length() {
    let pair = Pair::with_propagation_profile("included", false, true).await;
    let outcome = std::panic::AssertUnwindSafe(async {
        let client = pair.receiver.overlay_client(pair.master.id().shard()).await.unwrap();
        let id = PersistentStatePartId::WholeState(pair.master.id().clone());
        for n in [-1, 0, 65] {
            size(&pair, n);
            let error =
                client.check_persistent_state_bounded(&id, pair.master.id(), 64).await.unwrap_err();
            match n {
                -1 => assert!(
                    error.downcast_ref::<std::num::TryFromIntError>().is_some(),
                    "{error:#}"
                ),
                0 => assert_eq!(error.to_string(), "Empty advertised PSS"),
                65 => {
                    let limit = error
                        .downcast_ref::<adnl::ResponseLimitExceeded>()
                        .expect("advertised length must exceed caller budget");
                    assert_eq!((limit.limit, limit.actual), (64, 65));
                }
                _ => unreachable!(),
            }
        }
        let observations = pair.provider.overlays_router().unwrap().test_pss_observations().len();
        inject(&pair, None, vec![0x71; 129]);
        let oversized =
            client.check_persistent_state_bounded(&id, pair.master.id(), 64).await.unwrap_err();
        assert_provider_refused_answer(&pair, observations, None, 129, &oversized);
        // A normal response after refusal must still traverse the same peer.
        size(&pair, 64);
        let (_, total) = client
            .check_persistent_state_bounded(&id, pair.master.id(), 64)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(total, 64);
        let mut trailing = WireProfile::T0
            .serialize(
                &rtos_api::ton::ton_node::PersistentStateSize::TonNode_PersistentStateSizeNotFound,
            )
            .unwrap();
        trailing.push(0);
        inject(&pair, None, trailing);
        assert!(client.check_persistent_state_bounded(&id, pair.master.id(), 64).await.is_err());
        size(&pair, 64);
        let (peer, _) = client
            .check_persistent_state_bounded(&id, pair.master.id(), 64)
            .await
            .unwrap()
            .unwrap();
        let observations = pair.provider.overlays_router().unwrap().test_pss_observations().len();
        inject(&pair, Some(0), vec![0x71; 65]);
        let error = client
            .download_persistent_state_part_bounded(
                &id,
                pair.master.id(),
                0,
                64,
                &peer,
                0,
                adnl::QueryResponseLimits::from_payload_limit(64),
            )
            .await
            .unwrap_err();
        let limit =
            error.downcast_ref::<adnl::ResponseLimitExceeded>().expect("decoded slice limit");
        assert_eq!((limit.actual, limit.limit), (65, 64));
        assert!(
            pair.provider.overlays_router().unwrap().test_pss_observations().len() > observations
        );
        // A payload exceeding the whole wire budget is refused by the provider.
        let wire_limit = adnl::QueryResponseLimits::from_payload_limit(64).wire_bytes;
        let observations = pair.provider.overlays_router().unwrap().test_pss_observations().len();
        inject(&pair, Some(0), vec![0x71; wire_limit + 1]);
        let error = client
            .download_persistent_state_part_bounded(
                &id,
                pair.master.id(),
                0,
                64,
                &peer,
                0,
                adnl::QueryResponseLimits::from_payload_limit(64),
            )
            .await
            .unwrap_err();
        assert_provider_refused_answer(&pair, observations, Some(0), wire_limit + 1, &error);
        inject(&pair, Some(0), vec![0x72; 64]);
        let restored = client
            .download_persistent_state_part_bounded(
                &id,
                pair.master.id(),
                0,
                64,
                &peer,
                0,
                adnl::QueryResponseLimits::from_payload_limit(64),
            )
            .await
            .unwrap();
        assert_eq!(restored, vec![0x72; 64]);
        // Wire includes the native envelope allowance; decoded bytes stay slice-bounded.
        for limits in [
            adnl::QueryResponseLimits {
                wire_bytes: 64 + adnl::QueryResponseLimits::ENVELOPE_ALLOWANCE + 1,
                decoded_bytes: 64,
            },
            adnl::QueryResponseLimits { wire_bytes: 64, decoded_bytes: 65 },
        ] {
            let error = client
                .download_persistent_state_part_bounded(
                    &id,
                    pair.master.id(),
                    0,
                    64,
                    &peer,
                    0,
                    limits,
                )
                .await
                .unwrap_err();
            assert_eq!(error.to_string(), "Invalid bounded PSS slice size");
        }
        // All overflow checks precede network admission; no response is injected.
        for offset in [usize::MAX, i64::MAX as usize] {
            assert!(client
                .download_persistent_state_part_bounded(
                    &id,
                    pair.master.id(),
                    offset,
                    64,
                    &peer,
                    0,
                    adnl::QueryResponseLimits::from_payload_limit(64)
                )
                .await
                .is_err());
        }
    })
    .catch_unwind()
    .await;
    pair.stop_all().await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}
