// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use native_identity_tests::inspect;
use rtos_api::{ton::rldp, IntoBoxed, RldpChunk};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_outbound_count_matches_native_256() {
    boundary(OutboundBoundary::Count).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_outbound_local_identity_is_independent() {
    boundary(OutboundBoundary::LocalIdentity).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_outbound_ack_returns_exactly_one_slot() {
    boundary(OutboundBoundary::AckReuse).await;
}

// Retransmit the identical request under the original five-second fixture
// deadline. A completed transfer must not invoke the application twice.
async fn feed(node: &AdnlNode, responder: &RldpNode, route: &AdnlPeers, index: u32, handled: u64) {
    let mut id = [120; 32];
    id[..4].copy_from_slice(&index.to_le_bytes());
    let request = serialize_boxed(
        &rldp::message::Query {
            query_id: UInt256::from(id),
            max_answer_size: 1024,
            timeout: super::super::Version::get() + 60,
            data: serialize_boxed(&Query { overlay: UInt256::default() }).unwrap(),
        }
        .into_boxed(),
    )
    .unwrap();
    let mut encoder = crate::RaptorqEncoder::with_data(&request, Some(768));
    let mut seqno = 0;
    let chunk = RldpChunk {
        transfer_id: id.into(),
        fec_type: encoder.params().clone().into_boxed(),
        part: 0,
        total_size: request.len() as i64,
        data: encoder.encode(&mut seqno).unwrap(),
        seqno: seqno as i32,
    };
    let wire = serialize_boxed(&rldp2::messagepart::MessagePart(chunk).into_boxed()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            node.send_custom(
                &TaggedByteSlice {
                    object: &wire,
                    #[cfg(feature = "telemetry")]
                    tag: 0,
                },
                route,
            )
            .await
            .unwrap();
            if responder.allocated.response_lifecycle.1.load(Ordering::Acquire) >= handled {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("actual native application must finish its outbound admission");
    assert_eq!(responder.allocated.response_lifecycle.1.load(Ordering::Acquire), handled);
}

async fn boundary(mode: OutboundBoundary) {
    let local = matches!(mode, OutboundBoundary::LocalIdentity);
    let ack_reuse = matches!(mode, OutboundBoundary::AckReuse);
    let count_expected = checked_ack_native_effects(
        include_bytes!("../../../ci/conformance/rldp2_outbound_count_context.tsv"),
        include_bytes!("../../../ci/conformance/rldp2_outbound_count_effects.jsonl"),
        include_bytes!("../../../ci/conformance/rldp2_outbound_count_reference.cpp"),
        include_bytes!("../../../ci/conformance/rldp2_outbound_count_metadata.json"),
    );
    let local_expected = checked_ack_native_effects(
        include_bytes!("../../../ci/conformance/rldp2_local_identity_context.tsv"),
        include_bytes!("../../../ci/conformance/rldp2_local_identity_effects.jsonl"),
        include_bytes!("../../../ci/conformance/rldp2_local_identity_reference.cpp"),
        include_bytes!("../../../ci/conformance/rldp2_local_identity_metadata.json"),
    );
    assert_eq!(
        include_str!("../../../ci/conformance/rldp2_outbound_count_context.tsv").trim(),
        "257"
    );
    assert_eq!(
        include_str!("../../../ci/conformance/rldp2_local_identity_context.tsv").trim(),
        "256 1 64 60"
    );
    assert_eq!(
        include_str!("../../../ci/conformance/rldp2_ack_reuse_context.tsv").trim(),
        "257 64 60"
    );
    let (reply, packets, nodes, rldps, route) = topology(3).await;
    for node in &rldps {
        node.peers.enable_native_for_tests();
    }
    let outcome = std::panic::AssertUnwindSafe(async {
        packets.drop_parts.store(true, Ordering::Release);
        reply.response_bytes.store(64, Ordering::Release);
        let peer = rldps[1].get_peer(route.other(), route.local(), true, None).await.unwrap();
        let native = peer.native.get().expect("actual responder must use native Connection");
        let submitted = if local { 256 } else { 257 };
        for index in 0..submitted { feed(&nodes[0], &rldps[1], &route, index, u64::from(index+1)).await; }
        let initial = inspect(native).await.1;
        assert_eq!(initial, 256);
        assert_eq!(rldps[1].allocated.response_lifecycle.0.load(Ordering::Acquire), 256);
        assert_eq!(rldps[1].allocated.send_transfers.load(Ordering::Acquire), 0, "legacy senders must not supply the qualification");
        tokio::time::timeout(Duration::from_secs(5), async {
            while packets.transfers.lock().unwrap().len() != 256 { tokio::time::sleep(Duration::from_millis(5)).await; }
        }).await.expect("all accepted native responses must reach the actual wire");
        if local {
            let second = nodes[1].key_by_tag(1).unwrap();
            let remote = nodes[0].key_by_tag(0).unwrap();
            nodes[0].add_peer(remote.id(), nodes[1].ip_address_adnl(), None, &second).unwrap();
            nodes[1].add_peer(second.id(), nodes[0].ip_address_adnl(), None, &remote).unwrap();
            let other_route = AdnlPeers::with_keys(remote.id().clone(), second.id().clone());
            feed(&nodes[0], &rldps[1], &other_route, 300, 257).await;
            let other_peer = rldps[1].get_peer(second.id(), remote.id(), true, None).await.unwrap();
            let other = other_peer.native.get().expect("second identity must own its native Connection");
            let actual = serde_json::json!({"first_live":inspect(native).await.1,"second_live":inspect(other).await.1});
            assert_eq!(vec![actual.clone()], local_expected);
            eprintln!("NATIVE_OUTBOUND_LOCAL: {actual}");
        } else if ack_reuse {
            let id: [u8;32] = packets.transfers.lock().unwrap().iter().next().unwrap().as_slice().try_into().unwrap();
            let ack = serialize_boxed(&rldp2::messagepart::Complete { transfer_id: id.into(), part: 0 }.into_boxed()).unwrap();
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    nodes[0].send_custom(&TaggedByteSlice {object:&ack, #[cfg(feature="telemetry")] tag:0},&route).await.unwrap();
                    if inspect(native).await.1 == 255 && native.completed_send_ids.lock().unwrap().contains(&id) { break; }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }).await.expect("real UDP ACK must release exactly one native sender");
            let after_ack = inspect(native).await.1;
            assert_eq!(native.completed_send_ids.lock().unwrap().as_slice(), &[id]);
            feed(&nodes[0], &rldps[1], &route, 300, 258).await;
            let after_replacement = inspect(native).await.1;
            let reverse = AdnlPeers::with_keys(route.other().clone(),route.local().clone());
            // Synchronous authenticated handler plus driver barrier: the
            // duplicate ACK has actually been processed before observing count.
            assert!(rldps[1].try_consume_custom(&ack, &reverse).await.unwrap());
            let duplicate_ack_retained = inspect(native).await.1;
            assert_eq!(native.completed_send_ids.lock().unwrap().as_slice(), &[id]);
            let actual = serde_json::json!({"initial":initial,"after_ack":after_ack,"after_replacement":after_replacement,"started":rldps[1].allocated.response_lifecycle.0.load(Ordering::Acquire),"completed":native.completed_sends.load(Ordering::Acquire),"duplicate_ack_retained":duplicate_ack_retained});
            assert_eq!(actual, ack_reuse_native_effects());
            eprintln!("NATIVE_OUTBOUND_ACK: {actual}");
        } else {
            let actual = serde_json::json!({"submitted":submitted,"retained":initial});
            assert_eq!(vec![actual.clone()], count_expected);
            eprintln!("NATIVE_OUTBOUND_COUNT: {actual}");
        }
        assert_eq!(reply.calls.load(Ordering::Acquire), if local || !ack_reuse { 257 } else { 258 });
        if local || ack_reuse {
            let mut replacement = [120u8;32];
            replacement[..4].copy_from_slice(&300u32.to_le_bytes());
            let answer_id = replacement.map(|byte| byte ^ 0xff);
            tokio::time::timeout(Duration::from_secs(5), async {
                while !packets.transfers.lock().unwrap().contains(answer_id.as_slice()) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }).await.expect("independent or replacement sender must deliver its exact ID over UDP");
        }
        let healthy = nodes[2].key_by_tag(0).unwrap();
        let healthy_route = AdnlPeers::with_keys(healthy.id().clone(),route.other().clone());
        let bytes = serialize_boxed(&Query {overlay:UInt256::default()}).unwrap();
        let (answer,_) = tokio::time::timeout(Duration::from_secs(12), rldps[2].query(&TaggedByteSlice {object:&bytes,#[cfg(feature="telemetry")]tag:0},Some(1024),&healthy_route,true,None)).await.unwrap().unwrap();
        assert_eq!(answer.unwrap(), vec![42;64]);
        assert_eq!(inspect(native).await.1,256,"healthy progress must not evict saturated peer responses");
    }).catch_unwind().await;
    packets.drop_parts.store(false, Ordering::Release);
    let stopped = futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
    for result in stopped {
        result.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_outbound_refused_query_keeps_deadline_without_retry() {
    assert_eq!(
        include_str!("../../../ci/conformance/rldp2_refused_query_context.tsv").trim(),
        "256 60 10 64 1024"
    );
    let expected = refused_query_native_effects();
    let (reply, packets, nodes, rldps, route) = topology(2).await;
    for node in &rldps {
        node.peers.enable_native_for_tests();
    }
    let outcome = std::panic::AssertUnwindSafe(async {
        packets.drop_parts.store(true, Ordering::Release);
        reply.response_bytes.store(64, Ordering::Release);
        let peer = rldps[1].get_peer(route.other(),route.local(),true,None).await.unwrap();
        let native = peer.native.get().expect("actual responder must use native Connection");
        for index in 0..256 { feed(&nodes[0],&rldps[1],&route,index,u64::from(index+1)).await; }
        let saturated = inspect(native).await.1;
        assert_eq!(saturated,256);
        assert_eq!(rldps[1].allocated.send_transfers.load(Ordering::Acquire),0);
        let initial_submissions = native.query_send_results.lock().unwrap().clone();
        assert!(initial_submissions.is_empty());
        let reverse = AdnlPeers::with_keys(route.other().clone(),route.local().clone());
        let before = rldps[1].query_budget.remaining(&reverse);
        let bytes = serialize_boxed(&Query {overlay:UInt256::default()}).unwrap();
        let request = TaggedByteSlice {object:&bytes,#[cfg(feature="telemetry")]tag:0};
        let started = tokio::time::Instant::now();
        let query = rldps[1].query(&request,Some(1024),&reverse,true,None);
        tokio::pin!(query);
        // A single poll can stop at ReceiveLimit before Send. Wait for the
        // actual Send command result before releasing any saturated capacity.
        tokio::select! {
            biased;
            result = query.as_mut() => panic!("refused query completed before its deadline: {result:?}"),
            result = tokio::time::timeout(Duration::from_secs(5),async {
                while native.query_send_results.lock().unwrap().is_empty() { tokio::time::sleep(Duration::from_millis(5)).await; }
            }) => result.expect("query must reach actual native Send admission"),
        }
        let refused = native.query_send_results.lock().unwrap().clone();
        assert_eq!(refused.len(),1);
        assert!(!refused[0].1,"saturated native sender must reject the active query");
        assert_eq!(inspect(native).await.1,256);
        assert_eq!(rldps[1].query_budget.remaining(&reverse),(before.0-1,before.1-1));
        assert_eq!(reply.calls.load(Ordering::Acquire),256);
        packets.drop_parts.store(false, Ordering::Release);
        tokio::select! {
            biased;
            result = query.as_mut() => panic!("refused query completed while send slots drained: {result:?}"),
            result = tokio::time::timeout(Duration::from_secs(5),async {
                while inspect(native).await.1 != 0 { tokio::time::sleep(Duration::from_millis(5)).await; }
            }) => result.expect("original responses must drain before query deadline"),
        }
        let drained_before_deadline = started.elapsed() < Duration::from_secs(9);
        assert!(drained_before_deadline);
        let observed_submissions = native.query_send_results.lock().unwrap().clone();
        assert_eq!(observed_submissions,refused);
        let result = tokio::time::timeout(Duration::from_secs(12),query.as_mut()).await.expect("refused query must terminate");
        let elapsed_ms = started.elapsed().as_millis();
        let timed_out = result.unwrap_err().downcast_ref::<RldpQueryTimeout>().is_some();
        assert!(timed_out);
        assert!((9500..13000).contains(&elapsed_ms),"elapsed={elapsed_ms}");
        let implicit_retry = reply.calls.load(Ordering::Acquire)!=256;
        assert!(!implicit_retry);
        let observed_submissions = native.query_send_results.lock().unwrap().clone();
        assert_eq!(observed_submissions,refused);
        assert_eq!(rldps[1].query_budget.remaining(&reverse),before);
        let (answer,_) = tokio::time::timeout(Duration::from_secs(12),rldps[1].query(&request,Some(1024),&reverse,true,None)).await.unwrap().unwrap();
        let answer = answer.unwrap();
        assert_eq!(answer,vec![42;64]);
        assert_eq!(reply.calls.load(Ordering::Acquire),257);
        let submissions = native.query_send_results.lock().unwrap().clone();
        assert_eq!(submissions.len(),2);
        assert!(submissions[1].1);
        assert_ne!(submissions[1].0,refused[0].0);
        let actual = serde_json::json!({"saturated":saturated,"drained_before_deadline":drained_before_deadline,"timeout":timed_out,"implicit_retry":implicit_retry,"fresh_answer_bytes":answer.len()});
        assert_eq!(actual,expected);
        eprintln!("NATIVE_REFUSED_QUERY: {actual} elapsed_ms={elapsed_ms}");
    }).catch_unwind().await;
    packets.drop_parts.store(false, Ordering::Release);
    let stopped = futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
    for result in stopped {
        result.unwrap();
    }
}
