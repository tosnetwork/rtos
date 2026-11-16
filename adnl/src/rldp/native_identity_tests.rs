// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

pub(super) async fn inspect(
    native: &super::super::native_connection::NativeConnection,
) -> (usize, usize, usize) {
    let (reply, receipt) = tokio::sync::oneshot::channel();
    native.driver.submit(super::super::connection_driver::Command::Inspect(reply)).await.unwrap();
    receipt.await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_connection_same_transfer_id_isolated_by_connection() {
    assert_eq!(
        include_str!("../../../ci/conformance/rldp2_transfer_identity_context.tsv").trim(),
        "3"
    );
    use rtos_api::{ton::rldp, IntoBoxed, RldpChunk};
    let (reply, packets, nodes, rldps, peers) = topology_with_observers(3, None, true).await;
    for node in &rldps {
        node.peers.enable_native_for_tests();
    }
    let outcome = std::panic::AssertUnwindSafe(async {
        let local = nodes[1].key_by_tag(1).unwrap();
        let remote = nodes[0].key_by_tag(0).unwrap();
        nodes[0].add_peer(remote.id(), nodes[1].ip_address_adnl(), None, &local).unwrap();
        nodes[1].add_peer(local.id(), nodes[0].ip_address_adnl(), None, &remote).unwrap();
        let routes = [
            (0, peers.clone()),
            (2, AdnlPeers::with_keys(nodes[2].key_by_tag(0).unwrap().id().clone(), peers.other().clone())),
            (0, AdnlPeers::with_keys(remote.id().clone(), local.id().clone())),
        ];
        let message = serialize_boxed(&rldp::message::Message { id: UInt256::default(), data: b"churn".to_vec() }.into_boxed()).unwrap();
        let mut encoder = crate::RaptorqEncoder::with_data(&message, None);
        let mut seqno = 0;
        let chunk = RldpChunk { transfer_id: UInt256::default(), fec_type: encoder.params().clone().into_boxed(), part: 0, total_size: message.len() as i64, data: encoder.encode(&mut seqno).unwrap(), seqno: seqno as i32 };
        let wire = serialize_boxed(&rldp2::messagepart::MessagePart(chunk).into_boxed()).unwrap();
        for (index, (sender, route)) in routes.iter().enumerate() {
            nodes[*sender].send_custom(&TaggedByteSlice { object: &wire, #[cfg(feature = "telemetry")] tag: 0 }, route).await.unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                while reply.messages.load(Ordering::Acquire) < index + 1 { reply.message_received.notified().await; }
            }).await.expect("same transfer ID on another authenticated connection must deliver independently");
        }
        let mut remembered = Vec::new();
        for (_, route) in &routes {
            let reverse = AdnlPeers::with_keys(route.other().clone(), route.local().clone());
            assert!(rldps[1].try_consume_custom(&wire, &reverse).await.unwrap());
            let peer = rldps[1].get_peer(reverse.local(), reverse.other(), true, None).await.unwrap();
            let native = peer.native.get().expect("actual peer must own native Connection");
            let (inbound, outbound, completed) = inspect(native).await;
            assert_eq!((inbound, outbound), (0, 0));
            remembered.push(completed);
            assert!(peer.completed.lock().unwrap().is_empty(), "old receive wrapper must remain unused");
        }
        // Drop outgoing data at the remote authenticated observers, so ACKs
        // below are the sole completions. Use the actual owned Connection send
        // machinery with an explicit ID, as in the native vector.
        packets.drop_parts.store(true, Ordering::Release);
        let mut natives = Vec::new();
        for (_, route) in &routes {
            let peer = rldps[1].get_peer(route.other(), route.local(), true, None).await.unwrap();
            let native = peer.native.get().expect("actual peer must own native Connection").clone();
            assert!(native.driver.submit(super::super::connection_driver::Command::Send {
                id: [7; 32], data: vec![42; 64], deadline: Some(std::time::Instant::now()+Duration::from_secs(60)), answer: false,
            }).await.unwrap());
            assert_eq!(inspect(&native).await.1, 1);
            natives.push(native);
        }
        let ack = serialize_boxed(&rldp2::messagepart::Complete { transfer_id: UInt256::from([7; 32]), part: 0 }.into_boxed()).unwrap();
        let mut ack_pending = Vec::new();
        for (index, (_, route)) in routes.iter().enumerate() {
            let reverse = AdnlPeers::with_keys(route.other().clone(), route.local().clone());
            for _ in 0..2 {
                assert!(rldps[1].try_consume_custom(&ack, &reverse).await.unwrap());
                let mut pending = Vec::new();
                for native in &natives { pending.push(inspect(native).await.1); }
                let expected: Vec<_> = (0..3).map(|other| usize::from(other > index)).collect();
                assert_eq!(pending, expected, "ACK must affect only its own connection");
            }
            let mut pending = Vec::new();
            for native in &natives { pending.push(inspect(native).await.1); }
            ack_pending.push(pending);
        }
        let actual = serde_json::json!({"delivered":reply.messages.load(Ordering::Acquire),"remembered":remembered,"duplicates_suppressed":reply.messages.load(Ordering::Acquire)==3,"ack_pending":ack_pending});
        eprintln!("NATIVE_TRANSFER_IDENTITY: {actual}");
        assert_eq!(actual, transfer_identity_native_effects());
    }).catch_unwind().await;
    for result in futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await {
        result.unwrap();
    }
    assert_eq!(rldps[1].allocated.send_transfers.load(Ordering::Acquire), 0);
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_query_response_isolated_by_local_and_remote_identity() {
    use rtos_api::{ton::rldp, IntoBoxed, RldpChunk};
    assert_eq!(
        include_str!("../../../ci/conformance/rldp2_query_identity_context.tsv").trim(),
        "0 64 1024"
    );
    let expected = checked_ack_native_effects(
        include_bytes!("../../../ci/conformance/rldp2_query_identity_context.tsv"),
        include_bytes!("../../../ci/conformance/rldp2_query_identity_effects.jsonl"),
        include_bytes!("../../../ci/conformance/rldp2_query_identity_reference.cpp"),
        include_bytes!("../../../ci/conformance/rldp2_query_identity_metadata.json"),
    );
    let (reply, requests, nodes, rldps, peers) = topology(3).await;
    for node in &rldps {
        node.peers.enable_native_for_tests();
    }
    reply.hold.store(true, Ordering::Release);
    let outcome = std::panic::AssertUnwindSafe(async {
        let requester = peers.other().clone();
        let answerer = peers.local().clone();
        let other_local = nodes[1].key_by_tag(1).unwrap();
        let answerer_key = nodes[0].key_by_tag(0).unwrap();
        nodes[0].add_peer(&answerer, nodes[1].ip_address_adnl(), None, &other_local).unwrap();
        nodes[1].add_peer(other_local.id(), nodes[0].ip_address_adnl(), None, &answerer_key).unwrap();
        let query_route = AdnlPeers::with_keys(requester.clone(), answerer.clone());
        let before = rldps[1].query_budget.remaining(&query_route);
        let input = serialize_boxed(&Query { overlay: UInt256::default() }).unwrap();
        let query = TaggedByteSlice { object: &input, #[cfg(feature = "telemetry")] tag: 0 };
        let resolved = AtomicBool::new(false);
        let request = async {
            let result = rldps[1].query(&query, Some(1024), &query_route, true, None).await;
            resolved.store(true, Ordering::Release);
            result
        };
        let inject = async {
            tokio::time::timeout(Duration::from_secs(2), reply.entered.notified()).await.unwrap();
            let id = {
                let ids = requests.transfers.lock().unwrap();
                assert_eq!(ids.len(), 1);
                let request: [u8;32] = ids.iter().next().unwrap().as_slice().try_into().unwrap();
                request.map(|byte| byte ^ 0xff)
            };
            let answer = serialize_boxed(&rldp::message::Answer { query_id: UInt256::default(), data: vec![42;64] }.into_boxed()).unwrap();
            let mut encoder = crate::RaptorqEncoder::with_data(&answer, Some(768));
            let mut seqno=0;
            let chunk = RldpChunk { transfer_id:id.into(),fec_type:encoder.params().clone().into_boxed(),part:0,total_size:answer.len() as i64,data:encoder.encode(&mut seqno).unwrap(),seqno:0 };
            let wire=serialize_boxed(&rldp2::messagepart::MessagePart(chunk).into_boxed()).unwrap();
            let routes = [
                (2, AdnlPeers::with_keys(nodes[2].key_by_tag(0).unwrap().id().clone(), requester.clone())),
                (0, AdnlPeers::with_keys(answerer.clone(), other_local.id().clone())),
                (0, AdnlPeers::with_keys(answerer.clone(), requester.clone())),
            ];
            for (index,(sender,route)) in routes.iter().enumerate() {
                let peer=rldps[1].get_peer(route.other(),route.local(),true,None).await.unwrap();
                let native=peer.native.get().expect("actual peer must own native Connection");
                assert_eq!(native.routed_receives.load(Ordering::Acquire),0);
                nodes[*sender].send_custom(&TaggedByteSlice { object:&wire, #[cfg(feature="telemetry")] tag:0 },route).await.unwrap();
                tokio::time::timeout(Duration::from_secs(2),async {
                    while native.routed_receives.load(Ordering::Acquire)!=1 { tokio::task::yield_now().await; }
                }).await.expect("response must reach the actual Connection event route");
                assert_eq!(inspect(native).await.2,1,"response must have completed FEC decoding");
                if index<2 {
                    // Receipt follows waiter routing. The quota check observes
                    // query state directly, even before its caller is polled.
                    assert_eq!(rldps[1].query_budget.remaining(&query_route),(before.0-1,before.1-1),"wrong identity must not release the real query");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    assert!(!resolved.load(Ordering::Acquire),"wrong identity must not resolve the query");
                }
            }
        };
        let (answer,())=tokio::time::timeout(Duration::from_secs(5),async { tokio::join!(request,inject) }).await.unwrap();
        assert_eq!(answer.unwrap().0.unwrap(),vec![42;64]);
        assert_eq!(rldps[1].query_budget.remaining(&query_route),before);
        let actual=serde_json::json!({"wrong_remote_pending":true,"wrong_local_pending":true,"decoded_wrong_responses":2,"answer_bytes":64,"answer_fill":42});
        assert_eq!(vec![actual.clone()],expected);
        eprintln!("NATIVE_QUERY_IDENTITY: {actual}");
    }).catch_unwind().await;
    reply.hold.store(false, Ordering::Release);
    reply.release.notify_waiters();
    reply.release.notify_one();
    for result in futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await {
        result.unwrap();
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_identity_budget_shared_across_connections_and_released_on_eviction() {
    use rtos_api::{IntoBoxed, RldpChunk};
    let expected = checked_ack_native_effects(
        include_bytes!("../../../ci/conformance/rldp2_identity_budget_runtime_context.tsv"),
        include_bytes!("../../../ci/conformance/rldp2_identity_budget_runtime_effects.jsonl"),
        include_bytes!("../../../ci/conformance/rldp2_identity_budget_runtime_reference.cpp"),
        include_bytes!("../../../ci/conformance/rldp2_identity_budget_runtime_metadata.json"),
    );
    let (_, _, nodes, rldps, _) = topology_configured(7, None, false, true).await;
    for node in &rldps {
        node.peers.enable_native_for_tests();
    }
    let a = nodes[1].key_by_tag(0).unwrap();
    let b = nodes[6].key_by_tag(0).unwrap();
    let budget = super::super::rldp2::budget::InboundBudget::process_default();
    let outcome = std::panic::AssertUnwindSafe(async {
        let local = nodes[0].key_by_tag(0).unwrap();
        nodes[0].add_peer(local.id(), nodes[6].ip_address_adnl(), None, &b).unwrap();
        nodes[6].add_peer(b.id(), nodes[0].ip_address_adnl(), None, &local).unwrap();
        let mut encoder = crate::RaptorqEncoder::with_data(&vec![42; 2048], Some(768));
        let mut seqno = 0;
        let symbol = encoder.encode(&mut seqno).unwrap();
        let fec = encoder.params().clone().into_boxed();
        let feed = |sender: usize, receiver: usize, n: u16| {
            let nodes = &nodes;
            let rldps = &rldps;
            let symbol = &symbol;
            let fec = &fec;
            async move {
                let source = nodes[sender].key_by_tag(0).unwrap();
                let target = nodes[receiver].key_by_tag(0).unwrap();
                let route = AdnlPeers::with_keys(source.id().clone(), target.id().clone());
                let peer = rldps[receiver].get_peer(target.id(), source.id(), true, None).await.unwrap();
                let native = peer.native.get().expect("real peer must use native Connection");
                let before = native.processed_packets.load(Ordering::Acquire);
                let mut id = [0; 32];
                id[..2].copy_from_slice(&n.to_le_bytes());
                let chunk = RldpChunk { transfer_id: id.into(), fec_type: fec.clone(), part: 0, total_size: 2048, seqno: 0, data: symbol.clone() };
                let wire = serialize_boxed(&rldp2::messagepart::MessagePart(chunk).into_boxed()).unwrap();
                nodes[sender].send_custom(&TaggedByteSlice { object: &wire, #[cfg(feature="telemetry")] tag: 0 }, &route).await.unwrap();
                tokio::time::timeout(Duration::from_secs(2), async {
                    while native.processed_packets.load(Ordering::Acquire) == before { tokio::task::yield_now().await; }
                }).await.expect("including refused packets, actual Connection processing must finish");
                inspect(native).await.0
            }
        };
        // Finish before the native ten-second unsolicited receive deadline.
        let actual = tokio::time::timeout(Duration::from_secs(8), async {
            for receiver in [0, 2, 3, 4] {
                for n in 0..256 {
                    assert_eq!(feed(1, receiver, n).await, usize::from(n) + 1);
                }
            }
            let full = budget.identity_usage(a.id().data());
            assert_eq!(full.decoders, 1024);
            let blocked = feed(1, 5, 0).await;
            assert_eq!(blocked, 0, "fifth connection must share the remote identity quota");
            let independent = feed(6, 0, 0).await;
            assert_eq!(independent, 1, "another remote identity must retain its own quota");
            let route = AdnlPeers::with_keys(local.id().clone(), a.id().clone());
            let retired = rldps[0].peers.evict_for_test(&route);
            retired.drained.cancelled().await;
            let evicted = budget.identity_usage(a.id().data());
            assert_eq!(evicted.decoders, 768, "actual retired owner must release its 256 decoders");
            let retried = feed(1, 5, 0).await;
            assert_eq!(retried, 1, "budget refusal must remain retryable after actual release");
            let retry = budget.identity_usage(a.id().data());
            assert_eq!(budget.identity_usage(b.id().data()).decoders, 1);
            serde_json::json!({"full_decoders":full.decoders,"full_bytes":full.bytes,"blocked_inbound":blocked,"other_inbound":independent,"after_eviction":evicted.decoders,"bytes_after_eviction":evicted.bytes,"retry_inbound":retried,"after_retry":retry.decoders,"bytes_after_retry":retry.bytes})
        }).await.expect("qualification must complete before incomplete receives expire");
        actual
    }).catch_unwind().await;
    for result in futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await {
        result.unwrap();
    }
    let mut actual = match outcome {
        Ok(actual) => actual,
        Err(panic) => std::panic::resume_unwind(panic),
    };
    let released_a = budget.identity_usage(a.id().data());
    let released_b = budget.identity_usage(b.id().data());
    actual["released_a_decoders"] = released_a.decoders.into();
    actual["released_a_bytes"] = released_a.bytes.into();
    actual["released_b_decoders"] = released_b.decoders.into();
    actual["released_b_bytes"] = released_b.bytes.into();
    eprintln!("NATIVE_IDENTITY_BUDGET: {actual}");
    assert_eq!(vec![actual], expected);
}
