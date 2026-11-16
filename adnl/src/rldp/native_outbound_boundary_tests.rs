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
    feed_with_limit(node, responder, route, index, handled, 1024).await;
}

async fn feed_with_limit(
    node: &AdnlNode,
    responder: &RldpNode,
    route: &AdnlPeers,
    index: u32,
    handled: u64,
    limit: i64,
) {
    let mut id = [120; 32];
    id[..4].copy_from_slice(&index.to_le_bytes());
    let request = serialize_boxed(
        &rldp::message::Query {
            query_id: UInt256::from(id),
            max_answer_size: limit,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_silent_senders_preserve_healthy_peer_progress() {
    assert_eq!(
        include_str!("../../../ci/conformance/rldp2_sender_fairness_context.tsv").trim(),
        "8 60 10 64 1024"
    );
    let expected = checked_ack_native_effects(
        include_bytes!("../../../ci/conformance/rldp2_sender_fairness_context.tsv"),
        include_bytes!("../../../ci/conformance/rldp2_sender_fairness_effects.jsonl"),
        include_bytes!("../../../ci/conformance/rldp2_sender_fairness_reference.cpp"),
        include_bytes!("../../../ci/conformance/rldp2_sender_fairness_metadata.json"),
    );
    native_sender_progress(8, 64, 1024, expected, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_large_silent_responses_retain_initialized_encoders() {
    assert_eq!(
        include_str!("../../../ci/conformance/rldp2_retained_encoder_context.tsv").trim(),
        "16 60 10 262144 524288"
    );
    let expected = checked_ack_native_effects(
        include_bytes!("../../../ci/conformance/rldp2_retained_encoder_context.tsv"),
        include_bytes!("../../../ci/conformance/rldp2_retained_encoder_effects.jsonl"),
        include_bytes!("../../../ci/conformance/rldp2_retained_encoder_reference.cpp"),
        include_bytes!("../../../ci/conformance/rldp2_retained_encoder_metadata.json"),
    );
    native_sender_progress(16, 262144, 524288, expected, true).await;
}

async fn native_sender_progress(
    count: u32,
    payload: usize,
    limit: i64,
    expected: Vec<serde_json::Value>,
    inspect_encoders: bool,
) {
    let (reply, packets, nodes, rldps, route) = topology(3).await;
    for node in &rldps {
        node.peers.enable_native_for_tests();
    }
    let mut drain_receipts = Vec::new();
    let outcome = std::panic::AssertUnwindSafe(async {
        packets.drop_parts.store(true, Ordering::Release);
        reply.response_bytes.store(payload, Ordering::Release);
        let silent_peer = rldps[1].get_peer(route.other(), route.local(), true, None).await.unwrap();
        drain_receipts.push(silent_peer.drained.clone());
        let silent = silent_peer.native.get().expect("silent sender must use actual native Connection");
        let mut ids = std::collections::BTreeSet::new();
        for index in 0u32..count {
            feed_with_limit(&nodes[0], &rldps[1], &route, index, u64::from(index + 1), limit).await;
            let mut id = [120;32];
            id[..4].copy_from_slice(&index.to_le_bytes());
            ids.insert(id.map(|b| b ^ 0xff).to_vec());
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if ids.iter().all(|id|packets.transfers.lock().unwrap().contains(id)) {break;}
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }).await.expect("every silent response must emit its exact transfer ID over UDP");
        assert_eq!(inspect(silent).await.1, count as usize);
        let healthy = nodes[2].key_by_tag(0).unwrap();
        let healthy_route = AdnlPeers::with_keys(healthy.id().clone(),route.other().clone());
        let bytes = serialize_boxed(&Query {overlay:UInt256::default()}).unwrap();
        let started = tokio::time::Instant::now();
        let (answer,_) = rldps[2].query(&TaggedByteSlice {object:&bytes,#[cfg(feature="telemetry")]tag:0},Some(u64::try_from(limit).unwrap()),&healthy_route,true,None).await.unwrap();
        assert_eq!(answer,Some(vec![42;payload]));
        assert!(started.elapsed()<Duration::from_secs(10),"healthy query must retain its original API deadline");
        let healthy_peer = rldps[1].get_peer(route.other(),healthy.id(),true,None).await.unwrap();
        drain_receipts.push(healthy_peer.drained.clone());
        let healthy_native = healthy_peer.native.get().expect("healthy sender must use actual native Connection");
        tokio::time::timeout(Duration::from_secs(5),async {
            while healthy_native.completed_sends.load(Ordering::Acquire)!=1 {tokio::time::sleep(Duration::from_millis(5)).await;}
        }).await.expect("healthy answer must actually complete, not only reach its caller");
        assert_eq!(inspect(healthy_native).await.1,0);
        assert_eq!(silent.completed_sends.load(Ordering::Acquire),0);
        assert_eq!(rldps[1].allocated.send_transfers.load(Ordering::Acquire),0,"legacy sender must not satisfy native qualification");
        if inspect_encoders {
            let (done, receipt) = tokio::sync::oneshot::channel();
            silent.driver.submit(super::super::connection_driver::Command::InspectEncoders(done)).await.unwrap();
            let retained = receipt.await.unwrap();
            assert_eq!(retained.len(),count as usize);
            let retained_ids = retained.iter().map(|(id,_,_)|id.to_vec()).collect::<std::collections::BTreeSet<_>>();
            assert_eq!(retained_ids,ids,"all original silent responses must remain retained");
            for (_,bytes,encoders) in &retained {
                assert!(*bytes > payload,"retained wire data includes the answer envelope");
                assert_eq!(*encoders,1,"each sub-part-size answer retains its initialized encoder");
            }
            eprintln!("NATIVE_RETAINED_ENCODERS count={} wire_bytes={} encoders={}",retained.len(),retained.iter().map(|(_,bytes,_)|bytes).sum::<usize>(),retained.iter().map(|(_,_,encoders)|encoders).sum::<usize>());
        }
        let actual = serde_json::json!({"silent_live":inspect(silent).await.1,"healthy_answer_bytes":answer.unwrap().len(),"healthy_completed":true});
        assert_eq!(vec![actual.clone()],expected);
        assert_eq!(reply.calls.load(Ordering::Acquire),count as usize+1);
        eprintln!("NATIVE_SENDER_FAIRNESS: {actual} healthy_elapsed_ms={}",started.elapsed().as_millis());
    }).catch_unwind().await;
    packets.drop_parts.store(false, Ordering::Release);
    let stopped = futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
    for result in stopped {
        result.unwrap();
    }
    assert_eq!(drain_receipts.len(), 2);
    assert!(
        drain_receipts.iter().all(|receipt| receipt.is_cancelled()),
        "stop must join both actual native drivers"
    );
}

fn sender_deadline_effects() -> Vec<serde_json::Value> {
    checked_ack_native_effects(
        include_bytes!("../../../ci/conformance/rldp2_sender_absolute_deadline_context.tsv"),
        include_bytes!("../../../ci/conformance/rldp2_sender_absolute_deadline_effects.jsonl"),
        include_bytes!("../../../ci/conformance/rldp2_sender_absolute_deadline_reference.cpp"),
        include_bytes!("../../../ci/conformance/rldp2_sender_absolute_deadline_metadata.json"),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_sender_absolute_deadlines_match_native() {
    let expected = sender_deadline_effects();
    let (_, packets, nodes, rldps, route) = topology(2).await;
    for node in &rldps {
        node.peers.enable_native_for_tests();
    }
    let outcome=std::panic::AssertUnwindSafe(async {
        packets.drop_parts.store(true,Ordering::Release);
        let peer=rldps[1].get_peer(route.other(),route.local(),true,None).await.unwrap();
        let native=peer.native.get().expect("deadline probe requires actual native Connection");
        let mut ids=Vec::new();
        for (index,row) in expected.iter().enumerate() {
            let id=[180+index as u8;32]; ids.push(id);
            let deadline=std::time::Instant::now()+Duration::from_millis(row["deadline_ms"].as_u64().unwrap());
            assert!(native.driver.submit(super::super::connection_driver::Command::Send {id,data:b"query".to_vec(),deadline:Some(deadline),answer:false}).await.unwrap());
        }
        let loss=expected[0]["loss_ms"].as_u64().unwrap();
        assert!(expected.iter().all(|row|row["loss_ms"]==loss));
        tokio::time::sleep(Duration::from_millis(loss)).await;
        let (done,receipt)=tokio::sync::oneshot::channel();
        native.driver.submit(super::super::connection_driver::Command::InspectEncoders(done)).await.unwrap();
        let retained=receipt.await.unwrap();
        let failed=native.failed_send_ids.lock().unwrap().clone();
        let mut actual=Vec::new();
        for (row,id) in expected.iter().zip(&ids) {
            assert!(packets.transfers.lock().unwrap().contains(id.as_slice()),"each deadline sender must emit an actual UDP packet");
            actual.push(serde_json::json!({"deadline_ms":row["deadline_ms"],"loss_ms":loss,"pending":retained.iter().filter(|(sent,_,_)|sent==id).count(),"expired":failed.iter().filter(|sent|*sent==id).count()}));
        }
        assert_eq!(actual,expected);
        assert_eq!(native.completed_sends.load(Ordering::Acquire),0);
        assert_eq!(rldps[1].allocated.send_transfers.load(Ordering::Acquire),0);
        eprintln!("NATIVE_SENDER_DEADLINES: {}",serde_json::to_string(&actual).unwrap());
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
async fn native_query_survives_loss_until_absolute_deadline() {
    let expected = sender_deadline_effects();
    let (_, packets, nodes, rldps, route) = topology(2).await;
    for node in &rldps {
        node.peers.enable_native_for_tests();
    }
    let outcome = std::panic::AssertUnwindSafe(async {
        packets.drop_parts.store(true, Ordering::Release);
        let peer = rldps[1].get_peer(route.other(), route.local(), true, None).await.unwrap();
        let native = peer.native.get().expect("query must use actual native Connection");
        let reverse = AdnlPeers::with_keys(route.other().clone(), route.local().clone());
        let bytes = serialize_boxed(&Query { overlay: UInt256::default() }).unwrap();
        let request = TaggedByteSlice {
            object: &bytes,
            #[cfg(feature = "telemetry")]
            tag: 0,
        };
        let query = rldps[1].query(&request, Some(1024), &reverse, true, None);
        let loss = async {
            tokio::time::timeout(Duration::from_secs(5), async {
                while native.query_send_results.lock().unwrap().is_empty() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("query must actually submit before measuring loss");
            tokio::time::sleep(Duration::from_millis(expected[0]["loss_ms"].as_u64().unwrap()))
                .await;
            assert_eq!(inspect(native).await.1, expected[0]["pending"].as_u64().unwrap() as usize);
            assert!(native.failed_send_ids.lock().unwrap().is_empty());
            assert!(
                !packets.transfers.lock().unwrap().is_empty(),
                "loss control must observe real packets"
            );
            packets.drop_parts.store(false, Ordering::Release);
        };
        let (result, ()) = tokio::join!(query, loss);
        assert_eq!(result.unwrap().0, Some(vec![42; 64]));
        tokio::time::timeout(Duration::from_secs(5), async {
            while native.waiter_counts() != (0, 0)
                || native.completed_sends.load(Ordering::Acquire) != 1
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("recovered request must complete and retire actual waiters");
        assert_eq!(inspect(native).await.1, 0);
    })
    .catch_unwind()
    .await;
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
async fn native_unacknowledged_response_expires_and_recovers() {
    assert_eq!(
        include_str!("../../../ci/conformance/rldp2_sender_deadline_context.tsv").trim(),
        "10 64 1024 2000 13000"
    );
    let expected = checked_ack_native_effects(
        include_bytes!("../../../ci/conformance/rldp2_sender_deadline_context.tsv"),
        include_bytes!("../../../ci/conformance/rldp2_sender_deadline_effects.jsonl"),
        include_bytes!("../../../ci/conformance/rldp2_sender_deadline_reference.cpp"),
        include_bytes!("../../../ci/conformance/rldp2_sender_deadline_metadata.json"),
    );
    let (_, packets, nodes, rldps, route) = topology(2).await;
    for node in &rldps {
        node.peers.enable_native_for_tests();
    }
    let outcome=std::panic::AssertUnwindSafe(async {
        let responder=rldps[1].get_peer(route.other(),route.local(),true,None).await.unwrap();
        let requester=rldps[0].get_peer(route.local(),route.other(),true,None).await.unwrap();
        let native=responder.native.get().expect("response must use actual native Connection");
        let client=requester.native.get().expect("query must use actual native Connection");
        let quota=rldps[0].query_budget.remaining(&route);
        packets.drop_parts.store(true,Ordering::Release);
        let bytes=serialize_boxed(&Query {overlay:UInt256::default()}).unwrap();
        let request=TaggedByteSlice {object:&bytes,#[cfg(feature="telemetry")]tag:0};
        let started=tokio::time::Instant::now();
        let query=rldps[0].query(&request,Some(1024),&route,true,None);
        let observe=async {
            tokio::time::timeout(Duration::from_secs(5),async {
                while rldps[1].allocated.response_lifecycle.0.load(Ordering::Acquire)!=1 {tokio::time::sleep(Duration::from_millis(5)).await;}
            }).await.expect("response must be accepted before its retention window");
            tokio::time::sleep(Duration::from_millis(2000)).await;
            assert_eq!(packets.transfers.lock().unwrap().len(),1,"actual dropped response must have one transfer ID");
            assert_eq!(inspect(native).await.1,1,"unacknowledged native response must retain the query deadline");
            assert!(native.failed_send_ids.lock().unwrap().is_empty());
            assert_eq!(native.completed_sends.load(Ordering::Acquire),0);
        };
        let (result,())=tokio::join!(query,observe);
        let error=result.unwrap_err();
        assert!(error.downcast_ref::<RldpQueryTimeout>().is_some(),"{error:#}");
        let id: [u8;32]=packets.transfers.lock().unwrap().iter().next().unwrap().as_slice().try_into().unwrap();
        // Native's vector checks expiry at sent+13 seconds. Wait for the
        // actual sender error, not an already-finished application callback.
        tokio::time::timeout_at(started+Duration::from_millis(13000),async {
            loop {
                let failed=native.failed_send_ids.lock().unwrap().clone();
                if failed==vec![id] && inspect(native).await.1==0 {break;}
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }).await.expect("actual response sender must expire within the native vector's window");
        let expiry_ms=started.elapsed().as_millis();
        assert_eq!(native.completed_sends.load(Ordering::Acquire),0);
        assert_eq!(rldps[1].allocated.send_transfers.load(Ordering::Acquire),0);
        assert_eq!(rldps[0].query_budget.remaining(&route),quota);
        tokio::time::timeout(Duration::from_secs(5),async {
            while client.waiter_counts()!=(0,0) {tokio::task::yield_now().await;}
        }).await.expect("expired query must retire its actual waiters");
        packets.drop_parts.store(false,Ordering::Release);
        let (answer,_)=rldps[0].query(&request,Some(1024),&route,true,None).await.unwrap();
        assert_eq!(answer,Some(vec![42;64]));
        tokio::time::timeout(Duration::from_secs(5),async {
            while native.completed_sends.load(Ordering::Acquire)!=1 {tokio::task::yield_now().await;}
        }).await.expect("same peer recovery response must actually finish");
        assert_eq!(inspect(native).await.1,0);
        assert_eq!(*native.failed_send_ids.lock().unwrap(),vec![id],"recovery must not add a failed sender");
        let actual=serde_json::json!({"held_before_deadline":true,"live_after_deadline":0,"recovery":true});
        assert_eq!(vec![actual.clone()],expected);
        eprintln!("NATIVE_RESPONSE_EXPIRY: {actual} expiry_observed_ms={expiry_ms}");
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
