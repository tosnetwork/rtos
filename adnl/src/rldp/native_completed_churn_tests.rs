// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use native_identity_tests::inspect;
use rtos_api::{ton::rldp, IntoBoxed, RldpChunk};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_completed_retention_and_replay_match_native_under_churn() {
    assert_eq!(
        include_str!("../../../ci/conformance/rldp2_completed_churn_context.tsv").trim(),
        "2049"
    );
    let expected = completed_churn_native_effects();
    let (reply, _, nodes, rldps, route) = topology_configured(2, None, false, true).await;
    for node in &rldps {
        node.peers.enable_native_for_tests();
    }
    let outcome = std::panic::AssertUnwindSafe(async {
        let peer = rldps[1].get_peer(route.other(),route.local(),true,None).await.unwrap();
        let native = peer.native.get().expect("actual receiver must use native Connection");
        let message = serialize_boxed(&rldp::message::Message {id:UInt256::default(),data:b"churn".to_vec()}.into_boxed()).unwrap();
        let mut encoder = crate::RaptorqEncoder::with_data(&message,Some(768));
        let mut seqno = 0;
        let symbol = encoder.encode(&mut seqno).unwrap();
        let marker_payload = b"mtu:completed-churn-barrier";
        let marker_hash = hex::encode(rtos_block::sha256_digest(marker_payload));
        let wire = |value:u32| {
            let mut id=[0;32];id[..4].copy_from_slice(&value.to_le_bytes());
            if value==2049 {
                let marker=serialize_boxed(&rldp::message::Message {id:UInt256::default(),data:marker_payload.to_vec()}.into_boxed()).unwrap();
                let mut marker_encoder=crate::RaptorqEncoder::with_data(&marker,Some(768));
                let mut marker_seqno=0;
                let chunk=RldpChunk {transfer_id:id.into(),fec_type:marker_encoder.params().clone().into_boxed(),part:0,total_size:marker.len() as i64,data:marker_encoder.encode(&mut marker_seqno).unwrap(),seqno:marker_seqno as i32};
                return serialize_boxed(&rldp2::messagepart::MessagePart(chunk).into_boxed()).unwrap();
            }
            let chunk=RldpChunk {transfer_id:id.into(),fec_type:encoder.params().clone().into_boxed(),part:0,total_size:message.len() as i64,data:symbol.clone(),seqno:seqno as i32};
            serialize_boxed(&rldp2::messagepart::MessagePart(chunk).into_boxed()).unwrap()
        };
        let feed = |value:u32, delivered:usize| {
            let bytes=wire(value);let nodes=&nodes;let reply=&reply;let route=&route;let marker_hash=&marker_hash;
            async move {
                nodes[0].send_custom(&TaggedByteSlice {object:&bytes,#[cfg(feature="telemetry")]tag:0},route).await.unwrap();
                tokio::time::timeout(Duration::from_secs(5),async {
                    loop {
                        let delivered_now = if value==2049 {
                            reply.message_hash.lock().unwrap().as_ref()==Some(marker_hash)
                        } else {reply.messages.load(Ordering::Acquire)>=delivered};
                        if delivered_now { break; }
                        tokio::select! {
                            _=reply.message_received.notified()=>{},
                            _=tokio::time::sleep(Duration::from_millis(50))=>{
                                nodes[0].send_custom(&TaggedByteSlice {object:&bytes,#[cfg(feature="telemetry")]tag:0},route).await.unwrap();
                            }
                        }
                    }
                }).await.expect("unique native message must reach actual subscriber");
                assert_eq!(reply.messages.load(Ordering::Acquire),delivered,"retransmission must not duplicate delivery");
            }
        };
        let started = tokio::time::Instant::now();
        for value in 0..2049 { feed(value,value as usize+1).await; }
        assert!(started.elapsed()<Duration::from_secs(10),"must observe capacity before20s cache expiry");
        let unique_delivered=reply.messages.load(Ordering::Acquire);
        let (inbound,outbound,remembered)=inspect(native).await;
        assert_eq!((inbound,outbound,remembered),(0,0,2048));
        let old_completed_empty=peer.completed.lock().unwrap().is_empty();
        assert!(old_completed_empty,"old completed wrapper must remain unused");
        assert_eq!(rldps[1].allocated.recv_transfers.load(Ordering::Acquire),0);
        feed(0,2050).await;
        let oldest_replayed=reply.messages.load(Ordering::Acquire)==2050;
        let reverse=AdnlPeers::with_keys(route.other().clone(),route.local().clone());
        // The remembered replay enters the normal authenticated handler. A
        // subsequent fresh UDP marker passes through the FIFO event router,
        // proving any erroneous replay delivery has also reached that router.
        assert!(rldps[1].try_consume_custom(&wire(2048),&reverse).await.unwrap());
        feed(2049,2051).await;
        let routed=native.routed_receives.load(Ordering::Acquire);
        assert_eq!(routed,2051,"remembered replay must not emit a receive event");
        assert!(started.elapsed()<Duration::from_secs(10),"all replay checks must precede cache expiry");
        assert_eq!(inspect(native).await,(0,0,2048));
        let budget=super::super::rldp2::budget::InboundBudget::process_default();
        let usage=budget.identity_usage(route.local().data());
        assert_eq!(usage.decoders,0);
        assert_eq!(usage.bytes,0,"completed cache must not retain decoded payload reservations");
        let actual=serde_json::json!({"unique_delivered":unique_delivered,"remembered":remembered,"oldest_replayed":oldest_replayed,"recent_suppressed":routed==2051,"delivered":routed-1});
        assert_eq!(actual,expected);
        eprintln!("NATIVE_COMPLETED_CHURN: {actual} marker=1 elapsed_ms={}",started.elapsed().as_millis());
    }).catch_unwind().await;
    let stopped = futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
    for result in stopped {
        result.unwrap();
    }
    // Stop joins all entered application callbacks. Exclude the one explicit
    // ordering marker from the frozen vector's application delivery count.
    assert_eq!(reply.messages.load(Ordering::Acquire) - 1, 2050);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_query_churn_bounds_completed_cache_and_retires_sender_ids() {
    assert_eq!(
        include_str!("../../../ci/conformance/rldp2_outbound_retirement_context.tsv").trim(),
        "2049\t64\t60"
    );
    let expected = outbound_retirement_native_effects();
    let (reply, _, nodes, rldps, route) = topology_configured(2, None, false, true).await;
    for node in &rldps {
        node.peers.enable_native_for_tests();
    }
    let outcome=std::panic::AssertUnwindSafe(async {
        let peers=[
            rldps[0].get_peer(route.local(),route.other(),true,None).await.unwrap(),
            rldps[1].get_peer(route.other(),route.local(),true,None).await.unwrap(),
        ];
        let natives=peers.iter().map(|p|p.native.get().expect("both actual query endpoints must use native Connection")).collect::<Vec<_>>();
        let quota=rldps[0].query_budget.remaining(&route);
        let bytes=serialize_boxed(&Query {overlay:UInt256::default()}).unwrap();
        let request=TaggedByteSlice {object:&bytes,#[cfg(feature="telemetry")]tag:0};
        let started=tokio::time::Instant::now();
        for index in 0..2049 {
            let (answer,_)=rldps[0].query(&request,Some(1024),&route,true,None).await.unwrap_or_else(|error|panic!("native query {index} failed: {error}"));
            assert_eq!(answer,Some(vec![42;64]));
            if [0,127,128,2047,2048].contains(&index) {
                for native in &natives {assert_eq!(inspect(native).await.2,(index+1).min(2048));}
            }
        }
        assert!(started.elapsed()<Duration::from_secs(10),"cache bound must be observed before TTL pruning");
        assert_eq!(reply.calls.load(Ordering::Acquire),2049);
        let submissions=natives[0].query_send_results.lock().unwrap().clone();
        assert_eq!(submissions.len(),2049);
        assert!(submissions.iter().all(|(_,accepted)|*accepted));
        let requests=submissions.iter().map(|(id,_)|*id).collect::<std::collections::BTreeSet<_>>();
        let responses=requests.iter().map(|id|id.map(|b|b^0xff)).collect::<std::collections::BTreeSet<_>>();
        assert_eq!(requests.len(),2049);
        assert!(requests.is_disjoint(&responses));
        for (side,native) in natives.iter().enumerate() {
            // Answer delivery precedes final ACK and waiter cleanup. Observe
            // the actual send completions and waiters, not just API returns.
            tokio::time::timeout(Duration::from_secs(5),async {
                while native.completed_sends.load(Ordering::Acquire)!=2049 || native.waiter_counts()!=(0,0)
                    || native.retired_registrations.load(Ordering::Acquire)!=if side==0 {2049} else {0} {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }).await.unwrap_or_else(|error|panic!("{error}: side={side} sent={} retired={} waiters={:?}",native.completed_sends.load(Ordering::Acquire),native.retired_registrations.load(Ordering::Acquire),native.waiter_counts()));
            let (_,outbound,completed)=inspect(native).await;
            assert_eq!((outbound,completed),(0,2048));
            let sent=native.completed_send_ids.lock().unwrap().clone();
            let sent_ids=sent.iter().copied().collect::<std::collections::BTreeSet<_>>();
            let (expected_sent,expected_received)=if side==0 {(&requests,&responses)} else {(&responses,&requests)};
            assert_eq!(&sent_ids,expected_sent);
            assert_eq!(sent.len(),2049,"each actual sender completes exactly once");
            let (done,receipt)=tokio::sync::oneshot::channel();
            native.driver.submit(super::super::connection_driver::Command::InspectCompleted(done)).await.unwrap();
            let remembered=receipt.await.unwrap().into_iter().collect::<std::collections::BTreeSet<_>>();
            assert_eq!(remembered.len(),2048);
            assert!(remembered.is_subset(expected_received),"completed cache must contain received IDs only");
            let sender_ids_in_receive_cache=remembered.intersection(expected_sent).count();
            // Native's one-way vector has no received data on the sender.
            // Real queries have incoming answers/requests: report that cache
            // separately instead of calling its actual 2048 entries zero.
            assert_eq!(sent.len(),expected["completed"].as_u64().unwrap() as usize);
            assert_eq!(outbound,expected["outbound_retained"].as_u64().unwrap() as usize);
            assert_eq!(sender_ids_in_receive_cache,0,"sender IDs must not enter the receive cache");
            let actual=serde_json::json!({"completed":sent.len(),"outbound_retained":outbound,"sender_ids_in_receive_cache":sender_ids_in_receive_cache,"completed_inbound":completed});
            assert_eq!(rldps[side].allocated.send_transfers.load(Ordering::Acquire),0);
            assert_eq!(rldps[side].allocated.recv_transfers.load(Ordering::Acquire),0);
            eprintln!("NATIVE_QUERY_RETIREMENT side={side}: {actual} actual_inbound_cache={completed}");
        }
        assert_eq!(rldps[0].query_budget.remaining(&route),quota);
        eprintln!("NATIVE_QUERY_CHURN elapsed_ms={}",started.elapsed().as_millis());
    }).catch_unwind().await;
    let stopped = futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
    for result in stopped {
        result.unwrap();
    }
}
