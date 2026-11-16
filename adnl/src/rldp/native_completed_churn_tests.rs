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
            let (answer,_)=match rldps[0].query(&request,Some(1024),&route,true,None).await {
                Ok(answer)=>answer,
                Err(error)=>{
                    eprintln!("NATIVE_QUERY_FAILURE index={index} elapsed_ms={} calls={} response_started={} response_handlers={}",started.elapsed().as_millis(),reply.calls.load(Ordering::Acquire),rldps[1].allocated.response_lifecycle.0.load(Ordering::Acquire),rldps[1].allocated.response_lifecycle.1.load(Ordering::Acquire));
                    for (side,native) in natives.iter().enumerate() {
                        let state=tokio::time::timeout(Duration::from_secs(5),inspect(native)).await;
                        let submissions=native.query_send_results.lock().unwrap().clone();
                        eprintln!("NATIVE_QUERY_FAILURE side={side} state={state:?} completed={} failed={} waiters={:?} retired={} submitted={} refused={} last={:?}",native.completed_sends.load(Ordering::Acquire),native.failed_send_ids.lock().unwrap().len(),native.waiter_counts(),native.retired_registrations.load(Ordering::Acquire),submissions.len(),submissions.iter().filter(|(_,ok)|!*ok).count(),submissions.last());
                    }
                    panic!("native query {index} failed: {error}");
                }
            };
            assert_eq!(answer,Some(vec![42;64]));
            // The native retirement vector waits for on_sent and outbound=0
            // before its next transfer. API answer delivery is earlier than
            // request ACK/registration retirement; pacing by answers alone
            // can fill the legitimate 256 outbound slots on a slower runner.
            for (side,native) in natives.iter().enumerate() {
                tokio::time::timeout(Duration::from_secs(5),async {
                    while native.completed_sends.load(Ordering::Acquire)!=index as u64+1
                        || (side==0 && native.retired_registrations.load(Ordering::Acquire)!=index as u64+1) {
                        tokio::task::yield_now().await;
                    }
                }).await.expect("each iteration must retire actual senders before the next native-vector transfer");
                assert_eq!(inspect(native).await.1,0);
            }
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_query_replay_after_cache_eviction_preserves_active_response() {
    assert_eq!(
        include_str!("../../../ci/conformance/rldp2_query_replay_retention_context.tsv").trim(),
        "2048 64 65 60"
    );
    let expected = checked_ack_native_effects(
        include_bytes!("../../../ci/conformance/rldp2_query_replay_retention_context.tsv"),
        include_bytes!("../../../ci/conformance/rldp2_query_replay_retention_effects.jsonl"),
        include_bytes!("../../../ci/conformance/rldp2_query_replay_retention_reference.cpp"),
        include_bytes!("../../../ci/conformance/rldp2_query_replay_retention_metadata.json"),
    );
    fn wire(data: &[u8], id: [u8; 32]) -> Vec<u8> {
        let mut encoder = crate::RaptorqEncoder::with_data(data, Some(768));
        let mut seqno = 0;
        let chunk = RldpChunk {
            transfer_id: id.into(),
            fec_type: encoder.params().clone().into_boxed(),
            part: 0,
            total_size: data.len() as i64,
            data: encoder.encode(&mut seqno).unwrap(),
            seqno: seqno as i32,
        };
        serialize_boxed(&rldp2::messagepart::MessagePart(chunk).into_boxed()).unwrap()
    }
    let (reply, packets, nodes, rldps, route) = topology(2).await;
    for node in &rldps {
        node.peers.enable_native_for_tests();
    }
    let outcome = std::panic::AssertUnwindSafe(async {
        packets.drop_parts.store(true, Ordering::Release);
        let peer = rldps[1]
            .get_peer(route.other(), route.local(), true, None)
            .await
            .unwrap();
        let native = peer
            .native
            .get()
            .expect("replayed query responder must use native Connection");
        let receiver_peer = rldps[0]
            .get_peer(route.local(), route.other(), true, None)
            .await
            .unwrap();
        let receiver = receiver_peer
            .native
            .get()
            .expect("answer receiver must use native Connection");
        let (probe, decoded) = tokio::sync::oneshot::channel();
        *receiver.receive_hash_probe.lock().unwrap() = Some(probe);
        let request = serialize_boxed(
            &rldp::message::Query {
                query_id: [9; 32].into(),
                max_answer_size: 1024,
                timeout: super::super::Version::get() + 60,
                data: serialize_boxed(&Query {
                    overlay: UInt256::default(),
                })
                .unwrap(),
            }
            .into_boxed(),
        )
        .unwrap();
        let request_wire = wire(&request, [248; 32]);
        let started = tokio::time::Instant::now();
        let send = |data: Vec<u8>| {
            let nodes = &nodes;
            let route = &route;
            async move {
                nodes[0]
                    .send_custom(
                        &TaggedByteSlice {
                            object: &data,
                            #[cfg(feature = "telemetry")]
                            tag: 0,
                        },
                        route,
                    )
                    .await
                    .unwrap();
            }
        };
        send(request_wire.clone()).await;
        tokio::time::timeout(Duration::from_secs(5), async {
            while rldps[1]
                .allocated
                .response_lifecycle
                .0
                .load(Ordering::Acquire)
                != 1
                || !packets
                    .transfers
                    .lock()
                    .unwrap()
                    .contains([7u8; 32].as_slice())
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("original query must produce a real unacknowledged response");
        let (done, receipt) = tokio::sync::oneshot::channel();
        native
            .driver
            .submit(super::super::connection_driver::Command::InspectOutboundStarted(done))
            .await
            .unwrap();
        let before = receipt.await.unwrap();
        let message = serialize_boxed(
            &rldp::message::Message {
                id: UInt256::default(),
                data: b"churn".to_vec(),
            }
            .into_boxed(),
        )
        .unwrap();
        for index in 0u32..2048 {
            let mut id = [0; 32];
            id[..4].copy_from_slice(&index.to_le_bytes());
            let bytes = wire(&message, id);
            send(bytes.clone()).await;
            tokio::time::timeout(Duration::from_secs(5), async {
                while reply.messages.load(Ordering::Acquire) != index as usize + 1 {
                    tokio::select! {
                        _=reply.message_received.notified()=>{},
                        _=tokio::time::sleep(Duration::from_millis(50))=>send(bytes.clone()).await,
                    }
                }
            })
            .await
            .expect("churn must reach the real application before the next message");
        }
        let (done, receipt) = tokio::sync::oneshot::channel();
        native
            .driver
            .submit(super::super::connection_driver::Command::InspectCompleted(
                done,
            ))
            .await
            .unwrap();
        let remembered = receipt.await.unwrap();
        assert_eq!(remembered.len(), 2048);
        assert!(
            !remembered.contains(&[248; 32]),
            "capacity churn must evict the query receive ID"
        );
        assert_eq!(inspect(native).await.1, 1);
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "query replay must be caused by capacity, not20s TTL expiry"
        );
        reply.response_bytes.store(65, Ordering::Release);
        send(request_wire).await;
        tokio::time::timeout(Duration::from_secs(5), async {
            while reply.calls.load(Ordering::Acquire) != 2
                || rldps[1]
                    .allocated
                    .response_lifecycle
                    .1
                    .load(Ordering::Acquire)
                    != 2050
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("replayed application must finish its real response admission");
        assert!(started.elapsed() < Duration::from_secs(10));
        let (done, receipt) = tokio::sync::oneshot::channel();
        native
            .driver
            .submit(super::super::connection_driver::Command::InspectOutboundStarted(done))
            .await
            .unwrap();
        let after = receipt.await.unwrap();
        assert_eq!(
            after, 1,
            "replayed query must not replace its active response"
        );
        assert_eq!(
            rldps[1]
                .allocated
                .response_lifecycle
                .0
                .load(Ordering::Acquire),
            1
        );
        assert_eq!(inspect(native).await.1, 1);
        assert_eq!(native.completed_sends.load(Ordering::Acquire), 0);
        packets.drop_parts.store(false, Ordering::Release);
        let original = serialize_boxed(
            &rldp::message::Answer {
                query_id: [9; 32].into(),
                data: vec![42; 64],
            }
            .into_boxed(),
        )
        .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), decoded)
                .await
                .unwrap()
                .unwrap(),
            ([7; 32], rtos_block::sha256_digest(original))
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            while native.completed_sends.load(Ordering::Acquire) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("original response must complete after its real ACK");
        let retained = inspect(native).await.1;
        let actual = serde_json::json!({"messages":reply.messages.load(Ordering::Acquire),"queries":reply.calls.load(Ordering::Acquire),"started_before":before,"started_after_replay":after,"retained_after_ack":retained});
        assert_eq!(vec![actual.clone()], expected);
        eprintln!(
            "NATIVE_QUERY_REPLAY_RETENTION: {actual} elapsed_ms={}",
            started.elapsed().as_millis()
        );
        (native.clone(), receiver.clone())
    })
    .catch_unwind()
    .await;
    packets.drop_parts.store(false, Ordering::Release);
    let stopped = futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await;
    let (native, receiver) = match outcome {
        Ok(owners) => owners,
        Err(panic) => std::panic::resume_unwind(panic),
    };
    for result in stopped {
        result.unwrap();
    }
    assert_eq!(reply.messages.load(Ordering::Acquire), 2048);
    assert_eq!(reply.calls.load(Ordering::Acquire), 2);
    assert_eq!(native.completed_send_ids.lock().unwrap().as_slice(), &[[7; 32]]);
    assert_eq!(receiver.routed_receives.load(Ordering::Acquire), 1);
}
