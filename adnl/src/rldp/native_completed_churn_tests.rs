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
