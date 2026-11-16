// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

async fn inspect(
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
