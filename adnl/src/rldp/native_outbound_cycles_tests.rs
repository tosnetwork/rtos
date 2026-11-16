// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use native_identity_tests::inspect;
use rtos_api::{ton::rldp, IntoBoxed};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_outbound_saturation_and_ack_retirement_cycles_match_native() {
    use super::super::connection_driver::Command;
    assert_eq!(
        include_str!("../../../ci/conformance/rldp2_outbound_cycles_context.tsv").trim(),
        "32 256 64 60"
    );
    let expected = checked_ack_native_effects(
        include_bytes!("../../../ci/conformance/rldp2_outbound_cycles_context.tsv"),
        include_bytes!("../../../ci/conformance/rldp2_outbound_cycles_effects.jsonl"),
        include_bytes!("../../../ci/conformance/rldp2_outbound_cycles_reference.cpp"),
        include_bytes!("../../../ci/conformance/rldp2_outbound_cycles_metadata.json"),
    );
    // OS-selected ports and independent keys keep the fixture's ownership local.
    let (reply, packets, nodes, rldps, route) = topology_configured(2, None, false, true).await;
    for node in &rldps {
        node.peers.enable_native_for_tests();
    }
    let outcome = std::panic::AssertUnwindSafe(async {
        let sender_peer = rldps[1].get_peer(route.other(), route.local(), true, None).await.unwrap();
        let receiver_peer = rldps[0].get_peer(route.local(), route.other(), true, None).await.unwrap();
        let sender = sender_peer.native.get().unwrap();
        let receiver = receiver_peer.native.get().unwrap();
        let body = [b"mtu:".as_slice(), &[42; 23]].concat();
        let data = serialize_boxed(&rldp::message::Message { id: UInt256::default(), data: body.clone() }.into_boxed()).unwrap();
        assert_eq!(data.len(), 64);
        let mut accepted = std::collections::BTreeSet::new();
        let mut actual = Vec::new();
        let started = tokio::time::Instant::now();
        for round in 0u32..32 {
            packets.drop_parts.store(true, Ordering::Release);
            for n in 0u32..=256 {
                let serial = round * 257 + n + 1;
                let mut id = [7;32];
                id[..4].copy_from_slice(&serial.to_le_bytes());
                let admitted = sender.driver.submit(Command::Send {
                    id, data:data.clone(), deadline:Some(std::time::Instant::now()+Duration::from_secs(60)), answer:false,
                }).await.unwrap();
                assert_eq!(admitted, n < 256, "round {round}, slot {n}: exact capacity must recover after ACKs");
                if admitted { assert!(accepted.insert(id)); }
            }
            assert_eq!(inspect(sender).await.1,256);
            let (done, receipt) = tokio::sync::oneshot::channel();
            sender.driver.submit(Command::InspectOutboundStarted(done)).await.unwrap();
            assert_eq!(receipt.await.unwrap(),u64::from((round+1)*256));
            tokio::time::timeout(Duration::from_secs(10),async {
                while packets.transfers.lock().unwrap().len()!=accepted.len() {tokio::time::sleep(Duration::from_millis(5)).await;}
            }).await.expect("all accepted transfers must reach actual UDP before release");
            let (done, receipt) = tokio::sync::oneshot::channel();
            sender.driver.submit(Command::InspectEncoders(done)).await.unwrap();
            let retained = receipt.await.unwrap();
            assert_eq!(retained.len(),256);
            assert!(retained.iter().all(|(id,bytes,parts)|accepted.contains(id) && *bytes==64 && *parts==1));
            packets.drop_parts.store(false,Ordering::Release);
            tokio::time::timeout(Duration::from_secs(10),async {
                while sender.completed_sends.load(Ordering::Acquire)!=accepted.len() as u64
                    || reply.messages.load(Ordering::Acquire)!=accepted.len()
                    || rldps[0].allocated.response_lifecycle.1.load(Ordering::Acquire)!=accepted.len() as u64 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }).await.expect("real decode, application delivery, ACK and handler retirement must finish each cycle");
            let completed:std::collections::BTreeSet<_>=sender.completed_send_ids.lock().unwrap().iter().copied().collect();
            assert_eq!(completed,accepted);
            assert_eq!(sender.completed_send_ids.lock().unwrap().len(),accepted.len());
            assert_eq!(receiver.routed_receives.load(Ordering::Acquire),accepted.len() as u64);
            let state=inspect(sender).await;
            assert_eq!((state.0,state.1),(0,0));
            assert_eq!(inspect(receiver).await.0,0);
            assert!(inspect(receiver).await.2<=2048);
            let (done,receipt)=tokio::sync::oneshot::channel();
            sender.driver.submit(Command::InspectEncoders(done)).await.unwrap();
            assert!(receipt.await.unwrap().is_empty(),"ACK must retire real encoders before refill");
            assert!(sender.failed_send_ids.lock().unwrap().is_empty());
            assert_eq!(sender.waiter_counts(),(0,0));
            assert_eq!(*reply.message_hash.lock().unwrap(),Some(hex::encode(rtos_block::sha256_digest(&body))));
            let row=serde_json::json!({"round":round+1,"submitted":257,"peak":256,"completed":completed.len(),"delivered":reply.messages.load(Ordering::Acquire),"retained":state.1});
            assert_eq!(row,expected[round as usize]);
            actual.push(row);
        }
        assert_eq!(actual,expected);
        assert_eq!(rldps[1].allocated.send_transfers.load(Ordering::Acquire),0,"legacy senders must not supply this qualification");
        eprintln!("NATIVE_OUTBOUND_CYCLES rounds=32 completed={} elapsed_ms={}",accepted.len(),started.elapsed().as_millis());
        (sender.clone(),receiver.clone(),accepted)
    }).catch_unwind().await;
    packets.drop_parts.store(false, Ordering::Release);
    let stopped = futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await;
    let (sender, receiver, accepted) = match outcome {
        Ok(value) => value,
        Err(panic) => std::panic::resume_unwind(panic),
    };
    for result in stopped {
        result.unwrap();
    }
    assert_eq!(reply.messages.load(Ordering::Acquire), 8192);
    assert_eq!(receiver.routed_receives.load(Ordering::Acquire), 8192);
    assert_eq!(sender.completed_send_ids.lock().unwrap().len(), 8192);
    assert_eq!(
        sender
            .completed_send_ids
            .lock()
            .unwrap()
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>(),
        accepted
    );
}
