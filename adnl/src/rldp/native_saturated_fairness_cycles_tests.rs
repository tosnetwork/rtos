// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_saturated_peer_preserves_repeated_healthy_progress_and_recovery() {
    use super::super::super::connection_driver::Command;
    assert_eq!(
        include_str!("../../../ci/conformance/rldp2_saturated_fairness_cycles_context.tsv").trim(),
        "4 256 32 64 60 10 1024"
    );
    let expected = checked_ack_native_effects(
        include_bytes!("../../../ci/conformance/rldp2_saturated_fairness_cycles_context.tsv"),
        include_bytes!("../../../ci/conformance/rldp2_saturated_fairness_cycles_effects.jsonl"),
        include_bytes!("../../../ci/conformance/rldp2_saturated_fairness_cycles_reference.cpp"),
        include_bytes!("../../../ci/conformance/rldp2_saturated_fairness_cycles_metadata.json"),
    );
    let (reply, packets, nodes, rldps, route) = topology_configured(3, None, false, true).await;
    for node in &rldps {
        node.peers.enable_native_for_tests();
    }
    let outcome = std::panic::AssertUnwindSafe(async {
        let silent_peer = rldps[1].get_peer(route.other(),route.local(),true,None).await.unwrap();
        let silent = silent_peer.native.get().unwrap();
        let silent_receiver_peer = rldps[0].get_peer(route.local(),route.other(),true,None).await.unwrap();
        let silent_receiver = silent_receiver_peer.native.get().unwrap();
        let healthy_key=nodes[2].key_by_tag(0).unwrap();
        let healthy_route=AdnlPeers::with_keys(healthy_key.id().clone(),route.other().clone());
        let healthy_peer=rldps[1].get_peer(route.other(),healthy_key.id(),true,None).await.unwrap();
        let healthy=healthy_peer.native.get().unwrap();
        let client_peer=rldps[2].get_peer(healthy_key.id(),route.other(),true,None).await.unwrap();
        let client=client_peer.native.get().unwrap();
        let query=serialize_boxed(&Query {overlay:UInt256::default()}).unwrap();
        let mut all_ids=std::collections::BTreeSet::new();
        let mut actual=Vec::new();
        let started=tokio::time::Instant::now();
        let mut healthy_count=0u64;
        let mut max_healthy_window_ms=0;
        for round in 0u32..4 {
            packets.drop_parts.store(true,Ordering::Release);
            let mut current_ids=std::collections::BTreeSet::new();
            for n in 0u32..256 {
                let index=round*256+n;
                feed(&nodes[0],&rldps[1],&route,index,u64::from(round*288+n+1)).await;
                let mut id=[120u8;32];id[..4].copy_from_slice(&index.to_le_bytes());
                let id=id.map(|b|b^0xff);
                assert!(all_ids.insert(id));assert!(current_ids.insert(id));
            }
            tokio::time::timeout(Duration::from_secs(10),async {
                while !current_ids.iter().all(|id|packets.transfers.lock().unwrap().contains(id.as_slice())) {tokio::time::sleep(Duration::from_millis(5)).await;}
            }).await.expect("every saturated response must reach actual UDP");
            assert_eq!(inspect(silent).await.1,256);
            let (done,receipt)=tokio::sync::oneshot::channel();
            silent.driver.submit(Command::InspectEncoders(done)).await.unwrap();
            let initial=receipt.await.unwrap();
            assert_eq!(initial.iter().map(|(id,_,_)|*id).collect::<std::collections::BTreeSet<_>>(),current_ids);
            assert!(initial.iter().all(|(_,bytes,parts)|*bytes==104 && *parts==1));
            let saturated_at=tokio::time::Instant::now();
            for _ in 0..32 {
                let (answer,_)=rldps[2].query(&TaggedByteSlice {object:&query,#[cfg(feature="telemetry")]tag:0},Some(1024),&healthy_route,true,None).await.unwrap();
                assert_eq!(answer,Some(vec![42;64]));
                healthy_count+=1;
                tokio::time::timeout(Duration::from_secs(5),async {
                    while healthy.completed_sends.load(Ordering::Acquire)!=healthy_count
                        || client.completed_sends.load(Ordering::Acquire)!=healthy_count
                        || client.waiter_counts()!=(0,0) {tokio::time::sleep(Duration::from_millis(5)).await;}
                }).await.expect("both healthy request and answer must ACK and retire before the next query");
                assert_eq!(inspect(healthy).await.1,0);
                assert_eq!(inspect(client).await.1,0);
                assert_eq!(silent.completed_sends.load(Ordering::Acquire),u64::from(round*256));
                let (done,receipt)=tokio::sync::oneshot::channel();
                silent.driver.submit(Command::InspectEncoders(done)).await.unwrap();
                assert_eq!(receipt.await.unwrap(),initial,"healthy progress must preserve every original saturated response and encoder");
            }
            let healthy_window_ms=saturated_at.elapsed().as_millis();
            max_healthy_window_ms=max_healthy_window_ms.max(healthy_window_ms);
            assert!(healthy_window_ms<10_000,"healthy batch must finish before the vector observation window");
            packets.drop_parts.store(false,Ordering::Release);
            tokio::time::timeout(Duration::from_secs(10),async {
                while silent.completed_sends.load(Ordering::Acquire)!=u64::from((round+1)*256)
                    || silent_receiver.routed_receives.load(Ordering::Acquire)!=u64::from((round+1)*256) {tokio::time::sleep(Duration::from_millis(5)).await;}
            }).await.expect("previously silent connection must really ACK all retained responses");
            assert_eq!(silent.completed_send_ids.lock().unwrap().iter().copied().collect::<std::collections::BTreeSet<_>>(),all_ids);
            assert_eq!(silent.completed_send_ids.lock().unwrap().len(),all_ids.len());
            assert_eq!(inspect(silent).await.1,0);
            let (done,receipt)=tokio::sync::oneshot::channel();
            silent.driver.submit(Command::InspectEncoders(done)).await.unwrap();
            assert!(receipt.await.unwrap().is_empty());
            assert!(silent.failed_send_ids.lock().unwrap().is_empty());
            assert!(healthy.failed_send_ids.lock().unwrap().is_empty());
            let mut total_started=0;
            for native in [silent,healthy] {
                let (done,receipt)=tokio::sync::oneshot::channel();
                native.driver.submit(Command::InspectOutboundStarted(done)).await.unwrap();
                total_started+=receipt.await.unwrap();
            }
            let row=serde_json::json!({"round":round+1,"silent_peak":256,"healthy_completed":healthy_count,"silent_completed":silent.completed_sends.load(Ordering::Acquire),"started":total_started,"retained":0});
            assert_eq!(row,expected[round as usize]);actual.push(row);
        }
        assert_eq!(actual,expected);
        assert_eq!(rldps[1].allocated.send_transfers.load(Ordering::Acquire),0);
        eprintln!("NATIVE_SATURATED_FAIRNESS_CYCLES rounds=4 silent=1024 healthy=128 elapsed_ms={} max_healthy_window_ms={max_healthy_window_ms}",started.elapsed().as_millis());
        (silent.clone(),healthy.clone(),silent_receiver.clone(),client.clone(),all_ids)
    }).catch_unwind().await;
    packets.drop_parts.store(false, Ordering::Release);
    let stopped = futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await;
    let (silent, healthy, silent_receiver, client, ids) = match outcome {
        Ok(value) => value,
        Err(panic) => std::panic::resume_unwind(panic),
    };
    for result in stopped {
        result.unwrap();
    }
    assert_eq!(reply.calls.load(Ordering::Acquire), 1152);
    assert_eq!(silent.completed_send_ids.lock().unwrap().len(), 1024);
    assert_eq!(
        silent
            .completed_send_ids
            .lock()
            .unwrap()
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>(),
        ids
    );
    assert_eq!(healthy.completed_sends.load(Ordering::Acquire), 128);
    assert_eq!(client.completed_sends.load(Ordering::Acquire), 128);
    assert_eq!(silent_receiver.routed_receives.load(Ordering::Acquire), 1024);
}
