// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::{native_identity_tests::inspect, *};

#[test]
fn native_byte_limits_and_solver_recovery() {
    const CHILD: &str = "RTOS_BYTE_BUDGET_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = crate::test_process::output(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "rldp::lifetime_tests::native_byte_budget_tests::native_byte_limits_and_solver_recovery", "--nocapture"])
            .env(CHILD, "1")).unwrap();
        print!("{}", String::from_utf8_lossy(&output.stdout));
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
        assert!(
            output.status.success(),
            "isolated byte-budget qualification failed: {}",
            output.status
        );
        return;
    }
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
        .block_on(check_byte_budget());
}

async fn check_byte_budget() {
    use rtos_api::{ton::rldp, IntoBoxed, RldpChunk};
    let expected = checked_ack_native_effects(
        include_bytes!("../../../ci/conformance/rldp2_byte_budget_runtime_context.tsv"),
        include_bytes!("../../../ci/conformance/rldp2_byte_budget_runtime_effects.jsonl"),
        include_bytes!("../../../ci/conformance/rldp2_byte_budget_runtime_reference.cpp"),
        include_bytes!("../../../ci/conformance/rldp2_byte_budget_runtime_metadata.json"),
    );
    let (reply, _, nodes, rldps, _) = topology_configured(6, None, false, true).await;
    for node in &rldps {
        node.peers.enable_native_for_tests();
    }
    let budget = super::super::rldp2::budget::InboundBudget::process_default();
    assert_eq!(budget.usage(), super::super::rldp2::budget::Usage::default());
    let outcome = std::panic::AssertUnwindSafe(async {
        let target = nodes[0].key_by_tag(0).unwrap();
        for sender in 1..=5 {
            let source = nodes[sender].key_by_tag(0).unwrap();
            nodes[sender].add_peer(source.id(),nodes[0].ip_address_adnl(),None,&target).unwrap();
            nodes[0].add_peer(target.id(),nodes[sender].ip_address_adnl(),None,&source).unwrap();
            rldps[0].change_inbound_cap_for_peers(&[source.id().clone()],1).unwrap();
        }
        let mut payload=vec![42;1048576-40]; payload[..4].copy_from_slice(b"mtu:");
        let message=serialize_boxed(&rldp::message::Message {id:UInt256::default(),data:payload.clone()}.into_boxed()).unwrap();
        assert_eq!(message.len(),1048576);
        let mut large=crate::RaptorqEncoder::with_data(&message,Some(768));
        let large_fec=large.params().clone().into_boxed();
        let symbols=1048576u32.div_ceil(768);
        let large_symbols:Vec<_>=(0..=symbols).map(|seq| {let mut n=seq;large.encode(&mut n).unwrap()}).collect();
        let mut small=crate::RaptorqEncoder::with_data(&vec![42;2048],Some(768));
        let small_fec=small.params().clone().into_boxed();
        let small_symbol=small.encode(&mut 0).unwrap();
        let feed=|sender:usize,n:u16,seq:u32,solicited:bool,little:bool| {
            let nodes=&nodes;let rldps=&rldps;let large_symbols=&large_symbols;let large_fec=&large_fec;let small_fec=&small_fec;let small_symbol=&small_symbol;
            async move {
                let source=nodes[sender].key_by_tag(0).unwrap();let target=nodes[0].key_by_tag(0).unwrap();
                let peer=rldps[0].get_peer(target.id(),source.id(),true,None).await.unwrap();
                let native=peer.native.get().expect("actual peer must use native Connection");
                let mut id=[0;32];id[..2].copy_from_slice(&n.to_le_bytes());
                let size=if little {2048}else{1048576};
                if solicited {assert!(native.driver.submit(super::super::connection_driver::Command::ReceiveLimit {
                    id,deadline:std::time::Instant::now()+Duration::from_secs(60),max_size:size,
                }).await.unwrap());}
                let key=(id,0,seq as i32);
                let before=native.data_receipts.lock().unwrap().get(&key).copied().unwrap_or_default();
                let chunk=RldpChunk {transfer_id:id.into(),fec_type:if little {small_fec.clone()}else{large_fec.clone()},part:0,total_size:size as i64,seqno:seq as i32,data:if little {small_symbol.clone()}else{large_symbols[seq as usize].clone()}};
                let wire=serialize_boxed(&rldp2::messagepart::MessagePart(chunk).into_boxed()).unwrap();
                let route=AdnlPeers::with_keys(source.id().clone(),target.id().clone());
                nodes[sender].send_custom(&TaggedByteSlice {object:&wire,#[cfg(feature="telemetry")]tag:0},&route).await.unwrap();
                tokio::time::timeout(Duration::from_secs(2),async {
                    loop {
                        if native.data_receipts.lock().unwrap().get(&key).copied().unwrap_or_default()>before {break;}
                        tokio::select! {
                            _=native.data_processed.notified()=>{},
                            _=tokio::time::sleep(Duration::from_millis(50))=>{
                                nodes[sender].send_custom(&TaggedByteSlice {object:&wire,#[cfg(feature="telemetry")]tag:0},&route).await.unwrap();
                            }
                        }
                    }
                }).await.expect("the exact data symbol must finish actual Connection processing");
                inspect(native).await
            }
        };
        let fill=|sender,solicited| {
            let feed=&feed;
            async move {
                for n in 0..256u16 {
                    let count=feed(sender,n,0,solicited,false).await.0;
                    if count==usize::from(n) {return count;}
                    assert_eq!(count,usize::from(n)+1);
                }
                panic!("byte budget must refuse before the decoder-count cap");
            }
        };
        tokio::time::timeout(Duration::from_secs(8),async {
            let a=fill(1,false).await;assert_eq!(a,36,"identity admission must retain solver headroom");
            let b=fill(2,false).await;assert_eq!(b,36);
            let c=fill(3,false).await;assert_eq!(c,2,"unsolicited byte pool must preserve the reserve");
            let d=fill(4,true).await;assert_eq!(d,77,"solicited receives must obey the total byte bound");
            let full_bytes=budget.usage().bytes;
            for n in 0..30 {assert_eq!(feed(5,n,0,true,true).await.0,usize::from(n)+1);}
            let pressure_bytes=budget.usage().bytes;
            for seq in 1..symbols {feed(1,0,seq,false,false).await;}
            let peer=rldps[0].get_peer(target.id(),nodes[1].key_by_tag(0).unwrap().id(),true,None).await.unwrap();
            let blocked=inspect(peer.native.get().unwrap()).await;
            assert_eq!((blocked.0,blocked.2),(36,0),"solver must wait when temporary bytes do not fit");
            let blocked_deliveries=reply.messages.load(Ordering::Acquire);
            assert_eq!(blocked_deliveries,0);
            let blocked_decoders=budget.usage().decoders;
            let route=AdnlPeers::with_keys(target.id().clone(),nodes[5].key_by_tag(0).unwrap().id().clone());
            let retired=rldps[0].peers.evict_for_test(&route);retired.drained.cancelled().await;
            let released_solver_bytes=budget.usage().bytes;
            assert_eq!(feed(1,0,symbols,false,false).await.0,35);
            tokio::time::timeout(Duration::from_secs(2),async {
                while reply.messages.load(Ordering::Acquire)==0 {reply.message_received.notified().await;}
            }).await.unwrap();
            let payload_hash=reply.message_hash.lock().unwrap().clone();
            assert_eq!(payload_hash,Some(hex::encode(rtos_block::sha256_digest(&payload))));
            let decoded_bytes=budget.usage().bytes;
            assert_eq!(feed(1,a as u16,0,false,false).await.0,a);
            let route=AdnlPeers::with_keys(target.id().clone(),nodes[2].key_by_tag(0).unwrap().id().clone());
            let retired=rldps[0].peers.evict_for_test(&route);retired.drained.cancelled().await;
            let evicted=budget.usage().decoders;
            assert_eq!(feed(3,c as u16,0,false,false).await.0,c+1);
            assert_eq!(feed(4,d as u16,0,false,false).await.0,d+1);
            serde_json::json!({"identity_a":a,"identity_b":b,"pool_tail":c,"solicited_tail":d,"full_bytes":full_bytes,"solver_pressure_bytes":pressure_bytes,"blocked_decoders":blocked_decoders,"blocked_deliveries":blocked_deliveries,"after_solver_release_bytes":released_solver_bytes,"after_decode_bytes":decoded_bytes,"deliveries":reply.messages.load(Ordering::Acquire),"payload_sha256":reply.message_hash.lock().unwrap().clone().unwrap(),"after_eviction":evicted,"after_retry":budget.usage().decoders,"unsolicited_after_retry":budget.unsolicited_usage().decoders})
        }).await.expect("qualification must finish before the native ten-second receive expiry")
    }).catch_unwind().await;
    for result in futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await {
        result.unwrap();
    }
    let mut actual = match outcome {
        Ok(actual) => actual,
        Err(panic) => std::panic::resume_unwind(panic),
    };
    actual["released_decoders"] = budget.usage().decoders.into();
    actual["released_bytes"] = budget.usage().bytes.into();
    actual["released_identities"] = budget.identity_count().into();
    eprintln!("NATIVE_BYTE_BUDGET: {actual}");
    assert_eq!(vec![actual], expected);
}
