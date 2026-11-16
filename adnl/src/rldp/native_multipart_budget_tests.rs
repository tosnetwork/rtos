// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::{
    super::{native_connection::NativeConnection, rldp2::budget::InboundBudget},
    native_identity_tests::inspect,
    *,
};

#[test]
fn native_multipart_retention_assembly_and_retirement() {
    const CHILD: &str = "RTOS_MULTIPART_BUDGET_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output=std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact","rldp::lifetime_tests::native_multipart_budget_tests::native_multipart_retention_assembly_and_retirement","--nocapture"])
            .env(CHILD,"1").output().unwrap();
        print!("{}", String::from_utf8_lossy(&output.stdout));
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
        assert!(
            output.status.success(),
            "isolated multipart-budget qualification failed: {}",
            output.status
        );
        return;
    }
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let context = include_bytes!(
                "../../../ci/conformance/rldp2_multipart_budget_runtime_context.tsv"
            );
            let expected = checked_ack_native_effects(
                context,
                include_bytes!(
                    "../../../ci/conformance/rldp2_multipart_budget_runtime_effects.jsonl"
                ),
                include_bytes!(
                    "../../../ci/conformance/rldp2_multipart_budget_runtime_reference.cpp"
                ),
                include_bytes!(
                    "../../../ci/conformance/rldp2_multipart_budget_runtime_metadata.json"
                ),
            );
            // Repeat within the isolated child to retain the process-global budget and allocator.
            // Ordinary CI runs one round; the retained stress runner supplies an explicit bound.
            let rounds = std::env::var("RTOS_MULTIPART_BUDGET_ROUNDS")
                .map(|value| value.parse::<usize>().expect("integer round count"))
                .unwrap_or(1);
            assert!((1..=64).contains(&rounds), "round count must be in 1..=64");
            for round in 0..rounds {
                let mut actual = Vec::new();
                for line in std::str::from_utf8(context).unwrap().lines() {
                    let fields: Vec<_> = line.split_whitespace().collect();
                    assert_eq!(fields.len(), 6);
                    actual.extend(
                        check_case(
                            fields[0],
                            fields[1].parse().unwrap(),
                            fields[2] == "1",
                            fields[3] == "1",
                            fields[4] == "1",
                            fields[5].parse().unwrap(),
                        )
                        .await,
                    );
                }
                assert_eq!(actual.len(), expected.len());
                for (row, (observed, reference)) in actual.iter().zip(&expected).enumerate() {
                    assert_eq!(observed, reference, "multipart budget snapshot {row}");
                }
                eprintln!("NATIVE_MULTIPART_BUDGET: {}", serde_json::to_string(&actual).unwrap());
                eprintln!("NATIVE_MULTIPART_ROUND_DONE: {}", round + 1);
            }
        });
}

async fn snapshot(
    name: &str,
    phase: &str,
    part: usize,
    native: Option<&NativeConnection>,
    budget: &InboundBudget,
    identity: &[u8; 32],
    reply: &HeldReply,
) -> serde_json::Value {
    let inbound = if let Some(native) = native { Some(inspect(native).await.0) } else { None };
    let usage = budget.usage();
    serde_json::json!({"id":name,"phase":phase,"part":part,"owner_live":native.is_some(),"inbound":inbound,"decoders":usage.decoders,"bytes":usage.bytes,"unsolicited_bytes":budget.unsolicited_usage().bytes,"identity_bytes":budget.identity_usage(identity).bytes,"identities":budget.identity_count(),"deliveries":reply.messages.load(Ordering::Acquire),"payload_sha256":reply.message_hash.lock().unwrap().clone().unwrap_or_default()})
}

async fn check_case(
    name: &str,
    count: usize,
    reverse: bool,
    retire: bool,
    solicited: bool,
    tail: usize,
) -> Vec<serde_json::Value> {
    use rtos_api::{ton::rldp, IntoBoxed, RldpChunk};
    assert!((2..=3).contains(&count));
    assert!((4..=2_000_000).contains(&tail) && tail % 4 == 0);
    let (reply, _, nodes, rldps, peers) = topology_configured(2, None, false, true).await;
    for node in &rldps {
        node.peers.enable_native_for_tests();
    }
    let identity = *peers.other().data();
    let budget = InboundBudget::process_default();
    assert_eq!(budget.usage(), super::super::rldp2::budget::Usage::default());
    let outcome=std::panic::AssertUnwindSafe(async {
        let total=(count-1)*2_000_000+tail;
        let mut payload=vec![42;total-40];payload[..4].copy_from_slice(b"mtu:");
        let wire_message=serialize_boxed(&rldp::message::Message {id:UInt256::default(),data:payload.clone()}.into_boxed()).unwrap();
        assert_eq!(wire_message.len(),total);
        let mut parts=Vec::new();
        for data in wire_message.chunks(2_000_000) {
            let mut encoder=crate::RaptorqEncoder::with_data(data,Some(768));
            let fec=encoder.params().clone().into_boxed();
            let symbols:Vec<_>=(0..data.len().div_ceil(768)).map(|seq|{let mut n=seq as u32;encoder.encode(&mut n).unwrap()}).collect();
            parts.push((fec,symbols));
        }
        rldps[0].change_inbound_cap_for_peers(&[peers.other().clone()],1).unwrap();
        let peer=rldps[0].get_peer(peers.local(),peers.other(),true,None).await.unwrap();
        let native=peer.native.get().expect("real peer must own native Connection").clone();
        if solicited {assert!(native.driver.submit(super::super::connection_driver::Command::ReceiveLimit {
            id:[0;32],deadline:std::time::Instant::now()+Duration::from_secs(30),max_size:total as u64,
        }).await.unwrap());}
        let feed=|part:usize,seq:usize| {
            let nodes=&nodes;let peers=&peers;let native=&native;let parts=&parts;
            async move {
                let key=([0;32],part as i32,seq as i32);
                let before=native.data_receipts.lock().unwrap().get(&key).copied().unwrap_or_default();
                let chunk=RldpChunk {transfer_id:UInt256::default(),fec_type:parts[part].0.clone(),part:part as i32,total_size:total as i64,seqno:seq as i32,data:parts[part].1[seq].clone()};
                let wire=serialize_boxed(&rldp2::messagepart::MessagePart(chunk).into_boxed()).unwrap();
                let route=AdnlPeers::with_keys(peers.other().clone(),peers.local().clone());
                nodes[1].send_custom(&TaggedByteSlice {object:&wire,#[cfg(feature="telemetry")]tag:0},&route).await.unwrap();
                tokio::time::timeout(Duration::from_secs(2),async {
                    loop {
                        if native.data_receipts.lock().unwrap().get(&key).copied().unwrap_or_default()>before {break;}
                        tokio::select! {
                            _=native.data_processed.notified()=>{},
                            _=tokio::time::sleep(Duration::from_millis(50))=>{
                                nodes[1].send_custom(&TaggedByteSlice {object:&wire,#[cfg(feature="telemetry")]tag:0},&route).await.unwrap();
                            }
                        }
                    }
                }).await.expect("exact transfer/part/symbol must finish actual processing");
            }
        };
        tokio::time::timeout(Duration::from_secs(8),async {
            let mut rows=Vec::new();
            for part in 0..count {feed(part,0).await;}
            rows.push(snapshot(name,"admitted",0,Some(&native),&budget,&identity,&reply).await);
            for i in 0..count {
                let part=if reverse {count-1-i}else{i};
                for seq in 1..parts[part].1.len() {feed(part,seq).await;}
                if !retire && i+1==count {
                    tokio::time::timeout(Duration::from_secs(2),async {
                        while reply.messages.load(Ordering::Acquire)==0 {reply.message_received.notified().await;}
                    }).await.expect("fully assembled payload must reach the real application");
                    let hash=reply.message_hash.lock().unwrap().clone();
                    assert_eq!(hash,Some(hex::encode(rtos_block::sha256_digest(&payload))));
                }
                rows.push(snapshot(name,"decoded",part,Some(&native),&budget,&identity,&reply).await);
                if retire {
                    assert_eq!(reply.messages.load(Ordering::Acquire),0);
                    let retired=rldps[0].peers.evict_for_test(&peers);
                    retired.drained.cancelled().await;
                    rows.push(snapshot(name,"retired",part,None,&budget,&identity,&reply).await);
                    break;
                }
            }
            rows
        }).await.expect("check all live parts before native unsolicited expiry")
    }).catch_unwind().await;
    for result in futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await {
        result.unwrap();
    }
    let mut rows = match outcome {
        Ok(rows) => rows,
        Err(panic) => std::panic::resume_unwind(panic),
    };
    if !retire {
        rows.push(snapshot(name, "shutdown", count - 1, None, &budget, &identity, &reply).await);
    }
    assert_eq!(budget.usage(), super::super::rldp2::budget::Usage::default());
    assert_eq!(budget.identity_count(), 0);
    rows
}
