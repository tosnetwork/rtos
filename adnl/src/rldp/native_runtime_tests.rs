// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Frozen actual-query corpora through two owned native Connection drivers.
use super::*;

async fn check_runtime(corpus: &str, inputs: &str, frozen: &str, count: usize) {
    let expected: serde_json::Value = serde_json::from_str(frozen).unwrap();
    assert_eq!(
        expected["reference_commit"],
        include_str!("../../../ci/conformance/REFERENCE").trim()
    );
    assert_eq!(expected["input_sha256"], hex::encode(rtos_block::sha256_digest(inputs.as_bytes())));
    assert_eq!(
        expected["probe_source_sha256"],
        hex::encode(rtos_block::sha256_digest(include_bytes!(
            "../../../ci/conformance/rldp2_runtime_reference.cpp"
        )))
    );
    let rows: Vec<_> =
        inputs.lines().filter(|line| !line.trim().is_empty() && !line.starts_with('#')).collect();
    let effects = expected["effects"].as_array().unwrap();
    assert_eq!(rows.len(), count);
    assert_eq!(effects.len(), count);
    let (reply, _, nodes, rldps, _) = default_pair().await;
    reply.runtime_pattern.store(true, Ordering::Release);
    for node in &rldps {
        assert!(node.peers.native_enabled(), "ordinary constructors must select native Connection");
    }
    let outcome = std::panic::AssertUnwindSafe(async {
        let keys = [nodes[0].key_by_tag(0).unwrap(), nodes[1].key_by_tag(0).unwrap()];
        let mut differences = Vec::new();
        for (line, want) in rows.iter().zip(effects) {
            let fields: Vec<_> = line.split_whitespace().collect();
            assert_eq!(fields.len(), 4);
            let id = fields[0];
            assert_eq!(want["id"], id);
            let direction: usize = fields[1].parse().unwrap();
            let size: u32 = fields[2].parse().unwrap();
            let limit: u64 = fields[3].parse().unwrap();
            assert!(direction < 2 && size <= 2 * 1024 * 1024 && limit <= 2 * 1024 * 1024);
            let mut request = [0; 32];
            request[..4].copy_from_slice(&size.to_le_bytes());
            let bytes = serialize_boxed(&Query { overlay: UInt256::with_array(request) }).unwrap();
            let route = AdnlPeers::with_keys(keys[direction].id().clone(), keys[1-direction].id().clone());
            let started = tokio::time::Instant::now();
            let result = tokio::time::timeout(Duration::from_secs(30), rldps[direction].query(
                &TaggedByteSlice { object: &bytes, #[cfg(feature = "telemetry")] tag: 0 },
                Some(limit), &route, true, None)).await;
            let (status, payload, diagnostic) = match result {
                Ok(Ok((Some(bytes), _))) => ("answer", bytes, String::new()),
                Ok(Ok((None, _))) => ("no_answer", Vec::new(), String::new()),
                Ok(Err(error)) if error.downcast_ref::<RldpQueryTimeout>().is_some() => ("timeout", Vec::new(), error.to_string()),
                Ok(Err(error)) => ("error", Vec::new(), format!("{error:#}")),
                Err(error) => ("harness_timeout", Vec::new(), error.to_string()),
            };
            let elapsed = started.elapsed().as_millis() as u64;
            let hash = hex::encode(rtos_block::sha256_digest(&payload));
            let actual = serde_json::json!({"corpus":corpus,"id":id,"status":status,
                "payload_bytes":payload.len(),"payload_sha256":hash,"elapsed_ms":elapsed,"diagnostic":diagnostic});
            eprintln!("NATIVE_CONNECTION_RUNTIME: {actual}");
            if want["status"] != status || want["payload_bytes"] != payload.len() || want["payload_sha256"] != hash
                || want["timeout_not_before_ms"].as_u64().is_some_and(|minimum| elapsed < minimum) {
                differences.push(actual);
            }
            if status == "answer" {
                assert_eq!(payload, (0..size as usize).map(|i| (i % 251) as u8).collect::<Vec<_>>(), "{id}: complete payload");
            }
            for side in 0..2 {
                let peer = rldps[side].peers.find_v2(keys[side].id(), keys[1-side].id()).expect("actual query must open its peer");
                assert!(peer.native.get().is_some(), "actual peer must own native Connection");
                assert_eq!(rldps[side].allocated.send_transfers.load(Ordering::Acquire), 0, "native must not retain legacy send wrapper");
                assert_eq!(rldps[side].allocated.recv_transfers.load(Ordering::Acquire), 0, "native must not retain legacy receive wrapper");
            }
        }
        assert!(differences.is_empty(), "{corpus} differences: {differences:#?}");
        eprintln!("NATIVE_CONNECTION_RUNTIME_SUMMARY: {corpus} {count} equal 0 differences");
    }).catch_unwind().await;
    let stopped = futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await;
    for result in stopped {
        result.unwrap();
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_connection_runtime_cases() {
    check_runtime(
        "cases",
        include_str!("../../../ci/conformance/rldp2_runtime_cases.tsv"),
        include_str!("../../../ci/conformance/rldp2_runtime_expected.json"),
        11,
    )
    .await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_connection_runtime_boundaries() {
    check_runtime(
        "boundaries",
        include_str!("../../../ci/conformance/rldp2_runtime_boundaries.tsv"),
        include_str!("../../../ci/conformance/rldp2_runtime_boundaries_expected.json"),
        17,
    )
    .await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_connection_runtime_multipart() {
    check_runtime(
        "multipart",
        include_str!("../../../ci/conformance/rldp2_multipart_live_context.tsv"),
        include_str!("../../../ci/conformance/rldp2_multipart_live_expected.json"),
        3,
    )
    .await;
}
