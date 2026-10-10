// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
#[path = "common/pq_finality.rs"]
mod fixture;
use rtos_api::pq_finality::{PqApproval, PqSessionContext};
use rtos_block::*;
fn data() -> serde_json::Value {
    serde_json::from_str(include_str!("data/live-pq.json")).unwrap()
}
fn bytes(v: &serde_json::Value, name: &str) -> Vec<u8> {
    hex::decode(v[name].as_str().unwrap()).unwrap()
}
fn carrier(kind: &str, role: &str, context: &str) -> BlockSignaturesSimplexPq {
    let d = data();
    let mut value = fixture::unsigned(&fixture::context(&fixture::config()));
    let rows: Vec<_> = d["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["kind"] == kind && r["role"] == role && r["context"] == context)
        .collect();
    assert_eq!(rows.len(), 2);
    value.candidate_data =
        BlockSignaturesSimplex::bytes_to_cell_tree(&bytes(rows[0], "candidate")).unwrap();
    for row in rows {
        let index = row["index"].as_u64().unwrap();
        value.signatures.push(PqBlockSignaturePair {
            validator_id: UInt256::from([index as u8 + 1; 32]),
            algorithm_id: 1,
            signature: bytes(row, "signature"),
        });
        value.sig_count += 1;
        value.sig_weight += index + 1;
    }
    value
}
fn target(carrier: &BlockSignaturesSimplexPq) -> BlockIdExt {
    let bytes = carrier.candidate_bytes().unwrap();
    let candidate: rtos_api::ton::consensus::CandidateHashData =
        rtos_api::Deserializer::new(&mut std::io::Cursor::new(bytes)).read_boxed().unwrap();
    candidate.block().clone()
}
fn snapshot(shard: ShardIdent) -> PqSessionContext {
    PqSessionContext::from_authenticated_session_members(
        fixture::context(&fixture::config()).expected_session_id().clone(),
        shard,
        7,
        fixture::config().validator_set().unwrap().list().to_vec(),
    )
    .unwrap()
}
const SIMPLEX: &str = "TOS-CONSENSUS-SIMPLEX-v1";
#[test]
fn pq_live_final_and_notar_roles_remain_distinct() {
    for kind in ["empty", "ordinary", "shard_empty", "shard_ordinary"] {
        let finality = carrier(kind, "finalize", SIMPLEX);
        let block = target(&finality);
        let context = snapshot(block.shard().clone()).for_block(block.clone()).unwrap();
        let verified = context.verify_final(&finality).unwrap();
        assert_eq!(verified.block_id(), &block);
        assert_eq!(verified.slot(), 99);
        assert_eq!(verified.weight(), 3);
        let notar = carrier(kind, "notarize", SIMPLEX);
        assert!(context.verify_final(&notar).is_err(), "Notarize must never become Final");
        let approval = PqApproval::from_notarization_fields(notar).unwrap();
        if block.shard().is_masterchain() {
            assert!(context.verify_approval(&approval).is_err());
        } else {
            let verified = context.verify_approval(&approval).unwrap();
            assert_eq!(verified.block_id(), &block);
            assert_eq!(verified.weight(), 3);
        }
        assert!(context
            .verify_approval(&PqApproval::from_notarization_fields(finality).unwrap())
            .is_err());
        assert!(context.verify_final(&carrier(kind, "finalize", "TOS-AUTH-ML-DSA-44-v1")).is_err());
    }
}
#[test]
fn pq_live_finality_rejects_untrusted_context_members_and_bounds() {
    let good = carrier("shard_ordinary", "finalize", SIMPLEX);
    let block = target(&good);
    let context = snapshot(block.shard().clone()).for_block(block.clone()).unwrap();
    let mut variants = Vec::new();
    let mut bad = good.clone();
    bad.session_id = UInt256::from([77; 32]);
    variants.push(bad);
    let mut bad = good.clone();
    bad.slot += 1;
    variants.push(bad);
    let mut bad = good.clone();
    bad.validator_info.catchain_seqno += 1;
    variants.push(bad);
    let mut bad = good.clone();
    bad.validator_info.validator_list_hash_short ^= 1;
    variants.push(bad);
    let mut bad = good.clone();
    bad.sig_weight += 1;
    variants.push(bad);
    let mut bad = good.clone();
    bad.sig_count += 1;
    variants.push(bad);
    let mut bad = good.clone();
    bad.signatures[1] = bad.signatures[0].clone();
    variants.push(bad);
    let mut bad = good.clone();
    bad.signatures[0].validator_id = UInt256::from([99; 32]);
    variants.push(bad);
    let mut bad = good.clone();
    bad.signatures[0].algorithm_id = 2;
    variants.push(bad);
    let mut bad = good.clone();
    bad.signatures[0].signature.truncate(2419);
    variants.push(bad);
    let mut bad = good.clone();
    bad.signatures[0].signature.push(0);
    variants.push(bad);
    let mut bad = good.clone();
    bad.signatures[0].signature[100] ^= 1;
    variants.push(bad);
    let mut bad = good.clone();
    bad.signatures.remove(1);
    bad.sig_count = 1;
    bad.sig_weight = 1;
    variants.push(bad);
    let mut bad = good.clone();
    let mut candidate = bad.candidate_bytes().unwrap();
    candidate.push(0);
    bad.candidate_data = BlockSignaturesSimplex::bytes_to_cell_tree(&candidate).unwrap();
    variants.push(bad);
    for (i, bad) in variants.iter().enumerate() {
        assert!(context.verify_final(bad).is_err(), "negative case {i}");
    }
    for field in 0..3 {
        let mut other = block.clone();
        match field {
            0 => other.root_hash = UInt256::from([42; 32]),
            1 => other.file_hash = UInt256::from([43; 32]),
            _ => other.seq_no += 1,
        };
        assert!(snapshot(block.shard().clone())
            .for_block(other)
            .unwrap()
            .verify_final(&good)
            .is_err());
    }
    assert!(snapshot(ShardIdent::masterchain()).for_block(block).is_err());
    let mut members = fixture::config().validator_set().unwrap().list().to_vec();
    members[1].weight = u64::MAX;
    assert!(PqSessionContext::from_authenticated_session_members(
        good.session_id.clone(),
        ShardIdent::masterchain(),
        7,
        members
    )
    .is_err());
}
