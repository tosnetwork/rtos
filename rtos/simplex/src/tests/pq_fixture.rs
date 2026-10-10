// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use crate::{session_description::SessionDescription, SessionOptions, SimplexSessionNode};
use rtos_block::*;
use std::sync::Arc;
pub fn data() -> serde_json::Value {
    serde_json::from_str(include_str!("../../../../tl/rtos_api/tests/data/live-pq.json")).unwrap()
}
pub fn bytes(row: &serde_json::Value, key: &str) -> Vec<u8> {
    hex::decode(row[key].as_str().unwrap()).unwrap()
}
pub fn row(kind: &str, role: &str, index: usize, context: &str) -> serde_json::Value {
    data()["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| {
            r["kind"] == kind && r["role"] == role && r["index"] == index && r["context"] == context
        })
        .unwrap()
        .clone()
}
pub const CONTEXT: &str = "TOS-CONSENSUS-SIMPLEX-v1";
pub fn session() -> UInt256 {
    UInt256::from_slice(&bytes(&data(), "session"))
}
pub fn members() -> (Vec<SimplexSessionNode>, Vec<Arc<dyn KeyOption>>) {
    let mut nodes = Vec::new();
    let mut keys = Vec::new();
    for i in 0..2 {
        let key =
            Ed25519KeyOption::<ZeroizingBytes>::from_private_key(&[0x50 + i as u8; 32]).unwrap();
        let public_key = bytes(&row("empty", "candidate", i, CONTEXT), "public_key");
        let descriptor = ValidatorDescr::with_pq_params(
            UInt256::from([i as u8 + 1; 32]),
            PqConsensusKey {
                algorithm_id: 1,
                key_id: derive_consensus_key_id(1, &public_key),
                public_key,
            },
            i as u64 + 1,
            UInt256::from(*key.id().data()),
        );
        nodes.push(SimplexSessionNode::from_descriptor(&descriptor).unwrap());
        keys.push(key);
    }
    (nodes, keys)
}
pub fn description(shard: ShardIdent, version: u32) -> Arc<SessionDescription> {
    let (nodes, keys) = members();
    let options = SessionOptions { proto_version: version, ..Default::default() };
    Arc::new(
        SessionDescription::new(
            &options,
            session(),
            42,
            &nodes,
            keys[0].clone(),
            &shard,
            std::time::SystemTime::now(),
            None,
        )
        .unwrap()
        .bind_pq_session(7)
        .unwrap(),
    )
}
pub fn candidate_hash(kind: &str) -> UInt256 {
    UInt256::calc_file_hash(&bytes(&row(kind, "candidate", 0, CONTEXT), "candidate"))
}
pub fn block_id(kind: &str) -> BlockIdExt {
    let data = bytes(&row(kind, "candidate", 0, CONTEXT), "candidate");
    let tl: rtos_api::ton::consensus::CandidateHashData =
        rtos_api::Deserializer::new(&mut std::io::Cursor::new(data)).read_boxed().unwrap();
    tl.block().clone()
}
pub fn vote(
    kind: &str,
    role: &str,
    index: usize,
    context: &str,
) -> rtos_api::ton::consensus::simplex::Vote {
    use rtos_api::{
        ton::consensus::{
            candidateid::CandidateId,
            simplex::{unsignedvote, vote::Vote},
        },
        IntoBoxed,
    };
    let id =
        CandidateId { slot: 99, hash: candidate_hash(if kind == "skip" { "empty" } else { kind }) }
            .into_boxed();
    let vote = match role {
        "notarize" => unsignedvote::NotarizeVote { id }.into_boxed(),
        "finalize" => unsignedvote::FinalizeVote { id }.into_boxed(),
        "skip" => unsignedvote::SkipVote { slot: 99 }.into_boxed(),
        _ => panic!(),
    };
    Vote { vote, signature: bytes(&row(kind, role, index, context), "signature") }.into_boxed()
}
pub fn signatures(
    kind: &str,
    role: &str,
    context: &str,
) -> rtos_api::ton::consensus::simplex::VoteSignatureSet {
    use rtos_api::{
        ton::consensus::simplex::{
            votesignature::VoteSignature, votesignatureset::VoteSignatureSet,
        },
        IntoBoxed,
    };
    VoteSignatureSet {
        votes: (0..2)
            .map(|i| {
                VoteSignature {
                    who: i,
                    signature: bytes(&row(kind, role, i as usize, context), "signature"),
                }
                .into_boxed()
            })
            .collect(),
    }
    .into_boxed()
}
