// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::pq_fixture as f;
use rtos_api::IntoBoxed;
fn sources() -> Vec<SourceStats> {
    f::members()
        .0
        .into_iter()
        .enumerate()
        .map(|(i, n)| SourceStats::new(i as u32, n.adnl_id, n.identity, n.weight))
        .collect()
}
fn empty() -> rtos_api::ton::consensus::CandidateData {
    use rtos_api::ton::consensus::{candidatedata::Empty, candidateid::CandidateId};
    Empty {
        slot: 99,
        parent: CandidateId { slot: 98, hash: UInt256::from([5; 32]) }.into_boxed(),
        block: f::block_id("empty"),
        signature: f::bytes(&f::row("empty", "candidate", 1, f::CONTEXT), "signature"),
    }
    .into_boxed()
}
#[test]
fn pq_live_repair_candidate_authentication_and_bounds() {
    let bytes = rtos_api::serialize_boxed(&empty()).unwrap();
    let hash = f::candidate_hash("empty");
    let members = sources();
    for version in [0, 1] {
        let check = |session: &UInt256, slot, hash: &UInt256, bytes: &[u8], size| {
            ReceiverImpl::validate_repair_candidate_identity(
                session,
                &members,
                1,
                &rtos_block::ShardIdent::masterchain(),
                size,
                1 << 20,
                version,
                SlotIndex::new(slot),
                hash,
                bytes,
            )
        };
        assert!(check(&f::session(), 99, &hash, &bytes, 1 << 20).is_ok());
        assert!(check(&UInt256::from([71; 32]), 99, &hash, &bytes, 1 << 20).is_err());
        assert!(check(&f::session(), 98, &hash, &bytes, 1 << 20).is_err());
        assert!(check(&f::session(), 99, &UInt256::from([72; 32]), &bytes, 1 << 20).is_err());
        let mut bad = empty();
        let rtos_api::ton::consensus::CandidateData::Consensus_Empty(ref mut inner) = bad else {
            unreachable!()
        };
        inner.signature = f::bytes(&f::row("empty", "candidate", 0, f::CONTEXT), "signature");
        assert!(check(
            &f::session(),
            99,
            &hash,
            &rtos_api::serialize_boxed(&bad).unwrap(),
            1 << 20
        )
        .is_err());
        inner_signature_wallet(&mut bad);
        assert!(check(
            &f::session(),
            99,
            &hash,
            &rtos_api::serialize_boxed(&bad).unwrap(),
            1 << 20
        )
        .is_err());
        assert!(ReceiverImpl::validate_repair_candidate_identity(
            &f::session(),
            &members,
            1,
            &rtos_block::ShardIdent::masterchain(),
            1 << 20,
            1,
            version,
            SlotIndex::new(99),
            &hash,
            &bytes
        )
        .is_err());
    }
}
fn inner_signature_wallet(candidate: &mut rtos_api::ton::consensus::CandidateData) {
    let rtos_api::ton::consensus::CandidateData::Consensus_Empty(inner) = candidate else {
        unreachable!()
    };
    inner.signature =
        f::bytes(&f::row("empty", "candidate", 1, "TOS-AUTH-ML-DSA-44-v1"), "signature");
}
#[test]
fn pq_live_resolver_notar_quorum_and_member_rejection() {
    let hash = f::candidate_hash("empty");
    let members = sources();
    let check = |session: &UInt256, bytes: &[u8]| {
        ReceiverImpl::validate_repair_notar_signature_set(
            session,
            &members,
            1 << 20,
            SlotIndex::new(99),
            &hash,
            bytes,
        )
    };
    let good = f::signatures("empty", "notarize", f::CONTEXT);
    assert!(check(&f::session(), &rtos_api::serialize_boxed(&good).unwrap()).is_ok());
    assert!(check(&UInt256::from([71; 32]), &rtos_api::serialize_boxed(&good).unwrap()).is_err());
    for role in ["finalize", "candidate"] {
        assert!(check(
            &f::session(),
            &rtos_api::serialize_boxed(&f::signatures("empty", role, f::CONTEXT)).unwrap()
        )
        .is_err());
    }
    assert!(check(
        &f::session(),
        &rtos_api::serialize_boxed(&f::signatures("empty", "notarize", "TOS-AUTH-ML-DSA-44-v1"))
            .unwrap()
    )
    .is_err());
    let rtos_api::ton::consensus::simplex::VoteSignatureSet::Consensus_Simplex_VoteSignatureSet(
        mut inner,
    ) = good;
    inner.votes[1] = inner.votes[0].clone();
    assert!(check(&f::session(), &rtos_api::serialize_boxed(&inner.clone().into_boxed()).unwrap())
        .is_err());
    inner.votes.truncate(1);
    assert!(check(&f::session(), &rtos_api::serialize_boxed(&inner.clone().into_boxed()).unwrap())
        .is_err());
    let rtos_api::ton::consensus::simplex::VoteSignature::Consensus_Simplex_VoteSignature(
        ref mut sig,
    ) = inner.votes[0];
    sig.who = 2;
    assert!(check(&f::session(), &rtos_api::serialize_boxed(&inner.into_boxed()).unwrap()).is_err());
}
#[test]
fn pq_live_verified_candidate_survives_database_reopen_and_resolver_validation() {
    let members = sources();
    let payload = rtos_api::serialize_boxed(&empty()).unwrap();
    let hash = f::candidate_hash("empty");
    ReceiverImpl::validate_repair_candidate_identity(
        &f::session(),
        &members,
        1,
        &rtos_block::ShardIdent::masterchain(),
        1 << 20,
        1 << 20,
        0,
        SlotIndex::new(99),
        &hash,
        &payload,
    )
    .unwrap();
    let path = std::env::temp_dir().join(format!(
        "rtos-pq-candidate-{}-{}",
        std::process::id(),
        UInt256::rand().to_hex_string()
    ));
    let id = crate::block::RawCandidateId { slot: SlotIndex::new(99), hash: hash.clone() };
    {
        let db = crate::database::SimplexDb::open(&path, "pq-test").unwrap();
        db.save_candidate_payload_async(&id, &payload).unwrap().wait().unwrap();
        db.close(Some(Duration::from_secs(10))).unwrap();
    }
    let db = crate::database::SimplexDb::open(&path, "pq-test").unwrap();
    let restored = db.load_candidate_payload_by_id(&id, Duration::from_secs(10)).unwrap().unwrap();
    assert_eq!(restored, payload);
    ReceiverImpl::validate_repair_candidate_identity(
        &f::session(),
        &members,
        1,
        &rtos_block::ShardIdent::masterchain(),
        1 << 20,
        1 << 20,
        0,
        SlotIndex::new(99),
        &hash,
        &restored,
    )
    .unwrap();
    assert!(ReceiverImpl::validate_repair_candidate_identity(
        &UInt256::from([89; 32]),
        &members,
        1,
        &rtos_block::ShardIdent::masterchain(),
        1 << 20,
        1 << 20,
        0,
        SlotIndex::new(99),
        &hash,
        &restored
    )
    .is_err());
    db.close(Some(Duration::from_secs(10))).unwrap();
    drop(db);
    std::fs::remove_dir_all(path).unwrap();
}
