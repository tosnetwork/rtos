// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{
    certificate::{Certificate, VoteSignature},
    simplex_state::FinalizeVote,
};
use consensus_common::{sst_test_support as support, TestSstAction};
use rtos_block::ShardIdent;
use std::{path::Path, sync::atomic::AtomicBool};
fn id(slot: u32) -> RawCandidateId {
    RawCandidateId { slot: SlotIndex::new(slot), hash: UInt256::from([slot as u8; 32]) }
}
fn vote(slot: u32) -> VoteRecord {
    let data = vec![slot as u8; 128];
    VoteRecord {
        vote_hash: UInt256::calc_file_hash(&data),
        data,
        node_idx: ValidatorIndex::new(0),
        seqno: 0,
    }
}
fn cert(slot: u32) -> FinalCert {
    Certificate {
        vote: FinalizeVote { slot: SlotIndex::new(slot), block_hash: id(slot).hash },
        signatures: vec![VoteSignature {
            validator_idx: ValidatorIndex::new(0),
            signature: vec![slot as u8; 64],
        }],
    }
}
fn finalized(slot: u32) -> FinalizedBlockRecord {
    FinalizedBlockRecord {
        candidate_id: id(slot),
        block_id: BlockIdExt::with_params(
            ShardIdent::masterchain(),
            slot,
            UInt256::from([slot as u8; 32]),
            UInt256::from([slot as u8 + 10; 32]),
        ),
        parent: if slot == 1 { None } else { Some(id(1)) },
        is_final: true,
    }
}
fn payload(slot: u32) -> Vec<u8> {
    vec![slot as u8; 128]
}
fn put(db: &SimplexDbPtr, slot: u32) {
    support::wait(db.save_vote_async(&vote(slot)).unwrap()).unwrap();
    support::wait(db.save_final_cert_async(&id(slot), &cert(slot)).unwrap()).unwrap();
    support::wait(db.save_candidate_payload_async(&id(slot), &payload(slot)).unwrap()).unwrap();
    support::wait(db.save_finalized_block_async(&finalized(slot)).unwrap()).unwrap();
    db.sync(Some(support::TIMEOUT)).unwrap();
}
fn check(db: &SimplexDbPtr) {
    let boot = db
        .load_pq_bootstrap_cancellable(&Arc::new(AtomicBool::new(false)), Duration::from_millis(10))
        .unwrap();
    assert_eq!(boot.votes.len(), 2);
    assert_eq!(boot.final_certs.len(), 2);
    assert_eq!(boot.candidate_payloads.len(), 2);
    assert_eq!(boot.finalized_blocks.len(), 2);
    for slot in [1, 2] {
        let stored_cert = boot.final_certs.iter().find(|c| c.candidate_id == id(slot)).unwrap();
        assert_eq!(
            stored_cert.cert_bytes,
            serialize_boxed(&cert(slot).to_tl().unwrap()).unwrap(),
            "typed acknowledged certificate bytes must match intended subject and signatures"
        );
        let stored = boot.votes.iter().find(|v| v.vote_hash == vote(slot).vote_hash).unwrap();
        assert_eq!(stored.seqno, i64::from(slot - 1));
        assert_eq!(stored.data, vote(slot).data);
        assert_eq!(stored.node_idx, vote(slot).node_idx);
        assert_eq!(
            boot.candidate_payloads.iter().find(|(candidate, _)| *candidate == id(slot)).unwrap().1,
            payload(slot)
        );
        let block = boot.finalized_blocks.iter().find(|b| b.candidate_id == id(slot)).unwrap();
        assert_eq!(block.block_id, finalized(slot).block_id);
        assert_eq!(block.parent, finalized(slot).parent);
        assert!(block.is_final);
    }
    assert_eq!(
        db.next_vote_seqno.load(Ordering::Relaxed),
        2,
        "strict bootstrap must restore next vote sequence"
    );
}
fn open(path: &Path, label: &str) -> SimplexDbPtr {
    let db = SimplexDb::open(path, "session").expect(label);
    support::native(&db.storage, TestSstAction::Configure).unwrap();
    db
}
fn close(db: SimplexDbPtr) {
    let receipt = db.storage.teardown_receipt().unwrap();
    db.close(Some(support::TIMEOUT)).unwrap();
    assert!(support::wait(db.storage.sst_for_test(TestSstAction::Inspect)).is_err());
    drop(db);
    receipt.check().expect("typed DB/native teardown did not finish");
    eprintln!("SST-OBS typed-teardown-receipt=clean");
}
fn exercise(compact: bool) {
    let case = format!("typed-sst-{}", if compact { "compact" } else { "flush" });
    let path = support::root(&case);
    std::fs::create_dir_all(&path).unwrap();
    let control = support::control();
    let db = open(&path, "typed SST setup DB open failed");
    put(&db, 1);
    let seed = support::seed(&db.storage);
    put(&db, 2);
    check(&db);
    let expected = support::raw(&db.storage);
    let before = support::inputs(&db.storage, &seed, compact);
    let filler = if control { None } else { Some(support::fill(&path)) };
    support::run(&db.storage, &before, compact, control);
    assert_eq!(support::raw(&db.storage), expected, "live typed ACK snapshot changed");
    check(&db);
    if let Some(filler) = filler {
        std::fs::remove_file(filler).unwrap();
    }
    eprintln!("SST-OBS typed-post-error-sync={:?}", db.sync(Some(support::TIMEOUT)));
    close(db);
    let db = open(&path, "acknowledged typed SST open failed");
    assert_eq!(support::raw(&db.storage), expected, "cold typed ACK snapshot changed");
    check(&db);
    support::retry(&db.storage, compact);
    close(db);
    let db = open(&path, "acknowledged typed SST open failed");
    assert_eq!(support::raw(&db.storage), expected, "second typed ACK snapshot changed");
    check(&db);
    close(db);
    eprintln!("ENOSPC-CASE {case} {} ok", if control { "control" } else { "fault" });
}
#[test]
#[ignore = "private SST ENOSPC namespace and trace required"]
fn disk_full_typed_sst_flush() {
    exercise(false);
}
#[test]
#[ignore = "private SST ENOSPC namespace and trace required"]
fn disk_full_typed_sst_compact() {
    exercise(true);
}
#[test]
fn queued_typed_sst_bootstrap_and_teardown_roundtrip() {
    let path = std::env::temp_dir().join(format!("rtos-typed-sst-fixture-{}", std::process::id()));
    assert!(!path.exists());
    let db = open(&path, "acknowledged typed SST open failed");
    put(&db, 1);
    put(&db, 2);
    check(&db);
    let expected = support::raw(&db.storage);
    close(db);
    let db = open(&path, "acknowledged typed SST open failed");
    assert_eq!(support::raw(&db.storage), expected);
    check(&db);
    close(db);
    std::fs::remove_dir_all(&path).unwrap();
}
