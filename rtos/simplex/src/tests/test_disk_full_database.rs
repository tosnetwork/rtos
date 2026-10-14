// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Typed Simplex storage ENOSPC probes, not signature/quorum validation.
use super::*;
use crate::{
    certificate::{Certificate, VoteSignature},
    simplex_state::FinalizeVote,
};
use consensus_common::StorageAsyncResultPtr;
use rtos_block::ShardIdent;
use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

const TIMEOUT: Duration = Duration::from_secs(10);
fn wait<T: Clone + Send + Sync + 'static>(result: StorageAsyncResultPtr<T>) -> Result<T> {
    result.wait_timeout(TIMEOUT).expect("typed storage operation timed out")
}
fn fill(path: &Path) -> PathBuf {
    let path = path.join("enospc-filler");
    let mut file = std::fs::File::create(&path).unwrap();
    for size in [65536, 4096] {
        loop {
            match file.write_all(&vec![0; size]) {
                Ok(()) => (),
                Err(error) => {
                    assert_eq!(error.raw_os_error(), Some(28));
                    break;
                }
            }
        }
    }
    path
}
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
fn raw(db: &SimplexDbPtr) -> Vec<(Vec<u8>, Vec<u8>)> {
    wait(db.storage.get_by_prefix(Vec::new(), None)).unwrap()
}
fn strict(db: &SimplexDbPtr) -> Bootstrap {
    db.load_pq_bootstrap_cancellable(&Arc::new(AtomicBool::new(false)), Duration::from_millis(10))
        .unwrap()
}
fn target(db: &SimplexDbPtr, kind: &str) -> (Vec<u8>, Vec<u8>, StorageAsyncResultPtr<()>) {
    match kind {
        "vote" => {
            let mut record = vote(2);
            record.seqno = db.next_vote_seqno.load(Ordering::Relaxed);
            (
                serialize_vote_key(&record.vote_hash).unwrap(),
                serialize_vote_value(&record).unwrap(),
                db.save_vote_async(&record).unwrap(),
            )
        }
        "cert" => {
            let cert = cert(2);
            let (key, value) = serialize_cert_vote_entry(cert.to_tl().unwrap()).unwrap();
            (key, value, db.save_final_cert_async(&id(2), &cert).unwrap())
        }
        "payload" => {
            let value = vec![2; 65536];
            (
                serialize_candidate_payload_key(&id(2)).unwrap(),
                value.clone(),
                db.save_candidate_payload_async(&id(2), &value).unwrap(),
            )
        }
        "finalized" => {
            let record = finalized(2);
            (
                serialize_finalized_block_key(&id(2)).unwrap(),
                serialize_finalized_block_value(&record).unwrap(),
                db.save_finalized_block_async(&record).unwrap(),
            )
        }
        _ => panic!("unknown typed probe"),
    }
}
fn exercise(kind: &str) {
    let root = PathBuf::from(std::env::var_os("RTOS_ENOSPC_ROOT").expect("run in tmpfs harness"));
    let path = root.join(format!("typed-{kind}"));
    let control = std::env::var("RTOS_ENOSPC_CONTROL").as_deref() == Ok("1");
    let db = SimplexDb::open(&path, "session").unwrap();
    wait(db.save_vote_async(&vote(1)).unwrap()).unwrap();
    wait(db.save_final_cert_async(&id(1), &cert(1)).unwrap()).unwrap();
    wait(db.save_candidate_payload_async(&id(1), b"acknowledged candidate").unwrap()).unwrap();
    wait(db.save_finalized_block_async(&finalized(1)).unwrap()).unwrap();
    let seed = raw(&db);
    let seed_bootstrap = strict(&db);
    assert_eq!(seed_bootstrap.votes[0].seqno, 0);
    db.storage.flush_for_disk_full_test().unwrap();
    let filler = if control { None } else { Some(fill(&path)) };
    let (key, intended, pending) = target(&db, kind);
    let result = wait(pending);
    assert_eq!(result.is_ok(), control, "typed acknowledgement: {result:?}");
    if let Err(error) = result {
        let error = format!("{error:#}");
        assert!(error.contains("No space left") || error.contains("ENOSPC"), "{error}");
    }
    if let Some(filler) = filler {
        std::fs::remove_file(filler).unwrap();
    }
    let probe = wait(db.save_candidate_payload_async(&id(3), b"independent probe").unwrap());
    assert_eq!(probe.is_ok(), control, "same-instance typed probe: {probe:?}");
    drop(db);
    let db = SimplexDb::open(&path, "session").unwrap();
    let recovered = raw(&db);
    for entry in &seed {
        assert!(recovered.contains(entry), "acknowledged record changed");
    }
    let stored = recovered.iter().find(|entry| entry.0 == key).map(|entry| &entry.1);
    assert!(stored.is_none() || stored == Some(&intended), "torn target record");
    if control {
        assert_eq!(stored, Some(&intended));
    }
    assert_eq!(db.load_candidate_payload_by_id(&id(3), TIMEOUT).unwrap().is_some(), control);
    let bootstrap = strict(&db); // Restores max(seqno)+1 before ANY retry.
    assert_eq!(bootstrap.votes.iter().find(|v| v.vote_hash == vote(1).vote_hash).unwrap().seqno, 0);
    assert_eq!(
        bootstrap.candidate_payloads.iter().find(|(candidate, _)| *candidate == id(1)).unwrap().1,
        b"acknowledged candidate"
    );
    assert_eq!(
        bootstrap.finalized_blocks.iter().find(|b| b.candidate_id == id(1)).unwrap().block_id,
        finalized(1).block_id
    );
    let (retry_key, retry_value, retry) = target(&db, kind);
    wait(retry).unwrap();
    db.close(Some(TIMEOUT)).unwrap();
    drop(db);
    let db = SimplexDb::open(&path, "session").unwrap();
    let recovered = raw(&db);
    for entry in seed {
        assert!(recovered.contains(&entry));
    }
    assert!(recovered.contains(&(retry_key, retry_value)), "retry bytes did not survive");
    let bootstrap = strict(&db);
    if kind == "finalized" {
        let entry = bootstrap.finalized_blocks.iter().find(|b| b.candidate_id == id(2)).unwrap();
        assert_eq!(entry.parent, Some(id(1)));
        assert_eq!(entry.block_id, finalized(2).block_id);
        assert!(entry.is_final);
    }
    db.close(Some(TIMEOUT)).unwrap();
    eprintln!("ENOSPC-CASE typed-{kind} {} ok", if control { "control" } else { "fault" });
}
#[test]
#[ignore = "requires isolated ENOSPC tmpfs and syscall trace"]
fn disk_full_typed_vote() {
    exercise("vote");
}
#[test]
#[ignore = "requires isolated ENOSPC tmpfs and syscall trace"]
fn disk_full_typed_cert() {
    exercise("cert");
}
#[test]
#[ignore = "requires isolated ENOSPC tmpfs and syscall trace"]
fn disk_full_typed_payload() {
    exercise("payload");
}
#[test]
#[ignore = "requires isolated ENOSPC tmpfs and syscall trace"]
fn disk_full_typed_finalized() {
    exercise("finalized");
}
