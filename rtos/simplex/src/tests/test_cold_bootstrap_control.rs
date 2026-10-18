use super::*;
use crate::database::{CandidateInfoRecord, FinalCertRecord};
use rtos_api::IntoBoxed;
use rtos_block::{BlockIdExt, ShardIdent};

// Selector/memory scope tests only. Real body/certificate authentication is
// exercised by startup/receiver regressions and the separate actual-node case.
fn fixture(control: &Path, slot: u32) -> (SessionDescription, Bootstrap, RawCandidateId, Vec<u8>) {
    let description = crate::authenticated_fixture::description(true);
    let runtime = description.authenticated_runtime().unwrap();
    let data =
        b"scope-only block bytes; consensus authentication is a separate caller gate".to_vec();
    let collated = b"scope-only collated bytes".to_vec();
    let block = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        1,
        UInt256::calc_file_hash(b"root"),
        UInt256::calc_file_hash(&data),
    );
    let metadata = rtos_api::ton::consensus::candidatehashdata::CandidateHashDataOrdinary {
        block: block.clone(),
        collated_file_hash: UInt256::calc_file_hash(&collated),
        parent: rtos_api::ton::consensus::CandidateParent::Consensus_CandidateWithoutParents,
    }
    .into_boxed();
    let id = RawCandidateId {
        slot: SlotIndex::new(slot),
        hash: UInt256::calc_file_hash(&rtos_api::serialize_boxed(&metadata).unwrap()),
    };
    let inner = rtos_api::ton::validator_session::candidate::Candidate {
        src: UInt256::default(),
        round: 1,
        root_hash: block.root_hash().clone(),
        data,
        collated_data: collated,
    }
    .into_boxed();
    let payload = rtos_api::serialize_boxed(
        &rtos_api::ton::consensus::candidatedata::Block {
            slot: slot as i32,
            candidate: rtos_api::serialize_boxed(&inner).unwrap(),
            parent: rtos_api::ton::consensus::CandidateParent::Consensus_CandidateWithoutParents,
            signature: vec![],
        }
        .into_boxed(),
    )
    .unwrap();
    let namespace = runtime.runtime_directory("/original/db").unwrap();
    let selector = serde_json::json!({"schema":1,"session_id":runtime.session_id().to_hex_string(),
        "profile":runtime.profile().to_hex_string(),"local_adnl":UInt256::from(*runtime.local_adnl().data()).to_hex_string(),
        "local_validator_index":0,"global_id":runtime.pin().global_id,"zerostate":runtime.pin().zerostate.to_string(),
        "namespace":namespace,"slot":slot,"candidate_hash":id.hash.to_hex_string()});
    std::fs::write(control.join("selector.json"), serde_json::to_vec(&selector).unwrap()).unwrap();
    let info = CandidateInfoRecord {
        candidate_id: id.clone(),
        leader_idx: description.get_leader(id.slot).value(),
        candidate_hash_data: metadata,
        signature: vec![],
    };
    let mut bootstrap = Bootstrap::default();
    bootstrap.candidate_infos.push(info);
    bootstrap.final_certs.push(FinalCertRecord { candidate_id: id.clone(), cert_bytes: vec![1] });
    bootstrap.candidate_payloads.push((id.clone(), payload.clone()));
    (description, bootstrap, id, payload)
}
fn change(control: &Path, key: &str, value: serde_json::Value) {
    let path = control.join("selector.json");
    let mut selector: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    selector[key] = value;
    std::fs::write(path, serde_json::to_vec(&selector).unwrap()).unwrap();
}
#[test]
fn cold_body_scope_keeps_metadata_certificates_and_source_bytes() {
    let root = crate::authenticated_fixture::TestDirectory::new();
    let (description, mut bootstrap, id, payload) = fixture(root.path(), 4);
    let other = RawCandidateId { slot: SlotIndex::new(5), hash: UInt256::calc_file_hash(b"other") };
    bootstrap.candidate_payloads.push((other.clone(), b"untouched".to_vec()));
    assert!(apply(root.path(), &description, &mut bootstrap).unwrap());
    assert_eq!(bootstrap.candidate_payloads, vec![(other, b"untouched".to_vec())]);
    assert_eq!(bootstrap.candidate_infos.len(), 1);
    assert_eq!(bootstrap.final_certs.len(), 1);
    assert_eq!(std::fs::read(root.path().join("payload-before.bin")).unwrap(), payload);
    assert!(
        !apply(root.path(), &description, &mut bootstrap).unwrap(),
        "one cold application per selected process"
    );
    let digest = UInt256::calc_file_hash(&payload);
    assert!(record_delivery_at(
        root.path(),
        description.get_session_id(),
        id.slot,
        &id.hash,
        Some((payload.len(), UInt256::default()))
    )
    .is_err());
    assert!(!root.path().join("delivered.json").exists());
    record_delivery_at(
        root.path(),
        description.get_session_id(),
        id.slot,
        &id.hash,
        Some((payload.len(), digest)),
    )
    .unwrap();
    assert_eq!(
        std::fs::read(root.path().join("applied.json")).unwrap(),
        std::fs::read(root.path().join("delivered.json")).unwrap()
    );
}
#[test]
fn cold_body_scope_refuses_own_missing_duplicate_and_wrong_domain() {
    for mode in [
        "own",
        "missing",
        "duplicate",
        "certificate",
        "metadata",
        "empty",
        "body_header",
        "profile",
        "adnl",
        "namespace",
    ] {
        let root = crate::authenticated_fixture::TestDirectory::new();
        let (description, mut bootstrap, id, payload) =
            fixture(root.path(), if mode == "own" { 0 } else { 4 });
        match mode {
            "missing" => bootstrap.candidate_payloads.clear(),
            "duplicate" => bootstrap.candidate_payloads.push((id, payload)),
            "certificate" => bootstrap.final_certs.clear(),
            "metadata" => bootstrap.candidate_infos.clear(),
            "empty" => {
                let block = bootstrap.candidate_infos[0].candidate_hash_data.block().clone();
                bootstrap.candidate_infos[0].candidate_hash_data =
                    rtos_api::ton::consensus::candidatehashdata::CandidateHashDataEmpty {
                        block,
                        parent: rtos_api::ton::consensus::candidateid::CandidateId {
                            slot: 3,
                            hash: UInt256::default(),
                        },
                    }
                    .into_boxed();
            }
            "body_header" => {
                let rtos_api::ton::consensus::CandidateHashData::Consensus_CandidateHashDataOrdinary(info)=&mut bootstrap.candidate_infos[0].candidate_hash_data else {unreachable!()};
                info.block = BlockIdExt::default();
            }
            "profile" => change(root.path(), "profile", serde_json::json!("wrong")),
            "adnl" => change(root.path(), "local_adnl", serde_json::json!("wrong")),
            "namespace" => change(root.path(), "namespace", serde_json::json!("/wrong/namespace")),
            _ => {}
        }
        let before = bootstrap.candidate_payloads.clone();
        assert!(apply(root.path(), &description, &mut bootstrap).is_err(), "{mode}");
        assert_eq!(bootstrap.candidate_payloads, before);
        assert!(!root.path().join("applied.json").exists());
    }
}
#[test]
fn cold_body_control_is_bounded_and_unrelated_sessions_are_unchanged() {
    for mode in ["oversized", "symlink", "other-session"] {
        let root = crate::authenticated_fixture::TestDirectory::new();
        let (description, mut bootstrap, _, _) = fixture(root.path(), 4);
        let path = root.path().join("selector.json");
        if mode == "oversized" {
            File::create(&path).unwrap().set_len(MAX_CONTROL + 1).unwrap();
        } else if mode == "symlink" {
            std::fs::rename(&path, root.path().join("actual.json")).unwrap();
            std::os::unix::fs::symlink(root.path().join("actual.json"), &path).unwrap();
        } else {
            change(
                root.path(),
                "session_id",
                serde_json::json!(UInt256::calc_file_hash(b"other session").to_hex_string()),
            );
        }
        let before = bootstrap.candidate_payloads.clone();
        let result = apply(root.path(), &description, &mut bootstrap);
        if mode == "other-session" {
            assert!(!result.unwrap());
        } else {
            assert!(result.is_err());
        }
        assert_eq!(bootstrap.candidate_payloads, before);
        assert!(!root.path().join("applied.json").exists());
    }
}
