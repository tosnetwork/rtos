// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
#[path = "common/pq_finality.rs"]
mod fixture;
use rtos_api::{pq_finality::*, ton, IntoBoxed, WireProfile};
use rtos_block::*;
const DOMAIN: &str = "TOS-CONSENSUS-SIMPLEX-v1";

#[test]
fn target_network_finality_has_context_weight_and_no_legacy_codec() {
    let context = fixture::context(&fixture::config());
    let mut carrier = fixture::signed(&[1], "finalize", DOMAIN);
    // Wire carries no declared weight. It is recomputed from trusted members.
    carrier.sig_weight = u64::MAX;
    let network = PqNetworkSignatureSet::from_final_fields(&carrier).unwrap();
    let node = network.to_node().into_boxed();
    let bytes = WireProfile::T0.serialize(&node).unwrap();
    assert_eq!(&bytes[..4], &0x590da166u32.to_le_bytes());
    assert!(WireProfile::Legacy.serialize(&node).is_err());
    assert!(WireProfile::Legacy.deserialize(&bytes).is_err());
    let boxed: ton::ton_node::SignatureSet = WireProfile::T0.deserialize_typed(&bytes).unwrap();
    let ton::ton_node::SignatureSet::TonNode_SignatureSet_SimplexPq(parsed) = boxed else {
        panic!()
    };
    let parsed = PqNetworkSignatureSet::from_node(parsed).unwrap();
    let (final_carrier, verified) = context.verify_network(&parsed).unwrap().into_final().unwrap();
    assert_eq!(final_carrier.sig_weight, 2);
    assert_eq!(verified.weight(), 2);
    context.verify_final(&final_carrier).unwrap();
    assert!(context.verify_network(&parsed).unwrap().into_approval().is_err());

    let lite = network.to_lite().unwrap();
    let lite_bytes = WireProfile::T0.serialize(&lite.clone().into_boxed()).unwrap();
    assert_eq!(&lite_bytes[..4], &0xf9f0b390u32.to_le_bytes());
    assert!(WireProfile::Legacy.deserialize(&lite_bytes).is_err());
    context.verify_network(&PqNetworkSignatureSet::from_lite(lite).unwrap()).unwrap();
}

#[test]
fn network_roles_mutations_and_every_signature_are_checked() {
    let context = fixture::context(&fixture::config());
    let good =
        PqNetworkSignatureSet::from_final_fields(&fixture::signed(&[1, 0], "finalize", DOMAIN))
            .unwrap()
            .to_node();
    for mutation in 0..10 {
        let mut value = good.clone();
        match mutation {
            0 => value.final_ = ton::Bool::BoolFalse,
            1 => value.session_id = UInt256::from([0x71; 32]),
            2 => value.slot += 1,
            3 => value.cc_seqno += 1,
            4 => value.validator_set_hash ^= 1,
            5 => value.signatures[1].signature[0] ^= 1,
            6 => value.signatures[1].validator_id = UInt256::from([0x72; 32]),
            7 => value.signatures[1].algorithm_id = -1,
            8 => value.signatures[1].signature.pop().map(|_| ()).unwrap(),
            9 => value.signatures[1] = value.signatures[0].clone(),
            _ => unreachable!(),
        }
        let accepted = PqNetworkSignatureSet::from_node(value)
            .and_then(|value| context.verify_network(&value));
        assert!(accepted.is_err(), "mutation {mutation}");
    }
    let approval =
        PqApproval::from_notarization_fields(fixture::signed(&[1], "notarize", DOMAIN)).unwrap();
    let network = PqNetworkSignatureSet::from_approval(&approval).unwrap();
    assert!(!network.is_final());
    assert!(network.to_lite().is_err());
    assert!(context.verify_network(&network).is_err(), "masterchain must require final votes");
}

#[test]
fn network_resource_and_lite_inner_candidate_boundaries() {
    let good = PqNetworkSignatureSet::from_final_fields(&fixture::signed(&[1], "finalize", DOMAIN))
        .unwrap();
    let mut too_many = good.to_node();
    too_many.signatures = vec![too_many.signatures[0].clone(); 401];
    assert!(PqNetworkSignatureSet::from_node(too_many).unwrap_err().to_string().contains("count"));
    for mutation in 0..2 {
        let mut lite = good.to_lite().unwrap();
        if mutation == 0 {
            lite.candidate.push(0);
        } else {
            lite.candidate.resize(1025, 0);
        }
        assert!(PqNetworkSignatureSet::from_lite(lite).is_err());
    }
    let finality = ton::ton_node::broadcast::BlockFinalityBroadcast {
        id: fixture::block_id(),
        signature_set: good.to_node().into_boxed(),
    }
    .into_boxed();
    let bytes = WireProfile::T0.serialize(&finality).unwrap();
    assert_eq!(&bytes[..4], &0x8f4731efu32.to_le_bytes());
    assert!(WireProfile::T0.deserialize(&bytes).is_ok());
    assert!(WireProfile::Legacy.serialize(&finality).is_err());
}

#[test]
#[ignore = "exports public carriers for the isolated fixed-reference checked parser"]
fn export_checked_network_carriers() {
    use std::{fs, path::PathBuf};
    let out = PathBuf::from(std::env::var("RTOS_PQ_NETWORK_EXPORT").unwrap());
    fs::create_dir_all(&out).unwrap();
    let good =
        PqNetworkSignatureSet::from_final_fields(&fixture::signed(&[1, 0], "finalize", DOMAIN))
            .unwrap()
            .to_node();
    let mut manifest = String::new();
    for (name, value) in {
        let mut cases = vec![("final", good.clone())];
        let mut approve = good.clone();
        approve.final_ = ton::Bool::BoolFalse;
        cases.push(("approve", approve));
        let mut empty = good.clone();
        empty.signatures.clear();
        cases.push(("zero", empty));
        let mut max = good.clone();
        max.signatures = (0u32..400)
            .map(|i| {
                let mut pair = good.signatures[0].clone();
                let mut id = [0; 32];
                id[..4].copy_from_slice(&i.to_le_bytes());
                pair.validator_id = id.into();
                pair
            })
            .collect();
        cases.push(("max400", max.clone()));
        let mut parented = max.clone();
        let block = parented.candidate.block().clone();
        parented.candidate = ton::consensus::candidatehashdata::CandidateHashDataOrdinary {
            block,
            collated_file_hash: UInt256::default(),
            parent: ton::consensus::candidateparent::CandidateParent {
                id: ton::consensus::candidateid::CandidateId { slot: 98, hash: UInt256::default() }
                    .into_boxed(),
            }
            .into_boxed(),
        }
        .into_boxed();
        cases.push(("max400-parented", parented));
        max.signatures.push(good.signatures[0].clone());
        cases.push(("oversize401", max));
        for (name, algorithm) in [("negative-alg", -1), ("large-alg", 65536), ("wrong-alg", 2)] {
            let mut value = good.clone();
            value.signatures[0].algorithm_id = algorithm;
            cases.push((name, value));
        }
        let mut short = good.clone();
        short.signatures[0].signature.pop();
        cases.push(("short", short));
        let mut long = good.clone();
        long.signatures[0].signature.push(0);
        cases.push(("long", long));
        let mut duplicate = good.clone();
        duplicate.signatures.push(duplicate.signatures[0].clone());
        cases.push(("duplicate", duplicate));
        cases
    } {
        let accepted = PqNetworkSignatureSet::from_node(value.clone()).is_ok();
        let bytes = WireProfile::T0.serialize(&value.into_boxed()).unwrap();
        fs::write(out.join(format!("{name}.node")), &bytes).unwrap();
        manifest.push_str(&format!("{name}.node 0 {}\n", u8::from(accepted)));
    }
    let lite = PqNetworkSignatureSet::from_node(good).unwrap().to_lite().unwrap();
    for (name, value) in {
        let mut cases = vec![("final", lite.clone())];
        let mut trailing = lite.clone();
        trailing.candidate.extend_from_slice(&[0; 4]);
        cases.push(("inner-trailing", trailing));
        let mut large = lite.clone();
        large.candidate = vec![0; 1025];
        cases.push(("inner-oversize", large));
        let mut invalid = lite.clone();
        invalid.candidate[..4].fill(0);
        cases.push(("inner-invalid", invalid));
        cases
    } {
        let accepted = PqNetworkSignatureSet::from_lite(value.clone()).is_ok();
        fs::write(
            out.join(format!("{name}.lite")),
            WireProfile::T0.serialize(&value.into_boxed()).unwrap(),
        )
        .unwrap();
        manifest.push_str(&format!("{name}.lite 1 {}\n", u8::from(accepted)));
    }
    fs::write(out.join("cases.txt"), manifest).unwrap();
}
