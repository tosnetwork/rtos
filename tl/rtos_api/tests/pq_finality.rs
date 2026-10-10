// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
#[path = "common/pq_finality.rs"]
mod fixture;
use rtos_api::pq_finality::*;
use rtos_block::*;
const DOMAIN: &str = "TOS-CONSENSUS-SIMPLEX-v1";

#[test]
fn ordinary_candidates_with_boxed_parent_are_verified() {
    let context = fixture::context(&fixture::config());
    let data: serde_json::Value =
        serde_json::from_str(include_str!("data/pq-finality.json")).unwrap();
    for row in data["additional_candidates"].as_array().unwrap() {
        let mut carrier = fixture::signed(&[1], "finalize", DOMAIN);
        let bytes = hex::decode(row["candidate"].as_str().unwrap()).unwrap();
        carrier.candidate_data = BlockSignaturesSimplex::bytes_to_cell_tree(&bytes).unwrap();
        carrier.signatures[0].signature = hex::decode(row["signature"].as_str().unwrap()).unwrap();
        assert_eq!(
            hex::encode(final_vote_preimage(&fixture::block_id(), &carrier).unwrap()),
            row["preimage"].as_str().unwrap()
        );
        context.verify_final(&carrier).unwrap();
        if row["name"] == "ordinary-parent" {
            assert_eq!(bytes.len(), 160);
            let mut missing_constructor = bytes.clone();
            missing_constructor.drain(120..124);
            carrier.candidate_data =
                BlockSignaturesSimplex::bytes_to_cell_tree(&missing_constructor).unwrap();
            assert!(context.verify_final(&carrier).is_err());
        }
    }
}

#[test]
fn final_signatures_match_independent_preimage_and_exact_quorum() {
    let context = fixture::context(&fixture::config());
    let data: serde_json::Value =
        serde_json::from_str(include_str!("data/pq-finality.json")).unwrap();
    for indices in [&[1][..], &[0, 1][..]] {
        let carrier = fixture::signed(indices, "finalize", DOMAIN);
        assert_eq!(
            hex::encode(final_vote_preimage(&fixture::block_id(), &carrier).unwrap()),
            data["signatures"][0]["preimage"].as_str().unwrap()
        );
        let result = context.verify_final(&carrier).unwrap();
        assert_eq!(result.weight(), carrier.sig_weight);
        assert_eq!(result.block_id(), &fixture::block_id());
        assert_eq!(result.session_id(), &carrier.session_id);
        assert_eq!(result.slot(), 99);
        let decoded =
            BlockSignaturesSimplexPq::construct_from_bytes(&carrier.write_to_bytes().unwrap())
                .unwrap();
        context.verify_final(&decoded).unwrap();
    }
    for indices in [&[][..], &[0][..]] {
        assert!(context
            .verify_final(&fixture::signed(indices, "finalize", DOMAIN))
            .unwrap_err()
            .to_string()
            .contains("insufficient verified weight"));
    }
}

#[test]
fn roles_context_and_all_signers_are_verified() {
    let context = fixture::context(&fixture::config());
    for (role, domain) in [("notarize", DOMAIN), ("finalize", "TOS-AUTH-ML-DSA-44-v1")] {
        assert!(context
            .verify_final(&fixture::signed(&[1], role, domain))
            .unwrap_err()
            .to_string()
            .contains("invalid final signature"));
    }
    // A valid quorum cannot conceal an extra invalid signature.
    let mut carrier = fixture::signed(&[1, 0], "finalize", DOMAIN);
    carrier.signatures[1].signature[0] ^= 1;
    assert!(context
        .verify_final(&carrier)
        .unwrap_err()
        .to_string()
        .contains("invalid final signature"));
}

#[test]
fn carrier_identity_weight_and_candidate_mutations_are_rejected() {
    let context = fixture::context(&fixture::config());
    let good = fixture::signed(&[1], "finalize", DOMAIN);
    for mutation in 0..11 {
        let mut carrier = good.clone();
        match mutation {
            0 => carrier.session_id = UInt256::default(),
            1 => carrier.validator_info.catchain_seqno += 1,
            2 => carrier.validator_info.validator_list_hash_short ^= 1,
            3 => carrier.sig_weight += 1,
            4 => carrier.slot += 1,
            5 => carrier.signatures[0].validator_id = UInt256::from([9; 32]),
            6 => carrier.signatures[0].validator_id = UInt256::from([1; 32]),
            7 => carrier.signatures[0].algorithm_id = 2,
            8 => {
                carrier.signatures[0].signature.pop();
            }
            9 => {
                carrier.signatures.push(carrier.signatures[0].clone());
                carrier.sig_count = 2;
                carrier.sig_weight = 4;
            }
            10 => {
                let mut bytes = carrier.candidate_bytes().unwrap();
                bytes[119] ^= 1;
                carrier.candidate_data = BuilderData::with_raw(bytes.clone(), bytes.len() * 8)
                    .unwrap()
                    .into_cell()
                    .unwrap();
            }
            _ => unreachable!(),
        }
        assert!(context.verify_final(&carrier).is_err(), "mutation {mutation}");
    }
    let id = fixture::block_id();
    for changed in [
        BlockIdExt::with_params(
            ShardIdent::full(0),
            id.seq_no,
            id.root_hash.clone(),
            id.file_hash.clone(),
        ),
        BlockIdExt::with_params(
            id.shard().clone(),
            id.seq_no + 1,
            id.root_hash.clone(),
            id.file_hash.clone(),
        ),
        BlockIdExt::with_params(
            id.shard().clone(),
            id.seq_no,
            UInt256::default(),
            id.file_hash.clone(),
        ),
        BlockIdExt::with_params(
            id.shard().clone(),
            id.seq_no,
            id.root_hash.clone(),
            UInt256::default(),
        ),
    ] {
        assert!(final_vote_preimage(&changed, &good)
            .unwrap_err()
            .to_string()
            .contains("candidate block id mismatch"));
    }
}

#[test]
fn governing_config_rotation_and_global_id_cannot_be_substituted() {
    let config = fixture::config();
    let good = fixture::signed(&[1], "finalize", DOMAIN);
    assert!(PqVerificationContext::from_governing_config(
        0,
        &config,
        fixture::block_id(),
        1,
        10,
        7
    )
    .is_err());
    for mutation in 0..6 {
        let mut config = config.clone();
        let mut vertical = 1;
        let mut previous_key = 10;
        match mutation {
            0 => {
                config.set_config(ConfigParamEnum::ConfigParam19(0)).unwrap();
            }
            1 => {
                let mut c = config.consensus_config().unwrap();
                c.next_candidate_delay_ms += 1;
                config.set_config(ConfigParamEnum::ConfigParam29(c)).unwrap();
            }
            2 => {
                let mut c = SimplexConfig::default();
                c.protocol_version = 2;
                config
                    .set_config(ConfigParamEnum::ConfigParam30(NewConsensusConfigAll {
                        mc: Some(c.clone()),
                        shard: Some(c),
                    }))
                    .unwrap();
            }
            3 => {
                let old = config.validator_set().unwrap();
                let mut list = old.list().to_vec();
                list.reverse();
                config
                    .set_config(ConfigParamEnum::ConfigParam35(ConfigParam35 {
                        cur_temp_validators: ValidatorSet::new(0, 100000, 2, list).unwrap(),
                    }))
                    .unwrap();
            }
            4 => vertical += 1,
            5 => previous_key += 1,
            _ => unreachable!(),
        }
        let result = PqVerificationContext::from_governing_config(
            -239,
            &config,
            fixture::block_id(),
            vertical,
            previous_key,
            7,
        )
        .and_then(|context| context.verify_final(&good));
        assert!(result.is_err(), "governing mutation {mutation}");
    }
}
