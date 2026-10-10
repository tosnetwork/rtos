/*
 * Copyright (C) 2019-2024 EverX. All Rights Reserved.
 * Modifications Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This file has been modified from its original version.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use super::*;
use crate::{
    blocks::Block, config_params::ConfigParamEnum, merkle_proof::MerkleProof,
    signature::BlockProof, write_read_and_assert, Ed25519KeyOption, ShardIdent, ZeroizingBytes,
    BASE_WORKCHAIN_ID, MASTERCHAIN_ID,
};

#[test]
fn test_validator_info_new_default() {
    let vi = ValidatorInfo::default();
    let vi2 = ValidatorInfo::default();

    assert_eq!(vi, vi2);
    write_read_and_assert(vi);
}

#[test]
fn test_validator_info_new_with() {
    let vi = ValidatorInfo::with_params(1, 2, false);

    assert_ne!(vi, ValidatorInfo::with_params(3, 2, true));
    write_read_and_assert(vi);
}

#[test]
fn test_validator_base_info_new_default() {
    let vi = ValidatorBaseInfo::new();
    let vi2 = ValidatorBaseInfo::default();

    assert_eq!(vi, vi2);
    write_read_and_assert(vi);
}

#[test]
fn test_validator_base_info_new_with() {
    let vi = ValidatorBaseInfo::with_params(1, 2);

    assert_ne!(vi, ValidatorBaseInfo::with_params(3, 2));
    write_read_and_assert(vi);
}

#[test]
fn test_validator_desc_new_default() {
    let vd = ValidatorDescr::new();
    let vd2 = ValidatorDescr::default();

    assert_eq!(vd, vd2);
    write_read_and_assert(vd);
}

#[test]
fn test_validator_desc_info_new_with() {
    let keypair = Ed25519KeyOption::<ZeroizingBytes>::generate().unwrap();
    let key = SigPubKey::from_bytes(keypair.pub_key().unwrap()).unwrap();
    let vd = ValidatorDescr::with_params(key.clone(), 2121212121, None);

    assert_ne!(vd, ValidatorDescr::with_params(key, 2, None));
    write_read_and_assert(vd);
}

#[test]
fn test_validator_set_serialize() {
    let mut list = vec![];
    for n in 0..20 {
        let keypair = Ed25519KeyOption::<ZeroizingBytes>::generate().unwrap();
        let key = SigPubKey::from_bytes(keypair.pub_key().unwrap()).unwrap();
        let vd = ValidatorDescr::with_params(key, n + 1, None);
        list.push(vd);
    }

    let vset = ValidatorSet::new(0, 100, 1, list).unwrap();

    write_read_and_assert(vset);
}

fn check_block_proof(key_block_file_name: &str, proof_file_name: &str) {
    let key_block = Block::construct_from_file(key_block_file_name).unwrap();
    let proof = BlockProof::construct_from_file(proof_file_name).unwrap();

    let merkle_proof = MerkleProof::construct_from_cell(proof.root.clone()).unwrap();
    let block_virt_root = merkle_proof.proof.virtualize(1);
    let virt_block = Block::construct_from_cell(block_virt_root).unwrap();

    let config =
        key_block.read_extra().unwrap().read_custom().unwrap().unwrap().config().unwrap().clone();

    let cp34 = config.config(34).unwrap().unwrap();
    let cur_validator_set = if let ConfigParamEnum::ConfigParam34(vs) = cp34 {
        vs.cur_validators
    } else {
        unreachable!()
    };

    let cp28 = config.config(28).unwrap().unwrap();
    let cc_config =
        if let ConfigParamEnum::ConfigParam28(ccc) = cp28 { ccc } else { unreachable!() };

    let virt_info = virt_block.read_info().unwrap();

    let (validators, hash_short) = cur_validator_set
        .calc_subset(
            &cc_config,
            proof.proof_for.shard_id.shard_prefix_with_tag(),
            proof.proof_for.shard_id.workchain_id(),
            proof
                .signatures
                .as_ref()
                .map(|s| s.validator_info().catchain_seqno)
                .unwrap_or_else(|| virt_info.gen_catchain_seqno()),
        )
        .unwrap();

    if let Some(signatures) = proof.signatures.as_ref() {
        assert_eq!(signatures.validator_info().catchain_seqno, virt_info.gen_catchain_seqno());

        assert_eq!(signatures.validator_info().validator_list_hash_short, hash_short);

        let pure_signatures = signatures.pure_signatures();

        let data =
            Block::build_data_for_sign(&proof.proof_for.root_hash, &proof.proof_for.file_hash);
        let weight = pure_signatures.check_signatures(&validators, &data).unwrap();
        assert_eq!(weight, pure_signatures.weight());
    } else {
        assert_eq!(virt_info.gen_validator_list_hash_short(), hash_short);
    }
}

#[test]
fn test_calc_mc_subset() {
    check_block_proof(
        "src/tests/data/test_calc_subset/key_block__no_shuffle",
        "src/tests/data/test_calc_subset/proof__no_shuffle",
    );
}

#[test]
fn test_calc_mc_subset_shuffle() {
    check_block_proof(
        "src/tests/data/test_calc_subset/key_block__shuffle",
        "src/tests/data/test_calc_subset/proof__shuffle",
    );
}

#[test]
fn test_calc_shard_subset() {
    check_block_proof(
        "src/tests/data/test_calc_shard_subset/key_block",
        "src/tests/data/test_calc_shard_subset/proof_4377252",
    );
}

#[test]
fn test_isolate_mc_validators() {
    let key_block =
        Block::construct_from_file("src/tests/data/test_calc_subset/key_block__shuffle").unwrap();
    let config =
        key_block.read_extra().unwrap().read_custom().unwrap().unwrap().config().unwrap().clone();

    let cp34 = config.config(34).unwrap().unwrap();
    let cur_validator_set = if let ConfigParamEnum::ConfigParam34(vs) = cp34 {
        vs.cur_validators
    } else {
        unreachable!()
    };

    let cp28 = config.config(28).unwrap().unwrap();
    let mut cc_config =
        if let ConfigParamEnum::ConfigParam28(ccc) = cp28 { ccc } else { unreachable!() };
    cc_config.isolate_mc_validators = true;

    // calc subsets for shardes and check it does not contain main validators

    let (main_validators, _) = cur_validator_set
        .calc_subset(
            &cc_config,
            ShardIdent::masterchain().shard_prefix_with_tag(),
            MASTERCHAIN_ID,
            123,
        )
        .unwrap();

    println!("main validators");
    for v in main_validators.iter() {
        println!("{:x}", v.adnl_addr.as_ref().unwrap());
    }

    for shard in 0..16 {
        let shard =
            ShardIdent::with_tagged_prefix(BASE_WORKCHAIN_ID, (shard << 60) | (8 << 56)).unwrap();
        let (shard_validators, _) = cur_validator_set
            .calc_subset(&cc_config, shard.shard_prefix_with_tag(), BASE_WORKCHAIN_ID, 123)
            .unwrap();

        println!("shard {} validators", shard);
        for v in shard_validators.iter() {
            println!("{:x}", v.adnl_addr.as_ref().unwrap());
        }

        for sv in shard_validators.iter() {
            for mv in main_validators.iter() {
                assert_ne!(sv.public_key, mv.public_key)
            }
        }
    }
}

#[test]
fn test_validator_set_weight_admission() {
    let make = |weight| {
        let key = Ed25519KeyOption::<ZeroizingBytes>::generate().unwrap();
        ValidatorDescr::with_params(
            SigPubKey::from_bytes(key.pub_key().unwrap()).unwrap(),
            weight,
            None,
        )
    };
    let cap = crate::MAX_TOTAL_VALIDATOR_WEIGHT;
    let valid = vec![make(cap - 1), make(1)];
    assert_eq!(ValidatorSet::new(0, 100, 1, valid.clone()).unwrap().total_weight(), cap);
    assert!(ValidatorSet::new(0, 100, 1, vec![make(cap), make(1)]).is_err());
    assert!(ValidatorSet::new(0, 100, 1, vec![make(0)]).is_err());
    assert!(ValidatorSet::new(0, 100, 1, vec![valid[0].clone(), valid[0].clone()]).is_err());
    assert!(ValidatorSet::with_values_version_2(0, 100, 1, cap - 1, valid).is_err());

    // Exercise deserialization independently of the checked constructor.
    for weights in [[0, 1], [cap, 1], [u64::MAX, 1]] {
        let mut map = ValidatorDescriptions::default();
        map.set(&0u16, &make(weights[0])).unwrap();
        map.set(&1u16, &make(weights[1])).unwrap();
        let mut b = BuilderData::new();
        b.append_u8(0x12).unwrap();
        b.append_u32(0).unwrap();
        b.append_u32(100).unwrap();
        b.append_u16(2).unwrap();
        b.append_u16(1).unwrap();
        b.append_u64(weights[0].wrapping_add(weights[1])).unwrap();
        map.write_to(&mut b).unwrap();
        assert!(ValidatorSet::construct_from_cell(b.into_cell().unwrap()).is_err());
    }
}
