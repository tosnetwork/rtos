// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use rtos_api::session_identity::*;
use rtos_block::*;
use std::str::FromStr;

fn u256(s: &str) -> UInt256 {
    UInt256::from_str(s).unwrap()
}
fn pq(id: u8, key: u8, adnl: u8, weight: u64) -> ValidatorDescr {
    ValidatorDescr::with_pq_params(
        UInt256::from([id; 32]),
        PqConsensusKey {
            algorithm_id: 1,
            key_id: UInt256::from([key; 32]),
            public_key: vec![1; 1312],
        },
        weight,
        UInt256::from([adnl; 32]),
    )
}
fn coordinates(shard: &ShardIdent) -> SessionCoordinates<'_> {
    SessionCoordinates {
        shard,
        catchain_seqno: 1,
        vertical_seqno: 0,
        last_key_block_seqno: 0,
        new_catchain_ids: true,
    }
}
#[test]
fn fixed_cpp_member_and_group_bytes() {
    let shard = ShardIdent::full(0);
    for line in include_str!("data/validator-session-vectors.txt").lines() {
        let f: Vec<_> = line.split_whitespace().collect();
        assert_eq!(f.len(), 5);
        let member = match f[0] {
            "classical" => ValidatorDescr::with_params(
                SigPubKey::from_bytes(&[0x11; 32]).unwrap(),
                5,
                Some(UInt256::from([0xc0; 32])),
            ),
            "pq-a-key1" => pq(0xa0, 0xb0, 0xc0, 5),
            "pq-a-key2" => pq(0xa0, 0xb1, 0xc0, 5),
            other => panic!("unexpected vector {other}"),
        };
        let members = session_members(&[member.clone()]).unwrap();
        let member_bytes = rtos_api::serialize_boxed(&members[0]).unwrap();
        assert_eq!(
            u32::from_le_bytes(member_bytes[..4].try_into().unwrap()),
            u32::from_str_radix(f[1], 16).unwrap()
        );
        assert_eq!(hex::encode(member_bytes), f[2]);
        let bytes =
            session_group_bytes(coordinates(&shard), &UInt256::default(), &[member]).unwrap();
        assert_eq!(hex::encode(&bytes), f[3]);
        assert_eq!(UInt256::calc_file_hash(&bytes), u256(f[4]));
        assert!(decode_session_group(&bytes).is_ok());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_session_group(&trailing).is_err());
    }
}
#[test]
fn fixed_cpp_full_derivation_and_context_separation() {
    let text = include_str!("data/validator-session-derivation-vectors.tsv");
    let f: Vec<_> = text.lines().nth(1).unwrap().split('\t').collect();
    assert_eq!(f.len(), 15);
    let cell = read_single_root_boc(hex::decode(f[2]).unwrap()).unwrap();
    assert_eq!(cell.repr_hash(), &u256(f[3]));
    let shard =
        ShardIdent::with_tagged_prefix(f[4].parse().unwrap(), f[5].parse().unwrap()).unwrap();
    let coords = SessionCoordinates {
        shard: &shard,
        vertical_seqno: f[6].parse().unwrap(),
        last_key_block_seqno: f[7].parse().unwrap(),
        catchain_seqno: f[8].parse().unwrap(),
        new_catchain_ids: true,
    };
    let member = pq(0xa1, 0xb2, 0xc3, 23);
    let options = u256(f[1]);
    let baseline =
        derive_session_identity(-239, &options, &cell, coords, &[member.clone()]).unwrap();
    assert_eq!(baseline.config_hash, u256(f[13]));
    assert_eq!(baseline.session_id, u256(f[14]));
    let changed_cell =
        SimplexConfig { slots_per_leader_window: 5, protocol_version: 2, ..Default::default() }
            .serialize()
            .unwrap();
    for change in 0..10 {
        let mut c = coords;
        let mut v = member.clone();
        let mut o = options.clone();
        let mut global = -239;
        let mut selected = &cell;
        match change {
            0 => global = -238,
            1 => o = UInt256::from([7; 32]),
            2 => selected = &changed_cell,
            3 => c.catchain_seqno += 1,
            4 => c.vertical_seqno += 1,
            5 => c.last_key_block_seqno += 1,
            6 => c.new_catchain_ids = false,
            7 => v = pq(0xa2, 0xb2, 0xc3, 23),
            8 => v = pq(0xa1, 0xb3, 0xc3, 23),
            9 => v.adnl_addr = Some(UInt256::from([0xc4; 32])),
            _ => unreachable!(),
        }
        assert_ne!(
            baseline.session_id,
            derive_session_identity(global, &o, selected, c, &[v]).unwrap().session_id,
            "change {change}"
        );
    }
    // This vector deliberately has an arbitrary key ID: deriving bytes is not admission.
    assert!(member.validate_consensus().is_err());
}
#[test]
fn constructor_selection_and_unsigned_coordinates() {
    use rtos_api::{
        ton::validator::group::{Group, GroupEx, GroupNew},
        Constructor,
    };
    let shard = ShardIdent::full(0);
    let mut c = coordinates(&shard);
    c.catchain_seqno = u32::MAX;
    c.last_key_block_seqno = u32::MAX;
    for (new, vertical, ctor) in [
        (false, 0, Group::constructor_const()),
        (false, u32::MAX, GroupEx::constructor_const()),
        (true, u32::MAX, GroupNew::constructor_const()),
    ] {
        c.new_catchain_ids = new;
        c.vertical_seqno = vertical;
        let bytes = session_group_bytes(c, &UInt256::default(), &[pq(1, 2, 3, 1)]).unwrap();
        assert_eq!(u32::from_le_bytes(bytes[..4].try_into().unwrap()), ctor);
        assert!(decode_session_group(&bytes).is_ok());
    }
}
fn config29() -> ConsensusConfig {
    ConsensusConfig {
        round_candidates: 3,
        next_candidate_delay_ms: 2000,
        consensus_timeout_ms: 16000,
        fast_attempts: 4,
        attempt_duration: 16,
        catchain_max_deps: 4,
        max_block_bytes: 4 << 20,
        max_collated_bytes: 4 << 20,
        ..Default::default()
    }
}
#[test]
fn fixed_cpp_default_options_hash() {
    let bytes = session_options_bytes(&config29(), &CatchainConfig::default()).unwrap();
    assert_eq!(
        UInt256::calc_file_hash(&bytes),
        u256("39100EBB777D270D83451103F9C9A9D81AAB4B13CD42D7A069A44F9DAA9B48D1")
    );
}
#[test]
fn options_preserve_unsigned_fields_and_wide_product() {
    let mut config = config29();
    config.proto_version = 2;
    config.catchain_max_blocks_coeff = u32::MAX;
    config.max_block_bytes = u32::MAX;
    let cc = CatchainConfig { mc_catchain_lifetime: u32::MAX, ..Default::default() };
    let bytes = session_options_bytes(&config, &cc).unwrap();
    let boxed = rtos_api::deserialize_boxed(&bytes).unwrap();
    let opts = boxed.downcast::<rtos_api::ton::validator_session::Config>().unwrap();
    match opts {
        rtos_api::ton::validator_session::Config::ValidatorSession_ConfigVersionedV2(v) => {
            assert_eq!(v.max_block_size, -1);
            assert_eq!(*v.catchain_opts.max_block_height_ceoff(), 1);
        }
        _ => panic!("versioned V2 options expected"),
    }
    config.use_quic = true;
    assert_eq!(
        session_options_bytes(&config, &cc).unwrap(),
        bytes,
        "transport is not a Param29 TL option field"
    );
}

fn config_with_raw_cells(mc: Cell, shard: Cell) -> ConfigParams {
    let mut wrapper = BuilderData::new();
    wrapper.append_u8(0x10).unwrap();
    wrapper.append_bit_one().unwrap();
    wrapper.checked_append_reference(mc).unwrap();
    wrapper.append_bit_one().unwrap();
    wrapper.checked_append_reference(shard).unwrap();
    let mut value = BuilderData::new();
    value.checked_append_reference(wrapper.into_cell().unwrap()).unwrap();
    let mut config = ConfigParams::default();
    config.config_params.set_builder(30u32.write_to_bitstring().unwrap(), &value).unwrap();
    config.set_config(ConfigParamEnum::ConfigParam29(config29())).unwrap();
    config.set_config(ConfigParamEnum::ConfigParam28(CatchainConfig::default())).unwrap();
    config
}
#[test]
fn governing_config_binds_original_cell_and_selects_branch() {
    let sparse =
        read_single_root_boc(hex::decode("b5ee9c7201010101000900000d22040000000440").unwrap())
            .unwrap();
    let reencoded =
        SimplexConfig::construct_from_cell(sparse.clone()).unwrap().serialize().unwrap();
    assert_ne!(sparse.repr_hash(), reencoded.repr_hash());
    let mut config = config_with_raw_cells(sparse.clone(), reencoded.clone());
    let key = vec![7; 1312];
    let member = ValidatorDescr::with_pq_params(
        UInt256::from([1; 32]),
        PqConsensusKey {
            algorithm_id: 1,
            key_id: derive_consensus_key_id(1, &key),
            public_key: key,
        },
        1,
        UInt256::from([2; 32]),
    );
    let mc = ShardIdent::masterchain();
    let shard = ShardIdent::full(0);
    let options = UInt256::calc_file_hash(
        &session_options_bytes(&config29(), &CatchainConfig::default()).unwrap(),
    );
    for (id, cell) in [(&mc, &sparse), (&shard, &reencoded)] {
        let actual =
            derive_session_from_config(-239, &config, coordinates(id), &[member.clone()]).unwrap();
        let mut c = coordinates(id);
        c.new_catchain_ids = false; // chain Param29 overrides caller coordinates
        assert_eq!(
            actual,
            derive_session_identity(-239, &options, cell, c, &[member.clone()]).unwrap()
        );
    }
    let original =
        derive_session_from_config(-239, &config, coordinates(&mc), &[member.clone()]).unwrap();
    let mut p29 = config29();
    p29.new_catchain_ids = true;
    config.set_config(ConfigParamEnum::ConfigParam29(p29)).unwrap();
    assert_ne!(
        original.session_id,
        derive_session_from_config(-239, &config, coordinates(&mc), &[member.clone()])
            .unwrap()
            .session_id
    );
    let mut bad = member.clone();
    bad.adnl_addr = None;
    assert!(derive_session_from_config(-239, &config, coordinates(&mc), &[bad]).is_err());
    config.set_config(ConfigParamEnum::ConfigParam30(NewConsensusConfigAll::default())).unwrap();
    assert!(derive_session_from_config(-239, &config, coordinates(&mc), &[member]).is_err());
}
#[test]
fn rejects_legacy_constructor_trailing_and_resource_overflow() {
    let shard = ShardIdent::full(0);
    let mut bytes =
        session_group_bytes(coordinates(&shard), &UInt256::default(), &[pq(1, 2, 3, 1)]).unwrap();
    bytes[60..64].copy_from_slice(&65536u32.to_le_bytes());
    assert!(decode_session_group(&bytes).is_err());
    bytes[..4].copy_from_slice(&0x9843a14du32.to_le_bytes());
    assert!(decode_session_group(&bytes).is_err());
    assert!(decode_session_group(&[1, 2, 3]).is_err());
}

#[test]
fn fixed_reference_versioned_options_hash() {
    // The inherited reference-client session-options fixture, also checked by
    // the node's historical options test. This call exercises the canonical API.
    let mut config = config29();
    config.proto_version = 4;
    config.new_catchain_ids = true;
    config.fast_attempts = 3;
    config.attempt_duration = 8;
    config.max_block_bytes = 2097152;
    config.max_collated_bytes = 2097152;
    config.catchain_max_blocks_coeff = 2500000;
    let catchain = CatchainConfig { mc_catchain_lifetime: 1, ..Default::default() };
    let hash = UInt256::calc_file_hash(&session_options_bytes(&config, &catchain).unwrap());
    assert_eq!(base64_encode(hash), "zGHYA323cMOmXestPYStZs5hVCDfOY2mdQm2l9zF4Bo=");
}
