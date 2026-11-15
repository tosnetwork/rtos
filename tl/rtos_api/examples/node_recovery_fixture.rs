// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
// Synthetic, public-key test history for actual node restart tests.
#[path = "../tests/common/pq_finality.rs"]
mod fixture;
use rtos_api::pq_finality::{final_vote_preimage, PqVerificationContext};
use rtos_block::*;
fn id(root: &Cell, seq: u32, shard: ShardIdent) -> BlockIdExt {
    BlockIdExt::with_params(
        shard,
        seq,
        root.repr_hash().clone(),
        UInt256::calc_file_hash(&write_boc(root).unwrap()),
    )
}
fn reference(id: &BlockIdExt) -> ExtBlkRef {
    ExtBlkRef {
        end_lt: if id.seq_no == 0 {
            0
        } else {
            u64::from(id.seq_no) * 1_000_000
                + if id.shard().is_masterchain() { 3_000 } else { 1_000 }
        },
        seq_no: id.seq_no,
        root_hash: id.root_hash.clone(),
        file_hash: id.file_hash.clone(),
    }
}
fn install_config_account(state: &mut ShardStateUnsplit, config: &ConfigParams) {
    let mut data = BuilderData::new();
    data.checked_append_reference(config.config_params.data().unwrap().clone()).unwrap();
    let mut init = StateInit::default();
    init.set_code(BuilderData::with_raw(vec![0], 8).unwrap().into_cell().unwrap());
    init.set_data(data.into_cell().unwrap());
    let account =
        Account::active_standard(config.config_addr.clone(), 0, 0, state.gen_time(), init);
    state
        .insert_account(
            &config.config_addr,
            &ShardAccount::with_params(&account, UInt256::default(), 0).unwrap(),
        )
        .unwrap();
}

fn main() {
    use std::io::Read;
    let args: Vec<_> = std::env::args().collect();
    let gc_keys: Option<Vec<String>> =
        args.windows(2).find(|a| a[0] == "--gc-history-keys").map(|a| {
            let mut bytes = Vec::new();
            std::fs::File::open(&a[1])
                .unwrap()
                .take((16 << 10) + 1)
                .read_to_end(&mut bytes)
                .unwrap();
            assert!(bytes.len() <= 16 << 10, "GC public-key file exceeds 16KiB");
            serde_json::from_slice(&bytes).unwrap()
        });
    assert!(
        !args.iter().any(|a| a == "--gc-history-keys") || gc_keys.is_some(),
        "--gc-history-keys requires a public-key file"
    );
    if let Some(keys) = &gc_keys {
        assert_eq!(keys.len(), 3);
        assert!(
            keys.iter().all(|key| key.len() == 2 * 1312),
            "ML-DSA-44 public keys must be 1312 bytes"
        );
    }
    let gc_history = gc_keys.is_some();
    let network_keys: Option<Vec<String>> = args
        .windows(2)
        .find(|a| a[0] == "--active-network-keys")
        .map(|a| serde_json::from_slice(&std::fs::read(&a[1]).unwrap()).unwrap());
    if let Some(keys) = &network_keys {
        assert_eq!(keys.len(), 4, "network fixture requires four independent validators");
    }
    let active = network_keys.is_some() || args.iter().any(|arg| arg == "--active-validator");
    assert!(!gc_history || !active, "GC history is a separate public fixture mode");
    let history_cc = if network_keys.is_some() { 6 } else { 7 };
    let finality = gc_history || active || std::env::args().any(|arg| arg == "--retained-finality");
    let genesis_time = if active {
        u32::try_from(
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        )
        .unwrap()
            - 4
    } else if gc_history {
        1_000
    } else {
        1_700_000_000
    };
    let shard = ShardIdent::with_tagged_prefix(0, SHARD_FULL).unwrap();
    let mut wcstate = ShardStateUnsplit::default();
    wcstate.set_global_id(-239);
    wcstate.set_shard(shard.clone());
    wcstate.set_gen_time(genesis_time);
    let mut wcroot = wcstate.serialize().unwrap();
    let wczero = id(&wcroot, 0, shard.clone());
    let wcboc = write_boc(&wcroot).unwrap();
    let mut wcprevious = wczero.clone();
    let mut config = fixture::config();
    if let Some(keys) = &gc_keys {
        let members = keys
            .iter()
            .enumerate()
            .map(|(index, public)| {
                let public_key = hex::decode(public).unwrap();
                let mut stable = [0; 32];
                stable[..4].copy_from_slice(&((index + 1) as u32).to_le_bytes());
                let transport =
                    Ed25519KeyOption::<ZeroizingBytes>::from_private_key(&[0x60 + index as u8; 32])
                        .unwrap();
                ValidatorDescr::with_pq_params(
                    UInt256::from(stable),
                    PqConsensusKey {
                        algorithm_id: 1,
                        key_id: derive_consensus_key_id(1, &public_key),
                        public_key,
                    },
                    1,
                    UInt256::from(*transport.id().data()),
                )
            })
            .collect();
        config
            .set_config(ConfigParamEnum::ConfigParam34(ConfigParam34 {
                cur_validators: ValidatorSet::new(0, u32::MAX, 3, members).unwrap(),
            }))
            .unwrap();
        // The native schema requires positive lifetimes; factory zero defaults
        // are for missing configuration, not a serialized Param28 record.
        config
            .set_config(ConfigParamEnum::ConfigParam28(CatchainConfig {
                mc_catchain_lifetime: 86_400,
                shard_catchain_lifetime: 600,
                shard_validators_lifetime: 3_600,
                shard_validators_num: 3,
                shuffle_mc_validators: false,
                ..Default::default()
            }))
            .unwrap();
    }
    if finality {
        let simplex = SimplexConfig { protocol_version: 2, ..Default::default() };
        config
            .set_config(ConfigParamEnum::ConfigParam30(NewConsensusConfigAll {
                mc: Some(simplex.clone()),
                shard: Some(simplex),
            }))
            .unwrap();
    }
    if active {
        config.set_config(ConfigParamEnum::ConfigParam31(ConfigParam31::default())).unwrap();
        config
            .set_config(ConfigParamEnum::ConfigParam28(CatchainConfig {
                mc_catchain_lifetime: 86_400,
                shard_catchain_lifetime: 600,
                shard_validators_lifetime: 3_600,
                shard_validators_num: 1,
                shuffle_mc_validators: false,
                ..Default::default()
            }))
            .unwrap();
    }
    let template = ShardStateUnsplit::construct_from_bytes(include_bytes!(
        "../../../rtos/src/tests/static/zerostate.boc"
    ))
    .unwrap()
    .read_custom()
    .unwrap()
    .unwrap();
    config.config_addr = template.config.config_addr.clone();
    template
        .config
        .config_params
        .iterate_slices(|key, value| {
            if config.config_params.get(key.clone())?.is_none() {
                config.config_params.set(key, &value)?;
            }
            Ok(true)
        })
        .unwrap();
    let validators = if let Some(keys) = &network_keys {
        keys.iter()
            .enumerate()
            .map(|(i, public)| {
                let public_key = hex::decode(public).unwrap();
                let transport =
                    Ed25519KeyOption::<ZeroizingBytes>::from_private_key(&[0x61 + i as u8; 32])
                        .unwrap();
                ValidatorDescr::with_pq_params(
                    UInt256::from([i as u8 + 1; 32]),
                    PqConsensusKey {
                        algorithm_id: 1,
                        key_id: derive_consensus_key_id(1, &public_key),
                        public_key,
                    },
                    1,
                    UInt256::from(*transport.id().data()),
                )
            })
            .collect()
    } else if active {
        let member = config.validator_set().unwrap().list()[1].clone();
        let transport = Ed25519KeyOption::<ZeroizingBytes>::from_private_key(&[0x61; 32]).unwrap();
        vec![ValidatorDescr::with_pq_params(
            member.validator_id().unwrap(),
            member.pq_key().unwrap().clone(),
            member.weight,
            UInt256::from(*transport.id().data()),
        )]
    } else {
        config.validator_set().unwrap().list().to_vec()
    };
    config
        .set_config(ConfigParamEnum::ConfigParam34(ConfigParam34 {
            cur_validators: ValidatorSet::new(
                if gc_history { 0 } else { 1_600_000_000 },
                u32::MAX,
                validators.len() as u16,
                validators,
            )
            .unwrap(),
        }))
        .unwrap();
    let mut workchains = ConfigParam12::default();
    workchains
        .insert(
            0,
            &WorkchainDescr {
                active: !active,
                accept_msgs: !active,
                zerostate_root_hash: wczero.root_hash.clone(),
                zerostate_file_hash: wczero.file_hash.clone(),
                format: WorkchainFormat::Basic(WorkchainFormat1::with_params(0, 0)),
                ..Default::default()
            },
        )
        .unwrap();
    config.set_config(ConfigParamEnum::ConfigParam12(workchains)).unwrap();
    assert!(
        config.valid_config_data(false, None).unwrap(),
        "complete node fixture configuration must be valid"
    );
    let mut state = ShardStateUnsplit::default();
    state.set_global_id(-239);
    state.set_shard(ShardIdent::masterchain());
    state.set_gen_time(genesis_time);
    let mut custom = McStateExtra::default();
    custom.config = config.clone();
    custom.after_key_block = true;
    if active || gc_history {
        custom.validator_info.catchain_seqno = history_cc;
        custom.validator_info.validator_list_hash_short =
            ValidatorSet::calc_subset_hash_short(config.validator_set().unwrap().list(), 0)
                .unwrap();
    }
    state.write_custom(Some(&custom)).unwrap();
    if active {
        install_config_account(&mut state, &config);
    }
    let mut state_root = state.serialize().unwrap();
    let zero = id(&state_root, 0, ShardIdent::masterchain());
    let zero_boc = write_boc(&state_root).unwrap();
    let mut previous = zero.clone();
    let mut previous_key = true;
    let mut epoch = 0;
    let mut last_key = None;
    let mut rows = vec![];
    for seq in 1..=4 {
        let wc_start_lt = u64::from(seq) * 1_000_000;
        let wc_end_lt = wc_start_lt + 1_000;
        let mc_start_lt = wc_end_lt + 1_000;
        let mc_end_lt = mc_start_lt + 1_000;
        wcstate.set_seq_no(seq);
        wcstate.set_gen_lt(wc_end_lt);
        wcstate.set_gen_time(genesis_time + seq);
        wcstate.set_master_ref(Some(BlkMasterInfo { master: reference(&previous) }));
        let nextwc = wcstate.serialize().unwrap();
        let mut wcinfo = BlockInfo::default();
        wcinfo.set_seq_no(seq).unwrap();
        wcinfo.set_start_lt(wc_start_lt);
        wcinfo.set_end_lt(wc_end_lt);
        wcinfo.set_shard(shard.clone());
        wcinfo.set_gen_utime(genesis_time + seq);
        let mut wc_extra = BlockExtra::default();
        if gc_history {
            wcinfo.set_prev_key_block_seqno(epoch);
            wcinfo.set_gen_catchain_seqno(history_cc);
            wcinfo.set_gen_validator_list_hash_short(
                config
                    .validator_set()
                    .unwrap()
                    .calc_subset(&config.catchain_config().unwrap(), SHARD_FULL, 0, history_cc)
                    .unwrap()
                    .1,
            );
            let mut creator = [0; 32];
            creator[..4].copy_from_slice(&1u32.to_le_bytes());
            *wc_extra.created_by_mut() = UInt256::from(creator);
        }
        wcinfo.set_prev_stuff(false, &BlkPrevInfo::Block { prev: reference(&wcprevious) }).unwrap();
        wcinfo.write_master_ref(Some(&BlkMasterInfo { master: reference(&previous) })).unwrap();
        let wcblock = Block::with_params(
            -239,
            wcinfo,
            ValueFlow::default(),
            MerkleUpdate::create(&wcroot, &nextwc).unwrap(),
            wc_extra,
        )
        .unwrap();
        let wcblockroot = wcblock.serialize().unwrap();
        let wcid = id(&wcblockroot, seq, shard.clone());
        let governing = config.clone();
        let key = if gc_history { seq == 3 } else { seq % 2 == 1 };
        if key {
            let mut opts = config.consensus_config().unwrap();
            opts.next_candidate_delay_ms += 1;
            config.set_config(ConfigParamEnum::ConfigParam29(opts)).unwrap();
        }
        let descr = ShardDescr {
            seq_no: seq,
            reg_mc_seqno: seq,
            root_hash: wcid.root_hash.clone(),
            file_hash: wcid.file_hash.clone(),
            gen_utime: genesis_time + seq,
            start_lt: wc_start_lt,
            end_lt: wc_end_lt,
            next_validator_shard: SHARD_FULL,
            min_ref_mc_seqno: seq - 1,
            ..Default::default()
        };
        let mut shards = ShardHashes::default();
        if !active {
            shards.add_workchain(0, 0, wczero.root_hash.clone(), wczero.file_hash.clone()).unwrap();
            shards.update_shard(&shard, |_| Ok(descr)).unwrap();
        }
        custom
            .prev_blocks
            .set(
                &previous.seq_no,
                &KeyExtBlkRef { key: previous_key, blk_ref: reference(&previous) },
                &KeyMaxLt { key: previous_key, max_end_lt: reference(&previous).end_lt },
            )
            .unwrap();
        custom.shards = shards.clone();
        custom.config = config.clone();
        custom.after_key_block = key;
        custom.last_key_block = last_key.clone();
        if network_keys.is_some() {
            custom.validator_info.catchain_seqno = if seq == 4 { 7 } else { history_cc };
            custom.validator_info.nx_cc_updated = seq == 4;
        }
        state.set_seq_no(seq);
        state.set_gen_lt(mc_end_lt);
        state.set_gen_time(genesis_time + seq);
        state.write_custom(Some(&custom)).unwrap();
        if active {
            install_config_account(&mut state, &config);
        }
        let next_state = state.serialize().unwrap();
        let mut info = BlockInfo::default();
        info.set_seq_no(seq).unwrap();
        info.set_start_lt(mc_start_lt);
        info.set_end_lt(mc_end_lt);
        info.set_shard(ShardIdent::masterchain());
        info.set_key_block(key);
        info.set_gen_utime(genesis_time + seq);
        info.set_prev_key_block_seqno(epoch);
        info.set_vertical_stuff(0, if active || gc_history { 0 } else { 1 }, None).unwrap();
        if finality {
            info.set_gen_catchain_seqno(history_cc);
            let (_, hash) = governing
                .validator_set()
                .unwrap()
                .calc_subset(&governing.catchain_config().unwrap(), SHARD_FULL, -1, history_cc)
                .unwrap();
            info.set_gen_validator_list_hash_short(hash);
        }
        info.set_prev_stuff(false, &BlkPrevInfo::Block { prev: reference(&previous) }).unwrap();
        let mut extra = BlockExtra::default();
        if finality {
            let creator = if network_keys.is_some() {
                (99 / SimplexConfig::default().slots_per_leader_window % 4 + 1) as u8
            } else if active {
                2
            } else {
                1
            };
            *extra.created_by_mut() = if gc_history {
                let mut stable = [0; 32];
                stable[..4].copy_from_slice(&u32::from(creator).to_le_bytes());
                UInt256::from(stable)
            } else {
                UInt256::from([creator; 32])
            };
        }
        let mut mc = McBlockExtra::default();
        *mc.shards_mut() = shards;
        if key {
            mc.set_config(config.clone());
        }
        extra.write_custom(&mc).unwrap();
        let block = Block::with_params(
            -239,
            info,
            ValueFlow::default(),
            MerkleUpdate::create(&state_root, &next_state).unwrap(),
            extra,
        )
        .unwrap();
        let root = block.serialize().unwrap();
        let blockid = id(&root, seq, ShardIdent::masterchain());
        let ctx = PqVerificationContext::from_governing_config(
            -239,
            &governing,
            blockid.clone(),
            if active || gc_history { 0 } else { 1 },
            epoch,
            history_cc,
        )
        .unwrap();
        let mut candidate = 0x8354642du32.to_le_bytes().to_vec();
        candidate.extend_from_slice(&(-1i32).to_le_bytes());
        candidate.extend_from_slice(&SHARD_FULL.to_le_bytes());
        candidate.extend_from_slice(&seq.to_le_bytes());
        candidate.extend_from_slice(blockid.root_hash.as_slice());
        candidate.extend_from_slice(blockid.file_hash.as_slice());
        candidate.extend_from_slice(&98u32.to_le_bytes());
        candidate.extend_from_slice(&[5; 32]);
        if finality {
            candidate = 0x3f6431f8u32.to_le_bytes().to_vec();
            candidate.extend_from_slice(&(-1i32).to_le_bytes());
            candidate.extend_from_slice(&SHARD_FULL.to_le_bytes());
            candidate.extend_from_slice(&seq.to_le_bytes());
            candidate.extend_from_slice(blockid.root_hash.as_slice());
            candidate.extend_from_slice(blockid.file_hash.as_slice());
            candidate.extend_from_slice(UInt256::calc_file_hash(&[]).as_slice());
            candidate.extend(rtos_api::WireProfile::T0.serialize(
                &rtos_api::ton::consensus::CandidateParent::Consensus_CandidateWithoutParents
            ).unwrap());
        }
        let carrier = BlockSignaturesSimplexPq {
            validator_info: ValidatorBaseInfo::with_params(ctx.subset_hash(), history_cc),
            session_id: ctx.expected_session_id().clone(),
            slot: 99,
            candidate_data: BlockSignaturesSimplex::bytes_to_cell_tree(&candidate).unwrap(),
            sig_count: 0,
            sig_weight: 0,
            signatures: vec![],
        };
        rows.push(serde_json::json!({"block_boc":hex::encode(write_boc(&root).unwrap()),"state_boc":hex::encode(write_boc(&next_state).unwrap()),"wc_block_boc":hex::encode(write_boc(&wcblockroot).unwrap()),"wc_state_boc":hex::encode(write_boc(&nextwc).unwrap()),"candidate":hex::encode(candidate),"session":hex::encode(carrier.session_id.as_slice()),"subset_hash":ctx.subset_hash(),"slot":99,"preimage":hex::encode(final_vote_preimage(&blockid,&carrier).unwrap())}));
        if gc_history {
            let wc_ctx = PqVerificationContext::from_governing_config(
                -239,
                &governing,
                wcid.clone(),
                0,
                epoch,
                history_cc,
            )
            .unwrap();
            let mut candidate = 0x3f6431f8u32.to_le_bytes().to_vec();
            candidate.extend(0i32.to_le_bytes());
            candidate.extend(SHARD_FULL.to_le_bytes());
            candidate.extend(seq.to_le_bytes());
            candidate.extend(wcid.root_hash.as_slice());
            candidate.extend(wcid.file_hash.as_slice());
            candidate.extend(UInt256::calc_file_hash(&[]).as_slice());
            candidate.extend(rtos_api::WireProfile::T0.serialize(&rtos_api::ton::consensus::CandidateParent::Consensus_CandidateWithoutParents).unwrap());
            let carrier = BlockSignaturesSimplexPq {
                validator_info: ValidatorBaseInfo::with_params(wc_ctx.subset_hash(), history_cc),
                session_id: wc_ctx.expected_session_id().clone(),
                slot: 99,
                candidate_data: BlockSignaturesSimplex::bytes_to_cell_tree(&candidate).unwrap(),
                sig_count: 0,
                sig_weight: 0,
                signatures: vec![],
            };
            let row = rows.last_mut().unwrap();
            row["wc_candidate"] = hex::encode(candidate).into();
            row["wc_session"] = hex::encode(carrier.session_id.as_slice()).into();
            row["wc_subset_hash"] = wc_ctx.subset_hash().into();
            row["wc_preimage"] = hex::encode(final_vote_preimage(&wcid, &carrier).unwrap()).into();
        }
        if network_keys.is_some() || gc_history {
            rows.last_mut().unwrap()["catchain_seqno"] = history_cc.into();
        }
        if key {
            epoch = seq;
            last_key = Some(reference(&blockid));
        }
        previous = blockid;
        previous_key = key;
        state_root = next_state;
        wcprevious = wcid;
        wcroot = nextwc;
    }
    let mut output = serde_json::json!({"zerostate":hex::encode(zero_boc),"wc_zerostate":hex::encode(wcboc),"zero_root":zero.root_hash.as_hex_string(),"zero_file":zero.file_hash.as_hex_string(),"cases":rows});
    if active {
        output["masterchain_only"] = true.into();
    }
    if network_keys.is_some() {
        output["active_network"] = true.into();
    }
    println!("{}", output);
}
