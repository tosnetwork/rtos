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
fn main() {
    let finality = std::env::args().any(|arg| arg == "--retained-finality");
    let shard = ShardIdent::with_tagged_prefix(0, SHARD_FULL).unwrap();
    let mut wcstate = ShardStateUnsplit::default();
    wcstate.set_global_id(-239);
    wcstate.set_shard(shard.clone());
    wcstate.set_gen_time(1_700_000_000);
    let mut wcroot = wcstate.serialize().unwrap();
    let wczero = id(&wcroot, 0, shard.clone());
    let wcboc = write_boc(&wcroot).unwrap();
    let mut wcprevious = wczero.clone();
    let mut config = fixture::config();
    if finality {
        let simplex = SimplexConfig { protocol_version: 2, ..Default::default() };
        config.set_config(ConfigParamEnum::ConfigParam30(NewConsensusConfigAll {
            mc: Some(simplex.clone()), shard: Some(simplex),
        })).unwrap();
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
    let validators = config.validator_set().unwrap().list().to_vec();
    config
        .set_config(ConfigParamEnum::ConfigParam34(ConfigParam34 {
            cur_validators: ValidatorSet::new(1_600_000_000, u32::MAX, 2, validators).unwrap(),
        }))
        .unwrap();
    let mut workchains = ConfigParam12::default();
    workchains
        .insert(
            0,
            &WorkchainDescr {
                active: true,
                accept_msgs: true,
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
    state.set_gen_time(1_700_000_000);
    let mut custom = McStateExtra::default();
    custom.config = config.clone();
    custom.after_key_block = true;
    state.write_custom(Some(&custom)).unwrap();
    let mut state_root = state.serialize().unwrap();
    let zero = id(&state_root, 0, ShardIdent::masterchain());
    let zero_boc = write_boc(&state_root).unwrap();
    let mut previous = zero.clone();
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
        wcstate.set_gen_time(1_700_000_000 + seq);
        wcstate.set_master_ref(Some(BlkMasterInfo { master: reference(&previous) }));
        let nextwc = wcstate.serialize().unwrap();
        let mut wcinfo = BlockInfo::default();
        wcinfo.set_seq_no(seq).unwrap();
        wcinfo.set_start_lt(wc_start_lt);
        wcinfo.set_end_lt(wc_end_lt);
        wcinfo.set_shard(shard.clone());
        wcinfo.set_gen_utime(1_700_000_000 + seq);
        wcinfo.set_prev_stuff(false, &BlkPrevInfo::Block { prev: reference(&wcprevious) }).unwrap();
        wcinfo.write_master_ref(Some(&BlkMasterInfo { master: reference(&previous) })).unwrap();
        let wcblock = Block::with_params(
            -239,
            wcinfo,
            ValueFlow::default(),
            MerkleUpdate::create(&wcroot, &nextwc).unwrap(),
            BlockExtra::default(),
        )
        .unwrap();
        let wcblockroot = wcblock.serialize().unwrap();
        let wcid = id(&wcblockroot, seq, shard.clone());
        let governing = config.clone();
        let key = seq % 2 == 1;
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
            gen_utime: 1_700_000_000 + seq,
            start_lt: wc_start_lt,
            end_lt: wc_end_lt,
            next_validator_shard: SHARD_FULL,
            min_ref_mc_seqno: seq - 1,
            ..Default::default()
        };
        let mut shards = ShardHashes::default();
        shards.add_workchain(0, 0, wczero.root_hash.clone(), wczero.file_hash.clone()).unwrap();
        shards.update_shard(&shard, |_| Ok(descr)).unwrap();
        custom
            .prev_blocks
            .set(
                &previous.seq_no,
                &KeyExtBlkRef {
                    key: previous.seq_no == 0 || previous.seq_no % 2 == 1,
                    blk_ref: reference(&previous),
                },
                &KeyMaxLt {
                    key: previous.seq_no == 0 || previous.seq_no % 2 == 1,
                    max_end_lt: reference(&previous).end_lt,
                },
            )
            .unwrap();
        custom.shards = shards.clone();
        custom.config = config.clone();
        custom.after_key_block = key;
        custom.last_key_block = last_key.clone();
        state.set_seq_no(seq);
        state.set_gen_lt(mc_end_lt);
        state.set_gen_time(1_700_000_000 + seq);
        state.write_custom(Some(&custom)).unwrap();
        let next_state = state.serialize().unwrap();
        let mut info = BlockInfo::default();
        info.set_seq_no(seq).unwrap();
        info.set_start_lt(mc_start_lt);
        info.set_end_lt(mc_end_lt);
        info.set_shard(ShardIdent::masterchain());
        info.set_key_block(key);
        info.set_gen_utime(1_700_000_000 + seq);
        info.set_prev_key_block_seqno(epoch);
        info.set_vertical_stuff(0, 1, None).unwrap();
        if finality {
            info.set_gen_catchain_seqno(7);
            let (_, hash) = governing.validator_set().unwrap().calc_subset(
                &governing.catchain_config().unwrap(), SHARD_FULL, -1, 7).unwrap();
            info.set_gen_validator_list_hash_short(hash);
        }
        info.set_prev_stuff(false, &BlkPrevInfo::Block { prev: reference(&previous) }).unwrap();
        let mut extra = BlockExtra::default();
        if finality { *extra.created_by_mut() = UInt256::from([1; 32]); }
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
            1,
            epoch,
            7,
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
            validator_info: ValidatorBaseInfo::with_params(ctx.subset_hash(), 7),
            session_id: ctx.expected_session_id().clone(),
            slot: 99,
            candidate_data: BlockSignaturesSimplex::bytes_to_cell_tree(&candidate).unwrap(),
            sig_count: 0,
            sig_weight: 0,
            signatures: vec![],
        };
        rows.push(serde_json::json!({"block_boc":hex::encode(write_boc(&root).unwrap()),"state_boc":hex::encode(write_boc(&next_state).unwrap()),"wc_block_boc":hex::encode(write_boc(&wcblockroot).unwrap()),"wc_state_boc":hex::encode(write_boc(&nextwc).unwrap()),"candidate":hex::encode(candidate),"session":hex::encode(carrier.session_id.as_slice()),"subset_hash":ctx.subset_hash(),"slot":99,"preimage":hex::encode(final_vote_preimage(&blockid,&carrier).unwrap())}));
        if key {
            epoch = seq;
            last_key = Some(reference(&blockid));
        }
        previous = blockid;
        state_root = next_state;
        wcprevious = wcid;
        wcroot = nextwc;
    }
    println!(
        "{}",
        serde_json::json!({"zerostate":hex::encode(zero_boc),"wc_zerostate":hex::encode(wcboc),"zero_root":zero.root_hash.as_hex_string(),"zero_file":zero.file_hash.as_hex_string(),"cases":rows})
    );
}
