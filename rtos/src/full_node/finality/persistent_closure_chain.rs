// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
// Public deterministic fixture generator. Never use these keys in production.
use rtos_api::pq_finality::{final_vote_preimage, PqVerificationContext};
use rtos_block::*;
use serde_json::{json, Value};
fn reference(id: &BlockIdExt, end_lt: u64) -> ExtBlkRef {
    ExtBlkRef {
        end_lt,
        seq_no: id.seq_no,
        root_hash: id.root_hash.clone(),
        file_hash: id.file_hash.clone(),
    }
}
fn encode_block(block: &Block) -> (BlockIdExt, Vec<u8>) {
    let root = block.serialize().unwrap();
    let bytes =
        BocWriter::with_flags([root.clone()], BocFlags::all()).unwrap().write_to_vec().unwrap();
    let info = block.read_info().unwrap();
    (
        BlockIdExt::with_params(
            info.shard().clone(),
            info.seq_no(),
            root.repr_hash().clone(),
            UInt256::calc_file_hash(&bytes),
        ),
        bytes,
    )
}
fn sign(
    signer: &str,
    context: &PqVerificationContext,
    id: &BlockIdExt,
    cc: u32,
    config: &ConfigParams,
) -> (BlockSignaturesSimplexPq, Vec<u8>) {
    let mut candidate = 0x3f6431f8u32.to_le_bytes().to_vec();
    candidate.extend(id.shard().workchain_id().to_le_bytes());
    candidate.extend(id.shard().shard_prefix_with_tag().to_le_bytes());
    candidate.extend(id.seq_no.to_le_bytes());
    candidate.extend(id.root_hash.as_slice());
    candidate.extend(id.file_hash.as_slice());
    candidate.extend(UInt256::calc_file_hash(&[]).as_slice());
    // Native closed candidate: no fabricated missing ancestor.
    let parent = rtos_api::ton::consensus::CandidateParent::Consensus_CandidateWithoutParents;
    candidate.extend(rtos_api::WireProfile::T0.serialize(&parent).unwrap());
    let mut carrier = BlockSignaturesSimplexPq {
        validator_info: ValidatorBaseInfo::with_params(context.subset_hash(), cc),
        session_id: context.expected_session_id().clone(),
        slot: id.seq_no(),
        candidate_data: BlockSignaturesSimplex::bytes_to_cell_tree(&candidate).unwrap(),
        sig_count: 3,
        sig_weight: 3,
        signatures: vec![],
    };
    let preimage = final_vote_preimage(id, &carrier).unwrap();
    for index in 0..3 {
        let output = std::process::Command::new(signer)
            .args([
                index.to_string(),
                hex::encode(&preimage),
                hex::encode(b"TOS-CONSENSUS-SIMPLEX-v1"),
            ])
            .output()
            .unwrap();
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        let mut lines = text.lines();
        let public = hex::decode(lines.next().unwrap()).unwrap();
        let member = config.validator_set().unwrap().list()[index].clone();
        assert_eq!(&public, &member.pq_key().unwrap().public_key);
        carrier.signatures.push(PqBlockSignaturePair {
            validator_id: member.validator_id().unwrap(),
            algorithm_id: 1,
            signature: hex::decode(lines.next().unwrap()).unwrap(),
        });
    }
    context.verify_final(&carrier).unwrap();
    (carrier, candidate)
}

pub(super) fn successor(
    signer: &str,
    parent: &BlockIdExt,
    old_cell: &Cell,
    key: bool,
    epoch: u32,
    cc: u32,
    creator: &UInt256,
) -> (BlockIdExt, Cell, Value) {
    let old_state = ShardStateUnsplit::construct_from_cell(old_cell.clone()).unwrap();
    let config = old_state.read_custom().unwrap().unwrap().config;
    let seq = parent.seq_no + 1;
    let mut state = old_state.clone();
    state.set_seq_no(seq);
    state.set_gen_time(old_state.gen_time() + 1);
    state.set_gen_lt(old_state.gen_lt() + 5);
    let mut extra = state.read_custom().unwrap().unwrap();
    let parent_is_key = parent.seq_no == 0 || epoch == parent.seq_no;
    extra
        .prev_blocks
        .set(
            &parent.seq_no,
            &KeyExtBlkRef { key: parent_is_key, blk_ref: reference(parent, old_state.gen_lt()) },
            &KeyMaxLt { key: parent_is_key, max_end_lt: old_state.gen_lt() },
        )
        .unwrap();
    extra.after_key_block = key;
    state.write_custom(Some(&extra)).unwrap();
    let state_cell = state.serialize().unwrap();
    let placeholder = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        seq,
        UInt256::default(),
        UInt256::default(),
    );
    let context =
        PqVerificationContext::from_governing_config(-239, &config, placeholder, 0, epoch, cc)
            .unwrap();
    let mut info = BlockInfo::default();
    info.set_seq_no(seq).unwrap();
    info.set_shard(ShardIdent::masterchain());
    info.set_key_block(key);
    info.set_gen_utime(state.gen_time());
    info.set_start_lt(old_state.gen_lt() + 1);
    info.set_end_lt(state.gen_lt());
    info.set_gen_catchain_seqno(cc);
    info.set_prev_key_block_seqno(epoch);
    info.set_gen_validator_list_hash_short(context.subset_hash());
    info.set_prev_stuff(false, &BlkPrevInfo::Block { prev: reference(parent, old_state.gen_lt()) })
        .unwrap();
    let mut custom = McBlockExtra::default();
    if key {
        custom.set_config(config.clone());
    }
    *custom.shards_mut() = extra.shards().clone();
    let mut block_extra = BlockExtra::default();
    *block_extra.created_by_mut() = creator.clone();
    block_extra.write_custom(&custom).unwrap();
    let block = Block::with_params(
        -239,
        info,
        ValueFlow::default(),
        MerkleUpdate::create(old_cell, &state_cell).unwrap(),
        block_extra,
    )
    .unwrap();
    let (id, bytes) = encode_block(&block);
    let context =
        PqVerificationContext::from_governing_config(-239, &config, id.clone(), 0, epoch, cc)
            .unwrap();
    let (carrier, candidate) = sign(signer, &context, &id, cc, &config);
    let proof = BlockProof::with_params(
        id.clone(),
        MerkleProof::create(&block.serialize().unwrap(), |_| true).unwrap().serialize().unwrap(),
        Some(BlockSignaturesVariant::SimplexPq(carrier)),
    );
    let row = json!({"id":id.to_string(),"block_boc":hex::encode(bytes),"proof_boc":hex::encode(proof.write_to_bytes().unwrap()),"state_boc":hex::encode(write_boc(&state_cell).unwrap()),"session":hex::encode(context.expected_session_id().as_slice()),"candidate":hex::encode(candidate),"prev_key_block_seqno":epoch});
    (id, state_cell, row)
}
