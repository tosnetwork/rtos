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

// Match the collator's transition: last_key_block names the previous key
// block, while after_key_block describes the state being produced.
fn advance_masterchain_history(
    extra: &mut McStateExtra,
    parent: &BlockIdExt,
    parent_end_lt: u64,
    key: bool,
    epoch: u32,
) -> Result<()> {
    let parent_is_key = parent.seq_no == 0 || epoch == parent.seq_no;
    let parent_ref = reference(parent, parent_end_lt);
    extra.prev_blocks.set(
        &parent.seq_no,
        &KeyExtBlkRef { key: parent_is_key, blk_ref: parent_ref.clone() },
        &KeyMaxLt { key: parent_is_key, max_end_lt: parent_end_lt },
    )?;
    if extra.after_key_block {
        extra.last_key_block = Some(parent_ref);
    }
    extra.after_key_block = key;
    Ok(())
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
    successor_with_state_transform(signer, parent, old_cell, key, epoch, cc, creator, |_| {})
}

pub(super) fn successor_with_state_transform(
    signer: &str,
    parent: &BlockIdExt,
    old_cell: &Cell,
    key: bool,
    epoch: u32,
    cc: u32,
    creator: &UInt256,
    transform: impl FnOnce(&mut ShardStateUnsplit),
) -> (BlockIdExt, Cell, Value) {
    successor_in_domain(signer, parent, old_cell, key, epoch, cc, creator, -239, transform)
}

pub(super) fn successor_in_domain(
    signer: &str,
    parent: &BlockIdExt,
    old_cell: &Cell,
    key: bool,
    epoch: u32,
    cc: u32,
    creator: &UInt256,
    global_id: i32,
    transform: impl FnOnce(&mut ShardStateUnsplit),
) -> (BlockIdExt, Cell, Value) {
    let old_state = ShardStateUnsplit::construct_from_cell(old_cell.clone()).unwrap();
    let mut config = old_state.read_custom().unwrap().unwrap().config;
    // A foreign-domain response must still be internally valid and signed for
    // that domain, so rejection occurs at the requested exact block boundary.
    config.set_config(ConfigParamEnum::ConfigParam19(global_id as u32)).unwrap();
    let seq = parent.seq_no + 1;
    let mut state = old_state.clone();
    state.set_global_id(global_id);
    state.set_seq_no(seq);
    state.set_gen_time(old_state.gen_time() + 1);
    state.set_gen_lt(old_state.gen_lt() + 5);
    let mut extra = state.read_custom().unwrap().unwrap();
    extra.config = config.clone();
    advance_masterchain_history(&mut extra, parent, old_state.gen_lt(), key, epoch).unwrap();
    state.write_custom(Some(&extra)).unwrap();
    transform(&mut state);
    let state_cell = state.serialize().unwrap();
    let placeholder = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        seq,
        UInt256::default(),
        UInt256::default(),
    );
    let context =
        PqVerificationContext::from_governing_config(global_id, &config, placeholder, 0, epoch, cc)
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
        global_id,
        info,
        ValueFlow::default(),
        MerkleUpdate::create(old_cell, &state_cell).unwrap(),
        block_extra,
    )
    .unwrap();
    let (id, bytes) = encode_block(&block);
    let context =
        PqVerificationContext::from_governing_config(global_id, &config, id.clone(), 0, epoch, cc)
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

#[test]
fn signed_history_fixture_preserves_exact_previous_key_block_across_epochs() -> Result<()> {
    let fixture: Value =
        serde_json::from_str(include_str!("testdata/v2-propagation-recovery.json"))?;
    let bytes = hex::decode(fixture["state_boc"].as_str().unwrap())?;
    let root = read_single_root_boc(&bytes)?;
    let state = ShardStateUnsplit::construct_from_cell(root.clone())?;
    let zero = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        0,
        root.repr_hash().clone(),
        UInt256::calc_file_hash(&bytes),
    );
    let mut extra = state.read_custom()?.unwrap();
    assert!(extra.after_key_block, "the actual fixture zerostate is the epoch-zero key anchor");
    let zero_ref = reference(&zero, state.gen_lt());
    advance_masterchain_history(&mut extra, &zero, state.gen_lt(), false, 0)?;
    extra = McStateExtra::construct_from_cell(extra.serialize()?)?;
    assert_eq!(extra.last_key_block.as_ref(), Some(&zero_ref));
    assert!(!extra.after_key_block);
    for (seq, key) in [(1, false), (2, true)] {
        let parent = BlockIdExt::with_params(
            ShardIdent::masterchain(),
            seq,
            UInt256::from([seq as u8; 32]),
            UInt256::from([(seq + 10) as u8; 32]),
        );
        advance_masterchain_history(&mut extra, &parent, state.gen_lt() + seq as u64, key, 0)?;
        extra = McStateExtra::construct_from_cell(extra.serialize()?)?;
        assert_eq!(
            extra.last_key_block.as_ref(),
            Some(&zero_ref),
            "a newly produced key block is not its own previous key block"
        );
        assert_eq!(extra.after_key_block, key);
    }
    let key_parent = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        3,
        UInt256::from([3; 32]),
        UInt256::from([13; 32]),
    );
    let exact = reference(&key_parent, state.gen_lt() + 3);
    advance_masterchain_history(&mut extra, &key_parent, exact.end_lt, false, 3)?;
    extra = McStateExtra::construct_from_cell(extra.serialize()?)?;
    assert_eq!(extra.last_key_block.as_ref(), Some(&exact));
    assert!(!extra.after_key_block);
    Ok(())
}
