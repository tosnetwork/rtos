// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
// Public synthetic fixture maintenance. Keys and signatures come from a pinned native signer.
use rtos_api::{
    pq_finality::{build_simplex_vote_data, PqApproval, PqVerificationContext},
    ton::consensus::{candidateid::CandidateId, datatosign::DataToSign, CandidateHashData},
    IntoBoxed, WireProfile,
};
use rtos_block::*;
use serde_json::{json, Value};
fn root(value: &Value) -> Cell {
    read_single_root_boc(&hex::decode(value.as_str().unwrap()).unwrap()).unwrap()
}
fn boc(cell: Cell) -> Value {
    hex::encode(write_boc(&cell).unwrap()).into()
}
fn block_id(block: &Block) -> BlockIdExt {
    let info = block.read_info().unwrap();
    let cell = block.serialize().unwrap();
    BlockIdExt::with_params(
        info.shard().clone(),
        info.seq_no(),
        cell.repr_hash().clone(),
        UInt256::calc_file_hash(&write_boc(&cell).unwrap()),
    )
}
fn context(config: &ConfigParams, id: BlockIdExt) -> PqVerificationContext {
    PqVerificationContext::from_governing_config(-239, config, id, 0, 0, 7).unwrap()
}
fn candidate_preimage(session: &UInt256, slot: u32, candidate: &[u8]) -> Vec<u8> {
    let id =
        CandidateId { slot: slot as i32, hash: UInt256::calc_file_hash(candidate) }.into_boxed();
    WireProfile::T0
        .serialize(
            &DataToSign {
                session_id: session.clone(),
                data: WireProfile::T0.serialize(&id).unwrap(),
            }
            .into_boxed(),
        )
        .unwrap()
}
fn validate_old(row: &Value, config: &ConfigParams) {
    let block = Block::construct_from_cell(root(&row["block_boc"])).unwrap();
    let ctx = context(config, block_id(&block));
    assert_eq!(hex::encode(ctx.expected_session_id().as_slice()), row["session"].as_str().unwrap());
    let candidate = hex::decode(row["candidate"].as_str().unwrap()).unwrap();
    let slot = row["slot"].as_u64().unwrap() as u32;
    for (field, value) in [
        (
            "preimage",
            build_simplex_vote_data(ctx.expected_session_id(), slot, &candidate, true)
                .unwrap()
                .data_to_sign,
        ),
        (
            "approval_preimage",
            build_simplex_vote_data(ctx.expected_session_id(), slot, &candidate, false)
                .unwrap()
                .data_to_sign,
        ),
        ("candidate_preimage", candidate_preimage(ctx.expected_session_id(), slot, &candidate)),
    ] {
        assert_eq!(hex::encode(value), row[field].as_str().unwrap(), "old {field} mapping");
    }
}
fn prepare(input: &str, keys: &str, out: &str) {
    let mut data: Value = serde_json::from_slice(&std::fs::read(input).unwrap()).unwrap();
    let public: Vec<String> = serde_json::from_slice(&std::fs::read(keys).unwrap()).unwrap();
    assert_eq!(public.len(), 3);
    let mut config = ConfigParams::construct_from_cell(root(&data["config_boc"])).unwrap();
    let old_config = config.clone();
    let old_set = config.validator_set().unwrap();
    assert_eq!(old_set.total(), 3);
    for row in data["rows"].as_array().unwrap() {
        validate_old(row, &config);
    }
    let mut custody = Vec::new();
    let members:Vec<_>=old_set.list().iter().enumerate().map(|(index,old)| {
        let key=hex::decode(&public[index]).unwrap();let key_id=derive_consensus_key_id(1,&key);
        custody.push(json!({"validator_id":hex::encode(old.validator_id().unwrap().as_slice()),"seed":hex::encode(UInt256::calc_file_hash(format!("rtos/publication-custody-fixture/v1/{index}").as_bytes()).as_slice()),"key_id":hex::encode(key_id.as_slice()),"public_key":public[index]}));
        ValidatorDescr::with_pq_params(old.validator_id().unwrap(),PqConsensusKey{algorithm_id:1,key_id,public_key:key},old.weight,old.adnl_addr.clone().unwrap())
    }).collect();
    assert_eq!(data["rows"].as_array().unwrap().len(), 2);
    let new_set =
        ValidatorSet::new(old_set.utime_since(), old_set.utime_until(), old_set.main(), members)
            .unwrap();
    config
        .set_config(ConfigParamEnum::ConfigParam34(ConfigParam34 { cur_validators: new_set }))
        .unwrap();
    let cc = config.catchain_config().unwrap();
    let before = old_set.calc_subset(&cc, SHARD_FULL, 0, 7).unwrap().0;
    let (after, new_subset_hash) =
        config.validator_set().unwrap().calc_subset(&cc, SHARD_FULL, 0, 7).unwrap();
    assert_eq!(
        before.iter().map(|m| m.validator_id().unwrap()).collect::<Vec<_>>(),
        after.iter().map(|m| m.validator_id().unwrap()).collect::<Vec<_>>(),
        "preserve creator/leader subset indices"
    );
    let mut state = ShardStateUnsplit::construct_from_cell(root(&data["state_boc"])).unwrap();
    assert!(state.read_accounts().unwrap().is_empty());
    let mut extra = state.read_custom().unwrap().unwrap();
    assert_eq!(extra.config, old_config);
    extra.config = config.clone();
    extra.validator_info.validator_list_hash_short = config
        .validator_set()
        .unwrap()
        .calc_subset(&cc, SHARD_FULL, -1, extra.validator_info.catchain_seqno)
        .unwrap()
        .1;
    state.write_custom(Some(&extra)).unwrap();
    let mc = state.serialize().unwrap();
    let mc_hash = mc.repr_hash().clone();
    let mc_file = UInt256::calc_file_hash(&write_boc(&mc).unwrap());
    data["state_boc"] = boc(mc);
    data["config_boc"] = boc(config.serialize().unwrap());
    let old_ordinary = UInt256::calc_file_hash(
        &hex::decode(data["rows"][0]["candidate"].as_str().unwrap()).unwrap(),
    );
    let mut ordinary = None;
    for row in data["rows"].as_array_mut().unwrap() {
        let mut block = Block::construct_from_cell(root(&row["block_boc"])).unwrap();
        let mut info = block.read_info().unwrap();
        info.set_gen_validator_list_hash_short(new_subset_hash);
        let mut master = info.read_master_ref().unwrap().unwrap();
        master.master.root_hash = mc_hash.clone();
        master.master.file_hash = mc_file.clone();
        info.write_master_ref(Some(&master)).unwrap();
        block.write_info(&info).unwrap();
        let id = block_id(&block);
        let ctx = context(&config, id.clone());
        let mut candidate: CandidateHashData = WireProfile::T0
            .deserialize_typed(&hex::decode(row["candidate"].as_str().unwrap()).unwrap())
            .unwrap();
        match &mut candidate {
            CandidateHashData::Consensus_CandidateHashDataOrdinary(value) => {
                value.block = id.clone();
            }
            CandidateHashData::Consensus_CandidateHashDataEmpty(value) => {
                value.block = id.clone();
                assert_eq!(value.parent.hash, old_ordinary);
                value.parent.hash =
                    ordinary.clone().expect("ordinary creator precedes empty trigger");
            }
        }
        let bytes = WireProfile::T0.serialize(&candidate).unwrap();
        if row["candidate_kind"] == "ordinary" {
            ordinary = Some(UInt256::calc_file_hash(&bytes));
        }
        let slot = row["slot"].as_u64().unwrap() as u32;
        row["block_boc"] = boc(block.serialize().unwrap());
        row["candidate"] = hex::encode(&bytes).into();
        row["session"] = hex::encode(ctx.expected_session_id().as_slice()).into();
        row["subset_hash"] = ctx.subset_hash().into();
        row["preimage"] = hex::encode(
            build_simplex_vote_data(ctx.expected_session_id(), slot, &bytes, true)
                .unwrap()
                .data_to_sign,
        )
        .into();
        row["approval_preimage"] = hex::encode(
            build_simplex_vote_data(ctx.expected_session_id(), slot, &bytes, false)
                .unwrap()
                .data_to_sign,
        )
        .into();
        row["candidate_preimage"] =
            hex::encode(candidate_preimage(ctx.expected_session_id(), slot, &bytes)).into();
        for field in ["signatures", "approval_signatures", "candidate_signatures"] {
            for sig in row[field].as_array_mut().unwrap() {
                sig["signature"] = Value::Null;
            }
        }
    }
    data["public_custody"] = custody.into();
    data["reference_commit"] = include_str!("../../../ci/conformance/REFERENCE").trim().into();
    let mut wrong_state = state.clone();
    wrong_state.set_gen_time(state.gen_time() + 1);
    let mut wrong_candidate: CandidateHashData = WireProfile::T0
        .deserialize_typed(&hex::decode(data["rows"][0]["candidate"].as_str().unwrap()).unwrap())
        .unwrap();
    match &mut wrong_candidate {
        CandidateHashData::Consensus_CandidateHashDataOrdinary(value) => {
            value.block.file_hash = UInt256::from([0xe7; 32])
        }
        _ => panic!("first row must be ordinary"),
    }
    let controls = json!({"wrong_governing_state":boc(wrong_state.serialize().unwrap()),"wrong_candidate":hex::encode(WireProfile::T0.serialize(&wrong_candidate).unwrap())});
    std::fs::write(format!("{out}.controls.json"), serde_json::to_vec_pretty(&controls).unwrap())
        .unwrap();
    std::fs::write(out, serde_json::to_vec_pretty(&data).unwrap()).unwrap();
}
fn verify(input: &str) {
    let data: Value = serde_json::from_slice(&std::fs::read(input).unwrap()).unwrap();
    let config = ConfigParams::construct_from_cell(root(&data["config_boc"])).unwrap();
    let set = config.validator_set().unwrap();
    for row in data["rows"].as_array().unwrap() {
        validate_old(row, &config);
        for signature in row["candidate_signatures"].as_array().unwrap() {
            let member = &set.list()[signature["index"].as_u64().unwrap() as usize];
            assert!(rtos_pq_crypto::verify_simplex(
                &hex::decode(row["candidate_preimage"].as_str().unwrap()).unwrap(),
                &hex::decode(signature["signature"].as_str().unwrap()).unwrap(),
                &member.pq_key().unwrap().public_key
            )
            .unwrap());
        }
        let block = Block::construct_from_cell(root(&row["block_boc"])).unwrap();
        let id = block_id(&block);
        let ctx = context(&config, id);
        for (field, final_role) in [("signatures", true), ("approval_signatures", false)] {
            let signatures: Vec<_> = row[field]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| PqBlockSignaturePair {
                    validator_id: set.list()[s["index"].as_u64().unwrap() as usize]
                        .validator_id()
                        .unwrap(),
                    algorithm_id: 1,
                    signature: hex::decode(s["signature"].as_str().unwrap()).unwrap(),
                })
                .collect();
            let carrier = BlockSignaturesSimplexPq {
                validator_info: ValidatorBaseInfo::with_params(ctx.subset_hash(), 7),
                session_id: ctx.expected_session_id().clone(),
                slot: row["slot"].as_u64().unwrap() as u32,
                candidate_data: BlockSignaturesSimplex::bytes_to_cell_tree(
                    &hex::decode(row["candidate"].as_str().unwrap()).unwrap(),
                )
                .unwrap(),
                sig_count: signatures.len() as u32,
                sig_weight: row["weight"].as_u64().unwrap(),
                signatures,
            };
            if final_role {
                ctx.verify_final(&carrier).unwrap();
            } else {
                ctx.verify_approval(&PqApproval::from_notarization_fields(carrier).unwrap())
                    .unwrap();
            }
        }
    }
    println!("both final and approval roles verified for ordinary and empty-trigger candidates");
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    match args[1].as_str() {
        "prepare" => prepare(&args[2], &args[3], &args[4]),
        "verify" => verify(&args[2]),
        _ => panic!("prepare or verify required"),
    }
}
