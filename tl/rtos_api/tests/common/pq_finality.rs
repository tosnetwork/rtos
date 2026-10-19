// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use rtos_api::pq_finality::PqVerificationContext;
use rtos_block::*;

pub fn config() -> ConfigParams {
    let keys: Vec<String> =
        serde_json::from_str(include_str!("../data/pq-finality-keys.json")).unwrap();
    let validators: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(i, hex)| {
            let key = hex::decode(hex).unwrap();
            ValidatorDescr::with_pq_params(
                UInt256::from([(i + 1) as u8; 32]),
                PqConsensusKey {
                    algorithm_id: 1,
                    key_id: derive_consensus_key_id(1, &key),
                    public_key: key,
                },
                (i + 1) as u64,
                UInt256::from([(i + 11) as u8; 32]),
            )
        })
        .collect();
    let mut config = ConfigParams::default();
    config.set_config(ConfigParamEnum::ConfigParam19((-239i32) as u32)).unwrap();
    config
        .set_config(ConfigParamEnum::ConfigParam28(CatchainConfig {
            shuffle_mc_validators: false,
            ..Default::default()
        }))
        .unwrap();
    config
        .set_config(ConfigParamEnum::ConfigParam29(ConsensusConfig {
            new_catchain_ids: true,
            round_candidates: 3,
            next_candidate_delay_ms: 2000,
            consensus_timeout_ms: 16000,
            fast_attempts: 4,
            attempt_duration: 16,
            catchain_max_deps: 4,
            max_block_bytes: 4 << 20,
            max_collated_bytes: 4 << 20,
            ..Default::default()
        }))
        .unwrap();
    // The pinned fixture (config cell, governing session, signatures) was built with
    // a 2400 ms target rate; keep it explicit rather than following the default.
    let simplex = SimplexConfig {
        noncritical_params: NoncriticalParams { target_rate_ms: 2400, ..Default::default() },
        ..Default::default()
    };
    config
        .set_config(ConfigParamEnum::ConfigParam30(NewConsensusConfigAll {
            mc: Some(simplex.clone()),
            shard: Some(simplex),
        }))
        .unwrap();
    config
        .set_config(ConfigParamEnum::ConfigParam34(ConfigParam34 {
            cur_validators: ValidatorSet::new(0, 100000, 2, validators).unwrap(),
        }))
        .unwrap();
    config
}

pub fn target_block() -> Block {
    let mut info = BlockInfo::default();
    info.set_seq_no(42).unwrap();
    info.set_shard(ShardIdent::masterchain());
    info.set_gen_utime(1000);
    info.set_prev_key_block_seqno(10);
    info.set_vertical_stuff(0, 1, None).unwrap();
    Block::with_params(
        -239,
        info,
        ValueFlow::default(),
        MerkleUpdate::default(),
        BlockExtra::default(),
    )
    .unwrap()
}

pub fn block_id() -> BlockIdExt {
    let cell = target_block().serialize().unwrap();
    BlockIdExt::with_params(
        ShardIdent::masterchain(),
        42,
        cell.repr_hash().clone(),
        UInt256::calc_file_hash(&write_boc(&cell).unwrap()),
    )
}

pub fn context(config: &ConfigParams) -> PqVerificationContext {
    PqVerificationContext::from_governing_config(-239, config, block_id(), 1, 10, 7).unwrap()
}

pub fn unsigned(context: &PqVerificationContext) -> BlockSignaturesSimplexPq {
    // Independent literal TL encoding: boxed candidateHashDataEmpty, bare
    // blockIdExt, bare parent candidateId. No production serializer is reused.
    let mut candidate = 0x8354642du32.to_le_bytes().to_vec();
    candidate.extend((-1i32).to_le_bytes());
    candidate.extend(0x8000000000000000u64.to_le_bytes());
    candidate.extend(42u32.to_le_bytes());
    candidate.extend(block_id().root_hash.as_slice());
    candidate.extend(block_id().file_hash.as_slice());
    candidate.extend(98u32.to_le_bytes());
    candidate.extend([5; 32]);
    BlockSignaturesSimplexPq {
        validator_info: ValidatorBaseInfo::with_params(context.subset_hash(), 7),
        sig_count: 0,
        sig_weight: 0,
        signatures: vec![],
        session_id: context.expected_session_id().clone(),
        slot: 99,
        candidate_data: BuilderData::with_raw(candidate.clone(), candidate.len() * 8)
            .unwrap()
            .into_cell()
            .unwrap(),
    }
}

pub fn signed(indices: &[usize], role: &str, signing_context: &str) -> BlockSignaturesSimplexPq {
    let data: serde_json::Value =
        serde_json::from_str(include_str!("../data/pq-finality.json")).unwrap();
    let context = context(&config());
    let mut carrier = unsigned(&context);
    assert_eq!(hex::encode(carrier.session_id.as_slice()), data["session"].as_str().unwrap());
    for index in indices {
        let row = data["signatures"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["index"] == *index && r["role"] == role && r["context"] == signing_context)
            .unwrap();
        carrier.signatures.push(PqBlockSignaturePair {
            validator_id: UInt256::from([(*index + 1) as u8; 32]),
            algorithm_id: 1,
            signature: hex::decode(row["signature"].as_str().unwrap()).unwrap(),
        });
        carrier.sig_count += 1;
        carrier.sig_weight += (*index + 1) as u64;
    }
    carrier
}
