// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use crate::{
    collator_test_bundle::{try_validate, CollatorTestBundle},
    engine_traits::EngineOperations,
    validator::{validator_utils::compute_validator_set_cc, BlockCandidate},
};
use rtos_block::{Block, Deserializable, Result, Serializable, UInt256, ValidatorSet};
use std::sync::Arc;

const BUNDLE: &str = "src/tests/static/0.6000000000000000_439_d27493e2_collator_test_bundle";
// Independently computed from the archived governing state using the fixed reference.
const CATCHAIN_SEQNO: u32 = 3;
const SUBSET_HASH: u32 = 3494234678;

fn candidate_with_header(original: &BlockCandidate, seqno: u32, hash: u32) -> BlockCandidate {
    let mut candidate = original.clone();
    let mut block = Block::construct_from_bytes(&candidate.data).unwrap();
    let mut info = block.read_info().unwrap();
    info.set_gen_catchain_seqno(seqno);
    info.set_gen_validator_list_hash_short(hash);
    block.write_info(&info).unwrap();
    candidate.data = block.write_to_bytes().unwrap();
    candidate.block_id.root_hash = block.serialize().unwrap().repr_hash().clone();
    candidate.block_id.file_hash = UInt256::calc_file_hash(&candidate.data);
    candidate
}

// Exercise the complete non-fake validator with its expected set derived from
// the archived governing state. The bundle supplies in-memory proof cells.
async fn validate_real(engine: Arc<CollatorTestBundle>, candidate: BlockCandidate) -> Result<()> {
    let info = Block::construct_from_bytes(&candidate.data)?.read_info()?;
    let shard = info.shard().clone();
    let prev = info.read_prev_ids()?;
    let mc_id = if shard.is_masterchain() {
        prev[0].clone()
    } else {
        info.read_master_id()?.master_block_id().1
    };
    let state = engine.load_state(&mc_id).await?;
    let extra = state.shard_state_extra()?;
    let cc = if shard.is_masterchain() {
        extra.validator_info.catchain_seqno
    } else {
        extra.shards.calc_shard_cc_seqno(&shard)?
    };
    let mut derived_cc = 0;
    let nodes = compute_validator_set_cc(&state, &shard, info.seq_no(), cc, &mut derived_cc)?;
    let validators = ValidatorSet::with_cc_seqno(0, 0, 0, derived_cc, nodes)?;
    assert_eq!(validators.catchain_seqno(), CATCHAIN_SEQNO);
    assert_eq!(ValidatorSet::calc_subset_hash_short(validators.list(), derived_cc)?, SUBSET_HASH);
    let config = state.config_params()?;
    let simplex = if shard.is_masterchain() {
        config.get_mc_simplex_config()?.is_some()
    } else {
        config.get_shard_simplex_config()?.is_some()
    };
    super::ValidateQuery::new(
        shard,
        info.min_ref_mc_seqno() - 1,
        prev,
        None,
        candidate,
        validators,
        engine,
        false,
        false,
        simplex,
    )
    .try_validate()
    .await?;
    Ok(())
}

async fn check_headers(cases: &[(&str, u32, u32)], error_field: &str) {
    let bundle = Arc::new(CollatorTestBundle::load(BUNDLE).unwrap());
    let original = bundle.candidate().unwrap().clone();
    assert_eq!(
        original.block_id.root_hash.to_hex_string(),
        "d27493e29456e09f05a7fdf1d51a94106cea621b6e59e6a11f5da30eeb787bf2"
    );
    let valid = candidate_with_header(&original, CATCHAIN_SEQNO, SUBSET_HASH);
    if let Ok(dir) = std::env::var("RTOS_CANDIDATE_HEADER_EXPORT") {
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(std::path::Path::new(&dir).join("valid.boc"), &valid.data).unwrap();
    }
    validate_real(bundle.clone(), valid.clone())
        .await
        .expect("full non-fake validation accepts the migrated candidate");
    try_validate(bundle.clone(), valid).await.expect("the migrated full candidate is valid");
    let mut wrongly_accepted = vec![];
    for &(name, seqno, hash) in cases {
        let candidate = candidate_with_header(&original, seqno, hash);
        if let Ok(dir) = std::env::var("RTOS_CANDIDATE_HEADER_EXPORT") {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(std::path::Path::new(&dir).join(format!("{name}.boc")), &candidate.data)
                .unwrap();
        }
        match validate_real(bundle.clone(), candidate.clone()).await {
            Ok(_) => wrongly_accepted.push(name),
            Err(error) => assert!(error.to_string().contains(error_field), "real {name}: {error}"),
        }
        match try_validate(bundle.clone(), candidate).await {
            Ok(_) => wrongly_accepted.push(name),
            Err(error) => assert!(error.to_string().contains(error_field), "{name}: {error}"),
        }
    }
    assert!(
        wrongly_accepted.is_empty(),
        "accepted invalid header candidates: {wrongly_accepted:?}"
    );
}

#[tokio::test]
async fn candidate_header_rejects_wrong_validator_hash() {
    check_headers(
        &[
            ("legacy", 3, 4227316980),
            ("hash-bit", 3, SUBSET_HASH ^ 1),
            ("hash-zero", 3, 0),
            ("hash-max", 3, u32::MAX),
        ],
        "validator set hash",
    )
    .await;
}

#[tokio::test]
async fn candidate_header_rejects_wrong_catchain_sequence() {
    check_headers(
        &[
            ("cc-zero", 0, SUBSET_HASH),
            ("cc-next", 4, SUBSET_HASH),
            ("cc-max", u32::MAX, SUBSET_HASH),
        ],
        "catchain sequence",
    )
    .await;
}
