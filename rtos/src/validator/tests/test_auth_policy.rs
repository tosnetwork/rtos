// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use super::*;
use rtos_block::SliceData;

// Synthetic configuration-contract/state-extra divergence exercises the real
// installation path; it is not a governance-transaction history fixture.
async fn auth_bundle(kind: &str) -> Result<CollatorTestBundle> {
    let (mut state, _, _) =
        construct_from_file::<ShardStateUnsplit>("src/tests/static/zerostate.boc")?;
    let mut original = state.read_custom()?.unwrap();
    let old = rtos_block::AuthPolicy {
        network: UInt256::from([7; 32]),
        sequence: 1,
        retired: 2,
        deadline: 200,
    };
    original.config.set_config(ConfigParamEnum::ConfigParam48(old.clone()))?;
    for number in [9, 10] {
        let cell = original.config.config_cell_slice(number)?.into_cell()?;
        let mut map = rtos_block::HashmapE::with_hashmap(32, Some(cell));
        map.set(48u32.write_to_bitstring()?, &SliceData::default())?;
        original
            .config
            .set_config(ConfigParamEnum::ConfigParamAny(number, map.data().unwrap().clone()))?;
    }
    let mut proposed = original.clone();
    let mut next = old;
    match kind {
        "unchanged" => (),
        "valid" => {
            next.sequence = 2;
            next.deadline = 100;
        }
        "network" => {
            next.sequence = 2;
            next.network = UInt256::from([8; 32]);
        }
        "sequence" => {
            next.deadline = 100;
        }
        "retired" => {
            next.sequence = 2;
            next.retired = 0;
        }
        "deadline" => {
            next.sequence = 2;
            next.deadline = 201;
        }
        "unschedule" => {
            next.sequence = 2;
            next.deadline = 0;
        }
        _ => unreachable!(),
    }
    proposed.config.set_config(ConfigParamEnum::ConfigParam48(next))?;
    state.write_custom(Some(&proposed))?;
    state.update_config_smc()?;
    state.write_custom(Some(&original))?;
    let file = tempfile::NamedTempFile::new()?;
    std::fs::write(file.path(), rtos_block::write_boc(&state.serialize()?)?)?;
    CollatorTestBundle::build_with_zero_state(
        file.path().to_str().unwrap(),
        &["src/tests/static/basestate0.boc"],
    )
    .await
}

async fn collate_auth(
    bundle: Arc<CollatorTestBundle>,
    shard: ShardIdent,
    prev: Vec<BlockIdExt>,
    validate: bool,
) -> Result<(BlockCandidate, ShardStateUnsplit)> {
    let id = bundle.index.last_mc_state.clone();
    match try_collate(
        bundle,
        &id,
        shard,
        prev,
        None,
        None,
        Some(UInt256::default()),
        true,
        validate,
        true,
    )
    .await?
    {
        CollateResult::Ok { candidate, new_state, .. } => Ok((candidate, new_state)),
        CollateResult::Err { err, .. } => Err(err),
    }
}

fn write_auth_candidate(candidate: &BlockCandidate, name: &str) -> Result<()> {
    let dir = std::env::var("RTOS_AUTH_CANDIDATE_EXPORT")?;
    std::fs::create_dir_all(&dir)?;
    std::fs::write(format!("{dir}/{name}.boc"), &candidate.data)?;
    std::fs::write(format!("{dir}/{name}.collated.boc"), &candidate.collated_data)?;
    Ok(())
}

// Frozen candidates were generated with only the collator transition gate
// temporarily omitted. Normal tests always use the production validator gate.
fn read_auth_candidate(name: &str) -> Result<BlockCandidate> {
    let dir = "src/tests/static/auth-policy";
    let data = std::fs::read(format!("{dir}/{name}.boc"))?;
    let collated_data = std::fs::read(format!("{dir}/{name}.collated.boc"))?;
    let root = read_single_root_boc(&data)?;
    let info = rtos_block::Block::construct_from_cell(root.clone())?.read_info()?;
    // Migrate only missing time metadata in the frozen historical test input.
    // The configuration transition under test and the block bytes stay intact.
    let mut roots = if collated_data.is_empty() {
        Vec::new()
    } else {
        rtos_block::read_boc(&collated_data)?.roots
    };
    let metadata = roots
        .iter()
        .filter_map(|cell| rtos_block::ConsensusExtraData::construct_from_cell(cell.clone()).ok())
        .collect::<Vec<_>>();
    if metadata.is_empty() {
        roots.push(
            rtos_block::ConsensusExtraData {
                flags: 0,
                gen_utime_ms: u64::from(info.gen_utime()) * 1000,
            }
            .serialize()?,
        );
    } else {
        assert_eq!(metadata.len(), 1);
        assert_eq!(metadata[0].gen_utime_ms / 1000, u64::from(info.gen_utime()));
    }
    let collated_data =
        rtos_block::BocWriter::with_flags(roots, rtos_block::BocFlags::Crc32)?.write_to_vec()?;
    Ok(BlockCandidate {
        block_id: BlockIdExt::with_params(
            info.shard().clone(),
            info.seq_no(),
            root.repr_hash().clone(),
            UInt256::calc_file_hash(&data),
        ),
        collated_file_hash: UInt256::calc_file_hash(&collated_data),
        data,
        collated_data,
        created_by: UInt256::default(),
    })
}

async fn validate_auth_candidate(
    bundle: Arc<CollatorTestBundle>,
    candidate: BlockCandidate,
    prev: Vec<BlockIdExt>,
) -> Result<()> {
    let shard = candidate.block_id.shard().clone();
    let state = bundle.load_state(&bundle.index.last_mc_state).await?;
    let extra = state.shard_state_extra()?;
    let cc = if shard.is_masterchain() {
        extra.validator_info.catchain_seqno
    } else {
        extra.shards.calc_shard_cc_seqno(&shard)?
    };
    let mut delta = 0;
    let nodes =
        compute_validator_set_cc(&state, &shard, candidate.block_id.seq_no(), cc, &mut delta)?;
    let validators = ValidatorSet::with_cc_seqno(0, 0, 0, delta, nodes)?;
    let simplex = detect_simplex(&state, &shard)?;
    ValidateQuery::new(shard, 0, prev, None, candidate, validators, bundle, true, true, simplex)
        .try_validate()
        .await?;
    Ok(())
}

#[tokio::test]
async fn auth_collator_config_transition() -> Result<()> {
    for kind in ["unchanged", "valid", "network", "sequence", "retired", "deadline", "unschedule"] {
        let bundle = Arc::new(auth_bundle(kind).await?);
        let valid = matches!(kind, "unchanged" | "valid");
        let result = collate_auth(
            bundle.clone(),
            ShardIdent::masterchain(),
            bundle.index.prev_blocks.clone(),
            valid,
        )
        .await;
        if valid {
            result?;
        } else {
            let error = result.err().expect("AUTH rollback must fail collation").to_string();
            assert!(error.contains("AUTH retirement policy cannot roll back"), "{kind}: {error}");
        }
    }
    Ok(())
}

#[tokio::test]
async fn auth_validator_config_transition() -> Result<()> {
    for kind in ["network", "sequence", "retired", "deadline", "unschedule"] {
        let bundle = Arc::new(auth_bundle(kind).await?);
        if std::env::var_os("RTOS_AUTH_CANDIDATE_EXPORT").is_some() {
            let (candidate, _) = collate_auth(
                bundle.clone(),
                ShardIdent::masterchain(),
                bundle.index.prev_blocks.clone(),
                false,
            )
            .await?;
            write_auth_candidate(&candidate, kind)?;
        } else {
            let result = validate_auth_candidate(
                bundle.clone(),
                read_auth_candidate(kind)?,
                bundle.index.prev_blocks.clone(),
            )
            .await;
            let error =
                result.err().expect("AUTH rollback candidate must fail validation").to_string();
            assert!(error.contains("AUTH retirement policy cannot roll back"), "{kind}: {error}");
        }
    }
    Ok(())
}
