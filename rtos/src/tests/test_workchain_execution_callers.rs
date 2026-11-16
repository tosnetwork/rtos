// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use super::*;
use rtos_block::{
    BinTreeType, Block, BuilderData, ConfigParam12, IBitstring, WorkchainFormat, WorkchainFormat1,
};

async fn execution_bundle(kind: &str, transition: bool) -> Result<CollatorTestBundle> {
    let (mut state, _, _) =
        construct_from_file::<ShardStateUnsplit>("src/tests/static/zerostate.boc")?;
    let original = state.read_custom()?.unwrap();
    let mut extra = original.clone();
    let mut workchains = extra.config.workchains()?;
    let mut descriptor = workchains.get(&0)?.unwrap();
    descriptor.format = WorkchainFormat::Basic(WorkchainFormat1::with_params(
        if kind == "unknown" { 1 } else { -1 },
        if kind == "mode" { 1 } else { 0 },
    ));
    if kind == "root" {
        descriptor.zerostate_root_hash = UInt256::from([13; 32]);
    }
    workchains.set(&0, &descriptor)?;
    if kind.starts_with("malformed-") {
        let mut map = workchains.inner();
        let raw = descriptor.serialize()?;
        let mut bytes = raw.data().to_vec();
        match kind {
            "malformed-basic" => bytes[8] ^= 0x80,
            "malformed-flags" => bytes[9] |= 1,
            _ => (),
        }
        let mut value = BuilderData::with_raw(bytes, raw.bit_length())?;
        if kind == "malformed-tail" {
            value.append_bit_zero()?;
        }
        let id = if kind == "malformed-id" { i32::MIN } else { 0 };
        map.set_builder(id.write_to_bitstring()?, &value)?;
        extra.config.set_config(ConfigParamEnum::ConfigParamAny(12, map.serialize()?))?;
    } else {
        extra.config.set_config(ConfigParamEnum::ConfigParam12(ConfigParam12 { workchains }))?;
    }
    state.write_custom(Some(&extra))?;
    state.update_config_smc()?;
    if transition {
        state.write_custom(Some(&original))?;
    }
    let file = tempfile::NamedTempFile::new()?;
    std::fs::write(file.path(), rtos_block::write_boc(&state.serialize()?)?)?;
    CollatorTestBundle::build_with_zero_state(
        file.path().to_str().unwrap(),
        &["src/tests/static/basestate0.boc"],
    )
    .await
}

async fn collate_execution(
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

async fn execution_shard_bundle(kind: &str) -> Result<(Arc<CollatorTestBundle>, Vec<BlockIdExt>)> {
    let bundle = Arc::new(execution_bundle(kind, false).await?);
    let (mc, state) = collate_execution(
        bundle.clone(),
        ShardIdent::masterchain(),
        bundle.index.prev_blocks.clone(),
        true,
    )
    .await?;
    let mut bundle = Arc::try_unwrap(bundle).ok().unwrap();
    let mut prev = Vec::new();
    let extra = state.read_custom()?.unwrap();
    extra.shards.get(&0)?.unwrap().0.iterate(|prefix, descriptor| {
        prev.push(BlockIdExt::with_params(
            ShardIdent::with_prefix_slice(0, prefix)?,
            descriptor.seq_no,
            descriptor.root_hash,
            descriptor.file_hash,
        ));
        Ok(true)
    })?;
    bundle.index.last_mc_state = mc.block_id.clone();
    bundle.index.mc_states.push(mc.block_id.clone());
    bundle.index.now = state.gen_time() + 1;
    let new_state = ShardStateStuff::from_state(
        mc.block_id.clone(),
        state,
        #[cfg(feature = "telemetry")]
        &bundle.telemetry,
        &bundle.allocated,
    )?;
    bundle.states.insert(mc.block_id.clone(), new_state);
    bundle.prev_blocks.insert(
        mc.block_id.clone(),
        BlockStuff::deserialize_block(mc.block_id, Arc::new(mc.data))?,
    );
    Ok((Arc::new(bundle), prev))
}

#[tokio::test]
async fn execution_collator_local_role() -> Result<()> {
    for kind in ["tvm", "unknown", "mode"] {
        let (bundle, prev) = execution_shard_bundle(kind).await?;
        let result =
            collate_execution(bundle, ShardIdent::with_workchain_id(0)?, prev, kind == "tvm").await;
        if kind == "tvm" {
            result?;
        } else {
            let error = result.err().expect("unsupported local engine must fail").to_string();
            assert!(
                error.contains(if kind == "mode" {
                    "requires vm_mode=0"
                } else {
                    "missing local workchain execution engine"
                }),
                "{kind}: {error}"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn execution_collator_config_account_transition() -> Result<()> {
    for kind in ["tvm", "unknown", "mode", "root"] {
        let bundle = Arc::new(execution_bundle(kind, true).await?);
        let result = collate_execution(
            bundle.clone(),
            ShardIdent::masterchain(),
            bundle.index.prev_blocks.clone(),
            kind == "tvm",
        )
        .await;
        if kind == "tvm" {
            result?;
        } else {
            let error =
                result.err().expect("invalid config account transition must fail").to_string();
            assert!(error.contains("without a migration rule"), "{kind}: {error}");
        }
    }
    Ok(())
}

fn write_execution_candidate(candidate: &BlockCandidate, name: &str) -> Result<()> {
    let dir = std::env::var("RTOS_EXECUTION_EXPORT")?;
    std::fs::create_dir_all(&dir)?;
    std::fs::write(format!("{dir}/{name}.boc"), &candidate.data)?;
    std::fs::write(format!("{dir}/{name}.collated.boc"), &candidate.collated_data)?;
    Ok(())
}

fn read_execution_candidate(name: &str) -> Result<BlockCandidate> {
    let dir = "src/tests/static/workchain-execution";
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

// These two negative fixtures deliberately keep their historical WC body. Bind
// only their MC reference to the actual MC1 constructed by this test run.
async fn local_role_candidate(bundle: &CollatorTestBundle, name: &str) -> Result<BlockCandidate> {
    let mut candidate = read_execution_candidate(name)?;
    let expected = match name {
        "local-unknown" => "9314aae84e256f2dc80864b6bbeabbcc25cbc8ae08b52abaee3cdb48ab8d3a10",
        "local-mode" => "e32643fc3bbbe46818cb8beb63c12342620404f522d7dc48be95f2b8139fbabc",
        _ => panic!("unknown local execution fixture {name}"),
    };
    assert_eq!(candidate.block_id.root_hash().to_hex_string(), expected);
    let original_data = candidate.data.clone();
    let original = read_single_root_boc(&original_data)?;
    let mut block = Block::construct_from_cell(original.clone())?;
    let mut info = block.read_info()?;
    assert!(!info.shard().is_masterchain());
    let old_reference = info.read_master_ref()?.expect("local fixture MC reference");
    let master =
        bundle.prev_blocks.get(&bundle.index.last_mc_state).expect("generated masterchain anchor");
    assert!(master.id().shard().is_masterchain());
    assert_eq!(master.id().seq_no(), 1);
    assert_eq!(old_reference.master.seq_no, 1);
    let reference = rtos_block::BlkMasterInfo {
        master: rtos_block::ExtBlkRef {
            end_lt: master.block()?.read_info()?.end_lt(),
            seq_no: master.id().seq_no(),
            root_hash: master.id().root_hash().clone(),
            file_hash: master.id().file_hash().clone(),
        },
    };
    info.write_master_ref(Some(&reference))?;
    block.write_info(&info)?;
    let root = block.serialize()?;
    assert_eq!(original.data(), root.data());
    assert_eq!(original.references_count(), root.references_count());
    for index in 1..original.references_count() {
        assert_eq!(
            original.reference_repr_hash(index)?,
            root.reference_repr_hash(index)?,
            "local role migration changes only the info reference"
        );
    }
    let data = rtos_block::write_boc(&root)?;
    candidate.block_id = BlockIdExt::with_params(
        info.shard().clone(),
        info.seq_no(),
        root.repr_hash().clone(),
        UInt256::calc_file_hash(&data),
    );
    candidate.data = data;
    assert_eq!(
        Block::construct_from_cell(root)?.read_info()?.read_master_ref()?.unwrap(),
        reference
    );
    if let Some(path) = std::env::var_os("RTOS_EXECUTION_CONTEXT_EXPORT") {
        let path = std::path::PathBuf::from(path);
        std::fs::create_dir_all(&path)?;
        std::fs::write(path.join(format!("{name}-original.boc")), original_data)?;
        std::fs::write(path.join(format!("{name}-migrated.boc")), &candidate.data)?;
        std::fs::write(path.join(format!("{name}-mc1.boc")), master.data())?;
        let state = bundle.load_state(master.id()).await?;
        std::fs::write(
            path.join(format!("{name}-mc1-state.boc")),
            rtos_block::write_boc(&state.state()?.serialize()?)?,
        )?;
    }
    Ok(candidate)
}

async fn validate_execution_candidate(
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
async fn execution_validator_config_account_transition() -> Result<()> {
    for kind in ["unknown", "mode", "root"] {
        let bundle = Arc::new(execution_bundle(kind, true).await?);
        let name = format!("transition-{kind}");
        if std::env::var_os("RTOS_EXECUTION_EXPORT").is_some() {
            let (candidate, _) = collate_execution(
                bundle.clone(),
                ShardIdent::masterchain(),
                bundle.index.prev_blocks.clone(),
                false,
            )
            .await?;
            write_execution_candidate(&candidate, &name)?;
        } else {
            let result = validate_execution_candidate(
                bundle.clone(),
                read_execution_candidate(&name)?,
                bundle.index.prev_blocks.clone(),
            )
            .await;
            let error = result.err().expect("invalid candidate transition must fail").to_string();
            let expected = if kind == "root" {
                // New shard layout checks reject this genesis hash change before
                // configuration transition validation is reached.
                "incorrect zerostate hashes"
            } else {
                "without a migration rule"
            };
            assert!(error.contains(expected), "{kind}: {error}");
        }
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn execution_validator_local_role() -> Result<()> {
    crate::test_helper::fixture_clock(async {
        for kind in ["tvm", "unknown", "mode"] {
            let (bundle, prev) = execution_shard_bundle(kind).await?;
            let name = format!("local-{kind}");
            if kind == "tvm" {
                let (candidate, _) = collate_execution(
                    bundle.clone(),
                    ShardIdent::with_workchain_id(0)?,
                    prev.clone(),
                    false,
                )
                .await?;
                validate_execution_candidate(bundle, candidate, prev).await?;
                continue;
            }
            let candidate = local_role_candidate(&bundle, &name).await?;
            if std::env::var_os("RTOS_EXECUTION_EXPORT").is_some() {
                write_execution_candidate(&candidate, &name)?;
            } else {
                let result = validate_execution_candidate(bundle, candidate, prev).await;
                let error = result
                    .err()
                    .expect("unsupported local engine must fail validation")
                    .to_string();
                assert!(
                    error.contains(if kind == "mode" {
                        "requires vm_mode=0"
                    } else {
                        "missing local workchain execution engine"
                    }),
                    "{kind}: {error}"
                );
            }
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn execution_collator_malformed_descriptors() -> Result<()> {
    for (kind, expected) in [
        ("malformed-basic", "basic bit does not match format"),
        ("malformed-flags", "invalid workchain descriptor flags"),
        ("malformed-id", "invalid workchain execution identifier"),
        ("malformed-tail", "contains an invalid configuration in its data"),
    ] {
        let bundle = Arc::new(execution_bundle(kind, false).await?);
        let error = collate_execution(
            bundle.clone(),
            ShardIdent::masterchain(),
            bundle.index.prev_blocks.clone(),
            false,
        )
        .await
        .err()
        .expect("malformed descriptor must fail collation")
        .to_string();
        assert!(error.contains(expected), "{kind}: {error}");
    }
    Ok(())
}
