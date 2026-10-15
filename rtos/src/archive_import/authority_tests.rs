use super::*;

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("../../../tl/rtos_api/tests/data/archive-authority.json"))
        .unwrap()
}

fn initial() -> (ValidatorState, BlockIdExt) {
    let data = fixture();
    let bytes = hex::decode(data["zerostate"].as_str().unwrap()).unwrap();
    let root = read_single_root_boc(&bytes).unwrap();
    let pin = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        0,
        root.repr_hash().clone(),
        UInt256::calc_file_hash(&bytes),
    );
    let zero = crate::shard_state::ShardStateStuff::deserialize_zerostate(
        pin.clone(),
        &bytes,
        #[cfg(feature = "telemetry")]
        &crate::collator_test_bundle::create_engine_telemetry(),
        &crate::collator_test_bundle::create_engine_allocated(),
    )
    .unwrap();
    (ValidatorState::new(&pin, zero).unwrap(), pin)
}

fn proof(seq: usize, corrupt: bool) -> BlockProofStuff {
    bootstrap_fixture_proof(&fixture()["cases"][seq - 1], true, corrupt)
}

fn raw(start: usize, end: usize, corrupt: usize) -> HashMap<BlockIdExt, RawEntry> {
    (start..=end)
        .map(|seq| {
            let proof = proof(seq, seq == corrupt);
            (
                proof.id().clone(),
                RawEntry {
                    block_data: hex::decode(
                        fixture()["cases"][seq - 1]["block_boc"].as_str().unwrap(),
                    )
                    .unwrap(),
                    block_offset: 0,
                    proof_data: proof.data().to_vec(),
                    proof_offset: 0,
                },
            )
        })
        .collect()
}

#[test]
fn archive_authority_batches_authenticate_and_rollback() {
    let (mut validator, pin) = initial();
    assert!(parse_mc_entries(raw(1, 2, 2), &mut validator, false, pin.clone()).is_err());
    assert!(validator.current_key_block_proof().is_none());
    let (_, _, _, state) =
        parse_mc_entries(raw(1, 2, 0), &mut validator, false, pin.clone()).unwrap();
    assert_eq!(state.mc_block_id, *proof(2, false).id());
    assert_eq!(validator.current_key_block_proof().unwrap().id(), proof(1, false).id());
    assert!(
        parse_mc_entries(raw(3, 4, 4), &mut validator, false, state.mc_block_id.clone()).is_err()
    );
    assert_eq!(validator.current_key_block_proof().unwrap().id(), proof(1, false).id());
    parse_mc_entries(raw(3, 4, 0), &mut validator, false, state.mc_block_id).unwrap();
    assert_eq!(validator.current_key_block_proof().unwrap().id(), proof(3, false).id());
    assert!(parse_mc_entries(raw(1, 2, 0), &mut validator, false, pin).is_err());
}

#[test]
fn archive_authority_rejects_skip_gaps_and_multiple_keys() {
    let (mut validator, pin) = initial();
    assert!(parse_mc_entries(raw(1, 2, 0), &mut validator, true, pin.clone()).is_err());
    assert!(parse_mc_entries(raw(1, 4, 0), &mut validator, false, pin.clone()).is_err());
    let wrong = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        0,
        UInt256::from([9; 32]),
        pin.file_hash.clone(),
    );
    assert!(parse_mc_entries(raw(1, 2, 0), &mut validator, false, wrong).is_err());
    assert!(parse_mc_entries(raw(2, 2, 0), &mut validator, false, pin).is_err());
    assert!(validator.current_key_block_proof().is_none());
}

#[tokio::test]
async fn archive_authority_resume_authenticates_boundary_history() {
    for boundary in [2, 4] {
        let (mut validator, _) = initial();
        let id = validator
            .restore_to(boundary, |seq| async move { Ok(proof(seq as usize, false)) })
            .await
            .unwrap();
        assert_eq!(&id, proof(boundary as usize, false).id());
        assert_eq!(validator.current_key_block_proof().unwrap().id().seq_no, boundary - 1);
    }
    for corrupt in [1, 3, 4] {
        let (mut validator, _) = initial();
        assert!(validator
            .restore_to(4, |seq| async move { Ok(proof(seq as usize, seq == corrupt)) })
            .await
            .is_err());
        assert!(validator.current_key_block_proof().is_none());
    }
    let (mut validator, _) = initial();
    assert!(validator
        .restore_to(2, |seq| async move { Ok(proof(if seq == 1 { 3 } else { 2 }, false)) })
        .await
        .is_err());
    assert!(validator.current_key_block_proof().is_none());
}

fn bootstrap_fixture_proof(
    row: &serde_json::Value,
    signed: bool,
    corrupt: bool,
) -> BlockProofStuff {
    use rtos_block::*;
    let bytes = hex::decode(row["block_boc"].as_str().unwrap()).unwrap();
    let root = read_single_root_boc(&bytes).unwrap();
    let block = Block::construct_from_cell(root.clone()).unwrap();
    let info = block.read_info().unwrap();
    let id = BlockIdExt::with_params(
        info.shard().clone(),
        info.seq_no(),
        root.repr_hash().clone(),
        UInt256::calc_file_hash(&bytes),
    );
    let signatures = signed.then(|| {
        let mut signature = hex::decode(row["signature"].as_str().unwrap()).unwrap();
        if corrupt {
            signature[0] ^= 1;
        }
        BlockSignaturesVariant::SimplexPq(BlockSignaturesSimplexPq {
            validator_info: ValidatorBaseInfo::with_params(
                row["subset_hash"].as_u64().unwrap() as u32,
                7,
            ),
            session_id: UInt256::from_slice(
                &hex::decode(row["session"].as_str().unwrap()).unwrap(),
            ),
            slot: row["slot"].as_u64().unwrap() as u32,
            candidate_data: BlockSignaturesSimplex::bytes_to_cell_tree(
                &hex::decode(row["candidate"].as_str().unwrap()).unwrap(),
            )
            .unwrap(),
            sig_count: 1,
            sig_weight: 2,
            signatures: vec![PqBlockSignaturePair {
                validator_id: UInt256::from([2; 32]),
                algorithm_id: 1,
                signature,
            }],
        })
    });
    BlockProofStuff::new(
        BlockProof::with_params(
            id,
            MerkleProof::create(&root, |_| true).unwrap().serialize().unwrap(),
            signatures,
        ),
        !signed,
    )
    .unwrap()
}

fn import_config(dir: &Path) -> crate::archive_import::ImportConfig {
    crate::archive_import::ImportConfig {
        archives_path: dir.join("archives"),
        epochs_path: dir.join("epochs"),
        epoch_size: 20_000,
        node_db_path: dir.join("node_db"),
        mc_zerostate_path: dir.join("zero.boc"),
        wc_zerostate_paths: vec![],
        global_config_path: dir.join("global.json"),
        skip_validation: false,
        move_files: true,
    }
}

#[tokio::test]
async fn archive_authority_skip_rejected_before_io() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = import_config(dir.path());
    config.skip_validation = true;
    let error = crate::archive_import::run_import(config).await.err().unwrap();
    assert!(error.to_string().contains("--skip-validation is unsupported"));
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn archive_authority_native_import_and_resume() -> Result<()> {
    use storage::{
        archives::{package::Package, package_entry::PackageEntry, package_entry_id::GetFileName},
        block_handle_db::NodeStateDb,
        db::rocksdb::{AccessType, RocksDb, NODE_DB_NAME, NODE_STATE_DB_NAME},
    };
    let dir = tempfile::tempdir()?;
    let (_, pin) = initial();
    let mut global: serde_json::Value =
        serde_json::from_str(include_str!("../tests/config/mainnet.json"))?;
    global["validator"] = serde_json::json!({"zero_state": {
        "workchain": -1, "shard": i64::MIN, "seqno": 0,
        "root_hash": pin.root_hash.as_base64(false), "file_hash": pin.file_hash.as_base64(false)
    }});
    std::fs::write(dir.path().join("global.json"), serde_json::to_vec(&global)?)?;
    std::fs::write(
        dir.path().join("zero.boc"),
        hex::decode(fixture()["zerostate"].as_str().unwrap())?,
    )?;
    std::fs::create_dir(dir.path().join("archives"))?;
    let package_context_dir = tempfile::tempdir()?;
    let package_context_db = storage::db::rocksdb::RocksDb::new(package_context_dir.path(), "provider", None, storage::db::rocksdb::AccessType::ReadWrite)?;
    let package_view = package_context_db.bind_archive_domain(storage::archives::context::ArchiveDomain::new())?.view()?;
    let package_operation = package_view.enter()?;
    for start in [1, 3] {
        let path = dir.path().join("archives").join(format!("archive.{start:05}.pack"));
        let package = Package::open(package_view.clone(), &package_operation, path.clone(), false, true).await?;
        for (id, entry) in raw(start, start + 1, 0) {
            package
                .append_entry(
                    PackageEntry::with_data(
                        PackageEntryId::Block(id.clone()).filename(),
                        entry.block_data,
                    ),
                    |_, _| Ok(()),
                )
                .await?;
            package
                .append_entry(
                    PackageEntry::with_data(
                        PackageEntryId::Proof(id).filename(),
                        entry.proof_data,
                    ),
                    |_, _| Ok(()),
                )
                .await?;
        }
        drop(package);
        let db = crate::archive_import::run_import(import_config(dir.path())).await?;
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            while Arc::strong_count(&db) > 1 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await?;
        drop(db);
        assert!(!path.exists(), "Successful import must consume the requested source package");
        let db =
            RocksDb::new(&dir.path().join("node_db"), NODE_DB_NAME, None, AccessType::ReadWrite)?;
        let states = NodeStateDb::with_db(db, NODE_STATE_DB_NAME, false)?;
        let cursor = states.get(&LAST_APPLIED_MC_BLOCK)?;
        assert_eq!(BlockIdExt::deserialize(&cursor)?, *proof(start + 1, false).id());
    }
    Ok(())
}
