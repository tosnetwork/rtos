use super::*;
use crate::{
    engine_traits::EngineOperations,
    test_helper::{init_test_log, TestEngine},
};

#[ignore]
#[tokio::test]
async fn test_pss_fast_saving() -> Result<()> {
    init_test_log();
    let db_path = "/db";
    let res_path = "./";

    let engine = Arc::new(TestEngine::new_db_dir(db_path, Some(res_path)).await?);

    let last_id = engine.load_shard_client_mc_block_id()?.unwrap();
    let last_mc_state = engine.load_state(&last_id).await?;
    let db = engine.db.clone();

    // Build PssStorerPrevStuff (same as PssStorer::new does)
    let mc_state = engine.load_state(&last_id).await?;
    let split_depth = mc_state.config_params()?.base_workchain()?.persistent_state_split_depth;
    let prev_blocks_dict = &mc_state.shard_state_extra()?.prev_blocks;
    let (prev_handle, prev_top_blocks) =
        find_prev_pss(&db, engine.load_block_handle(&last_id)?.unwrap(), prev_blocks_dict)
            .await?
            .expect("No prev PSS found");

    let prev_block = db.load_block_data(&prev_handle).await?;
    let prev_split_depth =
        prev_block.read_config_params()?.base_workchain()?.persistent_state_split_depth;

    let db_ = db.clone();
    let load_cell = Arc::new(move |h: &UInt256| db_.load_cell(h));
    let cells_cache = CellsCache::new(load_cell, 50_000_000);

    let mut prev_stuff = PssStorerPrevStuff {
        mc_id: prev_handle.id().clone(),
        top_blocks: prev_top_blocks,
        split_depth: prev_split_depth,
        cells_cache,
        cached_states: HashSet::new(),
        prev_part_max_size: 5 * 1024 * 1024 * 1024,
    };

    // Get shard state and compute part roots
    let last_shard_id = last_mc_state.top_blocks(0)?.remove(0);
    let last_shard_state = engine.load_state(&last_shard_id).await?;
    let shard_handle = engine.load_block_handle(&last_shard_id)?.unwrap();
    log::info!("Last shard state: {}", last_shard_state.block_id());

    let mut part_prefixes = Vec::new();
    calc_pss_split_parts(last_shard_id.shard().clone(), split_depth, &mut part_prefixes)?;

    let abort = Arc::new(|| false) as Arc<dyn Fn() -> bool + Send + Sync>;

    for part_prefix in &part_prefixes {
        let root = last_shard_state
            .state()?
            .read_accounts()?
            .subtree_with_prefix(&part_prefix.shard_key(false), &mut 0)?
            .write_to_new_cell()?
            .into_cell()?;

        let part_id =
            PersistentStatePartId::Part(last_shard_id.clone(), part_prefix.shard_prefix_with_tag());

        PssStorer::store_one_part_fast(
            &mut prev_stuff,
            &db,
            &shard_handle,
            &part_id,
            root,
            abort.clone(),
        )
        .await?;
    }

    Ok(())
}

#[ignore]
#[tokio::test]
async fn test_pss_storer() -> Result<()> {
    init_test_log();
    let db_path = "/db";
    let res_path = "./";

    let engine = Arc::new(TestEngine::new_db_dir(db_path, Some(res_path)).await?);

    let id = engine.load_last_applied_mc_block_id()?.unwrap();
    let handle = engine.load_block_handle(&id)?.unwrap();

    let storer = PssStorer::new(
        engine.db.clone(),
        engine as Arc<dyn EngineOperations>,
        handle.clone(),
        50_000_000,
        5 * 1024 * 1024 * 1024, // 5 GB
    )
    .await?;
    storer.store().await?;

    println!("Press Enter to exit...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_snapshot_cache_and_merge_require_authenticated_state_identity() -> Result<()> {
    #[cfg(feature = "telemetry")]
    use crate::collator_test_bundle::create_engine_telemetry;
    use crate::collator_test_bundle::{create_block_handle_storage, create_engine_allocated};
    use rtos_block::write_boc;
    let dir = tempfile::tempdir()?;
    let engine = TestEngine::new_db_dir(dir.path().to_str().unwrap(), None).await?;
    let stopper = Arc::new(Stopper::new());
    let keeper = ShardStatesKeeper::new(
        engine.db.clone(),
        false,
        true,
        0,
        0,
        ShardStatesCacheMode::Moderate,
        u64::MAX,
        stopper.clone(),
        100,
        #[cfg(feature = "telemetry")]
        create_engine_telemetry(),
        create_engine_allocated(),
    )?;
    let handles = create_block_handle_storage(None)?;
    let id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        42,
        UInt256::from([1; 32]),
        UInt256::from([2; 32]),
    );
    let handle =
        handles.create_handle(id.clone(), storage::types::BlockMeta::default(), None)?.unwrap();
    handle.set_state();
    handle.set_persistent_state();
    for mutation in 0..5 {
        let mut header = ShardStateUnsplit::with_ident(id.shard().clone());
        header.set_seq_no(if mutation == 3 { 43 } else { 42 });
        if mutation == 4 {
            header.set_shard(ShardIdent::full(0));
        }
        let mut claimed = id.clone();
        if mutation == 2 {
            claimed.file_hash = UInt256::from([3; 32]);
        }
        let state = ShardStateStuff::from_state(
            claimed,
            header,
            #[cfg(feature = "telemetry")]
            &keeper.telemetry,
            &keeper.allocated,
        )?;
        let expected_root =
            if mutation == 1 { UInt256::default() } else { state.root_cell().repr_hash().clone() };
        keeper.states.insert(id.clone(), (state.clone(), handle.clone()));
        let whole =
            keeper.check_and_store_state(&handle, &expected_root, Arc::new(vec![]), vec![]).await;
        let split =
            keeper.merge_and_check_state(&handle, &expected_root, &[], Arc::new(vec![])).await;
        if mutation == 0 {
            assert!(Arc::ptr_eq(&whole?.0, &state));
            assert!(Arc::ptr_eq(&split?, &state));
        } else {
            let expected = match mutation {
                1 => "Snapshot root",
                2 => "Snapshot block identity",
                _ => "Snapshot header",
            };
            assert!(
                whole.err().unwrap().to_string().contains(expected),
                "whole mutation {mutation}"
            );
            assert!(
                split.err().unwrap().to_string().contains(expected),
                "split mutation {mutation}"
            );
        }
    }
    // The reconstructed root alone cannot authorize contradictory state metadata.
    // Check the uncached split path and ensure it rejects before setting state flags.
    for wrong_header in [true, false] {
        let mut header = ShardStateUnsplit::with_ident(ShardIdent::masterchain());
        header.set_seq_no(if wrong_header { 44 } else { 42 });
        let root = header.serialize()?;
        let mut block_id = id.clone();
        block_id.root_hash = UInt256::from([if wrong_header { 5 } else { 6 }; 32]);
        let h =
            handles.create_handle(block_id, storage::types::BlockMeta::default(), None)?.unwrap();
        let proof = MerkleProof::create(&root, |_| true)?.serialize()?;
        let result = keeper
            .merge_and_check_state(&h, root.repr_hash(), &[], Arc::new(write_boc(&proof)?))
            .await;
        if wrong_header {
            assert!(result.is_err());
            assert!(!h.has_state(), "invalid snapshot was stored before header rejection");
        } else {
            result?.verify_state_root(h.id(), root.repr_hash())?;
            assert!(h.has_state());
        }
    }
    stopper.set_stop();
    engine.db.stop_states_db().await.unwrap();
    Ok(())
}

/// The state write is asynchronous; pin once it is physically present.
async fn wait_pin(keeper: &Arc<ShardStatesKeeper>, id: &BlockIdExt) -> Result<PinnedShardStateGuard> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        match keeper.pin_cleanup_candidate(id) {
            Ok(guard) => return Ok(guard),
            Err(error) if std::time::Instant::now() >= deadline => return Err(error),
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
        }
    }
}

fn floor_keeper(db: Arc<InternalDb>, stopper: Arc<Stopper>) -> Result<Arc<ShardStatesKeeper>> {
    #[cfg(feature = "telemetry")]
    use crate::collator_test_bundle::create_engine_telemetry;
    use crate::collator_test_bundle::create_engine_allocated;
    ShardStatesKeeper::new(
        db,
        false,
        true,
        0,
        0,
        ShardStatesCacheMode::Moderate,
        3600,
        stopper,
        100,
        #[cfg(feature = "telemetry")]
        create_engine_telemetry(),
        create_engine_allocated(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cleanup_floor_custody_restores_and_never_replaces_a_missing_floor() -> Result<()> {
    use crate::collator_test_bundle::create_block_handle_storage;
    use consensus_common::validator_cleanup::{decode_checkpoint, encode_checkpoint, GC_FLOOR_KEY};
    let id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        42,
        UInt256::from([1; 32]),
        UInt256::from([2; 32]),
    );
    let floor_key = |db: &InternalDb| -> Result<Option<BlockIdExt>> {
        Ok(db.load_validator_state_key_bounded(GC_FLOOR_KEY, 256)?.and_then(|v| decode_checkpoint(&v)))
    };

    // A floor is adopted only with a deletion-coordinated pin, persisted synced.
    let dir = tempfile::tempdir()?;
    let engine = TestEngine::new_db_dir(dir.path().to_str().unwrap(), None).await?;
    let stopper = Arc::new(Stopper::new());
    let keeper = floor_keeper(engine.db.clone(), stopper.clone())?;
    assert!(keeper.cleanup_floor_unset());
    assert!(keeper.cleanup_floor().is_none());
    assert!(keeper.pin_cleanup_candidate(&id).is_err(), "no physical state, no pin");
    let handles = create_block_handle_storage(None)?;
    let handle =
        handles.create_handle(id.clone(), storage::types::BlockMeta::default(), None)?.unwrap();
    let mut header = ShardStateUnsplit::with_ident(ShardIdent::masterchain());
    header.set_seq_no(42);
    let state = ShardStateStuff::from_state(
        id.clone(),
        header,
        #[cfg(feature = "telemetry")]
        &keeper.telemetry,
        &keeper.allocated,
    )?;
    keeper.store_state(&handle, state, None, true).await?;
    let guard = wait_pin(&keeper, &id).await?;
    keeper.adopt_cleanup_floor(&id, guard)?;
    assert_eq!(keeper.cleanup_floor().map(|(floor, _)| floor), Some(id.clone()));
    assert!(!keeper.cleanup_floor_unset());
    assert_eq!(floor_key(&engine.db)?, Some(id.clone()), "persisted before publication");
    stopper.set_stop();
    engine.db.stop_states_db().await.unwrap();

    // A persisted floor whose state is gone stays Missing: cleanup is
    // disabled, the key is kept, and no replacement is ever adopted.
    let dir = tempfile::tempdir()?;
    let engine = TestEngine::new_db_dir(dir.path().to_str().unwrap(), None).await?;
    engine
        .db
        .write_validator_state_batch_sync(&[(GC_FLOOR_KEY.to_owned(), encode_checkpoint(&id))], &[])?;
    let stopper = Arc::new(Stopper::new());
    let keeper = floor_keeper(engine.db.clone(), stopper.clone())?;
    assert!(keeper.cleanup_floor().is_none());
    assert!(!keeper.cleanup_floor_unset(), "a missing floor is not a first run");
    let mut header = ShardStateUnsplit::with_ident(ShardIdent::masterchain());
    header.set_seq_no(42);
    let state = ShardStateStuff::from_state(
        id.clone(),
        header,
        #[cfg(feature = "telemetry")]
        &keeper.telemetry,
        &keeper.allocated,
    )?;
    let handles = create_block_handle_storage(None)?;
    let handle =
        handles.create_handle(id.clone(), storage::types::BlockMeta::default(), None)?.unwrap();
    keeper.store_state(&handle, state, None, true).await?;
    let guard = wait_pin(&keeper, &id).await?;
    assert!(keeper.adopt_cleanup_floor(&id, guard).is_err(), "never replaced");
    assert_eq!(floor_key(&engine.db)?, Some(id), "the key is retained");
    stopper.set_stop();
    engine.db.stop_states_db().await.unwrap();
    Ok(())
}
