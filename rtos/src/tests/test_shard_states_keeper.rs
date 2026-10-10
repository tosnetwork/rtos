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
    engine.db.stop_states_db().await;
    Ok(())
}
