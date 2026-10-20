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
        crate::config::DEFAULT_STATE_TTL_SEC,
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
async fn wait_pin(
    keeper: &Arc<ShardStatesKeeper>,
    id: &BlockIdExt,
) -> Result<PinnedShardStateGuard> {
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
    use crate::collator_test_bundle::create_engine_allocated;
    #[cfg(feature = "telemetry")]
    use crate::collator_test_bundle::create_engine_telemetry;
    ShardStatesKeeper::new(
        db,
        false,
        true,
        0,
        0,
        ShardStatesCacheMode::Moderate,
        3600.0,
        stopper,
        100,
        #[cfg(feature = "telemetry")]
        create_engine_telemetry(),
        create_engine_allocated(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cleanup_floor_custody_restores_and_refuses_a_missing_floor() -> Result<()> {
    use consensus_common::validator_cleanup::{decode_checkpoint, encode_checkpoint, GC_FLOOR_KEY};
    let id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        42,
        UInt256::from([1; 32]),
        UInt256::from([2; 32]),
    );
    let floor_key = |db: &InternalDb| -> Result<Option<BlockIdExt>> {
        Ok(db
            .load_validator_state_key_bounded(GC_FLOOR_KEY, 256)?
            .and_then(|v| decode_checkpoint(&v)))
    };

    // A floor is adopted only with a deletion-coordinated pin, persisted synced.
    let dir = tempfile::tempdir()?;
    let engine = TestEngine::new_db_dir(dir.path().to_str().unwrap(), None).await?;
    let stopper = Arc::new(Stopper::new());
    let keeper = floor_keeper(engine.db.clone(), stopper.clone())?;
    assert!(keeper.cleanup_floor_unset());
    assert!(keeper.cleanup_floor().is_none());
    assert!(keeper.pin_cleanup_candidate(&id).is_err(), "no physical state, no pin");
    store_mc_state(&keeper, &id, None).await?;
    let guard = wait_pin(&keeper, &id).await?;
    keeper.adopt_cleanup_floor(&id, guard, keeper.cleanup_floor_epoch())?;
    assert_eq!(keeper.cleanup_floor().map(|(floor, _)| floor), Some(id.clone()));
    assert!(!keeper.cleanup_floor_unset());
    assert_eq!(floor_key(&engine.db)?, Some(id.clone()), "persisted before publication");
    stopper.set_stop();
    engine.db.stop_states_db().await.unwrap();

    // A persisted floor whose state is gone stops the node, as the
    // reference's startup check does; the key is kept and nothing replaces it.
    let dir = tempfile::tempdir()?;
    let engine = TestEngine::new_db_dir(dir.path().to_str().unwrap(), None).await?;
    engine.db.write_validator_state_batch_sync(
        &[(GC_FLOOR_KEY.to_owned(), encode_checkpoint(&id))],
        &[],
    )?;
    let stopper = Arc::new(Stopper::new());
    let error = match floor_keeper(engine.db.clone(), stopper.clone()) {
        Ok(_) => panic!("a floor without state must refuse the keeper"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("has no state"), "{error}");
    assert_eq!(floor_key(&engine.db)?, Some(id.clone()), "the key is retained");
    // A malformed key refuses the keeper too.
    engine.db.write_validator_state_batch_sync(&[(GC_FLOOR_KEY.to_owned(), vec![0xff; 7])], &[])?;
    assert!(floor_keeper(engine.db.clone(), stopper.clone()).is_err());
    stopper.set_stop();
    engine.db.stop_states_db().await.unwrap();
    Ok(())
}

/// Stores a masterchain state for `id`; with `prev`, its history records it.
async fn store_mc_state(
    keeper: &Arc<ShardStatesKeeper>,
    id: &BlockIdExt,
    prev: Option<&BlockIdExt>,
) -> Result<()> {
    use crate::collator_test_bundle::create_block_handle_storage;
    use rtos_block::{ExtBlkRef, HashmapAugType, KeyExtBlkRef, KeyMaxLt, McStateExtra};
    let mut header = ShardStateUnsplit::with_ident(ShardIdent::masterchain());
    header.set_seq_no(id.seq_no());
    let mut extra = McStateExtra::default();
    if let Some(prev) = prev {
        let reference = KeyExtBlkRef {
            key: false,
            blk_ref: ExtBlkRef {
                end_lt: 0,
                seq_no: prev.seq_no(),
                root_hash: prev.root_hash().clone(),
                file_hash: prev.file_hash().clone(),
            },
        };
        extra.prev_blocks.set(
            &prev.seq_no(),
            &reference,
            &KeyMaxLt { key: false, max_end_lt: 0 },
        )?;
    }
    header.write_custom(Some(&extra))?;
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
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cleanup_floor_adoption_is_monotonic_and_uncertain_writes_fail_closed() -> Result<()> {
    use consensus_common::validator_cleanup::{decode_checkpoint, GC_FLOOR_KEY};
    let mc = |seqno: u32, hash: u8| {
        BlockIdExt::with_params(
            ShardIdent::masterchain(),
            seqno,
            UInt256::from([hash; 32]),
            UInt256::from([hash; 32]),
        )
    };
    let (older, floor, successor, fork) = (mc(41, 1), mc(42, 2), mc(43, 3), mc(43, 4));
    let dir = tempfile::tempdir()?;
    let engine = TestEngine::new_db_dir(dir.path().to_str().unwrap(), None).await?;
    let stopper = Arc::new(Stopper::new());
    let keeper = floor_keeper(engine.db.clone(), stopper.clone())?;
    store_mc_state(&keeper, &older, None).await?;
    store_mc_state(&keeper, &floor, None).await?;
    store_mc_state(&keeper, &successor, Some(&floor)).await?;
    store_mc_state(&keeper, &fork, None).await?;
    keeper.adopt_cleanup_floor(
        &floor,
        wait_pin(&keeper, &floor).await?,
        keeper.cleanup_floor_epoch(),
    )?;
    // No regression, and no fork that does not record the current floor.
    assert!(keeper
        .adopt_cleanup_floor(&older, wait_pin(&keeper, &older).await?, keeper.cleanup_floor_epoch())
        .is_err());
    assert!(keeper
        .adopt_cleanup_floor(&fork, wait_pin(&keeper, &fork).await?, keeper.cleanup_floor_epoch())
        .is_err());
    assert_eq!(keeper.cleanup_floor().map(|(id, _)| id), Some(floor.clone()));
    // A write that committed but reported an error leaves the floor uncertain:
    // cleanup is disabled and nothing can be adopted until the key is re-read.
    keeper.fail_floor_write_after_commit.store(true, std::sync::atomic::Ordering::Release);
    assert!(keeper
        .adopt_cleanup_floor(
            &successor,
            wait_pin(&keeper, &successor).await?,
            keeper.cleanup_floor_epoch()
        )
        .is_err());
    assert!(keeper.cleanup_floor().is_none(), "uncertain disables cleanup");
    assert!(!keeper.cleanup_floor_unset());
    assert!(keeper
        .adopt_cleanup_floor(
            &successor,
            wait_pin(&keeper, &successor).await?,
            keeper.cleanup_floor_epoch()
        )
        .is_err());
    let durable = engine
        .db
        .load_validator_state_key_bounded(GC_FLOOR_KEY, 256)?
        .and_then(|value| decode_checkpoint(&value));
    assert_eq!(durable, Some(successor.clone()), "the write committed");
    // The read-back alone is not durability: a failed re-write stays uncertain.
    keeper.fail_floor_resolve_write.store(true, std::sync::atomic::Ordering::Release);
    assert!(keeper.resolve_uncertain_cleanup_floor(keeper.cleanup_floor_epoch()).is_err());
    assert!(keeper.cleanup_floor().is_none(), "a failed re-write keeps cleanup disabled");
    assert!(!keeper.cleanup_floor_unset());
    keeper.resolve_uncertain_cleanup_floor(keeper.cleanup_floor_epoch())?;
    assert_eq!(keeper.cleanup_floor().map(|(id, _)| id), Some(successor.clone()));
    assert!(keeper
        .adopt_cleanup_floor(&floor, wait_pin(&keeper, &floor).await?, keeper.cleanup_floor_epoch())
        .is_err());
    stopper.set_stop();
    engine.db.stop_states_db().await.unwrap();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_uncertain_first_floor_resolves_only_from_a_genuinely_absent_key() -> Result<()> {
    use consensus_common::validator_cleanup::GC_FLOOR_KEY;
    let floor = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        42,
        UInt256::from([2; 32]),
        UInt256::from([2; 32]),
    );
    let dir = tempfile::tempdir()?;
    let engine = TestEngine::new_db_dir(dir.path().to_str().unwrap(), None).await?;
    let stopper = Arc::new(Stopper::new());
    let keeper = floor_keeper(engine.db.clone(), stopper.clone())?;
    store_mc_state(&keeper, &floor, None).await?;
    keeper.fail_floor_write_after_commit.store(true, std::sync::atomic::Ordering::Release);
    assert!(keeper
        .adopt_cleanup_floor(&floor, wait_pin(&keeper, &floor).await?, keeper.cleanup_floor_epoch())
        .is_err());
    // Malformed bytes are not absence: no fresh bootstrap may follow.
    engine.db.write_validator_state_batch_sync(&[(GC_FLOOR_KEY.to_owned(), vec![0xff; 7])], &[])?;
    keeper.resolve_uncertain_cleanup_floor(keeper.cleanup_floor_epoch())?;
    assert!(keeper.cleanup_floor().is_none());
    assert!(!keeper.cleanup_floor_unset(), "malformed key stays uncertain");
    // A genuinely absent key with no previous floor resolves to unset.
    engine.db.write_validator_state_batch_sync(&[], &[GC_FLOOR_KEY.to_owned()])?;
    keeper.resolve_uncertain_cleanup_floor(keeper.cleanup_floor_epoch())?;
    assert!(keeper.cleanup_floor_unset());
    assert!(engine.db.load_validator_state_key_bounded(GC_FLOOR_KEY, 256)?.is_none());
    stopper.set_stop();
    engine.db.stop_states_db().await.unwrap();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cleanup_floor_is_re_pinned_from_the_same_db_after_restart() -> Result<()> {
    let floor = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        42,
        UInt256::from([2; 32]),
        UInt256::from([2; 32]),
    );
    let dir = tempfile::tempdir()?;
    let path = dir.path().to_str().unwrap().to_owned();
    {
        let engine = TestEngine::new_db_dir(&path, None).await?;
        let stopper = Arc::new(Stopper::new());
        let keeper = floor_keeper(engine.db.clone(), stopper.clone())?;
        store_mc_state(&keeper, &floor, None).await?;
        keeper.adopt_cleanup_floor(
            &floor,
            wait_pin(&keeper, &floor).await?,
            keeper.cleanup_floor_epoch(),
        )?;
        stopper.set_stop();
        engine.db.stop_states_db().await.unwrap();
    }
    // A restart on the same database restores and pins the persisted floor
    // before states GC runs: it is published again, not a first run.
    let engine = TestEngine::new_db_dir(&path, None).await?;
    let stopper = Arc::new(Stopper::new());
    let keeper = floor_keeper(engine.db.clone(), stopper.clone())?;
    let (restored, state) = keeper.cleanup_floor().expect("the floor is re-pinned at boot");
    assert_eq!(restored, floor);
    assert_eq!(state.block_id(), &floor, "the pinned state is the floor's own");
    assert!(!keeper.cleanup_floor_unset());
    stopper.set_stop();
    engine.db.stop_states_db().await.unwrap();
    Ok(())
}

/// The floor driver's inputs read from a real `InternalDb` and keeper with
/// the same calls the engine makes.
struct DbFloorSource {
    db: Arc<InternalDb>,
    keeper: Arc<ShardStatesKeeper>,
}

#[async_trait::async_trait]
impl crate::validator::validator_cleanup_gc::CleanupFloorSource for DbFloorSource {
    async fn last_applied_mc_state(&self) -> Result<Arc<ShardStateStuff>> {
        match self.db.load_full_node_state(crate::internal_db::LAST_APPLIED_MC_BLOCK)? {
            Some(id) => self.keeper.load_state(&id).await,
            None => fail!("No last applied MC block set"),
        }
    }
    fn last_rotation_block_id(&self) -> Result<Option<Arc<BlockIdExt>>> {
        self.db.load_validator_state(crate::internal_db::LAST_ROTATION_MC_BLOCK)
    }
    fn shard_client_mc_block_id(&self) -> Result<Option<Arc<BlockIdExt>>> {
        self.db.load_full_node_state(crate::internal_db::SHARD_CLIENT_MC_BLOCK)
    }
    fn pss_keeper_mc_block_id(&self) -> Result<Option<Arc<BlockIdExt>>> {
        self.db.load_full_node_state(crate::internal_db::PSS_KEEPER_MC_BLOCK)
    }
    fn block_next1(&self, id: &BlockIdExt) -> Result<BlockIdExt> {
        self.db.load_block_next1(id)
    }
    fn keeper(&self) -> Arc<ShardStatesKeeper> {
        self.keeper.clone()
    }
    fn init_block_id(&self) -> BlockIdExt {
        driver_mc(100, 1)
    }
}

/// Stores a synthetic masterchain state with a handle in the real handle DB.
async fn store_driver_state(
    keeper: &Arc<ShardStatesKeeper>,
    db: &InternalDb,
    id: &BlockIdExt,
    prev: Option<&BlockIdExt>,
    gen_time: u32,
    min_ref: u32,
) -> Result<Arc<storage::block_handle_db::BlockHandle>> {
    use rtos_block::{ExtBlkRef, HashmapAugType, KeyExtBlkRef, KeyMaxLt, McStateExtra};
    let mut header = ShardStateUnsplit::with_ident(ShardIdent::masterchain());
    header.set_seq_no(id.seq_no());
    header.set_gen_time(gen_time);
    header.set_min_ref_mc_seqno(min_ref);
    let mut extra = McStateExtra::default();
    extra.after_key_block = true;
    if let Some(prev) = prev {
        let reference = KeyExtBlkRef {
            key: false,
            blk_ref: ExtBlkRef {
                end_lt: 0,
                seq_no: prev.seq_no(),
                root_hash: prev.root_hash().clone(),
                file_hash: prev.file_hash().clone(),
            },
        };
        extra.prev_blocks.set(
            &prev.seq_no(),
            &reference,
            &KeyMaxLt { key: false, max_end_lt: 0 },
        )?;
    }
    header.write_custom(Some(&extra))?;
    let state = ShardStateStuff::from_state(
        id.clone(),
        header,
        #[cfg(feature = "telemetry")]
        &keeper.telemetry,
        &keeper.allocated,
    )?;
    let handle = db.create_test_block_handle(id)?;
    keeper.store_state(&handle, state, None, true).await?;
    Ok(handle)
}

fn driver_mc(seqno: u32, hash: u8) -> BlockIdExt {
    BlockIdExt::with_params(
        ShardIdent::masterchain(),
        seqno,
        UInt256::from([hash; 32]),
        UInt256::from([hash; 32]),
    )
}

/// A real DB with floor F (MC 100, expired), its successor `next` linked as
/// next1, last applied L at MC 2000, and frontiers rotation 1800, shard
/// client 1900 and PSS keeper `pss`. The floor is adopted at F.
async fn driver_fixture(
    dir: &std::path::Path,
    next: &BlockIdExt,
    next_prev: Option<&BlockIdExt>,
    floor_gen_time: u32,
    pss: u32,
) -> Result<(TestEngine, Arc<Stopper>, DbFloorSource)> {
    let engine = TestEngine::new_db_dir(dir.to_str().unwrap(), None).await?;
    let stopper = Arc::new(Stopper::new());
    let keeper = floor_keeper(engine.db.clone(), stopper.clone())?;
    let floor = driver_mc(100, 1);
    let now = u32::try_from(rtos_block::UnixTime::now()).unwrap_or(u32::MAX);
    let floor_handle =
        store_driver_state(&keeper, &engine.db, &floor, None, floor_gen_time, 0).await?;
    store_driver_state(&keeper, &engine.db, next, next_prev, 1, 0).await?;
    let last = driver_mc(2000, 9);
    store_driver_state(&keeper, &engine.db, &last, None, now, 1500).await?;
    engine.db.store_block_next1(&floor_handle, next, None)?;
    engine
        .db
        .save_validator_state(crate::internal_db::LAST_ROTATION_MC_BLOCK, &driver_mc(1800, 7))?;
    engine
        .db
        .save_full_node_state(crate::internal_db::SHARD_CLIENT_MC_BLOCK, &driver_mc(1900, 8))?;
    engine.db.save_full_node_state(crate::internal_db::PSS_KEEPER_MC_BLOCK, &driver_mc(pss, 6))?;
    engine.db.save_full_node_state(crate::internal_db::LAST_APPLIED_MC_BLOCK, &last)?;
    keeper.adopt_cleanup_floor(
        &floor,
        wait_pin(&keeper, &floor).await?,
        keeper.cleanup_floor_epoch(),
    )?;
    let source = DbFloorSource { db: engine.db.clone(), keeper };
    Ok((engine, stopper, source))
}

fn durable_floor(db: &InternalDb) -> Result<Option<BlockIdExt>> {
    use consensus_common::validator_cleanup::{decode_checkpoint, GC_FLOOR_KEY};
    Ok(db.load_validator_state_key_bounded(GC_FLOOR_KEY, 256)?.and_then(|v| decode_checkpoint(&v)))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cleanup_floor_driver_advances_one_verified_step_on_real_storage() -> Result<()> {
    use crate::validator::validator_cleanup_gc::maintain_cleanup_floor;
    let (floor, successor) = (driver_mc(100, 1), driver_mc(101, 2));
    let current = |source: &DbFloorSource| source.keeper.cleanup_floor().map(|(id, _)| id);

    // A frontier at the floor blocks advancement: floor and key stay F.
    let dir = tempfile::tempdir()?;
    let (engine, stopper, source) =
        driver_fixture(dir.path(), &successor, Some(&floor), 1, 100).await?;
    maintain_cleanup_floor(&source).await?;
    assert_eq!(current(&source), Some(floor.clone()));
    assert_eq!(durable_floor(&engine.db)?, Some(floor.clone()));

    // Every frontier clear and F expired: exactly one step, to the stored
    // next1, synced before publication.
    engine.db.save_full_node_state(crate::internal_db::PSS_KEEPER_MC_BLOCK, &driver_mc(1950, 6))?;
    maintain_cleanup_floor(&source).await?;
    assert_eq!(current(&source), Some(successor.clone()));
    assert_eq!(durable_floor(&engine.db)?, Some(successor.clone()));
    let (_, pinned) = source.keeper.cleanup_floor().unwrap();
    assert_eq!(pinned.block_id(), &successor);
    // No next1 from S: like the reference, no successor means no step.
    maintain_cleanup_floor(&source).await?;
    assert_eq!(current(&source), Some(successor.clone()));
    assert_eq!(durable_floor(&engine.db)?, Some(successor));
    stopper.set_stop();
    engine.db.stop_states_db().await.unwrap();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cleanup_floor_driver_refuses_a_fork_successor_and_a_live_floor() -> Result<()> {
    use crate::validator::validator_cleanup_gc::maintain_cleanup_floor;
    let floor = driver_mc(100, 1);
    let current = |source: &DbFloorSource| source.keeper.cleanup_floor().map(|(id, _)| id);

    // next1 names a fork whose history does not record F: refused, F kept.
    let fork = driver_mc(101, 3);
    let dir = tempfile::tempdir()?;
    let (engine, stopper, source) = driver_fixture(dir.path(), &fork, None, 1, 1950).await?;
    let error = maintain_cleanup_floor(&source).await.unwrap_err().to_string();
    assert!(error.contains("not a verified descendant"), "{error}");
    assert_eq!(current(&source), Some(floor.clone()));
    assert_eq!(durable_floor(&engine.db)?, Some(floor.clone()));
    stopper.set_stop();
    engine.db.stop_states_db().await.unwrap();

    // A floor younger than the state TTL never advances.
    let successor = driver_mc(101, 2);
    let dir = tempfile::tempdir()?;
    let future =
        u32::try_from(rtos_block::UnixTime::now()).unwrap_or(u32::MAX).saturating_add(100_000);
    let (engine, stopper, source) =
        driver_fixture(dir.path(), &successor, Some(&floor), future, 1950).await?;
    maintain_cleanup_floor(&source).await?;
    assert_eq!(current(&source), Some(floor.clone()));
    assert_eq!(durable_floor(&engine.db)?, Some(floor));
    stopper.set_stop();
    engine.db.stop_states_db().await.unwrap();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cleanup_sibling_scan_counts_oversized_records() -> Result<()> {
    use crate::validator::validator_cleanup_gc::session_has_other_records;
    use consensus_common::validator_cleanup::{
        encode_record, make_record, record_key, NamespaceLayout,
    };
    let dir = tempfile::tempdir()?;
    let engine = TestEngine::new_db_dir(dir.path().to_str().unwrap(), None).await?;
    let session = UInt256::from([0x77; 32]);
    let checkpoint = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        9,
        UInt256::from([1; 32]),
        UInt256::from([2; 32]),
    );
    let make = |layout| {
        make_record(&session, &layout, &ShardIdent::masterchain(), 5, &checkpoint).unwrap()
    };
    let own = make(NamespaceLayout::V2Validator);
    let observer = make(NamespaceLayout::V2Observer(UInt256::from([0x01; 32])));
    let later = make(NamespaceLayout::V2Observer(UInt256::from([0xfe; 32])));
    engine.db.write_validator_state_batch_sync(
        &[(record_key(&own.namespace), encode_record(&own).unwrap())],
        &[],
    )?;
    assert!(!session_has_other_records(&engine.db, &own.namespace, &session)?);
    // An oversized sibling sorting before a valid one is still a holder: the
    // scan never skips a key because of its value.
    engine.db.write_validator_state_batch_sync(
        &[(record_key(&observer.namespace), vec![0u8; 1 << 16])],
        &[],
    )?;
    assert!(session_has_other_records(&engine.db, &own.namespace, &session)?);
    engine.db.write_validator_state_batch_sync(
        &[(record_key(&later.namespace), encode_record(&later).unwrap())],
        &[],
    )?;
    assert!(session_has_other_records(&engine.db, &own.namespace, &session)?);
    assert!(session_has_other_records(&engine.db, &later.namespace, &session)?);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_synced_validator_state_block_id_round_trips_and_replaces() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let engine = TestEngine::new_db_dir(dir.path().to_str().unwrap(), None).await?;
    let key = "LastRotationBlockIdSyncTest";
    let first = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        20,
        UInt256::from([3; 32]),
        UInt256::from([4; 32]),
    );
    let second = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        21,
        UInt256::from([5; 32]),
        UInt256::from([6; 32]),
    );
    engine.db.save_validator_state_sync(key, &second)?;
    assert_eq!(engine.db.load_validator_state(key)?.as_deref(), Some(&second));
    engine.db.save_validator_state_sync(key, &first)?;
    assert_eq!(engine.db.load_validator_state(key)?.as_deref(), Some(&first));
    engine.db.stop_states_db().await.unwrap();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_truncation_is_exclusive_bounded_by_the_floor_and_invalidates_floor_work() -> Result<()>
{
    let mc = |seqno: u32, hash: u8| {
        BlockIdExt::with_params(
            ShardIdent::masterchain(),
            seqno,
            UInt256::from([hash; 32]),
            UInt256::from([hash; 32]),
        )
    };
    let (floor, successor, next) = (mc(42, 2), mc(43, 3), mc(44, 4));
    let dir = tempfile::tempdir()?;
    let engine = TestEngine::new_db_dir(dir.path().to_str().unwrap(), None).await?;
    let stopper = Arc::new(Stopper::new());
    let keeper = floor_keeper(engine.db.clone(), stopper.clone())?;
    store_mc_state(&keeper, &floor, None).await?;
    store_mc_state(&keeper, &successor, Some(&floor)).await?;
    store_mc_state(&keeper, &next, Some(&successor)).await?;
    keeper.adopt_cleanup_floor(
        &floor,
        wait_pin(&keeper, &floor).await?,
        keeper.cleanup_floor_epoch(),
    )?;

    // Never below the floor; at the floor itself it is admitted.
    assert!(keeper.begin_truncation(41).is_err());
    drop(keeper.begin_truncation(42)?);

    // Floor work prepared before a truncation: epoch read, candidate pinned.
    let stale = keeper.cleanup_floor_epoch();
    let prepared = wait_pin(&keeper, &successor).await?;
    let truncation = keeper.begin_truncation(50)?;
    // Exclusive: a second admission is refused and cannot end the first.
    assert!(keeper.begin_truncation(50).is_err());
    assert!(keeper.begin_truncation(50).is_err(), "the refused attempt did not clear it");
    // Frozen: no adoption or resolution, even with the current epoch.
    let current = keeper.cleanup_floor_epoch();
    assert!(keeper
        .adopt_cleanup_floor(&successor, wait_pin(&keeper, &successor).await?, current)
        .is_err());
    assert!(keeper.resolve_uncertain_cleanup_floor(current).is_err());
    drop(truncation);
    assert_eq!(keeper.cleanup_floor_epoch(), stale + 2, "both increments published");
    // The work prepared before the truncation is refused; fresh work is not.
    assert!(keeper.adopt_cleanup_floor(&successor, prepared, stale).is_err());
    assert_eq!(keeper.cleanup_floor().map(|(id, _)| id), Some(floor.clone()));
    keeper.adopt_cleanup_floor(
        &successor,
        wait_pin(&keeper, &successor).await?,
        keeper.cleanup_floor_epoch(),
    )?;
    assert_eq!(keeper.cleanup_floor().map(|(id, _)| id), Some(successor.clone()));

    // While uncertain, both pins bound truncation.
    keeper.fail_floor_write_after_commit.store(true, std::sync::atomic::Ordering::Release);
    assert!(keeper
        .adopt_cleanup_floor(&next, wait_pin(&keeper, &next).await?, keeper.cleanup_floor_epoch())
        .is_err());
    assert!(keeper.cleanup_floor().is_none(), "uncertain");
    assert!(keeper.begin_truncation(43).is_err(), "the candidate lies above the head");
    drop(keeper.begin_truncation(44)?);

    // Exhaustion: both increments are reserved up front, or nothing changes.
    keeper.set_floor_epoch_for_test(u64::MAX - 1);
    assert!(keeper.begin_truncation(50).is_err());
    assert_eq!(keeper.cleanup_floor_epoch(), u64::MAX - 1);
    keeper.set_floor_epoch_for_test(u64::MAX - 2);
    drop(keeper.begin_truncation(50)?);
    assert_eq!(keeper.cleanup_floor_epoch(), u64::MAX);
    stopper.set_stop();
    engine.db.stop_states_db().await.unwrap();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_direct_database_truncation_refuses_below_the_durable_floor() -> Result<()> {
    use consensus_common::validator_cleanup::{decode_checkpoint, encode_checkpoint, GC_FLOOR_KEY};
    let mc = |seqno: u32| {
        BlockIdExt::with_params(
            ShardIdent::masterchain(),
            seqno,
            UInt256::from([seqno as u8; 32]),
            UInt256::from([seqno as u8; 32]),
        )
    };
    let dir = tempfile::tempdir()?;
    let engine = TestEngine::new_db_dir(dir.path().to_str().unwrap(), None).await?;
    let db = engine.db.clone();
    // The block to truncate from (50); its new head would be 49.
    let target = mc(50);
    let handle = db.create_test_block_handle(&target)?;
    db.store_block_prev1(&handle, &mc(49), None)?;
    let floor_bytes = |db: &InternalDb| db.load_validator_state_key_bounded(GC_FLOOR_KEY, 256);
    for (floor, refused) in [(mc(60), true), (mc(50), true), (mc(49), false), (mc(30), false)] {
        db.write_validator_state_batch_sync(
            &[(GC_FLOOR_KEY.to_owned(), encode_checkpoint(&floor))],
            &[],
        )?;
        let before = floor_bytes(&db)?;
        let error = db.truncate_database(&target).await.unwrap_err().to_string();
        assert_eq!(error.contains("below the cleanup floor"), refused, "{floor}: {error}");
        if !refused {
            // Past the check, it fails later on this synthetic chain.
            assert!(error.contains("no handle"), "{error}");
        }
        assert!(db.load_block_handle(&target)?.is_some(), "nothing truncated");
        assert_eq!(floor_bytes(&db)?, before, "the floor key is never touched");
        assert_eq!(before.and_then(|v| decode_checkpoint(&v)), Some(floor));
    }
    db.write_validator_state_batch_sync(&[(GC_FLOOR_KEY.to_owned(), vec![1, 2, 3])], &[])?;
    let error = db.truncate_database(&target).await.unwrap_err().to_string();
    assert!(error.contains("Malformed validator-cleanup GC floor"), "{error}");
    db.stop_states_db().await.unwrap();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "disk-full harness only"]
async fn disk_full_floor_adoption_is_uncertain_then_resolves_previous_or_candidate() -> Result<()> {
    use crate::publication_dependency_leases::disk_full_tests::{control, enospc_root, Filler};
    use consensus_common::validator_cleanup::{decode_checkpoint, GC_FLOOR_KEY};
    let mc = |seqno: u32, hash: u8| {
        BlockIdExt::with_params(
            ShardIdent::masterchain(),
            seqno,
            UInt256::from([hash; 32]),
            UInt256::from([hash; 32]),
        )
    };
    let (floor, successor) = (mc(42, 2), mc(43, 3));
    let root = enospc_root().join("floor");
    std::fs::create_dir_all(&root)?;
    let durable = |db: &InternalDb| -> Result<Option<BlockIdExt>> {
        Ok(db
            .load_validator_state_key_bounded(GC_FLOOR_KEY, 256)?
            .and_then(|v| decode_checkpoint(&v)))
    };
    let engine = TestEngine::new_db_dir(root.to_str().unwrap(), None).await?;
    let stopper = Arc::new(Stopper::new());
    let keeper = floor_keeper(engine.db.clone(), stopper.clone())?;
    store_mc_state(&keeper, &floor, None).await?;
    store_mc_state(&keeper, &successor, Some(&floor)).await?;
    keeper.adopt_cleanup_floor(
        &floor,
        wait_pin(&keeper, &floor).await?,
        keeper.cleanup_floor_epoch(),
    )?;
    let candidate = wait_pin(&keeper, &successor).await?;
    engine.db.rotate_validator_state_wal_for_test()?;
    if control() {
        keeper.adopt_cleanup_floor(&successor, candidate, keeper.cleanup_floor_epoch())?;
        assert_eq!(durable(&engine.db)?, Some(successor.clone()));
        assert_eq!(keeper.cleanup_floor().map(|(id, _)| id), Some(successor));
        stopper.set_stop();
        engine.db.stop_states_db().await.unwrap();
        eprintln!("ENOSPC-CASE V3 control ok");
        return Ok(());
    }
    let filler = Filler::fill(&root);
    let error = keeper
        .adopt_cleanup_floor(&successor, candidate, keeper.cleanup_floor_epoch())
        .unwrap_err();
    assert!(format!("{error:#}").contains("No space left on device"), "{error:#}");
    // The store's contract: the floor is uncertain, cleanup is disabled and
    // nothing is adopted until the key is re-read.
    assert!(keeper.cleanup_floor().is_none());
    assert!(!keeper.cleanup_floor_unset());
    filler.free();
    // In process, the DB still refuses writes after its WAL error: the
    // re-write cannot confirm either floor, so the floor stays uncertain.
    let resolved_in_process =
        keeper.resolve_uncertain_cleanup_floor(keeper.cleanup_floor_epoch()).is_ok();
    if !resolved_in_process {
        assert!(keeper.cleanup_floor().is_none(), "still fail-closed");
    }
    stopper.set_stop();
    engine.db.stop_states_db().await.unwrap();
    drop(keeper);
    drop(engine);
    // Cold reopen of the same directory: the durable floor is exactly the
    // previous one or the complete candidate, and is restored and pinned.
    let engine = TestEngine::new_db_dir(root.to_str().unwrap(), None).await?;
    let stopper = Arc::new(Stopper::new());
    let keeper = floor_keeper(engine.db.clone(), stopper.clone())?;
    let after = durable(&engine.db)?;
    assert!(after == Some(floor.clone()) || after == Some(successor.clone()), "{after:?}");
    assert_eq!(keeper.cleanup_floor().map(|(id, _)| id), after, "restored exactly");
    stopper.set_stop();
    engine.db.stop_states_db().await.unwrap();
    eprintln!("ENOSPC-CASE V3 resolved_in_process={resolved_in_process} durable_after={after:?}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "disk-full harness only"]
async fn disk_full_incarnation_is_refused_then_advances_past_any_applied_value() -> Result<()> {
    use crate::publication_dependency_leases::disk_full_tests::{control, enospc_root, Filler};
    use crate::validator::validator_cleanup_gc::next_cleanup_incarnation;
    let root = enospc_root().join("incarnation");
    std::fs::create_dir_all(&root)?;
    let engine = TestEngine::new_db_dir(root.to_str().unwrap(), None).await?;
    let first = next_cleanup_incarnation(&engine.db)?;
    engine.db.rotate_validator_state_wal_for_test()?;
    if control() {
        assert_eq!(next_cleanup_incarnation(&engine.db)?, first + 1);
        engine.db.stop_states_db().await.unwrap();
        eprintln!("ENOSPC-CASE V4 control ok");
        return Ok(());
    }
    let filler = Filler::fill(&root);
    let error = next_cleanup_incarnation(&engine.db).unwrap_err();
    assert!(format!("{error:#}").contains("No space left on device"), "{error:#}");
    filler.free();
    // In process the DB keeps refusing writes after its WAL error: no
    // incarnation is established, so no attempt of any kind can start.
    let in_process = next_cleanup_incarnation(&engine.db);
    engine.db.stop_states_db().await.unwrap();
    drop(engine);
    // After a cold reopen the next advance only ever moves forward, past any
    // value the failed write may have applied.
    let engine = TestEngine::new_db_dir(root.to_str().unwrap(), None).await?;
    let next = next_cleanup_incarnation(&engine.db)?;
    let floor = in_process.as_ref().map_or(first, |value| *value);
    assert!(next > floor && next <= first + 3, "{first} -> {in_process:?} -> {next}");
    engine.db.stop_states_db().await.unwrap();
    eprintln!("ENOSPC-CASE V4 first={first} in_process={in_process:?} next={next}");
    Ok(())
}

/// One call runs the floor forward as far as it may go (the reference tries
/// again after each durable step), and a second driver waits for the owner.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_cleanup_floor_driver_catches_up_under_one_owner() -> Result<()> {
    use crate::validator::validator_cleanup_gc::maintain_cleanup_floor;
    let (floor, first, second) = (driver_mc(100, 1), driver_mc(101, 2), driver_mc(102, 3));
    let dir = tempfile::tempdir()?;
    let (engine, stopper, source) =
        driver_fixture(dir.path(), &first, Some(&floor), 1, 1950).await?;
    let first_handle =
        engine.db.load_block_handle(&first)?.ok_or_else(|| error!("no handle for {first}"))?;
    store_driver_state(&source.keeper, &engine.db, &second, Some(&first), 1, 0).await?;
    engine.db.store_block_next1(&first_handle, &second, None)?;
    wait_pin(&source.keeper, &second).await?;
    let source = Arc::new(source);
    let held = source.keeper.floor_owner().lock().await;
    let driver = {
        let source = source.clone();
        tokio::spawn(async move { maintain_cleanup_floor(source.as_ref()).await })
    };
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(source.keeper.cleanup_floor().map(|(id, _)| id), Some(floor.clone()));
    assert!(!driver.is_finished(), "a second driver waits for the owner");
    drop(held);
    driver.await.map_err(|e| error!("{e}"))??;
    assert_eq!(source.keeper.cleanup_floor().map(|(id, _)| id), Some(second.clone()));
    assert_eq!(durable_floor(&engine.db)?, Some(second));
    stopper.set_stop();
    engine.db.stop_states_db().await.unwrap();
    Ok(())
}

/// A floor never persisted starts at the given block, which must have its
/// state; once set, seeding changes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_gc_floor_seed_requires_the_state_and_happens_once() -> Result<()> {
    let (init, other) = (driver_mc(7, 1), driver_mc(9, 2));
    let dir = tempfile::tempdir()?;
    let engine = TestEngine::new_db_dir(dir.path().to_str().unwrap(), None).await?;
    let stopper = Arc::new(Stopper::new());
    let keeper = floor_keeper(engine.db.clone(), stopper.clone())?;
    assert!(keeper.seed_cleanup_floor(&init, keeper.cleanup_floor_epoch()).is_err());
    assert!(keeper.cleanup_floor_unset(), "a failed seed leaves no floor");
    assert_eq!(durable_floor(&engine.db)?, None);
    store_driver_state(&keeper, &engine.db, &init, None, 1, 0).await?;
    store_driver_state(&keeper, &engine.db, &other, None, 1, 0).await?;
    wait_pin(&keeper, &init).await?;
    wait_pin(&keeper, &other).await?;
    keeper.seed_cleanup_floor(&init, keeper.cleanup_floor_epoch())?;
    assert_eq!(keeper.cleanup_floor().map(|(id, _)| id), Some(init.clone()));
    assert_eq!(durable_floor(&engine.db)?, Some(init.clone()));
    keeper.seed_cleanup_floor(&other, keeper.cleanup_floor_epoch())?;
    assert_eq!(durable_floor(&engine.db)?, Some(init), "seeding never replaces a floor");
    assert_eq!(keeper.cleanup_state_ttl(), 3600.0);
    stopper.set_stop();
    engine.db.stop_states_db().await.unwrap();
    Ok(())
}

/// State GC follows the published floor in store order: below the floor a
/// state goes, but not past an older state the floor keeps, which stays
/// readable; the floor itself and newer states stay.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_state_gc_follows_the_floor_in_store_order() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let engine = TestEngine::new_db_dir(dir.path().to_str().unwrap(), None).await?;
    let stopper = Arc::new(Stopper::new());
    let keeper = floor_keeper(engine.db.clone(), stopper.clone())?;
    engine.db.adjust_states_gc_interval(1);
    let (old, newer, held, floor) =
        (driver_mc(50, 1), driver_mc(150, 2), driver_mc(60, 3), driver_mc(100, 4));
    for id in [&old, &newer, &held, &floor] {
        store_driver_state(&keeper, &engine.db, id, None, 1, 0).await?;
        wait_pin(&keeper, id).await?;
    }
    keeper.seed_cleanup_floor(&floor, keeper.cleanup_floor_epoch())?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while engine.db.test_contains_dynamic_state_record(&old)? {
        assert!(std::time::Instant::now() < deadline, "the oldest eligible state is collected");
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    assert!(engine.db.test_contains_dynamic_state_record(&newer)?);
    assert!(engine.db.test_contains_dynamic_state_record(&floor)?);
    assert!(
        engine.db.test_contains_dynamic_state_record(&held)?,
        "an eligible state behind a kept older one is not collected"
    );
    assert!(engine.db.load_shard_state_dynamic(&held).is_ok(), "and it stays readable");
    assert!(engine.db.load_shard_state_dynamic(&old).is_err());
    stopper.set_stop();
    engine.db.stop_states_db().await.unwrap();
    Ok(())
}

/// A floor write that committed but did not report success, followed by a
/// crash: the next start restores the committed floor and publishes it to
/// state GC; a crash before the write keeps the previous floor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_floor_adoption_crash_cuts_restart_on_the_durable_floor() -> Result<()> {
    let (floor, successor) = (driver_mc(42, 2), driver_mc(43, 3));
    let dir = tempfile::tempdir()?;
    let path = dir.path().to_str().unwrap().to_owned();
    {
        let engine = TestEngine::new_db_dir(&path, None).await?;
        let stopper = Arc::new(Stopper::new());
        let keeper = floor_keeper(engine.db.clone(), stopper.clone())?;
        store_mc_state(&keeper, &floor, None).await?;
        store_mc_state(&keeper, &successor, Some(&floor)).await?;
        keeper.adopt_cleanup_floor(
            &floor,
            wait_pin(&keeper, &floor).await?,
            keeper.cleanup_floor_epoch(),
        )?;
        keeper.fail_floor_write_after_commit.store(true, std::sync::atomic::Ordering::Release);
        assert!(keeper
            .adopt_cleanup_floor(
                &successor,
                wait_pin(&keeper, &successor).await?,
                keeper.cleanup_floor_epoch()
            )
            .is_err());
        assert_eq!(
            keeper.gc_resolver.published_floor().map(|f| f.seqno()),
            Some(42),
            "an uncertain write never publishes its floor"
        );
        stopper.set_stop();
        engine.db.stop_states_db().await.unwrap();
    }
    {
        let engine = TestEngine::new_db_dir(&path, None).await?;
        let stopper = Arc::new(Stopper::new());
        let keeper = floor_keeper(engine.db.clone(), stopper.clone())?;
        assert_eq!(keeper.cleanup_floor().map(|(id, _)| id), Some(successor.clone()));
        assert_eq!(keeper.gc_resolver.published_floor().map(|f| f.seqno()), Some(43));
        stopper.set_stop();
        engine.db.stop_states_db().await.unwrap();
    }
    Ok(())
}
