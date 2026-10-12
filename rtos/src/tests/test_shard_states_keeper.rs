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
    engine.db.write_validator_state_batch_sync(
        &[(GC_FLOOR_KEY.to_owned(), encode_checkpoint(&id))],
        &[],
    )?;
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
    keeper.adopt_cleanup_floor(&floor, wait_pin(&keeper, &floor).await?)?;
    // No regression, and no fork that does not record the current floor.
    assert!(keeper.adopt_cleanup_floor(&older, wait_pin(&keeper, &older).await?).is_err());
    assert!(keeper.adopt_cleanup_floor(&fork, wait_pin(&keeper, &fork).await?).is_err());
    assert_eq!(keeper.cleanup_floor().map(|(id, _)| id), Some(floor.clone()));
    // A write that committed but reported an error leaves the floor uncertain:
    // cleanup is disabled and nothing can be adopted until the key is re-read.
    keeper.fail_floor_write_after_commit.store(true, std::sync::atomic::Ordering::Release);
    assert!(keeper.adopt_cleanup_floor(&successor, wait_pin(&keeper, &successor).await?).is_err());
    assert!(keeper.cleanup_floor().is_none(), "uncertain disables cleanup");
    assert!(!keeper.cleanup_floor_unset());
    assert!(keeper.adopt_cleanup_floor(&successor, wait_pin(&keeper, &successor).await?).is_err());
    let durable = engine
        .db
        .load_validator_state_key_bounded(GC_FLOOR_KEY, 256)?
        .and_then(|value| decode_checkpoint(&value));
    assert_eq!(durable, Some(successor.clone()), "the write committed");
    // The read-back alone is not durability: a failed re-write stays uncertain.
    keeper.fail_floor_resolve_write.store(true, std::sync::atomic::Ordering::Release);
    assert!(keeper.resolve_uncertain_cleanup_floor().is_err());
    assert!(keeper.cleanup_floor().is_none(), "a failed re-write keeps cleanup disabled");
    assert!(!keeper.cleanup_floor_unset());
    keeper.resolve_uncertain_cleanup_floor()?;
    assert_eq!(keeper.cleanup_floor().map(|(id, _)| id), Some(successor.clone()));
    assert!(keeper.adopt_cleanup_floor(&floor, wait_pin(&keeper, &floor).await?).is_err());
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
    assert!(keeper.adopt_cleanup_floor(&floor, wait_pin(&keeper, &floor).await?).is_err());
    // Malformed bytes are not absence: no fresh bootstrap may follow.
    engine.db.write_validator_state_batch_sync(&[(GC_FLOOR_KEY.to_owned(), vec![0xff; 7])], &[])?;
    keeper.resolve_uncertain_cleanup_floor()?;
    assert!(keeper.cleanup_floor().is_none());
    assert!(!keeper.cleanup_floor_unset(), "malformed key stays uncertain");
    // A genuinely absent key with no previous floor resolves to unset.
    engine.db.write_validator_state_batch_sync(&[], &[GC_FLOOR_KEY.to_owned()])?;
    keeper.resolve_uncertain_cleanup_floor()?;
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
        keeper.adopt_cleanup_floor(&floor, wait_pin(&keeper, &floor).await?)?;
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
    keeper.adopt_cleanup_floor(&floor, wait_pin(&keeper, &floor).await?)?;
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
    // No next1 from S: the next call errs and the floor stays S.
    assert!(maintain_cleanup_floor(&source).await.is_err());
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
