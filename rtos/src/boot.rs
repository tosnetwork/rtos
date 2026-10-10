/*
 * RTOS project modifications (2026-10-10): project and crate naming.
 * Copyright (C) 2019-2024 EverX. All Rights Reserved.
 * Modifications Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This file has been modified from its original version.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::{
    block::BlockStuff,
    block_proof::{BlockProofStuff, BootstrapAuthority, VerifiedMasterchainState},
    engine::Engine,
    engine_traits::EngineOperations,
    shard_state::ShardStateStuff,
    shard_states_keeper::calc_pss_split_parts,
    validator::accept_block::create_new_proof_link,
    CHECK,
};
use rtos_block::{error, fail, BlockIdExt, Result, ShardIdent, UInt256, SHARD_FULL};
use std::{ops::Deref, path::Path, sync::Arc, time::Duration};
use storage::{block_handle_db::BlockHandle, types::PersistentStatePartId};

pub const PSS_PERIOD_BITS: u32 = 17;
const RETRY_MASTER_STATE_DOWNLOAD: usize = 30;
const RETRY_SHARD_STATE_DOWNLOAD: usize = 30;

/// cold boot entry point
/// download zero state or block proof link and check it
pub(crate) async fn run_cold(
    engine: &dyn EngineOperations,
) -> Result<(Arc<BlockHandle>, Option<Arc<ShardStateStuff>>, Option<BlockProofStuff>)> {
    let block_id = engine.init_mc_block_id();
    log::info!(target: "boot", "cold boot start: init_block_id={}", block_id);
    CHECK!(block_id.shard().is_masterchain());
    CHECK!(block_id.seq_no >= engine.get_last_fork_masterchain_seqno());
    if block_id.seq_no() == 0 {
        if block_id != engine.zerostate_id()? {
            fail!("Boot zerostate differs from the configured network anchor");
        }
        let handle = download_zerostate(engine, block_id).await?;
        engine.save_last_applied_mc_block_id(&block_id)?;
        let zero_state = engine.load_state(handle.id()).await?;
        return Ok((handle, Some(zero_state), None));
    }

    // id should be key block if not it will never sync
    log::info!(target: "boot", "check if block proof is in database {}", block_id);
    let handle = if let Some(handle) = engine.load_block_handle(block_id)? {
        if handle.has_proof_link() || handle.has_proof() {
            let proof = match engine.load_block_proof(&handle, false).await {
                Ok(proof) => proof,
                Err(err) => {
                    log::warn!(
                        target: "boot",
                        "load_block_proof for init_block {} error: {}",
                        handle.id(), err
                    );
                    engine.load_block_proof(&handle, true).await?
                }
            };
            proof.check_trusted_checkpoint(block_id)?;
            CHECK!(handle.is_key_block()?);
            return Ok((handle, None, Some(proof)));
        }
        Some(handle)
    } else {
        None
    };

    let (handle, proof) = loop {
        if engine.check_stop() {
            fail!("Boot was stopped");
        }

        log::info!(target: "boot", "download init block proof {}", block_id);
        match engine.download_block_proof(block_id, false, true).await {
            Ok(proof) => match proof.check_trusted_checkpoint(block_id) {
                Ok(_) => {
                    log::info!(target: "boot", "block proof downloaded {}", block_id);
                    let handle = engine
                        .store_block_proof(block_id, handle, &proof)
                        .await?
                        .to_non_created()
                        .ok_or_else(|| {
                            error!("INTERNAL ERROR: Bad result in store block proof {}", block_id)
                        })?;
                    engine.save_last_applied_mc_block_id(handle.id())?;
                    break (handle, proof);
                }
                Err(err) => log::warn!(
                    target: "boot",
                    "check_proof for init_block {} error: {}",
                    block_id, err
                ),
            },
            Err(err) => log::warn!(
                target: "boot",
                "download block proof for init_block {} error: {}",
                block_id, err
            ),
        }
        futures_timer::Delay::new(Duration::from_secs(1)).await;

        log::info!(target: "boot", "download init block proof link {}", block_id);
        match engine.download_block_proof(block_id, true, true).await {
            Ok(proof) => match proof.check_trusted_checkpoint(block_id) {
                Ok(_) => {
                    let handle = engine
                        .store_block_proof(block_id, handle, &proof)
                        .await?
                        .to_non_created()
                        .ok_or_else(|| {
                            error!(
                                "INTERNAL ERROR: Bad result in store block proof link {}",
                                block_id
                            )
                        })?;
                    engine.save_last_applied_mc_block_id(handle.id())?;
                    break (handle, proof);
                }
                Err(err) => log::warn!(
                    target: "boot",
                    "check_proof_link for init_block {} error: {}",
                    block_id, err
                ),
            },
            Err(err) => log::warn!(
                target: "boot",
                "download block proof link for init_block {} error: {}",
                block_id, err
            ),
        }
        futures_timer::Delay::new(Duration::from_secs(1)).await;
    };

    CHECK!(handle.is_key_block()?);
    Ok((handle, None, Some(proof)))
}

/// download key blocks
/// 1. define time period
/// 2. get next key blocks ids infinitely
/// 3. download key block proofs and check with each other or with zero state for the first
/// 4. check if last key block can be selected for current state
async fn get_key_blocks(
    engine: &dyn EngineOperations,
    mut handle: Arc<BlockHandle>,
    zero_state: Option<&Arc<ShardStateStuff>>,
    prev_block_proof: Option<BlockProofStuff>,
) -> Result<Vec<Arc<BlockHandle>>> {
    const MAX_RETRIES: usize = 100;
    let mut history = match prev_block_proof {
        Some(proof) => BootstrapAuthority::from_checkpoint(engine.init_mc_block_id(), proof)?,
        None => BootstrapAuthority::from_zerostate(
            engine.zerostate_id()?,
            zero_state.ok_or_else(|| error!("Zero state is not set"))?.clone(),
        )?,
    };
    if handle.id() != history.id() {
        fail!("Bootstrap handle differs from authenticated history");
    }
    log::debug!(target: "boot", "bootstrap authority anchored at {}", history.anchor());
    let mut hardfork_iter = engine.hardforks().iter();
    let mut hardfork = hardfork_iter.next();
    let mut key_blocks = vec![handle.clone()];
    let mut stuck_count = 0;
    let init_block_seqno = history.id().seq_no;
    'main_loop: loop {
        if engine.check_stop() {
            fail!("Boot was stopped");
        }
        log::info!(target: "boot", "download_next_key_blocks_ids {}", handle.id());
        // this information is not trusted
        let ids = match engine.download_next_key_blocks_ids(handle.id()).await {
            Err(err) => {
                log::warn!(target: "boot", "download_next_key_blocks_ids {}: {}", handle.id(), err);
                return Ok(key_blocks);
            }
            Ok(ids) => {
                if let Some(block_id) = ids.last() {
                    stuck_count = 0;
                    log::info!(target: "boot", "last key block is {}", block_id);
                    ids
                } else {
                    stuck_count += 1;
                    if let Some(handle) = key_blocks.last() {
                        let utime = handle.gen_utime();
                        log::info!(
                            target: "boot",
                            "Stuck {} times on last key block time diff: {}",
                            stuck_count, engine.now() - utime
                        );
                    }
                    if stuck_count >= MAX_RETRIES {
                        return Ok(key_blocks);
                    } else {
                        continue 'main_loop;
                    }
                }
            }
        };
        for block_id in &ids {
            if block_id.seq_no() == 0 {
                log::warn!("somebody sent next key block with zero state {}", block_id);
                continue;
            }

            if let Some(last_handle) = key_blocks.last() {
                if block_id.seq_no() <= last_handle.id().seq_no() {
                    log::warn!("somebody sent next key block id with seq_no less or equal to already got {}", block_id);
                    continue;
                }
                // we need to check presence and correctness of every hardfork
                if let Some(hardfork_id) = hardfork {
                    match hardfork_id.seq_no.cmp(&block_id.seq_no) {
                        std::cmp::Ordering::Equal => {
                            if hardfork_id == block_id {
                                log::debug!(target: "boot", "hardfork {} found", block_id);
                                hardfork = hardfork_iter.next();
                            } else {
                                log::warn!(target: "boot", "keyblock is {}, but must equal to hardfork {}", block_id, hardfork_id);
                                break;
                            }
                        }
                        std::cmp::Ordering::Less if hardfork_id.seq_no > init_block_seqno => {
                            log::warn!(target: "boot", "keyblock is {}, but missed hardfork {}", block_id, hardfork_id);
                            break;
                        }
                        _ => (),
                    }
                }
                //let prev_time = handle.gen_utime();
                match download_and_check_key_block_proof(engine, block_id, &history).await {
                    Ok((next_handle, proof)) => {
                        handle = next_handle;
                        CHECK!(handle.is_key_block()?);
                        CHECK!(handle.gen_utime() != 0);
                        // if engine.is_persistent_state(handle.gen_utime(), prev_time) {
                        //     engine.set_init_mc_block_id(block_id);
                        // }
                        key_blocks.push(handle.clone());
                        history = proof;
                    }
                    Err(err) => {
                        log::warn!(target: "boot", "cannot get block proof link for {}: {}", block_id, err);
                        futures_timer::Delay::new(Duration::from_secs(1)).await;
                        continue 'main_loop;
                    }
                }
            }
        }
        if let Some(handle) = key_blocks.last() {
            let utime = handle.gen_utime();
            log::info!(target: "boot", "id: {}, utime: {}, now: {}", handle.id(), utime, engine.now());
            CHECK!(utime != 0);
            CHECK!(utime < engine.now());
            if (engine.sync_blocks_before() > engine.now() - utime)
                || (2 * engine.key_block_utime_step() > engine.now() - utime)
            {
                if history.id().seq_no != 0 {
                    let p = &history;
                    log::info!(target: "boot", "downloading last known block to update overlays: {}", p.id());
                    match engine.download_block(&p.id(), Some(5)).await {
                        Ok((block, _)) => {
                            block.verify_expected_id(history.id())?;
                            engine
                                .update_public_overlays(block.id(), &block.read_config_params()?)
                                .await?;
                        }
                        Err(err) => {
                            log::warn!(target: "boot", "cannot download block {}, skipping overlays update: {}", p.id(), err);
                        }
                    }
                } else {
                    engine.update_public_overlays(handle.id(), &history.config()?).await?;
                };
                return Ok(key_blocks);
            }
        }
    }
}

/// choose correct masterchain state
async fn choose_masterchain_state(
    engine: &dyn EngineOperations,
    key_blocks: &mut Vec<Arc<BlockHandle>>,
    pss_period_bits: u32,
) -> Result<Arc<BlockHandle>> {
    while let Some(handle) = key_blocks.pop() {
        let utime = handle.gen_utime();
        let ptime = if let Some(handle) = key_blocks.last() { handle.gen_utime() } else { 0 };
        log::info!(target: "boot", "key block candidate: seqno={} \
            is_persistent={} ttl={} syncbefore={}", handle.id().seq_no(),
                ptime == 0 || engine.is_persistent_state(utime, ptime, pss_period_bits),
                engine.persistent_state_ttl(utime, pss_period_bits),
                engine.sync_blocks_before());
        if engine.sync_blocks_before() > engine.now() - utime {
            log::info!(target: "boot", "ignoring: too new block");
            continue;
        }
        if ptime == 0 || engine.is_persistent_state(utime, ptime, pss_period_bits) {
            let ttl = engine.persistent_state_ttl(utime, pss_period_bits);
            let time_to_download = 3600;
            if ttl > engine.now() + time_to_download {
                log::info!(target: "boot", "best handle is {}", handle.id());
            } else {
                log::info!(target: "boot", "state is expiring shortly: expire_at={}", ttl);
            }
            return Ok(handle);
        } else {
            log::info!(target: "boot", "ignoring: state is not persistent");
        }
    }
    CHECK!(key_blocks.is_empty());
    fail!("Cannot boot node")
}

/// Download zerostate for all workchains
async fn download_wc_zerostates(
    engine: &dyn EngineOperations,
    mc_zerostate: &ShardStateStuff,
) -> Result<()> {
    let workchains = mc_zerostate.config_params()?.workchains()?;
    let mut ids = vec![];
    workchains.iterate_with_keys(|wc_id, wc| {
        ids.push(BlockIdExt {
            shard_id: ShardIdent::with_tagged_prefix(wc_id, SHARD_FULL)?,
            seq_no: 0,
            root_hash: wc.zerostate_root_hash,
            file_hash: wc.zerostate_file_hash,
        });
        Ok(true)
    })?;
    for zerostate_id in ids {
        download_zerostate(engine, &zerostate_id).await?;
    }
    Ok(())
}

/// Download persistent master block & state, enumerate shards and download block & state for each
pub(crate) async fn download_start_blocks_and_states(
    engine: &dyn EngineOperations,
    mc_handle: &Arc<BlockHandle>,
    pss_downloading_threads: usize,
) -> Result<()> {
    engine.set_sync_status(Engine::SYNC_STATUS_LOAD_STATES);

    let mut tasks = vec![];
    let mut states_hashes = vec![];
    let mut handles = vec![];
    let mut part_ids = vec![];

    // Download master block to obtain shards list

    let (mc_block, _proof) = engine.download_block(mc_handle.id(), None).await?;
    mc_block.verify_expected_id(mc_handle.id())?;
    engine.store_block(&mc_block).await?.to_any();
    let top_blocks = mc_block.top_blocks_all()?;
    let pss_split_depth =
        mc_block.read_config_params()?.base_workchain()?.persistent_state_split_depth;

    let mc_state_hash = mc_block.block()?.read_state_update()?.new_hash;
    states_hashes.push(mc_state_hash.clone());
    handles.push(mc_handle.clone());
    let id = PersistentStatePartId::WholeState(mc_handle.id().clone());
    part_ids.push(id.clone());
    tasks.push(engine.download_persistent_state(
        id,
        mc_handle.id(),
        Some(RETRY_MASTER_STATE_DOWNLOAD),
    ));

    // Downloading start blocks of all shardchains

    for block_id in &top_blocks {
        if block_id.seq_no() == 0 {
            download_zerostate(engine, block_id).await?;
        } else {
            log::info!(target: "boot", "downloading block {}", block_id);

            // If block is already exists in db, it will be just loaded
            let (block, proof) = engine.download_block(block_id, None).await?;
            block.verify_expected_id(block_id)?;
            let handle = engine.store_block(&block).await?.to_any();
            engine.store_block_proof(block_id, Some(handle.clone()), &proof).await?;

            log::info!(target: "boot", "start downloading shardchain state {}", block_id);

            let pss_split_depth = if block_id.shard().is_base_workchain() {
                pss_split_depth
            } else {
                mc_block
                    .read_config_params()?
                    .workchains()?
                    .get(&block_id.shard().workchain_id())?
                    .map_or(0, |wc| wc.persistent_state_split_depth)
            };

            let state_hash = block.block()?.read_state_update()?.new_hash;
            states_hashes.push(state_hash);

            if block_id.shard().prefix_len() >= pss_split_depth {
                let id = PersistentStatePartId::WholeState(handle.id().clone());
                part_ids.push(id.clone());
                tasks.push(engine.download_persistent_state(
                    id,
                    mc_handle.id(),
                    Some(RETRY_SHARD_STATE_DOWNLOAD),
                ));
            } else {
                let mut parts = vec![];
                calc_pss_split_parts(block_id.shard().clone(), pss_split_depth, &mut parts)?;
                for part in parts {
                    let id =
                        PersistentStatePartId::Part(block_id.clone(), part.shard_prefix_with_tag());
                    part_ids.push(id.clone());
                    tasks.push(engine.download_persistent_state(
                        id,
                        mc_handle.id(),
                        Some(RETRY_SHARD_STATE_DOWNLOAD),
                    ));
                }
                // It is important for later parsing to put the downloading header task
                // after all part tasks.
                let id = PersistentStatePartId::Head(block_id.clone());
                part_ids.push(id.clone());
                tasks.push(engine.download_persistent_state(
                    id,
                    mc_handle.id(),
                    Some(RETRY_SHARD_STATE_DOWNLOAD),
                ));
            }
            // one handle for all parts of single state
            handles.push(handle);
        }
    }

    // Download states
    let result = if pss_downloading_threads > 0 && tasks.len() > pss_downloading_threads {
        log::info!(
            target: "boot",
            "downloading shardchain states with {} parallel threads (limited by node's config)",
            pss_downloading_threads
        );
        let mut limited_tasks = Vec::with_capacity(tasks.len());
        let semaphore = Arc::new(tokio::sync::Semaphore::new(pss_downloading_threads));
        for task in tasks {
            let s = semaphore.clone();
            limited_tasks.push(async move {
                let _permit = s.acquire().await?;
                task.await
            });
        }
        futures::future::try_join_all(limited_tasks)
            .await
            .map_err(|err| error!("Error while downloading shard state: {}", err))?
    } else {
        // All states in parallel
        futures::future::try_join_all(tasks)
            .await
            .map_err(|err| error!("Error while downloading shard state: {}", err))?
    };
    let mut largest_state_len = 0;
    let mut largest_cells_count = 0;
    for (bytes, cells) in &result {
        largest_state_len = std::cmp::max(largest_state_len, *bytes);
        largest_cells_count = std::cmp::max(largest_cells_count, *cells);
    }
    log::info!(target: "boot", "all shardchain states were succesfully downloaded");

    // Parse all states and save to cells db
    let mut boc_buffer = Arc::new(Vec::with_capacity(largest_state_len));
    let mut cells_index = Vec::with_capacity(largest_cells_count);
    let mut part_root_hashes = vec![];
    let mut handle_index = 0;
    for (id, cells_count) in part_ids.iter().zip(result.iter().map(|(_b, c)| c)) {
        let mut attempts = 10;
        let b = loop {
            if let Some(b) = Arc::get_mut(&mut boc_buffer) {
                break b;
            } else if attempts == 0 {
                fail!(
                    "INTERNAL ERROR: can't get mut ref for states buffer, refs count: {}",
                    Arc::strong_count(&boc_buffer)
                );
            }
            log::warn!(
                "Can't get mut ref for states buffer, refs count: {}",
                Arc::strong_count(&boc_buffer)
            );
            attempts -= 1;
            tokio::time::sleep(Duration::from_millis(1000)).await;
        };
        b.truncate(0);
        log::info!(target: "boot", "loading state data {}", id);
        engine.load_persistent_state_to(&id, b).await?;

        log::info!(target: "boot", "applying state {}", id);

        cells_index.resize(*cells_count, (UInt256::default(), 0));
        cells_index.fill((UInt256::default(), 0));

        if matches!(id, PersistentStatePartId::Part(_, _)) {
            let root;
            (root, cells_index) =
                engine.apply_persistent_state_part(&id, boc_buffer.clone(), cells_index).await?;
            part_root_hashes.push(root.repr_hash().clone());
        } else {
            if handles.is_empty() {
                fail!("INTERNAL ERROR: no handle for persistent state {}", id);
            }
            let handle = handles.get(handle_index).ok_or_else(|| {
                error!(
                    "INTERNAL ERROR: no handle at index {} for persistent state {}",
                    handle_index, id
                )
            })?;
            handle_index += 1;
            if handle.id() != id.block_id() {
                fail!(
                    "INTERNAL ERROR: persistent state id {} does not match handle id {}",
                    id,
                    handle.id()
                );
            }
            if states_hashes.is_empty() {
                fail!("INTERNAL ERROR: no hash for persistent state {}", id);
            }
            let state_hash = states_hashes.remove(0);

            if matches!(id, PersistentStatePartId::WholeState(_)) {
                cells_index = engine
                    .apply_persistent_state(&handle, &state_hash, boc_buffer.clone(), cells_index)
                    .await?
                    .1;
            } else {
                engine
                    .apply_persistent_state_header(
                        &handle,
                        &state_hash,
                        &part_root_hashes,
                        boc_buffer.clone(),
                    )
                    .await?;
                part_root_hashes.clear();
            };
        };
    }

    // Mark all states as applied
    for handle in handles {
        handle.set_persistent_state();
        engine.set_applied(&handle, mc_handle.id().seq_no()).await?;
    }

    log::info!(target: "boot", "all shardchain states were succesfully applied");

    engine.cleanup_persistent_states().await?;

    Ok(())
}

/// download zero state and store it
pub(crate) async fn download_zerostate(
    engine: &dyn EngineOperations,
    block_id: &BlockIdExt,
) -> Result<Arc<BlockHandle>> {
    if let Some(handle) = engine.load_block_handle(block_id)? {
        if handle.has_state() {
            let state = engine.load_state(block_id).await?;
            state.verify_zerostate(block_id)?;
            return Ok(handle);
        }
    }
    log::info!(target: "boot", "download zero state {}", block_id);
    loop {
        if engine.check_stop() {
            fail!("Boot was stopped");
        }
        match engine.download_zerostate(block_id).await {
            Ok((state, state_bytes)) => {
                state.verify_zerostate(block_id)?;
                if UInt256::calc_file_hash(&state_bytes) != block_id.file_hash {
                    fail!("Downloaded zerostate file differs from the pinned file hash");
                }
                log::info!(target: "boot", "zero state {} received", block_id);
                let (_, handle) = engine.store_zerostate(state, &state_bytes).await?;
                engine.set_applied(&handle, 0).await?;
                engine.save_last_applied_mc_block_id(handle.id())?;
                return Ok(handle);
            }
            Err(err) => log::warn!(target: "boot", "download_zerostate error: {}", err),
        }
        futures_timer::Delay::new(Duration::from_secs(1)).await;
    }
}

/// download key block proof, check it and store
pub(crate) async fn download_and_check_key_block_proof(
    engine: &dyn EngineOperations,
    block_id: &BlockIdExt,
    history: &BootstrapAuthority,
) -> Result<(Arc<BlockHandle>, BootstrapAuthority)> {
    if let Some(handle) = engine.load_block_handle(block_id)? {
        if let Ok(proof) = engine.load_block_proof(&handle, false).await {
            match history.advance_key_block(block_id, proof) {
                Ok(next) => {
                    if handle.id() != block_id {
                        fail!("Cached key-block handle identity mismatch");
                    }
                    return Ok((handle, next));
                }
                Err(err) => log::warn!(target: "boot", "cached proof failed verification: {}", err),
            }
        }
    }
    loop {
        if engine.check_stop() {
            fail!("Boot was stopped");
        }
        let proof = engine.download_block_proof(block_id, false, true).await?;
        let result = history.advance_key_block(block_id, proof);
        match result {
            Ok(next) => {
                let proof = next
                    .key_block_proof()
                    .ok_or_else(|| error!("Verified key block is missing"))?;
                let handle = engine
                    .store_block_proof(block_id, None, proof)
                    .await?
                    .to_non_created()
                    .ok_or_else(|| {
                        error!("INTERNAL ERROR: Bad result in store block {} proof", block_id)
                    })?;
                if handle.id() != block_id {
                    fail!("Stored key-block handle identity mismatch");
                }
                engine.save_last_applied_mc_block_id(handle.id())?;
                return Ok((handle, next));
            }
            Err(err) => {
                log::warn!(target: "boot", "check_proof error: {}", err);
                futures_timer::Delay::new(Duration::from_secs(1)).await;
            }
        }
    }
}

/// Cold load best key block and its state
/// Must be used only zero_state or key_block id
pub async fn cold_boot(
    engine: Arc<dyn EngineOperations>,
    pss_downloading_threads: usize,
) -> Result<Arc<BlockHandle>> {
    const MAX_RETRIES: usize = 5;

    let (handle, zero_state, init_block_proof_link) = run_cold(engine.deref()).await?;
    let mut key_blocks = if !engine.flags().initial_sync_disabled {
        get_key_blocks(engine.deref(), handle, zero_state.as_ref(), init_block_proof_link).await?
    } else {
        vec![handle]
    };

    let mut i = 0;
    loop {
        let handle =
            choose_masterchain_state(engine.deref(), &mut key_blocks, PSS_PERIOD_BITS).await?;
        if handle.id().seq_no() == 0 {
            let Some(zero_state) = zero_state.as_ref() else { fail!("Zero state is not set") };
            download_wc_zerostates(engine.deref(), zero_state).await?;
            break Ok(handle);
        } else {
            if let Err(err) =
                download_start_blocks_and_states(engine.deref(), &handle, pss_downloading_threads)
                    .await
            {
                i += 1;
                if i >= MAX_RETRIES {
                    break Err(err);
                }
                log::warn!(target: "boot", "{}", err)
            } else {
                break Ok(handle);
            }
        }
    }
}

/// Rebuild authority from the explicit local pin. The recovered state's history
/// dictionary is only a lookup hint until its own root is authenticated below.
/// Keep one key proof at a time; no unbounded vector of historical proofs.
pub(crate) async fn authenticate_recovered_state(
    engine: &dyn EngineOperations,
    block_id: &BlockIdExt,
) -> Result<VerifiedMasterchainState> {
    let pin = engine.init_mc_block_id();
    if !block_id.shard().is_masterchain_ext() || block_id.seq_no < pin.seq_no {
        fail!("Recovery position is outside the pinned masterchain history");
    }
    let state = engine.load_state(block_id).await?;
    if state.block_id() != block_id {
        fail!("Recovery state identity mismatch");
    }
    let mut history = if pin.seq_no == 0 {
        if pin != engine.zerostate_id()? {
            fail!("Recovery pin differs from network zerostate");
        }
        BootstrapAuthority::from_zerostate(pin, engine.load_mc_zero_state().await?)?
    } else {
        let proof = load_history_proof(engine, pin, true, true).await?;
        BootstrapAuthority::from_checkpoint(pin, proof)?
    };
    if block_id == pin {
        return history.authenticate_current_state(state);
    }
    // Untrusted augmented dictionaries may omit or substitute keys. Every
    // returned proof must still name the preceding authenticated governing epoch.
    let index = &state.shard_state_extra()?.prev_blocks;
    loop {
        if engine.check_stop() {
            fail!("Recovery authentication stopped");
        }
        let seq = history
            .id()
            .seq_no
            .checked_add(1)
            .ok_or_else(|| error!("Recovery key sequence overflow"))?;
        let Some(next) = index.get_next_key_block(seq)? else {
            break;
        };
        let next = next.master_block_id().1;
        if next.seq_no < seq || next.seq_no >= block_id.seq_no {
            fail!("Recovery history index has an invalid key-block position");
        }
        let proof = load_history_proof(engine, &next, false, true).await?;
        history = history.advance_key_block(&next, proof)?;
    }
    let proof = load_history_proof(engine, block_id, false, false).await?;
    let verified = history.authenticate_block(block_id, proof)?.authenticate_state(state)?;
    if !verified.state().has_prev_block(pin)? {
        fail!("Authenticated recovered state does not contain the local pin");
    }
    Ok(verified)
}

pub(crate) async fn load_history_proof<E: EngineOperations + ?Sized>(
    engine: &E,
    id: &BlockIdExt,
    checkpoint: bool,
    key_block: bool,
) -> Result<BlockProofStuff> {
    if let Some(handle) = engine.load_block_handle(id)? {
        if handle.id() != id {
            fail!("Recovery proof handle identity mismatch");
        }
        if let Ok(proof) = engine.load_block_proof(&handle, false).await {
            return Ok(proof);
        }
        if checkpoint {
            if let Ok(proof) = engine.load_block_proof(&handle, true).await {
                return Ok(proof);
            }
        }
    }
    // A checkpoint may use a proof link because its complete ID is pinned.
    // Every unpinned successor requires a finality proof.
    engine.download_block_proof(id, checkpoint, key_block).await
}

pub async fn warm_boot(
    engine: Arc<Engine>,
    block_id: Arc<BlockIdExt>,
    hardfork_path: impl AsRef<Path>,
) -> Result<BlockIdExt> {
    log::info!(target: "boot", "Warm boot");
    ensure_block_chain_for_state(&engine, &block_id).await?;
    if !engine.hardforks().is_empty() {
        authenticate_recovered_state(engine.as_ref(), &block_id).await?;
        if let Some(block_id) = check_hardforks(&engine, &block_id, hardfork_path).await? {
            authenticate_recovered_state(engine.as_ref(), &block_id).await?;
            return Ok(block_id);
        }
    }
    recover_warm_boot_position(engine.as_ref(), &block_id).await
}

pub(crate) async fn recover_warm_boot_position(
    engine: &dyn EngineOperations,
    start: &BlockIdExt,
) -> Result<BlockIdExt> {
    if !start.shard().is_masterchain_ext() {
        fail!("Recovery cursor is not a full masterchain block");
    }
    let mut block_id = start.clone();
    loop {
        if engine.check_stop() {
            fail!("Warm boot recovery stopped");
        }
        let handle = engine
            .load_block_handle(&block_id)?
            .ok_or_else(|| error!("Cannot load handle for block {}", block_id))?;
        if handle.id() != &block_id {
            fail!("Recovery handle identity mismatch");
        }
        // go back to find last applied block
        if handle.is_applied() {
            break;
        }
        CHECK!(handle.has_state());
        CHECK!(handle.has_prev1());
        let previous = engine.load_block_prev1(&block_id)?;
        if !previous.shard().is_masterchain_ext()
            || previous.seq_no.checked_add(1) != Some(block_id.seq_no)
        {
            fail!("Recovery previous pointer does not move to the preceding masterchain block");
        }
        block_id = previous;
    }
    // walk forward via next1 to find the most recent applied block
    // (LAST_APPLIED_MC_BLOCK pointer may lag behind actual applied state after crash)
    loop {
        if engine.check_stop() {
            fail!("Warm boot recovery stopped");
        }
        let handle = engine
            .load_block_handle(&block_id)?
            .ok_or_else(|| error!("Cannot load handle for block {}", block_id))?;
        if handle.id() != &block_id {
            fail!("Recovery handle identity mismatch");
        }
        if !handle.has_next1() {
            break;
        }
        let next_id = engine.load_block_next1(&block_id)?;
        if !next_id.shard().is_masterchain_ext()
            || block_id.seq_no.checked_add(1) != Some(next_id.seq_no)
        {
            fail!("Recovery next pointer does not move to the next masterchain block");
        }
        let Some(next_handle) = engine.load_block_handle(&next_id)? else {
            break;
        };
        if next_handle.id() != &next_id {
            fail!("Recovery next handle identity mismatch");
        }
        if !next_handle.is_applied() {
            break;
        }
        block_id = next_id;
    }
    authenticate_recovered_state(engine, &block_id).await?;
    engine.save_last_applied_mc_block_id(&block_id)?;
    log::info!(target: "boot", "last applied block id = {}", block_id);
    Ok(block_id)
}

async fn ensure_block_chain_for_state(engine: &Arc<Engine>, start: &BlockIdExt) -> Result<()> {
    let mut id = start.clone();
    if !id.shard().is_masterchain_ext() {
        fail!("Recovery source is not masterchain");
    }
    loop {
        if engine.check_stop() {
            fail!("Warm boot recovery stopped");
        }
        let handle = engine
            .load_block_handle(&id)?
            .ok_or_else(|| error!("Cannot load handle for block {}", id))?;
        if handle.id() != &id {
            fail!("Recovery source handle identity mismatch");
        }
        if handle.has_saved_state() {
            return Ok(());
        }
        let needs_download = if !handle.has_data() {
            true
        } else {
            match engine.load_block_raw(&handle).await {
                Ok(_) => false,
                Err(e) => {
                    log::warn!(target: "boot", "Block {id} read failed: {e}, will re-download");
                    true
                }
            }
        };
        if needs_download {
            log::warn!(target: "boot", "Block {id} data is missing, downloading");
            let (block, proof) = engine.download_block(&id, None).await?;
            let h = engine.store_block(&block).await?.to_any();
            engine.store_block_proof(&id, Some(h), &proof).await?;
        }
        if !handle.has_prev1() {
            fail!("ensure_block_chain_for_state: no prev1 for {id}")
        }
        let previous = engine.load_block_prev1(&id)?;
        if !previous.shard().is_masterchain_ext()
            || previous.seq_no.checked_add(1) != Some(id.seq_no)
        {
            fail!("Recovery data chain has an invalid previous pointer");
        }
        id = previous;
    }
}

async fn check_hardforks(
    engine: &Arc<Engine>,
    last_applied_mc_block: &Arc<BlockIdExt>,
    hardfork_path: impl AsRef<Path>,
) -> Result<Option<BlockIdExt>> {
    let Some(hardfork_id) = engine.hardforks().last() else {
        return Ok(None);
    };
    log::info!(
        target: "boot",
        "last hardfork block id = {} last applied block id = {}",
        hardfork_id, last_applied_mc_block);
    if hardfork_id.seq_no == 0 {
        fail!("hardfork block id wrong seq_no 0")
    }
    let mc_state = engine.load_state(last_applied_mc_block).await?;
    if mc_state.seq_no() + 1 == hardfork_id.seq_no {
        log::info!(target: "boot", "previous block of hardfork is the last, just apply hardfork");
    } else if mc_state.seq_no() < hardfork_id.seq_no {
        fail!(
            "we cannot continue, because database does not have enough blocks to make hardfork by {}",
            hardfork_id
        )
    } else if &mc_state.find_block_id(hardfork_id.seq_no)? != hardfork_id {
        log::info!(
            target: "boot",
            "last hardfork block id = {} is not yet applied, truncating database",
            hardfork_id
        );
        engine.truncate_database(hardfork_id.seq_no).await?;
    } else {
        log::info!(target: "boot", "last hardfork block id = {} already applied", hardfork_id);
        return Ok(None);
        // hardfork already applied
    }
    let (block, proof);
    let handle = if let Some(handle) = engine.load_block_handle(hardfork_id)? {
        log::info!(target: "boot", "crafted block is already in the database");
        block = engine.load_block(&handle).await?;
        // we don't check error loading proof, if so - create new proof
        proof = match engine.load_block_proof(&handle, true).await {
            Ok(proof) => {
                log::info!(
                    target: "boot",
                    "the proof for crafted block is already in the database"
                );
                Some(proof)
            }
            Err(err) => {
                log::info!(
                    target: "boot",
                    "the proof for crafted block is not in the database: {}",
                    err
                );
                None
            }
        };
        handle
    } else {
        // then find new master block file in folders by root hash
        let file_name = hardfork_path.as_ref().join(hardfork_id.root_hash().as_hex_string());
        // if we have such block in folder - apply it
        match std::fs::read(&file_name) {
            Ok(data) => {
                block = BlockStuff::deserialize_block(hardfork_id.clone(), Arc::new(data))?;
                // we don't want to check presence of this block
                let handle = engine
                    .store_block(&block)
                    .await?
                    .to_non_created()
                    .ok_or_else(|| error!("crafted block is already in the database"))?;
                log::info!(
                    target: "boot",
                    "crafted block was loaded from the file and stored to the database"
                );
                proof = None;
                handle
            }
            // if we don't have crafted block
            Err(err) => {
                log::warn!(
                    target: "boot",
                    "cannot read crafted block {:?} : {}",
                    file_name, err
                );
                return Ok(Some(mc_state.find_block_id(hardfork_id.seq_no - 1)?));
            }
        }
    };
    if proof.is_none() {
        let proof = create_new_proof_link(&block)
            .map_err(|err| error!("cannot create proof link for crafted block : {}", err))?;
        engine.store_block_proof(hardfork_id, Some(handle.clone()), &proof).await?;
        log::info!(
            target: "boot",
            "the proof for crafted block is created and stored to the database"
        );
    }
    if !handle.is_applied() {
        let prev_id = mc_state.find_block_id(hardfork_id.seq_no - 1)?;
        let hardfork_prev_id = block.construct_prev_id()?.0;
        if prev_id != hardfork_prev_id {
            fail!(
                "prev block id of crafted block doesn't equal to previous block in the database {} != {}",
                prev_id, hardfork_prev_id
            )
        }
        engine.clone().apply_hardfork_block(&handle, &block).await?;
    }
    Ok(Some(hardfork_id.clone()))
}
