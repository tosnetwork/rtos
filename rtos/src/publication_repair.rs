// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Live-only repair of an existing applied masterchain Final.
//!
//! This never authorizes spool reclamation. State pins are process-local; archive
//! files and history have no persistent dependency lease here. Authentication is
//! bounded in historical proof/state reads. Merkle apply still allocates before
//! its output check; this is not a complete peak-memory-bounded repair owner.
use crate::{
    block::BlockStuff, block_proof::BlockProofStuff, engine::Engine,
    engine_traits::EngineOperations, shard_states_keeper::PinnedShardStateGuard,
    types::service_tasks::spawn_owned, validator::accept_block::accept_authenticated_mc_repair,
};
use consensus_common::{session_runtime::SessionNetworkPin, simplex_protocol::SimplexProtocol};
use rtos_api::WireProfile;
use rtos_block::{error, fail, BlockIdExt, Cell, Result, UInt256};
use std::{
    collections::HashSet,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};
use storage::archives::bounded_read::ArchiveReadLimits;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const MAX_LIVE_REPAIRS: usize = 4;
const MAX_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;
const MAX_STATE_CELLS: usize = 1_000_000;
const MAX_STATE_BYTES: usize = 128 * 1024 * 1024;
const MAX_STATE_DEPTH: usize = 4096;
const READ_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub(crate) struct McFinalRepairRequest {
    pub pin: SessionNetworkPin,
    pub history_init: BlockIdExt,
    pub block_id: BlockIdExt,
    pub session_id: UInt256,
    pub profile: UInt256,
    pub protocol: SimplexProtocol,
    pub carrier_version: u32,
    pub wire_profile: WireProfile,
}

struct Admission {
    key: (usize, BlockIdExt),
    _permit: OwnedSemaphorePermit,
}
fn active() -> &'static Mutex<HashSet<(usize, BlockIdExt)>> {
    static ACTIVE: OnceLock<Mutex<HashSet<(usize, BlockIdExt)>>> = OnceLock::new();
    ACTIVE.get_or_init(Default::default)
}
impl Drop for Admission {
    fn drop(&mut self) {
        active().lock().unwrap().remove(&self.key);
    }
}

/// A live state-GC guard, not a durable custody receipt. No release authority.
pub(crate) struct McFinalRepairCustody {
    block: BlockStuff,
    proof: BlockProofStuff,
    parent: PinnedShardStateGuard,
    target: PinnedShardStateGuard,
    _admission: Admission,
}
impl McFinalRepairCustody {
    pub(crate) fn block_id(&self) -> &BlockIdExt {
        self.block.id()
    }
    pub(crate) fn proof_digest(&self) -> UInt256 {
        UInt256::calc_file_hash(self.proof.data())
    }
    pub(crate) fn state_root(&self) -> &UInt256 {
        self.target.state().root_cell().repr_hash()
    }
    pub(crate) fn parent_id(&self) -> &BlockIdExt {
        self.parent.state().block_id()
    }
}

fn check_domain(engine: &Engine, request: &McFinalRepairRequest) -> Result<()> {
    if !request.block_id.shard().is_masterchain() || request.block_id.seq_no() == 0 {
        fail!("MC repair requires a nonzero masterchain target");
    }
    if &request.pin.zerostate != engine.zerostate_id()
        || &request.history_init != engine.init_mc_block_id()
        || request.wire_profile != WireProfile::T0
        || request.wire_profile != engine.validator_network().wire_profile()
        || request.protocol != SimplexProtocol::PrivateObserversPlumtree
    {
        fail!("MC repair request belongs to another or unsupported Engine domain");
    }
    let handle = engine
        .load_block_handle(&request.block_id)?
        .ok_or_else(|| error!("MC repair target handle is absent"))?;
    if !handle.is_applied() {
        fail!("MC repair target must already be applied");
    }
    Ok(())
}

pub(crate) async fn repair_mc_final(
    engine: Arc<Engine>,
    request: McFinalRepairRequest,
) -> Result<McFinalRepairCustody> {
    check_domain(engine.as_ref(), &request)?;
    static CAPACITY: OnceLock<Arc<Semaphore>> = OnceLock::new();
    let permit = CAPACITY
        .get_or_init(|| Arc::new(Semaphore::new(MAX_LIVE_REPAIRS)))
        .clone()
        .try_acquire_owned()
        .map_err(|_| error!("MC repair capacity exhausted"))?;
    let key = (Arc::as_ptr(&engine) as usize, request.block_id.clone());
    if !active().lock().unwrap().insert(key.clone()) {
        fail!("MC repair target is busy");
    }
    let admission = Admission { key, _permit: permit };
    let owner = engine.clone();
    let observed = spawn_owned(engine.as_ref(), "masterchain Final live repair", async move {
        repair_owned(owner, request, admission).await
    })?;
    // The timeout cancels only observation; the Engine still joins the real
    // worker with admission, budget, pins and blocking IO retained.
    tokio::time::timeout(READ_TIMEOUT, observed)
        .await
        .map_err(|_| error!("MC repair observation timed out"))?
        .map_err(|e| error!("MC repair worker failed: {e}"))?
}

async fn load_pinned_bounded(
    engine: &Engine,
    id: &BlockIdExt,
    budget: &Arc<crate::history_read_budget::HistoryReadBudget>,
) -> Result<PinnedShardStateGuard> {
    let keeper = engine.shard_states_keeper().clone();
    let id = id.clone();
    let budget = budget.clone();
    tokio::task::spawn_blocking(move || keeper.load_and_pin_bounded_state(&id, &budget))
        .await
        .map_err(|error| error!("Repair state reader failed: {error}"))?
}

async fn check_cells(root: &Cell) -> Result<()> {
    check_cells_with_limit(root, MAX_STATE_CELLS).await
}

async fn check_cells_with_limit(root: &Cell, max_cells: usize) -> Result<()> {
    let mut stack = vec![(root.clone(), 0usize)];
    let mut visited = HashSet::new();
    let mut bytes = 0usize;
    while let Some((cell, depth)) = stack.pop() {
        if depth > MAX_STATE_DEPTH {
            fail!("MC repair state depth exceeds budget");
        }
        if !visited.insert(cell.repr_hash().clone()) {
            continue;
        }
        bytes = bytes
            .checked_add((cell.bit_length() + 7) / 8 + 32)
            .ok_or_else(|| error!("MC repair state byte count overflow"))?;
        if visited.len() > max_cells || bytes > MAX_STATE_BYTES {
            fail!("MC repair state exceeds cell/byte budget");
        }
        for index in 0..cell.references_count() {
            stack.push((cell.reference(index)?, depth + 1));
        }
        if visited.len() % 512 == 0 {
            tokio::task::yield_now().await;
        }
    }
    Ok(())
}

async fn read_pair(
    engine: &Engine,
    id: &BlockIdExt,
    budget: &Arc<crate::history_read_budget::HistoryReadBudget>,
) -> Result<(BlockStuff, BlockProofStuff)> {
    let handle =
        engine.load_block_handle(id)?.ok_or_else(|| error!("MC repair handle disappeared"))?;
    let data_bytes = MAX_ARTIFACT_BYTES;
    #[cfg(test)]
    let data_bytes = artifact_test_limits()
        .lock()
        .unwrap()
        .remove(&(engine as *const Engine as usize))
        .unwrap_or(data_bytes);
    let limits = ArchiveReadLimits { data_bytes, filename_bytes: 512 };
    let body = budget.reserve(crate::history_read_budget::ReadKind::State, data_bytes)?;
    let raw = engine
        .db()
        .load_block_data_raw_bounded(
            &handle,
            ArchiveReadLimits { data_bytes: body.allowance(), ..limits },
        )
        .await;
    let raw = match raw {
        Ok(raw) => raw,
        Err(error) => {
            if let Some(evidence) =
                error.downcast_ref::<storage::archives::bounded_read::ArchiveReadNotStarted>()
            {
                body.refund_not_started(evidence)?;
            }
            return Err(error);
        }
    };
    body.finish(&raw)?;
    let block = BlockStuff::deserialize_block_bounded(id.clone(), Arc::new(raw), budget)?;
    let proof_read = budget.reserve(crate::history_read_budget::ReadKind::Proof, data_bytes)?;
    let proof_raw = engine
        .db()
        .load_block_proof_raw_bounded(
            &handle,
            false,
            ArchiveReadLimits { data_bytes: proof_read.allowance(), ..limits },
        )
        .await;
    let proof_raw = match proof_raw {
        Ok(raw) => raw,
        Err(error) => {
            if let Some(evidence) =
                error.downcast_ref::<storage::archives::bounded_read::ArchiveReadNotStarted>()
            {
                proof_read.refund_not_started(evidence)?;
            }
            return Err(error);
        }
    };
    proof_read.finish(&proof_raw)?;
    let proof = BlockProofStuff::deserialize_local_artifact(id, proof_raw, budget)?;
    Ok((block, proof))
}

async fn repair_owned(
    engine: Arc<Engine>,
    request: McFinalRepairRequest,
    admission: Admission,
) -> Result<McFinalRepairCustody> {
    check_domain(engine.as_ref(), &request)?;
    // The Engine-owned worker awaits local file IO to completion. Do not put
    // this under the timeout below: tokio file IO can own a blocking operation
    // which would otherwise outlive its observer and admission permit.
    let budget = crate::history_read_budget::HistoryReadBudget::new(Default::default());
    let mut local = match read_pair(engine.as_ref(), &request.block_id, &budget).await {
        Ok(pair) => Some(pair),
        Err(error) if crate::history_read_budget::stops_fallback(&error) => {
            return Err(error);
        }
        Err(_) => None,
    };
    let (accepted, parent) = async {
        check_domain(engine.as_ref(), &request)?;
        let accepted = loop {
            let from_local = local.is_some();
            let (block, proof) = match local.take() {
                Some(pair) => pair,
                None => {
                    let graph = budget.reserve_network_graph()?;
                    let body = budget
                        .reserve(crate::history_read_budget::ReadKind::State, MAX_ARTIFACT_BYTES)?;
                    let proof_bytes = budget
                        .reserve(crate::history_read_budget::ReadKind::Proof, MAX_ARTIFACT_BYTES)?;
                    let bytes = body.allowance().min(proof_bytes.allowance()).min(graph.bytes / 2);
                    let mut limits =
                        crate::network::full_node_overlay_client::NetworkDownloadLimits::proof(
                            bytes,
                            graph.cells / 2,
                            MAX_STATE_DEPTH as u16,
                        );
                    limits.block_bytes = bytes;
                    let pair = engine
                        .overlay_client(request.block_id.shard())
                        .await?
                        .download_block_full_bounded(&request.block_id, false, limits)
                        .await?;
                    body.finish(pair.0.data())?;
                    proof_bytes.finish(pair.1.data())?;
                    graph.finish_many(&[pair.0.root_cell(), pair.1.root_cell()])?;
                    pair
                }
            };
            if block.data().len() > MAX_ARTIFACT_BYTES || proof.data().len() > MAX_ARTIFACT_BYTES {
                fail!("MC repair downloaded artifact exceeds byte budget");
            }
            block.verify_expected_id(&request.block_id)?;
            if proof.is_link() || proof.id() != &request.block_id {
                fail!("MC repair requires full target proof");
            }
            let context = engine
                .historical_pq_publication_context_bounded(
                    block.id(),
                    block.block()?,
                    budget.clone(),
                )
                .await?;
            if context.zerostate() != &request.pin.zerostate
                || context.history_init() != &request.history_init
                || context.global_id() != request.pin.global_id
                || context.profile() != &request.profile
                || context.protocol() != request.protocol
                || context.carrier_version() != request.carrier_version
                || context.verifier().expected_session_id() != &request.session_id
            {
                fail!("MC repair authenticated history does not match requested coordinates");
            }
            match accept_authenticated_mc_repair(
                block,
                proof,
                context,
                engine.clone(),
                budget.clone(),
            )
            .await
            {
                Ok(accepted) => break accepted,
                Err(error) if crate::history_read_budget::stops_fallback(&error) => {
                    return Err(error)
                }
                Err(_) if from_local => continue,
                Err(error) => return Err(error),
            }
        };
        let block = accepted.block();
        let (parent_id, second) = block.construct_prev_id()?;
        if second.is_some() || !parent_id.shard().is_masterchain() {
            fail!("MC repair requires one MC parent");
        }
        let parent = load_pinned_bounded(&engine, &parent_id, &budget).await?;
        check_cells(parent.state().root_cell()).await?;
        if parent.state().root_cell().repr_hash() != &block.block()?.read_state_update()?.old_hash {
            fail!("MC repair parent state does not match update");
        }
        // Existing root with missing children is deliberately a defer, not a rebuild.
        match engine.load_state_bounded(&request.block_id, budget.clone()).await {
            Ok(state) => {
                if state.root_cell().repr_hash() == &block.block()?.read_state_update()?.new_hash {
                    check_cells(state.root_cell()).await?;
                }
            }
            Err(error) if crate::history_read_budget::stops_fallback(&error) => return Err(error),
            Err(_) => {} // Missing root may be reconstructed; partial graph failures cannot.
        }
        Ok::<_, anyhow::Error>((accepted, parent))
    }
    .await?;
    // Preflight a candidate in ordinary memory before any durable write. The
    // blocking worker is awaited by this Engine-owned task WITHOUT a timeout;
    // abandoning its JoinHandle would detach a real accepted computation.
    let update = accepted.block().block()?.read_state_update()?;
    let old_root = parent.state().root_cell().clone();
    let candidate = tokio::task::spawn_blocking(move || update.apply_for(&old_root))
        .await
        .map_err(|error| error!("MC repair candidate construction failed: {error}"))??
        .0;
    let candidate_limit = MAX_STATE_CELLS;
    #[cfg(test)]
    let candidate_limit = candidate_test_limits()
        .lock()
        .unwrap()
        .remove(&(Arc::as_ptr(&engine) as usize))
        .unwrap_or(candidate_limit);
    check_cells_with_limit(&candidate, candidate_limit).await?;
    // Construction itself has no allocator budget yet. This check prevents an
    // over-budget candidate being persisted, not peak memory use during apply.
    #[cfg(test)]
    if let Some(gate) = take_test_gate(&engine) {
        gate.entered.add_permits(1);
        gate.release.acquire().await.unwrap().forget();
    }
    engine.clone().ensure_publication_acceptance_durable(&accepted).await?;
    let target = load_pinned_bounded(&engine, &request.block_id, &budget).await?;
    check_cells(target.state().root_cell()).await?;
    if target.state().root_cell().repr_hash()
        != &accepted.block().block()?.read_state_update()?.new_hash
    {
        fail!("MC repair persisted state mismatch");
    }
    check_domain(engine.as_ref(), &request)?;
    Ok(McFinalRepairCustody {
        block: accepted.block().clone(),
        proof: accepted.proof().clone(),
        parent,
        target,
        _admission: admission,
    })
}

#[cfg(test)]
pub(crate) struct RepairTestGate {
    pub(crate) entered: Semaphore,
    pub(crate) release: Semaphore,
}
#[cfg(test)]
fn test_gates() -> &'static Mutex<std::collections::HashMap<usize, Arc<RepairTestGate>>> {
    static GATES: OnceLock<Mutex<std::collections::HashMap<usize, Arc<RepairTestGate>>>> =
        OnceLock::new();
    GATES.get_or_init(Default::default)
}
#[cfg(test)]
pub(crate) fn install_test_gate(engine: &Arc<Engine>) -> Arc<RepairTestGate> {
    let gate = Arc::new(RepairTestGate { entered: Semaphore::new(0), release: Semaphore::new(0) });
    assert!(test_gates()
        .lock()
        .unwrap()
        .insert(Arc::as_ptr(engine) as usize, gate.clone())
        .is_none());
    gate
}
#[cfg(test)]
fn take_test_gate(engine: &Arc<Engine>) -> Option<Arc<RepairTestGate>> {
    test_gates().lock().unwrap().remove(&(Arc::as_ptr(engine) as usize))
}

#[cfg(test)]
fn candidate_test_limits() -> &'static Mutex<std::collections::HashMap<usize, usize>> {
    static LIMITS: OnceLock<Mutex<std::collections::HashMap<usize, usize>>> = OnceLock::new();
    LIMITS.get_or_init(Default::default)
}
#[cfg(test)]
pub(crate) fn limit_next_candidate_for_test(engine: &Arc<Engine>, cells: usize) {
    candidate_test_limits().lock().unwrap().insert(Arc::as_ptr(engine) as usize, cells);
}

#[cfg(test)]
fn artifact_test_limits() -> &'static Mutex<std::collections::HashMap<usize, usize>> {
    static LIMITS: OnceLock<Mutex<std::collections::HashMap<usize, usize>>> = OnceLock::new();
    LIMITS.get_or_init(Default::default)
}

#[cfg(test)]
pub(crate) fn limit_next_artifact_for_test(engine: &Arc<Engine>, bytes: usize) {
    artifact_test_limits().lock().unwrap().insert(Arc::as_ptr(engine) as usize, bytes);
}
