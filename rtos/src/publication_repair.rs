// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Live-only repair of an existing applied masterchain Final.
//!
//! This never authorizes spool reclamation. State pins are process-local; archive
//! files and history have no persistent dependency lease here. Authentication is
//! bounded across historical reads, Merkle apply and dedicated state persistence.
//! Native database caches remain outside the request's Rust allocation accounting.
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

/// Only this module can construct the binding between authenticated Final bytes
/// and the bounded Merkle result. Not serializable and not durable custody.
pub(crate) struct PreparedRepairCandidate {
    accepted: crate::validator::accept_block::AcceptedSessionBlock,
    root: Cell,
    budget: Arc<crate::history_read_budget::HistoryReadBudget>,
}
impl PreparedRepairCandidate {
    pub(crate) fn budget(&self) -> &Arc<crate::history_read_budget::HistoryReadBudget> {
        &self.budget
    }
    pub(crate) fn block_id(&self) -> &BlockIdExt {
        self.accepted.block().id()
    }
    pub(crate) fn block(&self) -> &BlockStuff {
        self.accepted.block()
    }
    pub(crate) fn proof(&self) -> &BlockProofStuff {
        self.accepted.proof()
    }
    pub(crate) fn root(&self) -> &Cell {
        &self.root
    }
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
    let (accepted, parent, existing_target) = async {
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
        if parent.state().root_cell().repr_hash() != &block.block()?.read_state_update()?.old_hash {
            fail!("MC repair parent state does not match update");
        }
        // Only absence of the physical index admits reconstruction. GC denial,
        // malformed index and missing root/child are never equivalent to absence.
        let existing_target = if engine.db().has_repair_state_index(&request.block_id)? {
            let target = load_pinned_bounded(&engine, &request.block_id, &budget).await?;
            if target.state().root_cell().repr_hash()
                != &block.block()?.read_state_update()?.new_hash
            {
                fail!("Existing repair target root conflicts with Final");
            }
            Some(target)
        } else {
            None
        };
        Ok::<_, anyhow::Error>((accepted, parent, existing_target))
    }
    .await?;
    let update = accepted.block().block()?.read_state_update()?;
    let old_root = parent.state().root_cell().clone();
    let expected_root = update.new_hash.clone();
    let candidate_limit = MAX_STATE_CELLS;
    #[cfg(test)]
    let candidate_limit = candidate_test_limits()
        .lock()
        .unwrap()
        .remove(&(Arc::as_ptr(&engine) as usize))
        .unwrap_or(candidate_limit);
    let apply_budget = budget.clone();
    let limits = rtos_block::merkle_apply_budget::MerkleApplyLimits {
        max_entries: candidate_limit.min(budget.limits().cells),
        max_depth: budget.limits().depth,
    };
    let root = tokio::task::spawn_blocking(move || {
        update.apply_for_bounded(&old_root, &limits, apply_budget.as_ref())
    })
    .await
    .map_err(|error| error!("MC repair bounded candidate failed: {error}"))??
    .0;
    if root.repr_hash() != &expected_root {
        fail!("Bounded repair candidate root mismatch");
    }
    // Header parsing only sees the fully admitted detached candidate graph.
    let state = crate::shard_state::ShardStateStuff::from_root_cell(
        accepted.block().id().clone(),
        root.clone(),
        #[cfg(feature = "telemetry")]
        engine.engine_telemetry(),
        engine.engine_allocated(),
    )?;
    if state.state()?.global_id() != request.pin.global_id {
        fail!("Repair candidate global id mismatch");
    }
    let candidate = PreparedRepairCandidate { accepted, root, budget: budget.clone() };
    let target_reservation = if existing_target.is_none() {
        engine.shard_states_keeper().reserve_repair_target(&candidate)?
    } else {
        None
    };
    // If another writer materialized the target before reservation, it must be
    // fully readable and agree with the authenticated candidate before writes.
    let existing_target = if existing_target.is_none() && target_reservation.is_none() {
        let target = load_pinned_bounded(&engine, candidate.block_id(), &budget).await?;
        if target.state().root_cell().repr_hash() != candidate.root().repr_hash() {
            fail!("Concurrent repair state conflict");
        }
        Some(target)
    } else {
        existing_target
    };
    #[cfg(test)]
    if let Some(gate) = take_test_gate(&engine) {
        gate.entered.add_permits(1);
        gate.release.acquire().await.unwrap().forget();
    }
    let handle = engine.db().ensure_repair_artifacts(&candidate).await?;
    if existing_target.is_none() {
        engine.db().store_repair_candidate(&candidate).await?;
    }
    engine.db().sync_publication_state().await?;
    let target = load_pinned_bounded(&engine, &request.block_id, &budget).await?;
    if target.state().root_cell().repr_hash() != candidate.root().repr_hash() {
        fail!("MC repair persisted state mismatch");
    }
    handle.set_state();
    handle.set_state_saved();
    engine.db().repair_publication_links(&handle, candidate.accepted.previous_blocks())?;
    engine.db().sync_publication_metadata(&handle).await?;
    drop(target_reservation); // transfer to the verified target's existing pin
    drop(existing_target);
    check_domain(engine.as_ref(), &request)?;
    Ok(McFinalRepairCustody {
        block: candidate.block().clone(),
        proof: candidate.proof().clone(),
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

#[cfg(test)]
fn bounded_only_engines() -> &'static Mutex<HashSet<usize>> {
    static ENGINES: OnceLock<Mutex<HashSet<usize>>> = OnceLock::new();
    ENGINES.get_or_init(Default::default)
}
#[cfg(test)]
pub(crate) struct BoundedOnlyGuard(usize);
#[cfg(test)]
impl Drop for BoundedOnlyGuard {
    fn drop(&mut self) {
        bounded_only_engines().lock().unwrap().remove(&self.0);
    }
}
#[cfg(test)]
pub(crate) fn require_bounded_durability(engine: &Arc<Engine>) -> BoundedOnlyGuard {
    let id = Arc::as_ptr(engine) as usize;
    assert!(bounded_only_engines().lock().unwrap().insert(id));
    BoundedOnlyGuard(id)
}
#[cfg(test)]
pub(crate) fn assert_ordinary_durability_allowed(engine: &Engine) {
    assert!(
        !bounded_only_engines().lock().unwrap().contains(&(engine as *const Engine as usize)),
        "bounded repair entered ordinary durability/apply"
    );
}
