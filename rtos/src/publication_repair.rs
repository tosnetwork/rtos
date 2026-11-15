// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded repair of an existing applied masterchain Final.
//! Live guards alone convey no release authority. The separate persistent
//! entrypoint authenticates and durably protects an exact event's dependencies;
//! the publication worker still owns the source Delivered/Released transaction.
//! Native database caches remain outside request allocation accounting.
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
    pub(crate) fn previous_blocks(&self) -> &[BlockIdExt] {
        self.accepted.previous_blocks()
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
    budget: Arc<crate::history_read_budget::HistoryReadBudget>,
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

fn admit(engine: &Arc<Engine>, request: &McFinalRepairRequest) -> Result<Admission> {
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
    Ok(Admission { key, _permit: permit })
}

pub(crate) async fn repair_mc_final(
    engine: Arc<Engine>,
    request: McFinalRepairRequest,
) -> Result<McFinalRepairCustody> {
    let admission = admit(&engine, &request)?;
    let owner = engine.clone();
    let observed = spawn_owned(engine.as_ref(), "masterchain Final live repair", async move {
        repair_owned(
            owner,
            request,
            admission,
            crate::history_read_budget::HistoryReadBudget::new(Default::default()),
        )
        .await
    })?;
    // The timeout cancels only observation; the Engine still joins the real
    // worker with admission, budget, pins and blocking IO retained.
    tokio::time::timeout(READ_TIMEOUT, observed)
        .await
        .map_err(|_| error!("MC repair observation timed out"))?
        .map_err(|e| error!("MC repair worker failed: {e}"))?
}

// Calibration uses the actual admitted worker with an explicitly bounded budget.
// The test awaits the whole owner; no mocked context errors or fallback shortcut.
#[cfg(test)]
pub(crate) async fn repair_with_budget_for_test(
    engine: Arc<Engine>,
    request: McFinalRepairRequest,
    budget: Arc<crate::history_read_budget::HistoryReadBudget>,
) -> Result<McFinalRepairCustody> {
    let admission = admit(&engine, &request)?;
    repair_owned(engine, request, admission, budget).await
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

pub(crate) async fn read_pair(
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
    budget: Arc<crate::history_read_budget::HistoryReadBudget>,
) -> Result<McFinalRepairCustody> {
    check_domain(engine.as_ref(), &request)?;
    // The Engine-owned worker awaits local file IO to completion. Do not put
    // this under the timeout below: tokio file IO can own a blocking operation
    // which would otherwise outlive its observer and admission permit.
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
                    #[cfg(test)]
                    engine.db().test_note_read_refusal_effect(0);
                    let body = budget
                        .reserve(crate::history_read_budget::ReadKind::State, MAX_ARTIFACT_BYTES)?;
                    let proof_bytes = budget
                        .reserve(crate::history_read_budget::ReadKind::Proof, MAX_ARTIFACT_BYTES)?;
                    let maximum = body.allowance().min(proof_bytes.allowance());
                    // Wire, decoded TL, compressed expansion and output bytes
                    // coexist before graph parsing. Admit them before reserving
                    // the remaining graph capacity on this same request.
                    rtos_block::merkle_apply_budget::MerkleApplyBudget::workspace(
                        budget.as_ref(),
                        maximum
                            .checked_mul(6)
                            .ok_or_else(|| error!("Repair network workspace overflow"))?,
                    )?;
                    let graph = budget.reserve_network_graph()?;
                    let bytes = maximum.min(graph.bytes / 2);
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
                        .download_block_full_history(
                            &request.block_id,
                            false,
                            limits,
                            budget.clone(),
                            graph,
                        )
                        .await?;
                    body.finish(pair.0.data())?;
                    proof_bytes.finish(pair.1.data())?;
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
    engine.db().repair_candidate_links(&handle, &candidate)?;
    engine.db().sync_publication_metadata(&handle).await?;
    // Repair bypasses the ordinary keeper store. The verified physical state
    // is available even if a later request-domain check refuses the receipt.
    engine.shard_states_keeper().notify_state_ready(target.state_arc())?;
    drop(target_reservation); // transfer to the verified target's existing pin
    drop(existing_target);
    check_domain(engine.as_ref(), &request)?;
    budget.record_bytes("block", candidate.block_id(), candidate.block().data(), None)?;
    budget.record_history_proof(candidate.proof())?;
    budget.record_state(parent.state().block_id(), parent.state().root_cell())?;
    budget.record_state(target.state().block_id(), target.state().root_cell())?;
    Ok(McFinalRepairCustody {
        block: candidate.block().clone(),
        proof: candidate.proof().clone(),
        parent,
        target,
        budget,
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
pub(crate) fn remove_test_gate(engine: &Arc<Engine>) {
    drop(take_test_gate(engine));
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

/// Private capability: only the owned fresh-authentication handoff or verified
/// cold replay below can construct it. It cannot be decoded from a ledger.
pub(crate) struct DurableMcFinalRepairCustody {
    binding: crate::repair_lease_binding::RepairLeaseBinding,
    lease_generation: u64,
    dependency_digest: UInt256,
    _live: McFinalRepairCustody,
}
impl DurableMcFinalRepairCustody {
    pub(crate) fn binding(&self) -> &crate::repair_lease_binding::RepairLeaseBinding {
        &self.binding
    }
    pub(crate) fn lease_generation(&self) -> u64 {
        self.lease_generation
    }
    pub(crate) fn dependency_digest(&self) -> &UInt256 {
        &self.dependency_digest
    }
}
fn check_binding(
    request: &McFinalRepairRequest,
    binding: &crate::repair_lease_binding::RepairLeaseBinding,
) -> Result<()> {
    binding.validate()?;
    let domain = &binding.domain;
    if binding.canonical.block_id != request.block_id
        || domain.zerostate != request.pin.zerostate
        || domain.global_id != request.pin.global_id
        || domain.history_init != request.history_init
        || domain.session_id != request.session_id
        || domain.profile != request.profile
        || domain.protocol != request.protocol
        || domain.carrier_version != request.carrier_version
        || domain.wire_profile != request.wire_profile
    {
        fail!("Repair event and authenticated request differ");
    }
    Ok(())
}
fn request_from_binding(
    binding: &crate::repair_lease_binding::RepairLeaseBinding,
) -> McFinalRepairRequest {
    let d = &binding.domain;
    McFinalRepairRequest {
        pin: SessionNetworkPin { zerostate: d.zerostate.clone(), global_id: d.global_id },
        history_init: d.history_init.clone(),
        block_id: binding.canonical.block_id.clone(),
        session_id: d.session_id.clone(),
        profile: d.profile.clone(),
        protocol: d.protocol,
        carrier_version: d.carrier_version,
        wire_profile: d.wire_profile,
    }
}
pub(crate) async fn obtain_durable_mc_custody(
    engine: Arc<Engine>,
    request: McFinalRepairRequest,
    binding: crate::repair_lease_binding::RepairLeaseBinding,
) -> Result<DurableMcFinalRepairCustody> {
    check_binding(&request, &binding)?;
    let admission = admit(&engine, &request)?;
    let owner = engine.clone();
    let worker =
        spawn_owned(engine.as_ref(), "persistent masterchain repair custody", async move {
            let leases = owner.db().repair_leases().clone();
            let _authentication = leases.protection().authentication().await?;
            let budget = crate::history_read_budget::HistoryReadBudget::new(Default::default());
            budget.enable_provenance();
            let source_state = crate::retired_history::authenticate_state_with_budget(
                owner.as_ref(),
                &binding.domain.source_recovery_anchor,
                Some(&budget),
            )
            .await?;
            crate::validator::retired_session_auth::validate_close_recovery_binding_with_budget(
                owner.as_ref(),
                &binding,
                &source_state,
                &budget,
            )?;
            let live = repair_owned(owner.clone(), request, admission, budget.clone()).await?;
            if live.block.block()?.read_extra()?.created_by() != &binding.canonical.source_validator
            {
                fail!("Repair body creator differs from event source");
            }
            let (dependencies, proofs) = budget.take_provenance()?;
            use storage::bounded_cell::CellReadBudget;
            budget.metadata(256 << 10)?;
            let digest = crate::publication_dependency_leases::dependency_digest(&dependencies)?;
            let ledger = leases.clone();
            let exact = binding.clone();
            let accounting = budget.clone();
            let persisted_dependencies = dependencies.clone();
            let generation = tokio::task::spawn_blocking(move || {
                ledger.begin(&exact, persisted_dependencies, &accounting)
            })
            .await
            .map_err(|e| error!("Repair protection writer: {e}"))??;
            // Protecting is already durable. Any error below retains that protection
            // and the original publication record; only success permits handoff.
            let synchronized = async {
                for proof in &proofs {
                    owner.db().sync_repair_history_proof(proof, &budget).await?;
                }
                for dependency in &dependencies {
                    if dependency.kind == "capsule-state" {
                        crate::retired_history::sync_repair_capsule(
                            owner.as_ref(),
                            &dependency.validate()?,
                            &dependency.digest,
                            dependency.bytes,
                            &budget,
                        )
                        .await?;
                    }
                }
                owner.db().sync_publication_state().await
            }
            .await;
            if let Err(error) = synchronized {
                leases.dependency_sync_failed(&error);
                return Err(error);
            }

            let ledger = leases.clone();
            let accounting = budget.clone();
            tokio::task::spawn_blocking(move || ledger.durable(generation, &accounting))
                .await
                .map_err(|e| error!("Repair custody writer: {e}"))??;
            Ok(DurableMcFinalRepairCustody {
                binding,
                lease_generation: generation,
                dependency_digest: digest,
                _live: live,
            })
        })?;
    worker.await.map_err(|e| error!("Persistent repair owner failed: {e}"))?
}

pub(crate) async fn reopen_durable_mc_custody(
    engine: Arc<Engine>,
    lease_generation: u64,
    binding: crate::repair_lease_binding::RepairLeaseBinding,
    dependency_digest: UInt256,
) -> Result<DurableMcFinalRepairCustody> {
    let request = request_from_binding(&binding);
    check_binding(&request, &binding)?;
    let admission = admit(&engine, &request)?;
    let owner = engine.clone();
    let worker = spawn_owned(engine.as_ref(), "cold persistent repair custody", async move {
        let leases = owner.db().repair_leases().clone();
        let _authentication = leases.protection().authentication().await?;
        let budget = crate::history_read_budget::HistoryReadBudget::new(Default::default());
        budget.enable_provenance();
        let record = leases.lookup(lease_generation, &budget)?;
        if record.state != crate::publication_dependency_leases::LeaseState::DurableCustody
            || record.binding()? != binding
            || record.dependency_digest != format!("{dependency_digest:x}")
        {
            fail!("Repair custody event/generation mismatch");
        }
        let mut proofs = Vec::new();
        for dependency in &record.dependencies {
            budget.step()?;
            if !matches!(dependency.kind.as_str(), "proof" | "proof-link") {
                continue;
            }
            let id = dependency.validate()?;
            let handle = owner
                .load_block_handle(&id)?
                .ok_or_else(|| error!("Cold repair proof handle missing"))?;
            let read = budget
                .reserve(crate::history_read_budget::ReadKind::Proof, dependency.bytes as usize)?;
            let bytes = owner
                .db()
                .load_block_proof_raw_bounded(
                    &handle,
                    dependency.kind == "proof-link",
                    ArchiveReadLimits { data_bytes: read.allowance(), filename_bytes: 512 },
                )
                .await?;
            read.finish(&bytes)?;
            if bytes.len() as u64 != dependency.bytes
                || format!("{:x}", UInt256::calc_file_hash(&bytes)) != dependency.digest
            {
                fail!("Cold repair proof digest mismatch");
            }
            use storage::bounded_cell::CellReadBudget;
            budget.metadata(std::mem::size_of::<BlockProofStuff>())?;
            proofs.try_reserve_exact(1)?;
            proofs.push(BlockProofStuff::deserialize_bounded(
                &id,
                bytes,
                dependency.kind == "proof-link",
                &budget,
            )?);
        }
        budget.set_replay_proofs(proofs);
        // Authenticate capsule-internal closure as well as ordinary source
        // recovery state. No latest-state hint or authority cache is required.
        for dependency in &record.dependencies {
            if dependency.kind == "capsule-state" {
                let id = dependency.validate()?;
                crate::retired_history::authenticate_state_with_budget(
                    owner.as_ref(),
                    &id,
                    Some(&budget),
                )
                .await?;
            }
        }
        let source_state = crate::retired_history::authenticate_state_with_budget(
            owner.as_ref(),
            &binding.domain.source_recovery_anchor,
            Some(&budget),
        )
        .await?;
        crate::validator::retired_session_auth::validate_close_recovery_binding_with_budget(
            owner.as_ref(),
            &binding,
            &source_state,
            &budget,
        )?;
        let live = repair_owned(owner.clone(), request, admission, budget.clone()).await?;
        if live.block.block()?.read_extra()?.created_by() != &binding.canonical.source_validator {
            fail!("Repair body creator differs from event source");
        }
        let (dependencies, proofs) = budget.take_provenance()?;
        use storage::bounded_cell::CellReadBudget;
        budget.metadata(256 << 10)?;
        if dependencies != record.dependencies
            || crate::publication_dependency_leases::dependency_digest(&dependencies)?
                != dependency_digest
        {
            fail!("Cold authenticated dependency closure differs from durable lease");
        }
        let synchronized = async {
            for proof in &proofs {
                owner.db().sync_repair_history_proof(proof, &budget).await?;
            }
            for dependency in &dependencies {
                if dependency.kind == "capsule-state" {
                    crate::retired_history::sync_repair_capsule(
                        owner.as_ref(),
                        &dependency.validate()?,
                        &dependency.digest,
                        dependency.bytes,
                        &budget,
                    )
                    .await?;
                }
            }
            owner.db().sync_publication_state().await
        }
        .await;
        if let Err(error) = synchronized {
            leases.dependency_sync_failed(&error);
            return Err(error);
        }

        let ledger = leases.clone();
        let accounting = budget.clone();
        tokio::task::spawn_blocking(move || ledger.durable(lease_generation, &accounting))
            .await
            .map_err(|e| error!("Cold repair custody writer: {e}"))??;
        Ok(DurableMcFinalRepairCustody {
            binding,
            lease_generation,
            dependency_digest,
            _live: live,
        })
    })?;
    worker.await.map_err(|e| error!("Cold repair owner failed: {e}"))?
}
