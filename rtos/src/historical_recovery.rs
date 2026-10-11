// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Detached historical recovery. History authentication alone never authorizes
//! capsule admission, source delivery, ordinary head updates, or signing.
use crate::{
    block::BlockStuff,
    block_proof::{BlockProofStuff, VerifiedMasterchainState},
    engine::Engine,
    engine_traits::EngineOperations,
    history_read_budget::{HistoryReadBudget, HistoryReadLimits, ReadKind},
    shard_state::ShardStateStuff,
};
use rtos_block::{
    error, fail,
    merkle_apply_budget::{BudgetStack, MerkleApplyLimits},
    BlockIdExt, Result,
};
use std::sync::{Arc, LazyLock, Mutex};
use storage::{bounded_cell::CellReadBudget, types::PersistentStatePartId};
mod serialize;

static REQUESTS: LazyLock<Arc<tokio::sync::Semaphore>> =
    LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(2)));
const MAX_REPLAY: usize = 128;
const PART: usize = 2 << 20;

struct Prepared {
    id: BlockIdExt,
    verified: Arc<VerifiedMasterchainState>,
    proofs: Vec<BlockProofStuff>,
    detached: bool,
}
/// One actual owned source operation retains this across both governing/start
/// recovery and eventual authorized commit. Same-ID requests reuse evidence.
/// Construction and use are intentionally crate-private, not a network API.
pub(crate) struct Request {
    engine: Arc<Engine>,
    budget: Arc<HistoryReadBudget>,
    prepared: Mutex<Vec<Prepared>>,
    _permit: tokio::sync::OwnedSemaphorePermit,
    _gc: tokio::sync::OwnedRwLockReadGuard<()>,
}
impl Request {
    pub(crate) async fn new(engine: Arc<Engine>) -> Result<Arc<Self>> {
        let permit = REQUESTS
            .clone()
            .try_acquire_owned()
            .map_err(|e| error!("Historical recovery admission unavailable: {e}"))?;
        let gc = engine.db().repair_leases().protection().authentication().await?;
        Ok(Arc::new(Self {
            engine,
            budget: HistoryReadBudget::new(HistoryReadLimits::default()),
            prepared: Mutex::new(Vec::new()),
            _permit: permit,
            _gc: gc,
        }))
    }
    pub(crate) fn budget(&self) -> &Arc<HistoryReadBudget> {
        &self.budget
    }
    pub(crate) fn verified(
        &self,
        id: &BlockIdExt,
    ) -> Result<Option<Arc<VerifiedMasterchainState>>> {
        self.budget.step()?;
        Ok(self
            .prepared
            .lock()
            .map_err(|_| error!("Historical request poisoned"))?
            .iter()
            .find(|p| &p.id == id)
            .map(|p| p.verified.clone()))
    }
    pub(crate) async fn prepare(&self, id: &BlockIdExt) -> Result<Arc<VerifiedMasterchainState>> {
        self.budget.step()?;
        {
            let prepared =
                self.prepared.lock().map_err(|_| error!("Historical request poisoned"))?;
            if let Some(found) = prepared.iter().find(|p| &p.id == id) {
                return Ok(found.verified.clone());
            }
            if prepared.len() >= 2 {
                fail!("Historical recovery anchor count exceeds bound");
            }
        }
        if !id.shard().is_masterchain_ext() || id.seq_no < self.engine.init_mc_block_id().seq_no {
            fail!("Historical recovery outside exact pinned masterchain");
        }
        let (verified, proofs, detached) = if let Some(verified) =
            crate::retired_history::authenticate_capsule_with_budget(
                self.engine.as_ref(),
                id,
                Some(&self.budget),
            )
            .await?
        {
            let verified = Arc::new(verified);
            let check = verified.clone();
            let engine = self.engine.clone();
            let budget = self.budget.clone();
            tokio::task::spawn_blocking(move || {
                crate::retired_history::sync_recovered_capsule(
                    engine.as_ref(),
                    check.as_ref(),
                    &budget,
                )
            })
            .await
            .map_err(|e| error!("Historical capsule durability owner failed: {e}"))??;
            // Unwrap is safe: the blocking owner has joined and released check.
            (
                Arc::try_unwrap(verified)
                    .map_err(|_| error!("Historical capsule owner remains"))?,
                Vec::new(),
                false,
            )
        } else if self.engine.db().has_repair_state_index(id)? {
            (
                crate::retired_history::authenticate_ordinary_with_budget(
                    self.engine.as_ref(),
                    id,
                    Some(&self.budget),
                )
                .await?,
                Vec::new(),
                false,
            )
        } else {
            let (verified, proofs) = self.recover(id).await?;
            (verified, proofs, true)
        };
        let verified = Arc::new(verified);
        let mut prepared = self.prepared.lock().unwrap();
        // One source record has precisely governing/start anchors. Other
        // context reads must be independently justified before raising this.
        if prepared.len() >= 2 {
            fail!("Historical recovery anchor count exceeds bound");
        }
        self.budget.metadata(std::mem::size_of::<Prepared>())?;
        prepared.try_reserve_exact(1)?;
        prepared.push(Prepared { id: id.clone(), verified: verified.clone(), proofs, detached });
        Ok(verified)
    }
    async fn snapshot(&self, id: &BlockIdExt) -> Result<Option<Arc<ShardStateStuff>>> {
        self.budget.step()?;
        self.budget.metadata(140)?;
        // Raw transport and decoded probe buffers may coexist.
        rtos_block::merkle_apply_budget::MerkleApplyBudget::workspace(self.budget.as_ref(), 140)?;
        let client = self.engine.overlay_client(id.shard()).await?;
        let part = PersistentStatePartId::WholeState(id.clone());
        let Some((peer, length)) = client
            .check_persistent_state_bounded(&part, id, self.budget.limits().state_boc_bytes)
            .await?
        else {
            return Ok(None);
        };
        let reservation = self.budget.reserve(ReadKind::State, length)?;
        if reservation.allowance() != length {
            fail!("Snapshot exceeds remaining history bytes");
        }
        rtos_block::merkle_apply_budget::MerkleApplyBudget::workspace(
            self.budget.as_ref(),
            length,
        )?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length)?;
        while bytes.len() < length {
            self.budget.step()?;
            let maximum = PART.min(length - bytes.len());
            // Transport owns its response allocation alongside the assembly.
            rtos_block::merkle_apply_budget::MerkleApplyBudget::workspace(
                self.budget.as_ref(),
                maximum
                    .checked_mul(2)
                    .ok_or_else(|| error!("Historical transport workspace overflow"))?,
            )?;
            let chunk = client
                .download_persistent_state_part_bounded(
                    &part,
                    id,
                    bytes.len(),
                    maximum,
                    &peer,
                    0,
                    adnl::QueryResponseLimits { wire_bytes: maximum, decoded_bytes: maximum },
                )
                .await?;
            if chunk.len() != maximum {
                fail!("Historical snapshot part is missing or short");
            }
            bytes.extend_from_slice(&chunk);
        }
        reservation.finish(&bytes)?;
        let root = self.budget.parse_boc(&bytes)?;
        Ok(Some(ShardStateStuff::from_root_cell(
            id.clone(),
            root,
            #[cfg(feature = "telemetry")]
            self.engine.engine_telemetry(),
            self.engine.engine_allocated(),
        )?))
    }
    async fn pair(&self, id: &BlockIdExt) -> Result<(BlockStuff, BlockProofStuff)> {
        self.budget.step()?;
        if let Some(handle) = self.engine.load_block_handle(id)? {
            if handle.has_data() && handle.has_proof() {
                return crate::publication_repair::read_pair(
                    self.engine.as_ref(),
                    id,
                    &self.budget,
                )
                .await;
            }
        }
        let body = self.budget.reserve(ReadKind::State, 8 << 20)?;
        let proof = self.budget.reserve(ReadKind::Proof, 8 << 20)?;
        let maximum = body.allowance().min(proof.allowance());
        // Wire, transparent decoded response, decoded TL payload, expanded
        // compressed BOC, and two serialized outputs can coexist. Charge raw
        // workspace separately before reserving the remaining graph capacity.
        rtos_block::merkle_apply_budget::MerkleApplyBudget::workspace(
            self.budget.as_ref(),
            maximum.checked_mul(6).ok_or_else(|| error!("Historical pair workspace overflow"))?,
        )?;
        let graph = self.budget.reserve_network_graph()?;
        let maximum = maximum.min(graph.bytes / 2);
        let mut limits = crate::network::full_node_overlay_client::NetworkDownloadLimits::proof(
            maximum,
            graph.cells / 2,
            self.budget.limits().depth,
        );
        limits.block_bytes = maximum;
        let pair = self
            .engine
            .overlay_client(id.shard())
            .await?
            .download_block_full_bounded(id, false, limits)
            .await?;
        body.finish(pair.0.data())?;
        proof.finish(pair.1.data())?;
        graph.finish_many(&[pair.0.root_cell(), pair.1.root_cell()])?;
        Ok(pair)
    }
    async fn recover(
        &self,
        requested: &BlockIdExt,
    ) -> Result<(VerifiedMasterchainState, Vec<BlockProofStuff>)> {
        let mut suffix = BudgetStack::new(MAX_REPLAY);
        let mut cursor = requested.clone();
        let mut traversed = 0usize;
        let snapshot = loop {
            if self.engine.check_stop() {
                fail!("Historical recovery stopped");
            }
            if let Some(state) = self.snapshot(&cursor).await? {
                break state;
            }
            if cursor == *self.engine.init_mc_block_id() || traversed >= MAX_REPLAY {
                fail!("No available snapshot within bounded historical ancestry");
            }
            let (block, proof) = self.pair(&cursor).await?;
            block.verify_expected_id(&cursor)?;
            if proof.id() != &cursor || proof.is_link() {
                fail!("Historical successor proof identity mismatch");
            }
            let (parent, merge) = block.construct_prev_id()?;
            if merge.is_some()
                || parent.shard() != cursor.shard()
                || parent.seq_no.checked_add(1) != Some(cursor.seq_no)
                || parent.seq_no < self.engine.init_mc_block_id().seq_no
            {
                fail!("Historical successor has invalid exact predecessor");
            }
            suffix.push((block, proof), self.budget.as_ref())?;
            cursor = parent;
            traversed += 1;
        };
        let mut proofs = Vec::new();
        let mut verified = crate::boot::authenticate_detached_history_state(
            self.engine.as_ref(),
            &cursor,
            snapshot,
            &mut proofs,
            &self.budget,
        )
        .await?;
        while let Some((block, proof)) = suffix.pop() {
            self.budget.step()?;
            let (parent, merge) = block.construct_prev_id()?;
            if merge.is_some() || &parent != verified.state().block_id() {
                fail!("Historical replay chain has a hole");
            }
            // Actual supplied proofs remain bounded inputs. Final authentication
            // independently verifies the entire target history from the pin.
            self.budget.proof(&proof)?;
            let update = block.block()?.read_state_update()?;
            let old = verified.state().root_cell().clone();
            let budget = self.budget.clone();
            let limits = MerkleApplyLimits {
                max_entries: budget.limits().cells,
                max_depth: budget.limits().depth,
            };
            let root = tokio::task::spawn_blocking(move || {
                update.apply_for_bounded(&old, &limits, budget.as_ref())
            })
            .await
            .map_err(|e| error!("Historical replay owner failed: {e}"))??
            .0;
            let state = ShardStateStuff::from_root_cell(
                block.id().clone(),
                root,
                #[cfg(feature = "telemetry")]
                self.engine.engine_telemetry(),
                self.engine.engine_allocated(),
            )?;
            proofs.clear();
            verified = crate::boot::authenticate_detached_history_state(
                self.engine.as_ref(),
                block.id(),
                state,
                &mut proofs,
                &self.budget,
            )
            .await?;
        }
        if verified.state().block_id() != requested {
            fail!("Historical recovery changed requested anchor");
        }
        Ok((verified, proofs))
    }
}

/// Private two-phase admission. This is minted only after both historical
/// identity and the actual retained source certificate have been authenticated.
/// Keeping the source evidence also keeps its real namespace owner locked.
pub(crate) struct DurableHistoryAdmission {
    anchors: [BlockIdExt; 2],
    zero: BlockIdExt,
    global: i32,
    _evidence: AdmissionEvidence,
}
enum AdmissionEvidence {
    Source(simplex::finality_recovery::SourceHistoryDebt),
    Node(crate::publication_worker::NodeHistoryDebt),
}
impl DurableHistoryAdmission {
    fn from_source(
        identity: &crate::validator::retired_session_auth::AuthenticatedRetiredSession,
        source: simplex::finality_recovery::SourceHistoryDebt,
    ) -> Result<Self> {
        let expected = identity.record();
        let actual = source.record();
        if actual.pin != expected.pin
            || actual.binding != expected.binding
            || actual.protocol != expected.protocol
            || actual.carrier_version != expected.carrier_version
            || actual.wire_profile != expected.wire_profile
            || actual.profile != expected.profile
            || actual.session_id != expected.session_id
            || actual.local_adnl != expected.local_adnl
            || actual.local_validator_index != expected.local_validator_index
            || actual.prev_blocks != expected.prev_blocks
            || actual.start_masterchain != expected.start_masterchain
            || actual.namespace != expected.namespace
        {
            fail!("Source history admission differs from authenticated locator");
        }
        Ok(Self {
            anchors: [
                expected.binding.governing_masterchain.clone(),
                expected.start_masterchain.clone(),
            ],
            zero: expected.pin.zerostate.clone(),
            global: expected.pin.global_id,
            _evidence: AdmissionEvidence::Source(source),
        })
    }
    fn from_node(
        request: &consensus_common::finality_delivery::CloseFinalityRequest,
        runtime: &consensus_common::session_runtime::AuthenticatedSessionRuntime,
        debt: crate::publication_worker::NodeHistoryDebt,
    ) -> Result<Self> {
        if debt.request() != request
            || runtime.pin() != &request.domain.pin
            || runtime.recovery_binding() != request.domain.recovery_binding.as_ref()
        {
            fail!("Node historical admission differs from authenticated close");
        }
        let anchor = request
            .domain
            .recovery_binding
            .as_ref()
            .ok_or_else(|| error!("Closing history recovery binding missing"))?
            .governing_masterchain
            .clone();
        Ok(Self {
            anchors: [anchor.clone(), anchor],
            zero: request.domain.pin.zerostate.clone(),
            global: request.domain.pin.global_id,
            _evidence: AdmissionEvidence::Node(debt),
        })
    }
    pub(crate) fn validate(
        &self,
        engine: &dyn EngineOperations,
        id: &BlockIdExt,
        global: i32,
    ) -> Result<()> {
        if !self.anchors.contains(id)
            || global != self.global
            || &self.zero != engine.zerostate_id()?
        {
            fail!("Historical capsule commit outside source certificate admission");
        }
        Ok(())
    }
}
struct SourceBudget(Arc<HistoryReadBudget>);
impl simplex::finality_recovery::SourceHistoryDebtBudget for SourceBudget {
    fn step(&self) -> Result<()> {
        self.0.step()
    }
    fn workspace(&self, bytes: usize) -> Result<()> {
        rtos_block::merkle_apply_budget::MerkleApplyBudget::workspace(self.0.as_ref(), bytes)
    }
    fn read_bytes(&self, bytes: usize) -> Result<()> {
        if bytes == 0 {
            return self.0.step();
        }
        let reservation = self.0.reserve(ReadKind::State, bytes)?;
        if reservation.allowance() != bytes {
            fail!("Source history bytes exceed remaining request budget");
        }
        // Full exact-length charge is retained even if the subsequent read fails.
        drop(reservation);
        Ok(())
    }
}

pub(crate) async fn authenticate_retired(
    engine: Arc<Engine>,
    record: simplex::finality_recovery::SessionRecoveryRecord,
) -> Result<crate::validator::retired_session_auth::AuthenticatedRetiredSession> {
    let request = Request::new(engine.clone()).await?;
    let owner = engine.clone();
    crate::types::service_tasks::spawn_owned(
        engine.as_ref(),
        "historical source recovery",
        async move {
            let identity =
                crate::validator::retired_session_auth::authenticate_retired_session_in_request(
                    owner.as_ref(),
                    &record,
                    Some(request.as_ref()),
                )
                .await?;
            if !request.prepared.lock().unwrap().iter().any(|p| p.detached) {
                return Ok(identity);
            }
            if owner.adnl_key_by_id(identity.runtime().local_adnl()).is_none() {
                fail!("Historical transport key unavailable; source remains retained");
            }
            let runtime = identity.runtime().clone();
            let source_record = record.clone();
            let budget = request.budget.clone();
            let source = tokio::task::spawn_blocking(move || {
                simplex::finality_recovery::authenticate_source_history_debt(
                    &source_record,
                    &runtime,
                    &SourceBudget(budget),
                )
            })
            .await
            .map_err(|e| error!("Historical source evidence owner failed: {e}"))??;
            let admission = DurableHistoryAdmission::from_source(&identity, source)?;
            request.commit(admission).await?;
            Ok(identity)
        },
    )?
    .await
    .map_err(|e| error!("Historical source recovery join: {e}"))?
}

impl Request {
    async fn commit(self: Arc<Self>, admission: DurableHistoryAdmission) -> Result<()> {
        tokio::task::spawn_blocking(move || {
            // Retain actual source/node authority and request ownership until
            // every admitted capsule's final directory sync has completed.
            let mut prepared =
                self.prepared.lock().map_err(|_| error!("Historical request poisoned"))?;
            for state in prepared.iter_mut().filter(|p| p.detached) {
                let bytes = serialize::serialize(state.verified.state().root_cell(), &self.budget)?;
                crate::retired_history::commit_recovered_capsule(
                    self.engine.as_ref(),
                    &admission,
                    state.verified.as_ref(),
                    bytes,
                    std::mem::take(&mut state.proofs),
                    &self.budget,
                )?;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .map_err(|e| error!("Historical capsule owner failed: {e}"))?
    }
}
pub(crate) async fn authenticate_closing(
    engine: Arc<Engine>,
    closing: consensus_common::finality_delivery::CloseFinalityRequest,
    namespace: std::path::PathBuf,
) -> Result<Arc<consensus_common::session_runtime::AuthenticatedSessionRuntime>> {
    let request = Request::new(engine.clone()).await?;
    let owner = engine.clone();
    crate::types::service_tasks::spawn_owned(
        engine.as_ref(),
        "historical closing recovery",
        async move {
            let runtime =
                crate::validator::retired_session_auth::authenticate_closing_runtime_in_request(
                    owner.as_ref(),
                    &closing,
                    &namespace,
                    Some(request.as_ref()),
                )
                .await?;
            if request.prepared.lock().unwrap().iter().any(|p| p.detached) {
                let worker = owner.ensure_publication_worker().await?;
                let debt = worker
                    .authorize_closing_history_debt(
                        closing.clone(),
                        runtime.clone(),
                        request.budget.clone(),
                    )
                    .await?;
                let admission = DurableHistoryAdmission::from_node(&closing, &runtime, debt)?;
                request.commit(admission).await?;
            }
            Ok(runtime)
        },
    )?
    .await
    .map_err(|e| error!("Historical closing recovery join: {e}"))?
}

/// Metadata output uses the same request accounting before every Vec growth.
pub(crate) struct BudgetedBytes {
    bytes: Vec<u8>,
    limit: usize,
    budget: Arc<HistoryReadBudget>,
}
impl BudgetedBytes {
    pub(crate) fn new(limit: usize, budget: Arc<HistoryReadBudget>) -> Self {
        Self { bytes: Vec::new(), limit, budget }
    }
    pub(crate) fn finish(self) -> Vec<u8> {
        self.bytes
    }
}
impl std::io::Write for BudgetedBytes {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        let required = self
            .bytes
            .len()
            .checked_add(input.len())
            .filter(|n| *n <= self.limit)
            .ok_or_else(|| std::io::Error::other("Historical metadata exceeds limit"))?;
        if required > self.bytes.capacity() {
            let capacity =
                required.max(self.bytes.capacity().saturating_mul(2)).max(64).min(self.limit);
            self.budget.metadata(capacity).map_err(std::io::Error::other)?;
            rtos_block::merkle_apply_budget::MerkleApplyBudget::workspace(
                self.budget.as_ref(),
                capacity,
            )
            .map_err(std::io::Error::other)?;
            self.bytes
                .try_reserve_exact(capacity - self.bytes.len())
                .map_err(std::io::Error::other)?;
        }
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
