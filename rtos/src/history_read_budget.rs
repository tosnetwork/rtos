// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Request-scoped limits. Ordinary boot does not construct this capability.
use rtos_block::{error, Cell, Result, UInt256};
use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

#[derive(Clone, Debug)]
pub struct HistoryReadLimits {
    pub proof_count: usize,
    pub proof_bytes: usize,
    pub single_proof_bytes: usize,
    pub state_boc_bytes: usize,
    pub metadata_bytes: usize,
    pub cells: usize,
    pub cell_bytes: usize,
    pub depth: u16,
    pub steps: usize,
}
impl Default for HistoryReadLimits {
    fn default() -> Self {
        Self {
            proof_count: 128,
            proof_bytes: 32 << 20,
            single_proof_bytes: 8 << 20,
            state_boc_bytes: 128 << 20,
            metadata_bytes: 4 << 20,
            cells: 1_000_000,
            cell_bytes: 128 << 20,
            depth: 4096,
            steps: 4_000_000,
        }
    }
}
#[derive(Debug)]
pub struct HistoryBudgetExceeded(pub &'static str);
impl std::fmt::Display for HistoryBudgetExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "History read budget exhausted: {}", self.0)
    }
}
impl std::error::Error for HistoryBudgetExceeded {}
#[derive(Debug)]
pub struct UnsupportedBoundedHistoryRead(pub &'static str);
impl std::fmt::Display for UnsupportedBoundedHistoryRead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Bounded history read unsupported: {}", self.0)
    }
}
impl std::error::Error for UnsupportedBoundedHistoryRead {}
pub fn stops_fallback(e: &anyhow::Error) -> bool {
    e.downcast_ref::<HistoryBudgetExceeded>().is_some()
        || e.downcast_ref::<storage::bounded_cell::InvalidBoundedState>().is_some()
        || e.downcast_ref::<rtos_block::merkle_apply_budget::MerkleApplyLimitExceeded>().is_some()
        || e.downcast_ref::<UnsupportedBoundedHistoryRead>().is_some()
        || e.downcast_ref::<crate::network::full_node_overlay_client::BoundedBocDecodeRejected>()
            .is_some()
        || e.downcast_ref::<storage::archives::bounded_read::ArchiveReadLimitExceeded>().is_some()
        || e.downcast_ref::<storage::archives::context::ArchiveContextError>().is_some()
}
#[derive(Default)]
struct Usage {
    proof_count: usize,
    proof_bytes: usize,
    state_bytes: usize,
    metadata_bytes: usize,
    cells: usize,
    cell_bytes: usize,
    steps: usize,
    reserved_cells: usize,
    reserved_cell_bytes: usize,
    proofs: HashSet<UInt256>,
}
pub struct HistoryReadBudget {
    // Keep the table outside usage: BudgetMap charges through this budget,
    // which locks usage. Lock order is graphs then usage, never the reverse.
    graphs: Mutex<rtos_block::merkle_apply_budget::BudgetMap<()>>,
    provenance: Mutex<Option<crate::repair_provenance::Trace>>,
    replay_proofs: Mutex<Option<Vec<crate::block_proof::BlockProofStuff>>>,
    limits: HistoryReadLimits,
    usage: Mutex<Usage>,
    parsing: Mutex<()>,
    failed: AtomicBool,
    #[cfg(test)]
    local_proof_fallbacks: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    cell_gate: Mutex<Option<(tokio::sync::oneshot::Sender<()>, std::sync::mpsc::Receiver<()>)>>,
}
#[derive(Clone, Copy)]
pub(crate) enum ReadKind {
    Proof,
    State,
    Metadata,
}
/// Reserved before physical IO. On failure/drop the full reservation stays
/// charged; successful completion refunds only unread allowance, never work.
/// Proof count includes distinct completed digests and active reservations only.
pub(crate) struct ReadReservation {
    budget: Arc<HistoryReadBudget>,
    kind: ReadKind,
    allowance: usize,
    active: bool,
}
impl ReadReservation {
    pub(crate) fn allowance(&self) -> usize {
        self.allowance
    }
    pub(crate) fn finish(mut self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > self.allowance {
            return Err(HistoryBudgetExceeded("read reservation").into());
        }
        let mut u = self.budget.usage.lock().map_err(|_| error!("History accounting poisoned"))?;
        let unused = self.allowance - bytes.len();
        match self.kind {
            ReadKind::Proof => {
                u.proof_bytes -= unused;
                if !u.proofs.insert(UInt256::calc_file_hash(bytes)) {
                    u.proof_count -= 1;
                }
            }
            ReadKind::State => u.state_bytes -= unused,
            ReadKind::Metadata => u.metadata_bytes -= unused,
        }
        self.active = false;
        Ok(())
    }
    pub(crate) fn refund_not_started(
        mut self,
        evidence: &storage::archives::bounded_read::ArchiveReadNotStarted,
    ) -> Result<()> {
        if !evidence.is_not_found() {
            return Ok(());
        }
        let mut u = self.budget.usage.lock().map_err(|_| error!("History accounting poisoned"))?;
        match self.kind {
            ReadKind::Proof => {
                u.proof_bytes -= self.allowance;
                u.proof_count -= 1;
            }
            ReadKind::State => u.state_bytes -= self.allowance,
            ReadKind::Metadata => u.metadata_bytes -= self.allowance,
        }
        self.active = false;
        Ok(())
    }
}
impl Drop for ReadReservation {
    fn drop(&mut self) {
        // Unknown partial reads consume the full byte allowance. They are not
        // a distinct successfully obtained proof; attempts remain in steps.
        if self.active && matches!(self.kind, ReadKind::Proof) {
            if let Ok(mut u) = self.budget.usage.lock() {
                u.proof_count -= 1;
            }
        }
    }
}
/// Pre-reserves graph capacity while the transport parser owns a response.
/// Dropping an unfinished parse conservatively spends that capacity.
pub(crate) struct NetworkGraphReservation {
    budget: Arc<HistoryReadBudget>,
    pub cells: usize,
    pub bytes: usize,
    active: bool,
}
impl NetworkGraphReservation {
    /// Convert the transport reservation into actual parser charges under the
    /// same request lock. All roots (including compressed pair roots) share it.
    pub(crate) fn parse_many(
        mut self,
        inputs: &[&[u8]],
    ) -> Result<Vec<rtos_block::BocReaderResult>> {
        let _parse = self.budget.parsing.lock().map_err(|_| error!("History parsing poisoned"))?;
        {
            let mut usage =
                self.budget.usage.lock().map_err(|_| error!("History accounting poisoned"))?;
            usage.reserved_cells -= self.cells;
            usage.reserved_cell_bytes -= self.bytes;
        }
        self.active = false;
        self.budget.healthy()?;
        let result = (|| {
            rtos_block::merkle_apply_budget::MerkleApplyBudget::workspace(
                self.budget.as_ref(),
                inputs
                    .len()
                    .checked_mul(std::mem::size_of::<rtos_block::BocReaderResult>())
                    .ok_or_else(|| error!("Network root allocation overflow"))?,
            )?;
            let mut parsed = Vec::with_capacity(inputs.len());
            for input in inputs {
                parsed.push(self.budget.parse_boc_roots_inner(input)?);
            }
            Ok(parsed)
        })();
        if result.is_err() {
            self.budget.failed.store(true, Ordering::Release);
        }
        result.map_err(|error: anyhow::Error| {
            error.context(HistoryBudgetExceeded("network BOC validation failed"))
        })
    }
    pub fn finish(self, root: &Cell) -> Result<()> {
        self.finish_many(&[root])
    }
    pub fn finish_many(mut self, roots: &[&Cell]) -> Result<()> {
        let _parse = self.budget.parsing.lock().map_err(|_| error!("History parsing poisoned"))?;
        {
            let mut usage =
                self.budget.usage.lock().map_err(|_| error!("History accounting poisoned"))?;
            usage.reserved_cells -= self.cells;
            usage.reserved_cell_bytes -= self.bytes;
        }
        self.active = false;
        self.budget.healthy()?;
        let result = roots.iter().try_for_each(|root| self.budget.graph_inner(root));
        if result.is_err() {
            self.budget.failed.store(true, Ordering::Release);
        }
        result.map_err(|error| {
            error.context(HistoryBudgetExceeded("network graph validation failed"))
        })
    }
}
impl Drop for NetworkGraphReservation {
    fn drop(&mut self) {
        if self.active {
            if let Ok(mut usage) = self.budget.usage.lock() {
                usage.reserved_cells -= self.cells;
                usage.reserved_cell_bytes -= self.bytes;
                usage.cells += self.cells;
                usage.cell_bytes += self.bytes;
            }
        }
    }
}
fn add(value: &mut usize, amount: usize, limit: usize, label: &'static str) -> Result<()> {
    let next = value.checked_add(amount).ok_or(HistoryBudgetExceeded(label))?;
    if next > limit {
        return Err(HistoryBudgetExceeded(label).into());
    }
    *value = next;
    Ok(())
}
impl HistoryReadBudget {
    pub(crate) fn set_replay_proofs(&self, proofs: Vec<crate::block_proof::BlockProofStuff>) {
        *self.replay_proofs.lock().unwrap() = Some(proofs);
    }
    pub(crate) fn replay_proofs(&self) -> Result<Option<Vec<crate::block_proof::BlockProofStuff>>> {
        use storage::bounded_cell::CellReadBudget;
        let proofs = self.replay_proofs.lock().unwrap();
        if let Some(proofs) = proofs.as_ref() {
            self.metadata(
                proofs.len() * std::mem::size_of::<crate::block_proof::BlockProofStuff>(),
            )?;
        }
        match proofs.as_ref() {
            Some(proofs) => {
                let mut output = Vec::new();
                output.try_reserve_exact(proofs.len())?;
                for proof in proofs {
                    output.push(proof.clone_with_budget(Some(self))?);
                }
                Ok(Some(output))
            }
            None => Ok(None),
        }
    }
    pub(crate) fn enable_provenance(&self) {
        *self.provenance.lock().unwrap() = Some(Default::default());
    }
    pub(crate) fn provenance_enabled(&self) -> bool {
        self.provenance.lock().unwrap().is_some()
    }
    pub(crate) fn record_history_proof(
        &self,
        proof: &crate::block_proof::BlockProofStuff,
    ) -> Result<()> {
        if let Some(trace) = self.provenance.lock().unwrap().as_mut() {
            trace.proof(proof, self)?;
        }
        Ok(())
    }
    pub(crate) fn record_state(&self, id: &rtos_block::BlockIdExt, root: &Cell) -> Result<()> {
        if let Some(trace) = self.provenance.lock().unwrap().as_mut() {
            trace.state(id, root, self)?;
        }
        Ok(())
    }
    pub(crate) fn record_bytes(
        &self,
        kind: &str,
        id: &rtos_block::BlockIdExt,
        bytes: &[u8],
        root: Option<&UInt256>,
    ) -> Result<()> {
        if let Some(trace) = self.provenance.lock().unwrap().as_mut() {
            trace.bytes(kind, id, bytes, root, self)?;
        }
        Ok(())
    }
    pub(crate) fn take_provenance(
        &self,
    ) -> Result<(Vec<crate::repair_provenance::Dependency>, Vec<crate::block_proof::BlockProofStuff>)>
    {
        self.provenance
            .lock()
            .unwrap()
            .as_mut()
            .map(|t| t.take())
            .ok_or_else(|| error!("No authenticated dependency recorder"))
    }
    pub fn new(limits: HistoryReadLimits) -> Arc<Self> {
        Arc::new(Self {
            graphs: Mutex::new(rtos_block::merkle_apply_budget::BudgetMap::new(limits.cells)),
            limits,
            provenance: Mutex::new(None),
            replay_proofs: Mutex::new(None),
            usage: Mutex::new(Usage::default()),
            parsing: Mutex::new(()),
            failed: AtomicBool::new(false),
            #[cfg(test)]
            local_proof_fallbacks: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            cell_gate: Mutex::new(None),
        })
    }
    #[cfg(test)]
    pub(crate) fn pause_next_cell(
        &self,
    ) -> (tokio::sync::oneshot::Receiver<()>, std::sync::mpsc::Sender<()>) {
        let (entered, observed) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        assert!(self.cell_gate.lock().unwrap().replace((entered, wait)).is_none());
        (observed, release)
    }
    fn healthy(&self) -> Result<()> {
        if self.failed.load(Ordering::Acquire) {
            return Err(HistoryBudgetExceeded("previous failed graph").into());
        }
        Ok(())
    }
    pub fn limits(&self) -> &HistoryReadLimits {
        &self.limits
    }
    pub(crate) fn reserve_network_graph(self: &Arc<Self>) -> Result<NetworkGraphReservation> {
        self.healthy()?;
        let mut usage = self.usage.lock().map_err(|_| error!("History accounting poisoned"))?;
        let cells = self.limits.cells.saturating_sub(usage.cells + usage.reserved_cells);
        let bytes =
            self.limits.cell_bytes.saturating_sub(usage.cell_bytes + usage.reserved_cell_bytes);
        if cells == 0 || bytes == 0 {
            return Err(HistoryBudgetExceeded("network graph capacity").into());
        }
        usage.reserved_cells += cells;
        usage.reserved_cell_bytes += bytes;
        Ok(NetworkGraphReservation { budget: self.clone(), cells, bytes, active: true })
    }
    pub(crate) fn reserve(
        self: &Arc<Self>,
        kind: ReadKind,
        maximum: usize,
    ) -> Result<ReadReservation> {
        let mut u = self.usage.lock().map_err(|_| error!("History accounting poisoned"))?;
        add(&mut u.steps, 1, self.limits.steps, "read attempts")?;
        self.healthy()?;
        let allowance = match kind {
            ReadKind::Proof => {
                let available = self.limits.proof_bytes.saturating_sub(u.proof_bytes);
                let n = maximum.min(self.limits.single_proof_bytes).min(available);
                if n == 0 {
                    return Err(HistoryBudgetExceeded("proof bytes").into());
                }
                add(&mut u.proof_count, 1, self.limits.proof_count, "proof count")?;
                u.proof_bytes += n;
                n
            }
            ReadKind::State => {
                let n = maximum.min(self.limits.state_boc_bytes.saturating_sub(u.state_bytes));
                if n == 0 {
                    return Err(HistoryBudgetExceeded("state BOC bytes").into());
                }
                u.state_bytes += n;
                n
            }
            ReadKind::Metadata => {
                let n = maximum.min(self.limits.metadata_bytes.saturating_sub(u.metadata_bytes));
                if n == 0 {
                    return Err(HistoryBudgetExceeded("metadata bytes").into());
                }
                u.metadata_bytes += n;
                n
            }
        };
        Ok(ReadReservation { budget: self.clone(), kind, allowance, active: true })
    }
    #[cfg(test)]
    pub(crate) fn note_local_proof_fallback(&self) {
        self.local_proof_fallbacks.fetch_add(1, Ordering::Relaxed);
    }
    #[cfg(test)]
    pub(crate) fn local_proof_fallbacks(&self) -> usize {
        self.local_proof_fallbacks.load(Ordering::Relaxed)
    }
    pub(crate) fn step(&self) -> Result<()> {
        let mut u = self.usage.lock().map_err(|_| error!("History accounting poisoned"))?;
        add(&mut u.steps, 1, self.limits.steps, "lookup steps")
    }
    pub(crate) fn proof(&self, proof: &crate::block_proof::BlockProofStuff) -> Result<()> {
        self.proof_bytes(proof.data())?;
        self.graph(proof.root_cell())
    }
    pub(crate) fn proof_bytes(&self, bytes: &[u8]) -> Result<()> {
        self.healthy()?;
        if bytes.len() > self.limits.single_proof_bytes {
            return Err(HistoryBudgetExceeded("single proof bytes").into());
        }
        let hash = UInt256::calc_file_hash(bytes);
        {
            let mut u = self.usage.lock().map_err(|_| error!("History accounting poisoned"))?;
            if !u.proofs.contains(&hash) {
                let mut count = u.proof_count;
                let mut total = u.proof_bytes;
                add(&mut count, 1, self.limits.proof_count, "proof count")?;
                add(&mut total, bytes.len(), self.limits.proof_bytes, "proof bytes")?;
                u.proof_count = count;
                u.proof_bytes = total;
                u.proofs.insert(hash);
            }
        }
        Ok(())
    }
    pub(crate) fn detached_read<T>(&self, read: impl FnOnce() -> Result<T>) -> Result<T> {
        let _parse = self.parsing.lock().map_err(|_| error!("History parsing poisoned"))?;
        self.healthy()?;
        let before = self.usage.lock().map_err(|_| error!("History accounting poisoned"))?.cells;
        let result = read();
        if result.is_err()
            && self.usage.lock().map_err(|_| error!("History accounting poisoned"))?.cells != before
        {
            self.failed.store(true, Ordering::Release);
            return result.map_err(|error| {
                error.context(HistoryBudgetExceeded("detached state graph failed"))
            });
        }
        result
    }
    pub(crate) fn graph(&self, root: &Cell) -> Result<()> {
        let _parse = self.parsing.lock().map_err(|_| error!("History parsing poisoned"))?;
        self.healthy()?;
        let result = self.graph_inner(root);
        if result.is_err() {
            self.failed.store(true, Ordering::Release);
        }
        result.map_err(|error| error.context(HistoryBudgetExceeded("graph validation failed")))
    }
    fn graph_inner(&self, root: &Cell) -> Result<()> {
        // Cell depth authenticates every referenced path, including a DAG node
        // visited earlier at a shallower path; a visited-set alone does not.
        rtos_block::merkle_apply_budget::require_materialized(root)?;
        if root.repr_depth() > self.limits.depth {
            return Err(HistoryBudgetExceeded("cell depth").into());
        }
        // Each unique cell contributes at most four references to the pending
        // traversal. Capacity growth is charged at the actual allocation size.
        let mut stack = rtos_block::merkle_apply_budget::BudgetStack::new(
            self.limits.cells.saturating_mul(4).max(1),
        );
        stack.push(root.clone(), self)?;
        while let Some(cell) = stack.pop() {
            self.step()?;
            rtos_block::merkle_apply_budget::require_materialized(&cell)?;
            let mut graphs =
                self.graphs.lock().map_err(|_| error!("History graph table poisoned"))?;
            if graphs.get(cell.repr_hash(), self)?.is_some() {
                continue;
            }
            let mut u = self.usage.lock().map_err(|_| error!("History accounting poisoned"))?;
            let cell_limit = self.limits.cells.saturating_sub(u.reserved_cells);
            let byte_limit = self.limits.cell_bytes.saturating_sub(u.reserved_cell_bytes);
            add(&mut u.cells, 1, cell_limit, "cell count")?;
            add(&mut u.cell_bytes, (cell.bit_length() + 7) / 8 + 32, byte_limit, "cell bytes")?;
            drop(u);
            graphs.insert(cell.repr_hash().clone(), (), self)?;
            drop(graphs);
            for index in 0..cell.references_count() {
                stack.push(cell.reference(index)?, self)?;
            }
        }
        Ok(())
    }
    /// Local replaceable artifacts have no authority. Syntax failure consumes
    /// declared parse work but cannot publish an incomplete graph/cache entry.
    pub(crate) fn parse_local_artifact(&self, bytes: &[u8]) -> Result<Cell> {
        let _parse = self.parsing.lock().map_err(|_| error!("History parsing poisoned"))?;
        self.healthy()?;
        let mut reader = rtos_block::BocReader::new().set_max_cell_depth(self.limits.depth);
        let config_budget = crate::bounded_session_derivation::ConfigBudget(self);
        let (header, _) = reader
            .read_header_bounded(&mut std::io::Cursor::new(bytes), &config_budget)
            .map_err(|error| {
                if stops_fallback(&error) {
                    self.failed.store(true, Ordering::Release);
                }
                error
            })?;
        {
            let usage = self.usage.lock().map_err(|_| error!("History accounting poisoned"))?;
            if header.cells_count
                > self.limits.cells.saturating_sub(usage.cells + usage.reserved_cells)
                || header.tot_cells_size
                    > self
                        .limits
                        .cell_bytes
                        .saturating_sub(usage.cell_bytes + usage.reserved_cell_bytes)
            {
                self.failed.store(true, Ordering::Release);
                return Err(HistoryBudgetExceeded("local artifact BOC header").into());
            }
        }
        let parsed =
            reader.read_bounded(bytes, &config_budget).and_then(|boc| boc.withdraw_single_root());
        let root = match parsed {
            Ok(root) => root,
            Err(error) => {
                let mut usage =
                    self.usage.lock().map_err(|_| error!("History accounting poisoned"))?;
                usage.cells += header.cells_count;
                // The bounded reader already charged every attempted allocation.
                // Keep cell-count admission spent on discarded malformed graphs.
                // The parser has discarded every partial cell and has not
                // published graph-cache entries. Keep all attempted work charged.
                // A typed depth rejection is a limit, never replaceable syntax.
                if error.downcast_ref::<rtos_block::CellDepthLimitExceeded>().is_some()
                    || stops_fallback(&error)
                {
                    self.failed.store(true, Ordering::Release);
                    return Err(error.context(HistoryBudgetExceeded("local artifact parser limit")));
                }
                return Err(error);
            }
        };
        let result = self.graph_inner(&root);
        if result.is_err() {
            self.failed.store(true, Ordering::Release);
        }
        result.map_err(|error| error.context(HistoryBudgetExceeded("artifact graph failed")))?;
        Ok(root)
    }
    pub(crate) fn parse_boc(&self, bytes: &[u8]) -> Result<Cell> {
        let _parse = self.parsing.lock().map_err(|_| error!("History parsing poisoned"))?;
        self.healthy()?;
        let result = self.parse_boc_inner(bytes);
        if result.is_err() {
            self.failed.store(true, Ordering::Release);
        }
        result.map_err(|error| error.context(HistoryBudgetExceeded("graph validation failed")))
    }
    fn parse_boc_inner(&self, bytes: &[u8]) -> Result<Cell> {
        self.parse_boc_roots_inner(bytes)?.withdraw_single_root()
    }
    fn parse_boc_roots_inner(&self, bytes: &[u8]) -> Result<rtos_block::BocReaderResult> {
        // No await: serialize header admission with graph charging so shared
        // request callers cannot each parse against the same remaining quota.
        let mut reader = rtos_block::BocReader::new().set_max_cell_depth(self.limits.depth);
        let config_budget = crate::bounded_session_derivation::ConfigBudget(self);
        let (header, _) =
            reader.read_header_bounded(&mut std::io::Cursor::new(bytes), &config_budget)?;
        let u = self.usage.lock().map_err(|_| error!("History accounting poisoned"))?;
        if header.cells_count > self.limits.cells.saturating_sub(u.cells + u.reserved_cells)
            || header.tot_cells_size
                > self.limits.cell_bytes.saturating_sub(u.cell_bytes + u.reserved_cell_bytes)
        {
            return Err(HistoryBudgetExceeded("BOC header cells/bytes").into());
        }
        drop(u);
        let parsed = reader.read_bounded(bytes, &config_budget)?;
        for root in &parsed.roots {
            self.graph_inner(root)?;
        }
        Ok(parsed)
    }
}

impl rtos_block::merkle_apply_budget::MerkleApplyBudget for HistoryReadBudget {
    fn step(&self) -> Result<()> {
        self.healthy()?;
        HistoryReadBudget::step(self)
    }
    fn workspace(&self, bytes: usize) -> Result<()> {
        self.healthy()?;
        let mut usage = self.usage.lock().map_err(|_| error!("History accounting poisoned"))?;
        let limit = self.limits.cell_bytes.saturating_sub(usage.reserved_cell_bytes);
        add(&mut usage.cell_bytes, bytes, limit, "Merkle workspace")
    }
    fn new_cell(&self, bytes: usize) -> Result<()> {
        storage::bounded_cell::CellReadBudget::admit_cell(self, &UInt256::default(), bytes, 0)
    }
    fn max_depth(&self) -> u16 {
        self.limits.depth
    }
}

impl storage::bounded_cell::CellReadBudget for HistoryReadBudget {
    fn admit_cell(&self, _hash: &UInt256, bytes: usize, depth: usize) -> Result<()> {
        #[cfg(test)]
        {
            let gate = self.cell_gate.lock().unwrap().take();
            if let Some((entered, release)) = gate {
                let _ = entered.send(());
                let _ = release.recv();
            }
        }
        self.healthy()?;
        if depth > self.limits.depth as usize {
            return Err(HistoryBudgetExceeded("detached cell depth").into());
        }
        let mut usage = self.usage.lock().map_err(|_| error!("History accounting poisoned"))?;
        let mut cells = usage.cells;
        let mut total = usage.cell_bytes;
        add(
            &mut cells,
            1,
            self.limits.cells.saturating_sub(usage.reserved_cells),
            "detached cells",
        )?;
        add(
            &mut total,
            bytes,
            self.limits.cell_bytes.saturating_sub(usage.reserved_cell_bytes),
            "detached allocations",
        )?;
        usage.cells = cells;
        usage.cell_bytes = total;
        Ok(())
    }
    fn complete_cell(&self, cell: &Cell) -> Result<()> {
        rtos_block::merkle_apply_budget::require_materialized(cell)?;
        self.graphs.lock().map_err(|_| error!("History graph table poisoned"))?.insert(
            cell.repr_hash().clone(),
            (),
            self,
        )?;
        Ok(())
    }
    fn step(&self) -> Result<()> {
        HistoryReadBudget::step(self)
    }
    fn metadata(&self, bytes: usize) -> Result<()> {
        self.healthy()?;
        let mut usage = self.usage.lock().map_err(|_| error!("History accounting poisoned"))?;
        add(&mut usage.metadata_bytes, bytes, self.limits.metadata_bytes, "state index bytes")
    }
    fn max_depth(&self) -> u16 {
        self.limits.depth
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn history_budget_missing_local_refunds_only_verified_zero_read() -> Result<()> {
        let package_context_dir = tempfile::tempdir()?;
        let package_context_db = storage::db::rocksdb::RocksDb::new(package_context_dir.path(), "provider", None, storage::db::rocksdb::AccessType::ReadWrite)?;
        let package_view = package_context_db.bind_archive_domain(storage::archives::context::ArchiveDomain::new())?.view()?;
        let package_operation = package_view.enter()?;

        use storage::archives::{
            bounded_read::{ArchiveReadLimits, ArchiveReadNotStarted},
            package::Package,
        };
        // Open failure evidence comes from the actual bounded archive path;
        // callers cannot construct it from an unrelated NotFound after partial IO.
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("pack");
        let package = Package::open(package_view.clone(), &package_operation, path.clone(), false, true).await?;
        std::fs::remove_file(&path)?;
        let error = package
            .read_entry_bounded(0, ArchiveReadLimits { data_bytes: 4, filename_bytes: 64 })
            .await
            .err()
            .expect("missing physical file");
        let evidence = error.downcast_ref::<ArchiveReadNotStarted>().expect("open-only evidence");
        assert!(evidence.is_not_found());
        let budget = HistoryReadBudget::new(HistoryReadLimits {
            proof_count: 1,
            proof_bytes: 4,
            single_proof_bytes: 4,
            ..Default::default()
        });
        budget.reserve(ReadKind::Proof, 4)?.refund_not_started(evidence)?;
        assert_eq!(budget.usage.lock().unwrap().steps, 1);
        budget.reserve(ReadKind::Proof, 4)?.finish(b"abcd")?;
        assert_eq!(budget.usage.lock().unwrap().proof_count, 1);
        assert_eq!(budget.usage.lock().unwrap().proof_bytes, 4);
        let budget = HistoryReadBudget::new(HistoryReadLimits {
            proof_count: 1,
            proof_bytes: 4,
            ..Default::default()
        });
        drop(budget.reserve(ReadKind::Proof, 4)?);
        assert_eq!(budget.usage.lock().unwrap().proof_count, 0);
        assert_eq!(budget.usage.lock().unwrap().proof_bytes, 4);
        assert!(budget.reserve(ReadKind::Proof, 4).is_err());

        Ok(())
    }
    #[test]
    fn history_budget_graph_table_and_stack_growth_are_cumulative() -> Result<()> {
        use rtos_block::IBitstring;
        // Sixteen distinct leaves plus five parents force table and stack growth.
        let mut branches = Vec::new();
        for branch in 0..4u32 {
            let mut parent = rtos_block::BuilderData::new();
            for leaf in 0..4u32 {
                let mut child = rtos_block::BuilderData::new();
                child.append_u32(branch * 4 + leaf)?;
                parent.checked_append_reference(child.into_cell()?)?;
            }
            branches.push(parent.into_cell()?);
        }
        let mut builder = rtos_block::BuilderData::new();
        for branch in branches {
            builder.checked_append_reference(branch)?;
        }
        let root = builder.into_cell()?;
        let budget = HistoryReadBudget::new(Default::default());
        budget.graph(&root)?;
        let first_bytes = budget.usage.lock().unwrap().cell_bytes;
        let count = budget.usage.lock().unwrap().cells;
        assert_eq!(count, 21);
        assert_eq!(budget.graphs.lock().unwrap().len(), 21);
        assert!(first_bytes > 21 * 36, "table replacement and stack storage are admitted");
        budget.graph(&root)?;
        assert_eq!(budget.usage.lock().unwrap().cells, count);
        let both_bytes = budget.usage.lock().unwrap().cell_bytes;
        assert!(both_bytes > first_bytes, "even a deduplicated graph creates a charged stack");
        let exact = HistoryReadBudget::new(HistoryReadLimits {
            cell_bytes: both_bytes,
            ..Default::default()
        });
        exact.graph(&root)?;
        exact.graph(&root)?;
        assert_eq!(exact.usage.lock().unwrap().cell_bytes, both_bytes);
        let short = HistoryReadBudget::new(HistoryReadLimits {
            cell_bytes: both_bytes - 1,
            ..Default::default()
        });
        short.graph(&root)?;
        assert!(stops_fallback(&short.graph(&root).unwrap_err()));
        assert!(short.graph(&root).is_err());
        Ok(())
    }
    #[test]
    fn history_budget_network_parse_reservation_spends_shared_workspace() -> Result<()> {
        let root = Cell::default();
        let bytes = rtos_block::write_boc(&root)?;
        let budget = HistoryReadBudget::new(Default::default());
        let parsed = budget.reserve_network_graph()?.parse_many(&[&bytes, &bytes])?;
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].roots[0], root);
        let usage = budget.usage.lock().unwrap();
        let exact_bytes = usage.cell_bytes;
        assert!(
            exact_bytes > 2 * bytes.len(),
            "parser allocations are charged, not just unique graph data"
        );
        assert_eq!(usage.reserved_cell_bytes, 0);
        assert_eq!(usage.cells, 1, "graph identity is deduplicated but parse allocations are not");
        drop(usage);
        let budget = HistoryReadBudget::new(HistoryReadLimits {
            cell_bytes: exact_bytes,
            ..Default::default()
        });
        budget.reserve_network_graph()?.parse_many(&[&bytes, &bytes])?;
        assert!(
            budget.reserve_network_graph().is_err(),
            "a second parse cannot create fresh workspace"
        );
        let budget = HistoryReadBudget::new(HistoryReadLimits {
            cell_bytes: exact_bytes - 1,
            ..Default::default()
        });
        let error = budget
            .reserve_network_graph()?
            .parse_many(&[&bytes, &bytes])
            .err()
            .expect("one byte below cumulative parser admission");
        assert!(stops_fallback(&error));
        assert!(budget.graph(&root).is_err());
        Ok(())
    }
    #[test]
    fn history_budget_boc_preflight_and_failed_graph_stay_failed() -> Result<()> {
        let root = Cell::default();
        let boc = rtos_block::write_boc(&root)?;
        let budget = HistoryReadBudget::new(HistoryReadLimits { cells: 0, ..Default::default() });
        let error = budget.parse_boc(&boc).err().expect("header denied before parse");
        assert!(stops_fallback(&error));
        assert!(budget.graph(&root).is_err());
        let budget = HistoryReadBudget::new(HistoryReadLimits::default());
        budget.parse_boc(&boc)?;
        let count = budget.usage.lock().unwrap().cells;
        budget.graph(&root)?;
        assert_eq!(budget.usage.lock().unwrap().cells, count);
        let reservation = budget.reserve_network_graph()?;
        assert!(budget.reserve_network_graph().is_err());
        reservation.finish(&root)?;
        assert_eq!(budget.usage.lock().unwrap().cells, count);
        Ok(())
    }
    #[test]
    fn history_budget_local_syntax_preserves_attempts_and_only_limits_poison() -> Result<()> {
        let boc = rtos_block::write_boc(&Cell::default())?;
        let mut truncated = boc.clone();
        truncated.pop(); // header admitted, body incomplete
        let budget = HistoryReadBudget::new(HistoryReadLimits::default());
        budget.proof_bytes(&truncated)?;
        let error = budget.parse_local_artifact(&truncated).unwrap_err();
        assert!(!stops_fallback(&error), "ordinary syntax is not budget authority");
        assert_eq!(budget.usage.lock().unwrap().cells, 1);
        assert_eq!(budget.usage.lock().unwrap().proof_bytes, truncated.len());
        budget.proof_bytes(&boc)?;
        budget.parse_local_artifact(&boc)?;
        let usage = budget.usage.lock().unwrap();
        assert_eq!(usage.cells, 2, "failed parsing work must not be refunded");
        assert_eq!(usage.proof_count, 2);
        drop(usage);
        let budget = HistoryReadBudget::new(HistoryReadLimits { cells: 1, ..Default::default() });
        assert!(budget.parse_local_artifact(&truncated).is_err());
        assert!(stops_fallback(&budget.parse_local_artifact(&boc).unwrap_err()));
        assert!(budget.parse_local_artifact(&boc).is_err(), "no new quota after denial");
        Ok(())
    }
    #[test]
    fn history_budget_failed_detach_cannot_publish_partial_graph_to_competitor() {
        use storage::bounded_cell::CellReadBudget;
        let budget = HistoryReadBudget::new(Default::default());
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let first_budget = budget.clone();
        let first = std::thread::spawn(move || {
            first_budget.detached_read(|| {
                let root = Cell::default();
                first_budget.admit_cell(root.repr_hash(), 4096, 0)?;
                first_budget.complete_cell(&root)?;
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Err::<(), _>(error!("real traversal failed after a completed prefix"))
            })
        });
        entered_rx.recv().unwrap();
        let second_budget = budget.clone();
        let (attempt_tx, attempt_rx) = std::sync::mpsc::channel();
        let second = std::thread::spawn(move || {
            attempt_tx.send(()).unwrap();
            second_budget.graph(&Cell::default())
        });
        attempt_rx.recv().unwrap();
        release_tx.send(()).unwrap();
        assert!(stops_fallback(&first.join().unwrap().unwrap_err()));
        assert!(stops_fallback(&second.join().unwrap().unwrap_err()));
    }
    #[test]
    fn history_budget_exact_distinct_proofs_and_attempts() -> Result<()> {
        let budget = HistoryReadBudget::new(HistoryReadLimits {
            proof_count: 1,
            proof_bytes: 8,
            single_proof_bytes: 4,
            ..Default::default()
        });
        budget.reserve(ReadKind::Proof, 4)?.finish(b"abcd")?;
        budget.proof_bytes(b"abcd")?;
        assert_eq!(budget.usage.lock().unwrap().proof_count, 1);
        assert_eq!(budget.usage.lock().unwrap().proof_bytes, 4);
        assert!(budget.proof_bytes(b"efgh").is_err());
        assert_eq!(budget.usage.lock().unwrap().steps, 1);
        Ok(())
    }
}


#[cfg(test)]
#[test]
fn archive_context_refusal_always_stops_history_fallback() {
    use storage::archives::context::ArchiveContextError;
    for refusal in [ArchiveContextError::Closed(0), ArchiveContextError::RecoveryRequired(0), ArchiveContextError::Stale { expected: 0, current: 1 }] {
        let error = anyhow::Error::new(refusal).context("actual archive resolver boundary");
        assert!(stops_fallback(&error));
        assert!(!error.is::<storage::archives::bounded_read::ArchiveArtifactMissing>());
        assert!(!error.is::<storage::archives::bounded_read::ArchiveReadNotStarted>());
    }
}
