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
    graphs: HashSet<UInt256>,
}
pub struct HistoryReadBudget {
    limits: HistoryReadLimits,
    usage: Mutex<Usage>,
    parsing: Mutex<()>,
    failed: AtomicBool,
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
    pub fn new(limits: HistoryReadLimits) -> Arc<Self> {
        Arc::new(Self {
            limits,
            usage: Mutex::new(Usage::default()),
            parsing: Mutex::new(()),
            failed: AtomicBool::new(false),
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
        if root.repr_depth() > self.limits.depth {
            return Err(HistoryBudgetExceeded("cell depth").into());
        }
        let mut stack = vec![root.clone()];
        while let Some(cell) = stack.pop() {
            self.step()?;
            let mut u = self.usage.lock().map_err(|_| error!("History accounting poisoned"))?;
            if u.graphs.contains(cell.repr_hash()) {
                continue;
            }
            let cell_limit = self.limits.cells.saturating_sub(u.reserved_cells);
            let byte_limit = self.limits.cell_bytes.saturating_sub(u.reserved_cell_bytes);
            add(&mut u.cells, 1, cell_limit, "cell count")?;
            add(&mut u.cell_bytes, (cell.bit_length() + 7) / 8 + 32, byte_limit, "cell bytes")?;
            u.graphs.insert(cell.repr_hash().clone());
            drop(u);
            for index in 0..cell.references_count() {
                stack.push(cell.reference(index)?);
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
        let (header, _) = reader.read_header(&mut std::io::Cursor::new(bytes))?;
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
                return Err(HistoryBudgetExceeded("local artifact BOC header").into());
            }
        }
        let parsed = reader.read(bytes).and_then(|boc| boc.withdraw_single_root());
        let root = match parsed {
            Ok(root) => root,
            Err(error) => {
                let mut usage =
                    self.usage.lock().map_err(|_| error!("History accounting poisoned"))?;
                usage.cells += header.cells_count;
                usage.cell_bytes += header.tot_cells_size;
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
        // No await: serialize header admission with graph charging so shared
        // request callers cannot each parse against the same remaining quota.
        let mut reader = rtos_block::BocReader::new().set_max_cell_depth(self.limits.depth);
        let (header, _) = reader.read_header(&mut std::io::Cursor::new(bytes))?;
        let u = self.usage.lock().map_err(|_| error!("History accounting poisoned"))?;
        if header.cells_count > self.limits.cells.saturating_sub(u.cells + u.reserved_cells)
            || header.tot_cells_size
                > self.limits.cell_bytes.saturating_sub(u.cell_bytes + u.reserved_cell_bytes)
        {
            return Err(HistoryBudgetExceeded("BOC header cells/bytes").into());
        }
        drop(u);
        let root = reader.read(bytes)?.withdraw_single_root()?;
        self.graph_inner(&root)?;
        Ok(root)
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
        self.usage
            .lock()
            .map_err(|_| error!("History accounting poisoned"))?
            .graphs
            .insert(cell.repr_hash().clone());
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
        use storage::archives::{
            bounded_read::{ArchiveReadLimits, ArchiveReadNotStarted},
            package::Package,
        };
        // Open failure evidence comes from the actual bounded archive path;
        // callers cannot construct it from an unrelated NotFound after partial IO.
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("pack");
        let package = Package::open(path.clone(), false, true).await?;
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
