// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Source retirement preparation: an exclusive, read-only inventory of a
//! drained masterchain source namespace, reconciled against node custody.
//!
//! A preparation is input to a later retirement transaction, never retirement
//! itself. Nothing here writes, renames or deletes namespace content. Once a
//! sealed certificate has been collected its retained digest is opaque: this
//! module never claims to re-authenticate collected certificate bytes, and
//! `DigestMismatch` only reports disagreement between artifacts that still exist.
use super::*;
use crate::finality_recovery::SourceHistoryDebtBudget;
use consensus_common::finality_delivery::DurableFinalitySink;
use consensus_common::StorageTeardownReceipt;

const INVENTORY_TAG: &str = "rtos/source-retirement-inventory/v1";

/// Why a preparation was refused. Every refusal leaves the namespace unchanged.
#[derive(Debug)]
pub enum RetirementRefusal {
    /// Another owner holds a namespace lock; retry later.
    Busy,
    Unsupported(&'static str),
    DatabaseTeardown(String),
    Missing(PathBuf),
    Manifest(String),
    PendingRecord(PathBuf),
    UnsealedIntent(PathBuf),
    UnreleasedOutputSet(PathBuf),
    LegacyFormat(PathBuf, String),
    UnknownArtifact(PathBuf),
    UncertainTemporary(PathBuf),
    DomainMismatch(PathBuf, String),
    DigestMismatch(PathBuf, String),
    MissingDelivered(String),
    OrphanDelivered(PathBuf),
    NotNodeConfirmed(PathBuf),
    EmptyInventory,
    NotReleased {
        source_id: UInt256,
        state: &'static str,
    },
    OfferMismatch(UInt256),
    CustodyUnverified {
        source_id: UInt256,
        error: String,
    },
    BudgetExhausted(String),
    Failed(String),
}

impl std::fmt::Display for RetirementRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Busy => f.write_str("Source namespace owner busy"),
            Self::Unsupported(what) => write!(f, "Retirement unsupported: {what}"),
            Self::DatabaseTeardown(e) => write!(f, "Source database teardown unproven: {e}"),
            Self::Missing(p) => write!(f, "Required source artifact missing: {}", p.display()),
            Self::Manifest(e) => write!(f, "Source runtime manifest refused: {e}"),
            Self::PendingRecord(p) => write!(f, "Undelivered source record: {}", p.display()),
            Self::UnsealedIntent(p) => write!(f, "Unsealed source intent: {}", p.display()),
            Self::UnreleasedOutputSet(p) => {
                write!(f, "Source output set not released: {}", p.display())
            }
            Self::LegacyFormat(p, e) => write!(f, "Unknown/legacy artifact {}: {e}", p.display()),
            Self::UnknownArtifact(p) => write!(f, "Unexpected source artifact: {}", p.display()),
            Self::UncertainTemporary(p) => write!(f, "Uncertain temporary: {}", p.display()),
            Self::DomainMismatch(p, e) => write!(f, "Domain mismatch {}: {e}", p.display()),
            Self::DigestMismatch(p, e) => write!(f, "Identity mismatch {}: {e}", p.display()),
            Self::MissingDelivered(o) => write!(f, "Sealed output has no Delivered record: {o}"),
            Self::OrphanDelivered(p) => {
                write!(f, "Delivered record claimed by no sealed output: {}", p.display())
            }
            Self::NotNodeConfirmed(p) => write!(f, "Delivered not node-confirmed: {}", p.display()),
            Self::EmptyInventory => f.write_str("Source namespace has nothing proven to retire"),
            Self::NotReleased { source_id, state } => {
                write!(f, "Node has not released {}: {state}", source_id.to_hex_string())
            }
            Self::OfferMismatch(id) => {
                write!(f, "Node released a different offer for {}", id.to_hex_string())
            }
            Self::CustodyUnverified { source_id, error } => {
                write!(f, "Node custody unverified for {}: {error}", source_id.to_hex_string())
            }
            Self::BudgetExhausted(e) => write!(f, "Retirement preparation budget exhausted: {e}"),
            Self::Failed(e) => write!(f, "Retirement preparation failed: {e}"),
        }
    }
}
impl std::error::Error for RetirementRefusal {}

pub(crate) type Refusal<T> = std::result::Result<T, RetirementRefusal>;

pub(crate) fn failed(error: impl std::fmt::Display) -> RetirementRefusal {
    RetirementRefusal::Failed(format!("{error:#}"))
}

/// Which hard byte cap a file read counts against.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Bucket {
    /// The runtime manifest; its reader bounds it separately.
    Manifest,
    Delivered,
    Sets,
}

/// Parsed JSON with its owned strings and containers stays within this many
/// times the bytes it was parsed from.
pub(crate) const PARSE_WORKSPACE_FACTOR: usize = 4;
/// Upper bound for the runtime manifest the reader rebuilds for comparison.
pub(crate) const MANIFEST_WORKSPACE: usize = 4096;
/// Per committee member: its consensus node with PQ public key and its share
/// of the committee digest input, each bounded by the PQ key size.
const MANIFEST_PER_MEMBER: usize = 4096;

/// Workspace for rebuilding the manifest, including the committee digest's
/// per-member node and key buffers.
pub(crate) fn manifest_workspace(committee: usize) -> Refusal<usize> {
    committee
        .checked_mul(MANIFEST_PER_MEMBER)
        .and_then(|members| members.checked_add(MANIFEST_WORKSPACE))
        .ok_or_else(|| exhausted("manifest workspace overflow"))
}
/// Per-entry overhead of the index, file list and digest beyond its strings.
const ENTRY_OVERHEAD: usize = 256;

fn exhausted(error: impl std::fmt::Display) -> RetirementRefusal {
    RetirementRefusal::BudgetExhausted(format!("{error:#}"))
}

/// Charges the caller's budget before work and allocation, under hard caps
/// the caller cannot raise: never more entries or bytes per directory than the
/// source store itself may legally hold.
pub(crate) struct Charge<'a> {
    budget: &'a dyn SourceHistoryDebtBudget,
    entries: usize,
    delivered_bytes: u64,
    set_bytes: u64,
}
impl<'a> Charge<'a> {
    // Directory entries of both stores, plus their fixed subdirectories and lock.
    const MAX_ENTRIES: usize = MAX_REFERENCES + crate::finality_recovery::MAX_RETIREMENT_SETS + 8;
    const MAX_DELIVERED_BYTES: u64 = MAX_REFERENCE_TOTAL;
    const MAX_SET_BYTES: u64 = crate::finality_recovery::MAX_RETIREMENT_SET_BYTES;
    pub(crate) fn new(budget: &'a dyn SourceHistoryDebtBudget) -> Self {
        Self { budget, entries: 0, delivered_bytes: 0, set_bytes: 0 }
    }
    /// One directory entry examined.
    pub(crate) fn step(&mut self) -> Refusal<()> {
        self.entries =
            self.entries.checked_add(1).ok_or_else(|| exhausted("entry count overflow"))?;
        if self.entries > Self::MAX_ENTRIES {
            return Err(exhausted("directory entry hard cap"));
        }
        self.budget.step().map_err(exhausted)
    }
    /// Bytes about to be read from one file, and the buffer that holds them.
    pub(crate) fn read(&mut self, bucket: Bucket, bytes: usize) -> Refusal<()> {
        let bytes64 = u64::try_from(bytes).map_err(failed)?;
        let (total, cap) = match bucket {
            Bucket::Manifest => (None, 0),
            Bucket::Delivered => (Some(&mut self.delivered_bytes), Self::MAX_DELIVERED_BYTES),
            Bucket::Sets => (Some(&mut self.set_bytes), Self::MAX_SET_BYTES),
        };
        if let Some(total) = total {
            *total = total.checked_add(bytes64).ok_or_else(|| exhausted("byte count overflow"))?;
            if *total > cap {
                return Err(exhausted(format!("{bucket:?} byte hard cap")));
            }
        }
        self.budget.read_bytes(bytes).map_err(exhausted)?;
        self.budget.workspace(bytes).map_err(exhausted)
    }
    /// Memory about to be allocated for derived structures at `stage`.
    pub(crate) fn workspace(&mut self, stage: &'static str, bytes: usize) -> Refusal<()> {
        self.budget.workspace(bytes).map_err(|e| exhausted(format!("{stage}: {e:#}")))
    }
    /// Workspace for parsing `bytes` read from one file at `stage`.
    pub(crate) fn parse(&mut self, stage: &'static str, bytes: usize) -> Refusal<()> {
        let bound = bytes
            .checked_mul(PARSE_WORKSPACE_FACTOR)
            .ok_or_else(|| exhausted(format!("{stage}: workspace overflow")))?;
        self.workspace(stage, bound)
    }
    /// One node lookup about to be admitted.
    pub(crate) fn lookup(&mut self) -> Refusal<()> {
        self.budget.step().map_err(exhausted)
    }
}

/// Reads one regular file with a size bound, refusing symlinks and growth.
pub(crate) fn read_bounded(
    path: &Path,
    limit: u64,
    bucket: Bucket,
    charge: &mut Charge,
) -> Refusal<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path).map_err(failed)?;
    if !metadata.file_type().is_file() {
        return Err(RetirementRefusal::UnknownArtifact(path.to_owned()));
    }
    if metadata.len() > limit {
        return Err(RetirementRefusal::LegacyFormat(path.to_owned(), "oversized".into()));
    }
    let length = usize::try_from(metadata.len()).map_err(failed)?;
    charge.read(bucket, length)?;
    let file = File::open(path).map_err(failed)?;
    let mut bytes = Vec::with_capacity(length);
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes).map_err(failed)?;
    if bytes.len() != length {
        return Err(RetirementRefusal::LegacyFormat(path.to_owned(), "changed size".into()));
    }
    Ok(bytes)
}

/// Requires an existing real directory, never a symlink.
pub(crate) fn existing_directory(path: &Path) -> Refusal<()> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_dir() => Ok(()),
        Ok(_) => Err(RetirementRefusal::UnknownArtifact(path.to_owned())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(RetirementRefusal::Missing(path.to_owned()))
        }
        Err(e) => Err(failed(e)),
    }
}

/// One Delivered record, as read byte-exact under the source lock.
pub(crate) struct RetirementDelivered {
    pub(crate) path: PathBuf,
    pub(crate) file_hash: UInt256,
    pub(crate) block_id: String,
    pub(crate) is_final: bool,
    pub(crate) source_validator: String,
    pub(crate) source_id: UInt256,
    pub(crate) offer: CloseOffer,
}

/// One released sealed output set, as read byte-exact under the source lock.
pub(crate) struct RetirementSealedSet {
    pub(crate) path: PathBuf,
    pub(crate) file_hash: UInt256,
    /// (block id, is_final, source validator) of every sealed output.
    pub(crate) outputs: Vec<(String, bool, String)>,
}

/// One inventory item reconciled against node custody.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetirementItem {
    pub source_id: UInt256,
    pub offer: CloseOffer,
}

/// Locks, inventory and digest; the node has not yet been consulted.
pub struct PendingRetirementScan {
    runtime: Arc<AuthenticatedSessionRuntime>,
    manifest_digest: UInt256,
    items: Vec<RetirementItem>,
    inventory_digest: UInt256,
    // Drop order: store lock before the manifest lock, as a session would.
    _store: Arc<PendingFinalityStore>,
    _manifest: crate::runtime_manifest::RuntimeManifest,
}

/// A refused reconciliation, handing back the scan that still holds the locks.
pub struct ReconcileFailure {
    pub scan: PendingRetirementScan,
    pub refusal: RetirementRefusal,
}

/// Not serializable or constructible outside this module. Holding it keeps the
/// namespace locked; it authorizes nothing by itself.
pub struct SourceRetirementPreparation {
    scan: PendingRetirementScan,
}

impl PendingRetirementScan {
    pub fn runtime(&self) -> &Arc<AuthenticatedSessionRuntime> {
        &self.runtime
    }
    pub fn inventory(&self) -> &[RetirementItem] {
        &self.items
    }
    pub fn inventory_digest(&self) -> &UInt256 {
        &self.inventory_digest
    }
    pub fn manifest_digest(&self) -> &UInt256 {
        &self.manifest_digest
    }
    /// Asks the node, one item at a time, whether it released exactly the
    /// offer this source recorded. Each lookup is charged before admission and
    /// awaited asynchronously, so no thread blocks while the node's own
    /// workers complete it. An admitted lookup is never timed out: its
    /// completion is owned by the node and runs exactly once. On refusal the
    /// still-locked scan is handed back.
    pub async fn reconcile(
        self,
        sink: &dyn DurableFinalitySink,
        budget: &dyn SourceHistoryDebtBudget,
    ) -> std::result::Result<SourceRetirementPreparation, Box<ReconcileFailure>> {
        for index in 0..self.items.len() {
            let result = match self.items.get(index) {
                Some(item) => lookup_released(sink, budget, item).await,
                None => Err(failed("inventory changed during reconciliation")),
            };
            if let Err(refusal) = result {
                return Err(Box::new(ReconcileFailure { scan: self, refusal }));
            }
        }
        Ok(SourceRetirementPreparation { scan: self })
    }
}

async fn lookup_released(
    sink: &dyn DurableFinalitySink,
    budget: &dyn SourceHistoryDebtBudget,
    item: &RetirementItem,
) -> Refusal<()> {
    Charge::new(budget).lookup()?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    sink.lookup_terminal(
        item.offer.request.clone(),
        Box::new(move |result| {
            let _ = tx.send(result);
        }),
    )
    .map_err(|e| RetirementRefusal::CustodyUnverified {
        source_id: item.source_id.clone(),
        error: format!("lookup not admitted: {e:#}"),
    })?;
    let result = rx.await.map_err(|_| RetirementRefusal::CustodyUnverified {
        source_id: item.source_id.clone(),
        error: "lookup completion dropped".into(),
    })?;
    match result {
        Ok(FinalityTerminalLookup::Released(offer)) if offer == item.offer => Ok(()),
        Ok(FinalityTerminalLookup::Released(_)) => {
            Err(RetirementRefusal::OfferMismatch(item.source_id.clone()))
        }
        Ok(FinalityTerminalLookup::CloseOffered(_)) => Err(RetirementRefusal::NotReleased {
            source_id: item.source_id.clone(),
            state: "close offered",
        }),
        Ok(FinalityTerminalLookup::Retained) => Err(RetirementRefusal::NotReleased {
            source_id: item.source_id.clone(),
            state: "retained",
        }),
        Err(error) => Err(RetirementRefusal::CustodyUnverified {
            source_id: item.source_id.clone(),
            error: format!("{error:#}"),
        }),
    }
}

impl SourceRetirementPreparation {
    pub fn runtime(&self) -> &Arc<AuthenticatedSessionRuntime> {
        &self.scan.runtime
    }
    pub fn inventory(&self) -> &[RetirementItem] {
        &self.scan.items
    }
    pub fn inventory_digest(&self) -> &UInt256 {
        &self.scan.inventory_digest
    }
    pub fn manifest_digest(&self) -> &UInt256 {
        &self.scan.manifest_digest
    }
}

#[derive(Serialize)]
struct InventoryDigestInput {
    tag: &'static str,
    manifest: String,
    session: String,
    profile: String,
    /// (namespace-relative path, file hash) of every inventoried file.
    files: Vec<(String, String)>,
    items: Vec<(String, u64)>,
}

/// Exclusive, read-only scan of a drained source namespace. Call from a
/// blocking job after the session's storage instance was torn down; `teardown`
/// must observe that exact instance. Busy means another owner holds a lock.
pub fn scan_source_retirement(
    runtime: Arc<AuthenticatedSessionRuntime>,
    namespace: &Path,
    teardown: &StorageTeardownReceipt,
    budget: &dyn SourceHistoryDebtBudget,
) -> Refusal<PendingRetirementScan> {
    if runtime.protocol() != SimplexProtocol::PrivateObserversPlumtree {
        return Err(RetirementRefusal::Unsupported("protocol without runtime manifest"));
    }
    if runtime.recovery_binding().is_none() {
        return Err(RetirementRefusal::Unsupported("runtime without recovery binding"));
    }
    if !runtime.shard().is_masterchain() {
        return Err(RetirementRefusal::Unsupported("only masterchain Final reaches Released"));
    }
    // The receipt must observe this session's own storage at this namespace.
    // RocksDB admits one instance per directory, and an outcome exists only
    // after that instance's last reference is gone.
    if teardown.storage_id() != runtime.session_id().to_hex_string() || teardown.path() != namespace
    {
        return Err(RetirementRefusal::DatabaseTeardown(
            "receipt observes another storage instance".into(),
        ));
    }
    teardown.check().map_err(|e| RetirementRefusal::DatabaseTeardown(format!("{e:#}")))?;
    existing_directory(namespace)?;
    let mut charge = Charge::new(budget);
    let (manifest, manifest_digest) =
        crate::runtime_manifest::RuntimeManifest::open_existing(&runtime, namespace, &mut charge)?;
    let store = PendingFinalityStore::lock_existing(namespace.join(DIRECTORY))?;
    let delivered = store.retirement_delivered(&runtime, &mut charge)?;
    let sets = crate::finality_recovery::retirement_sealed_sets(namespace, &runtime, &mut charge)?;
    if sets.is_empty() && delivered.is_empty() {
        return Err(RetirementRefusal::EmptyInventory);
    }
    let files_count = sets
        .len()
        .checked_add(delivered.len())
        .ok_or_else(|| exhausted("inventory count overflow"))?;
    // Index keys, file list entries and digest input are bounded by the
    // strings they copy plus a fixed per-entry overhead.
    let mut inventory_bound = ENTRY_OVERHEAD;
    for path in sets.iter().map(|s| &s.path).chain(delivered.iter().map(|d| &d.path)) {
        inventory_bound = path
            .as_os_str()
            .len()
            .checked_add(ENTRY_OVERHEAD)
            .and_then(|entry| entry.checked_mul(2))
            .and_then(|entry| inventory_bound.checked_add(entry))
            .ok_or_else(|| exhausted("inventory workspace overflow"))?;
    }
    for record in &delivered {
        inventory_bound = record
            .block_id
            .len()
            .checked_add(record.source_validator.len())
            .and_then(|entry| entry.checked_add(ENTRY_OVERHEAD))
            .and_then(|entry| inventory_bound.checked_add(entry))
            .ok_or_else(|| exhausted("inventory workspace overflow"))?;
    }
    charge.workspace("inventory index and digest", inventory_bound)?;
    let mut index = std::collections::HashMap::new();
    for (position, record) in delivered.iter().enumerate() {
        let key = (record.block_id.clone(), record.is_final, record.source_validator.clone());
        if index.insert(key, position).is_some() {
            return Err(RetirementRefusal::DigestMismatch(
                record.path.clone(),
                "two Delivered records for one output".into(),
            ));
        }
    }
    let mut claimed = vec![false; delivered.len()];
    for set in &sets {
        for output in &set.outputs {
            if !output.1 {
                return Err(RetirementRefusal::Unsupported("Approval output cannot be released"));
            }
            let position = index.get(output).ok_or_else(|| {
                RetirementRefusal::MissingDelivered(format!(
                    "{} final={} source={} in {}",
                    output.0,
                    output.1,
                    output.2,
                    set.path.display()
                ))
            })?;
            if let Some(slot) = claimed.get_mut(*position) {
                *slot = true;
            }
        }
    }
    if let Some(position) = claimed.iter().position(|claimed| !claimed) {
        let path = delivered.get(position).map(|r| r.path.clone()).unwrap_or_default();
        return Err(RetirementRefusal::OrphanDelivered(path));
    }
    let relative = |path: &Path| -> Refusal<String> {
        path.strip_prefix(namespace)
            .map_err(failed)?
            .to_str()
            .map(str::to_owned)
            .ok_or_else(|| RetirementRefusal::UnknownArtifact(path.to_owned()))
    };
    let mut files = Vec::with_capacity(files_count);
    for set in &sets {
        files.push((relative(&set.path)?, set.file_hash.to_hex_string()));
    }
    for record in &delivered {
        files.push((relative(&record.path)?, record.file_hash.to_hex_string()));
    }
    files.sort();
    let mut items: Vec<RetirementItem> = delivered
        .into_iter()
        .map(|r| RetirementItem { source_id: r.source_id, offer: r.offer })
        .collect();
    items.sort_by(|a, b| a.source_id.as_slice().cmp(b.source_id.as_slice()));
    let input = InventoryDigestInput {
        tag: INVENTORY_TAG,
        manifest: manifest_digest.to_hex_string(),
        session: runtime.session_id().to_hex_string(),
        profile: runtime.profile().to_hex_string(),
        files,
        items: items.iter().map(|i| (i.source_id.to_hex_string(), i.offer.generation)).collect(),
    };
    let inventory_digest = UInt256::calc_file_hash(&serde_json::to_vec(&input).map_err(failed)?);
    Ok(PendingRetirementScan {
        runtime,
        manifest_digest,
        items,
        inventory_digest,
        _store: store,
        _manifest: manifest,
    })
}

#[cfg(test)]
#[path = "tests/test_source_retirement.rs"]
mod tests;
