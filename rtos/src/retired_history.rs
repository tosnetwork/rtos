// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded history evidence independent of ordinary state/archive GC.
//! Disk records are never authentication receipts. Every read repeats pinned
//! proof verification. Automatic reclamation requires source AND node-debt
//! ownership proofs and is deliberately not implemented here.
use crate::{
    block_proof::{BlockProofStuff, VerifiedMasterchainState},
    boot::authenticate_recovered_state_evidence,
    engine_traits::EngineOperations,
    shard_state::ShardStateStuff,
};
use consensus_common::session_runtime::AuthenticatedSessionRuntime;
use rtos_block::{error, fail, BlockIdExt, Result, UInt256};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};
use storage::bounded_cell::CellReadBudget;

/// Only bounded admission contention is retriable by the manager. Disk quota,
/// malformed evidence, failed authentication and ordinary IO errors are not.
#[derive(Debug, Clone, Copy)]
pub(crate) enum RetryableHistoryError {
    WriterBusy,
    IoCapacity,
    PreparationCapacity,
}
impl std::fmt::Display for RetryableHistoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::WriterBusy => "Retained history writer busy",
            Self::IoCapacity => "History IO capacity exhausted",
            Self::PreparationCapacity => "History preparation capacity exhausted",
        })
    }
}
impl std::error::Error for RetryableHistoryError {}

pub(crate) fn is_retryable(error: &anyhow::Error) -> bool {
    error.downcast_ref::<RetryableHistoryError>().is_some()
}

fn capacity_error(
    error: tokio::sync::TryAcquireError,
    busy: RetryableHistoryError,
) -> anyhow::Error {
    match error {
        tokio::sync::TryAcquireError::NoPermits => busy.into(),
        tokio::sync::TryAcquireError::Closed => error!("History admission closed"),
    }
}

const SCHEMA: u32 = 1;
static IO_JOBS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);
static PREPARATIONS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);

#[derive(Clone, Debug)]
pub(crate) struct Limits {
    pub total_bytes: u64,
    pub state_bytes: usize,
    pub proof_bytes: usize,
    pub anchors: usize,
    pub proofs_per_anchor: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            total_bytes: 512 << 20,
            state_bytes: 128 << 20,
            proof_bytes: 8 << 20,
            anchors: 128,
            proofs_per_anchor: 4096,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Domain {
    zero: String,
    init: String,
}
impl Domain {
    fn from_engine<E: EngineOperations + ?Sized>(engine: &E) -> Result<Self> {
        Ok(Self {
            zero: engine.zerostate_id()?.to_string(),
            init: engine.init_mc_block_id().to_string(),
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofRef {
    id: String,
    link: bool,
    blob: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: u32,
    domain: Domain,
    id: String,
    global_id: i32,
    state: String,
    proofs: Vec<ProofRef>,
}
struct Evidence {
    manifest_hash: UInt256,
    manifest: Manifest,
    state: Vec<u8>,
    proofs: Vec<BlockProofStuff>,
}
// Only successful pinned authentication creates this capability. It binds the
// exact bytes and complete file set that a later durability barrier must reread.
pub(crate) struct CapsuleDurabilityReceipt {
    manifest_hash: UInt256,
    manifest: Manifest,
}
struct Store {
    root: PathBuf,
    limits: Limits,
    _lock: File,
    #[cfg(test)]
    fail_manifest: bool,
}

fn charge_digest_work(length: usize, budget: &crate::history_read_budget::HistoryReadBudget) -> Result<()> {
    // SHA-256 input blocks plus padding; work is cumulative even on rejection.
    for _ in 0..length / 64 + 2 {
        budget.step()?;
    }
    Ok(())
}
fn bounded_digest(
    bytes: &[u8],
    budget: Option<&Arc<crate::history_read_budget::HistoryReadBudget>>,
) -> Result<UInt256> {
    if let Some(budget) = budget {
        charge_digest_work(bytes.len(), budget)?;
    }
    Ok(UInt256::calc_file_hash(bytes))
}
fn digest(bytes: &[u8]) -> String {
    UInt256::calc_file_hash(bytes).to_hex_string()
}
fn anchor_name(domain: &Domain, id: &BlockIdExt) -> String {
    digest(format!("{}\n{}\n{}", domain.zero, domain.init, id).as_bytes())
}
fn bounded_read(path: &Path, bound: usize) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    if file.metadata()?.len() > bound as u64 {
        fail!("Retained history file exceeds bound");
    }
    let mut bytes = Vec::new();
    (&mut file).take(bound as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > bound {
        fail!("Retained history file grew past bound");
    }
    Ok(bytes)
}
fn sync_ancestors(path: &Path) -> Result<()> {
    for directory in path.ancestors() {
        File::open(directory)?.sync_all()?;
    }
    Ok(())
}
impl Store {
    fn open(root: PathBuf, limits: Limits) -> Result<Self> {
        std::fs::create_dir_all(&root)?;
        sync_ancestors(&root)?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(root.join("owner.lock"))?;
        lock.try_lock().map_err(|e| match e {
            std::fs::TryLockError::WouldBlock => {
                anyhow::Error::from(RetryableHistoryError::WriterBusy)
            }
            std::fs::TryLockError::Error(error) => anyhow::Error::from(error),
        })?;
        Ok(Self {
            root,
            limits,
            _lock: lock,
            #[cfg(test)]
            fail_manifest: false,
        })
    }
    fn usage(&self) -> Result<(u64, usize)> {
        self.usage_budget(None)
    }
    fn usage_budget(
        &self,
        budget: Option<&Arc<crate::history_read_budget::HistoryReadBudget>>,
    ) -> Result<(u64, usize)> {
        use storage::bounded_cell::CellReadBudget;
        let mut bytes = 0u64;
        let mut anchors = 0usize;
        let mut files = 0usize;
        for entry in std::fs::read_dir(&self.root)? {
            if let Some(budget) = budget {
                budget.step()?;
                budget.metadata(512)?;
            }
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                fail!("Unexpected retained history directory entry");
            }
            bytes = bytes
                .checked_add(entry.metadata()?.len())
                .ok_or_else(|| error!("History quota overflow"))?;
            anchors += usize::from(entry.path().extension().is_some_and(|e| e == "json"));
            files += 1;
            if files > self.limits.anchors.saturating_mul(self.limits.proofs_per_anchor + 3) + 1
                || bytes > self.limits.total_bytes
                || anchors > self.limits.anchors
            {
                fail!("Retained history store exceeds quota");
            }
        }
        Ok((bytes, anchors))
    }
    fn sync_authenticated_capsule(
        &self,
        domain: &Domain,
        id: &BlockIdExt,
        receipt: &CapsuleDurabilityReceipt,
        budget: &Arc<crate::history_read_budget::HistoryReadBudget>,
    ) -> Result<()> {
        if receipt.manifest.domain != *domain || receipt.manifest.id != id.to_string() {
            fail!("Authenticated capsule receipt domain/identity mismatch");
        }
        self.usage_budget(Some(budget))?;
        let path = self.root.join(format!("{}.json", anchor_name(domain, id)));
        let (manifest_bytes, manifest_file) = self.budget_file_open(
            &path, 2 << 20, crate::history_read_budget::ReadKind::Metadata, budget,
        )?;
        if bounded_digest(&manifest_bytes, Some(budget))? != receipt.manifest_hash {
            fail!("Authenticated capsule manifest changed before durability barrier");
        }
        let mut total = 0usize;
        for (index, hash) in std::iter::once(&receipt.manifest.state)
            .chain(receipt.manifest.proofs.iter().map(|proof| &proof.blob)).enumerate()
        {
            let (bound, kind) = if index == 0 {
                (self.limits.state_bytes, crate::history_read_budget::ReadKind::State)
            } else {
                (self.limits.proof_bytes, crate::history_read_budget::ReadKind::Proof)
            };
            let (bytes, file) = self.budget_file_open(
                &self.root.join(format!("{hash}.blob")), bound, kind, budget,
            )?;
            total = total.checked_add(bytes.len()).ok_or_else(|| error!("Capsule size overflow"))?;
            if total as u64 > self.limits.total_bytes {
                fail!("Retained history evidence exceeds memory bound");
            }
            if bounded_digest(&bytes, Some(budget))?.to_hex_string() != *hash {
                fail!("Authenticated capsule blob changed before durability barrier");
            }
            budget.step()?;
            // Sync the descriptor whose bytes were checked, not a reopened path.
            file.sync_all()?;
        }
        budget.step()?;
        manifest_file.sync_all()?;
        budget.step()?;
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }
    fn blob(&self, hash: &str, bound: usize) -> Result<Vec<u8>> {
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            fail!("Invalid history blob reference");
        }
        let bytes = bounded_read(&self.root.join(format!("{hash}.blob")), bound)?;
        if digest(&bytes) != hash {
            fail!("Retained history blob checksum mismatch");
        }
        Ok(bytes)
    }
    fn budget_file(
        &self,
        path: &Path,
        bound: usize,
        kind: crate::history_read_budget::ReadKind,
        budget: &Arc<crate::history_read_budget::HistoryReadBudget>,
    ) -> Result<Vec<u8>> {
        self.budget_file_open(path, bound, kind, budget).map(|(bytes, _)| bytes)
    }
    fn budget_file_open(
        &self,
        path: &Path,
        bound: usize,
        kind: crate::history_read_budget::ReadKind,
        budget: &Arc<crate::history_read_budget::HistoryReadBudget>,
    ) -> Result<(Vec<u8>, File)> {
        use std::io::Read;
        budget.step()?;
        let file = File::open(path)?;
        let length = usize::try_from(file.metadata()?.len())?;
        if length > bound {
            return Err(
                crate::history_read_budget::HistoryBudgetExceeded("capsule file bytes").into()
            );
        }
        // The growth probe is real IO as well: reserve its potential byte
        // before read_exact/read, retaining that charge on any failure.
        let requested =
            length.checked_add(1).ok_or_else(|| error!("Capsule read length overflow"))?;
        let reservation = budget.reserve(kind, requested)?;
        let allowance = reservation.allowance();
        if requested > allowance {
            return Err(
                crate::history_read_budget::HistoryBudgetExceeded("capsule file bytes").into()
            );
        }
        // Exactly admitted buffer plus stack growth probe: read_to_end would
        // implicitly grow the allocation if the same file changed during IO.
        rtos_block::merkle_apply_budget::MerkleApplyBudget::workspace(budget.as_ref(), length)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length)?;
        bytes.resize(length, 0);
        let mut file = file;
        file.read_exact(&mut bytes)?;
        let mut extra = [0u8; 1];
        if file.read(&mut extra)? != 0 {
            return Err(
                crate::history_read_budget::HistoryBudgetExceeded("capsule file growth").into()
            );
        }
        if bytes.len() > allowance {
            return Err(
                crate::history_read_budget::HistoryBudgetExceeded("capsule file growth").into()
            );
        }
        if bytes.len() != length {
            fail!("Capsule file changed during read");
        }
        if matches!(kind, crate::history_read_budget::ReadKind::Proof) {
            // finish() hashes proof bytes for cumulative deduplication.
            charge_digest_work(bytes.len(), budget)?;
        }
        reservation.finish(&bytes)?;
        Ok((bytes, file))
    }
    fn blob_budget(
        &self,
        hash: &str,
        bound: usize,
        kind: crate::history_read_budget::ReadKind,
        budget: Option<&Arc<crate::history_read_budget::HistoryReadBudget>>,
    ) -> Result<Vec<u8>> {
        let Some(budget) = budget else {
            return self.blob(hash, bound);
        };
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            fail!("Invalid history blob reference");
        }
        let bytes =
            self.budget_file(&self.root.join(format!("{hash}.blob")), bound, kind, budget)?;
        if bounded_digest(&bytes, Some(budget))?.to_hex_string() != hash {
            fail!("History blob checksum mismatch");
        }
        Ok(bytes)
    }
    fn read(&self, domain: &Domain, id: &BlockIdExt) -> Result<Option<Evidence>> {
        self.read_budget(domain, id, None)
    }
    fn read_budget(
        &self,
        domain: &Domain,
        id: &BlockIdExt,
        budget: Option<&Arc<crate::history_read_budget::HistoryReadBudget>>,
    ) -> Result<Option<Evidence>> {
        self.usage_budget(budget)?;
        let path = self.root.join(format!("{}.json", anchor_name(domain, id)));
        if !path.try_exists()? {
            return Ok(None);
        }
        let bytes = match budget {
            Some(b) => {
                self.budget_file(&path, 2 << 20, crate::history_read_budget::ReadKind::Metadata, b)?
            }
            None => bounded_read(&path, 2 << 20)?,
        };
        let manifest_hash = bounded_digest(&bytes, budget)?;
        let manifest = Self::decode_manifest(&bytes, budget)?;
        if manifest.schema != SCHEMA
            || &manifest.domain != domain
            || manifest.id != id.to_string()
            || manifest.proofs.len() > self.limits.proofs_per_anchor
        {
            fail!("Retained history manifest domain/schema mismatch");
        }
        let state = self.blob_budget(
            &manifest.state,
            self.limits.state_bytes,
            crate::history_read_budget::ReadKind::State,
            budget,
        )?;
        let mut proofs: Vec<BlockProofStuff> = Vec::new();
        if let Some(budget) = budget {
            let bytes = manifest
                .proofs
                .len()
                .checked_mul(std::mem::size_of::<BlockProofStuff>())
                .ok_or_else(|| error!("History proof vector overflow"))?;
            rtos_block::merkle_apply_budget::MerkleApplyBudget::workspace(budget.as_ref(), bytes)?;
            proofs.try_reserve_exact(manifest.proofs.len())?;
        }
        let mut total = state.len() as u64;
        for proof in &manifest.proofs {
            let bytes = self.blob_budget(
                &proof.blob,
                self.limits.proof_bytes,
                crate::history_read_budget::ReadKind::Proof,
                budget,
            )?;
            total += bytes.len() as u64;
            if total > self.limits.total_bytes {
                fail!("Retained history evidence exceeds memory bound");
            }
            let id: BlockIdExt = proof.id.parse()?;
            for previous in &proofs {
                if let Some(budget) = budget {
                    budget.step()?;
                }
                if previous.id() == &id {
                    fail!("Duplicate retained proof identity");
                }
            }
            proofs.push(match budget {
                Some(b) => BlockProofStuff::deserialize_bounded(&id, bytes, proof.link, b)?,
                None => BlockProofStuff::deserialize(&id, bytes, proof.link)?,
            });
        }
        Ok(Some(Evidence { manifest_hash, manifest, state, proofs }))
    }
    /// Metadata lookup is bounded independently of proof/state authentication.
    /// Conflicting full identities at one height are never resolved by order.
    fn decode_manifest(
        bytes: &[u8],
        budget: Option<&Arc<crate::history_read_budget::HistoryReadBudget>>,
    ) -> Result<Manifest> {
        if let Some(budget) = budget {
            // Each JSON object requires at least two input bytes. Cover
            // geometric vector growth and string buffers before serde allocates.
            let workspace = bytes
                .len()
                .checked_mul(2 * std::mem::size_of::<ProofRef>() + 8)
                .and_then(|n| n.checked_add(4096))
                .ok_or_else(|| error!("History manifest workspace overflow"))?;
            rtos_block::merkle_apply_budget::MerkleApplyBudget::workspace(
                budget.as_ref(),
                workspace,
            )?;
        }
        let manifest: Manifest = serde_json::from_slice(bytes)?;
        Ok(manifest)
    }
    fn manifests(&self, domain: &Domain) -> Result<Vec<Manifest>> {
        self.manifests_budget(domain, None)
    }
    fn manifests_budget(
        &self,
        domain: &Domain,
        budget: Option<&Arc<crate::history_read_budget::HistoryReadBudget>>,
    ) -> Result<Vec<Manifest>> {
        use storage::bounded_cell::CellReadBudget;
        self.usage_budget(budget)?;
        let mut result = Vec::new();
        let mut identities = std::collections::BTreeMap::new();
        let mut read_bytes = 0usize;
        for entry in std::fs::read_dir(&self.root)? {
            if let Some(budget) = budget {
                budget.step()?;
                budget.metadata(512)?;
            }
            let entry = entry?;
            if entry.path().extension().is_none_or(|e| e != "json") {
                continue;
            }
            let bytes = match budget {
                Some(b) => {
                    b.step()?;
                    self.budget_file(
                        &entry.path(),
                        2 << 20,
                        crate::history_read_budget::ReadKind::Metadata,
                        b,
                    )?
                }
                None => bounded_read(&entry.path(), 2 << 20)?,
            };
            read_bytes = read_bytes
                .checked_add(bytes.len())
                .ok_or_else(|| error!("History metadata budget overflow"))?;
            if read_bytes > 16 << 20 {
                fail!("History metadata lookup exceeds budget");
            }
            let manifest = Self::decode_manifest(&bytes, budget)?;
            if &manifest.domain != domain {
                continue;
            }
            let id: BlockIdExt = manifest.id.parse()?;
            if manifest.schema != SCHEMA
                || !id.shard().is_masterchain_ext()
                || manifest.proofs.len() > self.limits.proofs_per_anchor
                || entry.file_name()
                    != std::ffi::OsString::from(format!("{}.json", anchor_name(domain, &id)))
            {
                fail!("Invalid retained history lookup manifest");
            }
            for id in std::iter::once(Ok(id))
                .chain(manifest.proofs.iter().map(|p| p.id.parse::<BlockIdExt>()))
            {
                if let Some(budget) = budget {
                    budget.step()?;
                    rtos_block::merkle_apply_budget::MerkleApplyBudget::workspace(
                        budget.as_ref(),
                        1024,
                    )?;
                }
                let id = id?;
                if !id.shard().is_masterchain_ext() {
                    fail!("Non-masterchain retained history proof");
                }
                if let Some(previous) = identities.insert(id.seq_no, id.clone()) {
                    if previous != id {
                        fail!("Conflicting retained history identities at height {}", id.seq_no);
                    }
                }
            }
            if let Some(budget) = budget {
                rtos_block::merkle_apply_budget::MerkleApplyBudget::workspace(
                    budget.as_ref(),
                    std::mem::size_of::<Manifest>(),
                )?;
                result.try_reserve_exact(1)?;
            }
            result.push(manifest);
        }
        Ok(result)
    }

    fn find_proof(
        &self,
        domain: &Domain,
        id: &BlockIdExt,
        allow_link: bool,
    ) -> Result<Option<BlockProofStuff>> {
        self.find_proof_budget(domain, id, allow_link, None)
    }
    fn find_proof_budget(
        &self,
        domain: &Domain,
        id: &BlockIdExt,
        allow_link: bool,
        budget: Option<&Arc<crate::history_read_budget::HistoryReadBudget>>,
    ) -> Result<Option<BlockProofStuff>> {
        let manifests = self.manifests_budget(domain, budget)?;
        if let Some(budget) = budget {
            budget.metadata(256)?;
        }
        let identity = id.to_string();
        let mut found: Option<&ProofRef> = None;
        for proof in manifests.iter().flat_map(|m| &m.proofs) {
            if let Some(budget) = budget {
                budget.step()?;
            }
            if proof.id != identity || (proof.link && !allow_link) {
                continue;
            }
            if let Some(previous) = found {
                if previous.link == proof.link && previous.blob != proof.blob {
                    fail!("Conflicting retained proof bytes");
                }
                if !previous.link {
                    continue;
                }
            }
            found = Some(proof);
        }
        found
            .map(|p| {
                let bytes = self.blob_budget(
                    &p.blob,
                    self.limits.proof_bytes,
                    crate::history_read_budget::ReadKind::Proof,
                    budget,
                )?;
                match budget {
                    Some(b) => BlockProofStuff::deserialize_bounded(id, bytes, p.link, b),
                    None => BlockProofStuff::deserialize(id, bytes, p.link),
                }
            })
            .transpose()
    }

    fn atomic_write(&self, name: &str, bytes: &[u8]) -> Result<()> {
        #[cfg(test)]
        if self.fail_manifest && name.ends_with(".json") {
            return Err(std::io::Error::from_raw_os_error(5).into());
        }
        let path = self.root.join(name);
        let tmp = self.root.join(format!("{name}.tmp"));
        let mut file = OpenOptions::new().write(true).create(true).truncate(true).open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(tmp, path)?;
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }
    fn commit(
        &self,
        domain: Domain,
        id: BlockIdExt,
        global_id: i32,
        state: Vec<u8>,
        proofs: Vec<BlockProofStuff>,
    ) -> Result<()> {
        self.commit_budget(domain, id, global_id, state, proofs, None)
    }
    fn commit_budget(
        &self,
        domain: Domain,
        id: BlockIdExt,
        global_id: i32,
        state: Vec<u8>,
        proofs: Vec<BlockProofStuff>,
        budget: Option<&Arc<crate::history_read_budget::HistoryReadBudget>>,
    ) -> Result<()> {
        use storage::bounded_cell::CellReadBudget;
        if state.len() > self.limits.state_bytes || proofs.len() > self.limits.proofs_per_anchor {
            fail!("History evidence exceeds bound");
        }
        if let Some(existing) = self.read_budget(&domain, &id, budget)? {
            if existing.state != state || existing.manifest.global_id != global_id {
                fail!("Conflicting retained history state");
            }
            // Previous atomic commit might have returned a directory-sync error.
            // Repeat file and directory barriers before acknowledging a retry.
            File::open(self.root.join(format!("{}.json", anchor_name(&domain, &id))))?
                .sync_all()?;
            File::open(&self.root)?.sync_all()?;
            return Ok(());
        }
        let (used, anchors) = self.usage_budget(budget)?;
        if anchors >= self.limits.anchors {
            fail!("Retained history anchor quota exhausted");
        }
        let mut blobs = std::collections::BTreeMap::new();
        if let Some(budget) = budget {
            budget.metadata(4096)?;
        }
        let state_hash = digest(&state);
        blobs.insert(state_hash.clone(), state);
        let mut references = Vec::new();
        for proof in proofs {
            if let Some(budget) = budget {
                budget.step()?;
                budget.metadata(4096)?;
                rtos_block::merkle_apply_budget::MerkleApplyBudget::workspace(
                    budget.as_ref(),
                    proof.data().len(),
                )?;
            }
            if proof.data().len() > self.limits.proof_bytes {
                fail!("History proof exceeds bound");
            }
            let hash = digest(proof.data());
            references.push(ProofRef {
                id: proof.id().to_string(),
                link: proof.is_link(),
                blob: hash.clone(),
            });
            blobs.insert(hash, proof.data().to_vec());
        }
        let manifest = Manifest {
            schema: SCHEMA,
            domain: domain.clone(),
            id: id.to_string(),
            global_id,
            state: state_hash,
            proofs: references,
        };
        let encoded = if let Some(budget) = budget {
            let mut writer =
                crate::historical_recovery::BudgetedBytes::new(2 << 20, budget.clone());
            serde_json::to_writer(&mut writer, &manifest)?;
            writer.finish()
        } else {
            serde_json::to_vec(&manifest)?
        };
        if encoded.len() > 2 << 20 {
            fail!("History manifest exceeds bound");
        }
        let mut extra = encoded.len() as u64;
        for (hash, bytes) in &blobs {
            let path = self.root.join(format!("{hash}.blob"));
            if path.try_exists()? {
                let existing = match budget {
                    Some(budget) => self.budget_file(
                        &path,
                        bytes.len(),
                        crate::history_read_budget::ReadKind::State,
                        budget,
                    )?,
                    None => bounded_read(&path, bytes.len())?,
                };
                if existing != *bytes {
                    fail!("Existing history blob conflicts");
                }
            } else {
                extra = extra
                    .checked_add(bytes.len() as u64)
                    .ok_or_else(|| error!("History quota overflow"))?;
            }
        }
        if used.checked_add(extra).is_none_or(|n| n > self.limits.total_bytes) {
            fail!("Retained history byte quota exhausted");
        }
        for (hash, bytes) in blobs {
            let name = format!("{hash}.blob");
            if !self.root.join(&name).try_exists()? {
                self.atomic_write(&name, &bytes)?;
            } else {
                File::open(self.root.join(name))?.sync_all()?;
            }
        }
        self.atomic_write(&format!("{}.json", anchor_name(&domain, &id)), &encoded)
    }
}

async fn owned_io<E: EngineOperations + ?Sized, T: Send + 'static>(
    engine: &E,
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    let permit =
        IO_JOBS.try_acquire().map_err(|e| capacity_error(e, RetryableHistoryError::IoCapacity))?;
    let (sent, received) = tokio::sync::oneshot::channel();
    // Register the actual worker before exposing a cancelable observation.
    let completion = engine.register_service_task(
        "retired history IO",
        0,
        Box::new(move || {
            tokio::spawn(async move {
                let _permit = permit;
                let result = tokio::task::spawn_blocking(work)
                    .await
                    .map_err(|e| error!("Retired history IO join: {e}"))
                    .and_then(|result| result);
                let _ = sent.send(result);
            })
        }),
    )?;
    completion.await.map_err(|e| error!("Retired history owner join: {e}"))?;
    received.await.map_err(|e| error!("Retired history result lost: {e}"))?
}

fn root<E: EngineOperations + ?Sized>(engine: &E) -> Result<PathBuf> {
    Ok(PathBuf::from(engine.db_root_dir()?).join("retired-history-v1"))
}

/// Read-only with respect to acceptance/publication. Missing private evidence
/// retains the old explicit load/defer behavior; corrupt evidence is not ignored.
pub(crate) async fn authenticate_state<E: EngineOperations + ?Sized>(
    engine: &E,
    id: &BlockIdExt,
) -> Result<VerifiedMasterchainState> {
    authenticate_state_with_budget(engine, id, None).await
}
pub(crate) async fn authenticate_state_with_budget<E: EngineOperations + ?Sized>(
    engine: &E,
    id: &BlockIdExt,
    budget: Option<&Arc<crate::history_read_budget::HistoryReadBudget>>,
) -> Result<VerifiedMasterchainState> {
    if let Some(state) = authenticate_capsule_with_budget(engine, id, budget).await? {
        return Ok(state);
    }
    authenticate_ordinary_with_budget(engine, id, budget).await
}

pub(crate) async fn authenticate_capsule_with_budget<E: EngineOperations + ?Sized>(
    engine: &E,
    id: &BlockIdExt,
    budget: Option<&Arc<crate::history_read_budget::HistoryReadBudget>>,
) -> Result<Option<VerifiedMasterchainState>> {
    Ok(authenticate_capsule_for_request(engine, id, budget).await?.map(|(state, _)| state))
}

pub(crate) async fn authenticate_capsule_for_request<E: EngineOperations + ?Sized>(
    engine: &E,
    id: &BlockIdExt,
    budget: Option<&Arc<crate::history_read_budget::HistoryReadBudget>>,
) -> Result<Option<(VerifiedMasterchainState, CapsuleDurabilityReceipt)>> {
    let path = root(engine)?;
    if !path.try_exists()? {
        return Ok(None);
    }
    let domain = Domain::from_engine(engine)?;
    let expected = id.clone();
    let read_budget = budget.cloned();
    let evidence = owned_io(engine, move || {
        Store::open(path, Limits::default())?.read_budget(&domain, &expected, read_budget.as_ref())
    })
    .await?;
    let Some(evidence) = evidence else {
        return Ok(None);
    };
    let state = ShardStateStuff::from_root_cell(
        id.clone(),
        match budget {
            Some(b) => b.parse_boc(&evidence.state)?,
            None => rtos_block::read_single_root_boc(&evidence.state)?,
        },
        #[cfg(feature = "telemetry")]
        engine.engine_telemetry(),
        engine.engine_allocated(),
    )?;
    let verified = crate::boot::authenticate_recovered_state_evidence_with_budget(
        engine,
        id,
        state,
        Some(&evidence.proofs),
        None,
        budget,
    )
    .await?;
    if let Some(budget) = budget {
        budget.record_bytes(
            "capsule-state",
            id,
            &evidence.state,
            Some(verified.state().root_cell().repr_hash()),
        )?;
    }
    if verified.state().state()?.global_id() != evidence.manifest.global_id {
        fail!("History global ID mismatch");
    }
    Ok(Some((verified, CapsuleDurabilityReceipt {
        manifest_hash: evidence.manifest_hash,
        manifest: evidence.manifest,
    })))
}

/// Raw evidence only: callers must verify through BootstrapAuthority.
pub(crate) async fn load_proof<E: EngineOperations + ?Sized>(
    engine: &E,
    id: &BlockIdExt,
    allow_link: bool,
) -> Result<Option<BlockProofStuff>> {
    load_proof_with_budget(engine, id, allow_link, None).await
}
pub(crate) async fn load_proof_with_budget<E: EngineOperations + ?Sized>(
    engine: &E,
    id: &BlockIdExt,
    allow_link: bool,
    budget: Option<&Arc<crate::history_read_budget::HistoryReadBudget>>,
) -> Result<Option<BlockProofStuff>> {
    let path = root(engine)?;
    if !path.try_exists()? {
        return Ok(None);
    }
    let domain = Domain::from_engine(engine)?;
    let id = id.clone();
    let read_budget = budget.cloned();
    owned_io(engine, move || {
        Store::open(path, Limits::default())?.find_proof_budget(
            &domain,
            &id,
            allow_link,
            read_budget.as_ref(),
        )
    })
    .await
}

// Preserve stable minimum-sequence selection without allocating a second
// ID vector or sorting outside the request budget.
fn select_hint(
    manifests: Vec<Manifest>,
    epoch: u32,
    budget: Option<&Arc<crate::history_read_budget::HistoryReadBudget>>,
) -> Result<Option<BlockIdExt>> {
    let mut selected: Option<BlockIdExt> = None;
    for manifest in manifests {
        if let Some(budget) = budget {
            budget.step()?;
        }
        let id: BlockIdExt = manifest.id.parse()?;
        if id.seq_no >= epoch
            && selected.as_ref().is_none_or(|previous| id.seq_no < previous.seq_no)
        {
            selected = Some(id);
        }
    }
    Ok(selected)
}

/// Authenticate one selected retained anchor before using its history index.
pub(crate) async fn lookup_hint<E: EngineOperations + ?Sized>(
    engine: &E,
    epoch: u32,
) -> Result<Option<Arc<ShardStateStuff>>> {
    lookup_hint_with_budget(engine, epoch, None).await
}
pub(crate) async fn lookup_hint_with_budget<E: EngineOperations + ?Sized>(
    engine: &E,
    epoch: u32,
    budget: Option<&Arc<crate::history_read_budget::HistoryReadBudget>>,
) -> Result<Option<Arc<ShardStateStuff>>> {
    let path = root(engine)?;
    if !path.try_exists()? {
        return Ok(None);
    }
    let domain = Domain::from_engine(engine)?;
    let read_budget = budget.cloned();
    let selected = owned_io(engine, move || {
        let store = Store::open(path, Limits::default())?;
        select_hint(
            store.manifests_budget(&domain, read_budget.as_ref())?,
            epoch,
            read_budget.as_ref(),
        )
    })
    .await?;
    let Some(id) = selected else {
        return Ok(None);
    };
    let verified = authenticate_state_with_budget(engine, &id, budget).await?;
    if let Some(budget) = budget {
        rtos_block::config_read_budget::lookup(
            &crate::bounded_session_derivation::ConfigBudget(budget.as_ref()),
            32,
        )?;
    }
    verified.state().find_block_id(epoch)?;
    Ok(Some(verified.state().clone()))
}

pub(crate) async fn authenticate_ordinary_with_budget<E: EngineOperations + ?Sized>(
    engine: &E,
    id: &BlockIdExt,
    budget: Option<&Arc<crate::history_read_budget::HistoryReadBudget>>,
) -> Result<VerifiedMasterchainState> {
    let Some(budget) = budget else {
        return crate::boot::authenticate_recovered_state(engine, id).await;
    };
    if !id.shard().is_masterchain_ext() || id.seq_no < engine.init_mc_block_id().seq_no {
        fail!("Bounded recovery outside pinned history");
    }
    let state = engine.load_state_bounded(id, budget.clone()).await?;
    crate::boot::authenticate_recovered_state_evidence_with_budget(
        engine,
        id,
        state,
        None,
        None,
        Some(budget),
    )
    .await
}

/// Live authenticated admission only. Two concurrent preparations bound working
/// memory; independent file locking serializes every quota/commit transaction.
pub(crate) async fn prepare(
    engine: Arc<dyn EngineOperations>,
    runtime: Arc<AuthenticatedSessionRuntime>,
    start: BlockIdExt,
) -> Result<()> {
    let permit = PREPARATIONS
        .try_acquire()
        .map_err(|e| capacity_error(e, RetryableHistoryError::PreparationCapacity))?;
    let task_engine = engine.clone();
    crate::types::service_tasks::spawn_owned(
        engine.as_ref(),
        "retired history preparation",
        async move {
            let _permit = permit;
            prepare_inner(task_engine, runtime, start).await
        },
    )?
    .await
    .map_err(|e| error!("History preparation owner join: {e}"))?
}
async fn prepare_inner(
    engine: Arc<dyn EngineOperations>,
    runtime: Arc<AuthenticatedSessionRuntime>,
    start: BlockIdExt,
) -> Result<()> {
    if runtime.protocol()
        != consensus_common::simplex_protocol::SimplexProtocol::PrivateObserversPlumtree
        || runtime.wire_profile() != engine.validator_network().wire_profile()
    {
        fail!("History runtime protocol/wire mismatch");
    }
    if runtime.pin().zerostate != *engine.zerostate_id()? {
        fail!("History runtime network mismatch");
    }
    let governing = runtime
        .recovery_binding()
        .ok_or_else(|| error!("Missing runtime history binding"))?
        .governing_masterchain
        .clone();
    for id in [governing.clone(), start.clone()] {
        let path = root(engine.as_ref())?;
        let domain = Domain::from_engine(engine.as_ref())?;
        let expected = id.clone();
        let check_domain = domain.clone();
        let check_path = path.clone();
        let exists = owned_io(engine.as_ref(), move || {
            Store::open(check_path, Limits::default())?.read(&check_domain, &expected)
        })
        .await?;
        if exists.is_some() {
            drop(exists);
            let verified = authenticate_state(engine.as_ref(), &id).await?;
            if verified.state().state()?.global_id() != runtime.pin().global_id {
                fail!("History runtime global mismatch");
            }
            continue;
        }
        let guard = engine.load_and_pin_state(&id).await?;
        let state = engine.load_state(&id).await?;
        let mut proofs = Vec::new();
        let verified = authenticate_recovered_state_evidence(
            engine.as_ref(),
            &id,
            state.clone(),
            None,
            Some(&mut proofs),
        )
        .await?;
        if verified.state().state()?.global_id() != runtime.pin().global_id {
            fail!("History runtime global mismatch");
        }
        let global = runtime.pin().global_id;
        owned_io(engine.as_ref(), move || {
            let _guard = guard;
            let mut bounded =
                BoundedWriter { bytes: Vec::new(), limit: Limits::default().state_bytes };
            state.write_to(&mut bounded)?;
            Store::open(path, Limits::default())?.commit(domain, id, global, bounded.bytes, proofs)
        })
        .await?;
    }
    let start_state = authenticate_state(engine.as_ref(), &start).await?;
    if start != governing && !start_state.state().has_prev_block(&governing)? {
        fail!("History start does not descend from governing anchor");
    }
    Ok(())
}
struct BoundedWriter {
    bytes: Vec<u8>,
    limit: usize,
}
impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("History state exceeds bound"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn identity(n: u8) -> BlockIdExt {
        BlockIdExt::with_params(
            rtos_block::ShardIdent::masterchain(),
            u32::from(n),
            UInt256::from([n; 32]),
            UInt256::from([n + 1; 32]),
        )
    }
    fn domain() -> Domain {
        Domain { zero: identity(0).to_string(), init: identity(0).to_string() }
    }

    #[test]
    fn retired_history_retry_classification_preserves_real_contention() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().to_owned(), Limits::default()).unwrap();
        let busy = Store::open(dir.path().to_owned(), Limits::default()).err().unwrap();
        assert!(is_retryable(&busy.context("preparing current session")));
        drop(store);
        drop(Store::open(dir.path().to_owned(), Limits::default()).unwrap());

        let file = dir.path().join("not-a-directory");
        std::fs::write(&file, b"occupied").unwrap();
        let io_error = Store::open(file, Limits::default()).err().unwrap();
        assert!(!is_retryable(&io_error));

        for kind in [RetryableHistoryError::IoCapacity, RetryableHistoryError::PreparationCapacity]
        {
            let semaphore = tokio::sync::Semaphore::new(1);
            let permit = semaphore.try_acquire().unwrap();
            assert!(is_retryable(&capacity_error(semaphore.try_acquire().unwrap_err(), kind)));
            drop(permit);
            assert!(semaphore.try_acquire().is_ok());
            semaphore.close();
            assert!(!is_retryable(&capacity_error(semaphore.try_acquire().unwrap_err(), kind)));
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn retired_history_root_io_error_is_not_missing_evidence() {
        struct PathOnlyEngine(String);
        #[async_trait::async_trait]
        impl EngineOperations for PathOnlyEngine {
            fn db_root_dir(&self) -> Result<&str> {
                Ok(&self.0)
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let engine = PathOnlyEngine(dir.path().to_str().unwrap().to_owned());
        let path = dir.path().join("retired-history-v1");
        let budget = crate::history_read_budget::HistoryReadBudget::new(Default::default());
        // Truly absent evidence remains a lookup miss, before domain or IO jobs.
        for budget in [None, Some(&budget)] {
            assert!(authenticate_capsule_with_budget(&engine, &identity(1), budget)
                .await
                .unwrap()
                .is_none());
            assert!(load_proof_with_budget(&engine, &identity(1), false, budget)
                .await
                .unwrap()
                .is_none());
            assert!(lookup_hint_with_budget(&engine, 1, budget).await.unwrap().is_none());
        }
        // A real ELOOP used to be swallowed by Path::exists. None of these
        // entry points may report absence and allow a remote fallback instead.
        std::os::unix::fs::symlink("retired-history-v1", &path).unwrap();
        let expected = std::fs::metadata(&path).unwrap_err().raw_os_error().unwrap();
        for budget in [None, Some(&budget)] {
            let errors = [
                authenticate_capsule_with_budget(&engine, &identity(1), budget).await.err(),
                load_proof_with_budget(&engine, &identity(1), false, budget).await.err(),
                lookup_hint_with_budget(&engine, 1, budget).await.err(),
            ];
            for error in errors {
                let error = error.expect("root IO error must not become missing evidence");
                assert_eq!(
                    error.downcast_ref::<std::io::Error>().and_then(|e| e.raw_os_error()),
                    Some(expected)
                );
            }
        }
        assert_eq!(std::fs::read_link(&path).unwrap(), PathBuf::from("retired-history-v1"));
    }

    #[test]
    fn retired_history_hint_selection_charges_each_candidate_cumulatively() {
        use crate::history_read_budget::{
            HistoryBudgetExceeded, HistoryReadBudget, HistoryReadLimits,
        };
        let manifests = || {
            [9, 3, 7]
                .into_iter()
                .map(|seq| Manifest {
                    schema: SCHEMA,
                    domain: domain(),
                    id: identity(seq).to_string(),
                    global_id: -239,
                    state: String::new(),
                    proofs: vec![],
                })
                .collect()
        };
        assert_eq!(select_hint(manifests(), 4, None).unwrap(), Some(identity(7)));
        let budget = HistoryReadBudget::new(HistoryReadLimits { steps: 3, ..Default::default() });
        assert_eq!(select_hint(manifests(), 4, Some(&budget)).unwrap(), Some(identity(7)));
        assert!(select_hint(manifests(), 4, Some(&budget))
            .unwrap_err()
            .downcast_ref::<HistoryBudgetExceeded>()
            .is_some());
        assert!(select_hint(manifests(), 10, None).unwrap().is_none());
    }

    #[test]
    fn retired_history_default_anchor_quota_rejects_129_and_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().to_owned(), Limits::default()).unwrap();
        assert_eq!(store.limits.anchors, 128);
        for seq in 1..=128 {
            store.commit(domain(), identity(seq), -239, vec![1, 2, 3], vec![]).unwrap();
        }
        let before = store.usage().unwrap();
        assert_eq!(before.1, 128);
        let error = store.commit(domain(), identity(129), -239, vec![4, 5, 6], vec![]).unwrap_err();
        assert!(error.to_string().contains("anchor quota"));
        assert_eq!(store.usage().unwrap(), before);
        drop(store);
        let reopened = Store::open(dir.path().to_owned(), Limits::default()).unwrap();
        assert_eq!(reopened.usage().unwrap(), before);
        assert!(reopened.commit(domain(), identity(129), -239, vec![4, 5, 6], vec![]).is_err());
        // Existing identical debt remains idempotent even at the full bound.
        reopened.commit(domain(), identity(1), -239, vec![1, 2, 3], vec![]).unwrap();
        assert_eq!(reopened.usage().unwrap(), before);
        for seq in 1..=128 {
            assert_eq!(
                reopened.read(&domain(), &identity(seq)).unwrap().unwrap().state,
                vec![1, 2, 3]
            );
        }
    }

    #[test]
    fn retired_history_store_reopen_dedup_and_bound() {
        let dir = tempfile::tempdir().unwrap();
        let limits = Limits { anchors: 2, ..Limits::default() };
        let store = Store::open(dir.path().to_owned(), limits.clone()).unwrap();
        store.commit(domain(), identity(1), -239, vec![1, 2, 3], vec![]).unwrap();
        let usage = store.usage().unwrap();
        store.commit(domain(), identity(1), -239, vec![1, 2, 3], vec![]).unwrap();
        assert_eq!(store.usage().unwrap(), usage);
        store.commit(domain(), identity(2), -239, vec![1, 2, 3], vec![]).unwrap();
        assert_eq!(
            std::fs::read_dir(dir.path())
                .unwrap()
                .filter(|p| p.as_ref().unwrap().path().extension().is_some_and(|e| e == "blob"))
                .count(),
            1
        );
        assert!(store.commit(domain(), identity(3), -239, vec![1, 2, 3], vec![]).is_err());
        drop(store);
        let reopened = Store::open(dir.path().to_owned(), limits).unwrap();
        assert_eq!(reopened.read(&domain(), &identity(1)).unwrap().unwrap().state, vec![1, 2, 3]);
        let wrong = Domain { init: identity(7).to_string(), ..domain() };
        assert!(reopened.read(&wrong, &identity(1)).unwrap().is_none());
    }

    #[test]
    fn retired_history_capsule_reader_charges_directory_and_workspace_before_decode() {
        use crate::history_read_budget::{
            HistoryBudgetExceeded, HistoryReadBudget, HistoryReadLimits,
        };
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().to_owned(), Limits::default()).unwrap();
        store.commit(domain(), identity(1), -239, vec![7; 32], vec![]).unwrap();
        let manifest_path =
            dir.path().join(format!("{}.json", anchor_name(&domain(), &identity(1))));
        let before = std::fs::read(&manifest_path).unwrap();
        for dimension in 0..3 {
            let mut limits = HistoryReadLimits::default();
            match dimension {
                0 => limits.steps = 0,
                1 => limits.metadata_bytes = 0,
                _ => limits.cell_bytes = 0,
            }
            let budget = HistoryReadBudget::new(limits);
            let error = store.read_budget(&domain(), &identity(1), Some(&budget)).err().unwrap();
            assert!(error.downcast_ref::<HistoryBudgetExceeded>().is_some(), "{error:#}");
            assert!(store.manifests_budget(&domain(), Some(&budget)).is_err());
            assert_eq!(std::fs::read(&manifest_path).unwrap(), before);
        }
        let budget = HistoryReadBudget::new(HistoryReadLimits::default());
        assert_eq!(
            store.read_budget(&domain(), &identity(1), Some(&budget)).unwrap().unwrap().state,
            vec![7; 32]
        );
    }

    #[test]
    fn retired_history_failed_manifest_never_commits_and_retry_reuses_blobs() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path().to_owned(), Limits::default()).unwrap();
        assert!(
            Store::open(dir.path().to_owned(), Limits::default()).is_err(),
            "second writer admitted"
        );
        store.fail_manifest = true;
        assert!(store.commit(domain(), identity(1), -239, vec![4; 32], vec![]).is_err());
        assert!(store.read(&domain(), &identity(1)).unwrap().is_none());
        drop(store);
        let store = Store::open(dir.path().to_owned(), Limits::default()).unwrap();
        store.commit(domain(), identity(1), -239, vec![4; 32], vec![]).unwrap();
        assert!(store.read(&domain(), &identity(1)).unwrap().is_some());
        let blob = store.root.join(format!("{}.blob", digest(&[4; 32])));
        std::fs::write(blob, [5; 32]).unwrap();
        assert!(store.read(&domain(), &identity(1)).is_err());
    }

    #[test]
    fn retired_history_rejects_truncation_schema_and_byte_quota() {
        let dir = tempfile::tempdir().unwrap();
        let tiny =
            Store::open(dir.path().to_owned(), Limits { total_bytes: 10, ..Limits::default() })
                .unwrap();
        let quota = tiny.commit(domain(), identity(1), -239, vec![0; 11], vec![]).unwrap_err();
        assert!(!is_retryable(&quota));
        assert!(tiny.read(&domain(), &identity(1)).unwrap().is_none());
        drop(tiny);
        let store = Store::open(dir.path().to_owned(), Limits::default()).unwrap();
        store.commit(domain(), identity(1), -239, vec![0], vec![]).unwrap();
        let path = store.root.join(format!("{}.json", anchor_name(&domain(), &identity(1))));
        let mut m: Manifest = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        m.schema = 99;
        std::fs::write(&path, serde_json::to_vec(&m).unwrap()).unwrap();
        assert!(store.read(&domain(), &identity(1)).is_err());
        std::fs::write(&path, b"{").unwrap();
        let malformed = store.read(&domain(), &identity(1)).err().unwrap();
        assert!(!is_retryable(&malformed));
    }
}

#[cfg(test)]
#[path = "tests/test_retained_publication_history.rs"]
mod publication_tests;

/// Repeat real barriers for the exact already authenticated capsule dependency.
/// Store admission holds its file lock; there is currently no capsule collector
/// or same-ID replacement path. A future collector must consume repair leases.
pub(crate) async fn sync_repair_capsule<E: EngineOperations + ?Sized>(
    engine: &E,
    id: &BlockIdExt,
    expected_digest: &str,
    expected_bytes: u64,
    budget: &Arc<crate::history_read_budget::HistoryReadBudget>,
) -> Result<()> {
    let path = root(engine)?;
    let domain = Domain::from_engine(engine)?;
    let id = id.clone();
    let expected_digest = expected_digest.to_owned();
    let budget = budget.clone();
    owned_io(engine, move || {
        let store = Store::open(path, Limits::default())?;
        let evidence = store
            .read_budget(&domain, &id, Some(&budget))?
            .ok_or_else(|| error!("Repair capsule disappeared"))?;
        if evidence.state.len() as u64 != expected_bytes
            || format!("{:x}", UInt256::calc_file_hash(&evidence.state)) != expected_digest
        {
            fail!("Repair capsule state changed");
        }
        File::open(store.root.join(format!("{}.json", anchor_name(&domain, &id))))?.sync_all()?;
        File::open(store.root.join(format!("{}.blob", evidence.manifest.state)))?.sync_all()?;
        for proof in &evidence.manifest.proofs {
            File::open(store.root.join(format!("{}.blob", proof.blob)))?.sync_all()?;
        }
        File::open(&store.root)?.sync_all()?;
        Ok(())
    })
    .await
}

// Test-only quota injection is scoped to one database path and only the
// actual recovered-capsule commit. Readers still validate production limits.
#[cfg(test)]
static RECOVERED_LIMITS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<PathBuf, Limits>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));
#[cfg(test)]
pub(crate) struct RecoveredLimitsGuard(PathBuf);
#[cfg(test)]
impl Drop for RecoveredLimitsGuard {
    fn drop(&mut self) {
        RECOVERED_LIMITS.lock().unwrap().remove(&self.0);
    }
}
#[cfg(test)]
pub(crate) fn test_recovered_capsule_limits(
    db_root: &Path,
    limits: Limits,
) -> RecoveredLimitsGuard {
    let root = db_root.join("retired-history-v1");
    let mut configured = RECOVERED_LIMITS.lock().unwrap();
    assert!(!configured.contains_key(&root), "quota override already installed for database");
    configured.insert(root.clone(), limits);
    RecoveredLimitsGuard(root)
}
fn recovered_commit_limits(root: &Path) -> Limits {
    #[cfg(test)]
    if let Some(limits) = RECOVERED_LIMITS.lock().unwrap().get(root).cloned() {
        return limits;
    }
    let _ = root;
    Limits::default()
}

/// Narrow durable admission: a verified state alone cannot call this writer.
/// The capability retains actual source certificate ownership across this IO.
pub(crate) fn commit_recovered_capsule(
    engine: &dyn EngineOperations,
    admission: &crate::historical_recovery::DurableHistoryAdmission,
    state: &VerifiedMasterchainState,
    bytes: Vec<u8>,
    proofs: Vec<BlockProofStuff>,
    budget: &Arc<crate::history_read_budget::HistoryReadBudget>,
) -> Result<()> {
    let id = state.state().block_id();
    let global = state.state().state()?.global_id();
    admission.validate(engine, id, global)?;
    let root = root(engine)?;
    let limits = recovered_commit_limits(&root);
    Store::open(root, limits)?.commit_budget(
        Domain::from_engine(engine)?,
        id.clone(),
        global,
        bytes,
        proofs,
        Some(budget),
    )
}

pub(crate) fn sync_recovered_capsule(
    engine: &dyn EngineOperations,
    state: &VerifiedMasterchainState,
    receipt: &CapsuleDurabilityReceipt,
    budget: &Arc<crate::history_read_budget::HistoryReadBudget>,
) -> Result<()> {
    let store = Store::open(root(engine)?, Limits::default())?;
    store.sync_authenticated_capsule(
        &Domain::from_engine(engine)?, state.state().block_id(), receipt, budget,
    )
}

#[cfg(test)]
#[path = "retired_history_capsule_barrier_tests.rs"]
mod capsule_barrier_tests;
