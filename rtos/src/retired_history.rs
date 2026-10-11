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

const SCHEMA: u32 = 1;
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
    fn from_engine(engine: &dyn EngineOperations) -> Result<Self> {
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
    manifest: Manifest,
    state: Vec<u8>,
    proofs: Vec<BlockProofStuff>,
}
struct Store {
    root: PathBuf,
    limits: Limits,
    _lock: File,
    #[cfg(test)]
    fail_manifest: bool,
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
        lock.try_lock().map_err(|e| error!("Retained history writer busy: {e}"))?;
        Ok(Self {
            root,
            limits,
            _lock: lock,
            #[cfg(test)]
            fail_manifest: false,
        })
    }
    fn usage(&self) -> Result<(u64, usize)> {
        let mut bytes = 0u64;
        let mut anchors = 0usize;
        let mut files = 0usize;
        for entry in std::fs::read_dir(&self.root)? {
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
    fn read(&self, domain: &Domain, id: &BlockIdExt) -> Result<Option<Evidence>> {
        self.usage()?;
        let path = self.root.join(format!("{}.json", anchor_name(domain, id)));
        if !path.exists() {
            return Ok(None);
        }
        let manifest: Manifest = serde_json::from_slice(&bounded_read(&path, 2 << 20)?)?;
        if manifest.schema != SCHEMA
            || &manifest.domain != domain
            || manifest.id != id.to_string()
            || manifest.proofs.len() > self.limits.proofs_per_anchor
        {
            fail!("Retained history manifest domain/schema mismatch");
        }
        let state = self.blob(&manifest.state, self.limits.state_bytes)?;
        let mut proofs = Vec::new();
        let mut total = state.len() as u64;
        for proof in &manifest.proofs {
            let bytes = self.blob(&proof.blob, self.limits.proof_bytes)?;
            total += bytes.len() as u64;
            if total > self.limits.total_bytes {
                fail!("Retained history evidence exceeds memory bound");
            }
            let id: BlockIdExt = proof.id.parse()?;
            if proofs.iter().any(|p: &BlockProofStuff| p.id() == &id) {
                fail!("Duplicate retained proof identity");
            }
            proofs.push(BlockProofStuff::deserialize(&id, bytes, proof.link)?);
        }
        Ok(Some(Evidence { manifest, state, proofs }))
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
        if state.len() > self.limits.state_bytes || proofs.len() > self.limits.proofs_per_anchor {
            fail!("History evidence exceeds bound");
        }
        if let Some(existing) = self.read(&domain, &id)? {
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
        let (used, anchors) = self.usage()?;
        if anchors >= self.limits.anchors {
            fail!("Retained history anchor quota exhausted");
        }
        let mut blobs = std::collections::BTreeMap::new();
        let state_hash = digest(&state);
        blobs.insert(state_hash.clone(), state);
        let mut references = Vec::new();
        for proof in proofs {
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
        let encoded = serde_json::to_vec(&manifest)?;
        if encoded.len() > 2 << 20 {
            fail!("History manifest exceeds bound");
        }
        let mut extra = encoded.len() as u64;
        for (hash, bytes) in &blobs {
            let path = self.root.join(format!("{hash}.blob"));
            if path.exists() {
                if bounded_read(&path, bytes.len())? != *bytes {
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
            if !self.root.join(&name).exists() {
                self.atomic_write(&name, &bytes)?;
            } else {
                File::open(self.root.join(name))?.sync_all()?;
            }
        }
        self.atomic_write(&format!("{}.json", anchor_name(&domain, &id)), &encoded)
    }
}

async fn owned_io<T: Send + 'static>(
    engine: &dyn EngineOperations,
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    crate::types::service_tasks::spawn_owned(engine, "retired history IO", async move {
        tokio::task::spawn_blocking(work)
            .await
            .map_err(|e| error!("Retired history IO join: {e}"))?
    })?
    .await
    .map_err(|e| error!("Retired history owner join: {e}"))?
}
fn root(engine: &dyn EngineOperations) -> Result<PathBuf> {
    Ok(PathBuf::from(engine.db_root_dir()?).join("retired-history-v1"))
}

/// Read-only with respect to acceptance/publication. Missing private evidence
/// retains the old explicit load/defer behavior; corrupt evidence is not ignored.
pub(crate) async fn authenticate_state(
    engine: &dyn EngineOperations,
    id: &BlockIdExt,
) -> Result<VerifiedMasterchainState> {
    let path = root(engine)?;
    if !path.exists() {
        return crate::boot::authenticate_recovered_state(engine, id).await;
    }
    let domain = Domain::from_engine(engine)?;
    let expected = id.clone();
    let evidence =
        owned_io(engine, move || Store::open(path, Limits::default())?.read(&domain, &expected))
            .await?;
    let Some(evidence) = evidence else {
        return crate::boot::authenticate_recovered_state(engine, id).await;
    };
    let state = ShardStateStuff::from_root_cell(
        id.clone(),
        rtos_block::read_single_root_boc(&evidence.state)?,
        #[cfg(feature = "telemetry")]
        engine.engine_telemetry(),
        engine.engine_allocated(),
    )?;
    let verified =
        authenticate_recovered_state_evidence(engine, id, state, Some(&evidence.proofs), None)
            .await?;
    if verified.state().state()?.global_id() != evidence.manifest.global_id {
        fail!("History global ID mismatch");
    }
    Ok(verified)
}

/// Live authenticated admission only. Two concurrent preparations bound working
/// memory; independent file locking serializes every quota/commit transaction.
pub(crate) async fn prepare(
    engine: Arc<dyn EngineOperations>,
    runtime: Arc<AuthenticatedSessionRuntime>,
    start: BlockIdExt,
) -> Result<()> {
    let permit =
        PREPARATIONS.try_acquire().map_err(|_| error!("History preparation capacity exhausted"))?;
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
        assert!(tiny.commit(domain(), identity(1), -239, vec![0; 11], vec![]).is_err());
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
        assert!(store.read(&domain(), &identity(1)).is_err());
    }
}
