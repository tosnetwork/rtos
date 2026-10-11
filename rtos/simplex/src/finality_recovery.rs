// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Retired source discovery. Persisted claims never authenticate a runtime.
use consensus_common::session_runtime::{SessionNetworkPin, SessionRecoveryBinding};
use consensus_common::simplex_protocol::SimplexProtocol;
use rtos_api::WireProfile;
use rtos_block::{BlockIdExt, UInt256};
use std::path::PathBuf;

/// Untrusted locator for a source session with incomplete certificate delivery.
/// Engine must authenticate the exact governing MC state against the full pin,
/// recompute the current/next-set committee and derive the same session/profile.
/// Local role and transport are claims requiring independent binding checks.
#[derive(Clone, Debug)]
pub struct SessionRecoveryRecord {
    pub pin: SessionNetworkPin,
    pub binding: SessionRecoveryBinding,
    pub protocol: SimplexProtocol,
    pub carrier_version: u32,
    pub wire_profile: WireProfile,
    pub profile: UInt256,
    pub session_id: UInt256,
    pub local_adnl: UInt256,
    pub local_validator_index: Option<u32>,
    pub prev_blocks: Vec<BlockIdExt>,
    pub start_masterchain: BlockIdExt,
    pub namespace: PathBuf,
}

use consensus_common::session_runtime::{
    AuthenticatedSessionRuntime, LocalRole, SessionRecoveryCoordinates,
};
use rtos_block::{error, fail, Result, ShardIdent};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    sync::Mutex,
};
#[path = "finality_intent_outputs.rs"]
mod outputs;
pub(crate) use outputs::{
    retirement_sealed_sets, ExpectedFinalityOutput, MAX_RETIREMENT_SETS, MAX_RETIREMENT_SET_BYTES,
};
#[cfg(test)]
pub(crate) use outputs::MAX_SEALED_SET_FILE;
const DIRECTORY: &str = "finality-intents";
const MAX_INTENT_BYTES: u64 = 16 << 20;
const MAX_INTENT_TOTAL: u64 = 64 << 20;
const MAX_INTENTS: usize = 1024;
// Completed evidence has its own finite budget. This is not retirement GC:
// reaching either completed limit deliberately backpressures further resolution.
const COMPLETED_DIRECTORY: &str = "completed-v1";
const MAX_COMPLETED: usize = 16_384;
const MAX_COMPLETED_TOTAL: u64 = 256 << 20;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletedIntent {
    schema: u32,
    record: DiskIntent,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiskIntent {
    schema: u32,
    global_id: i32,
    zerostate: String,
    governing_masterchain: String,
    workchain: i32,
    shard_prefix: u64,
    catchain_seqno: u32,
    vertical_seqno: u32,
    last_key_block_seqno: u32,
    new_catchain_ids: bool,
    protocol: u32,
    carrier_version: u32,
    wire_profile: u8,
    profile: String,
    session_id: String,
    local_adnl: String,
    local_validator_index: Option<u32>,
    #[serde(deserialize_with = "bounded_prev_blocks")]
    prev_blocks: Vec<String>,
    start_masterchain: String,
    slot: u32,
    candidate_hash: String,
    certificate: String,
}
/// A session has one or two parents; each is one block id in text form.
const MAX_PREV_BLOCKS: usize = 2;
const MAX_PREV_BLOCK_TEXT: usize = 512;

/// Refuses an oversized parent list while parsing, before any element beyond
/// the bound or any oversized string is allocated.
fn bounded_prev_blocks<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<String>, D::Error> {
    struct Text(String);
    impl<'de> Deserialize<'de> for Text {
        fn deserialize<D: serde::Deserializer<'de>>(
            deserializer: D,
        ) -> std::result::Result<Self, D::Error> {
            struct Visitor;
            impl serde::de::Visitor<'_> for Visitor {
                type Value = Text;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("a bounded block id")
                }
                fn visit_str<E: serde::de::Error>(self, value: &str) -> std::result::Result<Text, E> {
                    if value.len() > MAX_PREV_BLOCK_TEXT {
                        return Err(E::custom("session parent text too long"));
                    }
                    Ok(Text(value.to_owned()))
                }
            }
            deserializer.deserialize_str(Visitor)
        }
    }
    struct Visitor;
    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = Vec<String>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("at most two session parents")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> std::result::Result<Vec<String>, A::Error> {
            let mut parents = Vec::with_capacity(MAX_PREV_BLOCKS);
            while let Some(Text(parent)) = seq.next_element()? {
                if parents.len() == MAX_PREV_BLOCKS {
                    return Err(serde::de::Error::custom("too many session parents"));
                }
                parents.push(parent);
            }
            Ok(parents)
        }
    }
    deserializer.deserialize_seq(Visitor)
}

impl SessionRecoveryRecord {
    pub fn validate_runtime(&self, runtime: &AuthenticatedSessionRuntime) -> Result<()> {
        if &self.pin != runtime.pin()
            || runtime.recovery_binding() != Some(&self.binding)
            || self.protocol != runtime.protocol()
            || self.carrier_version != runtime.carrier_version()
            || self.wire_profile != runtime.wire_profile()
            || &self.profile != runtime.profile()
            || &self.session_id != runtime.session_id()
            || self.local_adnl.as_slice() != runtime.local_adnl().data()
            || self.local_validator_index
                != match runtime.local_role() {
                    LocalRole::Validator(i) => Some(i),
                    LocalRole::Observer => None,
                }
        {
            fail!("Retired source differs from authenticated historical runtime");
        }
        Ok(())
    }
    fn from_runtime(
        runtime: &AuthenticatedSessionRuntime,
        namespace: PathBuf,
        prev_blocks: Vec<BlockIdExt>,
        start_masterchain: BlockIdExt,
    ) -> Result<Self> {
        let binding = runtime.recovery_binding().cloned().ok_or_else(|| {
            error!(
                "Source recovery anchor unavailable; retain legacy namespace for explicit repair"
            )
        })?;
        if prev_blocks.is_empty() || prev_blocks.len() > 2 {
            fail!("Source recovery requires exact session start parents");
        }
        Ok(Self {
            pin: runtime.pin().clone(),
            binding,
            protocol: runtime.protocol(),
            carrier_version: runtime.carrier_version(),
            wire_profile: runtime.wire_profile(),
            profile: runtime.profile().clone(),
            session_id: runtime.session_id().clone(),
            local_adnl: UInt256::from(*runtime.local_adnl().data()),
            local_validator_index: match runtime.local_role() {
                LocalRole::Validator(i) => Some(i),
                LocalRole::Observer => None,
            },
            prev_blocks,
            start_masterchain,
            namespace,
        })
    }
    fn disk(&self, event: &crate::simplex_state::BlockFinalizedEvent) -> Result<DiskIntent> {
        let c = &self.binding.coordinates;
        Ok(DiskIntent {
            schema: 1,
            global_id: self.pin.global_id,
            zerostate: self.pin.zerostate.to_string(),
            governing_masterchain: self.binding.governing_masterchain.to_string(),
            workchain: c.shard.workchain_id(),
            shard_prefix: c.shard.shard_prefix_with_tag(),
            catchain_seqno: c.catchain_seqno,
            vertical_seqno: c.vertical_seqno,
            last_key_block_seqno: c.last_key_block_seqno,
            new_catchain_ids: c.new_catchain_ids,
            protocol: self.protocol.version(),
            carrier_version: self.carrier_version,
            wire_profile: self.wire_profile as u8,
            profile: self.profile.to_hex_string(),
            session_id: self.session_id.to_hex_string(),
            local_adnl: self.local_adnl.to_hex_string(),
            local_validator_index: self.local_validator_index,
            start_masterchain: self.start_masterchain.to_string(),
            prev_blocks: self.prev_blocks.iter().map(ToString::to_string).collect(),
            slot: event.slot.value(),
            candidate_hash: event.block_hash.to_hex_string(),
            certificate: hex::encode(self.wire_profile.serialize(&event.certificate.to_tl()?)?),
        })
    }
}
fn read_intent(
    path: &std::path::Path,
    namespace: &std::path::Path,
) -> Result<(SessionRecoveryRecord, Vec<u8>)> {
    let file = File::open(path)?;
    if file.metadata()?.len() > MAX_INTENT_BYTES {
        fail!("Source recovery intent oversized");
    }
    let mut bytes = Vec::new();
    file.take(MAX_INTENT_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_INTENT_BYTES {
        fail!("Source recovery intent grew beyond bound");
    }
    decode_intent(path, namespace, &bytes)
}
fn decode_intent(path: &std::path::Path, namespace: &std::path::Path, bytes: &[u8])
    -> Result<(SessionRecoveryRecord, Vec<u8>)> {
    let (record, certificate, _) = decode_intent_typed(path, namespace, bytes)?;
    Ok((record, certificate))
}
fn decode_intent_typed(path: &std::path::Path, namespace: &std::path::Path, bytes: &[u8])
    -> Result<(SessionRecoveryRecord, Vec<u8>, rtos_api::ton::consensus::simplex::Certificate)> {
    let disk: DiskIntent = if path.extension().and_then(|s| s.to_str()) == Some("complete") {
        let completed: CompletedIntent = serde_json::from_slice(&bytes)?;
        if completed.schema != 1 {
            fail!("Unknown completed source intent schema");
        }
        completed.record
    } else {
        serde_json::from_slice(&bytes)?
    };
    if disk.schema != 1 || disk.protocol != 2 || disk.wire_profile != 1 {
        fail!("Unknown source recovery domain/schema");
    }
    let certificate = hex::decode(disk.certificate)?;
    let wire: rtos_api::ton::consensus::simplex::Certificate =
        WireProfile::T0.deserialize_value_bounded(&certificate, certificate.len())?;
    if WireProfile::T0.serialize(&wire)? != certificate {
        fail!("Noncanonical source final certificate");
    }
    let rtos_api::ton::consensus::simplex::Certificate::Consensus_Simplex_Certificate(cert) = &wire;
    let rtos_api::ton::consensus::simplex::UnsignedVote::Consensus_Simplex_FinalizeVote(vote) =
        &cert.vote
    else {
        fail!("Source intent is not a FinalCert");
    };
    let hash: UInt256 = disk.candidate_hash.parse()?;
    if *vote.id.slot() != disk.slot as i32 || vote.id.hash() != &hash {
        fail!("Source intent identity mismatch");
    }
    if path.file_stem().and_then(|s| s.to_str())
        != Some(&format!("{}-{}", disk.slot, hash.to_hex_string()))
    {
        fail!("Source intent filename mismatch");
    }
    let pin = SessionNetworkPin { global_id: disk.global_id, zerostate: disk.zerostate.parse()? };
    let start_masterchain: BlockIdExt = disk.start_masterchain.parse()?;
    if !pin.zerostate.shard().is_masterchain()
        || pin.zerostate.seq_no() != 0
        || pin.zerostate.root_hash().is_zero()
        || pin.zerostate.file_hash().is_zero()
        || !start_masterchain.shard().is_masterchain()
        || start_masterchain.root_hash().is_zero()
        || start_masterchain.file_hash().is_zero()
        || (start_masterchain.seq_no() == 0 && start_masterchain != pin.zerostate)
    {
        fail!("Invalid recovery pin or session start anchor");
    }
    let anchor: BlockIdExt = disk.governing_masterchain.parse()?;
    if !anchor.shard().is_masterchain()
        || anchor.root_hash().is_zero()
        || anchor.file_hash().is_zero()
        || (anchor.seq_no() == 0 && anchor != pin.zerostate)
    {
        fail!("Invalid source recovery anchor");
    }
    let record = SessionRecoveryRecord {
        pin,
        binding: SessionRecoveryBinding {
            governing_masterchain: anchor,
            coordinates: SessionRecoveryCoordinates {
                shard: ShardIdent::with_tagged_prefix(disk.workchain, disk.shard_prefix)?,
                catchain_seqno: disk.catchain_seqno,
                vertical_seqno: disk.vertical_seqno,
                last_key_block_seqno: disk.last_key_block_seqno,
                new_catchain_ids: disk.new_catchain_ids,
            },
        },
        protocol: disk.protocol.try_into()?,
        carrier_version: disk.carrier_version,
        wire_profile: WireProfile::T0,
        profile: disk.profile.parse()?,
        session_id: disk.session_id.parse()?,
        local_adnl: disk.local_adnl.parse()?,
        local_validator_index: disk.local_validator_index,
        start_masterchain,
        prev_blocks: disk.prev_blocks.iter().map(|b| b.parse()).collect::<Result<Vec<_>>>()?,
        namespace: namespace.to_owned(),
    };
    if record.prev_blocks.is_empty() || record.prev_blocks.len() > 2 {
        fail!("Invalid retained session parents");
    }
    Ok((record, certificate, wire))
}

/// Owned by the same source lifetime as the pending Draft WAL. Scanner uses
/// that source lock, so it cannot race live mutation or claim a running source.
pub(crate) struct FinalityIntentStore {
    namespace: PathBuf,
    mutation: Mutex<()>,
    unresolved: Mutex<Option<std::collections::HashSet<PathBuf>>>,
    output_cursor: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    fail_resolve_once: std::sync::atomic::AtomicBool,
}
impl FinalityIntentStore {
    pub(crate) fn new(namespace: &std::path::Path) -> Self {
        Self {
            namespace: namespace.to_owned(),
            mutation: Mutex::new(()),
            unresolved: Mutex::new(None),
            output_cursor: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            fail_resolve_once: std::sync::atomic::AtomicBool::new(false),
        }
    }
    pub(crate) fn prepare(&self, has_existing_certificates: bool) -> Result<()> {
        let _guard = self.mutation.lock().unwrap();
        let directory = self.namespace.join(DIRECTORY);
        if !directory.exists() {
            if has_existing_certificates {
                fail!("Legacy source certificates lack durable recovery anchors; explicit migration required");
            }
            std::fs::create_dir(&directory)?;
            File::open(&self.namespace)?.sync_all()?;
        }
        for path in self.paths()? {
            if path.extension().and_then(|s| s.to_str()) == Some("resolved") {
                self.complete_path(&path)?;
            }
        }
        Ok(())
    }
    fn paths(&self) -> Result<Vec<PathBuf>> {
        let directory = self.namespace.join(DIRECTORY);
        if !directory.exists() {
            return Ok(Vec::new());
        }
        let mut pending_total = 0u64;
        let mut pending_count = 0usize;
        let mut completed_total = 0u64;
        let mut completed_count = 0usize;
        let mut pending_physical = 0u64;
        let mut completed_physical = 0u64;
        let mut pending_temps = 0usize;
        let mut completed_temps = 0usize;
        let mut completed_keys = std::collections::HashMap::<String, (PathBuf, u64)>::new();
        let mut paths = Vec::new();
        // Flatten only the one known completed directory, with no recursive walk.
        let mut entries = std::collections::VecDeque::from([std::fs::read_dir(&directory)?]);
        while let Some(mut entries_in_directory) = entries.pop_front() {
            for entry in &mut entries_in_directory {
                let entry = entry?;
                let path = entry.path();
                if path == directory.join("outputs-v1") {
                    if !entry.file_type()?.is_dir() {
                        fail!("Source output index not directory");
                    }
                    Self::validate_output_directory(&path)?;
                    continue;
                }
                if path == directory.join(COMPLETED_DIRECTORY) {
                    if !entry.file_type()?.is_dir() {
                        fail!("Completed intent index is not a directory");
                    }
                    entries.push_back(std::fs::read_dir(&path)?);
                    continue;
                }
                if !entry.file_type()?.is_file() {
                    fail!("Unexpected source recovery artifact");
                }
                let extension = path.extension().and_then(|s| s.to_str());
                let in_completed =
                    path.parent() == Some(directory.join(COMPLETED_DIRECTORY).as_path());
                let size = entry.metadata()?.len();
                if size > MAX_INTENT_BYTES {
                    fail!("Source recovery artifact oversized");
                }
                let completed = in_completed || extension == Some("resolved");
                if completed {
                    completed_physical += size;
                } else {
                    pending_physical += size;
                }
                if completed_physical > MAX_COMPLETED_TOTAL + MAX_INTENT_BYTES
                    || pending_physical > MAX_INTENT_TOTAL + MAX_INTENT_BYTES
                {
                    fail!("Source recovery physical quota exceeded");
                }
                if extension == Some("tmp") {
                    if completed {
                        completed_temps += 1;
                    } else {
                        pending_temps += 1;
                    }
                    if completed_temps > 1 || pending_temps > 1 {
                        fail!("Source recovery temporary quota exceeded");
                    }
                    continue;
                }
                if (in_completed && extension != Some("complete"))
                    || (!in_completed && !matches!(extension, Some("json" | "resolved")))
                {
                    fail!("Unexpected source recovery artifact");
                }
                if completed {
                    let key = path.file_stem().unwrap().to_string_lossy().into_owned();
                    if let Some((old, old_size)) = completed_keys.get_mut(&key) {
                        let canonical = |path: &std::path::Path| -> Result<Vec<u8>> {
                            let bytes = std::fs::read(path)?;
                            let record =
                                if path.extension().and_then(|s| s.to_str()) == Some("complete") {
                                    let value: CompletedIntent = serde_json::from_slice(&bytes)?;
                                    if value.schema != 1 {
                                        fail!("Unknown completed intent schema");
                                    }
                                    value.record
                                } else {
                                    serde_json::from_slice(&bytes)?
                                };
                            Ok(serde_json::to_vec(&record)?)
                        };
                        if canonical(old)? != canonical(&path)? {
                            fail!("Conflicting legacy/completed source intent");
                        }
                        if size > *old_size {
                            completed_total += size - *old_size;
                            *old_size = size;
                        }
                    } else {
                        completed_keys.insert(key, (path.clone(), size));
                        completed_total += size;
                        completed_count += 1;
                    }
                } else {
                    pending_total += size;
                    pending_count += 1;
                }
                if pending_total > MAX_INTENT_TOTAL
                    || pending_count > MAX_INTENTS
                    || completed_total > MAX_COMPLETED_TOTAL
                    || completed_count > MAX_COMPLETED
                {
                    fail!("Source recovery intent quota exceeded");
                }
                paths.push(path);
            }
        }
        paths.sort();
        Ok(paths)
    }
    fn prepare_temporary(path: &std::path::Path) -> Result<()> {
        for entry in std::fs::read_dir(path.parent().unwrap())? {
            let entry = entry?;
            let other = entry.path();
            if other.extension().and_then(|s| s.to_str()) == Some("tmp") && other != path {
                fail!("Another uncertain source intent temporary requires retry/repair");
            }
        }
        Ok(())
    }
    fn completed_path(&self, path: &std::path::Path) -> PathBuf {
        self.namespace
            .join(DIRECTORY)
            .join(COMPLETED_DIRECTORY)
            .join(path.file_name().unwrap())
            .with_extension("complete")
    }
    // Persist the exact original proof before removing its old representation.
    // Both copies may survive a crash; they must agree byte-for-byte semantically.
    fn complete_path(&self, path: &std::path::Path) -> Result<()> {
        let completed = self.completed_path(path);
        let directory = completed.parent().unwrap();
        let parent = directory.parent().unwrap();
        std::fs::create_dir_all(directory)?;
        File::open(parent)?.sync_all()?;
        if path.exists() {
            read_intent(path, &self.namespace)?;
            let record: DiskIntent = serde_json::from_slice(&std::fs::read(path)?)?;
            let bytes = serde_json::to_vec(&CompletedIntent { schema: 1, record })?;
            if bytes.len() as u64 > MAX_INTENT_BYTES {
                fail!("Completed intent exceeds readable bound");
            }
            if completed.exists() {
                read_intent(&completed, &self.namespace)?;
                if std::fs::read(&completed)? != bytes {
                    fail!("Conflicting completed source intent");
                }
            } else {
                let paths = self.paths()?;
                let completed_paths: Vec<_> = paths
                    .iter()
                    .filter(|p| {
                        p.as_path() != path
                            && matches!(
                                p.extension().and_then(|s| s.to_str()),
                                Some("complete" | "resolved")
                            )
                    })
                    .collect();
                let total = completed_paths.iter().try_fold(0u64, |n, p| {
                    Ok::<_, anyhow::Error>(n + std::fs::metadata(p)?.len())
                })?;
                if completed_paths.len() >= MAX_COMPLETED
                    || total + bytes.len() as u64 > MAX_COMPLETED_TOTAL
                {
                    fail!("Completed source intent backpressure");
                }
                let temporary = completed.with_extension("tmp");
                Self::prepare_temporary(&temporary)?;
                let mut file =
                    OpenOptions::new().write(true).create(true).truncate(true).open(&temporary)?;
                file.write_all(&bytes)?;
                file.sync_all()?;
                drop(file);
                std::fs::rename(temporary, &completed)?;
            }
        }
        #[cfg(test)]
        if self.fail_resolve_once.swap(false, std::sync::atomic::Ordering::AcqRel) {
            fail!("Injected source resolve sync failure after rename");
        }
        read_intent(&completed, &self.namespace)?;
        File::open(&completed)?.sync_all()?;
        File::open(directory)?.sync_all()?;
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        File::open(parent)?.sync_all()?;
        Ok(())
    }
    pub(crate) fn retain(
        &self,
        runtime: &AuthenticatedSessionRuntime,
        prevs: Vec<BlockIdExt>,
        start_masterchain: BlockIdExt,
        event: &crate::simplex_state::BlockFinalizedEvent,
    ) -> Result<()> {
        let _guard = self.mutation.lock().unwrap();
        let record = SessionRecoveryRecord::from_runtime(
            runtime,
            self.namespace.clone(),
            prevs,
            start_masterchain,
        )?;
        let directory = self.namespace.join(DIRECTORY);
        std::fs::create_dir_all(&directory)?;
        File::open(&self.namespace)?.sync_all()?;
        let path = directory.join(format!(
            "{}-{}.json",
            event.slot.value(),
            event.block_hash.to_hex_string()
        ));
        let resolved = path.with_extension("resolved");
        let completed = self.completed_path(&path);
        let old = if completed.exists() {
            &completed
        } else if resolved.exists() {
            &resolved
        } else {
            &path
        };
        if old.exists() {
            read_intent(old, &self.namespace)?.0.validate_runtime(runtime)?;
            File::open(old)?.sync_all()?;
            File::open(old.parent().unwrap())?.sync_all()?;
            File::open(&directory)?.sync_all()?;
            return Ok(());
        }
        let disk = record.disk(event)?;
        if self.released_intent(&disk)? {
            return Ok(());
        }
        let bytes = serde_json::to_vec(&disk)?;
        let paths: Vec<_> = self
            .paths()?
            .into_iter()
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
            .collect();
        let total = paths
            .iter()
            .try_fold(0u64, |n, p| Ok::<_, anyhow::Error>(n + std::fs::metadata(p)?.len()))?;
        if bytes.len() as u64 > MAX_INTENT_BYTES - 1024
            || paths.len() >= MAX_INTENTS
            || total + bytes.len() as u64 > MAX_INTENT_TOTAL
        {
            fail!("Source recovery intent backpressure");
        }
        let temporary = path.with_extension("tmp");
        Self::prepare_temporary(&temporary)?;
        if let Some(pending) = self.unresolved.lock().unwrap().as_mut() {
            pending.insert(path.clone());
        }
        let mut file =
            OpenOptions::new().write(true).create(true).truncate(true).open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(temporary, path)?;
        File::open(&directory)?.sync_all()?;
        Ok(())
    }
    pub(crate) fn resolve(&self, id: &crate::block::RawCandidateId) -> Result<()> {
        let _guard = self.mutation.lock().unwrap();
        let directory = self.namespace.join(DIRECTORY);
        let path = directory.join(format!("{}-{}.json", id.slot.value(), id.hash.to_hex_string()));
        let resolved = path.with_extension("resolved");
        if !path.exists()
            && !resolved.exists()
            && !self.completed_path(&path).exists()
            && self.output_is_released(id)?
        {
            if let Some(pending) = self.unresolved.lock().unwrap().as_mut() {
                pending.remove(&path);
            }
            return Ok(());
        }
        if path.exists() {
            self.complete_path(&path)?;
        } else if resolved.exists() {
            self.complete_path(&resolved)?;
        } else {
            self.complete_path(&path)?;
        }
        if let Some(pending) = self.unresolved.lock().unwrap().as_mut() {
            pending.remove(&path);
        }
        Ok(())
    }
    pub(crate) fn pending(&self) -> Result<Vec<Vec<u8>>> {
        let _guard = self.mutation.lock().unwrap();
        let mut pending = Vec::new();
        for path in self.paths()? {
            let (_, certificate) = read_intent(&path, &self.namespace)?;
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                let completed = self.completed_path(&path);
                if completed.exists() {
                    let original: DiskIntent = serde_json::from_slice(&std::fs::read(&path)?)?;
                    if std::fs::read(&completed)?
                        != serde_json::to_vec(&CompletedIntent { schema: 1, record: original })?
                    {
                        fail!("Conflicting pending/completed intent");
                    }
                }
            }
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                pending.push(certificate);
            }
        }
        // Initialize once: after a failed rename/fsync transition the in-process
        // set remains authoritative until resolve retries finish all barriers.
        let mut cached = self.unresolved.lock().unwrap();
        if cached.is_none() {
            *cached = Some(
                self.paths()?
                    .into_iter()
                    .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
                    .collect(),
            );
        }
        Ok(pending)
    }
    pub(crate) fn authenticate_pending(&self, runtime: &AuthenticatedSessionRuntime) -> Result<()> {
        let _guard = self.mutation.lock().unwrap();
        for path in self.paths()? {
            read_intent(&path, &self.namespace)?.0.validate_runtime(runtime)?;
        }
        Ok(())
    }
    pub(crate) fn pending_count(&self) -> Result<usize> {
        if let Some(pending) = self.unresolved.lock().unwrap().as_ref() {
            return Ok(pending.len());
        }
        self.pending()?;
        Ok(self.unresolved.lock().unwrap().as_ref().unwrap().len())
    }
}

/// Bounded discovery of idle source sessions with unresolved certificate intents.
/// The result is a locator, not an ownership or authentication capability. The
/// recovery factory must acquire the namespace and recheck the runtime binding.
pub fn scan_finality_recovery(root: &std::path::Path) -> Result<Vec<SessionRecoveryRecord>> {
    let base = root.join("consensus/v2");
    if !base.exists() {
        return Ok(Vec::new());
    }
    let mut sessions = Vec::new();
    for entry in std::fs::read_dir(base)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        if let Some(record) = scan_finality_recovery_namespace(&entry.path())? {
            sessions.push(record);
        }
        if sessions.len() >= 128 {
            break;
        }
    }
    Ok(sessions)
}

/// Scan one namespace so Engine can isolate malformed/legacy records and fairly
/// revisit other sessions. None means no idle unresolved work, not authentication.
pub fn scan_finality_recovery_namespace(
    namespace: &std::path::Path,
) -> Result<Option<SessionRecoveryRecord>> {
    let owner_path = namespace.join("finality-pending");
    if !owner_path.exists() {
        if namespace.join("session-runtime.json").exists() {
            fail!("Legacy runtime lacks source recovery provenance: {}", namespace.display());
        }
        return Ok(None);
    }
    let Some(_owner) = crate::finality_delivery::PendingFinalityStore::lock(owner_path)? else {
        return Ok(None);
    };
    let store = FinalityIntentStore::new(namespace);
    if !namespace.join(DIRECTORY).is_dir() {
        fail!("Legacy source lacks final certificate recovery provenance: {}", namespace.display());
    }
    let mut found: Option<SessionRecoveryRecord> = None;
    for path in store.paths()? {
        let (record, _) = read_intent(&path, namespace)?;
        if path.extension().and_then(|s| s.to_str()) == Some("json")
            || store.needs_output_rebuild(&path)?
        {
            if let Some(existing) = &found {
                if existing.binding != record.binding
                    || existing.session_id != record.session_id
                    || existing.prev_blocks != record.prev_blocks
                    || existing.local_adnl != record.local_adnl
                    || existing.start_masterchain != record.start_masterchain
                    || existing.pin != record.pin
                    || existing.profile != record.profile
                    || existing.local_validator_index != record.local_validator_index
                {
                    fail!("Conflicting source recovery contexts within namespace");
                }
            } else {
                found = Some(record);
            }
        }
    }
    Ok(found)
}

#[path = "source_history_debt.rs"]
mod history_debt;
pub use history_debt::{authenticate_source_history_debt, SourceHistoryDebt, SourceHistoryDebtBudget, SourceHistoryDebtBusy};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_finality_cert_intent_process_child() {
        let Some(root) = std::env::var_os("RTOS_CERT_INTENT_CRASH_ROOT") else {
            return;
        };
        let root = PathBuf::from(root);
        let (runtime, draft) = crate::finality_delivery::tests::fixture();
        let namespace = PathBuf::from(runtime.runtime_directory(root.to_str().unwrap()).unwrap());
        std::fs::create_dir_all(&namespace).unwrap();
        let consensus_common::SessionFinality::Carrier(
            rtos_block::BlockSignaturesVariant::SimplexPq(proof),
        ) = draft.finality
        else {
            unreachable!()
        };
        let candidate = rtos_api::pq_finality::PqNetworkSignatureSet::from_final_fields(&proof)
            .unwrap()
            .to_node()
            .candidate;
        let hash = UInt256::calc_file_hash(&rtos_api::serialize_boxed(&candidate).unwrap());
        let event = crate::simplex_state::BlockFinalizedEvent {
            slot: crate::block::SlotIndex::new(proof.slot),
            block_hash: hash.clone(),
            block_id: None,
            certificate: std::sync::Arc::new(crate::certificate::Certificate {
                vote: crate::simplex_state::FinalizeVote {
                    slot: crate::block::SlotIndex::new(proof.slot),
                    block_hash: hash,
                },
                signatures: proof
                    .signatures
                    .iter()
                    .enumerate()
                    .map(|(index, signature)| crate::certificate::VoteSignature {
                        validator_idx: crate::block::ValidatorIndex::new(index as u32),
                        signature: signature.signature.clone(),
                    })
                    .collect(),
            }),
        };
        let source = crate::finality_delivery::SourceFinalityDelivery::open(
            runtime.clone(),
            &namespace,
            std::sync::Arc::new(crate::finality_delivery::tests::HeldSink::default()),
        )
        .unwrap();
        source.bind_start(runtime.pin().zerostate.clone()).unwrap();
        source.retain_intent(vec![runtime.pin().zerostate.clone()], &event).unwrap();
        // Exit without Drop, candidate body, source Draft, node stage or receipt.
        std::process::exit(77);
    }
    #[test]
    fn source_finality_cert_only_process_exit_retains_authentic_recovery_debt() {
        let directory = crate::authenticated_fixture::TestDirectory::new();
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "finality_recovery::tests::source_finality_cert_intent_process_child",
                "--nocapture",
            ])
            .env("RTOS_CERT_INTENT_CRASH_ROOT", directory.path())
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(77), "{}", String::from_utf8_lossy(&result.stderr));
        let records = scan_finality_recovery(directory.path()).unwrap();
        assert_eq!(
            records.len(),
            1,
            "source-only certificate vanished before candidate materialization"
        );
        let (runtime, _) = crate::finality_delivery::tests::fixture();
        records[0].validate_runtime(&runtime).unwrap();
        let owner =
            crate::finality_delivery::PendingFinalityStore::open(&records[0].namespace).unwrap();
        let intents = FinalityIntentStore::new(&records[0].namespace).pending().unwrap();
        assert_eq!(intents.len(), 1);
        let nodes = runtime
            .committee()
            .iter()
            .map(crate::SimplexSessionNode::from_descriptor)
            .collect::<Result<Vec<_>>>()
            .unwrap();
        let transport =
            rtos_block::Ed25519KeyOption::<rtos_block::ZeroizingBytes>::from_private_key(
                &[0x71; 32],
            )
            .unwrap();
        let options = crate::SessionOptions {
            protocol: runtime.protocol(),
            proto_version: runtime.carrier_version(),
            wire_profile: runtime.wire_profile(),
            slots_per_leader_window: runtime.slots_per_leader_window(),
            ..Default::default()
        };
        let description = crate::session_description::SessionDescription::new_with_runtime(
            &options,
            runtime.session_id().clone(),
            1,
            &nodes,
            transport,
            runtime.shard(),
            std::time::SystemTime::now(),
            None,
            Some(&runtime),
        )
        .unwrap()
        .bind_pq_session(runtime.catchain_seqno())
        .unwrap();
        let certificate = runtime.wire_profile().deserialize_typed(&intents[0]).unwrap();
        crate::certificate::Certificate::<crate::simplex_state::Vote>::from_tl(
            &certificate,
            &description,
            runtime.session_id(),
        )
        .unwrap();
        assert!(
            std::fs::read_dir(records[0].namespace.join("finality-pending"))
                .unwrap()
                .all(|entry| entry.unwrap().file_name() == ".lock"),
            "this window must precede any full Draft or node custody"
        );
        drop(owner);
    }
    #[test]
    fn source_finality_legacy_namespace_is_not_silently_empty_or_upgraded() {
        let directory = crate::authenticated_fixture::TestDirectory::new();
        let (runtime, _) = crate::finality_delivery::tests::fixture();
        let namespace =
            PathBuf::from(runtime.runtime_directory(directory.path().to_str().unwrap()).unwrap());
        std::fs::create_dir_all(&namespace).unwrap();
        std::fs::write(namespace.join("session-runtime.json"), b"{}").unwrap();
        assert!(scan_finality_recovery(directory.path()).is_err());
        let owner = crate::finality_delivery::PendingFinalityStore::open(&namespace).unwrap();
        let store = FinalityIntentStore::new(&namespace);
        assert!(store.prepare(true).is_err(), "existing certs cannot be assigned invented anchors");
        assert!(!namespace.join(DIRECTORY).exists());
        drop(owner);
        assert!(scan_finality_recovery(directory.path()).is_err());
        store.prepare(false).unwrap();
        assert!(scan_finality_recovery(directory.path()).unwrap().is_empty());
    }
    #[test]
    fn source_finality_cert_intent_survives_restart_and_preserves_first_proof() {
        let directory = crate::authenticated_fixture::TestDirectory::new();
        let (runtime, draft) = crate::finality_delivery::tests::fixture();
        let namespace =
            PathBuf::from(runtime.runtime_directory(directory.path().to_str().unwrap()).unwrap());
        std::fs::create_dir_all(&namespace).unwrap();
        let consensus_common::SessionFinality::Carrier(
            rtos_block::BlockSignaturesVariant::SimplexPq(proof),
        ) = draft.finality
        else {
            unreachable!()
        };
        let wire = rtos_api::pq_finality::PqNetworkSignatureSet::from_final_fields(&proof)
            .unwrap()
            .to_node();
        let hash = UInt256::calc_file_hash(&rtos_api::serialize_boxed(&wire.candidate).unwrap());
        let event = crate::simplex_state::BlockFinalizedEvent {
            slot: crate::block::SlotIndex::new(proof.slot),
            block_hash: hash.clone(),
            block_id: None,
            certificate: std::sync::Arc::new(crate::certificate::Certificate {
                vote: crate::simplex_state::FinalizeVote {
                    slot: crate::block::SlotIndex::new(proof.slot),
                    block_hash: hash.clone(),
                },
                signatures: proof
                    .signatures
                    .iter()
                    .enumerate()
                    .map(|(i, s)| crate::certificate::VoteSignature {
                        validator_idx: crate::block::ValidatorIndex::new(i as u32),
                        signature: s.signature.clone(),
                    })
                    .collect(),
            }),
        };
        let owner = crate::finality_delivery::PendingFinalityStore::open(&namespace).unwrap();
        let store = FinalityIntentStore::new(&namespace);
        store
            .retain(
                &runtime,
                vec![runtime.pin().zerostate.clone()],
                runtime.pin().zerostate.clone(),
                &event,
            )
            .unwrap();
        let original = store.pending().unwrap();
        assert_eq!(original.len(), 1);
        assert!(
            scan_finality_recovery(directory.path()).unwrap().is_empty(),
            "live source remains exclusively owned"
        );
        drop(store);
        drop(owner);
        let records = scan_finality_recovery(directory.path()).unwrap();
        assert_eq!(records.len(), 1);
        records[0].validate_runtime(&runtime).unwrap();
        assert_eq!(records[0].start_masterchain, runtime.pin().zerostate);
        let reopened = FinalityIntentStore::new(&namespace);
        assert_eq!(reopened.pending().unwrap(), original);
        let mut different = event.clone();
        std::sync::Arc::make_mut(&mut different.certificate).signatures.clear();
        reopened
            .retain(
                &runtime,
                vec![runtime.pin().zerostate.clone()],
                runtime.pin().zerostate.clone(),
                &different,
            )
            .unwrap();
        assert_eq!(
            reopened.pending().unwrap(),
            original,
            "reconstruction must not overwrite the first proof"
        );
        let id = crate::block::RawCandidateId { slot: event.slot, hash };
        assert_eq!(reopened.pending_count().unwrap(), 1);
        reopened.fail_resolve_once.store(true, std::sync::atomic::Ordering::Release);
        assert!(reopened.resolve(&id).is_err());
        assert_eq!(
            reopened.pending_count().unwrap(),
            1,
            "rename alone cannot certify durable completion"
        );
        let uncertain_reopen = FinalityIntentStore::new(&namespace);
        assert_eq!(
            uncertain_reopen.pending_count().unwrap(),
            1,
            "index copy alone cannot skip pending debt after reopen"
        );
        reopened.resolve(&id).unwrap();
        assert_eq!(reopened.pending_count().unwrap(), 0);
        // Resolving the certificate does not prove that its complete output set
        // was sealed. Legacy completed evidence must remain discoverable.
        let reconstruction = scan_finality_recovery(directory.path()).unwrap();
        assert_eq!(reconstruction.len(), 1);
        macro_rules! same_field {
            ($($field:ident),+ $(,)?) => { $(assert_eq!(reconstruction[0].$field, records[0].$field);)+ };
        }
        same_field!(
            pin,
            binding,
            protocol,
            carrier_version,
            wire_profile,
            profile,
            session_id,
            local_adnl,
            local_validator_index,
            prev_blocks,
            start_masterchain,
            namespace
        );
        drop(uncertain_reopen);
        drop(reopened);
        let reopened = FinalityIntentStore::new(&namespace);
        assert_eq!(reopened.pending_count().unwrap(), 0);
        assert_eq!(reopened.legacy_output_count().unwrap(), 1);
        assert_eq!(
            reopened.pending_with_legacy_outputs().unwrap(),
            original,
            "cold reconstruction must replay the exact first certificate"
        );
        reopened
            .seal_outputs(
                &id,
                vec![ExpectedFinalityOutput::new(
                    &draft.block_id,
                    true,
                    &draft.source_info.source.block_creator().unwrap(),
                )],
            )
            .unwrap();
        assert!(
            !reopened.output_is_released(&id).unwrap(),
            "sealing expected outputs does not manufacture Delivered confirmation"
        );
        assert_eq!(reopened.legacy_output_count().unwrap(), 0);
        assert!(scan_finality_recovery(directory.path()).unwrap().is_empty());
        assert_eq!(reopened.paths().unwrap().len(), 1, "canonical resolved evidence retained");
        std::fs::write(&reopened.paths().unwrap()[0], b"{broken").unwrap();
        assert!(
            scan_finality_recovery(directory.path()).is_err(),
            "bad resolved records cannot become an empty scan"
        );
    }
    #[test]
    fn source_finality_completed_index_does_not_consume_pending_quota_or_skip_holes() {
        let directory = crate::authenticated_fixture::TestDirectory::new();
        let (runtime, _) = crate::finality_delivery::tests::fixture();
        let namespace =
            PathBuf::from(runtime.runtime_directory(directory.path().to_str().unwrap()).unwrap());
        std::fs::create_dir_all(&namespace).unwrap();
        let store = FinalityIntentStore::new(&namespace);
        store.prepare(false).unwrap();
        // Storage accepts untrusted evidence. These structural certificates test
        // storage admission, not cryptographic authentication or finality.
        let event = |slot: u32| {
            let hash = UInt256::calc_file_hash(&slot.to_le_bytes());
            crate::simplex_state::BlockFinalizedEvent {
                slot: crate::block::SlotIndex::new(slot),
                block_hash: hash.clone(),
                block_id: None,
                certificate: std::sync::Arc::new(crate::certificate::Certificate {
                    vote: crate::simplex_state::FinalizeVote {
                        slot: crate::block::SlotIndex::new(slot),
                        block_hash: hash,
                    },
                    signatures: Vec::new(),
                }),
            }
        };
        let retain = |event: &crate::simplex_state::BlockFinalizedEvent| {
            store
                .retain(
                    &runtime,
                    vec![runtime.pin().zerostate.clone()],
                    runtime.pin().zerostate.clone(),
                    event,
                )
                .unwrap()
        };
        let hole = event(1u32);
        retain(&hole);
        for slot in 2u32..1104 {
            let next = event(slot);
            retain(&next);
            store
                .resolve(&crate::block::RawCandidateId { slot: next.slot, hash: next.block_hash })
                .unwrap();
        }
        assert_eq!(
            store.pending_count().unwrap(),
            1,
            "high completed slots cannot consume the hole"
        );
        assert_eq!(store.pending().unwrap().len(), 1);
        assert_eq!(store.paths().unwrap().len(), 1103);
        drop(store);
        let reopened = FinalityIntentStore::new(&namespace);
        reopened.prepare(true).unwrap();
        assert_eq!(reopened.pending_count().unwrap(), 1);
        let already = event(1103);
        reopened
            .retain(
                &runtime,
                vec![runtime.pin().zerostate.clone()],
                runtime.pin().zerostate.clone(),
                &already,
            )
            .unwrap();
        assert_eq!(reopened.pending_count().unwrap(), 1, "exact completed replay is idempotent");
        let next = event(1104);
        reopened
            .retain(
                &runtime,
                vec![runtime.pin().zerostate.clone()],
                runtime.pin().zerostate.clone(),
                &next,
            )
            .unwrap();
        assert_eq!(
            reopened.pending_count().unwrap(),
            2,
            "independent pending quota remains available"
        );
        let completed = reopened
            .paths()
            .unwrap()
            .into_iter()
            .find(|p| p.extension().and_then(|s| s.to_str()) == Some("complete"))
            .unwrap();
        let decoded: CompletedIntent =
            serde_json::from_slice(&std::fs::read(&completed).unwrap()).unwrap();
        let legacy = namespace
            .join(DIRECTORY)
            .join(completed.file_name().unwrap())
            .with_extension("resolved");
        std::fs::write(&legacy, serde_json::to_vec(&decoded.record).unwrap()).unwrap();
        std::fs::remove_file(&completed).unwrap();
        reopened.prepare(true).unwrap();
        assert!(!legacy.exists());
        assert!(completed.exists(), "legacy exact proof migrated durably");
        let temporary = namespace.join(DIRECTORY).join("oversized.tmp");
        File::create(&temporary).unwrap().set_len(MAX_INTENT_BYTES + 1).unwrap();
        assert!(reopened.paths().is_err(), "temporary bytes cannot bypass physical quota");
    }
}
