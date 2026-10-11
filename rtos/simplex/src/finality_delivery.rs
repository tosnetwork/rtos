// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Source retention before node WAL acknowledgement. Records are untrusted on recovery.
use consensus_common::{
    finality_delivery::FinalizedDeliveryDraft,
    session_runtime::{AuthenticatedSessionRuntime, SessionNetworkPin},
    simplex_protocol::SimplexProtocol,
    SessionFinality,
};
use rtos_api::{pq_finality::PqNetworkSignatureSet, IntoBoxed, WireProfile};
use rtos_block::{error, fail, BlockIdExt, BlockSignaturesVariant, Result, UInt256};
use serde::{Deserialize, Serialize};
use std::{fs::{File, OpenOptions}, io::{Read, Write}, path::{Path, PathBuf}, sync::{Arc, Mutex}};

const MAX_RECORD_BYTES: u64 = 64 << 20;
const MAX_TOTAL_BYTES: u64 = 128 << 20;
const MAX_RECORDS: usize = 1024;
const DIRECTORY: &str = "finality-pending";

/// Untrusted retained evidence. Recovery must authenticate historical configuration
/// through Engine before obtaining node durability; this is not a runtime capability.
#[derive(Clone, Debug)]
pub struct PendingFinalityRecord {
    pub pin: SessionNetworkPin,
    pub protocol: SimplexProtocol,
    pub carrier_version: u32,
    pub wire_profile: WireProfile,
    pub profile: UInt256,
    pub session_id: UInt256,
    pub block_id: BlockIdExt,
    pub local_adnl: UInt256,
    pub local_validator_index: Option<u32>,
    pub source_validator: UInt256,
    pub data: Vec<u8>,
    /// Canonical boxed node SignatureSet. Its encoded Final/Approval role must
    /// equal `is_final`; approvals cannot be promoted by changing this field.
    pub signature_set: Vec<u8>,
    pub is_final: bool,
    pub last_mc_finalized_seqno: u32,
    pub candidate_already_sent: bool,
    pub created_at_unix_secs: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiskRecord {
    schema: u32, global_id: i32, zerostate: String, protocol: u32, carrier_version: u32,
    wire_profile: u8, profile: String, session_id: String, block_id: String,
    local_adnl: String, local_validator_index: Option<u32>, source_validator: String,
    data: String, signature_set: String, is_final: bool, last_mc_finalized_seqno: u32,
    candidate_already_sent: bool, created_at_unix_secs: u64,
}
impl PendingFinalityRecord {
    pub fn id(&self) -> Result<UInt256> {
        Ok(UInt256::calc_file_hash(&serde_json::to_vec(&(
            "rtos-source-finality-v1", self.pin.global_id, self.pin.zerostate.to_string(),
            self.protocol.version(), self.carrier_version, self.wire_profile as u8,
            self.profile.to_hex_string(), self.session_id.to_hex_string(),
            self.block_id.to_string(), self.is_final,
            (self.local_adnl.to_hex_string(), self.local_validator_index, self.source_validator.to_hex_string()),
        ))?))
    }
    pub(crate) fn from_draft(runtime: &AuthenticatedSessionRuntime, draft: &FinalizedDeliveryDraft) -> Result<Self> {
        let signatures = match &draft.finality {
            SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(value)) => PqNetworkSignatureSet::from_final_fields(value)?,
            SessionFinality::PqApproval(value) => PqNetworkSignatureSet::from_approval(value)?,
            _ => fail!("Durable v2 source requires PQ finality evidence"),
        };
        let record = Self {
            pin: runtime.pin().clone(), protocol: runtime.protocol(), carrier_version: runtime.carrier_version(),
            wire_profile: runtime.wire_profile(), profile: runtime.profile().clone(), session_id: runtime.session_id().clone(),
            block_id: draft.block_id.clone(), data: draft.data.data().to_vec(),
            local_adnl: UInt256::from(*runtime.local_adnl().data()),
            local_validator_index: match runtime.local_role() {
                consensus_common::session_runtime::LocalRole::Validator(index) => Some(index),
                consensus_common::session_runtime::LocalRole::Observer => None,
            },
            source_validator: UInt256::from(*draft.source_info.source.id().data()),
            signature_set: runtime.wire_profile().serialize(&signatures.to_node().into_boxed())?,
            is_final: signatures.is_final(), last_mc_finalized_seqno: draft.last_mc_finalized_seqno,
            candidate_already_sent: draft.candidate_already_sent,
            created_at_unix_secs: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),
        };
        record.validate()?;
        Ok(record)
    }
    fn validate(&self) -> Result<()> {
        if self.protocol != SimplexProtocol::PrivateObserversPlumtree || self.wire_profile != WireProfile::T0 {
            fail!("Unsupported source finality protocol/wire domain");
        }
        if self.pin.zerostate.seq_no() != 0 || !self.pin.zerostate.shard().is_masterchain()
            || self.pin.zerostate.root_hash() == &UInt256::default() || self.pin.zerostate.file_hash() == &UInt256::default() {
            fail!("Invalid source full network pin");
        }
        if self.data.len() > (16 << 20) || self.signature_set.len() > (16 << 20) {
            fail!("Source finality body/carrier exceeds bound");
        }
        let wire: rtos_api::ton::ton_node::SignatureSet = self.wire_profile.deserialize_typed(&self.signature_set)?;
        if self.wire_profile.serialize(&wire)? != self.signature_set { fail!("Noncanonical source signature set"); }
        let rtos_api::ton::ton_node::SignatureSet::TonNode_SignatureSet_SimplexPq(value) = wire else {
            fail!("Source signature set is not PQ");
        };
        let signatures = PqNetworkSignatureSet::from_node(value)?;
        if signatures.is_final() != self.is_final || signatures.session_id() != &self.session_id
            || signatures.block_id() != &self.block_id { fail!("Source finality role/session/block mismatch"); }
        if UInt256::calc_file_hash(&self.data) != *self.block_id.file_hash()
            || rtos_block::read_single_root_boc(&self.data)?.repr_hash() != self.block_id.root_hash() {
            fail!("Source finality body hash mismatch");
        }
        Ok(())
    }
    fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(&DiskRecord {
            schema: 1, global_id: self.pin.global_id, zerostate: self.pin.zerostate.to_string(),
            protocol: self.protocol.version(), carrier_version: self.carrier_version, wire_profile: self.wire_profile as u8,
            profile: self.profile.to_hex_string(), session_id: self.session_id.to_hex_string(), block_id: self.block_id.to_string(),
            local_adnl: self.local_adnl.to_hex_string(), local_validator_index: self.local_validator_index,
            source_validator: self.source_validator.to_hex_string(),
            data: hex::encode(&self.data), signature_set: hex::encode(&self.signature_set), is_final: self.is_final,
            last_mc_finalized_seqno: self.last_mc_finalized_seqno, candidate_already_sent: self.candidate_already_sent,
            created_at_unix_secs: self.created_at_unix_secs,
        })?;
        if bytes.len() as u64 > MAX_RECORD_BYTES { fail!("Source finality record exceeds bound"); }
        Ok(bytes)
    }
    fn read(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        if file.metadata()?.len() > MAX_RECORD_BYTES { fail!("Oversized source finality record"); }
        let mut bytes = Vec::new(); file.take(MAX_RECORD_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_RECORD_BYTES { fail!("Growing source finality record exceeds bound"); }
        let disk: DiskRecord = serde_json::from_slice(&bytes)?;
        if disk.schema != 1 { fail!("Unknown source finality schema {}", disk.schema); }
        let record = Self {
            pin: SessionNetworkPin { global_id: disk.global_id, zerostate: disk.zerostate.parse()? },
            protocol: disk.protocol.try_into()?, carrier_version: disk.carrier_version,
            wire_profile: match disk.wire_profile { 0 => WireProfile::Legacy, 1 => WireProfile::T0, _ => fail!("Unknown source wire profile") },
            profile: disk.profile.parse()?, session_id: disk.session_id.parse()?, block_id: disk.block_id.parse()?,
            local_adnl: disk.local_adnl.parse()?, local_validator_index: disk.local_validator_index,
            source_validator: disk.source_validator.parse()?,
            data: hex::decode(disk.data)?, signature_set: hex::decode(disk.signature_set)?, is_final: disk.is_final,
            last_mc_finalized_seqno: disk.last_mc_finalized_seqno, candidate_already_sent: disk.candidate_already_sent,
            created_at_unix_secs: disk.created_at_unix_secs,
        };
        record.validate()?;
        if path.file_stem().and_then(|s| s.to_str()) != Some(&record.id()?.to_hex_string()) { fail!("Source finality filename/domain mismatch"); }
        Ok(record)
    }
}

pub(crate) struct PendingFinalityStore {
    directory: PathBuf,
    _lock: File,
    mutation: Mutex<()>,
}
impl PendingFinalityStore {
    pub(crate) fn open(namespace: &Path) -> Result<Arc<Self>> {
        let directory = namespace.join(DIRECTORY);
        std::fs::create_dir_all(&directory)?;
        File::open(namespace)?.sync_all()?;
        Self::lock(directory)?.ok_or_else(|| error!("Source finality store already owned"))
    }
    fn lock(directory: PathBuf) -> Result<Option<Arc<Self>>> {
        let lock = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(directory.join(".lock"))?;
        match lock.try_lock() {
            Ok(()) => Ok(Some(Arc::new(Self { directory, _lock: lock, mutation: Mutex::new(()) }))),
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(error) => Err(error!("Source finality ownership: {error}")),
        }
    }
    fn paths(&self) -> Result<Vec<PathBuf>> {
        let mut total = 0u64; let mut paths = Vec::new();
        for entry in std::fs::read_dir(&self.directory)? {
            let entry = entry?; let path = entry.path();
            let name = entry.file_name(); let name = name.to_string_lossy();
            if name == ".lock" || name.ends_with(".tmp") { continue; }
            if !entry.file_type()?.is_file() || path.extension().and_then(|s| s.to_str()) != Some("json") { fail!("Unexpected source finality entry"); }
            total = total.checked_add(entry.metadata()?.len()).ok_or_else(|| error!("Source quota overflow"))?;
            paths.push(path);
            if total > MAX_TOTAL_BYTES || paths.len() > MAX_RECORDS { fail!("Source finality quota exceeded"); }
        }
        paths.sort(); Ok(paths)
    }
    pub(crate) fn retain(&self, record: &PendingFinalityRecord) -> Result<PendingFinalityRecord> {
        let _guard = self.mutation.lock().unwrap();
        let path = self.directory.join(format!("{}.json", record.id()?.to_hex_string()));
        if path.exists() {
            let old = PendingFinalityRecord::read(&path)?;
            if old.data != record.data { fail!("Conflicting retained body for source finality identity"); }
            return Ok(old);
        }
        let bytes = record.encode()?;
        let paths = self.paths()?;
        let total = paths.iter().try_fold(0u64, |total, path| Ok::<_, anyhow::Error>(total + std::fs::metadata(path)?.len()))?;
        if paths.len() >= MAX_RECORDS || total + bytes.len() as u64 > MAX_TOTAL_BYTES { fail!("Source finality backpressure"); }
        let temporary = path.with_extension("tmp");
        let mut file = OpenOptions::new().write(true).create(true).truncate(true).open(&temporary)?;
        file.write_all(&bytes)?; file.sync_all()?; drop(file);
        std::fs::rename(&temporary, &path)?; File::open(&self.directory)?.sync_all()?;
        Ok(record.clone())
    }
    pub(crate) fn acknowledge(&self, id: &UInt256, _node_receipt: UInt256) -> Result<()> {
        let _guard = self.mutation.lock().unwrap();
        std::fs::remove_file(self.directory.join(format!("{}.json", id.to_hex_string())))?;
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }
}

/// A scan result holds the source ownership lock until authenticated node takeover
/// and acknowledgement, or drop. Failed authentication must leave it untouched.
pub struct PendingFinalityRecovery {
    store: Arc<PendingFinalityStore>,
    record: PendingFinalityRecord,
}
impl PendingFinalityRecovery {
    pub fn record(&self) -> &PendingFinalityRecord { &self.record }
    pub fn acknowledge(self, node_receipt: UInt256) -> Result<()> {
        self.store.acknowledge(&self.record.id()?, node_receipt)
    }
}
/// Scan retired v2 namespaces beneath the same root passed to runtime_directory.
/// Busy stores are skipped. Malformed/unknown records are errors, never empty recovery.
pub fn scan_pending_finality(root: &Path) -> Result<Vec<PendingFinalityRecovery>> {
    let base = root.join("consensus/v2");
    if !base.exists() { return Ok(Vec::new()); }
    let mut records = Vec::new(); let mut bytes = 0usize;
    for namespace in std::fs::read_dir(base)? {
        let namespace = namespace?;
        if !namespace.file_type()?.is_dir() { continue; }
        let path = namespace.path().join(DIRECTORY);
        if !path.exists() { continue; }
        let Some(store) = PendingFinalityStore::lock(path)? else { continue; };
        for path in store.paths()? {
            let record = PendingFinalityRecord::read(&path)?;
            let size = record.data.len() + record.signature_set.len();
            if bytes + size > MAX_TOTAL_BYTES as usize || records.len() >= MAX_RECORDS { return Ok(records); }
            bytes += size;
            records.push(PendingFinalityRecovery { store: store.clone(), record });
        }
    }
    Ok(records)
}
