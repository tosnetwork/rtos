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
// A single ACK transition may temporarily duplicate the largest admitted record.
// Reserve both its physical file and its bytes at admission, not at completion.
const ACK_ENVELOPE_RESERVE: u64 = 1024;
fn check_retention_capacity(count: usize, total: u64, incoming: u64) -> Result<()> {
    if incoming > MAX_RECORD_BYTES - ACK_ENVELOPE_RESERVE
        || count >= MAX_RECORDS - 1
        || total.checked_add(incoming).and_then(|n| n.checked_add(MAX_RECORD_BYTES))
            .is_none_or(|n| n > MAX_TOTAL_BYTES) {
        fail!("Source finality backpressure (ACK transition capacity reserved)");
    }
    Ok(())
}

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
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcknowledgedRecord {
    schema: u32,
    node_receipt: String,
    record: DiskRecord,
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
            created_at_unix_secs: draft.created_at_unix_secs,
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
        let disk: DiskRecord = if path.extension().and_then(|s| s.to_str()) == Some("acked") {
            let ack: AcknowledgedRecord = serde_json::from_slice(&bytes)?;
            if ack.schema != 1 { fail!("Unknown acknowledged source finality schema"); }
            let _: UInt256 = ack.node_receipt.parse()?;
            ack.record
        } else { serde_json::from_slice(&bytes)? };
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
            if !entry.file_type()?.is_file() || !matches!(path.extension().and_then(|s| s.to_str()), Some("json" | "acked")) { fail!("Unexpected source finality entry"); }
            total = total.checked_add(entry.metadata()?.len()).ok_or_else(|| error!("Source quota overflow"))?;
            paths.push(path);
            if total > MAX_TOTAL_BYTES || paths.len() > MAX_RECORDS { fail!("Source finality quota exceeded"); }
        }
        paths.sort(); Ok(paths)
    }
    pub(crate) fn retain(&self, record: &PendingFinalityRecord) -> Result<PendingFinalityRecord> {
        let _guard = self.mutation.lock().unwrap();
        let path = self.directory.join(format!("{}.json", record.id()?.to_hex_string()));
        let acknowledged = path.with_extension("acked");
        if path.exists() || acknowledged.exists() {
            let retained_path = if acknowledged.exists() { &acknowledged } else { &path };
            let old = PendingFinalityRecord::read(retained_path)?;
            if path.exists() && acknowledged.exists() && old.encode()? != PendingFinalityRecord::read(&path)?.encode()? {
                fail!("Conflicting pending and acknowledged source records");
            }
            if old.data != record.data { fail!("Conflicting retained body for source finality identity"); }
            // A prior rename may have succeeded while directory sync failed.
            // Re-establish durability before returning the retained proof.
            File::open(retained_path)?.sync_all()?;
            File::open(&self.directory)?.sync_all()?;
            return Ok(old);
        }
        let bytes = record.encode()?;
        let paths = self.paths()?;
        for existing in &paths {
            let old = PendingFinalityRecord::read(existing)?;
            if old.block_id.seq_no() == record.block_id.seq_no() && old.block_id != record.block_id {
                fail!("Conflicting source finality blocks at one seqno");
            }
        }
        let total = paths.iter().try_fold(0u64, |total, path| Ok::<_, anyhow::Error>(total + std::fs::metadata(path)?.len()))?;
        check_retention_capacity(paths.len(), total, bytes.len() as u64)?;
        let temporary = path.with_extension("tmp");
        let mut file = OpenOptions::new().write(true).create(true).truncate(true).open(&temporary)?;
        file.write_all(&bytes)?; file.sync_all()?; drop(file);
        std::fs::rename(&temporary, &path)?; File::open(&self.directory)?.sync_all()?;
        Ok(record.clone())
    }
    pub(crate) fn acknowledge(&self, id: &UInt256, node_receipt: UInt256) -> Result<()> {
        let _guard = self.mutation.lock().unwrap();
        let path = self.directory.join(format!("{}.json", id.to_hex_string()));
        let acknowledged = path.with_extension("acked");
        // The complete canonical proof remains available after node takeover,
        // including a crash before the local finalized-state write. The receipt
        // is only a lookup hint; later source replay still invokes node stage.
        let retained_path = if path.exists() { &path } else { &acknowledged };
        let record = PendingFinalityRecord::read(retained_path)?;
        if acknowledged.exists() && PendingFinalityRecord::read(&acknowledged)?.encode()? != record.encode()? {
            fail!("Conflicting source acknowledged proof");
        }
        if !acknowledged.exists() {
            let bytes = serde_json::to_vec(&AcknowledgedRecord { schema: 1,
                node_receipt: node_receipt.to_hex_string(), record: serde_json::from_slice(&record.encode()?)? })?;
            if bytes.len() as u64 > MAX_RECORD_BYTES { fail!("Acknowledged source record exceeds readable bound"); }
            // Account the temporary duplicate too: no unbounded receipt history.
            let paths = self.paths()?;
            let total = paths.iter().try_fold(0u64, |n, p| Ok::<_, anyhow::Error>(n + std::fs::metadata(p)?.len()))?;
            if paths.len() >= MAX_RECORDS || total + bytes.len() as u64 > MAX_TOTAL_BYTES {
                fail!("Source acknowledged retention backpressure");
            }
            let temporary = path.with_extension("ack.tmp");
            let mut file = OpenOptions::new().write(true).create(true).truncate(true).open(&temporary)?;
            file.write_all(&bytes)?; file.sync_all()?; drop(file);
            std::fs::rename(temporary, &acknowledged)?;
        }
        File::open(&acknowledged)?.sync_all()?;
        File::open(&self.directory)?.sync_all()?;
        #[cfg(test)]
        if std::env::var("RTOS_SOURCE_FINALITY_CRASH_CUT").as_deref() == Ok("after_ack_commit") {
            std::process::exit(23);
        }
        match std::fs::remove_file(&path) {
            Ok(()) => {},
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
            Err(error) => return Err(error.into()),
        }
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
            if path.extension().and_then(|s| s.to_str()) == Some("acked") {
                let pending = path.with_extension("json");
                if pending.exists() && PendingFinalityRecord::read(&pending)?.encode()? != record.encode()? {
                    fail!("Conflicting pending and acknowledged source records");
                }
                continue;
            }
            let size = record.data.len() + record.signature_set.len();
            if bytes + size > MAX_TOTAL_BYTES as usize || records.len() >= MAX_RECORDS { return Ok(records); }
            bytes += size;
            records.push(PendingFinalityRecovery { store: store.clone(), record });
        }
    }
    Ok(records)
}


/// Session-local admission state. Accepted node work owns this Arc, so source
/// cancellation cannot drop the retention lock or turn an outstanding stage
/// into an acknowledged delivery.
pub(crate) struct SourceFinalityDelivery {
    runtime: Arc<AuthenticatedSessionRuntime>,
    store: Arc<PendingFinalityStore>,
    sink: consensus_common::finality_delivery::DurableFinalitySinkPtr,
    stages: Mutex<std::collections::HashMap<UInt256, SourceStage>>,
}
enum SourceStage {
    Running,
    Retry(std::time::Instant),
    Durable(UInt256, FinalizedDeliveryDraft),
    Acknowledging(UInt256, FinalizedDeliveryDraft),
}
impl SourceFinalityDelivery {
    pub(crate) fn open(runtime: Arc<AuthenticatedSessionRuntime>, namespace: &Path,
        sink: consensus_common::finality_delivery::DurableFinalitySinkPtr) -> Result<Arc<Self>> {
        Ok(Arc::new(Self { runtime, store: PendingFinalityStore::open(namespace)?, sink,
            stages: Mutex::new(std::collections::HashMap::new()) }))
    }
    /// None means not yet durable. Retention precedes every first stage; later
    /// attempts use the exact retained certificate, metadata and creation time.
    pub(crate) fn poll(self: &Arc<Self>, draft: FinalizedDeliveryDraft)
        -> Result<Option<(UInt256, FinalizedDeliveryDraft)>> {
        let record = PendingFinalityRecord::from_draft(&self.runtime, &draft)?;
        let id = record.id()?;
        {
            let mut stages = self.stages.lock().unwrap();
            match stages.get(&id) {
                Some(SourceStage::Running) => return Ok(None),
                Some(SourceStage::Retry(at)) if std::time::Instant::now() < *at => return Ok(None),
                Some(SourceStage::Acknowledging(receipt, draft)) => {
                    self.store.acknowledge(&id, receipt.clone())?;
                    let result = (receipt.clone(), draft.clone());
                    stages.remove(&id);
                    return Ok(Some(result));
                }
                Some(SourceStage::Durable(_, _)) => {
                    let Some(SourceStage::Durable(receipt, draft)) = stages.remove(&id) else { unreachable!() };
                    return Ok(Some((receipt, draft)));
                }
                _ => {}
            }
            stages.insert(id.clone(), SourceStage::Running);
        }
        let prepare = || -> Result<FinalizedDeliveryDraft> {
            let retained = self.store.retain(&record)?;
            let wire: rtos_api::ton::ton_node::SignatureSet = retained.wire_profile.deserialize_typed(&retained.signature_set)?;
            let rtos_api::ton::ton_node::SignatureSet::TonNode_SignatureSet_SimplexPq(value) = wire else { fail!("Retained signature set is not PQ"); };
            let signatures = PqNetworkSignatureSet::from_node(value)?;
            let verifier = self.runtime.pq_context().ok_or_else(|| error!("Missing PQ context"))?.for_block(retained.block_id.clone())?;
            let verified = verifier.verify_network(&signatures)?;
            let finality = if retained.is_final {
                SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(verified.into_final()?.0))
            } else { SessionFinality::PqApproval(verified.into_approval()?.0) };
            Ok(FinalizedDeliveryDraft {
                block_id: retained.block_id,
                source_info: draft.source_info,
                data: consensus_common::ConsensusCommonFactory::create_block_payload(retained.data),
                finality,
                last_mc_finalized_seqno: retained.last_mc_finalized_seqno,
                candidate_already_sent: retained.candidate_already_sent,
                created_at_unix_secs: retained.created_at_unix_secs,
            })
        };
        let draft = match prepare() {
            Ok(draft) => draft,
            Err(error) => { self.retry(&id); return Err(error); }
        };
        let owner = self.clone();
        let completion_id = id.clone();
        let completion_draft = draft.clone();
        if let Err(error) = self.sink.stage(draft, Box::new(move |result| {
            match result {
                Ok(receipt) => {
                    let state = match owner.store.acknowledge(&completion_id, receipt.clone()) {
                        Ok(()) => SourceStage::Durable(receipt, completion_draft),
                        Err(error) => {
                            log::error!("Node WAL durable but source ACK needs retry: {error}");
                            SourceStage::Acknowledging(receipt, completion_draft)
                        }
                    };
                    owner.stages.lock().unwrap().insert(completion_id, state);
                },
                Err(error) => {
                    log::error!("Durable finality stage failed; retained for recovery: {error}");
                    owner.retry(&completion_id);
                }
            }
        })) {
            self.retry(&id);
            return Err(error);
        }
        Ok(None)
    }
    fn retry(&self, id: &UInt256) {
        self.stages.lock().unwrap().insert(id.clone(),
            SourceStage::Retry(std::time::Instant::now() + std::time::Duration::from_millis(250)));
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use consensus_common::finality_delivery::{DurableFinalitySink, FinalizedDeliveryCompletion};
    use rtos_block::*;

    #[derive(Default)]
    pub(crate) struct HeldSink(pub(crate) Mutex<Vec<(FinalizedDeliveryDraft, FinalizedDeliveryCompletion)>>);
    impl DurableFinalitySink for HeldSink {
        fn stage(&self, draft: FinalizedDeliveryDraft, completion: FinalizedDeliveryCompletion) -> Result<()> {
            self.0.lock().unwrap().push((draft, completion)); Ok(())
        }
    }
    pub(crate) fn fixture() -> (Arc<AuthenticatedSessionRuntime>, FinalizedDeliveryDraft) {
        fixture_role(true, ShardIdent::masterchain())
    }
    pub(crate) fn fixture_role(is_final: bool, shard: ShardIdent) -> (Arc<AuthenticatedSessionRuntime>, FinalizedDeliveryDraft) {
        let stores: Vec<_> = [0xa9, 0xaa].iter().map(|seed|
            rtos_pq_consensus::ConsensusKeyStore::from_seed(&[*seed; 32], 0).unwrap()).collect();
        let (_, keys) = crate::pq_fixture::members();
        let members = stores.iter().enumerate().map(|(index, store)| ValidatorDescr::with_pq_params(
            UInt256::from([index as u8 + 1; 32]), store.consensus_key().clone(), index as u64 + 1,
            UInt256::from(*keys[index].id().data()),
        )).collect();
        let observer = Ed25519KeyOption::<ZeroizingBytes>::from_private_key(&[0x71; 32]).unwrap();
        let (runtime, _, _) = crate::authenticated_fixture::runtime_with_members_on_shard(members, observer, shard);
        let mut block = Block::default();
        block.set_global_id(runtime.pin().global_id);
        let mut info = BlockInfo::default(); info.set_seq_no(1).unwrap(); info.set_shard(runtime.shard().clone());
        block.write_info(&info).unwrap();
        let cell = block.serialize().unwrap(); let data = write_boc(&cell).unwrap();
        let block_id = BlockIdExt::with_params(runtime.shard().clone(), 1, cell.repr_hash().clone(), UInt256::calc_file_hash(&data));
        let candidate = rtos_api::ton::consensus::candidatehashdata::CandidateHashDataOrdinary {
            block: block_id.clone(), collated_file_hash: UInt256::default(),
            parent: rtos_api::ton::consensus::CandidateParent::Consensus_CandidateWithoutParents,
        }.into_boxed();
        let candidate_bytes = rtos_api::serialize_boxed(&candidate).unwrap();
        let id = rtos_api::ton::consensus::candidateid::CandidateId {
            slot: 0, hash: UInt256::calc_file_hash(&candidate_bytes),
        }.into_boxed();
        let vote = if is_final {
            rtos_api::ton::consensus::simplex::unsignedvote::FinalizeVote { id }.into_boxed()
        } else {
            rtos_api::ton::consensus::simplex::unsignedvote::NotarizeVote { id }.into_boxed()
        };
        let bytes = crate::utils::create_data_to_sign(runtime.session_id(), &crate::utils::serialize_unsigned_vote(&vote));
        let signatures = stores.iter().zip(runtime.committee()).map(|(store, member)| PqBlockSignaturePair {
            validator_id: member.validator_id().unwrap(), algorithm_id: 1,
            signature: store.sign_consensus(&bytes).unwrap().bytes.to_vec(),
        }).collect();
        let finality = BlockSignaturesSimplexPq {
            validator_info: runtime.pq_context().unwrap().validator_info(), sig_count: 2,
            sig_weight: runtime.committee().iter().map(|member| member.weight).sum(), signatures,
            session_id: runtime.session_id().clone(), slot: 0,
            candidate_data: BlockSignaturesSimplex::bytes_to_cell_tree(&candidate_bytes).unwrap(),
        };
        let finality = if is_final {
            runtime.pq_context().unwrap().for_block(block_id.clone()).unwrap().verify_final(&finality).unwrap();
            SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(finality))
        } else {
            let approval = rtos_api::pq_finality::PqApproval::from_notarization_fields(finality).unwrap();
            runtime.pq_context().unwrap().for_block(block_id.clone()).unwrap().verify_approval(&approval).unwrap();
            SessionFinality::PqApproval(approval)
        };
        let source_info = consensus_common::BlockSourceInfo {
            source: crate::SimplexSessionNode::from_descriptor(&runtime.committee()[0]).unwrap().identity,
            priority: consensus_common::BlockCandidatePriority { round: 0, priority: 0, first_block_round: 0 },
        };
        (runtime, FinalizedDeliveryDraft { block_id, source_info,
            data: consensus_common::ConsensusCommonFactory::create_block_payload(data),
            finality,
            last_mc_finalized_seqno: 41, candidate_already_sent: false, created_at_unix_secs: 123456,
        })
    }
    #[test]
    fn source_finality_held_stage_survives_owner_drop_until_node_wal() {
        let temp = crate::authenticated_fixture::TestDirectory::new();
        let (runtime, draft) = fixture();
        let namespace = PathBuf::from(runtime.runtime_directory(temp.path().to_str().unwrap()).unwrap());
        let sink = Arc::new(HeldSink::default());
        let source = SourceFinalityDelivery::open(runtime, &namespace, sink.clone()).unwrap();
        assert!(source.poll(draft.clone()).unwrap().is_none());
        assert_eq!(source.store.paths().unwrap().len(), 1);
        assert!(source.poll(draft).unwrap().is_none());
        assert_eq!(sink.0.lock().unwrap().len(), 1);
        drop(source);
        assert!(scan_pending_finality(temp.path()).unwrap().is_empty(), "accepted work owns retention lock");
        let (_, complete) = sink.0.lock().unwrap().pop().unwrap();
        complete(Err(error!("WAL failed")));
        let recovered = scan_pending_finality(temp.path()).unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].record().created_at_unix_secs, 123456);
        recovered.into_iter().next().unwrap().acknowledge(UInt256::from([3; 32])).unwrap();
        assert!(scan_pending_finality(temp.path()).unwrap().is_empty());
    }
    #[test]
    fn source_finality_retry_reuses_exact_retained_proof_and_metadata() {
        let temp = crate::authenticated_fixture::TestDirectory::new();
        let (runtime, draft) = fixture();
        let namespace = PathBuf::from(runtime.runtime_directory(temp.path().to_str().unwrap()).unwrap());
        let sink = Arc::new(HeldSink::default());
        let source = SourceFinalityDelivery::open(runtime.clone(), &namespace, sink.clone()).unwrap();
        source.poll(draft.clone()).unwrap();
        let (original, complete) = sink.0.lock().unwrap().pop().unwrap();
        complete(Err(error!("First stage failed")));
        std::thread::sleep(std::time::Duration::from_millis(260));
        let mut changed = draft.clone(); changed.created_at_unix_secs += 500;
        changed.last_mc_finalized_seqno = 99; changed.candidate_already_sent = true;
        if let SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(ref mut proof)) = changed.finality { proof.signatures.reverse(); }
        source.poll(changed).unwrap();
        let (retried, complete) = sink.0.lock().unwrap().pop().unwrap();
        assert_eq!(PendingFinalityRecord::from_draft(&runtime, &original).unwrap().encode().unwrap(),
            PendingFinalityRecord::from_draft(&runtime, &retried).unwrap().encode().unwrap());
        let receipt = UInt256::from([4; 32]); complete(Ok(receipt.clone()));
        assert!(source.store.paths().unwrap().iter().all(|path| path.extension().unwrap() == "acked"));
        assert_eq!(source.poll(draft).unwrap().unwrap().0, receipt);
    }
    #[test]
    fn source_finality_scanner_rejects_unknown_schema_without_deleting_evidence() {
        let temp = crate::authenticated_fixture::TestDirectory::new();
        let (runtime, draft) = fixture();
        let namespace = PathBuf::from(runtime.runtime_directory(temp.path().to_str().unwrap()).unwrap());
        let store = PendingFinalityStore::open(&namespace).unwrap();
        store.retain(&PendingFinalityRecord::from_draft(&runtime, &draft).unwrap()).unwrap();
        let path = store.paths().unwrap().pop().unwrap();
        drop(store);
        let mut disk: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        disk["schema"] = 99.into(); std::fs::write(&path, serde_json::to_vec(&disk).unwrap()).unwrap();
        assert!(scan_pending_finality(temp.path()).is_err());
        assert!(path.exists());
    }
    #[test]
    fn source_finality_approval_and_final_keep_distinct_recoverable_roles() {
        let temp = crate::authenticated_fixture::TestDirectory::new();
        let (runtime, approval) = fixture_role(false, ShardIdent::with_tagged_prefix(0, 0x8000000000000000).unwrap());
        let (_, finality) = fixture_role(true, runtime.shard().clone());
        let namespace = PathBuf::from(runtime.runtime_directory(temp.path().to_str().unwrap()).unwrap());
        let store = PendingFinalityStore::open(&namespace).unwrap();
        let a = PendingFinalityRecord::from_draft(&runtime, &approval).unwrap();
        let f = PendingFinalityRecord::from_draft(&runtime, &finality).unwrap();
        assert_ne!(a.id().unwrap(), f.id().unwrap());
        assert_eq!(a.block_id, f.block_id);
        store.retain(&a).unwrap(); store.retain(&f).unwrap(); drop(store);
        let restored = scan_pending_finality(temp.path()).unwrap();
        assert_eq!(restored.len(), 2);
        assert_eq!(restored.iter().filter(|r| r.record().is_final).count(), 1);
        assert_eq!(restored.iter().filter(|r| !r.record().is_final).count(), 1);
    }

    #[test]
    fn source_finality_process_crash_child() {
        let Ok(root) = std::env::var("RTOS_SOURCE_FINALITY_CHILD_ROOT") else { return; };
        let (runtime, draft) = fixture();
        let namespace = PathBuf::from(runtime.runtime_directory(&root).unwrap());
        let sink = Arc::new(HeldSink::default());
        let source = SourceFinalityDelivery::open(runtime, &namespace, sink.clone()).unwrap();
        source.poll(draft).unwrap();
        let cut = std::env::var("RTOS_SOURCE_FINALITY_CRASH_CUT").unwrap();
        if cut == "before_node_wal" { std::process::exit(21); }
        let (_, complete) = sink.0.lock().unwrap().pop().unwrap();
        complete(Ok(UInt256::from([4; 32])));
        // Real process exit without source controller polling or DB persistence.
        std::process::exit(22);
    }
    #[test]
    fn source_finality_process_restart_preserves_canonical_proof_across_wal_window() {
        for (cut, code) in [("before_node_wal", 21), ("after_ack_commit", 23), ("before_local_finalized", 22)] {
            let temp = crate::authenticated_fixture::TestDirectory::new();
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "finality_delivery::tests::source_finality_process_crash_child", "--nocapture"])
                .env("RTOS_SOURCE_FINALITY_CHILD_ROOT", temp.path())
                .env("RTOS_SOURCE_FINALITY_CRASH_CUT", cut).status().unwrap();
            assert_eq!(status.code(), Some(code), "{cut}");
            let pending = scan_pending_finality(temp.path()).unwrap();
            assert_eq!(pending.len(), usize::from(cut != "before_local_finalized"), "{cut}");
            drop(pending);
            let (runtime, original) = fixture();
            let namespace = PathBuf::from(runtime.runtime_directory(temp.path().to_str().unwrap()).unwrap());
            let sink = Arc::new(HeldSink::default());
            let source = SourceFinalityDelivery::open(runtime.clone(), &namespace, sink.clone()).unwrap();
            let retained_before = PendingFinalityRecord::read(&source.store.paths().unwrap()[0]).unwrap().encode().unwrap();
            let mut rebuilt = original.clone(); rebuilt.created_at_unix_secs += 900;
            if let SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(ref mut proof)) = rebuilt.finality { proof.signatures.reverse(); }
            source.poll(rebuilt).unwrap();
            let (staged, complete) = sink.0.lock().unwrap().pop().unwrap();
            assert_eq!(UInt256::calc_file_hash(&PendingFinalityRecord::from_draft(&runtime, &staged).unwrap().encode().unwrap()),
                UInt256::calc_file_hash(&retained_before), "{cut}");
            complete(Ok(UInt256::from([4; 32])));
            assert!(source.poll(original).unwrap().is_some());
        }
    }

    #[test]
    fn source_finality_admission_reserves_ack_file_and_byte_headroom() {
        let temp = crate::authenticated_fixture::TestDirectory::new();
        let (runtime, draft) = fixture();
        let namespace = PathBuf::from(runtime.runtime_directory(temp.path().to_str().unwrap()).unwrap());
        let store = PendingFinalityStore::open(&namespace).unwrap();
        let record = PendingFinalityRecord::from_draft(&runtime, &draft).unwrap();
        store.retain(&record).unwrap();
        // Fill the advertised logical capacity using valid on-disk records.
        for index in 1..MAX_RECORDS - 1 {
            let mut next = record.clone();
            let mut adnl = [0u8; 32]; adnl[..8].copy_from_slice(&(index as u64).to_be_bytes());
            next.local_adnl = UInt256::from(adnl);
            std::fs::write(store.directory.join(format!("{}.json", next.id().unwrap().to_hex_string())), next.encode().unwrap()).unwrap();
        }
        let mut overflow = record.clone(); overflow.local_adnl = UInt256::from([0xff; 32]);
        assert!(store.retain(&overflow).unwrap_err().to_string().contains("backpressure"));
        // All source capacity may be occupied; already admitted work can still ACK.
        store.acknowledge(&record.id().unwrap(), UInt256::from([1; 32])).unwrap();
        assert_eq!(store.paths().unwrap().len(), MAX_RECORDS - 1);
        assert!(store.directory.join(format!("{}.acked", record.id().unwrap().to_hex_string())).exists());
        let readable = MAX_RECORD_BYTES - ACK_ENVELOPE_RESERVE;
        assert!(check_retention_capacity(0, 0, readable).is_ok());
        assert!(check_retention_capacity(0, 0, readable + 1).is_err());
        assert!(check_retention_capacity(1, MAX_TOTAL_BYTES - MAX_RECORD_BYTES - 1, 1).is_ok());
        assert!(check_retention_capacity(1, MAX_TOTAL_BYTES - MAX_RECORD_BYTES, 1).is_err());
    }

}
