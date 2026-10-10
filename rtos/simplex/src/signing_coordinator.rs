// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Own decisions are separate from peer caches. No production signer is enabled.
//! Synchronous waits run on the session thread, never on the independent storage
//! worker or a storage callback. Any uncertain write poisons this coordinator.
use crate::{block::SlotIndex, database::SimplexDbPtr, simplex_state::Vote, utils};
use consensus_common::ValidatorIdentity;
use rtos_api::{
    ton::consensus::{simplex, CandidateData},
    IntoBoxed,
};
use rtos_block::{error, fail, Result, ShardIdent, UInt256};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub(crate) const PREFIX: &[u8; 4] = b"RSJ1";
const HEADER: &[u8] = b"RSJ1H";
const MAX_RECORD: usize = 64 << 20;
const TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SigningBinding {
    pub schema: u32,
    /// Required constructor-domain binding; absent historical headers fail closed.
    pub wire_profile: u8,
    pub global_id: i32,
    pub zerostate_workchain: i32,
    pub zerostate_root: [u8; 32],
    pub zerostate_file: [u8; 32],
    pub profile: [u8; 32],
    pub session: [u8; 32],
    pub committee: [u8; 32],
    pub validator: [u8; 32],
    pub algorithm: u32,
    pub key_id: [u8; 32],
    pub public_key: Vec<u8>,
    pub generation: u64,
    pub expire_at: u64,
    pub shard_workchain: i32,
    pub shard_prefix: u64,
    pub protocol: u32,
    pub local_index: u32,
    pub validator_count: u32,
    pub slots_per_window: u32,
}

impl SigningBinding {
    fn wire(&self) -> Result<rtos_api::WireProfile> {
        match self.wire_profile {
            0 => Ok(rtos_api::WireProfile::Legacy),
            1 => Ok(rtos_api::WireProfile::T0),
            _ => fail!("unknown signing wire profile"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    binding: SigningBinding,
    retired: bool,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Decision {
    // 0=notarize, 1=finalize, 2=skip, 3=candidate. Hash absent only for skip.
    kind: u8,
    slot: u32,
    hash: Option<[u8; 32]>,
    unsigned: Vec<u8>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    sequence: u64,
    binding: [u8; 32],
    decision: Decision,
    // Complete boxed publication object, never a signature-only cache.
    signed: Option<Vec<u8>>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ownership {
    binding: SigningBinding,
    database: String,
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(value)?)
}
fn decode<T: Serialize + serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.len() > MAX_RECORD {
        fail!("signing journal record exceeds limit");
    }
    let result: T = serde_json::from_slice(bytes)?;
    if encode(&result)? != bytes {
        fail!("noncanonical signing journal record");
    }
    Ok(result)
}
fn tl<T: rtos_api::AnyBoxedSerialize>(bytes: &[u8]) -> Result<T> {
    tl_with_profile(rtos_api::WireProfile::Legacy, bytes)
}
fn tl_with_profile<T: rtos_api::AnyBoxedSerialize>(
    profile: rtos_api::WireProfile,
    bytes: &[u8],
) -> Result<T> {
    let value = profile.deserialize_typed::<T>(bytes)?;
    if profile.serialize(&value)? != bytes {
        fail!("noncanonical signing carrier");
    }
    Ok(value)
}
fn key(decision: &Decision) -> Result<Vec<u8>> {
    let mut result = PREFIX.to_vec();
    result.push(b'D');
    result.extend_from_slice(UInt256::calc_file_hash(&encode(decision)?).as_slice());
    Ok(result)
}
pub(crate) fn validate_record(key_bytes: &[u8], value: &[u8]) -> Result<()> {
    if key_bytes == HEADER {
        let header: Header = decode(value)?;
        if header.binding.schema != 2 {
            fail!("unsupported signing header schema");
        }
        header.binding.wire()?;
    } else {
        let record: Record = decode(value)?;
        if key(&record.decision)? != key_bytes {
            fail!("signing decision key mismatch");
        }
        if record.decision.kind > 3 || (record.decision.kind == 2) != record.decision.hash.is_none()
        {
            fail!("invalid signing decision role");
        }
    }
    Ok(())
}
fn compatible(a: &Decision, b: &Decision) -> bool {
    if a.slot != b.slot {
        return true;
    }
    if a.kind == 3 || b.kind == 3 {
        return a.kind != b.kind || a == b;
    }
    if a.kind == 2 || b.kind == 2 {
        return a.kind != 1 && b.kind != 1;
    }
    a.hash == b.hash
}

#[allow(dead_code)] // Production construction deliberately remains Disabled.
pub(crate) enum Signer {
    Disabled,
    #[cfg(test)]
    PublicTest(Box<dyn Fn(&[u8]) -> Result<Vec<u8>> + Send + Sync>),
}
impl Signer {
    fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Disabled => {
                let _ = bytes;
                fail!("PQ consensus signer is Disabled")
            }
            #[cfg(test)]
            Self::PublicTest(sign) => sign(bytes),
        }
    }
}
struct State {
    header: Header,
    records: BTreeMap<Vec<u8>, Record>,
    poisoned: bool,
}

// No public constructor or configuration enables this capability. Provisioning
// the complete authenticated binding and safe custody is a separate gate.
#[allow(dead_code)]
pub(crate) struct SigningCoordinator {
    db: SimplexDbPtr,
    identity: ValidatorIdentity,
    signer: Signer,
    state: Mutex<State>,
    _ownership: File,
    #[cfg(test)]
    pub test_time: std::sync::Arc<std::sync::atomic::AtomicU64>,
    #[cfg(test)]
    pub fail_at: Mutex<Option<&'static str>>,
}
#[allow(dead_code)]
impl SigningCoordinator {
    /// `initialize` is explicit trusted provisioning, never inferred from an
    /// empty DB. Recover requires the durable ownership marker and DB header.
    /// The caller selects one protected identity-wide directory on this host.
    /// This is not distributed fencing or protection from storage rollback.
    pub fn open(
        db: SimplexDbPtr,
        binding: SigningBinding,
        identity: ValidatorIdentity,
        owner_root: &Path,
        initialize: bool,
        signer: Signer,
    ) -> Result<Self> {
        let pq = identity.pq_key().ok_or_else(|| error!("journal requires PQ identity"))?;
        if binding.schema != 2 {
            fail!("unsupported signing binding schema");
        }
        if binding.protocol > 1
            || binding.generation == 0
            || binding.slots_per_window == 0
            || binding.validator_count == 0
            || binding.local_index >= binding.validator_count
            || binding.validator != *identity.id().data()
            || binding.algorithm != pq.algorithm_id as u32
            || binding.key_id != *pq.key_id.as_array()
            || binding.public_key != pq.public_key
        {
            fail!("signing identity/profile binding mismatch");
        }
        binding.wire()?;
        ShardIdent::with_tagged_prefix(binding.shard_workchain, binding.shard_prefix)?;
        // The protected directory must already exist; provisioning is outside
        // session cache lifecycle and must not be created by untrusted requests.
        let owner_path = owner_root.join(format!("{}.signer", hex::encode(binding.validator)));
        let mut owner =
            OpenOptions::new().read(true).write(true).create_new(initialize).open(&owner_path)?;
        owner.try_lock().map_err(|e| error!("identity writer already owns journal: {e}"))?;
        let ownership = Ownership {
            binding: binding.clone(),
            database: db.get_path().canonicalize()?.to_string_lossy().into_owned(),
        };
        let expected = encode(&ownership)?;
        if initialize {
            owner.write_all(&expected)?;
            owner.sync_all()?;
            File::open(owner_root)?.sync_all()?;
        } else {
            let mut persisted = Vec::new();
            (&mut owner).take((MAX_RECORD + 1) as u64).read_to_end(&mut persisted)?;
            if persisted != expected {
                fail!("identity ownership binding/database/generation mismatch");
            }
        }
        let raw = db.storage.get_by_prefix(PREFIX.to_vec(), None).wait()?;
        let mut header = None;
        let mut records = BTreeMap::new();
        for (k, v) in &raw {
            validate_record(k, v)?;
            if k == HEADER {
                header = Some(decode::<Header>(v)?);
            } else {
                records.insert(k.clone(), decode::<Record>(v)?);
            }
        }
        if initialize && (!records.is_empty() || header.is_some()) {
            fail!("cannot initialize existing signing journal");
        }
        let header = match header {
            Some(h) if h.binding == binding => h,
            Some(_) => fail!("signing journal binding mismatch"),
            None if initialize => {
                let h = Header { binding, retired: false };
                db.storage
                    .set(HEADER.to_vec(), encode(&h)?, None)
                    .wait_timeout(TIMEOUT)
                    .ok_or_else(|| error!("journal initialization timeout"))??;
                // Persist newly created DB directory entries as well as its WAL.
                File::open(db.get_path())?.sync_all()?;
                if let Some(parent) = db.get_path().parent() {
                    File::open(parent)?.sync_all()?;
                }
                h
            }
            None => fail!("initialized signing journal header missing"),
        };
        let result = Self {
            db,
            identity,
            signer,
            state: Mutex::new(State { header, records, poisoned: false }),
            _ownership: owner,
            #[cfg(test)]
            test_time: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            #[cfg(test)]
            fail_at: Mutex::new(None),
        };
        {
            let state = result.state.lock().map_err(|_| error!("journal lock poisoned"))?;
            if state.header.retired {
                fail!("signing generation retired");
            }
            let mut previous = Vec::new();
            let mut sequences = std::collections::BTreeSet::new();
            for record in state.records.values() {
                result.verify_record(&state.header.binding, record)?;
                if !sequences.insert(record.sequence) {
                    fail!("duplicate journal sequence");
                }
                if previous.iter().any(|p| !compatible(p, &record.decision)) {
                    fail!("conflicting durable signing intents");
                }
                previous.push(record.decision.clone());
            }
            if sequences.iter().copied().ne(1..=sequences.len() as u64) {
                fail!("signing journal sequence gap");
            }
        }
        Ok(result)
    }
    pub fn check_session(
        &self,
        description: &crate::session_description::SessionDescription,
    ) -> Result<()> {
        let state = self.state.lock().map_err(|_| error!("journal lock poisoned"))?;
        let b = &state.header.binding;
        if b.session != *description.get_session_id().as_array()
            || b.committee != *description.committee_digest().as_array()
            || b.validator
                != *description.get_source_public_key_hash(description.get_self_idx()).data()
            || b.protocol != description.opts().proto_version
            || b.wire()? != description.opts().wire_profile
            || b.local_index != description.get_self_idx().value()
            || b.validator_count as usize != description.get_total_nodes()
            || b.slots_per_window != description.opts().slots_per_leader_window
            || ShardIdent::with_tagged_prefix(b.shard_workchain, b.shard_prefix)?
                != *description.get_shard()
        {
            fail!("coordinator/session binding mismatch");
        }
        Ok(())
    }
    fn now(&self) -> Result<u64> {
        #[cfg(test)]
        {
            let now = self.test_time.load(std::sync::atomic::Ordering::SeqCst);
            if now != 0 {
                return Ok(now);
            }
        }
        Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
    }
    fn checkpoint(&self, point: &'static str) -> Result<()> {
        #[cfg(test)]
        if self.fail_at.lock().unwrap().as_ref() == Some(&point) {
            fail!("injected signing boundary {point}");
        }
        #[cfg(test)]
        {
            if std::env::var("RTOS_SIGNING_PROBE_ROOT").is_ok() {
                if std::env::var("RTOS_SIGNING_HOLD_AT").as_deref() == Ok(point) {
                    let root = std::path::PathBuf::from(std::env::var("RTOS_SIGNING_PROBE_ROOT")?);
                    File::create(root.join("held"))?.sync_all()?;
                    let start = std::time::Instant::now();
                    while !root.join("release").exists() {
                        if start.elapsed() > Duration::from_secs(10) {
                            fail!("test writer hold timeout");
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
                if std::env::var("RTOS_SIGNING_CRASH_AT").as_deref() == Ok(point) {
                    std::process::exit(77);
                }
                if std::env::var("RTOS_SIGNING_ARM_AT").as_deref() == Ok(point) {
                    File::create(std::env::var("RTOS_WAL_FAIL_ARM")?)?.sync_all()?;
                }
            }
        }
        let _ = point;
        Ok(())
    }
    fn live(&self, state: &mut State) -> Result<()> {
        if state.poisoned || state.header.retired {
            fail!("signing journal stopped/retired");
        }
        if state.header.binding.expire_at != 0 && self.now()? >= state.header.binding.expire_at {
            // Failed persistence poisons this process. Without an external
            // monotonic anchor, an old active header plus clock rollback after
            // restart cannot prove that expiry was previously observed.
            state.header.retired = true;
            self.put(HEADER.to_vec(), encode(&state.header)?)?;
            fail!("signing generation expired and retired");
        }
        Ok(())
    }
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        if value.len() > MAX_RECORD {
            fail!("signing journal record too large");
        }
        self.db
            .storage
            .set(key, value, None)
            .wait_timeout(TIMEOUT)
            .ok_or_else(|| error!("signing journal write timeout"))??;
        Ok(())
    }
    fn preimage(&self, b: &SigningBinding, decision: &Decision) -> Result<Vec<u8>> {
        let unsigned = if decision.kind == 3 {
            utils::create_candidate_id_to_sign(
                SlotIndex::new(decision.slot),
                &UInt256::from(decision.hash.ok_or_else(|| error!("candidate hash missing"))?),
            )
        } else {
            decision.unsigned.clone()
        };
        Ok(utils::create_data_to_sign(&UInt256::from(b.session), &unsigned))
    }
    fn verify_record(&self, b: &SigningBinding, record: &Record) -> Result<()> {
        if record.binding != *UInt256::calc_file_hash(&encode(b)?).as_array() {
            fail!("decision binding mismatch");
        }
        if record.sequence == 0 || record.sequence > i64::MAX as u64 {
            fail!("invalid journal sequence");
        }
        let d = &record.decision;
        let mut canonical = if d.kind == 3 {
            let candidate: CandidateData = tl_with_profile(b.wire()?, &d.unsigned)?;
            let expected = candidate_decision(candidate, b)?;
            if expected != *d {
                fail!("candidate decision/body mismatch");
            }
            None
        } else {
            let unsigned: simplex::UnsignedVote = tl(&d.unsigned)?;
            let vote = utils::tl_unsigned_to_vote(&unsigned)?;
            if vote_decision(&vote)? != *d {
                fail!("vote intent mismatch");
            }
            Some(unsigned)
        };
        if let Some(bytes) = &record.signed {
            let signature = if d.kind == 3 {
                let mut candidate: CandidateData = tl_with_profile(b.wire()?, bytes)?;
                let sig = take_signature(&mut candidate);
                if b.wire()?.serialize(&candidate)? != d.unsigned {
                    fail!("signed candidate body mismatch");
                }
                sig
            } else {
                let vote: simplex::Vote = tl(bytes)?;
                let vote = vote.only();
                if Some(vote.vote) != canonical.take() {
                    fail!("signed vote intent mismatch");
                }
                vote.signature
            };
            self.identity.verify_simplex(&self.preimage(b, d)?, &signature)?;
        }
        Ok(())
    }
    fn authorize(&self, decision: Decision) -> Result<Vec<u8>> {
        let mut state = self.state.lock().map_err(|_| error!("journal lock poisoned"))?;
        let result = (|| {
            self.live(&mut state)?;
            let k = key(&decision)?;
            if state.records.values().any(|r| !compatible(&r.decision, &decision)) {
                fail!("conflicting durable signing decision");
            }
            if let Some(record) = state.records.get(&k) {
                if let Some(bytes) = &record.signed {
                    return Ok(bytes.clone());
                }
            }
            let sequence = match state.records.get(&k) {
                Some(r) => r.sequence,
                None => state
                    .records
                    .values()
                    .map(|r| r.sequence)
                    .max()
                    .unwrap_or(0)
                    .checked_add(1)
                    .ok_or_else(|| error!("journal sequence exhausted"))?,
            };
            let mut record = Record {
                sequence,
                binding: *UInt256::calc_file_hash(&encode(&state.header.binding)?).as_array(),
                decision,
                signed: None,
            };
            self.verify_record(&state.header.binding, &record)?;
            self.checkpoint("before_intent")?;
            self.put(k.clone(), encode(&record)?)?;
            state.records.insert(k.clone(), record.clone());
            self.checkpoint("after_intent")?;
            self.live(&mut state)?;
            self.checkpoint("before_sign")?;
            let preimage = self.preimage(&state.header.binding, &record.decision)?;
            let signature = self.signer.sign(&preimage)?;
            self.checkpoint("after_sign")?;
            self.live(&mut state)?;
            self.identity.verify_simplex(&preimage, &signature)?;
            let bytes = if record.decision.kind == 3 {
                let mut candidate: CandidateData =
                    tl_with_profile(state.header.binding.wire()?, &record.decision.unsigned)?;
                set_signature(&mut candidate, signature);
                state.header.binding.wire()?.serialize(&candidate)?
            } else {
                let vote = tl::<simplex::UnsignedVote>(&record.decision.unsigned)?;
                rtos_api::serialize_boxed(&simplex::vote::Vote { vote, signature }.into_boxed())?
            };
            record.signed = Some(bytes.clone());
            self.checkpoint("before_signed")?;
            self.put(k.clone(), encode(&record)?)?;
            state.records.insert(k, record);
            self.checkpoint("after_signed")?;
            self.live(&mut state)?;
            Ok(bytes)
        })();
        if result.is_err() {
            state.poisoned = true;
        }
        result
    }
    pub fn vote(&self, vote: &Vote) -> Result<simplex::vote::Vote> {
        Ok(tl::<simplex::Vote>(&self.authorize(vote_decision(vote)?)?)?.only())
    }
    pub fn candidate(&self, candidate: CandidateData) -> Result<CandidateData> {
        let binding =
            self.state.lock().map_err(|_| error!("journal lock poisoned"))?.header.binding.clone();
        tl_with_profile(binding.wire()?, &self.authorize(candidate_decision(candidate, &binding)?)?)
    }
    /// Resume only previously committed decisions, then feed the existing
    /// authenticated startup replay. No receiver or network publication here.
    pub fn recover_bootstrap(
        &self,
        bootstrap: &mut crate::database::Bootstrap,
        local: crate::block::ValidatorIndex,
    ) -> Result<()> {
        self.verify_bootstrap(&bootstrap.own_journal)?;
        let (binding, mut records) = {
            let state = self.state.lock().map_err(|_| error!("journal lock poisoned"))?;
            (state.header.binding.clone(), state.records.values().cloned().collect::<Vec<_>>())
        };
        records.sort_by_key(|r| r.sequence);
        for record in records {
            let bytes = self.authorize(record.decision.clone())?;
            let id = crate::block::RawCandidateId {
                slot: SlotIndex::new(record.decision.slot),
                hash: UInt256::from(record.decision.hash.unwrap_or_default()),
            };
            if record.decision.kind == 3 {
                let candidate: CandidateData = tl_with_profile(binding.wire()?, &bytes)?;
                let data = candidate_hash_data(&candidate, &binding)?;
                let info = crate::database::CandidateInfoRecord {
                    candidate_id: id.clone(),
                    leader_idx: local.value(),
                    candidate_hash_data: tl(&data)?,
                    signature: candidate.signature().clone(),
                };
                if let Some(old) = bootstrap.candidate_infos.iter().find(|r| r.candidate_id == id) {
                    if old.leader_idx != info.leader_idx
                        || old.signature != info.signature
                        || rtos_api::serialize_boxed(&old.candidate_hash_data)? != data
                    {
                        fail!("own candidate differs from peer cache");
                    }
                } else {
                    bootstrap.candidate_infos.push(info);
                }
                if let Some((_, old)) =
                    bootstrap.candidate_payloads.iter().find(|(key, _)| key == &id)
                {
                    if old != &bytes {
                        fail!("own candidate payload differs from cache");
                    }
                } else {
                    bootstrap.candidate_payloads.push((id, bytes));
                }
            } else {
                let hash = UInt256::calc_file_hash(&bytes);
                if !bootstrap.votes.iter().any(|r| r.vote_hash == hash && r.node_idx == local) {
                    bootstrap.votes.push(crate::database::VoteRecord {
                        vote_hash: hash,
                        data: bytes,
                        node_idx: local,
                        seqno: record.sequence as i64,
                    });
                }
            }
        }
        bootstrap.own_journal = self.db.storage.get_by_prefix(PREFIX.to_vec(), None).wait()?;
        Ok(())
    }
    pub fn verify_bootstrap(&self, raw: &[(Vec<u8>, Vec<u8>)]) -> Result<()> {
        let state = self.state.lock().map_err(|_| error!("journal lock poisoned"))?;
        let mut expected = vec![(HEADER.to_vec(), encode(&state.header)?)];
        for (k, r) in &state.records {
            expected.push((k.clone(), encode(r)?));
        }
        let mut raw = raw.to_vec();
        raw.sort();
        expected.sort();
        if raw != expected {
            fail!("bootstrap journal differs from admitted journal");
        }
        Ok(())
    }
}
fn vote_decision(vote: &Vote) -> Result<Decision> {
    let (kind, slot, hash) = match vote {
        Vote::Notarize(v) => (0, v.slot, Some(*v.block_hash.as_array())),
        Vote::Finalize(v) => (1, v.slot, Some(*v.block_hash.as_array())),
        Vote::Skip(v) => (2, v.slot, None),
    };
    if slot.value() > i32::MAX as u32 {
        fail!("invalid signing slot");
    }
    Ok(Decision {
        kind,
        slot: slot.value(),
        hash,
        unsigned: utils::serialize_unsigned_vote(&utils::vote_to_tl_unsigned(vote)?),
    })
}
fn take_signature(candidate: &mut CandidateData) -> Vec<u8> {
    match candidate {
        CandidateData::Consensus_Block(c) => std::mem::take(&mut c.signature),
        CandidateData::Consensus_Empty(c) => std::mem::take(&mut c.signature),
    }
}
fn set_signature(candidate: &mut CandidateData, signature: Vec<u8>) {
    match candidate {
        CandidateData::Consensus_Block(c) => c.signature = signature,
        CandidateData::Consensus_Empty(c) => c.signature = signature,
    }
}
fn candidate_decision(mut candidate: CandidateData, b: &SigningBinding) -> Result<Decision> {
    if !take_signature(&mut candidate).is_empty() {
        fail!("candidate intent already signed");
    }
    let shard = ShardIdent::with_tagged_prefix(b.shard_workchain, b.shard_prefix)?;
    let (slot, hash) = match &candidate {
        CandidateData::Consensus_Empty(c) => {
            if *c.parent.slot() < 0 || *c.parent.slot() >= c.slot || c.block.shard() != &shard {
                fail!("invalid empty candidate parent/shard");
            }
            (
                c.slot,
                utils::compute_candidate_id_hash_empty(
                    &c.block,
                    (SlotIndex::new(*c.parent.slot() as u32), c.parent.hash()),
                ),
            )
        }
        CandidateData::Consensus_Block(c) => {
            let parent = match &c.parent {
                rtos_api::ton::consensus::CandidateParent::Consensus_CandidateParent(p) => {
                    if *p.id.slot() < 0 || *p.id.slot() >= c.slot {
                        fail!("invalid candidate parent");
                    }
                    Some((SlotIndex::new(*p.id.slot() as u32), p.id.hash()))
                }
                _ => None,
            };
            (
                c.slot,
                utils::compute_candidate_id_hash_from_bytes(
                    SlotIndex::new(c.slot as u32),
                    &c.candidate,
                    parent,
                    &shard,
                    MAX_RECORD,
                    b.protocol,
                )?,
            )
        }
    };
    if slot < 0 || (slot as u32 / b.slots_per_window) % b.validator_count != b.local_index {
        fail!("invalid candidate slot/leader");
    }
    Ok(Decision {
        kind: 3,
        slot: slot as u32,
        hash: Some(*hash.as_array()),
        unsigned: b.wire()?.serialize(&candidate)?,
    })
}

#[cfg(test)]
#[path = "tests/test_signing_coordinator.rs"]
pub(crate) mod tests;

fn candidate_hash_data(candidate: &CandidateData, b: &SigningBinding) -> Result<Vec<u8>> {
    Ok(match candidate {
        CandidateData::Consensus_Empty(c) => utils::build_candidate_hash_data_bytes_empty(
            &c.block,
            (SlotIndex::new(*c.parent.slot() as u32), c.parent.hash()),
        ),
        CandidateData::Consensus_Block(c) => {
            let shard = ShardIdent::with_tagged_prefix(b.shard_workchain, b.shard_prefix)?;
            let info = utils::extract_block_info_from_candidate(
                &c.candidate,
                &shard,
                MAX_RECORD,
                b.protocol,
            )?
            .ok_or_else(|| error!("full candidate has no block"))?;
            let parent = match &c.parent {
                rtos_api::ton::consensus::CandidateParent::Consensus_CandidateParent(p) => {
                    Some((SlotIndex::new(*p.id.slot() as u32), p.id.hash()))
                }
                _ => None,
            };
            utils::build_candidate_hash_data_bytes(
                Some(&info.block_id),
                Some(&info.collated_file_hash),
                parent,
            )
        }
    })
}
