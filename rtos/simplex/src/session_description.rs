/*
 * RTOS project modifications (2026-10-10): naming and durable own-decision journal integration.
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
//! Session description implementation for Simplex consensus
//!
//! Contains session-level constants, validator information, and time management.
//! This module is crate-private.

use crate::{
    block::{SlotIndex, ValidatorIndex, WindowIndex},
    utils::{threshold_33, threshold_66},
    MetricsHandle, PrivateKey, PublicKeyHash, SessionId, SessionOptions, ValidatorWeight,
};
use rtos_block::{error, fail, Result, ShardIdent};
use std::{
    collections::HashMap,
    fmt,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

// ======================================================================
// Source node
// ======================================================================
// Per-validator source record (id, public key, ADNL id, stake weight)
// backing `SessionDescription`'s validator set.

/// Validator source node description
struct Source {
    /// Public key hash for the node
    id: PublicKeyHash,
    /// Public key of the node
    public_key: consensus_common::ValidatorIdentity,
    /// ADNL identifier
    #[allow(dead_code)]
    adnl_id: PublicKeyHash,
    /// Node's weight according to stake
    weight: ValidatorWeight,
}

/// Session description for Simplex consensus
///
/// Contains all immutable session-level configuration:
/// - Session identity (session_id, shard, initial_block_seqno)
/// - Validator set (sources, weights, local key)
/// - Options and timing
pub(crate) struct SessionDescription {
    /// Session identifier
    session_id: SessionId,
    pq_members: Vec<rtos_block::ValidatorDescr>,
    own_signing:
        std::sync::Mutex<Option<std::sync::Arc<crate::signing_coordinator::SigningCoordinator>>>,
    pq_context: Option<rtos_api::pq_finality::PqSessionContext>,
    authenticated_runtime: Option<consensus_common::session_runtime::AuthenticatedSessionRuntime>,
    /// Session options
    options: SessionOptions,
    /// Initial block seqno (first block produced by this session)
    initial_block_seqno: u32,
    /// List of validator sources
    sources: Vec<Source>,
    /// Mapping between public key hash and source index
    #[allow(dead_code)]
    rev_sources: HashMap<PublicKeyHash, ValidatorIndex>,
    /// Total weight of all validators
    total_weight: ValidatorWeight,
    /// Index of this validator in the list of sources
    self_idx: Option<ValidatorIndex>,
    recovery_only: bool,
    /// Shard identifier
    shard: ShardIdent,
    /// Local validator's private key (for signing votes and candidates)
    local_key: PrivateKey,
    /// Session creation time
    session_creation_time: SystemTime,
    /// Current time for log replaying (0 for real-time).
    ///
    /// Stored as unix micros: `0 => real-time`, otherwise `micros_since_epoch + 1`.
    ///
    /// This is atomic so `SessionDescription` can be shared via `Arc<SessionDescription>`
    /// without a mutex (used by tests / log replay).
    replay_time_us: AtomicU64,
    /// Metrics receiver handle
    metrics_receiver: MetricsHandle,
}

// ======================================================================
// Construction
// ======================================================================
// Build the immutable session description from the validator set: compute
// weights, sources and the reverse index, and resolve `self_idx`.
impl SessionDescription {
    /// Create new session description
    ///
    /// # Parameters
    /// * `options` - Session options (immutable configuration)
    /// * `session_id` - Unique session identifier
    /// * `initial_block_seqno` - Expected seqno for the first block produced
    /// * `nodes` - Validator set for this session
    /// * `local_key` - This validator's private key (for signing)
    /// * `shard` - Shard identifier
    /// * `session_creation_time` - When the session was created
    /// * `metrics_receiver` - Optional metrics handle
    pub fn new<N: Clone + Into<crate::SimplexSessionNode>>(
        options: &SessionOptions,
        session_id: SessionId,
        initial_block_seqno: u32,
        nodes: &[N],
        local_key: PrivateKey,
        shard: &ShardIdent,
        session_creation_time: SystemTime,
        metrics_receiver: Option<MetricsHandle>,
    ) -> Result<Self> {
        Self::new_with_runtime(
            options,
            session_id,
            initial_block_seqno,
            nodes,
            local_key,
            shard,
            session_creation_time,
            metrics_receiver,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_runtime<N: Clone + Into<crate::SimplexSessionNode>>(
        options: &SessionOptions,
        session_id: SessionId,
        initial_block_seqno: u32,
        nodes: &[N],
        local_key: PrivateKey,
        shard: &ShardIdent,
        session_creation_time: SystemTime,
        metrics_receiver: Option<MetricsHandle>,
        runtime: Option<&consensus_common::session_runtime::AuthenticatedSessionRuntime>,
    ) -> Result<Self> {
        let nodes: Vec<crate::SimplexSessionNode> = nodes.iter().cloned().map(Into::into).collect();
        let session_id_str = session_id.to_hex_string();

        log::info!("Session {} options: {:?}", session_id_str, options);

        // Find local index for logging (may be missing if node is not in validator set)
        let local_id = local_key.id();
        let local_idx = nodes.iter().position(|n| {
            if n.identity.pq_key().is_some() {
                &n.adnl_id == local_id
            } else {
                n.identity.id() == local_id
            }
        });

        // Calculate weights (same as old log_creation_info)
        let total_weight =
            rtos_block::checked_validator_weight_sum(nodes.iter().map(|n| n.weight))?;
        let threshold_66_weight = threshold_66(total_weight);
        let threshold_33_weight = threshold_33(total_weight);

        log::info!(
            "Session {} creating SessionDescription: nodes={}, local_idx={}, total_weight={}, threshold_66={}, threshold_33={}",
            session_id_str,
            nodes.len(),
            local_idx.map_or("unknown".to_string(), |i| format!("v{i:03}")),
            total_weight,
            threshold_66_weight,
            threshold_33_weight,
        );

        // Log each node on separate line with session_id prefix for grep
        for (idx, node) in nodes.iter().enumerate() {
            let is_local = if Some(idx) == local_idx { " (local)" } else { "" };
            log::info!(
                "Session {} node v{:03}: weight={}, adnl_id={}, public_key_hash={}{}",
                session_id_str,
                idx,
                node.weight,
                node.adnl_id,
                node.identity.id(),
                is_local
            );
        }

        if nodes.iter().any(|n| n.identity.pq_key().is_some())
            && nodes.iter().any(|n| n.identity.pq_key().is_none())
        {
            fail!("mixed classical/PQ Simplex committee is not supported");
        }
        let options = *options;
        let local_id = local_id;

        // Initialize sources
        let mut network_ids = std::collections::HashSet::new();
        let mut sources = Vec::with_capacity(nodes.len());
        let mut rev_sources = HashMap::new();

        for (node_index, node) in nodes.iter().enumerate() {
            let source = Source {
                public_key: node.identity.clone(),
                adnl_id: node.adnl_id.clone(),
                id: node.identity.id().clone(),
                weight: node.weight,
            };

            if rev_sources.insert(source.id.clone(), ValidatorIndex::from(node_index)).is_some() {
                fail!("duplicate validator identity in session");
            }
            if !network_ids.insert(source.adnl_id.clone()) {
                fail!("duplicate validator network identity in session");
            }
            sources.push(source);
        }

        if let Some(runtime) = runtime {
            if runtime.session_id() != &session_id
                || runtime.shard() != shard
                || runtime.local_adnl() != local_key.id()
                || runtime.protocol() != options.protocol
                || runtime.carrier_version() != options.proto_version
                || runtime.slots_per_leader_window() != options.slots_per_leader_window
                || runtime.wire_profile() != options.wire_profile
                || runtime.committee().len() != nodes.len()
            {
                fail!("SessionDescription differs from authenticated runtime");
            }
            for (node, member) in nodes.iter().zip(runtime.committee()) {
                let expected = crate::SimplexSessionNode::from_descriptor(member)?;
                if node.adnl_id != expected.adnl_id
                    || node.identity.id() != expected.identity.id()
                    || node.identity.pq_key() != expected.identity.pq_key()
                    || node.descriptor.as_ref() != Some(member)
                    || node.weight != expected.weight
                {
                    fail!("SessionDescription committee differs from authenticated runtime");
                }
            }
            let role = local_idx
                .map(|i| consensus_common::session_runtime::LocalRole::Validator(i as u32))
                .unwrap_or(consensus_common::session_runtime::LocalRole::Observer);
            if runtime.local_role() != role {
                fail!("Authenticated local role mismatch");
            }
        } else if local_idx.is_none() {
            fail!("Observer requires authenticated session runtime");
        }
        let self_idx = local_idx.map(ValidatorIndex::from);

        let metrics_receiver = metrics_receiver.unwrap_or_else(|| MetricsHandle::new(None));

        let pq_members = nodes.iter().filter_map(|n| n.descriptor.clone()).collect();
        Ok(Self {
            pq_members,
            own_signing: std::sync::Mutex::new(None),
            pq_context: None,
            authenticated_runtime: runtime.cloned(),
            recovery_only: false,
            session_id,
            options,
            initial_block_seqno,
            sources,
            rev_sources,
            total_weight,
            self_idx,
            shard: shard.clone(),
            local_key,
            session_creation_time,
            replay_time_us: AtomicU64::new(0),
            metrics_receiver,
        })
    }
}

// ======================================================================
// Accessors & runtime helpers
// ======================================================================
// Read-only access to identity, options, the validator set, weights /
// thresholds, slot / leader-window mapping, replay-aware time, and the
// metrics handle. Finer groups are marked with lightweight comments.
impl SessionDescription {
    /*
        Session identity
    */

    /// Get session identifier
    pub fn bind_pq_session(mut self, catchain_seqno: u32) -> Result<Self> {
        if !self.pq_members.is_empty() {
            self.pq_context =
                Some(rtos_api::pq_finality::PqSessionContext::from_authenticated_session_members(
                    self.session_id.clone(),
                    self.shard.clone(),
                    catchain_seqno,
                    self.pq_members.clone(),
                )?);
        }
        Ok(self)
    }
    pub(crate) fn authenticated_runtime(&self) -> Option<&consensus_common::session_runtime::AuthenticatedSessionRuntime> {
        self.authenticated_runtime.as_ref()
    }

    pub fn pq_context(&self) -> Option<&rtos_api::pq_finality::PqSessionContext> {
        self.pq_context.as_ref()
    }

    pub fn is_pq(&self) -> bool {
        self.sources.iter().any(|source| source.public_key.pq_key().is_some())
    }

    pub fn sign_own_vote(
        &self,
        vote: &crate::simplex_state::Vote,
    ) -> Result<rtos_api::ton::consensus::simplex::vote::Vote> {
        self.require_validator_index()?;
        if !self.is_pq() {
            return Ok(crate::utils::sign_vote(
                vote,
                &self.session_id,
                self.get_legacy_signing_key()?,
            )?
            .only());
        }
        let guard = self.own_signing.lock().map_err(|_| error!("signer capability poisoned"))?;
        guard.as_ref().ok_or_else(|| error!("PQ consensus signer is Disabled"))?.vote(vote)
    }

    pub fn seal_own_candidate(
        &self,
        candidate: rtos_api::ton::consensus::CandidateData,
    ) -> Result<rtos_api::ton::consensus::CandidateData> {
        self.require_validator_index()?;
        let slot = *candidate.slot();
        if slot < 0 || Some(self.get_leader(SlotIndex::new(slot as u32))) != self.self_idx {
            fail!("candidate signer is not session leader");
        }
        let guard = self.own_signing.lock().map_err(|_| error!("signer capability poisoned"))?;
        guard
            .as_ref()
            .ok_or_else(|| error!("PQ consensus signer is Disabled"))?
            .candidate(candidate)
    }

    pub fn recover_own_journal(&self, bootstrap: &mut crate::database::Bootstrap) -> Result<()> {
        if self.recovery_only { return self.verify_own_journal(&bootstrap.own_journal); }
        let guard = self.own_signing.lock().map_err(|_| error!("signer capability poisoned"))?;
        match guard.as_ref() {
            Some(signer) => signer.recover_bootstrap(bootstrap, self.require_validator_index()?),
            None if bootstrap.own_journal.is_empty() => Ok(()),
            None => fail!("own journal requires authenticated binding"),
        }
    }

    pub fn verify_own_journal(&self, raw: &[(Vec<u8>, Vec<u8>)]) -> Result<()> {
        if self.recovery_only {
            return crate::signing_coordinator::verify_recovery_journal(self.authenticated_runtime.as_ref().ok_or_else(|| error!("Recovery requires authenticated runtime"))?, raw);
        }
        let guard = self.own_signing.lock().map_err(|_| error!("signer capability poisoned"))?;
        match guard.as_ref() {
            Some(signer) => signer.verify_bootstrap(raw),
            None if raw.is_empty() => Ok(()),
            None => {
                fail!("own signing journal requires authenticated network and ownership binding")
            }
        }
    }

    #[cfg(any(test, feature = "isolated-consensus-signing"))]
    pub fn install_test_coordinator(
        &self,
        coordinator: std::sync::Arc<crate::signing_coordinator::SigningCoordinator>,
    ) -> Result<()> {
        self.require_validator_index()?;
        coordinator.check_session(self)?;
        let mut guard =
            self.own_signing.lock().map_err(|_| error!("signer capability poisoned"))?;
        if guard.is_some() {
            fail!("signer capability already installed");
        }
        *guard = Some(coordinator);
        Ok(())
    }

    pub(crate) fn committee_digest(&self) -> rtos_block::UInt256 {
        let mut data = Vec::new();
        for source in &self.sources {
            data.extend_from_slice(source.id.data());
            data.extend_from_slice(source.adnl_id.data());
            data.extend_from_slice(&source.weight.to_le_bytes());
            if let Some(key) = source.public_key.pq_key() {
                data.extend_from_slice(&key.algorithm_id.to_le_bytes());
                data.extend_from_slice(key.key_id.as_slice());
                data.extend_from_slice(&key.public_key);
            }
        }
        rtos_block::UInt256::calc_file_hash(&data)
    }

    pub fn get_session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Get initial block seqno
    pub fn get_initial_block_seqno(&self) -> u32 {
        self.initial_block_seqno
    }

    /// Get local validator's private key
    pub fn get_legacy_signing_key(&self) -> Result<&PrivateKey> {
        self.require_validator_index()?;
        if self.sources.iter().any(|source| source.public_key.pq_key().is_some()) {
            fail!("PQ consensus signer is Disabled");
        }
        Ok(&self.local_key)
    }

    /// Get session creation time
    pub fn get_session_creation_time(&self) -> SystemTime {
        self.session_creation_time
    }

    /*
        Options access
    */

    /// Get session options
    pub fn opts(&self) -> &SessionOptions {
        &self.options
    }

    /*
        Validators management
    */

    /// Get source public key hash by index
    pub fn get_source_public_key_hash(&self, src_idx: ValidatorIndex) -> &PublicKeyHash {
        &self.sources[src_idx.value() as usize].id
    }

    /// Get source public key by index
    pub fn get_source_public_key(
        &self,
        src_idx: ValidatorIndex,
    ) -> &consensus_common::ValidatorIdentity {
        &self.sources[src_idx.value() as usize].public_key
    }

    /// Get source ADNL ID by index
    #[allow(dead_code)]
    pub fn get_source_adnl_id(&self, src_idx: ValidatorIndex) -> &PublicKeyHash {
        &self.sources[src_idx.value() as usize].adnl_id
    }

    /// Get source index by public key hash (returns Result instead of panicking)
    #[allow(dead_code)]
    pub fn get_source_index(&self, public_key_hash: &PublicKeyHash) -> Result<ValidatorIndex> {
        self.rev_sources.get(public_key_hash).copied().ok_or_else(|| {
            error!(
                "SessionDescription::get_source_index: unknown public key hash: {}",
                public_key_hash
            )
        })
    }

    /// Get validator weight by index
    pub fn get_node_weight(&self, src_idx: ValidatorIndex) -> ValidatorWeight {
        self.sources[src_idx.value() as usize].weight
    }

    /// Get total number of nodes
    pub fn get_total_nodes(&self) -> usize {
        self.sources.len()
    }

    /// Get this validator's index
    pub fn get_self_idx(&self) -> ValidatorIndex {
        self.self_idx.expect("validator-only operation requires local validator role")
    }

    pub fn local_validator_index(&self) -> Option<ValidatorIndex> {
        self.self_idx
    }
    pub(crate) fn with_recovery_only(mut self, enabled: bool) -> Self { self.recovery_only = enabled; self }
    pub fn is_validator(&self) -> bool {
        !self.recovery_only && self.self_idx.is_some()
    }
    pub fn require_validator_index(&self) -> Result<ValidatorIndex> {
        if self.recovery_only { fail!("Retired recovery has no signing or voting authority"); }
        self.self_idx.ok_or_else(|| error!("Observer has no signing or voting authority"))
    }
    pub fn local_role_label(&self) -> String {
        self.self_idx.map_or_else(|| "observer".into(), |index| index.to_string())
    }

    /// Check if the given validator index is this validator
    #[inline]
    #[cfg(test)]
    pub fn is_self(&self, idx: ValidatorIndex) -> bool {
        Some(idx) == self.self_idx
    }

    /// Get shard identifier
    pub fn get_shard(&self) -> &ShardIdent {
        &self.shard
    }

    /*
        Weights and thresholds
    */

    /// Get total weight of all validators
    pub fn get_total_weight(&self) -> ValidatorWeight {
        self.total_weight
    }

    /// Get strict 2/3 threshold for certificates (C++: `(total * 2) / 3 + 1`)
    pub fn get_threshold_66(&self) -> ValidatorWeight {
        threshold_66(self.total_weight)
    }

    /// Get strict 1/3 threshold for safety conditions (C++: `total / 3 + 1`)
    pub fn get_threshold_33(&self) -> ValidatorWeight {
        threshold_33(self.total_weight)
    }

    /*
        Slot and leader window helpers
    */

    /// Get window index for a given slot
    pub fn get_window_idx(&self, slot: SlotIndex) -> WindowIndex {
        slot.window_index(self.options.slots_per_leader_window)
    }

    /// Get slot offset within the window (0-based)
    pub fn get_slot_offset_in_window(&self, slot: SlotIndex) -> u32 {
        slot.offset_in_window(self.options.slots_per_leader_window)
    }

    /// Is this the first slot in its leader window?
    #[cfg(test)]
    pub fn is_first_in_window(&self, slot: SlotIndex) -> bool {
        slot.is_first_in_window(self.options.slots_per_leader_window)
    }

    /// Is this the last slot in its leader window?
    #[allow(dead_code)]
    pub fn is_last_in_window(&self, slot: SlotIndex) -> bool {
        slot.is_last_in_window(self.options.slots_per_leader_window)
    }

    /// Get leader for the given slot's window (round-robin by window index)
    pub fn get_leader(&self, slot: SlotIndex) -> ValidatorIndex {
        ValidatorIndex::new(self.get_window_idx(slot).value() % (self.sources.len() as u32))
    }

    /// Is this node the leader for the given slot's window?
    #[cfg(test)]
    pub fn is_self_leader(&self, slot: SlotIndex) -> bool {
        Some(self.get_leader(slot)) == self.self_idx
    }

    /*
        Time management
    */

    /// Set time for log replaying
    #[allow(dead_code)]
    pub fn set_time(&self, time: SystemTime) {
        let micros = match time.duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_micros(),
            Err(_) => 0,
        };

        let micros_u64 = u64::try_from(micros).unwrap_or(u64::MAX - 1);
        self.replay_time_us.store(micros_u64.saturating_add(1), Ordering::Relaxed);
    }

    /// Get current time (SystemTime::now() for real-time, or replayed time)
    pub fn get_time(&self) -> SystemTime {
        let stored = self.replay_time_us.load(Ordering::Relaxed);
        if stored == 0 {
            SystemTime::now()
        } else {
            UNIX_EPOCH + Duration::from_micros(stored - 1)
        }
    }

    /// Check if time is in the future
    pub fn is_in_future(&self, time: SystemTime) -> bool {
        time > self.get_time()
    }

    /// Check if time is in the past
    #[allow(dead_code)]
    pub fn is_in_past(&self, time: SystemTime) -> bool {
        time < self.get_time()
    }

    /*
        Metrics
    */

    /// Get metrics receiver handle
    pub fn get_metrics_receiver(&self) -> &MetricsHandle {
        &self.metrics_receiver
    }
}

// ======================================================================
// Display
// ======================================================================
// Compact one-line summary (node count, total weight, self index).
impl fmt::Display for SessionDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SessionDescription(nodes={}, total_weight={}, self_idx={})",
            self.sources.len(),
            self.total_weight,
            self.local_role_label()
        )
    }
}
