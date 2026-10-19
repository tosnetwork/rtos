/*
 * RTOS project modifications (2026-10-10): project and crate naming; owned consumer readiness and authenticated finality recovery.
 * Copyright (C) 2019-2024 EverX. All Rights Reserved.
 * Modifications Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This file has been modified from its original version.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::{
    block::BlockStuff,
    block_proof::BlockProofStuff,
    config::{CollatorConfig, CollatorTestBundlesGeneralConfig, TonNodeConfig},
    confirmed_blocks::ConfirmedBlockEvents,
    engine::{EngineFlags, SplitQueues},
    internal_db::BlockResult,
    shard_state::ShardStateStuff,
    shard_states_keeper::PinnedShardStateGuard,
    types::top_block_descr::{TopBlockDescrId, TopBlockDescrStuff},
    validator::{collator::HardforkData, validator_manager::ValidationStatus},
};
#[cfg(feature = "telemetry")]
use crate::{
    full_node::telemetry::FullNodeTelemetry, network::telemetry::FullNodeNetworkTelemetry,
    validator::telemetry::CollatorValidatorTelemetry,
};
#[cfg(feature = "telemetry")]
use adnl::telemetry::Metric;
use adnl::PrivateOverlayShortId;
use catchain::{
    CatchainNode, CatchainOverlay, CatchainOverlayListenerPtr, CatchainOverlayLogReplayListenerPtr,
};
use consensus_common::{BlockSyncOverlayParams, OverlayTransportType};
use rtos_api::ton::{
    engine::validator::customoverlay::CustomOverlay,
    ton_node::{
        broadcast::{BlockBroadcast, ExternalMessageBroadcast, NewShardBlockBroadcast},
        OutMsgQueueProof,
    },
};
use rtos_block::{
    error, AccountId, AccountIdPrefixFull, BlockIdExt, BlockSignaturesVariant, Cell, CellsFactory,
    ConfigParams, CryptoSignaturePair, Deserializable, ImportedMsgQueueLimits, KeyId, KeyOption,
    Message, OutMsgQueue, Result, ShardAccount, ShardIdent, UInt256, UnixTime, MASTERCHAIN_ID,
};
use std::{
    collections::HashSet,
    sync::{atomic::AtomicU64, Arc},
};
#[cfg(feature = "telemetry")]
use storage::StorageTelemetry;
use storage::{block_handle_db::BlockHandle, types::PersistentStatePartId, StorageAlloc};
use validator_session::{BlockHash, PrivateKey, SessionId, ValidatorBlockCandidate};

#[cfg(feature = "telemetry")]
pub struct EngineTelemetry {
    pub storage: Arc<StorageTelemetry>,
    pub awaiters: Arc<Metric>,
    pub catchain_clients: Arc<Metric>,
    pub cells: Arc<Metric>,
    pub cells_mb: Arc<Metric>,
    pub arena_cells: Arc<Metric>,
    pub arena_bytes_mb: Arc<Metric>,
    pub shard_states: Arc<Metric>,
    pub top_blocks: Arc<Metric>,
    pub validator_adnl_keys: Arc<Metric>,
    pub validator_peers: Arc<Metric>,
    pub validator_sets: Arc<Metric>,
    pub account_state_cache_mb: Arc<Metric>,
    pub storage_dicts_cache_cells: Arc<Metric>,
    pub jemalloc_allocated_mb: Arc<Metric>,
    pub jemalloc_resident_mb: Arc<Metric>,
    pub jemalloc_mapped_mb: Arc<Metric>,
    pub jemalloc_retained_mb: Arc<Metric>,
}

pub struct EngineAlloc {
    pub storage: Arc<StorageAlloc>,
    pub awaiters: Arc<AtomicU64>,
    pub catchain_clients: Arc<AtomicU64>,
    pub shard_states: Arc<AtomicU64>,
    pub top_blocks: Arc<AtomicU64>,
    pub validator_adnl_keys: Arc<AtomicU64>,
    pub validator_peers: Arc<AtomicU64>,
    pub validator_sets: Arc<AtomicU64>,
    pub account_state_cache_bytes: Arc<AtomicU64>,
}

/// Config-level binding of a validator key to an election.
///
/// Each entry represents the `(election_id, validator_key, adnl_key)` tuple
/// stored in the node configuration. `election_id` is the primary key —
/// at most one binding must exist per election.
#[derive(Debug, Clone)]
pub struct ValidatorKeyBinding {
    pub election_id: i32,
    pub validator_key_id: String,
    pub validator_adnl_key_id: Option<String>,
    pub expire_at: i32,
}

/// Outcome of [`PrivateOverlayOperations::set_validator_list`].
///
/// Models the result of checking whether the local node belongs to a given validator list.
///
/// # C++ counterpart
///
/// C++ uses `get_validator()` (`manager.cpp`) which returns a `PublicKeyHash`
/// (zero = not a validator). Membership is determined by pubkey-in-set only;
/// ADNL/overlay readiness is handled in transport/context paths, not in the
/// membership outcome itself.
///
/// # Variants
///
/// - `Selected { key, matching_keys }` -- local node's public key is in the
///   validator set. `key` is the first selected local key used for network setup, while
///   `matching_keys` preserves all local matches in C++ `temp_keys_` order so shard subsets
///   can still choose the right local validator key.
/// - `NotValidator` -- no local key matches the validator set.
#[derive(Debug)]
pub enum ValidatorListOutcome {
    Selected { key: Arc<dyn KeyOption>, matching_keys: Vec<Arc<dyn KeyOption>> },
    NotValidator,
}

#[async_trait::async_trait]
pub trait PrivateOverlayOperations: Sync + Send {
    fn wire_profile(&self) -> rtos_api::WireProfile {
        rtos_api::WireProfile::Legacy
    }

    async fn set_validator_list(
        &self,
        validator_list_id: UInt256,
        validators: &[CatchainNode],
    ) -> Result<ValidatorListOutcome>;

    fn has_validator_list_context(&self, validator_list_id: &UInt256) -> bool;

    fn activate_validator_list(&self, validator_list_id: UInt256) -> Result<()>;

    fn remove_validator_list(&self, validator_list_id: UInt256) -> Result<bool>;

    fn create_catchain_client(
        &self,
        validator_list_id: UInt256,
        local_validator_key: &PrivateKey,
        overlay_short_id: &Arc<PrivateOverlayShortId>,
        nodes_public_keys: &[CatchainNode],
        listener: CatchainOverlayListenerPtr,
        _log_replay_listener: CatchainOverlayLogReplayListenerPtr,
        broadcast_hops: Option<u8>,
        transport_type: OverlayTransportType,
        // Block-sync overlay membership/auth + overlay_id (Some only when
        // simplex session has `enable_observers=true`).
        block_sync_params: Option<BlockSyncOverlayParams>,
    ) -> Result<Arc<dyn CatchainOverlay + Send>>;

    /// The governing-state caller supplies an immutable authenticated runtime.
    /// Unlike classical creation, observer transport needs no consensus key match.
    fn create_authenticated_consensus_client(
        &self,
        _validator_list_id: UInt256,
        _local_transport_key: &PrivateKey,
        _overlay_short_id: &Arc<PrivateOverlayShortId>,
        _runtime: Arc<consensus_common::session_runtime::AuthenticatedSessionRuntime>,
        _listener: CatchainOverlayListenerPtr,
        _replay_listener: CatchainOverlayLogReplayListenerPtr,
        _broadcast_hops: Option<u8>,
        _transport_type: OverlayTransportType,
    ) -> Result<consensus_common::ConsensusOverlayPtr> {
        rtos_block::fail!("Authenticated consensus overlay creation is unavailable")
    }

    /// Stop the exact registered generation; unsupported implementations must not
    /// claim success or allow session database ownership to be released.
    fn stop_catchain_client_checked(
        &self,
        _id: &Arc<PrivateOverlayShortId>,
        _overlay: &consensus_common::ConsensusOverlayPtr,
    ) -> Result<()> {
        rtos_block::fail!("Checked consensus overlay shutdown is unavailable")
    }

    fn catchain_client_drained(&self, _overlay: &consensus_common::ConsensusOverlayPtr) -> bool {
        false
    }

    fn stop_catchain_client(&self, overlay_short_id: &Arc<PrivateOverlayShortId>);
}

/// Default window, in seconds, of recent blocks an initial sync downloads
/// instead of starting from a persistent state inside it.
pub const DEFAULT_SYNC_BLOCKS_BEFORE: u32 = 3600;

// TODO make separate traits for read and write operations (may be critical and not etc.)
#[async_trait::async_trait]
#[allow(unused)]
pub trait EngineOperations: Sync + Send {
    // Global node's state

    fn set_sync_status(&self, status: u32) {
        unimplemented!()
    }

    fn get_sync_status(&self) -> u32 {
        unimplemented!()
    }

    fn need_monitor(&self, shard: &ShardIdent) -> Result<bool> {
        Ok(true)
    }

    async fn check_sync(&self) -> Result<bool> {
        unimplemented!()
    }

    fn set_will_validate(&self, will_validate: bool) {
        unimplemented!()
    }

    fn is_validator(&self) -> bool {
        unimplemented!()
    }

    fn get_monitor_min_split(&self) -> u8 {
        unimplemented!()
    }

    // Validator specific operations

    fn consensus_transport_bindings(
        &self,
    ) -> Result<Vec<crate::config::ConsensusTransportBinding>> {
        Ok(Vec::new())
    }

    fn get_validator_status(&self) -> bool {
        unimplemented!()
    }

    fn validator_network(&self) -> Arc<dyn PrivateOverlayOperations> {
        unimplemented!()
    }

    /// returns the underlying `adnl::OverlayNode`
    /// Used by `BlockSyncObserver` to join the block-sync overlay directly
    /// (bypasses the consensus-private-overlay creation path used by validators).
    /// Default `None` for test stubs; the real `Engine` impl returns `Some`
    fn overlay_node(&self) -> Option<Arc<adnl::OverlayNode>> {
        None
    }

    /// look up a local ADNL key by its short id.
    /// Used by `BlockSyncObserver` activation to resolve the validator-class ADNL key
    /// that joins the block-sync overlay. Default `None` for test stubs
    fn adnl_key_by_id(
        &self,
        _id: &Arc<rtos_block::KeyId>,
    ) -> Option<Arc<dyn rtos_block::KeyOption>> {
        None
    }

    fn validation_status(&self) -> ValidationStatus {
        unimplemented!()
    }

    /// Return all `(election_id, validator_key, adnl_key)` bindings known to this node.
    ///
    /// Used by the validator manager to display and verify key uniqueness per election_id.
    fn get_validator_key_bindings(&self) -> Result<Vec<ValidatorKeyBinding>> {
        unimplemented!()
    }

    fn set_validation_status(&self, status: ValidationStatus) {
        unimplemented!()
    }

    fn last_validation_time(&self) -> &lockfree::map::Map<ShardIdent, u64> {
        unimplemented!()
    }

    fn set_last_validation_time(&self, shard: ShardIdent, time: u64) {
        unimplemented!()
    }

    fn remove_last_validation_time(&self, shard: &ShardIdent) {
        unimplemented!()
    }

    fn last_collation_time(&self) -> &lockfree::map::Map<ShardIdent, u64> {
        unimplemented!()
    }

    fn set_last_collation_time(&self, shard: ShardIdent, time: u64) {
        unimplemented!()
    }

    fn remove_last_collation_time(&self, shard: &ShardIdent) {
        unimplemented!()
    }

    fn get_hardfork_data(&self) -> Option<HardforkData> {
        None
    }

    async fn set_validator_list(
        &self,
        validator_list_id: UInt256,
        validators: &[CatchainNode],
    ) -> Result<ValidatorListOutcome> {
        unimplemented!()
    }

    fn activate_validator_list(&self, validator_list_id: UInt256) -> Result<()> {
        unimplemented!()
    }

    fn remove_validator_list(&self, validator_list_id: UInt256) -> Result<bool> {
        unimplemented!()
    }

    fn create_catchain_client(
        &self,
        validator_list_id: UInt256,
        local_validator_key: &PrivateKey,
        overlay_short_id: &Arc<PrivateOverlayShortId>,
        nodes_public_keys: &[CatchainNode],
        listener: CatchainOverlayListenerPtr,
        _log_replay_listener: CatchainOverlayLogReplayListenerPtr,
        broadcast_hops: Option<u8>,
        _transport_type: OverlayTransportType,
        _block_sync_params: Option<BlockSyncOverlayParams>,
    ) -> Result<Arc<dyn CatchainOverlay + Send>> {
        unimplemented!()
    }

    fn stop_catchain_client(&self, overlay_short_id: &Arc<PrivateOverlayShortId>) {
        unimplemented!()
    }

    // Block related operations

    fn load_block_handle(&self, id: &BlockIdExt) -> Result<Option<Arc<BlockHandle>>> {
        unimplemented!()
    }
    async fn load_applied_block(&self, handle: &Arc<BlockHandle>) -> Result<BlockStuff> {
        unimplemented!()
    }
    async fn wait_applied_block(
        &self,
        id: &BlockIdExt,
        timeout_ms: Option<u64>,
    ) -> Result<Arc<BlockHandle>> {
        unimplemented!()
    }
    async fn load_block(&self, handle: &Arc<BlockHandle>) -> Result<BlockStuff> {
        unimplemented!()
    }
    async fn load_block_raw(&self, handle: &Arc<BlockHandle>) -> Result<Vec<u8>> {
        unimplemented!()
    }
    async fn wait_next_applied_mc_block(
        &self,
        prev_handle: &BlockHandle,
        timeout_ms: Option<u64>,
    ) -> Result<(Arc<BlockHandle>, BlockStuff)> {
        unimplemented!()
    }
    async fn load_last_applied_mc_block(&self) -> Result<BlockStuff> {
        unimplemented!()
    }
    fn served_masterchain_cache(&self) -> Option<&crate::served_masterchain::ServedMasterchain> {
        None
    }
    async fn observe_served_shard_progress(&self, id: &BlockIdExt) -> Result<()> {
        if let Some(cache) = self.served_masterchain_cache() {
            cache.observe_shard_progress(self, id).await?;
        }
        Ok(())
    }
    fn load_last_applied_mc_block_id(&self) -> Result<Option<Arc<BlockIdExt>>> {
        unimplemented!()
    }
    fn save_last_applied_mc_block_id(&self, last_mc_block: &BlockIdExt) -> Result<()> {
        unimplemented!()
    }
    async fn check_masterchain_proof_bounded(
        &self,
        proof: &BlockProofStuff,
        budget: Arc<crate::history_read_budget::HistoryReadBudget>,
    ) -> Result<()> {
        crate::block_proof::MasterchainProofVerifier::default()
            .verify_bounded(self, proof, budget)
            .await
            .map(|_| ())
    }
    async fn historical_pq_publication_context_bounded(
        &self,
        id: &BlockIdExt,
        block: &rtos_block::Block,
        budget: Arc<crate::history_read_budget::HistoryReadBudget>,
    ) -> Result<crate::block_proof::PqPublicationContext> {
        crate::block_proof::MasterchainProofVerifier::default()
            .pq_publication_context_bounded(self, id, block, budget)
            .await
    }
    async fn load_block_proof_bounded(
        &self,
        _handle: &Arc<BlockHandle>,
        _is_link: bool,
        _budget: Arc<crate::history_read_budget::HistoryReadBudget>,
    ) -> Result<BlockProofStuff> {
        Err(crate::history_read_budget::UnsupportedBoundedHistoryRead("physical proof loader")
            .into())
    }
    async fn download_block_proof_bounded(
        &self,
        _id: &BlockIdExt,
        _is_link: bool,
        _key_block: bool,
        _budget: Arc<crate::history_read_budget::HistoryReadBudget>,
    ) -> Result<BlockProofStuff> {
        Err(crate::history_read_budget::UnsupportedBoundedHistoryRead("network proof loader")
            .into())
    }

    async fn check_masterchain_proof(&self, proof: &BlockProofStuff) -> Result<()> {
        crate::block_proof::MasterchainProofVerifier::default()
            .verify(self, proof)
            .await
            .map(|_| ())
    }

    async fn historical_pq_broadcast_context(
        &self,
        id: &BlockIdExt,
        block: &rtos_block::Block,
    ) -> Result<rtos_api::pq_finality::PqVerificationContext> {
        crate::block_proof::MasterchainProofVerifier::default()
            .pq_broadcast_context(self, id, block)
            .await
    }

    /// Authenticate both finality context and dissemination policy for recovery.
    /// Persisted protocol/profile fields are claims until matched to this result.
    async fn historical_pq_publication_context(
        &self,
        id: &BlockIdExt,
        block: &rtos_block::Block,
    ) -> Result<crate::block_proof::PqPublicationContext> {
        crate::block_proof::MasterchainProofVerifier::default()
            .pq_publication_context(self, id, block)
            .await
    }

    async fn load_actual_config_params(&self) -> Result<ConfigParams> {
        match self.load_last_applied_mc_block_id()? {
            Some(block_id) => {
                let handle = self
                    .load_block_handle(&block_id)?
                    .ok_or_else(|| error!("no handle for block {}", block_id))?;
                if handle.is_applied() {
                    self.load_state(&block_id).await?.config_params().cloned()
                } else if handle.has_data() {
                    self.load_block(&handle).await?.read_config_params()
                } else if handle.has_proof_link() {
                    self.load_block_proof(&handle, true).await?.get_config_params()
                } else {
                    self.load_block_proof(&handle, false).await?.get_config_params()
                }
            }
            None => {
                let mc_zero_state = self.load_mc_zero_state().await?;
                Ok(mc_zero_state.config_params()?.clone())
            }
        }
    }
    async fn load_last_applied_mc_state(&self) -> Result<Arc<ShardStateStuff>> {
        unimplemented!()
    }
    fn load_shard_client_mc_block_id(&self) -> Result<Option<Arc<BlockIdExt>>> {
        unimplemented!()
    }
    fn save_shard_client_mc_block_id(&self, id: &BlockIdExt) -> Result<()> {
        unimplemented!()
    }
    fn load_last_rotation_block_id(&self) -> Result<Option<Arc<BlockIdExt>>> {
        unimplemented!()
    }
    fn save_last_rotation_block_id(&self, info: &BlockIdExt) -> Result<()> {
        unimplemented!()
    }
    fn load_destroyed_session_ids(&self) -> Result<Vec<UInt256>> {
        unimplemented!()
    }
    fn save_destroyed_session_ids(&self, _ids: &HashSet<UInt256>) -> Result<()> {
        unimplemented!()
    }
    /// Persists the destroyed-session fence together with new cleanup records
    /// in one synced batch; groups may close only after it succeeds.
    fn persist_validator_retirement(
        &self,
        _fence: &HashSet<UInt256>,
        _records: &[consensus_common::validator_cleanup::PendingValidatorCleanup],
    ) -> Result<()> {
        rtos_block::fail!("Validator retirement persistence is unavailable")
    }
    /// One bounded page of durable cleanup records strictly after `after`.
    fn load_validator_cleanup_page(
        &self,
        _after: &str,
        _max_keys: usize,
    ) -> Result<consensus_common::validator_cleanup::Page> {
        rtos_block::fail!("Validator cleanup records are unavailable")
    }
    /// The durable cleanup record of one physical namespace, if any.
    fn load_validator_cleanup_record(
        &self,
        _namespace: &str,
    ) -> Result<Option<consensus_common::validator_cleanup::PendingValidatorCleanup>> {
        rtos_block::fail!("Validator cleanup records are unavailable")
    }
    /// Erases one namespace's cleanup record with a synced write; with
    /// `claim`, the same batch writes that session's candidate cleanup claim.
    fn erase_validator_cleanup_record(
        &self,
        _namespace: &str,
        _claim: Option<&UInt256>,
    ) -> Result<()> {
        rtos_block::fail!("Validator cleanup records are unavailable")
    }
    /// Whether any cleanup record of `session` other than `namespace` (a
    /// canonical namespace of that session) is durable.
    fn session_has_other_cleanup_records(
        &self,
        _namespace: &str,
        _session: &UInt256,
    ) -> Result<bool> {
        rtos_block::fail!("Validator cleanup records are unavailable")
    }
    /// One bounded page of candidate cleanup claims strictly after `after`:
    /// each session with the namespace whose erase wrote the claim, the last
    /// key read and whether the range was exhausted.
    #[allow(clippy::type_complexity)]
    fn load_candidate_claims_page(
        &self,
        _after: &str,
        _max_keys: usize,
    ) -> Result<(Vec<(UInt256, String)>, String, bool)> {
        rtos_block::fail!("Candidate cleanup claims are unavailable")
    }
    /// Synced delete of `session`'s candidate cleanup claim, idempotent.
    /// Engines without candidate storage have nothing to invalidate.
    fn erase_candidate_claim(&self, _session: &UInt256) -> Result<()> {
        Ok(())
    }
    /// Allows `session`'s candidate table to be opened. Engines without
    /// candidate storage have nothing to admit.
    fn admit_candidate_table(&self, _session: &UInt256) -> Result<()> {
        Ok(())
    }
    /// Reserves a retired authenticated namespace for cleanup: no session,
    /// recovery or replay may open it while the reservation is held.
    fn reserve_cleanup_admission(
        &self,
        _session: &UInt256,
        _layout: &consensus_common::validator_cleanup::NamespaceLayout,
    ) -> Result<Option<crate::validator::finality_recovery_owner::RecoveryReservation>> {
        rtos_block::fail!("Cleanup admission is unavailable")
    }
    /// The journaled cleanup attempt of a retired authenticated namespace
    /// under reservation `token`, holding a share of its ownership.
    async fn execute_v2_cleanup(
        self: Arc<Self>,
        _record: consensus_common::validator_cleanup::PendingValidatorCleanup,
        _token: crate::validator::validator_cleanup_gc::AttemptToken,
        _held: Arc<crate::validator::validator_cleanup_gc::CleanupHeld>,
    ) -> crate::validator::validator_cleanup_gc::V2Outcome {
        crate::validator::validator_cleanup_gc::V2Outcome::Kept(
            "Authenticated namespace cleanup is unavailable".into(),
        )
    }
    /// Advances the durable cleanup incarnation with a synced write and
    /// returns it: each process bases its cleanup attempt ids on its own.
    fn next_cleanup_incarnation(&self) -> Result<u64> {
        rtos_block::fail!("Validator cleanup incarnation is unavailable")
    }
    /// Re-writes `record` synced, confirming an uncertain journal write.
    fn rewrite_validator_cleanup_record(
        &self,
        _record: &consensus_common::validator_cleanup::PendingValidatorCleanup,
    ) -> Result<()> {
        rtos_block::fail!("Validator cleanup records are unavailable")
    }
    /// Blocking: deletes `session`'s candidate table for its claim; true only
    /// when it is confirmed gone.
    fn delete_candidate_table(&self, _session: &UInt256) -> Result<bool> {
        rtos_block::fail!("Candidate table deletion is unavailable")
    }
    /// Bootstraps or advances the durable cleanup GC floor by at most one step.
    async fn maintain_validator_cleanup_floor(&self) -> Result<()> {
        rtos_block::fail!("Validator cleanup floor is unavailable")
    }
    /// The published cleanup GC floor and its pinned state; None disables
    /// deletion.
    fn validator_cleanup_floor(&self) -> Option<(BlockIdExt, Arc<ShardStateStuff>)> {
        None
    }
    /// Blocking: deletes one retired namespace already reserved for cleanup;
    /// true only when it is confirmed gone.
    fn delete_validator_consensus_namespace(
        &self,
        _record: &consensus_common::validator_cleanup::PendingValidatorCleanup,
    ) -> Result<bool> {
        rtos_block::fail!("Validator consensus namespace deletion is unavailable")
    }
    fn save_block_candidate(
        &self,
        session_id: &SessionId,
        candidate: Arc<ValidatorBlockCandidate>,
    ) -> Result<()> {
        unimplemented!()
    }
    fn load_block_candidate(
        &self,
        session_id: &SessionId,
        root_hash: &BlockHash,
    ) -> Result<Arc<ValidatorBlockCandidate>> {
        unimplemented!()
    }
    fn destroy_block_candidates(&self, session_id: &SessionId) -> Result<bool> {
        unimplemented!()
    }
    async fn lookup_block_by_seqno(
        &self,
        prefix: &AccountIdPrefixFull,
        seqno: u32,
    ) -> Result<Option<(BlockIdExt, Vec<u8>)>> {
        unimplemented!()
    }
    async fn lookup_block_by_lt(
        &self,
        prefix: &AccountIdPrefixFull,
        lt: u64,
    ) -> Result<Option<(BlockIdExt, Vec<u8>)>> {
        unimplemented!()
    }
    async fn lookup_blocks_by_utime<'a>(
        &self,
        prefix: &AccountIdPrefixFull,
        utime: u32,
        f: Box<dyn FnMut(BlockIdExt, Vec<u8>) -> Result<bool> + Send + 'a>,
    ) -> Result<()> {
        unimplemented!()
    }
    fn find_full_block_id(&self, root_hash: &UInt256) -> Result<Option<BlockIdExt>> {
        unimplemented!()
    }
    async fn apply_block(
        self: Arc<Self>,
        handle: &Arc<BlockHandle>,
        block: &BlockStuff,
        mc_seq_no: u32,
        pre_apply: bool,
    ) -> Result<()> {
        self.apply_block_internal(handle, block, mc_seq_no, pre_apply, 0).await
    }
    async fn apply_block_internal(
        self: Arc<Self>,
        handle: &Arc<BlockHandle>,
        block: &BlockStuff,
        mc_seq_no: u32,
        pre_apply: bool,
        recursion_depth: u32,
    ) -> Result<()> {
        unimplemented!()
    }
    async fn download_and_apply_block(
        self: Arc<Self>,
        id: &BlockIdExt,
        mc_seq_no: u32,
        pre_apply: bool,
    ) -> Result<()> {
        self.download_and_apply_block_internal(id, mc_seq_no, pre_apply, 0).await
    }
    async fn download_and_apply_block_internal(
        self: Arc<Self>,
        id: &BlockIdExt,
        mc_seq_no: u32,
        pre_apply: bool,
        recursion_depth: u32,
    ) -> Result<()> {
        unimplemented!()
    }
    async fn download_block(
        &self,
        id: &BlockIdExt,
        limit: Option<u32>,
    ) -> Result<(BlockStuff, BlockProofStuff)> {
        unimplemented!()
    }
    async fn download_block_proof(
        &self,
        id: &BlockIdExt,
        is_link: bool,
        key_block: bool,
    ) -> Result<BlockProofStuff> {
        unimplemented!()
    }
    async fn download_next_block(
        &self,
        prev_id: &BlockIdExt,
    ) -> Result<(BlockStuff, BlockProofStuff)> {
        unimplemented!()
    }
    async fn download_next_key_blocks_ids(&self, block_id: &BlockIdExt) -> Result<Vec<BlockIdExt>> {
        unimplemented!()
    }
    async fn download_out_msg_queue_proof(
        &self,
        dst_shard: &ShardIdent,
        ids: &[BlockIdExt],
        limits: &ImportedMsgQueueLimits,
    ) -> Result<OutMsgQueueProof> {
        unimplemented!()
    }
    async fn store_block(&self, block: &BlockStuff) -> Result<BlockResult> {
        unimplemented!()
    }
    async fn store_block_proof(
        &self,
        id: &BlockIdExt,
        handle: Option<Arc<BlockHandle>>,
        proof: &BlockProofStuff,
    ) -> Result<BlockResult> {
        unimplemented!()
    }
    async fn load_block_proof(
        &self,
        handle: &Arc<BlockHandle>,
        is_link: bool,
    ) -> Result<BlockProofStuff> {
        unimplemented!()
    }
    async fn load_block_proof_raw(
        &self,
        handle: &Arc<BlockHandle>,
        is_link: bool,
    ) -> Result<Vec<u8>> {
        unimplemented!()
    }

    // This function WAITS the shard account belonging to the shard's last committed state.
    async fn load_account(
        self: Arc<Self>,
        wc: i32,
        address: AccountId,
    ) -> Result<(ShardAccount, ShardIdent)> {
        let last_mc_state = self.load_last_applied_mc_state().await?;

        if wc == MASTERCHAIN_ID {
            let acc =
                last_mc_state.state()?.read_accounts()?.account(&address)?.ok_or_else(|| {
                    error!(
                        "Can't get account {:x} from last master state {}",
                        address,
                        last_mc_state.block_id()
                    )
                })?;
            Ok((acc, last_mc_state.block_id().shard().clone()))
        } else {
            let prefix =
                AccountIdPrefixFull::workchain(wc, u64::construct_from(&mut address.clone())?);
            let shard_header = last_mc_state
                .shards()?
                .find_shard_by_prefix(&prefix)?
                .ok_or_else(|| error!("Can't get shard for prefix {}", prefix))?;
            let last_shard_state =
                self.wait_state(&shard_header.block_id, Some(10_000), false).await?;
            let acc =
                last_shard_state.state()?.read_accounts()?.account(&address)?.ok_or_else(|| {
                    error!(
                        "Can't get account {:x} from state {}",
                        address,
                        last_shard_state.block_id()
                    )
                })?;
            Ok((acc, last_shard_state.block_id().shard().clone()))
        }
    }

    fn cache_block_candidate(
        &self,
        id: &BlockIdExt,
        cc_seqno: u32,
        validator_set_hash: u32,
        signature: CryptoSignaturePair,
        block_data: Vec<u8>,
    ) -> Result<()> {
        unimplemented!()
    }

    // State related operations

    async fn download_persistent_state(
        &self,
        id: PersistentStatePartId,
        master_id: &BlockIdExt,
        attempts: Option<usize>,
    ) -> Result<(usize, usize)> {
        // (bytes, cells_count)
        unimplemented!()
    }

    // Deserialize BOC and save to cells DB.
    async fn apply_persistent_state(
        &self,
        handle: &Arc<BlockHandle>,
        root_hash: &UInt256,
        data: Arc<Vec<u8>>,
        cells_index: Vec<(UInt256, u16)>,
    ) -> Result<(Arc<ShardStateStuff>, Vec<(UInt256, u16)>)> {
        unimplemented!()
    }

    async fn apply_persistent_state_part(
        &self,
        id: &PersistentStatePartId,
        data: Arc<Vec<u8>>,
        cells_index: Vec<(UInt256, u16)>,
    ) -> Result<(Cell, Vec<(UInt256, u16)>)> {
        unimplemented!()
    }

    async fn apply_persistent_state_header(
        &self,
        handle: &Arc<BlockHandle>,
        root_hash: &UInt256,
        part_root_hashes: &[UInt256],
        header_boc: Arc<Vec<u8>>,
    ) -> Result<Arc<ShardStateStuff>> {
        unimplemented!()
    }

    // Cleanup all persistent states except given.
    // Used for cleaning partially downloaded states after unsuccesfull boot attempts.
    async fn cleanup_persistent_states(&self) -> Result<()> {
        unimplemented!()
    }

    async fn download_zerostate(&self, id: &BlockIdExt) -> Result<(Arc<ShardStateStuff>, Vec<u8>)> {
        unimplemented!()
    }
    fn zerostate_id(&self) -> Result<&BlockIdExt> {
        unimplemented!()
    }
    async fn load_mc_zero_state(&self) -> Result<Arc<ShardStateStuff>> {
        unimplemented!()
    }
    async fn authenticate_closing_source_with_history(
        self: Arc<Self>,
        _request: consensus_common::finality_delivery::CloseFinalityRequest,
        _namespace: std::path::PathBuf,
    ) -> Result<Arc<consensus_common::session_runtime::AuthenticatedSessionRuntime>> {
        Err(error!("Owned historical closing recovery unsupported"))
    }
    async fn authenticate_retired_source_with_history(
        self: Arc<Self>,
        _record: simplex::finality_recovery::SessionRecoveryRecord,
    ) -> Result<crate::validator::retired_session_auth::AuthenticatedRetiredSession> {
        Err(error!("Owned historical source recovery unsupported"))
    }
    async fn load_state_bounded(
        &self,
        _id: &BlockIdExt,
        _budget: Arc<crate::history_read_budget::HistoryReadBudget>,
    ) -> Result<Arc<ShardStateStuff>> {
        Err(crate::history_read_budget::UnsupportedBoundedHistoryRead("state graph").into())
    }
    async fn load_last_applied_mc_state_bounded(
        &self,
        budget: Arc<crate::history_read_budget::HistoryReadBudget>,
    ) -> Result<Arc<ShardStateStuff>> {
        let id = self
            .load_last_applied_mc_block_id()?
            .ok_or_else(|| error!("Missing last applied state"))?;
        self.load_state_bounded(&id, budget).await
    }
    async fn load_mc_zero_state_bounded(
        &self,
        budget: Arc<crate::history_read_budget::HistoryReadBudget>,
    ) -> Result<Arc<ShardStateStuff>> {
        let id = self.zerostate_id()?;
        let state = self.load_state_bounded(id, budget).await?;
        state.verify_zerostate(id)?;
        Ok(state)
    }
    async fn load_state(&self, block_id: &BlockIdExt) -> Result<Arc<ShardStateStuff>> {
        unimplemented!()
    }

    // It is prohibited to use any cell from the state after the guard's disposal.
    async fn load_and_pin_state(&self, block_id: &BlockIdExt) -> Result<PinnedShardStateGuard> {
        unimplemented!()
    }
    async fn load_persistent_state_size(&self, id: &PersistentStatePartId) -> Result<u64> {
        unimplemented!()
    }
    async fn load_persistent_state_slice(
        &self,
        handle: &PersistentStatePartId,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>> {
        unimplemented!()
    }
    async fn load_persistent_state_to(
        &self,
        id: &PersistentStatePartId,
        buffer: &mut Vec<u8>,
    ) -> Result<()> {
        unimplemented!()
    }
    async fn wait_state(
        self: Arc<Self>,
        id: &BlockIdExt,
        timeout_ms: Option<u64>,
        allow_block_downloading: bool,
    ) -> Result<Arc<ShardStateStuff>> {
        unimplemented!()
    }
    async fn store_state(
        &self,
        handle: &Arc<BlockHandle>,
        state: Arc<ShardStateStuff>,
    ) -> Result<Arc<ShardStateStuff>> {
        unimplemented!()
    }
    async fn store_state_update(
        &self,
        handle: &Arc<BlockHandle>,
        state_update: Cell,
    ) -> Result<()> {
        unimplemented!()
    }
    async fn store_zerostate(
        &self,
        state: Arc<ShardStateStuff>,
        state_bytes: &[u8],
    ) -> Result<(Arc<ShardStateStuff>, Arc<BlockHandle>)> {
        unimplemented!()
    }

    // Block next prev links

    fn store_block_prev1(&self, handle: &Arc<BlockHandle>, prev: &BlockIdExt) -> Result<()> {
        unimplemented!()
    }
    fn load_block_prev1(&self, id: &BlockIdExt) -> Result<BlockIdExt> {
        unimplemented!()
    }
    fn store_block_prev2(&self, handle: &Arc<BlockHandle>, prev2: &BlockIdExt) -> Result<()> {
        unimplemented!()
    }
    fn load_block_prev2(&self, id: &BlockIdExt) -> Result<Option<BlockIdExt>> {
        unimplemented!()
    }
    fn store_block_next1(&self, handle: &Arc<BlockHandle>, next: &BlockIdExt) -> Result<()> {
        unimplemented!()
    }
    fn load_block_next1(&self, id: &BlockIdExt) -> Result<BlockIdExt> {
        unimplemented!()
    }
    fn store_block_next2(&self, handle: &Arc<BlockHandle>, next2: &BlockIdExt) -> Result<()> {
        unimplemented!()
    }
    fn load_block_next2(&self, id: &BlockIdExt) -> Result<Option<BlockIdExt>> {
        unimplemented!()
    }

    // Top shard blocks

    // Get current list of new shard blocks with respect to last mc block.
    // If given mc_seq_no is not equal to last mc seq_no - function fails.
    async fn get_shard_blocks(
        &self,
        last_mc_state: &Arc<ShardStateStuff>,
        actual_last_mc_seqno: Option<&mut u32>,
    ) -> Result<Vec<Arc<TopBlockDescrStuff>>> {
        unimplemented!()
    }
    async fn get_own_shard_blocks(
        &self,
        last_mc_state: &Arc<ShardStateStuff>,
        actual_last_mc_seqno: Option<&mut u32>,
    ) -> Result<Vec<Arc<TopBlockDescrStuff>>> {
        unimplemented!()
    }

    // Save tsb into persistent storage
    fn save_top_shard_block(&self, id: &TopBlockDescrId, tsb: &TopBlockDescrStuff) -> Result<()> {
        unimplemented!()
    }

    // Remove tsb from persistent storage
    fn remove_top_shard_block(&self, id: &TopBlockDescrId) -> Result<()> {
        unimplemented!()
    }

    // External messages
    fn new_external_message(&self, id: &UInt256, message: Arc<Message>) -> Result<()> {
        unimplemented!()
    }
    fn get_external_messages(&self, shard: &ShardIdent) -> Result<Vec<(Arc<Message>, UInt256)>> {
        unimplemented!()
    }
    fn get_external_messages_iterator(
        &self,
        shard: ShardIdent,
        finish_time_ms: u64,
    ) -> Box<dyn Iterator<Item = (Arc<Message>, UInt256)> + Send + Sync> {
        unimplemented!()
    }
    fn get_external_messages_len(&self) -> u32 {
        0
    }
    fn complete_external_messages(
        &self,
        to_delay: &[UInt256],
        to_delete: &[UInt256],
    ) -> Result<()> {
        unimplemented!()
    }
    fn confirmed_block_events(&self) -> Option<ConfirmedBlockEvents> {
        None
    }

    // Utils

    fn now(&self) -> u32 {
        UnixTime::now() as u32
    }

    fn now_ms(&self) -> u64 {
        UnixTime::now_ms()
    }

    fn is_persistent_state(&self, block_time: u32, prev_time: u32, pss_period_bits: u32) -> bool {
        block_time >> pss_period_bits != prev_time >> pss_period_bits
    }

    fn persistent_state_ttl(&self, block_time: u32, pss_period_bits: u32) -> u32 {
        let x = block_time >> pss_period_bits;
        debug_assert!(x != 0);
        block_time + ((1 << (pss_period_bits + 1)) << x.trailing_zeros())
    }

    // Options

    fn get_last_fork_masterchain_seqno(&self) -> u32 {
        self.hardforks().last().map_or(0, |block_id| block_id.seq_no)
    }

    fn hardforks(&self) -> &[BlockIdExt] {
        unimplemented!()
    }

    fn flags(&self) -> &EngineFlags {
        unimplemented!()
    }

    // Time in past to get blocks in: a cold boot starts from a key block at
    // least this old and downloads the blocks after it.
    fn sync_blocks_before(&self) -> u32 {
        DEFAULT_SYNC_BLOCKS_BEFORE
    }

    fn key_block_utime_step(&self) -> u32 {
        86400 // One day period
    }

    // Is got from global config
    fn init_mc_block_id(&self) -> &BlockIdExt {
        unimplemented!()
    }

    fn save_init_mc_block_id(&self, _init_block_id: &BlockIdExt) -> Result<()> {
        unimplemented!()
    }

    fn test_bundles_config(&self) -> &CollatorTestBundlesGeneralConfig {
        unimplemented!()
    }

    fn collator_config(&self) -> &CollatorConfig {
        unimplemented!()
    }

    fn collator_config_mc(&self) -> &CollatorConfig {
        unimplemented!()
    }

    fn db_root_dir(&self) -> Result<&str> {
        Ok(TonNodeConfig::DEFAULT_DB_ROOT)
    }

    fn produce_shard_hashes_enabled(&self) -> bool {
        unimplemented!()
    }

    fn adjust_states_gc_interval(&self, interval_ms: u32) {
        unimplemented!()
    }

    // I/O

    async fn send_ext_message_broadcast(
        &self,
        to: &AccountIdPrefixFull,
        data: &[u8],
    ) -> Result<()> {
        unimplemented!()
    }

    async fn ensure_publication_acceptance_durable(
        self: Arc<Self>,
        _accepted: &crate::validator::accept_block::AcceptedSessionBlock,
    ) -> Result<()> {
        rtos_block::fail!("Durable publication acceptance is unsupported")
    }

    fn reserve_normal_session_namespace(
        &self,
        _runtime: &consensus_common::session_runtime::AuthenticatedSessionRuntime,
    ) -> Result<Option<crate::validator::finality_recovery_owner::RecoveryReservation>> {
        rtos_block::fail!("Atomic consensus namespace admission is unavailable")
    }

    fn finality_recovery_generation(&self) -> u64 {
        0
    }
    fn finality_recovery_owns(
        &self,
        _runtime: &consensus_common::session_runtime::AuthenticatedSessionRuntime,
    ) -> bool {
        false
    }
    async fn wait_finality_recovery_change(&self, _seen: u64) -> Result<()> {
        std::future::pending().await
    }

    /// Persist independently authenticated history before a v2 source can
    /// retain certificate debt. Implementations must own outstanding I/O even
    /// if the group preparing this session is cancelled.
    async fn prepare_retired_history(
        self: Arc<Self>,
        _runtime: Arc<consensus_common::session_runtime::AuthenticatedSessionRuntime>,
        _start_mc: BlockIdExt,
    ) -> Result<()> {
        rtos_block::fail!("Retired history preparation unsupported")
    }

    async fn durable_finality_sink(
        self: Arc<Self>,
        _runtime: Arc<consensus_common::session_runtime::AuthenticatedSessionRuntime>,
    ) -> Result<consensus_common::finality_delivery::DurableFinalitySinkPtr> {
        rtos_block::fail!("Durable finality sink is unavailable")
    }
    /// Optional on compatibility engines; an absent callback preserves source
    /// retention and never permits a Delivered transition.
    async fn durable_finality_delivered_sink(
        self: Arc<Self>,
        _runtime: Arc<consensus_common::session_runtime::AuthenticatedSessionRuntime>,
    ) -> Result<Option<simplex::finality_delivery::DeliveredCompletionSink>> {
        Ok(None)
    }
    async fn await_publication(
        self: Arc<Self>,
        _delivery_id: UInt256,
    ) -> Result<crate::validator::accept_block::AcceptedSessionBlock> {
        rtos_block::fail!("Durable finality query is unavailable")
    }
    async fn recover_finality_delivery(
        self: Arc<Self>,
        _record: crate::propagation_outbox::PublicationRecord,
        _last_mc: u32,
        _candidate_already_sent: bool,
        _origin: crate::propagation_outbox::RecoveryOrigin,
    ) -> Result<UInt256> {
        rtos_block::fail!("Durable finality recovery is unavailable")
    }

    async fn submit_publication(
        self: Arc<Self>,
        _record: crate::propagation_outbox::PublicationRecord,
    ) -> Result<crate::validator::accept_block::AcceptedSessionBlock> {
        rtos_block::fail!("Durable publication submission is unavailable")
    }

    async fn resolve_propagation_targets(
        &self,
        id: &BlockIdExt,
        plan: &crate::validator::propagation::PropagationPlan,
    ) -> Result<Vec<crate::validator::propagation::PropagationDestination>> {
        rtos_block::fail!("Propagation destination resolution is unavailable")
    }

    /// Propagation reports never undo or obscure an already durable acceptance.
    async fn propagate_accepted_session_block(
        &self,
        _accepted: &crate::validator::accept_block::AcceptedSessionBlock,
        plan: &crate::validator::propagation::PropagationPlan,
    ) -> crate::validator::propagation::PropagationOutcome {
        use crate::validator::propagation::*;
        let mut outcome = PropagationOutcome::failed_for_plan(
            PropagationKind::Block,
            plan,
            "Accepted-block propagation is unavailable",
        );
        outcome.receipts.extend(
            PropagationOutcome::failed_for_plan(
                PropagationKind::Finality,
                plan,
                "Finality propagation is unavailable",
            )
            .receipts,
        );
        if plan.send_shard_description {
            outcome.record(
                PropagationKind::ShardDescription,
                PropagationTarget::ShardDescription,
                PropagationStatus::Failed("Shard-description propagation is unavailable".into()),
            );
        }
        outcome
    }

    async fn relay_validated_candidate(
        &self,
        _candidate: &crate::validator::propagation::ValidatedCandidateRelay,
        plan: &crate::validator::propagation::PropagationPlan,
    ) -> crate::validator::propagation::PropagationOutcome {
        use crate::validator::propagation::*;
        PropagationOutcome::failed_for_plan(
            PropagationKind::Candidate,
            plan,
            "Candidate propagation is unavailable",
        )
    }

    async fn send_block_broadcast(
        &self,
        block: &BlockStuff,
        proof: &BlockProofStuff,
        signatures: &BlockSignaturesVariant,
    ) -> Result<()> {
        unimplemented!()
    }

    async fn register_top_shard_block_description(
        &self,
        _tbd: Arc<TopBlockDescrStuff>,
        _cc_seqno: u32,
    ) -> Result<()> {
        rtos_block::fail!("Local shard description registration is unavailable")
    }

    async fn send_top_shard_block_description(
        &self,
        tbd: Arc<TopBlockDescrStuff>,
        cc_seqno: u32,
        is_resend: bool,
    ) -> Result<()> {
        unimplemented!()
    }

    async fn send_block_candidate_broadcast(
        &self,
        id: &BlockIdExt,
        cc_seqno: u32,
        validator_set_hash: u32,
        block_root: &Cell,
    ) -> Result<()> {
        unimplemented!()
    }

    async fn redirect_external_message(&self, message_data: &[u8]) -> Result<()> {
        unimplemented!()
    }

    async fn update_validators(
        &self,
        to_resolve: Vec<CatchainNode>,
        to_delete: Vec<CatchainNode>,
    ) -> Result<()> {
        unimplemented!()
    }

    fn process_block_broadcast(self: Arc<Self>, broadcast: BlockBroadcast, src: Arc<KeyId>) {
        unimplemented!()
    }

    async fn process_block_finality_broadcast(
        self: Arc<Self>,
        broadcast: rtos_api::ton::ton_node::broadcast::BlockFinalityBroadcast,
        src: Arc<KeyId>,
        received_bytes: usize,
    ) -> Result<()> {
        rtos_block::fail!("Finality broadcast consumer is unavailable")
    }

    fn process_block_broadcast_v2(
        self: Arc<Self>,
        broadcast: crate::network::BlockBroadcastV2,
        src: Arc<KeyId>,
    ) {
        unimplemented!()
    }

    async fn process_ext_msg_broadcast(
        &self,
        broadcast: ExternalMessageBroadcast,
        src: Arc<KeyId>,
    ) {
        unimplemented!()
    }

    fn process_new_shard_block_broadcast(
        self: Arc<Self>,
        broadcast: NewShardBlockBroadcast,
        src: Arc<KeyId>,
    ) {
        unimplemented!()
    }

    // Boot specific operations

    async fn set_applied(&self, handle: &Arc<BlockHandle>, mc_seq_no: u32) -> Result<bool> {
        unimplemented!()
    }

    async fn get_archive_id(&self, mc_seq_no: u32, shard: &ShardIdent) -> Option<u64> {
        unimplemented!()
    }

    async fn get_archive_slice(&self, archive_id: u64, offset: u64, limit: u32) -> Result<Vec<u8>> {
        unimplemented!()
    }

    async fn download_archive(
        &self,
        shard: Option<ShardIdent>,
        masterchain_seqno: u32,
    ) -> Result<Option<Vec<u8>>> {
        unimplemented!()
    }

    #[cfg(feature = "telemetry")]
    fn full_node_telemetry(&self) -> &FullNodeTelemetry {
        unimplemented!()
    }

    #[cfg(feature = "telemetry")]
    fn collator_telemetry(&self) -> &CollatorValidatorTelemetry {
        unimplemented!()
    }

    #[cfg(feature = "telemetry")]
    fn validator_telemetry(&self) -> &CollatorValidatorTelemetry {
        unimplemented!()
    }

    #[cfg(feature = "telemetry")]
    fn full_node_service_telemetry(&self) -> &FullNodeNetworkTelemetry {
        unimplemented!()
    }

    #[cfg(feature = "telemetry")]
    fn engine_telemetry(&self) -> &Arc<EngineTelemetry> {
        unimplemented!()
    }

    fn engine_allocated(&self) -> &Arc<EngineAlloc> {
        unimplemented!()
    }

    fn calc_tps(&self, period: u64) -> Result<u32> {
        unimplemented!()
    }

    // Engine stopping

    /// Atomically register a service before starting its actual worker.
    fn register_service_task(
        &self,
        name: &'static str,
        mask: u32,
        start: Box<dyn FnOnce() -> tokio::task::JoinHandle<()> + Send>,
    ) -> Result<tokio::task::JoinHandle<()>> {
        rtos_block::fail!("Engine does not provide owned service registration: {name}");
    }

    fn acquire_stop(&self, mask: u32) {
        unimplemented!();
    }

    fn check_stop(&self) -> bool {
        unimplemented!();
    }

    fn release_stop(&self, mask: u32) {
        unimplemented!();
    }

    /// Terminal failure after the service drained its owned work. Never clears its bit.
    fn report_service_failure(&self, mask: u32, error: String) {
        unimplemented!(
            "EngineOperations must report terminal service failure {mask:#06x}: {error}"
        );
    }

    fn set_split_queues_calculating(&self, before_split_block: &BlockIdExt) -> bool {
        true
    }

    fn set_split_queues(
        &self,
        before_split_block: &BlockIdExt,
        queue0: OutMsgQueue,
        queue1: OutMsgQueue,
        visited_cells: ahash::AHashSet<UInt256>,
    ) {
        unimplemented!();
    }

    fn get_split_queues(&self, before_split_block: &BlockIdExt) -> SplitQueues {
        unimplemented!();
    }

    fn db_cells_factory(&self) -> Result<Arc<dyn CellsFactory>> {
        unimplemented!();
    }

    fn db_cells_loader(&self) -> Result<Arc<dyn Fn(&UInt256) -> Result<Cell> + Send + Sync>> {
        unimplemented!();
    }

    fn get_account_storage_dict(&self, _dict_hash: &UInt256) -> Option<Cell> {
        None
    }

    fn add_account_storage_dict(&self, _dict: Cell, _size: u64) {}

    fn trace_collector(&self) -> Option<simplex::TraceCollector> {
        None
    }

    async fn update_custom_overlays(&self, _configs: Option<&[CustomOverlay]>) -> Result<()> {
        unimplemented!();
    }

    async fn update_public_overlays(
        &self,
        keyblock_id: &BlockIdExt,
        config: &ConfigParams,
    ) -> Result<()> {
        Ok(())
    }

    fn is_archival_mode(&self) -> bool {
        false
    }
}

#[async_trait::async_trait]
pub trait Stoppable: Send + Sync {
    fn name(&self) -> &'static str;
    async fn shutdown(self: Box<Self>);
}

#[cfg(test)]
#[path = "tests/test_sync_blocks_before.rs"]
mod sync_blocks_before_tests;
