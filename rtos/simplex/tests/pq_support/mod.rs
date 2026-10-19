// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Post-quantum custody sessions for the multi-node integration tests.
//!
//! Every test node is a post-quantum committee member whose ML-DSA-44 seed is
//! held in a `PqConsensusCustody`; its session is created through
//! `SessionFactory::create_authenticated_validator_session_checked` with the
//! signer `SessionSigner::from_custody_match` selects for its descriptor. The
//! transport (ADNL) key of each node stays the one its overlay already uses.
#![allow(dead_code)]

use consensus_common::{
    finality_delivery::{DurableFinalitySink, FinalizedDeliveryCompletion, FinalizedDeliveryDraft},
    session_runtime::{AuthenticatedSessionRuntime, SessionNetworkPin},
    ConsensusOverlayManager, ConsensusOverlayManagerPtr, PrivateKey, SessionListener,
};
use rtos_api::session_identity::SessionCoordinates;
use rtos_block::{
    sha256_digest, BlockIdExt, BuilderData, CatchainConfig, ConfigParam34, ConfigParamEnum,
    ConfigParams, ConsensusConfig, IBitstring, PqConsensusKey, Result, Serializable, ShardIdent,
    SimplexConfig, UInt256, ValidatorDescr, ValidatorSet,
};
use rtos_pq_consensus::{ConsensusKeyStore, PqConsensusCustody};
use simplex::{SessionFactory, SessionOptions, SessionPtr, SessionSigner};
use std::{
    sync::{Arc, Weak},
    time::{SystemTime, UNIX_EPOCH},
};

/// Authenticated sessions carry the native wire profile end to end.
pub fn in_process_overlay_manager(threads: usize) -> ConsensusOverlayManagerPtr {
    consensus_common::ConsensusCommonFactory::create_in_process_overlay_manager_with_profile(
        threads,
        rtos_api::WireProfile::T0,
    )
}

/// The in-process, lossy and test-network overlay managers only start plain
/// private overlays. Authenticated sessions ask for an authenticated overlay;
/// this test adapter checks the local transport key and overlay identity
/// against the runtime and starts the inner overlay over exactly the runtime's
/// committee. Every node of a test shares one inner transport, so message
/// encoding is the same on both ends of every link.
pub struct AuthenticatedOverlays {
    inner: ConsensusOverlayManagerPtr,
    /// Overlays of an inner manager without a checked drain, stopped by the
    /// plain synchronous stop; they are drained once that stop has returned.
    stopped: std::sync::Mutex<std::collections::HashSet<usize>>,
}

pub fn authenticated(inner: ConsensusOverlayManagerPtr) -> ConsensusOverlayManagerPtr {
    Arc::new(AuthenticatedOverlays { inner, stopped: Default::default() })
}

fn overlay_key(overlay: &consensus_common::ConsensusOverlayPtr) -> usize {
    Arc::as_ptr(overlay) as *const () as usize
}

impl ConsensusOverlayManager for AuthenticatedOverlays {
    fn wire_profile(&self) -> rtos_api::WireProfile {
        rtos_api::WireProfile::T0
    }
    fn start_overlay(
        &self,
        local_validator_key: &PrivateKey,
        overlay_short_id: &Arc<adnl::PrivateOverlayShortId>,
        nodes: &[consensus_common::ConsensusNode],
        overlay_listener: consensus_common::ConsensusOverlayListenerPtr,
        log_replay_listener: consensus_common::ConsensusOverlayLogReplayListenerPtr,
        transport_type: consensus_common::OverlayTransportType,
        block_sync_params: Option<consensus_common::BlockSyncOverlayParams>,
    ) -> Result<consensus_common::ConsensusOverlayPtr> {
        self.inner.start_overlay(
            local_validator_key,
            overlay_short_id,
            nodes,
            overlay_listener,
            log_replay_listener,
            transport_type,
            block_sync_params,
        )
    }
    fn start_authenticated_overlay(
        &self,
        local_transport_key: &PrivateKey,
        overlay_short_id: &Arc<adnl::PrivateOverlayShortId>,
        runtime: Arc<AuthenticatedSessionRuntime>,
        listener: consensus_common::ConsensusOverlayListenerPtr,
        replay_listener: consensus_common::ConsensusOverlayLogReplayListenerPtr,
        transport_type: consensus_common::OverlayTransportType,
    ) -> Result<consensus_common::ConsensusOverlayPtr> {
        if local_transport_key.id() != runtime.local_adnl()
            || overlay_short_id != &runtime.overlay_short_id()?
        {
            rtos_block::fail!("Authenticated overlay key or ID differs from the runtime");
        }
        self.inner.start_overlay(
            local_transport_key,
            overlay_short_id,
            &runtime.consensus_nodes()?,
            listener,
            replay_listener,
            transport_type,
            None,
        )
    }
    fn stop_overlay_checked(
        &self,
        overlay_short_id: &Arc<adnl::PrivateOverlayShortId>,
        overlay: &consensus_common::ConsensusOverlayPtr,
    ) -> Result<()> {
        if self.inner.stop_overlay_checked(overlay_short_id, overlay).is_err() {
            self.inner.stop_overlay(overlay_short_id, overlay);
            self.stopped.lock().unwrap().insert(overlay_key(overlay));
        }
        Ok(())
    }
    fn overlay_drained(&self, overlay: &consensus_common::ConsensusOverlayPtr) -> bool {
        self.inner.overlay_drained(overlay)
            || self.stopped.lock().unwrap().contains(&overlay_key(overlay))
    }
    fn stop_overlay(
        &self,
        overlay_short_id: &Arc<adnl::PrivateOverlayShortId>,
        overlay: &consensus_common::ConsensusOverlayPtr,
    ) {
        self.inner.stop_overlay(overlay_short_id, overlay)
    }
}

/// The masterchain zerostate every test network is pinned to. A session's
/// start anchor at seqno 0 must be exactly this block.
pub fn zerostate() -> BlockIdExt {
    BlockIdExt::with_params(
        ShardIdent::masterchain(),
        0,
        UInt256::from([21; 32]),
        UInt256::from([22; 32]),
    )
}

/// Deterministic seed for one node of one test. Tests use distinct names, so
/// no two tests share an identity in the process-global retirement registry.
pub fn seed(test: &str, index: usize) -> [u8; 32] {
    let mut input = b"rtos-simplex-integration-seed/".to_vec();
    input.extend_from_slice(test.as_bytes());
    input.extend_from_slice(&(index as u64).to_le_bytes());
    sha256_digest(&input)
}

/// One custody-backed committee member.
pub struct PqMember {
    pub validator: UInt256,
    pub descriptor: ValidatorDescr,
    pub custody: PqConsensusCustody,
}

/// The committee of one test: member `i` uses transport key `transports[i]`.
pub struct PqCommittee {
    pub test: String,
    pub members: Vec<PqMember>,
    pub transports: Vec<PrivateKey>,
    pub shard: ShardIdent,
    pub slots_per_leader_window: u32,
    /// Per-node ledger of delivered finalizations. It outlives a session, as
    /// a node's ledger does across a session restart.
    ledgers: Vec<Arc<std::sync::Mutex<std::collections::HashSet<BlockIdExt>>>>,
    /// Per-node acceptance gate: a held gate parks every finality completion,
    /// as a node whose acceptance has stopped keeping up would.
    gates: Vec<Arc<FinalityGate>>,
}

/// Holds a node's finality completions while closed and runs them on release.
#[derive(Default)]
pub struct FinalityGate {
    held: std::sync::atomic::AtomicBool,
    parked: std::sync::Mutex<Vec<Box<dyn FnOnce() + Send>>>,
    staged: std::sync::atomic::AtomicUsize,
}

impl FinalityGate {
    fn complete(&self, completion: Box<dyn FnOnce() + Send>) {
        let mut parked = self.parked.lock().unwrap();
        if self.held.load(std::sync::atomic::Ordering::SeqCst) {
            parked.push(completion);
        } else {
            drop(parked);
            std::thread::spawn(completion);
        }
    }

    fn set_held(&self, held: bool) {
        let released = {
            let mut parked = self.parked.lock().unwrap();
            self.held.store(held, std::sync::atomic::Ordering::SeqCst);
            if held {
                Vec::new()
            } else {
                std::mem::take(&mut *parked)
            }
        };
        for completion in released {
            std::thread::spawn(completion);
        }
    }

    fn parked(&self) -> usize {
        self.parked.lock().unwrap().len()
    }
}

impl PqCommittee {
    pub fn new(
        test: &str,
        transports: Vec<PrivateKey>,
        shard: ShardIdent,
        slots_per_leader_window: u32,
    ) -> Self {
        let members = transports
            .iter()
            .enumerate()
            .map(|(index, transport)| {
                let seed = seed(test, index);
                let store = Arc::new(ConsensusKeyStore::from_seed(&seed, 0).unwrap());
                let key: PqConsensusKey = store.consensus_key().clone();
                let mut id = sha256_digest(&[b"validator".as_slice(), &seed].concat());
                id[0] |= 1;
                let validator = UInt256::from(id);
                let descriptor = ValidatorDescr::with_pq_params(
                    validator.clone(),
                    key,
                    1,
                    UInt256::from(*transport.id().data()),
                );
                let mut custody = PqConsensusCustody::default();
                custody.install(validator.clone(), store, 0, 0).unwrap();
                PqMember { validator, descriptor, custody }
            })
            .collect();
        let ledgers = (0..transports.len()).map(|_| Default::default()).collect();
        let gates = (0..transports.len()).map(|_| Default::default()).collect();
        Self {
            test: test.to_owned(),
            members,
            transports,
            shard,
            slots_per_leader_window,
            ledgers,
            gates,
        }
    }

    /// Close or open every node's acceptance gate; opening runs what was parked.
    pub fn hold_finality(&self, held: bool) {
        for gate in &self.gates {
            gate.set_held(held);
        }
    }

    /// Finalizations staged at all nodes so far (the source keeps handing work
    /// to the node while acceptance is held).
    pub fn finality_staged(&self) -> usize {
        self.gates.iter().map(|gate| gate.staged.load(std::sync::atomic::Ordering::SeqCst)).sum()
    }

    /// Completions currently parked behind closed gates.
    pub fn finality_parked(&self) -> usize {
        self.gates.iter().map(|gate| gate.parked()).sum()
    }

    pub fn descriptors(&self) -> Vec<ValidatorDescr> {
        self.members.iter().map(|member| member.descriptor.clone()).collect()
    }

    /// The authenticated runtime of node `index`, derived from a configuration
    /// that lists this committee as the current validator set.
    pub fn runtime(&self, index: usize) -> Arc<AuthenticatedSessionRuntime> {
        let selected = SimplexConfig {
            // Durable source finality is defined for the private-observer
            // protocol only, so these sessions run it.
            protocol_version: 2,
            slots_per_leader_window: self.slots_per_leader_window,
            ..Default::default()
        };
        let selected_cell = selected.serialize().unwrap();
        let mut wrapper = BuilderData::new();
        wrapper.append_u8(0x10).unwrap();
        wrapper.append_bit_one().unwrap();
        wrapper.checked_append_reference(selected_cell.clone()).unwrap();
        wrapper.append_bit_one().unwrap();
        wrapper.checked_append_reference(selected_cell).unwrap();
        let mut value = BuilderData::new();
        value.checked_append_reference(wrapper.into_cell().unwrap()).unwrap();
        let mut config = ConfigParams::default();
        config.config_params.set_builder(30u32.write_to_bitstring().unwrap(), &value).unwrap();
        config
            .set_config(ConfigParamEnum::ConfigParam29(ConsensusConfig {
                round_candidates: 1,
                new_catchain_ids: true,
                max_block_bytes: 2 << 20,
                max_collated_bytes: 2 << 20,
                ..Default::default()
            }))
            .unwrap();
        config.set_config(ConfigParamEnum::ConfigParam28(CatchainConfig::default())).unwrap();
        let count = self.members.len() as u16;
        config
            .set_config(ConfigParamEnum::ConfigParam34(ConfigParam34 {
                cur_validators: ValidatorSet::new(1, u32::MAX, count, self.descriptors()).unwrap(),
            }))
            .unwrap();
        let zerostate = zerostate();
        Arc::new(
            AuthenticatedSessionRuntime::from_authenticated_config(
                SessionNetworkPin { global_id: -239, zerostate: zerostate.clone() },
                &config,
                SessionCoordinates {
                    shard: &self.shard,
                    catchain_seqno: 7,
                    vertical_seqno: 0,
                    last_key_block_seqno: 0,
                    new_catchain_ids: true,
                },
                self.descriptors(),
                self.transports[index].id().clone(),
            )
            .unwrap()
            .bind_recovery_anchor(zerostate)
            .unwrap(),
        )
    }

    /// The custody signer node `index` takes for its own descriptor.
    pub fn signer(&self, index: usize) -> SessionSigner {
        let member = &self.members[index];
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
        SessionSigner::from_custody_match(
            &member.custody,
            &member.validator,
            &member.descriptor,
            now,
        )
        .unwrap()
    }

    /// Bring test options in line with the authenticated runtime they run under.
    pub fn options(&self, base: &SessionOptions) -> SessionOptions {
        let runtime = self.runtime(0);
        let mut options = *base;
        options.protocol = runtime.protocol();
        options.proto_version = runtime.carrier_version();
        options.wire_profile = runtime.wire_profile();
        options.slots_per_leader_window = runtime.slots_per_leader_window();
        options
    }

    /// Create node `index`'s post-quantum validator session.
    pub fn create_session(
        &self,
        index: usize,
        options: &SessionOptions,
        db_path: String,
        overlay_manager: ConsensusOverlayManagerPtr,
        listener: Weak<dyn SessionListener + Send + Sync>,
    ) -> Result<SessionPtr> {
        let runtime = self.runtime(index);
        // A validator namespace is provisioned explicitly once; a restart
        // reopens the existing namespace and its journal.
        if !std::path::Path::new(&db_path).exists() {
            simplex::provision_test_validator_namespace(&runtime, std::path::Path::new(&db_path))?;
        }
        let sink: Arc<dyn DurableFinalitySink> = Arc::new(ListenerSink {
            listener: listener.clone(),
            delivered: self.ledgers[index].clone(),
            gate: self.gates[index].clone(),
        });
        SessionFactory::create_authenticated_validator_session_checked(
            options,
            runtime,
            self.signer(index),
            &self.transports[index],
            db_path,
            overlay_manager,
            listener,
            None,
            Some(sink),
            None,
        )
        .map_err(|failure| failure.into_error())
    }
}

/// Durable finality goes through the session's sink rather than the listener.
/// This sink hands each staged finalization to the test listener exactly as a
/// finalized-block notification and confirms it durable.
struct ListenerSink {
    listener: Weak<dyn SessionListener + Send + Sync>,
    /// A node ledger records each finalized block once; a source may stage the
    /// same block again while an earlier completion is still in flight.
    delivered: Arc<std::sync::Mutex<std::collections::HashSet<BlockIdExt>>>,
    gate: Arc<FinalityGate>,
}

impl DurableFinalitySink for ListenerSink {
    /// The finalization was handed to the listener when it was staged, which is
    /// this test node's acceptance.
    fn await_accepted(
        &self,
        _request: consensus_common::finality_delivery::CanonicalFinalityRequest,
        completion: Box<dyn FnOnce(Result<()>) + Send>,
    ) -> Result<()> {
        self.gate.complete(Box::new(move || completion(Ok(()))));
        Ok(())
    }

    fn stage(
        &self,
        draft: FinalizedDeliveryDraft,
        completion: FinalizedDeliveryCompletion,
    ) -> Result<()> {
        let record = UInt256::calc_file_hash(&draft.block_id.root_hash().as_slice()[..]);
        let first = self.delivered.lock().unwrap().insert(draft.block_id.clone());
        if !first {
            log::info!("test sink: block {} already delivered", draft.block_id);
        } else if let Some(listener) = self.listener.upgrade() {
            listener.on_block_finalized(
                draft.block_id.clone(),
                draft.source_info,
                draft.block_id.root_hash().clone(),
                draft.block_id.file_hash().clone(),
                draft.data,
                draft.finality,
                Vec::new(),
            );
        }
        self.gate.staged.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.gate.complete(Box::new(move || completion(Ok(record))));
        Ok(())
    }
}
