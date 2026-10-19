// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::validator::propagation::*;
use adnl::PlumtreeConfig;
use consensus_common::simplex_protocol::SimplexProtocol;
use rtos_api::{pq_finality::PqNetworkSignatureSet, WireProfile};
use rtos_block::{
    boc_compression::{boc_compress, CompressionAlgorithm},
    UInt256,
};
use std::collections::BTreeMap;

const PAYLOAD_LIMIT: usize = crate::network::MAX_COMPRESSED_SIZE;

#[derive(Clone)]
pub(super) struct PropagationConfig {
    mc: bool,
    shard: bool,
    public_authority: BTreeMap<[u8; 32], usize>,
    fast_authority: BTreeMap<[u8; 32], usize>,
    signer: Option<Arc<dyn KeyOption>>,
}
impl PropagationConfig {
    fn enabled(&self, shard: &ShardIdent) -> bool {
        if shard.is_masterchain() {
            self.mc
        } else {
            self.shard
        }
    }
    fn same(&self, other: &Self) -> bool {
        self.mc == other.mc
            && self.shard == other.shard
            && self.public_authority == other.public_authority
            && self.fast_authority == other.fast_authority
            && self.signer.as_ref().map(|s| s.id()) == other.signer.as_ref().map(|s| s.id())
    }
    fn policy(&self, fast: bool) -> PlumtreeConfig {
        let authority = if fast { &self.fast_authority } else { &self.public_authority };
        PlumtreeConfig {
            authorized_keys: authority.clone(),
            max_untrusted_size: if fast { 0 } else { PAYLOAD_LIMIT },
            // T0 public policy allows FEC, but untrusted sources require application
            // authentication; they are not promoted to trusted Plumtree producers.
            untrusted_flags: if fast { 0 } else { 1 },
            fixed_members: fast,
            original_sender: self
                .signer
                .as_ref()
                .is_some_and(|s| authority.contains_key(s.id().data())),
            eager_limit: 4,
            max_retained_bytes: 64 << 20,
            max_broadcasts: 256,
        }
    }
}

/// Whether a workchain's full-node overlays use Plumtree: the reference full
/// node reads enable_plumtree_broadcast of the workchain's configuration, which
/// holds for protocol 2 and newer, including a version this build would refuse
/// to validate with.
fn full_node_plumtree_enabled(config: Option<&rtos_block::SimplexConfig>) -> bool {
    config.is_some_and(|config| u32::from(config.protocol_version) >= 2)
}

impl FullNodeOverlaysRouter {
    /// Only called with configuration read from the actual applied MC state.
    /// Consumer ownership is established by client construction before activation.
    pub(super) async fn update_propagation_config(
        self: &Arc<Self>,
        config: &ConfigParams,
        signer: Option<&Arc<dyn KeyOption>>,
        binding: &FastSyncRefreshBinding,
    ) -> Result<()> {
        let mc = full_node_plumtree_enabled(config.get_mc_simplex_config()?.as_ref());
        let shard = full_node_plumtree_enabled(config.get_shard_simplex_config()?.as_ref());
        if (mc || shard) && self.network.context().stack.overlay.wire_profile() != WireProfile::T0 {
            rtos_block::fail!("v2 full-node propagation requires the pinned T0 wire profile");
        }
        let sets =
            [config.prev_validator_set()?, config.validator_set()?, config.next_validator_set()?];
        let mut all = Vec::new();
        for set in &sets {
            all.extend_from_slice(set.list());
        }
        let (public, _) = fast_sync_transport_authority(
            &all,
            self.network.context().stack.overlay.wire_profile(),
        )?;
        // Shard overlay rules follow every applied refresh, including ones
        // that leave the propagation configuration unchanged.
        self.update_public_authorization(&public).await?;
        // T0 current_validators_adnl_ is named historically: it contains the
        // previous/current/next union, not merely ConfigParam34.
        let desired = PropagationConfig {
            mc,
            shard,
            public_authority: public.iter().map(|k| (*k.data(), PAYLOAD_LIMIT)).collect(),
            fast_authority: public.iter().map(|k| (*k.data(), PAYLOAD_LIMIT)).collect(),
            signer: signer.cloned(),
        };
        if self.propagation_config_ready.load(Ordering::Acquire)
            && self
                .propagation_config
                .read()
                .unwrap()
                .as_ref()
                .is_some_and(|old| old.same(&desired))
        {
            return Ok(());
        }
        self.propagation_config_ready.store(false, Ordering::Release);
        self.publish_fast_sync(Some(binding), || {
            *self.propagation_config.write().unwrap() = Some(desired);
            Ok(())
        })?;
        // The transport policy is immutable. Drain each old public generation;
        // the ordinary creation path installs the new consumer then the policy.
        let shards: Vec<_> = self.public_overlays.iter().map(|g| g.key().clone()).collect();
        for shard in shards {
            let generation =
                self.public_generations.lock().unwrap().entry(shard.clone()).or_default().clone();
            {
                let _generation = generation.lock().await;
                if let Some(guard) = self.public_overlays.get(&shard) {
                    guard.val().stop_and_wait().await?;
                    self.public_overlays.remove(&shard);
                }
            }
            self.overlay_client_for_shard(shard).await?;
        }
        // Force fast-sync replacement even when only protocol/policy changed.
        *self.fast_sync_snapshot.lock().await = None;
        self.propagation_config_ready.store(true, Ordering::Release);
        Ok(())
    }

    /// Plumtree broadcasts are sent over QUIC. As in the reference overlay, a
    /// node without a QUIC sender warns and runs the overlay without Plumtree;
    /// a QUIC sender that is present but cannot be initialized is an error.
    fn plumtree_sender_available(&self, overlay: &str, shard: &ShardIdent) -> bool {
        let available = self.network.context().stack.quic.is_some();
        if !available {
            log::warn!(
                "Plumtree broadcast sender is not set; Plumtree is disabled in the {overlay} \
                 overlay of {shard}"
            );
        }
        available
    }
    pub(super) fn configure_public_propagation(
        &self,
        client: &FullNodeOverlayClient,
    ) -> Result<()> {
        let config = self.propagation_config.read().unwrap();
        if let Some(config) = config.as_ref().filter(|c| c.enabled(client.shard())) {
            if !self.plumtree_sender_available("public", client.shard()) {
                return Ok(());
            }
            self.network.ensure_public_overlay_quic()?;
            client.overlay_client().configure_plumtree(config.policy(false))?;
        }
        Ok(())
    }
    pub(super) fn configure_fast_sync_propagation(
        &self,
        client: &FastSyncOverlayClient,
    ) -> Result<()> {
        let config = self.propagation_config.read().unwrap();
        if let Some(config) = config.as_ref().filter(|c| c.enabled(client.shard())) {
            if !self.plumtree_sender_available("fast-sync", client.shard()) {
                return Ok(());
            }
            client.client().configure_plumtree(config.policy(true))?;
        }
        Ok(())
    }
}

/// Structural serialization only. Callers must retain the accepted block token;
/// this function does not authenticate network signature fields.
fn pq_block_wire(
    block: &BlockStuff,
    proof: &BlockProofStuff,
    signatures: &PqNetworkSignatureSet,
) -> Result<Vec<u8>> {
    if signatures.block_id() != block.id() || proof.id() != block.id() {
        rtos_block::fail!("Accepted PQ broadcast block/proof/signature identity mismatch");
    }
    WireProfile::T0.serialize(
        &rtos_api::ton::ton_node::broadcast::BlockBroadcastCompressedV2 {
            id: block.id().clone(),
            signature_set: signatures.to_node().into_boxed(),
            proof: proof.data().to_vec(),
            data_compressed: boc_compress(
                vec![block.root_cell().clone()],
                CompressionAlgorithm::ImprovedStructureLZ4,
            )?,
        }
        .into_boxed(),
    )
}

/// The tosNode.blockFinalityBroadcast of an accepted block and its transport
/// identity. As in the reference block accepter, a shard block carries the set
/// it was accepted with, the notarization (approve) set of a finalized
/// ancestor included; a masterchain block is accepted only with a final set.
fn pq_finality_wire(signatures: &PqNetworkSignatureSet) -> Result<(Vec<u8>, [u8; 32])> {
    if !signatures.is_final() && signatures.block_id().shard().is_masterchain() {
        rtos_block::fail!("A masterchain finality broadcast requires a final signature set");
    }
    let signature_set = signatures.to_node().into_boxed();
    let signature_hash = UInt256::calc_file_hash(&WireProfile::T0.serialize(&signature_set)?);
    let mut identity = WireProfile::T0.serialize(
        &rtos_api::ton::ton_node::finalitybroadcastid::FinalityBroadcastId {
            id: signatures.block_id().clone(),
        }
        .into_boxed(),
    )?;
    identity.extend_from_slice(signature_hash.as_slice());
    let transport_id = *UInt256::calc_file_hash(&identity).as_array();
    let bytes = WireProfile::T0.serialize(
        &rtos_api::ton::ton_node::broadcast::BlockFinalityBroadcast {
            id: signatures.block_id().clone(),
            signature_set,
        }
        .into_boxed(),
    )?;
    Ok((bytes, transport_id))
}

impl FullNodeOverlaysRouter {
    pub async fn resolve_propagation_targets(
        self: &Arc<Self>,
        id: &BlockIdExt,
        plan: &PropagationPlan,
    ) -> Result<Vec<PropagationDestination>> {
        let _lease = self.tasks.enter()?;
        self.refresh_fast_sync_from_applied_state().await?;
        if let Some(destination) = plan.destination() {
            return Ok(vec![destination.clone()]);
        }
        let mut names: Vec<_> = self
            .custom_overlays
            .iter()
            .filter(|guard| guard.val().sends_blocks_to(id.shard()))
            .map(|guard| guard.key().clone())
            .collect();
        names.sort();
        let mut destinations = Vec::new();
        for kind in [PropagationKind::Candidate, PropagationKind::Block, PropagationKind::Finality]
        {
            let targets = plan.targets_for(kind);
            if targets.public {
                destinations
                    .push(PropagationDestination { kind, target: PropagationTarget::Public });
            }
            if targets.fast_sync && self.fast_sync_overlay(id.shard()).is_some() {
                destinations
                    .push(PropagationDestination { kind, target: PropagationTarget::FastSync });
            }
            if targets.custom {
                destinations.extend(names.iter().cloned().map(|name| PropagationDestination {
                    kind,
                    target: PropagationTarget::Custom(name),
                }));
            }
        }
        if plan.send_shard_description {
            destinations.push(PropagationDestination {
                kind: PropagationKind::ShardDescription,
                target: PropagationTarget::ShardDescription,
            });
        }
        Ok(destinations)
    }

    async fn propagate_wire(
        self: &Arc<Self>,
        id: &BlockIdExt,
        kind: PropagationKind,
        targets: TargetSet,
        protocol: SimplexProtocol,
        bytes: &[u8],
        simple_id: Option<[u8; 32]>,
        destination: Option<&PropagationDestination>,
    ) -> PropagationOutcome {
        let _admission = match self.tasks.enter() {
            Ok(lease) => lease,
            Err(error) => return failed_selected(kind, targets, destination, error),
        };
        let mut outcome = PropagationOutcome::default();
        let plumtree = protocol.enable_plumtree_broadcast() && kind != PropagationKind::Block;
        let tagged = TaggedByteSlice {
            object: bytes,
            #[cfg(feature = "telemetry")]
            tag: u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        };
        let status = |r: Result<()>| match r {
            Ok(()) => PropagationStatus::Sent,
            Err(error) => PropagationStatus::Failed(format!("{error:#}")),
        };
        // Without a QUIC sender the overlays run without Plumtree, and the
        // reference overlay drops a Plumtree broadcast; nothing is retried.
        let no_sender = plumtree && self.network.context().stack.quic.is_none();
        if no_sender {
            let skipped =
                || PropagationStatus::Skipped("Plumtree broadcast sender is not set".into());
            if targets.public {
                outcome.record(kind, PropagationTarget::Public, skipped());
            }
            if targets.fast_sync {
                outcome.record(kind, PropagationTarget::FastSync, skipped());
            }
        }
        if targets.public && !no_sender {
            let result: Result<()> = async {
                let client = self.overlay_client(id.shard()).await?;
                if plumtree {
                    self.propagation_config
                        .read()
                        .unwrap()
                        .clone()
                        .filter(|c| c.enabled(id.shard()))
                        .ok_or_else(|| error!("No authenticated public Plumtree configuration"))?;
                    // The shard's outbound source signs; publication requires
                    // its verdict, certificate included, to be Allowed.
                    let source = self.public_outbound_source(&client, bytes.len(), true)?;
                    client.overlay_client().broadcast_plumtree(&source, simple_id, bytes).await
                } else {
                    self.send_public_broadcast(&client, &tagged, PublicBroadcastKind::Block).await
                }
            }
            .await;
            outcome.record(kind, PropagationTarget::Public, status(result));
        }
        if targets.fast_sync && !no_sender {
            let receipt = if let Some(client) = self.fast_sync_overlay(id.shard()) {
                let result: Result<()> = async {
                    if plumtree {
                        let signer = client
                            .propagation_signer
                            .as_ref()
                            .ok_or_else(|| error!("No fast-sync transport signer"))?;
                        client.client().broadcast_plumtree(signer, simple_id, bytes).await
                    } else if client.use_twostep() {
                        client.send_twostep_broadcast(&tagged, 0).await
                    } else {
                        client.send_broadcast(&tagged, 0, AdnlSendMethod::Fast).await
                    }
                }
                .await;
                status(result)
            } else {
                if destination.is_some() {
                    PropagationStatus::Deferred("Resolved fast-sync overlay is unavailable".into())
                } else {
                    PropagationStatus::Skipped("No eligible fast-sync overlay".into())
                }
            };
            outcome.record(kind, PropagationTarget::FastSync, receipt);
        }
        if targets.custom {
            if let Some(PropagationDestination {
                target: PropagationTarget::Custom(name), ..
            }) = destination
            {
                let receipt = match self.custom_overlays.get(name) {
                    Some(guard) if guard.val().sends_blocks_to(id.shard()) => {
                        status(guard.val().send_propagation_broadcast(&tagged).await)
                    }
                    _ => PropagationStatus::Deferred(
                        "Resolved custom overlay is absent or no longer matches this shard".into(),
                    ),
                };
                outcome.record(kind, PropagationTarget::Custom(name.clone()), receipt);
                return outcome;
            }
            let mut selected = false;
            for guard in self.custom_overlays.iter() {
                let client = guard.val();
                if client.sends_blocks_to(id.shard()) {
                    selected = true;
                    // T0 custom overlays keep the existing FEC/two-step carrier,
                    // including when public/fast-sync use Plumtree.
                    outcome.record(
                        kind,
                        PropagationTarget::Custom(guard.key().clone()),
                        status(client.send_propagation_broadcast(&tagged).await),
                    );
                }
            }
            if !selected {
                outcome.record(
                    kind,
                    PropagationTarget::Custom(String::new()),
                    PropagationStatus::Skipped("No eligible custom overlay".into()),
                );
            }
        }
        outcome
    }

    pub async fn relay_validated_candidate(
        self: &Arc<Self>,
        candidate: &ValidatedCandidateRelay,
        plan: &PropagationPlan,
    ) -> PropagationOutcome {
        if plan.candidate_targets == TargetSet::NONE {
            return PropagationOutcome::default();
        }
        // A bounded single cache also bounds sessions. Cancellation before the
        // receipt leaves the entry retryable; successful retries are idempotent.
        let mut cache = self.candidate_relays.lock().await;
        if plan.destination().is_none() && cache.contains(candidate.block().id()) {
            let mut outcome = PropagationOutcome::default();
            outcome.record(
                PropagationKind::Candidate,
                PropagationTarget::Public,
                PropagationStatus::Skipped("Candidate already relayed".into()),
            );
            return outcome;
        }
        let prepared: Result<Vec<u8>> = async {
            let _admission = self.tasks.enter()?;
            self.refresh_fast_sync_from_applied_state().await?;
            let value = build_block_candidate_broadcast_compressed(
                candidate.block().id().clone(),
                candidate.catchain_seqno(),
                candidate.validator_set_hash(),
                candidate.block().root_cell(),
            )?
            .into_boxed();
            self.network.context().stack.overlay.wire_profile().serialize(&value)
        }
        .await;
        match prepared {
            Ok(bytes) => {
                let outcome = self
                    .propagate_wire(
                        candidate.block().id(),
                        PropagationKind::Candidate,
                        plan.candidate_targets,
                        plan.protocol,
                        &bytes,
                        None,
                        plan.destination(),
                    )
                    .await;
                if plan.destination().is_none() && outcome.attempted() && !outcome.needs_retry() {
                    cache.record_sent(candidate.block().id().clone());
                }
                outcome
            }
            Err(error) => failed_selected(
                PropagationKind::Candidate,
                plan.candidate_targets,
                plan.destination(),
                error,
            ),
        }
    }

    pub async fn propagate_accepted_session_block(
        self: &Arc<Self>,
        accepted: &crate::validator::accept_block::AcceptedSessionBlock,
        plan: &PropagationPlan,
    ) -> PropagationOutcome {
        let mut outcome = PropagationOutcome::default();
        if plan.candidate_targets != TargetSet::NONE {
            let candidate_outcome = match accepted.candidate_relay() {
                Ok(candidate) => self.relay_validated_candidate(&candidate, plan).await,
                Err(error) => failed_selected(
                    PropagationKind::Candidate,
                    plan.candidate_targets,
                    plan.destination(),
                    error,
                ),
            };
            outcome.receipts.extend(candidate_outcome.receipts);
        }
        if plan.block_targets != TargetSet::NONE || plan.finality_targets != TargetSet::NONE {
            let prepared: Result<_> = async {
                let _admission = self.tasks.enter()?;
                self.refresh_fast_sync_from_applied_state().await?;
                if self.network.context().stack.overlay.wire_profile() != WireProfile::T0 {
                    rtos_block::fail!("PQ propagation requires pinned T0 wire profile");
                }
                // The accepted wrapper binds verified evidence to these exact bytes;
                // arbitrary network signature fields cannot enter this boundary.
                accepted.network_signatures()
            }
            .await;
            match prepared {
                Ok(signatures) => {
                    if plan.block_targets != TargetSet::NONE {
                        let sent =
                            match pq_block_wire(accepted.block(), accepted.proof(), &signatures) {
                                Ok(bytes) => {
                                    self.propagate_wire(
                                        accepted.block().id(),
                                        PropagationKind::Block,
                                        plan.block_targets,
                                        plan.protocol,
                                        &bytes,
                                        None,
                                        plan.destination(),
                                    )
                                    .await
                                }
                                Err(error) => failed_selected(
                                    PropagationKind::Block,
                                    plan.block_targets,
                                    plan.destination(),
                                    error,
                                ),
                            };
                        outcome.receipts.extend(sent.receipts);
                    }
                    if plan.finality_targets != TargetSet::NONE {
                        let sent = match pq_finality_wire(&signatures) {
                            Ok((bytes, id)) => {
                                self.propagate_wire(
                                    accepted.block().id(),
                                    PropagationKind::Finality,
                                    plan.finality_targets,
                                    plan.protocol,
                                    &bytes,
                                    Some(id),
                                    plan.destination(),
                                )
                                .await
                            }
                            Err(error) => failed_selected(
                                PropagationKind::Finality,
                                plan.finality_targets,
                                plan.destination(),
                                error,
                            ),
                        };
                        outcome.receipts.extend(sent.receipts);
                    }
                }
                Err(error) => {
                    outcome.receipts.extend(
                        PropagationOutcome::failed_for_plan(PropagationKind::Block, plan, &error)
                            .receipts,
                    );
                    outcome.receipts.extend(
                        PropagationOutcome::failed_for_plan(
                            PropagationKind::Finality,
                            plan,
                            &error,
                        )
                        .receipts,
                    );
                }
            }
        }
        // Separate effects: a failed block/finality send must not silently omit
        // the legacy shard-description operation or erase its own result.
        if plan.send_shard_description {
            if accepted.block().id().shard().is_masterchain() || !accepted.is_final() {
                outcome.record(
                    PropagationKind::ShardDescription,
                    PropagationTarget::ShardDescription,
                    PropagationStatus::Skipped(
                        "No finalized shard description for this acceptance".into(),
                    ),
                );
            } else {
                let result = accepted
                    .publish_shard_description(self.engine.clone(), plan.locally_generated)
                    .await;
                outcome.record(
                    PropagationKind::ShardDescription,
                    PropagationTarget::ShardDescription,
                    match result {
                        Ok(()) => PropagationStatus::Sent,
                        Err(error) => PropagationStatus::Failed(format!("{error:#}")),
                    },
                );
            }
        }
        outcome
    }
}

pub(crate) fn failed_selected(
    kind: PropagationKind,
    targets: TargetSet,
    destination: Option<&PropagationDestination>,
    error: impl std::fmt::Display,
) -> PropagationOutcome {
    if let Some(destination) = destination.filter(|d| d.kind == kind) {
        let mut outcome = PropagationOutcome::default();
        outcome.record(
            kind,
            destination.target.clone(),
            PropagationStatus::Failed(error.to_string()),
        );
        outcome
    } else {
        failed_targets(kind, targets, error)
    }
}

fn failed_targets(
    kind: PropagationKind,
    targets: TargetSet,
    error: impl std::fmt::Display,
) -> PropagationOutcome {
    let mut outcome = PropagationOutcome::default();
    let mut selected = vec![];
    if targets.public {
        selected.push(PropagationTarget::Public);
    }
    if targets.fast_sync {
        selected.push(PropagationTarget::FastSync);
    }
    if targets.custom {
        selected.push(PropagationTarget::Custom(String::new()));
    }
    for target in selected {
        outcome.record(kind, target, PropagationStatus::Failed(format!("{error:#}")));
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtos_block::{
        BlockSignaturesSimplex, BlockSignaturesSimplexPq, PqBlockSignaturePair, ValidatorBaseInfo,
    };
    fn carrier() -> BlockSignaturesSimplexPq {
        carrier_of("ordinary", "finalize")
    }
    fn carrier_of(kind: &str, role: &str) -> BlockSignaturesSimplexPq {
        let data: serde_json::Value =
            serde_json::from_str(include_str!("../../../../tl/rtos_api/tests/data/live-pq.json"))
                .unwrap();
        let mut rows: Vec<_> = data["rows"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| {
                r["kind"] == kind && r["role"] == role && r["context"] == "TOS-CONSENSUS-SIMPLEX-v1"
            })
            .collect();
        rows.sort_by_key(|r| r["index"].as_u64());
        let bytes = |value: &serde_json::Value| hex::decode(value.as_str().unwrap()).unwrap();
        BlockSignaturesSimplexPq {
            validator_info: ValidatorBaseInfo::with_params(1, 7),
            sig_count: 2,
            sig_weight: 3,
            slot: 99,
            session_id: UInt256::from_slice(&bytes(&data["session"])),
            candidate_data: BlockSignaturesSimplex::bytes_to_cell_tree(&bytes(
                &rows[0]["candidate"],
            ))
            .unwrap(),
            signatures: rows
                .iter()
                .map(|r| PqBlockSignaturePair {
                    validator_id: UInt256::from([r["index"].as_u64().unwrap() as u8 + 1; 32]),
                    algorithm_id: 1,
                    signature: bytes(&r["signature"]),
                })
                .collect(),
        }
    }
    #[test]
    fn propagation_finality_id_binds_certificate_and_approval_stays_nonfinal() {
        // Carrier test only: no claim that structural decoding grants authority.
        let carrier = carrier();
        let final_ = PqNetworkSignatureSet::from_final_fields(&carrier).unwrap();
        let (bytes, id) = pq_finality_wire(&final_).unwrap();
        let decoded: rtos_api::ton::ton_node::Broadcast =
            WireProfile::T0.deserialize_typed(&bytes).unwrap();
        let rtos_api::ton::ton_node::Broadcast::TonNode_BlockFinalityBroadcast(decoded) = decoded
        else {
            panic!("wrong carrier");
        };
        assert_eq!(decoded.id, *final_.block_id());
        let signature_bytes = WireProfile::T0.serialize(&decoded.signature_set).unwrap();
        let mut identity = WireProfile::T0
            .serialize(
                &rtos_api::ton::ton_node::finalitybroadcastid::FinalityBroadcastId {
                    id: decoded.id,
                }
                .into_boxed(),
            )
            .unwrap();
        identity.extend_from_slice(UInt256::calc_file_hash(&signature_bytes).as_slice());
        assert_eq!(id, *UInt256::calc_file_hash(&identity).as_array());
        let mut changed = carrier.clone();
        changed.signatures.reverse();
        assert_ne!(
            id,
            pq_finality_wire(&PqNetworkSignatureSet::from_final_fields(&changed).unwrap())
                .unwrap()
                .1
        );
        // A masterchain block is never broadcast with an approve set.
        let approval =
            rtos_api::pq_finality::PqApproval::from_notarization_fields(carrier).unwrap();
        let approval = PqNetworkSignatureSet::from_approval(&approval).unwrap();
        assert!(!approval.is_final());
        assert!(approval.block_id().shard().is_masterchain());
        assert!(pq_finality_wire(&approval).is_err());
    }

    /// The final and the approve set of one shard block, built from the same
    /// fixture rows by a driver over the reference node's signature-set
    /// factories, serialize to the same tosNode.blockFinalityBroadcast bytes
    /// and the same distinct transport identities here.
    #[test]
    fn propagation_shard_final_and_approve_finality_match_reference_vectors() {
        let vectors = include_str!("testdata/finality-broadcast-vector.tsv");
        let field = |line: &str, name: &str| {
            line.split('\t')
                .find_map(|f| f.strip_prefix(&format!("{name}=")))
                .map(str::to_owned)
                .unwrap()
        };
        let mut ids = Vec::new();
        for line in vectors.lines().skip(1) {
            let kind = line.split('\t').next().unwrap();
            let signatures = if kind == "final" {
                PqNetworkSignatureSet::from_final_fields(&carrier_of("shard_ordinary", "finalize"))
                    .unwrap()
            } else {
                let approval = rtos_api::pq_finality::PqApproval::from_notarization_fields(
                    carrier_of("shard_ordinary", "notarize"),
                )
                .unwrap();
                PqNetworkSignatureSet::from_approval(&approval).unwrap()
            };
            assert!(!signatures.block_id().shard().is_masterchain());
            assert_eq!(signatures.is_final(), field(line, "final") == "1", "{kind}");
            let (bytes, id) = pq_finality_wire(&signatures).unwrap();
            assert_eq!(hex::encode(&bytes), field(line, "wire"), "{kind} wire");
            assert_eq!(hex::encode(id), field(line, "transport_id"), "{kind} transport id");
            ids.push(id);
        }
        assert_eq!(ids.len(), 2);
        assert_ne!(ids[0], ids[1], "approve and final broadcasts of one block are distinct");
    }
}

#[cfg(test)]
mod configuration_tests {
    use super::*;
    use crate::{
        engine::{Engine, EngineFlags, Stopper},
        shard_state::ShardStateStuff,
        validator::validator_manager::emulator_network_bootstrap::EmulatorNetworkBootstrap,
    };
    use futures::FutureExt;
    use rtos_block::{
        ConfigParam34, ConfigParamEnum, NewConsensusConfigAll, PqConsensusKey, SimplexConfig,
    };

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn propagation_normal_applied_configuration_installs_and_rotates_transport() -> Result<()>
    {
        // Protocol 3 is newer than this build validates with; the reference
        // full node still selects Plumtree for it (enable_plumtree_broadcast).
        for (protocol, binding_mode) in [(0, 0), (1, 0), (2, 0), (2, 1), (2, 2), (3, 0)] {
            let bootstrap = EmulatorNetworkBootstrap::build_with_config(2, |config, keys| {
                let corpus: serde_json::Value = serde_json::from_str(include_str!(
                    "../../../../tl/rtos_api/tests/data/live-pq.json"
                ))?;
                let mut members = vec![];
                for (index, key) in keys.iter().enumerate() {
                    let row = corpus["rows"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|row| row["index"] == index)
                        .unwrap();
                    let public_key = hex::decode(row["public_key"].as_str().unwrap())?;
                    members.push(ValidatorDescr::with_pq_params(
                        UInt256::from([index as u8 + 1; 32]),
                        PqConsensusKey {
                            algorithm_id: 1,
                            key_id: rtos_block::derive_consensus_key_id(1, &public_key),
                            public_key,
                        },
                        1,
                        UInt256::from(*key.adnl_key.id().data()),
                    ));
                }
                config.set_config(ConfigParamEnum::ConfigParam34(
                    ConfigParam34::with_validator_set(ValidatorSet::new(0, u32::MAX, 2, members)?),
                ))?;
                let selected = SimplexConfig {
                    protocol_version: protocol,
                    use_quic: true,
                    ..Default::default()
                };
                config.set_config(ConfigParamEnum::ConfigParam30(NewConsensusConfigAll {
                    mc: Some(selected.clone()),
                    shard: Some(selected),
                }))?;
                Ok(())
            })?;
            let mut local: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&bootstrap.config_path)?)?;
            local["ip_address_quic"] = "127.0.0.1:0".into();
            for registration in local["validator_keys"].as_array_mut().unwrap() {
                registration["election_id"] =
                    (registration["election_id"].as_i64().unwrap() + 1000).into();
            }
            if binding_mode != 0 {
                local["validator_keys"] = serde_json::json!([]);
                local["consensus_transport_bindings"] = serde_json::json!([{
                    "validator_id": rtos_block::base64_encode(&[if binding_mode == 1 { 1 } else { 99 }; 32]),
                    "adnl_key_id": rtos_block::base64_encode(bootstrap.validators[0].adnl_key.id().data()),
                }]);
            }
            std::fs::write(&bootstrap.config_path, serde_json::to_vec(&local)?)?;
            let engine = Engine::new(
                bootstrap.load_node_config().await?,
                EngineFlags {
                    initial_sync_disabled: true,
                    force_check_db: false,
                    truncate_db: None,
                },
                Arc::new(Stopper::new()),
            )
            .await?;
            let result = std::panic::AssertUnwindSafe(async {
                // The trusted, hash-pinned bootstrap is applied exactly as boot does;
                // no successor is marked applied and no runtime v2 admission is bypassed.
                let bytes = std::fs::read(bootstrap.config_dir().join("zerostate.boc"))?;
                let state = ShardStateStuff::deserialize_zerostate(
                    bootstrap.zerostate_id.clone(),
                    &bytes,
                    #[cfg(feature = "telemetry")]
                    engine.engine_telemetry(),
                    engine.engine_allocated(),
                )?;
                let (_, handle) = engine.store_zerostate(state, &bytes).await?;
                engine.set_applied(&handle, 0).await?;
                engine.save_last_applied_mc_block_id(&bootstrap.zerostate_id)?;
                engine.save_shard_client_mc_block_id(&bootstrap.zerostate_id)?;
                engine.initialize_test_full_node_overlays().await?;
                let router = engine.overlays_router()?;
                router.refresh_fast_sync_from_applied_state().await?;
                let public = router.overlay_client(&ShardIdent::MASTERCHAIN).await?;
                if binding_mode == 2 {
                    assert!(
                        router
                            .propagation_config
                            .read()
                            .unwrap()
                            .as_ref()
                            .unwrap()
                            .signer
                            .is_none(),
                        "a loaded binding with the wrong stable member ID is not authority"
                    );
                    assert!(router.fast_sync_overlay(&ShardIdent::MASTERCHAIN).is_none());
                    return Ok::<_, anyhow::Error>(());
                }
                let fast = router.fast_sync_overlay(&ShardIdent::MASTERCHAIN).unwrap();
                let signer = router
                    .propagation_config
                    .read()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .signer
                    .clone()
                    .unwrap();
                if binding_mode == 1 {
                    assert!(!engine.network().config_handler().get_validator_status());
                    assert_eq!(signer.id(), bootstrap.validators[0].adnl_key.id());
                    assert_eq!(
                        engine.network().context().stack.adnl.key_by_id(signer.id())?.id(),
                        signer.id()
                    );
                }
                // Exercise actual signed transport publication after normal config
                // activation. This transport-only check is not block acceptance or
                // mixed-network evidence; consensus/full-node consumers remain in place.
                for client in [public.overlay_client(), fast.client()] {
                    let sent = client
                        .broadcast_plumtree(
                            &signer,
                            Some([92; 32]),
                            b"configuration transport probe",
                        )
                        .await;
                    let error = sent
                        .expect_err("an isolated overlay has no outbound neighbours")
                        .to_string();
                    assert!(
                        error.contains(if protocol >= 2 {
                            "no outbound neighbour"
                        } else {
                            "disabled"
                        }),
                        "typed protocol must select actual transport activation: {error}"
                    );
                }
                if protocol == 2 && binding_mode == 0 {
                    let other = bootstrap
                        .validators
                        .iter()
                        .find(|k| k.adnl_key.id() != signer.id())
                        .unwrap();
                    for registration in &bootstrap.validators {
                        engine
                            .network()
                            .config_handler()
                            .add_validator_adnl_key(
                                registration.validator_key.id().data(),
                                other.adnl_key.id().data(),
                            )
                            .await?;
                    }
                    router.refresh_fast_sync_from_applied_state().await?;
                    let replacement = router.overlay_client(&ShardIdent::MASTERCHAIN).await?;
                    assert!(!Arc::ptr_eq(&public, &replacement));
                    assert!(public.overlay_client().cancellation_token().is_cancelled());
                    assert!(fast.client().cancellation_token().is_cancelled());
                    assert!(public
                        .overlay_client()
                        .broadcast_plumtree(&signer, Some([93; 32]), b"retired generation")
                        .await
                        .is_err());
                    let new_signer = router
                        .propagation_config
                        .read()
                        .unwrap()
                        .as_ref()
                        .unwrap()
                        .signer
                        .clone()
                        .unwrap();
                    assert_ne!(signer.id(), new_signer.id());
                    assert!(replacement
                        .overlay_client()
                        .broadcast_plumtree(&new_signer, Some([94; 32]), b"replacement generation")
                        .await
                        .expect_err("replacement still has no outbound neighbours")
                        .to_string()
                        .contains("no outbound neighbour"));
                }
                Ok::<_, anyhow::Error>(())
            })
            .catch_unwind()
            .await;
            let shutdown = engine.wait_stop().await;
            match result {
                Ok(result) => {
                    result?;
                    shutdown?;
                }
                Err(panic) => std::panic::resume_unwind(panic),
            }
        }
        Ok(())
    }
}
