/*
 * RTOS project modifications (2026-10-10): project and crate naming; explicit target wire profile integration; owned consumer readiness and authenticated finality recovery.
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::{
    engine_traits::EngineOperations,
    network::{
        check_block_candidate_data, check_sync_for_listen_bcasts,
        decompress_and_check_candidate_data, decompress_block_broadcast,
        decompress_block_broadcast_v2, node_network::NetworkContext, overlay_client::OverlayClient,
    },
    types::owned_tasks::OwnedTasks,
};
use adnl::{
    common::{hash, TaggedByteSlice},
    node::AdnlSendMethod,
    DhtSearchPolicy, OverlayNode, OverlayShortId,
};
use rtos_api::{
    ton::{
        overlay::membercertificate::MemberCertificate, pub_::publickey::Overlay as OverlayKey,
        ton_node::Broadcast,
    },
    BoxedSerialize, IntoBoxed, WireProfile,
};
use rtos_block::{fail, KeyId, KeyOption, Result, ShardIdent, ValidatorDescr};
use std::sync::Arc;

const MAX_FAST_SYNC_OVERLAY_CLIENTS: usize = 5;

pub(super) fn fast_sync_transport_authority(
    validators: &[ValidatorDescr],
    profile: WireProfile,
) -> Result<(Vec<Arc<KeyId>>, Vec<Arc<KeyId>>)> {
    if profile == WireProfile::Legacy {
        let mut members = Vec::with_capacity(validators.len());
        let mut roots = Vec::with_capacity(validators.len());
        for validator in validators {
            members.push(validator.adnl_addr()?);
            roots.push(validator.public_key()?.pub_key().id().clone());
        }
        return Ok((members, roots));
    }
    // Target membership and certificate authority use the same transport
    // identity. Consensus keys and stable PQ validator IDs are not roots.
    let mut roots = Vec::with_capacity(validators.len());
    for validator in validators {
        let root = match validator.adnl_addr.as_ref().filter(|id| !id.is_zero()) {
            Some(id) => KeyId::from_data(*id.as_array()),
            // Only classical descriptors may leave the transport ID implicit.
            None => validator.public_key()?.pub_key().id().clone(),
        };
        roots.push(root);
    }
    roots.sort_by(|left, right| left.data().cmp(right.data()));
    roots.dedup();
    Ok((roots.clone(), roots))
}

pub struct FastSyncOverlayClient {
    id: Arc<OverlayShortId>,
    shard: ShardIdent,
    client: Arc<OverlayClient>,
    engine: Arc<dyn EngineOperations>,
    use_twostep: bool,
    pub(super) propagation_signer: Option<Arc<dyn KeyOption>>,
    tasks: Arc<OwnedTasks>,
    #[cfg(test)]
    received_for_test: std::sync::Mutex<(
        std::collections::HashSet<rtos_block::BlockIdExt>,
        std::collections::HashSet<rtos_block::BlockIdExt>,
    )>,
    #[cfg(test)]
    exit_gate: std::sync::Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
}

impl FastSyncOverlayClient {
    pub(crate) async fn new(
        shard: ShardIdent,
        validators: &[ValidatorDescr],
        key: Option<&Arc<dyn KeyOption>>,
        certificate: Option<MemberCertificate>,
        cancellation_token: tokio_util::sync::CancellationToken,
        network_context: Arc<NetworkContext>,
        engine: Arc<dyn EngineOperations>,
        policy: DhtSearchPolicy,
        default_rldp_roundtrip: Option<u32>,
        use_quic: bool,
        owner: Arc<OwnedTasks>,
    ) -> Result<Arc<Self>> {
        let (root_adnl_ids, root_public_keys) = fast_sync_transport_authority(
            validators,
            network_context.stack.overlay.wire_profile(),
        )?;
        let id = rtos_api::ton::ton_node::fastsyncoverlayid::FastSyncOverlayId {
            zero_state_file_hash: engine.zerostate_id()?.file_hash().clone(),
            shard: (&shard).into(),
        };
        let id_full = rtos_block::UInt256::calc_file_hash(
            &network_context.stack.overlay.wire_profile().serialize(&id.into_boxed())?,
        )
        .as_slice()
        .to_owned();
        let overlay_key = OverlayKey { name: id_full.clone().into() };
        let id_short = OverlayShortId::from_data(hash(overlay_key)?);

        let use_twostep = use_quic && network_context.stack.quic.is_some() && key.is_some();
        if use_quic && !use_twostep {
            log::warn!("Fast sync overlay {id_short}: use_quic=true but QUIC or key not available");
        }

        log::info!(
            "Creating fast sync overlay client for shard {shard}, id: {id_short}, adnl id: {}",
            key.map(|k| k.id().to_string()).unwrap_or_default()
        );

        let client = OverlayClient::new_semiprivate(
            id_short.clone(),
            id_full,
            root_adnl_ids,
            root_public_keys,
            key,
            certificate,
            network_context,
            cancellation_token.clone(),
            policy,
            default_rldp_roundtrip,
            MAX_FAST_SYNC_OVERLAY_CLIENTS,
            use_twostep,
            owner.clone(),
        )
        .await?;

        let subscription = match client.subscribe_broadcast() {
            Ok(subscription) => subscription,
            Err(error) => {
                let _ = client.delete();
                return Err(error);
            }
        };
        let result = Arc::new(Self {
            id: id_short,
            shard,
            client,
            engine,
            use_twostep,
            propagation_signer: key.cloned(),
            tasks: Arc::new(OwnedTasks::child(owner, cancellation_token)),
            #[cfg(test)]
            received_for_test: Default::default(),
            #[cfg(test)]
            exit_gate: std::sync::Mutex::new(None),
        });

        if let Err(error) = result.clone().listen_broadcasts(subscription) {
            result.stop();
            return Err(error);
        }

        Ok(result)
    }

    pub(super) fn shard(&self) -> &ShardIdent {
        &self.shard
    }

    pub fn id(&self) -> &OverlayShortId {
        &self.id
    }

    pub fn client(&self) -> &Arc<OverlayClient> {
        &self.client
    }

    #[cfg(test)]
    pub(crate) fn received_candidate_and_finality(&self, id: &rtos_block::BlockIdExt) -> bool {
        let seen = self.received_for_test.lock().unwrap();
        seen.0.contains(id) && seen.1.contains(id)
    }

    #[cfg(test)]
    pub(crate) fn hold_listener_exit(&self) -> tokio::sync::oneshot::Sender<()> {
        let (release, gate) = tokio::sync::oneshot::channel();
        *self.exit_gate.lock().unwrap() = Some(gate);
        release
    }

    pub fn stop(&self) {
        log::info!("Stopping fast sync overlay {} {}", self.shard, self.id);
        self.tasks.stop();
        self.client.delete().ok();
    }

    pub async fn stop_and_wait(&self) -> Result<()> {
        self.stop();
        let (listener, client) = tokio::join!(self.tasks.wait(), self.client.stop_and_wait());
        if listener.is_err() || client.is_err() {
            fail!("Fast overlay shutdown: listener={listener:?}; client={client:?}");
        }
        Ok(())
    }

    fn listen_broadcasts(
        self: Arc<Self>,
        mut subscription: adnl::BroadcastSubscription,
    ) -> Result<()> {
        let tasks = self.tasks.clone();
        tasks.spawn("fast-sync broadcast listener", async move {
            log::debug!(
                "Started listening broadcasts in fast sync overlay {} {}",
                self.shard,
                self.id
            );
            loop {
                if self.engine.check_stop() || self.tasks.cancellation().is_cancelled() {
                    break;
                }
                if !check_sync_for_listen_bcasts(self.engine.as_ref()) {
                    log::debug!(
                        "Node is not synced, pause processing broadcasts for fast sync overlay {} {}",
                        self.shard,
                        self.id
                    );
                    tokio::select! { _ = self.tasks.cancellation().cancelled() => break, _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {} }
                    continue;
                }
                let broadcast = tokio::select! { biased; _ = self.tasks.cancellation().cancelled() => break, result = self.client.wait_broadcast(&mut subscription) => result };
                match broadcast {
                    Err(e) => {
                        log::error!(
                            "Error while wait_broadcast in fast sync overlay {} {}: {e}",
                            self.shard,
                            self.id
                        );
                        // Wait for the graceful loop exit
                        tokio::select! { _ = self.tasks.cancellation().cancelled() => break, _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {} }
                    }
                    Ok(None) => {
                        log::debug!(
                            "Finish listening broadcasts in fast sync overlay {} {}",
                            self.shard,
                            self.id
                        );
                        break;
                    }
                    Ok(Some((broadcast, src, received_bytes))) => {
                        log::trace!(
                            "Received broadcast {:08x} in fast sync overlay {} {} from {src}",
                            broadcast.bare_object().constructor(),
                            self.shard,
                            self.id
                        );
                        if let Err(e) =
                            self.process_broadcast(&src, broadcast, received_bytes).await
                        {
                            log::warn!(
                                "Error while processing broadcast from {src} \
                                in fast sync overlay {} {}: {e}",
                                self.shard,
                                self.id
                            );
                        }
                    }
                }
            }
            #[cfg(test)]
            {
                let gate = self.exit_gate.lock().unwrap().take();
                if let Some(gate) = gate { let _ = gate.await; }
            }
        })?;
        Ok(())
    }

    async fn process_broadcast(
        &self,
        src: &Arc<KeyId>,
        broadcast: Broadcast,
        received_bytes: usize,
    ) -> Result<()> {
        match broadcast {
            Broadcast::TonNode_BlockFinalityBroadcast(broadcast) => {
                #[cfg(test)]
                let received_id = broadcast.id.clone();
                self.engine.clone().process_block_finality_broadcast(
                    broadcast, src.clone(), received_bytes,
                ).await?;
                #[cfg(test)]
                self.received_for_test.lock().unwrap().1.insert(received_id);
            }
            Broadcast::TonNode_BlockBroadcast(broadcast) => {
                self.engine.clone().process_block_broadcast(broadcast, src.clone())
            }
            Broadcast::TonNode_ExternalMessageBroadcast(_broadcast) => log::warn!(
                "ExternalMessageBroadcast from {src} is not allowed \
                    in fast sync overlay {} {}",
                self.shard,
                self.id
            ),
            Broadcast::TonNode_IhrMessageBroadcast(_broadcast) => log::warn!(
                "IhrMessageBroadcast from {src} is not allowed in fast sync overlay {} {}",
                self.shard,
                self.id
            ),
            Broadcast::TonNode_NewShardBlockBroadcast(broadcast) => {
                self.engine.clone().process_new_shard_block_broadcast(broadcast, src.clone())
            }
            Broadcast::TonNode_BlockBroadcastCompressed(broadcast) => {
                match decompress_block_broadcast(broadcast, self.client.network_context().stack.overlay.wire_profile()) {
                    Err(e) => log::error!("Error decompressing block broadcast: {e}"),
                    Ok(b) => self.engine.clone().process_block_broadcast(b, src.clone()),
                }
            }
            Broadcast::TonNode_BlockBroadcastCompressedV2(broadcast) => {
                match decompress_block_broadcast_v2(broadcast) {
                    Err(e) => log::error!("Error decompressing block broadcast V2: {e}"),
                    Ok(b) => self.engine.clone().process_block_broadcast_v2(b, src.clone()),
                }
            }
            Broadcast::TonNode_NewBlockCandidateBroadcast(broadcast) => {
                log::debug!(
                    "NewBlockCandidateBroadcast {} (overlay {}) received from {src}",
                    broadcast.id,
                    self.id
                );
                check_block_candidate_data(&broadcast)?;
                self.engine.cache_block_candidate(
                    &broadcast.id,
                    broadcast.catchain_seqno as u32,
                    broadcast.validator_set_hash as u32,
                    broadcast.collator_signature.try_into().unwrap_or_default(),
                    broadcast.data,
                )?;
                #[cfg(test)]
                self.received_for_test.lock().unwrap().0.insert(broadcast.id.clone());
            }
            Broadcast::TonNode_NewBlockCandidateBroadcastCompressed(broadcast) => {
                log::debug!(
                    "NewBlockCandidateBroadcastCompressed {} (overlay {}) received from {src}",
                    broadcast.id,
                    self.id
                );
                let data = decompress_and_check_candidate_data(&broadcast)?;
                self.engine.cache_block_candidate(
                    &broadcast.id,
                    broadcast.catchain_seqno as u32,
                    broadcast.validator_set_hash as u32,
                    broadcast.collator_signature.try_into().unwrap_or_default(),
                    data,
                )?;
                #[cfg(test)]
                self.received_for_test.lock().unwrap().0.insert(broadcast.id.clone());
            }
            Broadcast::TonNode_NewBlockCandidateBroadcastCompressedV2(_broadcast) => log::warn!(
                "NewBlockCandidateBroadcastCompressedV2 from {src} is not supported in fast sync overlay {} {}",
                self.shard,
                self.id
            ),
            Broadcast::TonNode_OutMsgQueueProofBroadcast(_) => {
                fail!("OutMsgQueueProofBroadcast processing is not implemented")
            }
        }
        Ok(())
    }

    pub async fn send_broadcast(
        &self,
        data: &TaggedByteSlice<'_>,
        flags: u32,
        method: AdnlSendMethod,
    ) -> Result<()> {
        match self
            .client
            .broadcast(data, None, flags | OverlayNode::FLAG_BCAST_ANY_SENDER, method)
            .await
        {
            Ok(info) => {
                #[cfg(feature = "telemetry")]
                log::debug!(
                    "sent broadcast {:08x} in {} to {} nodes",
                    data.tag,
                    self.id,
                    info.send_to
                );
                #[cfg(not(feature = "telemetry"))]
                log::debug!("sent broadcast in {} to {} nodes", self.id, info.send_to);

                Ok(())
            }
            Err(e) => {
                log::warn!("Error sending broadcast: {}", e);
                Err(e)
            }
        }
    }

    pub async fn send_twostep_broadcast(
        &self,
        data: &TaggedByteSlice<'_>,
        flags: u32,
    ) -> Result<()> {
        match self
            .client
            .broadcast_twostep(data, None, flags | OverlayNode::FLAG_BCAST_ANY_SENDER)
            .await
        {
            Ok(info) => {
                #[cfg(feature = "telemetry")]
                log::debug!(
                    "sent twostep broadcast {:08x} in {} to {} nodes",
                    data.tag,
                    self.id,
                    info.send_to
                );
                #[cfg(not(feature = "telemetry"))]
                log::debug!("sent twostep broadcast in {} to {} nodes", self.id, info.send_to);

                Ok(())
            }
            Err(e) => {
                log::warn!("Error sending twostep broadcast: {}", e);
                Err(e)
            }
        }
    }

    pub fn use_twostep(&self) -> bool {
        self.use_twostep
    }
}

#[cfg(test)]
#[path = "tests/test_fast_sync_transport_authority.rs"]
mod transport_authority_tests;
