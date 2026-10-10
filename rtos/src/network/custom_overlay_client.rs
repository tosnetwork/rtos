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
        check_block_candidate_data, decompress_and_check_candidate_data,
        decompress_and_check_candidate_data_v2, decompress_block_broadcast,
        decompress_block_broadcast_v2, node_network::NodeNetwork,
    },
    types::owned_tasks::OwnedTasks,
};
use adnl::{
    common::{hash, TaggedByteSlice},
    BroadcastRecvInfo, NetworkStack, OverlayNode, OverlayParams, OverlayShortId,
};
use rtos_api::{
    ton::{
        engine::validator::{customoverlay::CustomOverlay, customoverlaynode::CustomOverlayNode},
        pub_::publickey::Overlay as OverlayKey,
        ton_node::{customoverlayid::CustomOverlayId, Broadcast},
        Bool,
    },
    BoxedSerialize, IntoBoxed,
};
use rtos_block::{error, fail, AccountIdPrefixFull, KeyId, Result, ShardIdent, UInt256};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

pub struct CustomOverlayClient {
    id: Arc<OverlayShortId>,
    config: CustomOverlay,
    nodes: HashMap<Arc<KeyId>, CustomOverlayNode>,
    shards: Vec<ShardIdent>,
    // Don't send external messages to public overlays
    skip_public_msg_send: bool,
    // Per-overlay opt-in for QUIC two-step broadcasts, from TL config.
    use_quic: bool,
    stack: Arc<NetworkStack>,
    engine: Arc<dyn EngineOperations>,
    cancellation_token: tokio_util::sync::CancellationToken,
    // Inactive overlay doesn't have key and not added at protocol level (OverlayNode).
    // Client can become active later by calling try_activate().
    is_active: AtomicBool,
    is_msg_sender: AtomicBool,
    is_block_sender: AtomicBool,
    tasks: Arc<OwnedTasks>,
    #[cfg(test)]
    exit_gate: std::sync::Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    activation: std::sync::Mutex<()>,
}

impl CustomOverlayClient {
    pub(crate) fn new(
        config: &CustomOverlay,
        cancellation_token: tokio_util::sync::CancellationToken,
        stack: Arc<NetworkStack>,
        engine: Arc<dyn EngineOperations>,
        owner: Arc<OwnedTasks>,
    ) -> Result<Arc<Self>> {
        let quic_available = stack.quic.is_some();
        let mut nodes = HashMap::new();
        for node in &config.nodes {
            let id = KeyId::from_data(node.adnl_id.as_slice().to_owned());
            nodes.insert(id, node.clone());
        }
        let id_short = Self::calc_overlay_id_with_profile(
            config,
            engine.zerostate_id()?.file_hash(),
            stack.overlay.wire_profile(),
        )?;
        log::debug!("Creating custom overlay {} with id {}", config.name, id_short);

        let mut shards = Vec::new();
        for shard_id in &config.sender_shards {
            shards.push(ShardIdent::try_from(shard_id)?);
        }
        let use_quic: bool = (&config.use_quic).into();
        if use_quic && !quic_available {
            log::warn!(
                "Custom overlay \"{}\" {id_short} requests use_quic \
                but QUIC stack is not available; falling back to RLDP two-step broadcasts",
                config.name
            );
        }
        let result = Arc::new(Self {
            id: id_short,
            config: config.clone(),
            nodes,
            shards,
            skip_public_msg_send: (&config.skip_public_msg_send).into(),
            use_quic,
            stack,
            engine,
            tasks: Arc::new(OwnedTasks::child(owner, cancellation_token.clone())),
            activation: std::sync::Mutex::new(()),
            #[cfg(test)]
            exit_gate: std::sync::Mutex::new(None),
            cancellation_token,
            is_active: AtomicBool::new(false),
            is_msg_sender: AtomicBool::new(false),
            is_block_sender: AtomicBool::new(false),
        });

        let activated = match result.clone().try_activate() {
            Ok(active) => active,
            Err(error) => {
                result.stop();
                return Err(error);
            }
        };
        if activated {
            log::info!("Custom overlay \"{}\" with id {} created", config.name, result.id);
        } else {
            log::info!(
                "Custom overlay \"{}\" with id {} created as inactive (no key)",
                config.name,
                result.id
            );
        }
        Ok(result)
    }

    pub fn try_activate(self: Arc<Self>) -> Result<bool> {
        let _activation = self.activation.lock().unwrap();
        let _admission = self.tasks.enter()?;
        let mut attempt = 0;
        loop {
            if self.is_active.load(Ordering::Relaxed) {
                return Ok(true);
            }
            let mut peers = Vec::new();
            let mut key = None;
            for node in &self.config.nodes {
                let id = KeyId::from_data(node.adnl_id.as_slice().to_owned());
                if let Ok(k) = self.stack.adnl.key_by_id(&id) {
                    key = Some(k);
                    self.is_msg_sender
                        .store(matches!(node.msg_sender, Bool::BoolTrue), Ordering::Relaxed);
                    self.is_block_sender
                        .store(matches!(node.block_sender, Bool::BoolTrue), Ordering::Relaxed);
                }
                peers.push(id.clone());
            }
            let Some(key) = key else {
                return Ok(false);
            };
            let params =
                OverlayParams { flags: 0, hops: None, overlay_id: &self.id, runtime: None };
            if let Err(e) =
                self.stack.overlay.add_private_overlay(params, &key, &peers, self.use_quic, None)
            {
                attempt += 1;
                if attempt >= 10 {
                    fail!("Error while adding custom overlay \"{}\": {}", self.config.name, e);
                }
                continue;
            }
            let subscription = self.stack.overlay.subscribe_broadcast(&self.id)?;
            self.is_active.store(true, Ordering::Relaxed);
            self.clone().listen_broadcasts(subscription)?;
            self.tasks.spawn_handle("custom overlay peer resolver", || {
                NodeNetwork::spawn_overlay_peer_resolver(
                    key.id().clone(),
                    self.nodes.keys().cloned().collect(),
                    self.stack.dht.clone(),
                    self.stack.overlay.clone(),
                    self.cancellation_token.child_token(),
                    format!("custom overlay {}", self.id),
                )
            })?;
            log::info!("Custom overlay \"{}\" with id {} activated", self.config.name, self.id);
            return Ok(true);
        }
    }

    #[allow(dead_code)]
    pub fn id(&self) -> &OverlayShortId {
        &self.id
    }

    #[cfg(test)]
    pub(crate) fn hold_listener_exit(&self) -> tokio::sync::oneshot::Sender<()> {
        let (release, gate) = tokio::sync::oneshot::channel();
        *self.exit_gate.lock().unwrap() = Some(gate);
        release
    }

    pub fn stop(&self) {
        let _activation = self.activation.lock().unwrap();
        self.tasks.stop();
        log::debug!("Stopping custom overlay \"{}\"", self.config.name);
        self.cancellation_token.cancel();
        if let Err(e) = self.stack.overlay.delete_private_overlay(&self.id) {
            self.tasks.record_error(format!("Custom overlay {} deletion: {e}", self.id));
            log::error!("Error while deleting custom overlay \"{}\": {}", self.config.name, e);
        }
    }

    pub async fn stop_and_wait(&self) -> Result<()> {
        self.stop();
        self.tasks.wait().await
    }

    pub fn skip_public_msg_send(&self) -> bool {
        self.skip_public_msg_send
    }

    pub fn sends_msgs_to(&self, to: &AccountIdPrefixFull) -> bool {
        if self.is_msg_sender.load(Ordering::Relaxed) {
            for shard in &self.shards {
                if shard.contains_full_prefix(to) {
                    return true;
                }
            }
        }
        false
    }

    pub fn sends_blocks_to(&self, shard: &ShardIdent) -> bool {
        if self.is_block_sender.load(Ordering::Relaxed) {
            for s in &self.shards {
                if s.intersect_with(shard) {
                    return true;
                }
            }
        }
        false
    }

    fn listen_broadcasts(
        self: Arc<Self>,
        mut subscription: adnl::BroadcastSubscription,
    ) -> Result<()> {
        let tasks = self.tasks.clone();
        tasks.spawn("custom overlay broadcast listener", async move {
            log::debug!(
                "Started listening broadcasts in custom overlay \"{}\" {}",
                self.config.name,
                self.id
            );
            loop {
                if self.engine.check_stop() || self.cancellation_token.is_cancelled() {
                    break;
                }
                let broadcast = tokio::select! { biased; _ = self.cancellation_token.cancelled() => break, result = subscription.recv() => result };
                match broadcast {
                    Err(e) => log::error!(
                        "Error while wait_broadcast in custom overlay \"{}\" {}: {}",
                        self.config.name,
                        self.id,
                        e
                    ),
                    Ok(None) => {
                        log::debug!(
                            "Finish listening broadcasts in custom overlay \"{}\" {}",
                            self.config.name,
                            self.id
                        );
                        break;
                    }
                    Ok(Some(info)) => {
                        log::trace!(
                            "Received broadcast in custom overlay \"{}\" {} from {}",
                            self.config.name,
                            self.id,
                            info.recv_from
                        );
                        if let Err(e) = self.process_broadcast(&info).await {
                            log::warn!(
                                "Error while processing broadcast from {} \
                                in custom overlay \"{}\" {}: {e}",
                                info.recv_from,
                                self.config.name,
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

    async fn process_broadcast(&self, info: &BroadcastRecvInfo) -> Result<()> {
        let broadcast: Broadcast =
            self.stack.overlay.wire_profile().deserialize_typed(&info.data)?;
        let src = &info.recv_from;
        log::trace!(
            "Received broadcast {:08x} in custom overlay {} {} from {src}",
            broadcast.bare_object().constructor(),
            self.config.name,
            self.id
        );
        match broadcast {
            Broadcast::TonNode_BlockFinalityBroadcast(broadcast) => {
                self.check_send_block_permission(src)?;
                self.engine
                    .clone()
                    .process_block_finality_broadcast(broadcast, src.clone(), info.data.len())
                    .await?;
            }
            Broadcast::TonNode_BlockBroadcast(broadcast) => {
                self.check_send_block_permission(src)?;
                self.engine.clone().process_block_broadcast(broadcast, src.clone())
            }
            Broadcast::TonNode_ExternalMessageBroadcast(broadcast) => {
                self.check_send_message_permission(src)?;
                self.engine.process_ext_msg_broadcast(broadcast, src.clone()).await
            }
            Broadcast::TonNode_IhrMessageBroadcast(_broadcast) => log::warn!(
                "IhrMessageBroadcast from {src} is not allowed in custom overlay \"{}\" {}",
                self.config.name,
                self.id
            ),
            Broadcast::TonNode_NewShardBlockBroadcast(broadcast) => {
                self.check_send_block_permission(src)?;
                self.engine.clone().process_new_shard_block_broadcast(broadcast, src.clone())
            }
            Broadcast::TonNode_BlockBroadcastCompressed(broadcast) => {
                self.check_send_block_permission(src)?;
                let bb = decompress_block_broadcast(broadcast, self.stack.overlay.wire_profile())
                    .map_err(|e| {
                    error!(
                        "Error decompressing block broadcast: \
                        {e} in custom overlay \"{}\" {} from {src}",
                        self.config.name, self.id
                    )
                })?;
                self.engine.clone().process_block_broadcast(bb, src.clone())
            }
            Broadcast::TonNode_BlockBroadcastCompressedV2(broadcast) => {
                self.check_send_block_permission(src)?;
                let bb = decompress_block_broadcast_v2(broadcast).map_err(|e| {
                    error!(
                        "Error decompressing block broadcast V2: \
                        {e} in custom overlay \"{}\" {} from {src}",
                        self.config.name, self.id
                    )
                })?;
                self.engine.clone().process_block_broadcast_v2(bb, src.clone())
            }
            Broadcast::TonNode_NewBlockCandidateBroadcast(broadcast) => {
                self.check_send_block_permission(src)?;
                check_block_candidate_data(&broadcast)?;
                self.engine.cache_block_candidate(
                    &broadcast.id,
                    broadcast.catchain_seqno as u32,
                    broadcast.validator_set_hash as u32,
                    broadcast.collator_signature.try_into().unwrap_or_default(),
                    broadcast.data,
                )?;
            }
            Broadcast::TonNode_NewBlockCandidateBroadcastCompressed(broadcast) => {
                self.check_send_block_permission(src)?;
                let data = decompress_and_check_candidate_data(&broadcast)?;
                self.engine.cache_block_candidate(
                    &broadcast.id,
                    broadcast.catchain_seqno as u32,
                    broadcast.validator_set_hash as u32,
                    broadcast.collator_signature.try_into().unwrap_or_default(),
                    data,
                )?;
            }
            Broadcast::TonNode_NewBlockCandidateBroadcastCompressedV2(broadcast) => {
                self.check_send_block_permission(src)?;
                let data = decompress_and_check_candidate_data_v2(&broadcast)?;
                self.engine.cache_block_candidate(
                    &broadcast.id,
                    broadcast.catchain_seqno as u32,
                    broadcast.validator_set_hash as u32,
                    broadcast.collator_signature.try_into().unwrap_or_default(),
                    data,
                )?;
            }
            Broadcast::TonNode_OutMsgQueueProofBroadcast(_) => log::debug!(
                "OutMsgQueueProofBroadcast from {src} is not supported \
                    in custom overlay \"{}\" {}",
                self.config.name,
                self.id
            ),
        }
        Ok(())
    }

    fn check_send_block_permission(&self, sender: &Arc<KeyId>) -> Result<()> {
        if let Some(node) = self.nodes.get(sender) {
            if matches!(node.block_sender, Bool::BoolFalse) {
                fail!(
                    "Node {} is not allowed to send blocks in custom overlay \"{}\" {}",
                    sender,
                    self.config.name,
                    self.id
                );
            }
            Ok(())
        } else {
            fail!("Unknown node {} in custom overlay \"{}\" {}", sender, self.config.name, self.id);
        }
    }

    fn check_send_message_permission(&self, sender: &Arc<KeyId>) -> Result<()> {
        if let Some(node) = self.nodes.get(sender) {
            if matches!(node.msg_sender, Bool::BoolFalse) {
                fail!(
                    "Node {} is not allowed to send messages in custom overlay \"{}\" {}",
                    sender,
                    self.config.name,
                    self.id
                );
            }
            Ok(())
        } else {
            fail!("Unknown node {} in custom overlay \"{}\" {}", sender, self.config.name, self.id);
        }
    }

    pub async fn send_broadcast(&self, data: &TaggedByteSlice<'_>, flags: u32) -> Result<()> {
        if !self.is_active.load(Ordering::Relaxed) {
            return Ok(());
        }
        match self
            .stack
            .overlay
            .broadcast_twostep(
                &self.id,
                data,
                None,
                flags | OverlayNode::FLAG_BCAST_ANY_SENDER,
                Vec::new(),
            )
            .await
        {
            Ok(info) => {
                #[cfg(feature = "telemetry")]
                log::debug!(
                    "sent twostep broadcast {:08x} in \"{}\" {} to {} nodes",
                    data.tag,
                    self.config.name,
                    self.id,
                    info.send_to
                );
                #[cfg(not(feature = "telemetry"))]
                log::debug!(
                    "sent twostep broadcast in \"{}\" {} to {} nodes",
                    self.config.name,
                    self.id,
                    info.send_to
                );
                Ok(())
            }
            Err(e) => {
                log::warn!(
                    "Error sending twostep broadcast in \"{}\" {}: {}",
                    self.config.name,
                    self.id,
                    e
                );
                Err(e)
            }
        }
    }

    pub fn calc_overlay_id(
        config: &CustomOverlay,
        zero_state_file_hash: &UInt256,
    ) -> Result<Arc<OverlayShortId>> {
        Self::calc_overlay_id_with_profile(
            config,
            zero_state_file_hash,
            rtos_api::WireProfile::Legacy,
        )
    }

    pub fn calc_overlay_id_with_profile(
        config: &CustomOverlay,
        zero_state_file_hash: &UInt256,
        profile: rtos_api::WireProfile,
    ) -> Result<Arc<OverlayShortId>> {
        let mut nodes: Vec<UInt256> = config.nodes.iter().map(|n| n.adnl_id.clone()).collect();
        nodes.sort();
        let id_full = CustomOverlayId {
            zero_state_file_hash: zero_state_file_hash.clone(),
            name: config.name.clone(),
            nodes,
        };
        let overlay_key = OverlayKey {
            name: UInt256::calc_file_hash(&profile.serialize(&id_full.into_boxed())?)
                .as_slice()
                .to_vec(),
        };
        let id_short = OverlayShortId::from_data(hash(overlay_key)?);
        Ok(id_short)
    }
}
