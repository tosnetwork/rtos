/*
 * RTOS project modifications (2026-10-10): project and crate naming; explicit target wire profile integration; owned consumer readiness and authenticated finality recovery.
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::history_read_budget::{HistoryReadBudget, NetworkGraphReservation};
use crate::{
    block::BlockStuff,
    block_proof::BlockProofStuff,
    engine_traits::EngineOperations,
    network::{
        check_block_candidate_data, check_sync_for_listen_bcasts,
        decompress_and_check_candidate_data, decompress_block_broadcast,
        decompress_block_broadcast_v2, neighbours::Neighbour, overlay_client::OverlayClient,
        MAX_COMPRESSED_SIZE,
    },
    shard_state::ShardStateStuff,
    types::owned_tasks::OwnedTasks,
};
use adnl::{
    common::{TaggedByteSlice, TaggedObject},
    node::AdnlSendMethod,
};
#[cfg(feature = "telemetry")]
use rtos_api::Constructor;
use rtos_api::{
    ton::{
        rpc::ton_node::{
            DownloadBlockFull, DownloadBlockProof, DownloadBlockProofLink, DownloadKeyBlockProof,
            DownloadKeyBlockProofLink, DownloadNextBlockFull, DownloadPersistentStateSliceV2,
            DownloadZeroState, GetArchiveInfo, GetArchiveSlice, GetNextBlockDescription,
            GetNextKeyBlockIds, GetPersistentStateSizeV2, GetShardArchiveInfo, PrepareBlock,
            PrepareBlockProof, PrepareKeyBlockProof, PreparePersistentState, PrepareZeroState,
        },
        ton_node::{
            persistentstateidv2::PersistentStateIdV2, shardid::ShardId, ArchiveInfo,
            BlockDescription, Broadcast, DataFull, KeyBlocks, PersistentStateSize, Prepared,
            PreparedProof, PreparedState,
        },
    },
    AnyBoxedSerialize, BoxedSerialize,
};
use rtos_block::{
    error, fail, lz4_decompress, read_boc, write_boc, BlockIdExt, BocFlags, BocWriter, KeyId,
    KeyOption, Lz4DecompressMode, Result, ShardIdent,
};
use std::sync::Arc;

struct HistoryNetworkDecode {
    budget: Arc<HistoryReadBudget>,
    graph: Option<NetworkGraphReservation>,
}
impl HistoryNetworkDecode {
    fn parse(&mut self, inputs: &[&[u8]]) -> Result<Vec<rtos_block::BocReaderResult>> {
        self.graph
            .take()
            .ok_or_else(|| error!("Network graph already consumed"))?
            .parse_many(inputs)
    }
}

use storage::types::PersistentStatePartId;

/// Terminal rejection by the scoped BOC decoder (including malformed input and
/// depth limits). The original decoder error remains in the error chain; this
/// context deliberately does not invent an actual size or match error strings.
#[derive(Debug)]
pub struct BoundedBocDecodeRejected {
    pub phase: &'static str,
}
impl std::fmt::Display for BoundedBocDecodeRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "bounded network BOC {} rejected", self.phase)
    }
}
impl std::error::Error for BoundedBocDecodeRejected {}

fn checked_pss_slice(
    offset: usize,
    max_size: usize,
    limits: adnl::QueryResponseLimits,
) -> Result<(i64, i64)> {
    limits.validate()?;
    if max_size == 0
        || max_size > (1 << 21)
        || limits.wire_bytes > max_size
        || limits.decoded_bytes > max_size
    {
        fail!("Invalid bounded PSS slice size");
    }
    let end =
        offset.checked_add(max_size).ok_or_else(|| rtos_block::error!("PSS range overflow"))?;
    let offset = i64::try_from(offset)?;
    let size = i64::try_from(max_size)?;
    i64::try_from(end)?;
    Ok((offset, size))
}

// Keep one decoding path for both network wrappers and deterministic tests.
fn decode_bounded_pair(
    id: &BlockIdExt,
    data_full: DataFull,
    limits: NetworkDownloadLimits,
    mut history: Option<HistoryNetworkDecode>,
) -> Result<(BlockStuff, BlockProofStuff)> {
    let (block_data, proof_data, is_link, roots) = match data_full {
        DataFull::TonNode_DataFull(value) => {
            if id != &value.id {
                fail!("Block with another id was received");
            }
            (value.block, value.proof, value.is_link.into(), None)
        }
        DataFull::TonNode_DataFullCompressed(value) => {
            if id != &value.id {
                fail!("Block with another id was received");
            }
            let decompressed = decompress_pair_payload(
                &value.compressed,
                limits.expanded_bytes,
                history.as_ref().map(|h| h.budget.as_ref()),
            )?;
            NetworkDownloadLimits::check_bytes(decompressed.len(), limits.expanded_bytes)?;
            let mut roots = if let Some(history) = history.as_mut() {
                history.parse(&[&decompressed])?.remove(0).roots
            } else {
                limits.parse_boc(&decompressed, limits.expanded_bytes)?.roots
            };
            if roots.len() != 2 {
                fail!("DataFullCompressed contains {} roots instead of 2", roots.len());
            }
            let proof_root = roots.remove(0);
            let block_root = roots.remove(0);
            let (proof_data, block_data) = if let Some(history) = history.as_mut() {
                (
                    encode_history_network_boc(
                        &proof_root,
                        BocFlags::None,
                        limits.proof_bytes,
                        &history.budget,
                    )?,
                    encode_history_network_boc(
                        &block_root,
                        BocFlags::all(),
                        limits.block_bytes,
                        &history.budget,
                    )?,
                )
            } else {
                let mut proof_output =
                    LimitedBocOutput { bytes: Vec::new(), limit: limits.proof_bytes };
                BocWriter::with_root(&proof_root)?.write(&mut proof_output)?;
                let mut block_output =
                    LimitedBocOutput { bytes: Vec::new(), limit: limits.block_bytes };
                BocWriter::with_flags([block_root.clone()], BocFlags::all())?
                    .write(&mut block_output)?;
                (proof_output.bytes, block_output.bytes)
            };
            (block_data, proof_data, value.is_link.into(), Some((block_root, proof_root)))
        }
        DataFull::TonNode_DataFullEmpty => fail!("DownloadBlockFull returned DataFullEmpty"),
    };
    if let Some(history) = history.as_mut() {
        let (block_root, proof_root) = match roots {
            Some(roots) => roots,
            None => {
                NetworkDownloadLimits::check_bytes(block_data.len(), limits.block_bytes)?;
                NetworkDownloadLimits::check_bytes(proof_data.len(), limits.proof_bytes)?;
                let mut parsed = history.parse(&[&block_data, &proof_data])?;
                let block = parsed.remove(0).withdraw_single_root()?;
                let proof = parsed.remove(0).withdraw_single_root()?;
                (block, proof)
            }
        };
        let proof = BlockProofStuff::from_parsed_history_root(
            id,
            proof_data,
            is_link,
            proof_root,
            &history.budget,
        )?;
        let block = BlockStuff::from_parsed_history_root(
            id.clone(),
            Arc::new(block_data),
            block_root,
            &history.budget,
        )?;
        Ok((block, proof))
    } else {
        limits.parse_boc(&block_data, limits.block_bytes)?;
        limits.parse_boc(&proof_data, limits.proof_bytes)?;
        Ok((
            BlockStuff::deserialize_block_checked(id.clone(), Arc::new(block_data))?,
            BlockProofStuff::deserialize(id, proof_data, is_link)?,
        ))
    }
}

fn encode_history_network_boc(
    root: &rtos_block::Cell,
    flags: BocFlags,
    limit: usize,
    budget: &Arc<HistoryReadBudget>,
) -> Result<Vec<u8>> {
    let config_budget = crate::bounded_session_derivation::ConfigBudget(budget);
    let writer = BocWriter::with_flags_bounded([root.clone()], flags, &config_budget)?;
    let length = writer.calc_boc_size();
    NetworkDownloadLimits::check_bytes(length, limit)?;
    let output = writer.write_to_vec()?;
    if output.len() != length {
        fail!("Bounded network BOC length mismatch");
    }
    Ok(output)
}

/// Per-request bounds. These limit encoded buffers and BOC cardinality, not total heap usage.
#[derive(Clone, Copy, Debug)]
pub struct NetworkDownloadLimits {
    pub wire_bytes: usize,
    pub response_bytes: usize,
    pub expanded_bytes: usize,
    pub block_bytes: usize,
    pub proof_bytes: usize,
    pub boc_cells: usize,
    pub boc_depth: u16,
}
impl NetworkDownloadLimits {
    pub fn proof(bytes: usize, cells: usize, depth: u16) -> Self {
        Self {
            wire_bytes: bytes,
            response_bytes: bytes,
            expanded_bytes: bytes,
            block_bytes: 0,
            proof_bytes: bytes,
            boc_cells: cells,
            boc_depth: depth,
        }
    }
    fn transport(self) -> Result<adnl::QueryResponseLimits> {
        let limits = adnl::QueryResponseLimits {
            wire_bytes: self.wire_bytes,
            decoded_bytes: self.response_bytes,
        };
        limits.validate()?;
        if self.expanded_bytes > MAX_COMPRESSED_SIZE || self.boc_cells == 0 || self.boc_depth == 0 {
            fail!("Invalid bounded download limits");
        }
        Ok(limits)
    }
    fn check_bytes(actual: usize, limit: usize) -> Result<()> {
        if actual > limit {
            return Err(adnl::ResponseLimitExceeded { limit, actual }.into());
        }
        Ok(())
    }
    fn parse_boc(self, data: &[u8], max_bytes: usize) -> Result<rtos_block::BocReaderResult> {
        Self::check_bytes(data.len(), max_bytes)?;
        let mut reader = rtos_block::BocReader::new().set_max_cell_depth(self.boc_depth);
        let (header, _) = reader
            .read_header(&mut std::io::Cursor::new(data))
            .map_err(|error| error.context(BoundedBocDecodeRejected { phase: "header" }))?;
        Self::check_bytes(header.cells_count, self.boc_cells)?;
        Self::check_bytes(header.tot_cells_size, max_bytes)?;
        reader
            .read(data)
            .map_err(|error| error.context(BoundedBocDecodeRejected { phase: "graph" }))
    }
}

// Admission precedes the preflight scan, then the decoder's input/output
// work. A work unit covers at most 64 bytes, matching bounded BOC bulk work.
fn decompress_pair_payload(
    input: &[u8],
    limit: usize,
    budget: Option<&HistoryReadBudget>,
) -> Result<Vec<u8>> {
    let admit = |bytes: usize| -> Result<()> {
        if let Some(budget) = budget {
            rtos_block::config_read_budget::steps(
                &crate::bounded_session_derivation::ConfigBudget(budget),
                bytes.div_ceil(64).max(1),
            )?;
        }
        Ok(())
    };
    admit(input.len())?;
    let expanded = check_lz4_expansion(input, limit)?;
    admit(input.len())?;
    admit(expanded)?;
    lz4_decompress(input, Lz4DecompressMode::WithMaxSize(i32::try_from(limit)?))
}

// Preflight the raw LZ4 block without allocating its advertised output.
fn check_lz4_expansion(input: &[u8], limit: usize) -> Result<usize> {
    fn length(input: &[u8], pos: &mut usize, initial: usize) -> Result<usize> {
        let mut value = initial;
        if initial == 15 {
            loop {
                let next = *input.get(*pos).ok_or_else(|| error!("Truncated LZ4 length"))? as usize;
                *pos += 1;
                value = value.checked_add(next).ok_or_else(|| error!("LZ4 length overflow"))?;
                if next != 255 {
                    break;
                }
            }
        }
        Ok(value)
    }
    let mut pos = 0;
    let mut output = 0usize;
    while pos < input.len() {
        let token = input[pos];
        pos += 1;
        let literals = length(input, &mut pos, (token >> 4) as usize)?;
        output = output.checked_add(literals).ok_or_else(|| error!("LZ4 length overflow"))?;
        NetworkDownloadLimits::check_bytes(output, limit)?;
        pos = pos.checked_add(literals).ok_or_else(|| error!("LZ4 length overflow"))?;
        if pos > input.len() {
            fail!("Truncated LZ4 literals");
        }
        if pos == input.len() {
            break;
        }
        let offset = input.get(pos..pos + 2).ok_or_else(|| error!("Truncated LZ4 offset"))?;
        let offset = u16::from_le_bytes([offset[0], offset[1]]) as usize;
        if offset == 0 || offset > output {
            fail!("Invalid LZ4 offset");
        }
        pos += 2;
        let matched = length(input, &mut pos, (token & 15) as usize)?;
        output = output
            .checked_add(matched)
            .and_then(|v| v.checked_add(4))
            .ok_or_else(|| error!("LZ4 length overflow"))?;
        NetworkDownloadLimits::check_bytes(output, limit)?;
    }
    Ok(output)
}

struct LimitedBocOutput {
    bytes: Vec<u8>,
    limit: usize,
}
impl std::io::Write for LimitedBocOutput {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let actual = self.bytes.len().saturating_add(bytes.len());
        if actual > self.limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                adnl::ResponseLimitExceeded { limit: self.limit, actual },
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Wrapper for OverlayClient that provides methods for performing fullnode network requests
pub struct FullNodeOverlayClient {
    #[cfg(test)]
    test_consumer_gate: std::sync::Mutex<Option<Arc<super::test_broadcast_faults::ConsumerGate>>>,
    active_peers: lockfree::set::Set<Arc<KeyId>>,
    bad_peers: lockfree::set::Set<Arc<KeyId>>,
    engine: Arc<dyn EngineOperations>,
    client: Arc<OverlayClient>,
    shard: ShardIdent,
    tasks: Arc<OwnedTasks>,
    #[cfg(test)]
    exit_gate: std::sync::Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
}

impl FullNodeOverlayClient {
    const TIMEOUT_PREPARE: u64 = 6000; // Milliseconds
    const FAN_OUT_PEERS: usize = 5;

    pub(crate) fn new(
        engine: Arc<dyn EngineOperations>,
        client: Arc<OverlayClient>,
        shard: ShardIdent,
        owner: Arc<OwnedTasks>,
    ) -> Result<Arc<Self>> {
        let subscription = match client.subscribe_broadcast() {
            Ok(subscription) => subscription,
            Err(error) => {
                let _ = client.delete();
                return Err(error);
            }
        };
        let fnc = Arc::new(Self {
            #[cfg(test)]
            test_consumer_gate: std::sync::Mutex::new(None),
            active_peers: lockfree::set::Set::new(),
            bad_peers: lockfree::set::Set::new(),
            engine,
            client,
            shard,
            #[cfg(test)]
            exit_gate: std::sync::Mutex::new(None),
            tasks: Arc::new(OwnedTasks::child(owner.clone(), owner.cancellation().child_token())),
        });
        if let Err(error) = fnc.clone().listen_broadcasts(subscription) {
            fnc.stop();
            return Err(error);
        }
        Ok(fnc)
    }

    #[cfg(test)]
    pub(crate) fn pause_test_consumer(&self) -> Arc<super::test_broadcast_faults::ConsumerGate> {
        let gate = super::test_broadcast_faults::ConsumerGate::new();
        *self.test_consumer_gate.lock().unwrap() = Some(gate.clone());
        gate
    }

    pub fn overlay_client(&self) -> &Arc<OverlayClient> {
        &self.client
    }

    pub fn shard(&self) -> &ShardIdent {
        &self.shard
    }

    #[cfg(test)]
    pub(crate) fn hold_listener_exit(&self) -> tokio::sync::oneshot::Sender<()> {
        let (release, gate) = tokio::sync::oneshot::channel();
        *self.exit_gate.lock().unwrap() = Some(gate);
        release
    }

    pub fn stop(&self) {
        self.tasks.stop();
        let _ = self.client.delete();
    }

    pub async fn stop_and_wait(&self) -> Result<()> {
        self.stop();
        let (listener, client) = tokio::join!(self.tasks.wait(), self.client.stop_and_wait());
        if listener.is_err() || client.is_err() {
            fail!("Public overlay shutdown: listener={listener:?}; client={client:?}");
        }
        Ok(())
    }

    fn listen_broadcasts(
        self: Arc<Self>,
        mut subscription: adnl::BroadcastSubscription,
    ) -> Result<()> {
        let tasks = self.tasks.clone();
        tasks.spawn("public overlay broadcast listener", async move {
            log::debug!("Started listening broadcasts for shard {}", self.shard());
            loop {
                if self.engine.check_stop() || self.tasks.cancellation().is_cancelled() {
                    break;
                }
                if !self.overlay_client().is_active() {
                    tokio::select! {
                        _ = self.tasks.cancellation().cancelled() => break,
                        _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
                    }
                    continue;
                }
                if self.overlay_client().is_died() {
                    log::warn!("Overlay client {} is dead", self.shard());
                    return;
                }
                if !check_sync_for_listen_bcasts(self.engine.as_ref()) {
                    log::debug!(
                        "Node is not synced, pause processing broadcasts for shard {}",
                        self.shard()
                    );
                    tokio::select! {
                        _ = self.tasks.cancellation().cancelled() => break,
                        _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {}
                    }
                    continue;
                }
                #[cfg(test)]
                {
                    let gate = self.test_consumer_gate.lock().unwrap().clone();
                    if let Some(gate) = gate {
                        if !gate.hold(&self.client.cancellation_token()).await {
                            break;
                        }
                    }
                }
                let broadcast = tokio::select! {
                    biased;
                    _ = self.tasks.cancellation().cancelled() => break,
                    result = self.overlay_client().wait_broadcast(&mut subscription) => result,
                };
                match broadcast {
                    Err(e) => {
                        log::error!("Error while wait_broadcast for shard {}: {e}", self.shard());
                        // Wait for the graceful loop exit
                        tokio::select! {
                            _ = self.tasks.cancellation().cancelled() => break,
                            _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
                        }
                    }
                    Ok(None) => {
                        log::warn!("wait_broadcast finished.");
                        break;
                    }
                    Ok(Some((broadcast, src, received_bytes))) => {
                        log::trace!(
                            "Received broadcast {:08x} in public overlay {} shard {} from {src}",
                            broadcast.bare_object().constructor(),
                            self.client.id(),
                            self.shard
                        );
                        if let Err(e) =
                            self.process_broadcast(&src, broadcast, received_bytes).await
                        {
                            log::warn!(
                                "Error while processing broadcast from {src} \
                                in public overlay {} for shard {}: {e}",
                                self.client.id(),
                                self.shard()
                            );
                        }
                    }
                }
            }
            #[cfg(test)]
            {
                let gate = self.exit_gate.lock().unwrap().take();
                if let Some(gate) = gate {
                    let _ = gate.await;
                }
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
                self.engine.clone().process_block_finality_broadcast(
                    broadcast, src.clone(), received_bytes,
                ).await?;
            }
            Broadcast::TonNode_BlockBroadcast(broadcast) => {
                self.engine.clone().process_block_broadcast(broadcast, src.clone())
            }
            Broadcast::TonNode_ExternalMessageBroadcast(broadcast) => {
                self.engine.process_ext_msg_broadcast(broadcast, src.clone()).await
            }
            Broadcast::TonNode_IhrMessageBroadcast(broadcast) => {
                log::debug!("Skipped TonNode_IhrMessageBroadcast from {src}: {broadcast:?}")
            }
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
                    self.client.id()
                );
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
                log::debug!(
                    "NewBlockCandidateBroadcastCompressed {} (overlay {}) received from {src}",
                    broadcast.id,
                    self.client.id()
                );
                let data = decompress_and_check_candidate_data(&broadcast)?;
                self.engine.cache_block_candidate(
                    &broadcast.id,
                    broadcast.catchain_seqno as u32,
                    broadcast.validator_set_hash as u32,
                    broadcast.collator_signature.try_into().unwrap_or_default(),
                    data,
                )?;
            }
            Broadcast::TonNode_NewBlockCandidateBroadcastCompressedV2(_broadcast) => log::warn!(
                "NewBlockCandidateBroadcastCompressedV2 from {src} is not supported in public overlay {}",
                self.client.id()
            ),
            Broadcast::TonNode_OutMsgQueueProofBroadcast(_) => log::debug!(
                "OutMsgQueueProofBroadcast from {src} is not supported in public overlay {}",
                self.client.id()
            ),
        }
        Ok(())
    }

    // tonNode.prepareBlockProof block:tonNode.blockIdExt allow_partial:Bool = tonNode.PreparedProof;
    // tonNode.preparedProofEmpty = tonNode.PreparedProof;
    // tonNode.preparedProof = tonNode.PreparedProof;
    // tonNode.preparedProofLink = tonNode.PreparedProof;
    //
    // tonNode.downloadBlockProof block:tonNode.blockIdExt = tonNode.Data;
    // tonNode.downloadBlockProofLink block:tonNode.blockIdExt = tonNode.Data;
    pub async fn download_block_proof(
        &self,
        block_id: &BlockIdExt,
        is_link: bool,
        key_block: bool,
    ) -> Result<BlockProofStuff> {
        // Prepare
        let request = if key_block {
            PrepareKeyBlockProof { block: block_id.clone(), allow_partial: is_link.into() }
                .into_tl_object()
        } else {
            PrepareBlockProof { block: block_id.clone(), allow_partial: is_link.into() }
                .into_tl_object()
        }
        .into();
        let (prepare, good_peer): (PreparedProof, _) =
            self.client.send_adnl_query(&request, None, Some(Self::TIMEOUT_PREPARE), None).await?;
        // Download
        let (request, is_link) = match prepare {
            PreparedProof::TonNode_PreparedProofEmpty => {
                fail!("Got `TonNode_PreparedProofEmpty` from {}", good_peer.id())
            }
            PreparedProof::TonNode_PreparedProof => {
                let request = if key_block {
                    DownloadKeyBlockProof { block: block_id.clone() }.into_tl_object()
                } else {
                    DownloadBlockProof { block: block_id.clone() }.into_tl_object()
                };
                (request, false)
            }
            PreparedProof::TonNode_PreparedProofLink => {
                let request = if key_block {
                    DownloadKeyBlockProofLink { block: block_id.clone() }.into_tl_object()
                } else {
                    DownloadBlockProofLink { block: block_id.clone() }.into_tl_object()
                };
                (request, true)
            }
        };
        let proof = self.client.send_rldp_query_raw(&request.into(), &good_peer, 0, true).await?;
        BlockProofStuff::deserialize(block_id, proof, is_link)
    }

    pub async fn download_block_proof_bounded(
        &self,
        block_id: &BlockIdExt,
        is_link: bool,
        key_block: bool,
        limits: NetworkDownloadLimits,
    ) -> Result<BlockProofStuff> {
        self.download_block_proof_bounded_inner(block_id, is_link, key_block, limits, None).await
    }
    pub(crate) async fn download_block_proof_history(
        &self,
        block_id: &BlockIdExt,
        is_link: bool,
        key_block: bool,
        limits: NetworkDownloadLimits,
        budget: Arc<HistoryReadBudget>,
        graph: NetworkGraphReservation,
    ) -> Result<BlockProofStuff> {
        self.download_block_proof_bounded_inner(
            block_id,
            is_link,
            key_block,
            limits,
            Some(HistoryNetworkDecode { budget, graph: Some(graph) }),
        )
        .await
    }
    async fn download_block_proof_bounded_inner(
        &self,
        block_id: &BlockIdExt,
        is_link: bool,
        key_block: bool,
        limits: NetworkDownloadLimits,
        mut history: Option<HistoryNetworkDecode>,
    ) -> Result<BlockProofStuff> {
        let transport = limits.transport()?;
        // Prepare
        let request = if key_block {
            PrepareKeyBlockProof { block: block_id.clone(), allow_partial: is_link.into() }
                .into_tl_object()
        } else {
            PrepareBlockProof { block: block_id.clone(), allow_partial: is_link.into() }
                .into_tl_object()
        }
        .into();
        let (prepare, good_peer): (PreparedProof, _) =
            self.client.send_adnl_query(&request, None, Some(Self::TIMEOUT_PREPARE), None).await?;
        // Download
        let (request, is_link) = match prepare {
            PreparedProof::TonNode_PreparedProofEmpty => {
                fail!("Got `TonNode_PreparedProofEmpty` from {}", good_peer.id())
            }
            PreparedProof::TonNode_PreparedProof => {
                let request = if key_block {
                    DownloadKeyBlockProof { block: block_id.clone() }.into_tl_object()
                } else {
                    DownloadBlockProof { block: block_id.clone() }.into_tl_object()
                };
                (request, false)
            }
            PreparedProof::TonNode_PreparedProofLink => {
                let request = if key_block {
                    DownloadKeyBlockProofLink { block: block_id.clone() }.into_tl_object()
                } else {
                    DownloadBlockProofLink { block: block_id.clone() }.into_tl_object()
                };
                (request, true)
            }
        };
        let proof = self
            .client
            .send_rldp_query_raw_bounded(&request.into(), &good_peer, 0, true, transport)
            .await?;
        NetworkDownloadLimits::check_bytes(proof.len(), limits.proof_bytes)?;
        if let Some(history) = history.as_mut() {
            let root = history.parse(&[&proof])?.remove(0).withdraw_single_root()?;
            BlockProofStuff::from_parsed_history_root(
                block_id,
                proof,
                is_link,
                root,
                &history.budget,
            )
        } else {
            limits.parse_boc(&proof, limits.proof_bytes)?;
            BlockProofStuff::deserialize(block_id, proof, is_link)
        }
    }

    // tonNode.prepareBlock block:tonNode.blockIdExt = tonNode.Prepared;
    // tonNode.downloadBlockFull block:tonNode.blockIdExt = tonNode.DataFull;
    // tonNode.dataFull id:tonNode.blockIdExt proof:bytes block:bytes is_link:Bool = tonNode.DataFull;
    // tonNode.dataFullEmpty = tonNode.DataFull;
    //
    // tonNode.downloadBlock block:tonNode.blockIdExt = tonNode.Data; DEPRECATED?
    pub async fn download_block_full(
        &self,
        id: &BlockIdExt,
        fan_out_prepare: bool,
    ) -> Result<(BlockStuff, BlockProofStuff)> {
        let (peer, was_active) = if fan_out_prepare {
            // Probe FAN_OUT_PEERS in parallel with PrepareBlock; pick the
            // first peer that says it has the block, then RLDP from it.
            // The fan-out helper deliberately does not insert the winner into
            // active_peers — promotion happens below on full success.
            let request = PrepareBlock { block: id.clone() }.into_tl_object().into();
            let (_prepare, peer): (Prepared, _) = self
                .client
                .send_adnl_query_fan_out(
                    &request,
                    Self::FAN_OUT_PEERS,
                    Some(Self::TIMEOUT_PREPARE),
                    |p: &Prepared| matches!(p, &Prepared::TonNode_Prepared),
                    &self.active_peers,
                )
                .await?;
            (peer, false)
        } else {
            // Skip the prepare round-trip: pick a neighbour and RLDP directly.
            self.client.choose_peer(Some(&self.active_peers)).await?
        };
        log::debug!(
            "download_block_full: sending RLDP to peer {}, id: {}, fan_out={fan_out_prepare}",
            peer.id(),
            id
        );
        let result = self
            .client
            .send_rldp_query_typed(
                &TaggedObject {
                    object: DownloadBlockFull { block: id.clone() },
                    #[cfg(feature = "telemetry")]
                    tag: DownloadBlockFull::constructor_const(),
                },
                &peer,
                0,
                true,
            )
            .await;
        log::debug!(
            "download_block_full: got {}, peer {}, id: {}",
            if result.is_ok() { "OK" } else { "ERR" },
            peer.id(),
            id
        );
        let data_full: DataFull = result.inspect_err(|_| {
            self.active_peers.remove(peer.id());
        })?;
        let id = id.clone();
        let deserialized: Result<(BlockStuff, BlockProofStuff)> =
            tokio::task::block_in_place(|| {
                let (block_data, proof_data, is_link) = match data_full {
                    DataFull::TonNode_DataFull(data_full) => {
                        if id != data_full.id {
                            fail!("Block with another id was received");
                        }
                        (data_full.block, data_full.proof, data_full.is_link.into())
                    }
                    DataFull::TonNode_DataFullCompressed(data_full) => {
                        if id != data_full.id {
                            fail!("Block with another id was received");
                        }
                        let decompressed = lz4_decompress(
                            &data_full.compressed,
                            Lz4DecompressMode::WithMaxSize(MAX_COMPRESSED_SIZE as i32),
                        )?;
                        let mut roots = read_boc(&decompressed)?.roots;
                        if roots.len() != 2 {
                            fail!("DataFullCompressed contains {} roots instead of 2", roots.len());
                        }
                        let proof_data = write_boc(&roots.remove(0))?;
                        // Block's boc here must be serialized absolutely
                        // the same way as in collator, because of file hash concept.
                        let mut block_data = Vec::new();
                        BocWriter::with_flags(roots, BocFlags::all())?.write(&mut block_data)?;
                        (block_data, proof_data, data_full.is_link.into())
                    }
                    DataFull::TonNode_DataFullEmpty => {
                        fail!("DownloadBlockFull returned DataFullEmpty from {}", peer.id())
                    }
                };
                let proof =
                    BlockProofStuff::deserialize(&id, proof_data, is_link).map_err(|e| {
                        error!("Error deserializing block proof from {}: {}", peer.id(), e)
                    })?;
                let block = BlockStuff::deserialize_block_checked(id, Arc::new(block_data))
                    .map_err(|e| error!("Error deserializing block from {}: {}", peer.id(), e))?;
                Ok((block, proof))
            });
        match deserialized {
            Ok(pair) => {
                if !was_active {
                    self.active_peers.insert(peer.id().clone()).ok();
                }
                Ok(pair)
            }
            Err(e) => {
                self.active_peers.remove(peer.id());
                Err(e)
            }
        }
    }

    pub async fn download_block_full_bounded(
        &self,
        id: &BlockIdExt,
        fan_out_prepare: bool,
        limits: NetworkDownloadLimits,
    ) -> Result<(BlockStuff, BlockProofStuff)> {
        self.download_block_full_bounded_inner(id, fan_out_prepare, limits, None).await
    }
    pub(crate) async fn download_block_full_history(
        &self,
        id: &BlockIdExt,
        fan_out_prepare: bool,
        limits: NetworkDownloadLimits,
        budget: Arc<HistoryReadBudget>,
        graph: NetworkGraphReservation,
    ) -> Result<(BlockStuff, BlockProofStuff)> {
        self.download_block_full_bounded_inner(
            id,
            fan_out_prepare,
            limits,
            Some(HistoryNetworkDecode { budget, graph: Some(graph) }),
        )
        .await
    }
    async fn download_block_full_bounded_inner(
        &self,
        id: &BlockIdExt,
        fan_out_prepare: bool,
        limits: NetworkDownloadLimits,
        history: Option<HistoryNetworkDecode>,
    ) -> Result<(BlockStuff, BlockProofStuff)> {
        let transport = limits.transport()?;
        let (peer, was_active) = if fan_out_prepare {
            // Probe FAN_OUT_PEERS in parallel with PrepareBlock; pick the
            // first peer that says it has the block, then RLDP from it.
            // The fan-out helper deliberately does not insert the winner into
            // active_peers — promotion happens below on full success.
            let request = PrepareBlock { block: id.clone() }.into_tl_object().into();
            let (_prepare, peer): (Prepared, _) = self
                .client
                .send_adnl_query_fan_out(
                    &request,
                    Self::FAN_OUT_PEERS,
                    Some(Self::TIMEOUT_PREPARE),
                    |p: &Prepared| matches!(p, &Prepared::TonNode_Prepared),
                    &self.active_peers,
                )
                .await?;
            (peer, false)
        } else {
            // Skip the prepare round-trip: pick a neighbour and RLDP directly.
            self.client.choose_peer(Some(&self.active_peers)).await?
        };
        log::debug!(
            "download_block_full: sending RLDP to peer {}, id: {}, fan_out={fan_out_prepare}",
            peer.id(),
            id
        );
        let result = self
            .client
            .send_rldp_query_raw_bounded(
                &TaggedObject {
                    object: DownloadBlockFull { block: id.clone() },
                    #[cfg(feature = "telemetry")]
                    tag: DownloadBlockFull::constructor_const(),
                },
                &peer,
                0,
                true,
                transport,
            )
            .await;
        log::debug!(
            "download_block_full: got {}, peer {}, id: {}",
            if result.is_ok() { "OK" } else { "ERR" },
            peer.id(),
            id
        );
        let response = result.inspect_err(|_| {
            self.active_peers.remove(peer.id());
        })?;
        let data_full: DataFull = self
            .client
            .network_context()
            .stack
            .overlay
            .wire_profile()
            .deserialize_value_bounded(&response, limits.response_bytes)?;
        let id = id.clone();
        let deserialized =
            tokio::task::block_in_place(|| decode_bounded_pair(&id, data_full, limits, history));
        match deserialized {
            Ok(pair) => {
                if !was_active {
                    self.active_peers.insert(peer.id().clone()).ok();
                }
                Ok(pair)
            }
            Err(e) => {
                self.active_peers.remove(peer.id());
                Err(e)
            }
        }
    }

    pub async fn check_persistent_state(
        &self,
        id: &PersistentStatePartId,
        masterchain_block_id: &BlockIdExt,
    ) -> Result<Option<(Arc<Neighbour>, usize)>> {
        if let PersistentStatePartId::WholeState(id) = &id {
            let request = PreparePersistentState {
                block: id.clone(),
                masterchain_block: masterchain_block_id.clone(),
            }
            .into_tl_object()
            .into();
            let (prepare, peer): (PreparedState, _) = self
                .client
                .send_adnl_query_to_all_peers(
                    &request,
                    Some(Self::TIMEOUT_PREPARE),
                    None,
                    &self.bad_peers,
                    |result| matches!(result, &PreparedState::TonNode_PreparedState),
                )
                .await?;
            match prepare {
                PreparedState::TonNode_NotFoundState => Ok(None),
                PreparedState::TonNode_PreparedState => Ok(Some((peer, 0))),
            }
        } else {
            let request = GetPersistentStateSizeV2 {
                state: PersistentStateIdV2 {
                    block: id.block_id().clone(),
                    masterchain_block: masterchain_block_id.clone(),
                    effective_shard: id.part_prefix() as i64,
                },
            }
            .into_tl_object()
            .into();
            let (size, peer): (PersistentStateSize, _) = self
                .client
                .send_adnl_query_to_all_peers(
                    &request,
                    Some(Self::TIMEOUT_PREPARE),
                    None,
                    &self.bad_peers,
                    |result| matches!(result, &PersistentStateSize::TonNode_PersistentStateSize(_)),
                )
                .await?;
            match size {
                PersistentStateSize::TonNode_PersistentStateSizeNotFound => Ok(None),
                PersistentStateSize::TonNode_PersistentStateSize(size) => {
                    Ok(Some((peer, size.size as usize)))
                }
            }
        }
    }

    /// Single-peer bounded size probe, including WholeState via the V2 query.
    /// Caller charges one attempt and 128 wire / 12 decoded bytes before entry.
    /// Peer-advertised size is only a hint, never state authentication.
    pub async fn check_persistent_state_bounded(
        &self,
        id: &PersistentStatePartId,
        masterchain_block_id: &BlockIdExt,
        max_bytes: usize,
    ) -> Result<Option<(Arc<Neighbour>, usize)>> {
        if max_bytes == 0 {
            fail!("Empty PSS budget");
        }
        let (peer, _) = self.client.choose_peer(None).await?;
        let request = TaggedObject {
            object: GetPersistentStateSizeV2 {
                state: PersistentStateIdV2 {
                    block: id.block_id().clone(),
                    masterchain_block: masterchain_block_id.clone(),
                    effective_shard: id.part_prefix() as i64,
                },
            },
            #[cfg(feature = "telemetry")]
            tag: GetPersistentStateSizeV2::constructor_const(),
        };
        let bytes = self
            .client
            .send_rldp_query_raw_bounded(
                &request,
                &peer,
                0,
                true,
                adnl::QueryResponseLimits { wire_bytes: 128, decoded_bytes: 12 },
            )
            .await?;
        let size: PersistentStateSize = self
            .client
            .network_context()
            .stack
            .overlay
            .wire_profile()
            .deserialize_value_bounded(&bytes, 12)?;
        if self.client.network_context().stack.overlay.wire_profile().serialize(&size)? != bytes {
            fail!("Noncanonical PSS size response");
        }
        match size {
            PersistentStateSize::TonNode_PersistentStateSizeNotFound => Ok(None),
            PersistentStateSize::TonNode_PersistentStateSize(size) => {
                let size = usize::try_from(size.size)?;
                if size == 0 {
                    fail!("Empty advertised PSS");
                }
                if size > max_bytes {
                    return Err(
                        adnl::ResponseLimitExceeded { limit: max_bytes, actual: size }.into()
                    );
                }
                Ok(Some((peer, size)))
            }
        }
    }

    /// One bounded PSS slice attempt. The owned caller reserves cumulative
    /// wire/decoded bytes, part count and attempts before calling this method.
    /// No retry, state publication or BOC parsing occurs here. A short/empty
    /// response is returned verbatim for the caller to validate against EOF.
    #[allow(clippy::too_many_arguments)]
    pub async fn download_persistent_state_part_bounded(
        &self,
        block_id: &PersistentStatePartId,
        masterchain_block_id: &BlockIdExt,
        offset: usize,
        max_size: usize,
        peer: &Arc<Neighbour>,
        attempt: u32,
        limits: adnl::QueryResponseLimits,
    ) -> Result<Vec<u8>> {
        let (offset, max_size) = checked_pss_slice(offset, max_size, limits)?;
        let request = TaggedObject {
            object: DownloadPersistentStateSliceV2 {
                state: PersistentStateIdV2 {
                    block: block_id.block_id().clone(),
                    masterchain_block: masterchain_block_id.clone(),
                    // The protocol encodes a shard-prefix bit pattern in `long`.
                    effective_shard: block_id.part_prefix() as i64,
                },
                offset,
                max_size,
            },
            #[cfg(feature = "telemetry")]
            tag: DownloadPersistentStateSliceV2::constructor_const(),
        };
        self.client.send_rldp_query_raw_bounded(&request, peer, attempt, true, limits).await
    }

    pub async fn download_persistent_state_part(
        &self,
        block_id: &PersistentStatePartId,
        masterchain_block_id: &BlockIdExt,
        offset: usize,
        max_size: usize,
        peer: &Arc<Neighbour>,
        attempt: u32,
    ) -> Result<Vec<u8>> {
        let request = TaggedObject {
            object: DownloadPersistentStateSliceV2 {
                state: PersistentStateIdV2 {
                    block: block_id.block_id().clone(),
                    masterchain_block: masterchain_block_id.clone(),
                    effective_shard: block_id.part_prefix() as i64,
                },
                offset: offset as i64,
                max_size: max_size as i64,
            },
            #[cfg(feature = "telemetry")]
            tag: DownloadPersistentStateSliceV2::constructor_const(),
        };
        self.client.send_rldp_query_raw(&request, peer, attempt, true).await
    }

    // tonNode.prepareZeroState block:tonNode.blockIdExt = tonNode.PreparedState;
    // tonNode.downloadZeroState block:tonNode.blockIdExt = tonNode.Data;
    pub async fn download_zero_state(
        &self,
        id: &BlockIdExt,
    ) -> Result<(Arc<ShardStateStuff>, Vec<u8>)> {
        // Prepare
        let (prepare, good_peer): (PreparedState, _) = self
            .client
            .send_adnl_query(
                &PrepareZeroState { block: id.clone() }.into_tl_object().into(),
                None,
                Some(Self::TIMEOUT_PREPARE),
                None,
            )
            .await?;
        // Download
        match prepare {
            PreparedState::TonNode_NotFoundState => {
                fail!("Got `TonNode_NotFoundState` from {}", good_peer.id())
            }
            PreparedState::TonNode_PreparedState => {
                let state_bytes = self
                    .client
                    .send_rldp_query_raw(
                        &TaggedObject {
                            object: DownloadZeroState { block: id.clone() },
                            #[cfg(feature = "telemetry")]
                            tag: DownloadZeroState::constructor_const(),
                        },
                        &good_peer,
                        0,
                        true,
                    )
                    .await?;
                let state = ShardStateStuff::deserialize_zerostate(
                    id.clone(),
                    state_bytes.as_slice(),
                    #[cfg(feature = "telemetry")]
                    &self.client.network_context().engine_telemetry,
                    &self.client.network_context().engine_allocated,
                )?;
                Ok((state, state_bytes))
            }
        }
    }

    // tonNode.keyBlocks blocks:(vector tonNode.blockIdExt) incomplete:Bool error:Bool
    //     = tonNode.KeyBlocks;
    // tonNode.getNextKeyBlockIds block:tonNode.blockIdExt max_size:int
    //     = tonNode.KeyBlocks;
    pub async fn download_next_key_blocks_ids(
        &self,
        block_id: &BlockIdExt,
        max_size: i32,
    ) -> Result<Vec<BlockIdExt>> {
        let request =
            GetNextKeyBlockIds { block: block_id.clone(), max_size }.into_tl_object().into();
        let (ids, _): (KeyBlocks, _) =
            self.client.send_adnl_query(&request, None, None, None).await?;
        if !ids.blocks().is_empty() {
            return Ok(ids.only().blocks);
        }
        return Ok(Vec::new());
    }

    // tonNode.downloadNextBlockFull prev_block:tonNode.blockIdExt = tonNode.DataFull;
    pub async fn download_next_block_full(
        &self,
        prev_id: &BlockIdExt,
        fan_out_prepare: bool,
    ) -> Result<(BlockStuff, BlockProofStuff)> {
        let (peer, was_active) = if fan_out_prepare {
            // Fan-out a cheap GetNextBlockDescription probe to find a peer that
            // already knows the next block, then RLDP-download from that peer.
            // The fan-out helper does not promote the winner — that happens
            // below on full success.
            let probe =
                GetNextBlockDescription { prev_block: prev_id.clone() }.into_tl_object().into();
            let (_description, peer): (BlockDescription, _) = self
                .client
                .send_adnl_query_fan_out(
                    &probe,
                    Self::FAN_OUT_PEERS,
                    Some(Self::TIMEOUT_PREPARE),
                    |d: &BlockDescription| {
                        matches!(d, BlockDescription::TonNode_BlockDescription(_))
                    },
                    &self.active_peers,
                )
                .await?;
            (peer, false)
        } else {
            self.client.choose_peer(Some(&self.active_peers)).await?
        };
        log::debug!(
            "download_next_block_full: sending RLDP to peer {}, prev: {}",
            peer.id(),
            prev_id
        );
        let request = TaggedObject {
            object: DownloadNextBlockFull { prev_block: prev_id.clone() },
            #[cfg(feature = "telemetry")]
            tag: DownloadNextBlockFull::constructor_const(),
        };
        let result = self.client.send_rldp_query_typed(&request, &peer, 0, true).await;
        log::debug!(
            "download_next_block_full: got {}, peer {}, prev: {}",
            if result.is_ok() { "OK" } else { "ERR" },
            peer.id(),
            prev_id
        );
        let data_full: DataFull = result.inspect_err(|_| {
            self.active_peers.remove(peer.id());
        })?;
        // DataFullEmpty is normally a "not yet" signal — the next block may
        // simply not exist yet, so the peer is not logically bad. But when
        // fan_out_prepare is set, the caller believes the block should already
        // be on the network (we've been lagging), so a peer returning Empty is
        // logically stale and we evict it from active_peers.
        if matches!(data_full, DataFull::TonNode_DataFullEmpty) {
            if fan_out_prepare {
                self.active_peers.remove(peer.id());
            }
            return Err(error!("Got DataFullEmpty from {}", peer.id()));
        }
        let deserialized: Result<(BlockStuff, BlockProofStuff)> =
            tokio::task::block_in_place(|| {
                let (block_data, proof_data, id, is_link) = match data_full {
                    DataFull::TonNode_DataFull(data_full) => {
                        (data_full.block, data_full.proof, data_full.id, data_full.is_link.into())
                    }
                    DataFull::TonNode_DataFullCompressed(data_full) => {
                        let decompressed = lz4_decompress(
                            &data_full.compressed,
                            Lz4DecompressMode::WithMaxSize(MAX_COMPRESSED_SIZE as i32),
                        )?;
                        let mut roots = read_boc(&decompressed)?.roots;
                        if roots.len() != 2 {
                            fail!("DataFullCompressed contains {} roots instead of 2", roots.len());
                        }
                        let proof_data = write_boc(&roots.remove(0))?;
                        // Block's boc here must be serialized absolutely
                        // the same way as in collator, because of file hash concept.
                        let mut block_data = Vec::new();
                        BocWriter::with_flags(roots, BocFlags::all())?.write(&mut block_data)?;
                        (block_data, proof_data, data_full.id, data_full.is_link.into())
                    }
                    DataFull::TonNode_DataFullEmpty => unreachable!(),
                };
                let proof =
                    BlockProofStuff::deserialize(&id, proof_data, is_link).map_err(|e| {
                        error!("Failed to deserialize block proof from peer {}: {:?}", peer.id(), e)
                    })?;
                let block = BlockStuff::deserialize_block_checked(id, Arc::new(block_data))
                    .map_err(|e| {
                        error!("Failed to deserialize block from peer {}: {:?}", peer.id(), e)
                    })?;
                Ok((block, proof))
            });
        match deserialized {
            Ok(pair) => {
                if !was_active {
                    self.active_peers.insert(peer.id().clone()).ok();
                }
                Ok(pair)
            }
            Err(e) => {
                self.active_peers.remove(peer.id());
                Err(e)
            }
        }
    }

    pub async fn download_archive(
        &self,
        mc_seq_no: u32,
        shard: &ShardIdent,
    ) -> Result<Option<Vec<u8>>> {
        const CHUNK_SIZE: i32 = 1 << 21;
        const MAX_ATTEMPTS: usize = 10;
        // tonNode.getArchiveInfo masterchain_seqno:int
        //     = tonNode.ArchiveInfo;
        // OR
        // tonNode.getShardArchiveInfo masterchain_seqno:int shard_prefix:tonNode.shardId
        //     = tonNode.ArchiveInfo;
        if !self.shard.intersect_with(shard) {
            fail!("Cannot download archive for shard {} in overlay {}", shard, self.shard);
        }
        let object = if self.shard.is_masterchain() {
            GetArchiveInfo { masterchain_seqno: mc_seq_no as i32 }.into_tl_object()
        } else {
            GetShardArchiveInfo {
                masterchain_seqno: mc_seq_no as i32,
                shard_prefix: ShardId {
                    workchain: shard.workchain_id(),
                    shard: shard.shard_prefix_with_tag() as i64,
                },
            }
            .into_tl_object()
        }
        .into();
        let (archive_info, peer) = self
            .client
            .send_adnl_query(&object, None, Some(Self::TIMEOUT_PREPARE), Some(&self.active_peers))
            .await?;
        let info = match archive_info {
            ArchiveInfo::TonNode_ArchiveNotFound => {
                self.active_peers.remove(peer.id());
                return Ok(None);
            }
            ArchiveInfo::TonNode_ArchiveInfo(info) => info,
        };
        let mut result = Vec::new();
        let mut slice = TaggedObject {
            object: GetArchiveSlice { archive_id: info.id, offset: 0, max_size: CHUNK_SIZE },
            #[cfg(feature = "telemetry")]
            tag: GetArchiveSlice::constructor_const(),
        };
        let mut part_attempt = 0;
        let mut peer_attempt = 0;
        loop {
            if self.engine.check_stop() {
                log::info!("Engine is stopping, quit download archive");
                break Ok(None);
            }
            match self.client.send_rldp_query_raw(&slice, &peer, peer_attempt, true).await {
                Ok(mut block_bytes) => {
                    let actual_size = block_bytes.len() as i32;
                    result.append(&mut block_bytes);
                    if actual_size < CHUNK_SIZE {
                        self.active_peers.remove(peer.id());
                        break Ok(Some(result));
                    }
                    slice.object.offset += actual_size as i64;
                    part_attempt = 0;
                }
                Err(e) => {
                    peer_attempt += 1;
                    part_attempt += 1;
                    log::error!(
                        "download_archive {}: {e}, offset: {}, attempt: {part_attempt}",
                        info.id,
                        slice.object.offset
                    );
                    if part_attempt > MAX_ATTEMPTS {
                        self.active_peers.remove(peer.id());
                        fail!("Error download_archive after {part_attempt} attempts : {e}")
                    }
                }
            }
        }
    }

    /// Send as `source` (the node key when `None`) with exactly `flags`.
    pub async fn send_broadcast(
        &self,
        data: &TaggedByteSlice<'_>,
        source: Option<&Arc<dyn KeyOption>>,
        flags: u32,
        method: AdnlSendMethod,
    ) -> Result<()> {
        match self.client.broadcast(data, source, flags, method).await {
            Ok(info) => {
                #[cfg(feature = "telemetry")]
                log::debug!(
                    "sent broadcast {:08x} in {} to {} nodes",
                    data.tag,
                    self.client.id(),
                    info.send_to
                );
                #[cfg(not(feature = "telemetry"))]
                log::debug!("sent broadcast in {} to {} nodes", self.client.id(), info.send_to);

                Ok(())
            }
            Err(e) => {
                log::warn!("Error sending broadcast: {}", e);
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod bounded_download_tests {
    use super::*;
    mod pq_fixture {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tl/rtos_api/tests/common/pq_finality.rs"
        ));
    }
    // Real typed block and PQ carrier; this tests transport decoding, not authority.
    fn history_pair_fixture() -> (BlockIdExt, Vec<u8>, Vec<u8>) {
        use rtos_block::Serializable;
        let root = pq_fixture::target_block().serialize().unwrap();
        let mut body = Vec::new();
        BocWriter::with_flags([root.clone()], BocFlags::all()).unwrap().write(&mut body).unwrap();
        let id = BlockIdExt::with_params(
            ShardIdent::masterchain(),
            42,
            root.repr_hash().clone(),
            rtos_block::UInt256::calc_file_hash(&body),
        );
        let carrier = pq_fixture::signed(&[0, 1], "finalize", "TOS-CONSENSUS-SIMPLEX-v1");
        let proof = rtos_block::BlockProof::with_params(
            id.clone(),
            rtos_block::Cell::default(),
            Some(rtos_block::BlockSignaturesVariant::SimplexPq(carrier)),
        );
        (id, body, write_boc(&proof.serialize().unwrap()).unwrap())
    }
    fn history_pair_response(
        id: &BlockIdExt,
        body: &[u8],
        proof: &[u8],
        compressed: bool,
    ) -> DataFull {
        use rtos_api::IntoBoxed;
        if compressed {
            let roots = [
                rtos_block::read_single_root_boc(proof).unwrap(),
                rtos_block::read_single_root_boc(body).unwrap(),
            ];
            let mut bytes = Vec::new();
            BocWriter::with_roots(roots).unwrap().write(&mut bytes).unwrap();
            rtos_api::ton::ton_node::datafull::DataFullCompressed {
                id: id.clone(),
                compressed: rtos_block::lz4_compress(&bytes, false).unwrap(),
                is_link: false.into(),
            }
            .into_boxed()
        } else {
            rtos_api::ton::ton_node::datafull::DataFull {
                id: id.clone(),
                block: body.to_vec(),
                proof: proof.to_vec(),
                is_link: false.into(),
            }
            .into_boxed()
        }
    }
    #[test]
    fn bounded_history_network_pair_preserves_flags_and_shared_budget() {
        let (id, body, proof) = history_pair_fixture();
        let limits = NetworkDownloadLimits {
            wire_bytes: 1 << 20,
            response_bytes: 1 << 20,
            expanded_bytes: 1 << 20,
            block_bytes: 1 << 20,
            proof_bytes: 1 << 20,
            boc_cells: 10000,
            boc_depth: 1024,
        };
        for compressed in [false, true] {
            let budget = HistoryReadBudget::new(Default::default());
            let graph = budget.reserve_network_graph().unwrap();
            let (block, parsed) = decode_bounded_pair(
                &id,
                history_pair_response(&id, &body, &proof, compressed),
                limits,
                Some(HistoryNetworkDecode { budget: budget.clone(), graph: Some(graph) }),
            )
            .unwrap();
            assert_eq!(block.data(), body);
            assert_eq!(parsed.data(), proof);
            let budget = HistoryReadBudget::new(crate::history_read_budget::HistoryReadLimits {
                steps: 0,
                ..Default::default()
            });
            let graph = budget.reserve_network_graph().unwrap();
            let error = decode_bounded_pair(
                &id,
                history_pair_response(&id, &body, &proof, compressed),
                limits,
                Some(HistoryNetworkDecode { budget: budget.clone(), graph: Some(graph) }),
            )
            .err()
            .expect("shared work budget denies parse");
            assert!(crate::history_read_budget::stops_fallback(&error));
            assert!(budget.step().is_err());
        }
    }
    #[test]
    fn bounded_history_network_pair_rejects_wrong_header_identity() {
        let (mut id, body, proof) = history_pair_fixture();
        id.seq_no += 1;
        // Both wire and proof claim this id; the actual block header still says 42.
        use rtos_block::{Deserializable, Serializable};
        let mut parsed = rtos_block::BlockProof::construct_from_bytes(&proof).unwrap();
        parsed.proof_for = id.clone();
        let proof = parsed.write_to_bytes().unwrap();
        let limits = NetworkDownloadLimits {
            wire_bytes: 1 << 20,
            response_bytes: 1 << 20,
            expanded_bytes: 1 << 20,
            block_bytes: 1 << 20,
            proof_bytes: 1 << 20,
            boc_cells: 10000,
            boc_depth: 1024,
        };
        let budget = HistoryReadBudget::new(Default::default());
        let graph = budget.reserve_network_graph().unwrap();
        assert!(decode_bounded_pair(
            &id,
            history_pair_response(&id, &body, &proof, false),
            limits,
            Some(HistoryNetworkDecode { budget, graph: Some(graph) })
        )
        .is_err());
    }
    #[test]
    fn bounded_download_boc_and_serialization_limits() {
        let mut builder = rtos_block::BuilderData::new();
        builder.checked_append_reference(rtos_block::Cell::default()).unwrap();
        let cell = builder.into_cell().unwrap();
        let encoded = write_boc(&cell).unwrap();
        let limits = NetworkDownloadLimits::proof(encoded.len(), 1, 16);
        assert!(limits
            .parse_boc(&encoded, encoded.len())
            .err()
            .expect("cell budget must reject")
            .downcast_ref::<adnl::ResponseLimitExceeded>()
            .is_some());
        let limits = NetworkDownloadLimits::proof(encoded.len(), 2, 16);
        assert_eq!(limits.parse_boc(&encoded, encoded.len()).unwrap().roots[0], cell);
        let mut output = LimitedBocOutput { bytes: Vec::new(), limit: encoded.len() - 1 };
        assert!(BocWriter::with_root(&cell).unwrap().write(&mut output).is_err());
        assert!(output.bytes.len() < encoded.len());
    }
    #[test]
    fn bounded_history_lz4_admits_scan_and_decode_before_work() {
        use crate::history_read_budget::{stops_fallback, HistoryReadLimits};
        let denied = HistoryReadBudget::new(HistoryReadLimits { steps: 0, ..Default::default() });
        let error = decompress_pair_payload(&[0xf0], 4096, Some(&denied)).unwrap_err();
        assert!(stops_fallback(&error), "zero budget rejects before malformed-token inspection");
        assert!(!stops_fallback(&decompress_pair_payload(&[0xf0], 4096, None).unwrap_err()));
        let plain = vec![7; 4096];
        let compressed = rtos_block::lz4_compress(&plain, false).unwrap();
        let one_decode = 2 * compressed.len().div_ceil(64).max(1) + plain.len().div_ceil(64);
        let budget = HistoryReadBudget::new(HistoryReadLimits {
            steps: 2 * one_decode,
            ..Default::default()
        });
        assert_eq!(decompress_pair_payload(&compressed, 4096, Some(&budget)).unwrap(), plain);
        assert_eq!(decompress_pair_payload(&compressed, 4096, Some(&budget)).unwrap(), plain);
        assert!(stops_fallback(
            &decompress_pair_payload(&compressed, 4096, Some(&budget)).unwrap_err()
        ));
        let short = HistoryReadBudget::new(HistoryReadLimits {
            steps: one_decode - 1,
            ..Default::default()
        });
        assert!(stops_fallback(
            &decompress_pair_payload(&compressed, 4096, Some(&short)).unwrap_err()
        ));
        let budget = HistoryReadBudget::new(Default::default());
        assert!(decompress_pair_payload(&compressed, 1024, Some(&budget))
            .unwrap_err()
            .downcast_ref::<adnl::ResponseLimitExceeded>()
            .is_some());
    }
    #[test]
    fn bounded_download_lz4_preflight_rejects_before_expansion() {
        let compressed = rtos_block::lz4_compress(&vec![7; 4096], false).unwrap();
        check_lz4_expansion(&compressed, 4096).unwrap();
        assert!(check_lz4_expansion(&compressed, 1024)
            .unwrap_err()
            .downcast_ref::<adnl::ResponseLimitExceeded>()
            .is_some());
        assert!(check_lz4_expansion(&[0xf0, 255], 4096).is_err());
    }
}
