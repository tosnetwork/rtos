/*
 * RTOS project modifications (2026-10-10): project and crate naming; explicit target wire profile integration.
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
    engine_traits::EngineOperations,
    network::neighbours::{PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR},
};
use adnl::common::{
    AdnlPeers, Answer, QueryAnswer, QueryResult, Subscriber, TaggedByteVec, TaggedTlObject,
};
#[cfg(feature = "telemetry")]
use rtos_api::BoxedSerialize;
use rtos_api::{
    serialize_boxed,
    ton::{
        self,
        rpc::ton_node::{
            DownloadBlock, DownloadBlockFull, DownloadBlockProof, DownloadBlockProofLink,
            DownloadKeyBlockProof, DownloadKeyBlockProofLink, DownloadNextBlockFull,
            DownloadNextBlocksFull, DownloadPersistentStateSliceV2, DownloadZeroState,
            GetArchiveInfo, GetArchiveSlice, GetCapabilities, GetNextBlockDescription,
            GetNextKeyBlockIds, GetPersistentStateSizeV2, GetShardArchiveInfo, PrepareBlock,
            PrepareBlockProof, PrepareKeyBlockProof, PreparePersistentState, PrepareZeroState,
        },
        ton_node::{
            self,
            archiveinfo::ArchiveInfo,
            capabilities::Capabilities,
            datafull::{DataFull, DataFullCompressed},
            nextblocksfull::NextBlocksFull,
            persistentstateidv2::PersistentStateIdV2,
            ArchiveInfo as ArchiveInfoBoxed, BlockDescription, DataFull as DataFullBoxed,
            KeyBlocks, Prepared, PreparedProof, PreparedState,
        },
    },
    AnyBoxedSerialize, IntoBoxed, TLObject,
};
use rtos_block::{
    error, fail, lz4_compress, read_single_root_boc, BlockIdExt, BocFlags, BocWriter, Result,
    ShardIdent,
};
use std::{cmp::min, fmt::Debug, sync::Arc};
use storage::{block_handle_db::BlockHandle, types::PersistentStatePartId};

// max part size for partially transmitted data like archives and states
const PART_MAX_SIZE: usize = 1 << 21;

use crate::types::owned_tasks::OwnedTasks;

pub struct FullNodeOverlayService {
    engine: Arc<dyn EngineOperations>,
    compression: bool,
    tasks: Arc<OwnedTasks>,
    #[cfg(test)]
    block_download_queries: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    bounded_reply: std::sync::Mutex<Option<(Arc<rtos_block::KeyId>, BlockIdExt, bool, Vec<u8>)>>,
    #[cfg(test)]
    bounded_queries: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    pss_reply: std::sync::Mutex<Option<(Arc<rtos_block::KeyId>, PersistentStateIdV2, Option<i64>, Vec<u8>)>>,
    #[cfg(test)]
    pss_observations: std::sync::Mutex<Vec<(BlockIdExt, Option<i64>, Option<usize>)>>,
}

impl FullNodeOverlayService {
    pub(crate) fn new(
        engine: Arc<dyn EngineOperations>,
        compression: bool,
        tasks: Arc<OwnedTasks>,
    ) -> Self {
        Self {
            engine,
            compression,
            tasks,
            #[cfg(test)]
            block_download_queries: Default::default(),
            #[cfg(test)]
            bounded_reply: Default::default(),
            #[cfg(test)]
            bounded_queries: Default::default(),
            #[cfg(test)]
            pss_reply: Default::default(),
            #[cfg(test)]
            pss_observations: Default::default(),
        }
    }

    #[cfg(test)]
    pub(crate) fn test_block_download_queries(&self) -> usize {
        self.block_download_queries.load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn test_bounded_reply(
        &self,
        peer: Arc<rtos_block::KeyId>,
        id: BlockIdExt,
        full: bool,
        bytes: Vec<u8>,
    ) {
        let mut reply = self.bounded_reply.lock().unwrap();
        assert!(reply.is_none(), "unused previous scoped reply");
        *reply = Some((peer, id, full, bytes));
    }
    #[cfg(test)]
    pub(crate) fn test_bounded_queries(&self) -> usize {
        self.bounded_queries.load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn test_clear_history_replies(&self) {
        self.pss_reply.lock().unwrap().take();
        self.bounded_reply.lock().unwrap().take();
    }

    #[cfg(test)]
    pub(crate) fn test_pss_observations(&self) -> Vec<(BlockIdExt, Option<i64>, Option<usize>)> {
        self.pss_observations.lock().unwrap().clone()
    }

    #[cfg(test)]
    pub(crate) fn test_pss_reply(&self, peer: Arc<rtos_block::KeyId>, state: PersistentStateIdV2, offset: Option<i64>, bytes: Vec<u8>) {
        let mut reply = self.pss_reply.lock().unwrap();
        assert!(reply.is_none(), "unused scoped PSS reply");
        *reply = Some((peer, state, offset, bytes));
    }

    // tonNode.getNextBlockDescription prev_block:tonNode.blockIdExt = tonNode.BlockDescription;
    async fn get_next_block_description(&self, query: GetNextBlockDescription) -> Result<TLObject> {
        let answer = match self.engine.load_block_next1(&query.prev_block) {
            Ok(id) => ton_node::blockdescription::BlockDescription { id }.into_boxed(),
            Err(_) => BlockDescription::TonNode_BlockDescriptionEmpty,
        };
        Ok(answer.into_tl_object())
    }

    // tonNode.getNextBlocksDescription prev_block:tonNode.blockIdExt limit:int
    //     = tonNode.BlocksDescription;
    // Not supported in t-node

    // tonNode.getPrevBlocksDescription next_block:tonNode.blockIdExt limit:int cutoff_seqno:int
    //     = tonNode.BlocksDescription;
    // Not supported in t-node

    fn prepare_block_proof_internal(
        &self,
        block_id: BlockIdExt,
        allow_partial: bool,
        key_block: bool,
    ) -> Result<TLObject> {
        let answer = if let Some(handle) = self.engine.load_block_handle(&block_id)? {
            if key_block && !handle.is_key_block()? {
                fail!("prepare_key_block_proof: given block is not key");
            }
            if !handle.has_proof() && (!allow_partial || !handle.has_proof_link()) {
                PreparedProof::TonNode_PreparedProofEmpty
            } else if handle.has_proof() && handle.id().shard().is_masterchain() {
                PreparedProof::TonNode_PreparedProof
            } else {
                PreparedProof::TonNode_PreparedProofLink
            }
        } else {
            PreparedProof::TonNode_PreparedProofEmpty
        };
        Ok(answer.into_tl_object())
    }

    // tonNode.prepareBlockProof block:tonNode.blockIdExt allow_partial:Bool
    //     = tonNode.PreparedProof;
    async fn prepare_block_proof(&self, query: PrepareBlockProof) -> Result<TLObject> {
        self.prepare_block_proof_internal(query.block, query.allow_partial.into(), false)
    }

    // tonNode.prepareKeyBlockProof block:tonNode.blockIdExt allow_partial:Bool
    //     = tonNode.PreparedProof;
    async fn prepare_key_block_proof(&self, query: PrepareKeyBlockProof) -> Result<TLObject> {
        self.prepare_block_proof_internal(query.block, query.allow_partial.into(), true)
    }

    // tonNode.prepareBlockProofs blocks:(vector tonNode.blockIdExt) allow_partial:Bool
    //     = tonNode.PreparedProof;
    // Not supported in t-node

    // tonNode.prepareKeyBlockProofs blocks:(vector tonNode.blockIdExt) allow_partial:Bool
    //     = tonNode.PreparedProof;
    // Not supported in t-node

    // tonNode.prepareBlock block:tonNode.blockIdExt = tonNode.Prepared;
    async fn prepare_block(&self, query: PrepareBlock) -> Result<TLObject> {
        let answer = if self
            .engine
            .load_block_handle(&query.block)?
            .map(|h| h.has_data())
            .unwrap_or(false)
        {
            Prepared::TonNode_Prepared
        } else {
            Prepared::TonNode_NotFound
        };
        Ok(answer.into_tl_object())
    }

    // tonNode.prepareBlocks blocks:(vector tonNode.blockIdExt) = tonNode.Prepared;
    // Not supported in t-node

    fn prepare_state_internal(&self, block_id: &BlockIdExt) -> Result<TLObject> {
        let answer = if self
            .engine
            .load_block_handle(block_id)?
            .map(|h| h.has_persistent_state())
            .unwrap_or(false)
        {
            PreparedState::TonNode_PreparedState
        } else {
            PreparedState::TonNode_NotFoundState
        };
        Ok(answer.into_tl_object())
    }

    // tonNode.preparePersistentState block:tonNode.blockIdExt masterchain_block:tonNode.blockIdExt
    //     = tonNode.PreparedState;
    async fn prepare_persistent_state(&self, query: PreparePersistentState) -> Result<TLObject> {
        self.prepare_state_internal(&query.block)
    }

    // tonNode.prepareZeroState block:tonNode.blockIdExt = tonNode.PreparedState;
    async fn prepare_zero_state(&self, query: PrepareZeroState) -> Result<TLObject> {
        self.prepare_state_internal(&query.block)
    }

    const NEXT_KEY_BLOCKS_LIMIT: usize = 8;
    const NEXT_BLOCKS_MAX_BLOCKS: u32 = 10;
    const NEXT_BLOCKS_MAX_TOTAL_SIZE: usize = 1 << 20;

    fn build_next_key_blocks_answer(
        blocks: Vec<BlockIdExt>,
        incomplete: bool,
        error: bool,
    ) -> KeyBlocks {
        ton_node::keyblocks::KeyBlocks {
            blocks,
            incomplete: incomplete.into(),
            error: error.into(),
        }
        .into_boxed()
    }

    async fn get_next_key_block_ids_(
        &self,
        start_block_id: &BlockIdExt,
        limit: usize,
    ) -> Result<KeyBlocks> {
        if !start_block_id.shard().is_masterchain() {
            fail!("Given block {} doesn't belong master chain", start_block_id);
        }

        let last_mc_state = match self.engine.load_last_applied_mc_block_id()? {
            Some(block_id) if start_block_id.seq_no() < block_id.seq_no() => {
                self.engine.load_state(&block_id).await?
            }
            _ => {
                return Ok(ton_node::keyblocks::KeyBlocks {
                    blocks: Vec::new(),
                    incomplete: false.into(),
                    error: true.into(),
                }
                .into_boxed())
            }
        };
        let prev_blocks = &last_mc_state.shard_state_extra()?.prev_blocks;

        if start_block_id.seq_no != 0 {
            // check if start block is key-block
            prev_blocks.check_key_block(start_block_id, Some(true))?;
        }

        let mut ids = vec![];
        let mut seq_no = start_block_id.seq_no();
        while let Some(id) = prev_blocks.get_next_key_block(seq_no + 1)? {
            seq_no = id.seq_no;
            let ext_id = id.master_block_id().1;
            ids.push(ext_id);
            if ids.len() == limit {
                break;
            }
        }
        let incomplete = ids.len() < limit;
        Ok(Self::build_next_key_blocks_answer(ids, incomplete, false))
    }

    // tonNode.getNextKeyBlockIds block:tonNode.blockIdExt max_size:int = tonNode.KeyBlocks;
    async fn get_next_key_block_ids(&self, query: GetNextKeyBlockIds) -> Result<TLObject> {
        let limit = min(Self::NEXT_KEY_BLOCKS_LIMIT, query.max_size as usize);
        let answer = match self.get_next_key_block_ids_(&query.block, limit).await {
            Err(e) => {
                log::warn!("tonNode.getNextKeyBlockIds: {:?}", e);
                Self::build_next_key_blocks_answer(vec![], false, true)
            }
            Ok(r) => r,
        };
        Ok(answer.into_tl_object())
    }

    /// One block with its proof as a full-block answer: the full proof when
    /// the block has one, otherwise its proof link; `None` when the block's
    /// data or both proofs are missing.
    async fn block_full_entry(
        &self,
        handle: &Arc<BlockHandle>,
        compressed: bool,
    ) -> Result<Option<DataFullBoxed>> {
        let has_proof = handle.has_proof();
        if !handle.has_data() || !(has_proof || handle.has_proof_link()) {
            return Ok(None);
        }
        let is_link = !has_proof;
        let block = self.engine.load_block_raw(handle).await?;
        let proof = self.engine.load_block_proof_raw(handle, is_link).await?;
        Ok(Some(Self::serialize_block_full(
            handle.id().clone(),
            proof,
            block,
            is_link,
            compressed,
        )?))
    }

    /// tonNode.dataFull, or with compression tonNode.dataFullCompressed: the
    /// proof and block roots in one BOC with a CRC32C, LZ4-compressed.
    fn serialize_block_full(
        id: BlockIdExt,
        proof: Vec<u8>,
        block: Vec<u8>,
        is_link: bool,
        compressed: bool,
    ) -> Result<DataFullBoxed> {
        let is_link = if is_link { ton::Bool::BoolTrue } else { ton::Bool::BoolFalse };
        if !compressed {
            return Ok(DataFull { id, proof, block, is_link }.into_boxed());
        }
        let proof_root = read_single_root_boc(&proof)?;
        let block_root = read_single_root_boc(&block)?;
        let mut data = vec![];
        BocWriter::with_flags([proof_root, block_root], BocFlags::Crc32)?.write(&mut data)?;
        let compressed = lz4_compress(&data, false)?;
        Ok(DataFullCompressed { id, compressed, is_link }.into_boxed())
    }

    // tonNode.downloadNextBlockFull prev_block:tonNode.blockIdExt = tonNode.DataFull;
    async fn download_next_block_full(&self, query: DownloadNextBlockFull) -> Result<TLObject> {
        let mut answer = DataFullBoxed::TonNode_DataFullEmpty;
        if let Some(prev_handle) = self.engine.load_block_handle(&query.prev_block)? {
            if prev_handle.has_next1() {
                let next_id = self.engine.load_block_next1(&query.prev_block)?;
                if let Some(next_handle) = self.engine.load_block_handle(&next_id)? {
                    if let Some(entry) =
                        self.block_full_entry(&next_handle, self.compression).await?
                    {
                        answer = entry;
                    }
                }
            }
        }
        Ok(answer.into_tl_object())
    }

    // tonNode.downloadNextBlocksFull prev_block:tonNode.blockIdExt max_blocks:int
    //     = tonNode.NextBlocksFull;
    // Always answered with the blocks collected so far, also when a later
    // block cannot be read.
    async fn download_next_blocks_full(&self, query: DownloadNextBlocksFull) -> Result<TLObject> {
        let mut blocks = Vec::new();
        if let Err(e) = self.collect_next_blocks_full(&query, &mut blocks).await {
            log::debug!(
                "downloadNextBlocksFull after {}: {e} (sending {} blocks)",
                query.prev_block,
                blocks.len()
            );
        }
        Ok(NextBlocksFull { blocks }.into_boxed().into_tl_object())
    }

    async fn collect_next_blocks_full(
        &self,
        query: &DownloadNextBlocksFull,
        blocks: &mut Vec<DataFullBoxed>,
    ) -> Result<()> {
        // The requested count is read as unsigned, so a negative one asks for
        // the most.
        let max_blocks = min(query.max_blocks as u32, Self::NEXT_BLOCKS_MAX_BLOCKS) as usize;
        if !query.prev_block.shard().is_masterchain() || !query.prev_block.shard().is_full() {
            fail!("expected masterchain block");
        }
        let mut handle = self
            .engine
            .load_block_handle(&query.prev_block)?
            .ok_or_else(|| error!("unknown block {}", query.prev_block))?;
        let mut total_size = 0usize;
        while blocks.len() < max_blocks && handle.has_next1() {
            let next_id = self.engine.load_block_next1(handle.id())?;
            let Some(next) = self.engine.load_block_handle(&next_id)? else {
                break;
            };
            if !next.has_data() || !next.has_proof() {
                break;
            }
            let block = self.engine.load_block_raw(&next).await?;
            let proof = self.engine.load_block_proof_raw(&next, false).await?;
            let entry = Self::serialize_block_full(next.id().clone(), proof, block, false, true)?;
            // The size of the entry without its constructor.
            let size = serialize_boxed(&entry)?.len().saturating_sub(4);
            if total_size.saturating_add(size) > Self::NEXT_BLOCKS_MAX_TOTAL_SIZE
                && !blocks.is_empty()
            {
                break;
            }
            total_size = total_size.saturating_add(size);
            blocks.push(entry);
            if total_size > Self::NEXT_BLOCKS_MAX_TOTAL_SIZE {
                break;
            }
            handle = next;
        }
        Ok(())
    }

    // tonNode.downloadBlockFull block:tonNode.blockIdExt = tonNode.DataFull;
    async fn download_block_full(&self, query: DownloadBlockFull) -> Result<TLObject> {
        #[cfg(test)]
        self.block_download_queries.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut answer = DataFullBoxed::TonNode_DataFullEmpty;
        if let Some(handle) = self.engine.load_block_handle(&query.block)? {
            if let Some(entry) = self.block_full_entry(&handle, self.compression).await? {
                answer = entry;
            }
        }
        Ok(answer.into_tl_object())
    }

    // tonNode.downloadBlock block:tonNode.blockIdExt = tonNode.Data;
    async fn download_block(&self, query: DownloadBlock) -> Result<TaggedByteVec> {
        if let Some(handle) = self.engine.load_block_handle(&query.block)? {
            if handle.has_data() {
                let answer = TaggedByteVec {
                    object: self.engine.load_block_raw(&handle).await?,
                    #[cfg(feature = "telemetry")]
                    tag: 0x8000000A, // Raw reply do download block
                };
                return Ok(answer);
            }
        }
        fail!("Block's data isn't initialized");
    }

    // tonNode.downloadBlocks blocks:(vector tonNode.blockIdExt) = tonNode.DataList;
    // Not supported in t-node

    async fn download_persistent_state_slice_v2(
        &self,
        query: DownloadPersistentStateSliceV2,
    ) -> Result<TaggedByteVec> {
        if query.max_size as usize > PART_MAX_SIZE {
            fail!("Part size {} is too big, max is {}", query.max_size, PART_MAX_SIZE);
        }
        if let Some(handle) = self.engine.load_block_handle(&query.state.block)? {
            if handle.has_persistent_state() {
                let data = self
                    .engine
                    .load_persistent_state_slice(
                        &Self::convert_pss_id(&query.state),
                        query.offset as u64,
                        query.max_size as u64,
                    )
                    .await?;
                #[cfg(test)]
                self.pss_observations.lock().unwrap().push((query.state.block.clone(), Some(query.offset), Some(data.len())));
                let answer = TaggedByteVec {
                    object: data,
                    #[cfg(feature = "telemetry")]
                    tag: 0x8000000B, // Raw reply to download state slice
                };
                return Ok(answer);
            }
        }
        fail!(
            "Persistent state for block {}, {:016x} is not exist",
            query.state.block,
            query.state.effective_shard
        )
    }

    // tonNode.downloadZeroState block:tonNode.blockIdExt = tonNode.Data;
    async fn download_zero_state(&self, query: DownloadZeroState) -> Result<TaggedByteVec> {
        if let Some(handle) = self.engine.load_block_handle(&query.block)? {
            if handle.has_persistent_state() {
                let id = PersistentStatePartId::WholeState(handle.id().clone());
                let size = self.engine.load_persistent_state_size(&id).await?;
                let data = self.engine.load_persistent_state_slice(&id, 0, size).await?;
                let answer = TaggedByteVec {
                    object: data,
                    #[cfg(feature = "telemetry")]
                    tag: 0x8000000C, // Raw reply to download zero state
                };
                return Ok(answer);
            }
        }
        fail!("Zero state {} is not inited", query.block)
    }

    fn convert_pss_id(id: &PersistentStateIdV2) -> PersistentStatePartId {
        let shard_prefix = id.block.shard().shard_prefix_with_tag();
        let part_prefix = id.effective_shard as u64;
        match part_prefix {
            0 => PersistentStatePartId::WholeState(id.block.clone()),
            _ if part_prefix == shard_prefix => PersistentStatePartId::Head(id.block.clone()),
            _ => PersistentStatePartId::Part(id.block.clone(), part_prefix),
        }
    }

    async fn get_persistent_state_size_v2(
        &self,
        query: GetPersistentStateSizeV2,
    ) -> Result<TLObject> {
        self.get_persistent_state_size_internal(Self::convert_pss_id(&query.state)).await
    }

    async fn get_persistent_state_size_internal(
        &self,
        id: PersistentStatePartId,
    ) -> Result<TLObject> {
        let published = self
            .engine
            .load_block_handle(id.block_id())?
            .is_some_and(|handle| handle.has_persistent_state());
        if !published {
            return Ok(
                ton_node::PersistentStateSize::TonNode_PersistentStateSizeNotFound.into_tl_object()
            );
        }
        if let Ok(size) = self.engine.load_persistent_state_size(&id).await {
            let answer = ton_node::persistentstatesize::PersistentStateSize { size: size as i64 }
                .into_boxed();
            Ok(answer.into_tl_object())
        } else {
            Ok(ton_node::PersistentStateSize::TonNode_PersistentStateSizeNotFound.into_tl_object())
        }
    }

    #[cfg(test)]
    pub(crate) async fn test_persistent_size(&self, id: PersistentStatePartId) -> Result<Option<u64>> {
        let answer = self.get_persistent_state_size_internal(id).await?;
        let answer = answer.downcast::<ton_node::PersistentStateSize>()
            .map_err(|_| rtos_block::error!("Unexpected persistent-size reply type"))?;
        Ok(match answer {
            ton_node::PersistentStateSize::TonNode_PersistentStateSize(value) => Some(value.size as u64),
            ton_node::PersistentStateSize::TonNode_PersistentStateSizeNotFound => None,
        })
    }

    #[cfg(test)]
    pub(crate) async fn test_persistent_slice(&self, id: &PersistentStatePartId) -> Result<Vec<u8>> {
        let query = DownloadPersistentStateSliceV2 {
            state: PersistentStateIdV2 {
                block: id.block_id().clone(),
                masterchain_block: id.block_id().clone(),
                effective_shard: id.part_prefix() as i64,
            },
            offset: 0,
            max_size: PART_MAX_SIZE as i64,
        };
        let answer = self.download_persistent_state_slice_v2(query).await?;
        Ok(answer.object)
    }

    async fn download_block_proof_internal(
        &self,
        block_id: BlockIdExt,
        is_link: bool,
        _key_block: bool,
    ) -> Result<TaggedByteVec> {
        if let Some(handle) = self.engine.load_block_handle(&block_id)? {
            if (is_link && handle.has_proof_link()) || (!is_link && handle.has_proof()) {
                let answer = TaggedByteVec {
                    object: self.engine.load_block_proof_raw(&handle, is_link).await?,
                    #[cfg(feature = "telemetry")]
                    tag: 0x8000000D, // Raw reply to download proof
                };
                return Ok(answer);
            }
        }
        if is_link {
            fail!("Block's proof link isn't initialized")
        } else {
            fail!("Block's proof isn't initialized")
        }
    }

    // tonNode.downloadBlockProof block:tonNode.blockIdExt = tonNode.Data;
    async fn download_block_proof(&self, query: DownloadBlockProof) -> Result<TaggedByteVec> {
        self.download_block_proof_internal(query.block, false, false).await
    }

    // tonNode.downloadKeyBlockProof block:tonNode.blockIdExt = tonNode.Data;
    async fn download_key_block_proof(
        &self,
        query: DownloadKeyBlockProof,
    ) -> Result<TaggedByteVec> {
        self.download_block_proof_internal(query.block, false, true).await
    }

    // tonNode.downloadBlockProofs blocks:(vector tonNode.blockIdExt) = tonNode.DataList;
    // Not supported in t-node

    // tonNode.downloadKeyBlockProofs blocks:(vector tonNode.blockIdExt) = tonNode.DataList;
    // Not supported in t-node

    // tonNode.downloadBlockProofLink block:tonNode.blockIdExt = tonNode.Data;
    async fn download_block_proof_link(
        &self,
        query: DownloadBlockProofLink,
    ) -> Result<TaggedByteVec> {
        self.download_block_proof_internal(query.block, true, false).await
    }

    // tonNode.downloadKeyBlockProofLink block:tonNode.blockIdExt = tonNode.Data;
    async fn download_key_block_proof_link(
        &self,
        query: DownloadKeyBlockProofLink,
    ) -> Result<TaggedByteVec> {
        self.download_block_proof_internal(query.block, true, true).await
    }

    // tonNode.downloadBlockProofLinks blocks:(vector tonNode.blockIdExt) = tonNode.DataList;
    // Not supported in t-node

    // tonNode.downloadKeyBlockProofLinks blocks:(vector tonNode.blockIdExt) = tonNode.DataList;
    // Not supported in t-node

    async fn get_any_archive_info(&self, mc_seq_no: u32, shard: ShardIdent) -> Result<TLObject> {
        let mut answer = ArchiveInfoBoxed::TonNode_ArchiveNotFound;
        if let Some(id) = self.engine.load_last_applied_mc_block_id()? {
            if mc_seq_no <= id.seq_no() {
                if let Some(id) = self.engine.load_shard_client_mc_block_id()? {
                    if mc_seq_no <= id.seq_no() {
                        if let Some(id) = self.engine.get_archive_id(mc_seq_no, &shard).await {
                            answer = ArchiveInfo { id: id as ton::long }.into_boxed()
                        }
                    }
                }
            }
        }
        Ok(answer.into_tl_object())
    }

    // tonNode.getArchiveInfo masterchain_seqno:int = tonNode.ArchiveInfo;
    async fn get_archive_info(&self, query: GetArchiveInfo) -> Result<TLObject> {
        self.get_any_archive_info(query.masterchain_seqno as u32, ShardIdent::masterchain()).await
    }

    // tonNode.getShardArchiveInfo masterchain_seqno:int shard_prefix:tonNode.shardId
    //   = tonNode.ArchiveInfo;
    async fn get_shard_archive_info(&self, query: GetShardArchiveInfo) -> Result<TLObject> {
        let shard = ShardIdent::with_tagged_prefix(
            query.shard_prefix.workchain,
            query.shard_prefix.shard as u64,
        )?;
        self.get_any_archive_info(query.masterchain_seqno as u32, shard).await
    }

    // tonNode.getArchiveSlice archive_id:long offset:long max_size:int = tonNode.Data;
    async fn get_archive_slice(&self, query: GetArchiveSlice) -> Result<TaggedByteVec> {
        if query.max_size as usize > storage::archives::bounded_read::ARCHIVE_RANGE_MAX_BYTES {
            fail!("Part size {} is too big, max is {}", query.max_size, storage::archives::bounded_read::ARCHIVE_RANGE_MAX_BYTES);
        }
        let answer = TaggedByteVec {
            object: self
                .engine
                .get_archive_slice(
                    query.archive_id as u64,
                    query.offset as u64,
                    query.max_size as u32,
                )
                .await?,
            #[cfg(feature = "telemetry")]
            tag: 0x8000000E, // Raw reply to download archive slice
        };
        Ok(answer)
    }

    // tonNode.getCapabilities = tonNode.Capabilities;
    async fn get_capabilities(&self, _query: GetCapabilities) -> Result<TLObject> {
        let answer = Capabilities {
            version_major: PROTOCOL_VERSION_MAJOR,
            version_minor: PROTOCOL_VERSION_MINOR,
        }
        .into_boxed();
        Ok(answer.into_tl_object())
    }

    async fn consume_query<'a, Q, F>(
        &'a self,
        query: TLObject,
        consumer: &'a (dyn Fn(&'a Self, Q) -> F + Send + Sync),
    ) -> Result<std::result::Result<QueryResult, TLObject>>
    where
        Q: AnyBoxedSerialize + Debug,
        F: futures::Future<Output = Result<TLObject>>,
    {
        Ok(match query.downcast::<Q>() {
            Ok(query) => {
                let query_str =
                    if log::log_enabled!(log::Level::Trace) || cfg!(feature = "telemetry") {
                        std::any::type_name::<Q>().to_string()
                    } else {
                        String::default()
                    };
                log::trace!("consume_query: before consume query {}", query_str);
                #[cfg(feature = "telemetry")]
                let now = std::time::Instant::now();
                let answer = match consumer(self, query).await {
                    Ok(answer) => {
                        #[cfg(feature = "telemetry")]
                        let tag = answer.bare_object().constructor();
                        let answer = TaggedTlObject {
                            object: answer,
                            #[cfg(feature = "telemetry")]
                            tag,
                        };
                        log::trace!("consume_query: consumed {}", query_str);
                        #[cfg(feature = "telemetry")]
                        self.engine.full_node_service_telemetry().consumed_query(
                            query_str,
                            true,
                            now.elapsed(),
                            serialize_boxed(&answer.object)?.len(),
                        );
                        answer
                    }
                    Err(e) => {
                        log::warn!("consume_query: consumed {}, error {:?}", query_str, e);
                        #[cfg(feature = "telemetry")]
                        self.engine.full_node_service_telemetry().consumed_query(
                            query_str,
                            false,
                            now.elapsed(),
                            0,
                        );
                        return Err(e);
                    }
                };
                Ok(QueryResult::Consumed(QueryAnswer::Ready(Some(Answer::Object(answer)))))
            }
            Err(query) => Err(query),
        })
    }

    async fn consume_query_raw<'a, Q, F>(
        &'a self,
        query: TLObject,
        consumer: &'a (dyn Fn(&'a Self, Q) -> F + Send + Sync),
    ) -> Result<std::result::Result<QueryResult, TLObject>>
    where
        Q: AnyBoxedSerialize + Debug,
        F: futures::Future<Output = Result<TaggedByteVec>>,
    {
        Ok(match query.downcast::<Q>() {
            Ok(query) => {
                let query_str =
                    if log::log_enabled!(log::Level::Trace) || cfg!(feature = "telemetry") {
                        std::any::type_name::<Q>().to_string()
                    } else {
                        String::default()
                    };
                log::trace!("consume_query_raw: before consume query {}", query_str);
                #[cfg(feature = "telemetry")]
                let now = std::time::Instant::now();
                let answer = match consumer(self, query).await {
                    Ok(answer) => {
                        #[cfg(feature = "telemetry")]
                        log::trace!("consume_query_raw: consumed {}", query_str);
                        #[cfg(feature = "telemetry")]
                        self.engine.full_node_service_telemetry().consumed_query(
                            query_str,
                            true,
                            now.elapsed(),
                            answer.object.len(),
                        );
                        answer
                    }
                    Err(e) => {
                        #[cfg(feature = "telemetry")]
                        log::trace!("consume_query_raw: consumed {}, error {:?}", query_str, e);
                        #[cfg(feature = "telemetry")]
                        self.engine.full_node_service_telemetry().consumed_query(
                            query_str,
                            false,
                            now.elapsed(),
                            0,
                        );
                        return Err(e);
                    }
                };
                Ok(QueryResult::Consumed(QueryAnswer::Ready(Some(Answer::Raw(answer)))))
            }
            Err(query) => Err(query),
        })
    }
}

#[async_trait::async_trait]
impl Subscriber for FullNodeOverlayService {
    #[allow(dead_code)]
    async fn try_consume_query(
        &self,
        query: TLObject,
        adnl_peers: &AdnlPeers,
    ) -> Result<QueryResult> {
        let _admission = self.tasks.enter()?;
        log::debug!("try_consume_query {:?} from {}", query, adnl_peers.other());
        #[cfg(test)]
        {
            let pss = if query.is::<DownloadPersistentStateSliceV2>() {
                let request = query.clone().downcast::<DownloadPersistentStateSliceV2>().unwrap();
                Some((request.state, Some(request.offset)))
            } else if query.is::<GetPersistentStateSizeV2>() {
                Some((query.clone().downcast::<GetPersistentStateSizeV2>().unwrap().state, None))
            } else { None };
            if let Some((state, offset)) = pss {
                self.pss_observations.lock().unwrap().push((state.block.clone(), offset, None));
                let mut reply = self.pss_reply.lock().unwrap();
                if reply.as_ref().is_some_and(|(peer, expected, at, _)| {
                    peer == adnl_peers.other() && expected == &state && at == &offset
                }) {
                    let (_, _, _, bytes) = reply.take().unwrap();
                    self.pss_observations.lock().unwrap().push((state.block.clone(), offset, Some(bytes.len())));
                    return Ok(QueryResult::Consumed(QueryAnswer::Ready(Some(Answer::Raw(
                        TaggedByteVec { object: bytes, #[cfg(feature = "telemetry")] tag: 0 },
                    )))));
                }
            }
            let request = if query.is::<DownloadBlockFull>() {
                Some((query.clone().downcast::<DownloadBlockFull>().unwrap().block, true))
            } else if query.is::<DownloadBlockProof>() {
                Some((query.clone().downcast::<DownloadBlockProof>().unwrap().block, false))
            } else {
                None
            };
            if let Some((id, full)) = request {
                self.bounded_queries.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let mut injected = self.bounded_reply.lock().unwrap();
                if injected.as_ref().is_some_and(|(peer, target, kind, _)| {
                    peer == adnl_peers.other() && target == &id && *kind == full
                }) {
                    let (_, _, _, bytes) = injected.take().unwrap();
                    return Ok(QueryResult::Consumed(QueryAnswer::Ready(Some(Answer::Raw(
                        TaggedByteVec {
                            object: bytes,
                            #[cfg(feature = "telemetry")]
                            tag: 0,
                        },
                    )))));
                }
            }
        }

        let query = match self
            .consume_query::<GetNextBlockDescription, _>(query, &Self::get_next_block_description)
            .await?
        {
            Ok(answer) => return Ok(answer),
            Err(query) => query,
        };

        let query = match self
            .consume_query::<PrepareBlockProof, _>(query, &Self::prepare_block_proof)
            .await?
        {
            Ok(answer) => return Ok(answer),
            Err(query) => query,
        };

        let query = match self
            .consume_query::<PrepareKeyBlockProof, _>(query, &Self::prepare_key_block_proof)
            .await?
        {
            Ok(answer) => return Ok(answer),
            Err(query) => query,
        };

        let query = match self.consume_query::<PrepareBlock, _>(query, &Self::prepare_block).await?
        {
            Ok(answer) => return Ok(answer),
            Err(query) => query,
        };

        let query = match self
            .consume_query::<PreparePersistentState, _>(query, &Self::prepare_persistent_state)
            .await?
        {
            Ok(answer) => return Ok(answer),
            Err(query) => query,
        };

        let query = match self
            .consume_query::<PrepareZeroState, _>(query, &Self::prepare_zero_state)
            .await?
        {
            Ok(answer) => return Ok(answer),
            Err(query) => query,
        };

        let query = match self
            .consume_query::<GetNextKeyBlockIds, _>(query, &Self::get_next_key_block_ids)
            .await?
        {
            Ok(answer) => return Ok(answer),
            Err(query) => query,
        };

        let query = match self
            .consume_query::<DownloadNextBlockFull, _>(query, &Self::download_next_block_full)
            .await?
        {
            Ok(answer) => return Ok(answer),
            Err(query) => query,
        };

        let query = match self
            .consume_query::<DownloadNextBlocksFull, _>(query, &Self::download_next_blocks_full)
            .await?
        {
            Ok(answer) => return Ok(answer),
            Err(query) => query,
        };

        let query = match self
            .consume_query::<DownloadBlockFull, _>(query, &Self::download_block_full)
            .await?
        {
            Ok(answer) => return Ok(answer),
            Err(query) => query,
        };

        let query =
            match self.consume_query_raw::<DownloadBlock, _>(query, &Self::download_block).await? {
                Ok(answer) => return Ok(answer),
                Err(query) => query,
            };

        let query = match self
            .consume_query_raw::<DownloadZeroState, _>(query, &Self::download_zero_state)
            .await?
        {
            Ok(answer) => return Ok(answer),
            Err(query) => query,
        };

        let query = match self
            .consume_query_raw::<DownloadBlockProof, _>(query, &Self::download_block_proof)
            .await?
        {
            Ok(answer) => return Ok(answer),
            Err(query) => query,
        };

        let query = match self
            .consume_query_raw::<DownloadKeyBlockProof, _>(query, &Self::download_key_block_proof)
            .await?
        {
            Ok(answer) => return Ok(answer),
            Err(query) => query,
        };

        let query = match self
            .consume_query_raw::<DownloadBlockProofLink, _>(query, &Self::download_block_proof_link)
            .await?
        {
            Ok(answer) => return Ok(answer),
            Err(query) => query,
        };

        let query = match self
            .consume_query_raw::<DownloadKeyBlockProofLink, _>(
                query,
                &Self::download_key_block_proof_link,
            )
            .await?
        {
            Ok(answer) => return Ok(answer),
            Err(query) => query,
        };

        let query =
            match self.consume_query::<GetArchiveInfo, _>(query, &Self::get_archive_info).await? {
                Ok(answer) => return Ok(answer),
                Err(query) => query,
            };

        let query = match self
            .consume_query_raw::<GetArchiveSlice, _>(query, &Self::get_archive_slice)
            .await?
        {
            Ok(answer) => return Ok(answer),
            Err(query) => query,
        };

        let query =
            match self.consume_query::<GetCapabilities, _>(query, &Self::get_capabilities).await? {
                Ok(answer) => return Ok(answer),
                Err(query) => query,
            };

        let query = match self
            .consume_query_raw::<DownloadPersistentStateSliceV2, _>(
                query,
                &Self::download_persistent_state_slice_v2,
            )
            .await?
        {
            Ok(answer) => return Ok(answer),
            Err(query) => query,
        };

        let query = match self
            .consume_query::<GetPersistentStateSizeV2, _>(
                query,
                &Self::get_persistent_state_size_v2,
            )
            .await?
        {
            Ok(answer) => return Ok(answer),
            Err(query) => query,
        };

        let query = match self
            .consume_query::<GetShardArchiveInfo, _>(query, &Self::get_shard_archive_info)
            .await?
        {
            Ok(answer) => return Ok(answer),
            Err(query) => query,
        };

        log::warn!("Unsupported full node query {:?}", query);
        fail!("Unsupported full node query {:?}", query);
    }
}

#[cfg(test)]
#[path = "tests/test_full_node_protocol.rs"]
mod tests;
