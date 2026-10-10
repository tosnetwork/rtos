/*
 * RTOS project modifications (2026-10-10): project and crate naming.
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
    block::BlockIdExtExtention,
    engine_traits::EngineOperations,
    error::NodeError,
    shard_state::ShardStateStuff,
    validating_utils::build_checked_data,
    validator::validator_utils::{calc_subset_for_masterchain, ValidatorSubsetInfo},
};
use rtos_block::{
    error, fail, write_boc, Block, BlockIdExt, BlockInfo, BlockProof, BlockSignaturesVariant,
    BocReader, Cell, ConfigParams, Deserializable, HashmapType, MerkleProof, Result, Serializable,
};
use std::sync::Arc;

#[cfg(test)]
#[path = "tests/test_block_proof.rs"]
mod tests;

/// An authenticated bootstrap position, rooted in an explicit local pin.
/// Private fields prevent parsed peer proofs from being promoted by assignment.
/// A checkpoint pin supplies out-of-band authority, not proof of earlier history.
#[derive(Clone)]
pub(crate) struct BootstrapAuthority {
    anchor: BlockIdExt,
    global_id: i32,
    source: BootstrapSource,
}

#[derive(Clone)]
enum BootstrapSource {
    Zerostate(Arc<ShardStateStuff>),
    KeyBlock(BlockProofStuff),
}

/// Signature-authenticated masterchain proof under a particular bootstrap history.
/// This is not full execution validity and cannot by itself authorize signing.
#[derive(Debug)]
pub(crate) struct VerifiedMasterchainProof {
    proof: BlockProofStuff,
    anchor: BlockIdExt,
    global_id: i32,
}

/// State whose root is committed by an authenticated masterchain block or pin.
/// This attests to the commitment, not replayed execution or permission to sign.
pub(crate) struct VerifiedMasterchainState {
    state: Arc<ShardStateStuff>,
}

impl VerifiedMasterchainState {
    pub(crate) fn state(&self) -> &Arc<ShardStateStuff> {
        &self.state
    }
}

impl VerifiedMasterchainProof {
    pub(crate) fn authenticate_state(
        self,
        state: Arc<ShardStateStuff>,
    ) -> Result<VerifiedMasterchainState> {
        authenticate_committed_state(&self.proof, self.global_id, state)
    }
}

fn authenticate_committed_state(
    proof: &BlockProofStuff,
    global_id: i32,
    state: Arc<ShardStateStuff>,
) -> Result<VerifiedMasterchainState> {
    let root = proof.virtualize_block()?.0.read_state_update()?.new_hash;
    state.verify_state_root(proof.id(), &root)?;
    if state.state()?.global_id() != global_id {
        fail!("Recovered state global_id differs from authenticated block");
    }
    Ok(VerifiedMasterchainState { state })
}

impl std::fmt::Debug for BootstrapAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapAuthority")
            .field("anchor", &self.anchor)
            .field("current", self.id())
            .finish()
    }
}

impl BootstrapAuthority {
    pub(crate) fn from_zerostate(pin: &BlockIdExt, state: Arc<ShardStateStuff>) -> Result<Self> {
        if !pin.shard().is_masterchain_ext() {
            fail!("Bootstrap requires a masterchain zerostate");
        }
        state.verify_zerostate(pin)?;
        let global_id = state.state()?.global_id();
        match state.config_params()?.config(19)? {
            Some(rtos_block::ConfigParamEnum::ConfigParam19(id)) if id == global_id as u32 => {}
            _ => fail!("Bootstrap zerostate global_id disagrees with Param19"),
        }
        Ok(Self { anchor: pin.clone(), global_id, source: BootstrapSource::Zerostate(state) })
    }

    pub(crate) fn from_checkpoint(pin: &BlockIdExt, proof: BlockProofStuff) -> Result<Self> {
        proof.check_trusted_checkpoint(pin)?;
        let global_id = proof.virtualize_block()?.0.global_id();
        Ok(Self { anchor: pin.clone(), global_id, source: BootstrapSource::KeyBlock(proof) })
    }

    pub(crate) fn id(&self) -> &BlockIdExt {
        match &self.source {
            BootstrapSource::Zerostate(state) => state.block_id(),
            BootstrapSource::KeyBlock(proof) => proof.id(),
        }
    }
    pub(crate) fn anchor(&self) -> &BlockIdExt {
        &self.anchor
    }
    pub(crate) fn key_block_proof(&self) -> Option<&BlockProofStuff> {
        match &self.source {
            BootstrapSource::KeyBlock(proof) => Some(proof),
            _ => None,
        }
    }
    pub(crate) fn config(&self) -> Result<ConfigParams> {
        match &self.source {
            BootstrapSource::Zerostate(state) => Ok(state.config_params()?.clone()),
            BootstrapSource::KeyBlock(proof) => proof.get_config_params(),
        }
    }

    pub(crate) fn authenticate_current_state(
        &self,
        state: Arc<ShardStateStuff>,
    ) -> Result<VerifiedMasterchainState> {
        match &self.source {
            BootstrapSource::Zerostate(_) => {
                state.verify_zerostate(self.id())?;
                Ok(VerifiedMasterchainState { state })
            }
            BootstrapSource::KeyBlock(proof) => {
                authenticate_committed_state(proof, self.global_id, state)
            }
        }
    }

    pub(crate) fn authenticate_block(
        &self,
        expected: &BlockIdExt,
        proof: BlockProofStuff,
    ) -> Result<VerifiedMasterchainProof> {
        if proof.id() != expected {
            fail!("Boot proof does not match requested block identity");
        }
        if proof.is_link() || !expected.shard().is_masterchain_ext() {
            fail!("Bootstrap successor requires a full masterchain proof");
        }
        if proof.virtualize_block()?.0.global_id() != self.global_id {
            fail!("Bootstrap successor belongs to a different global_id");
        }
        match &self.source {
            BootstrapSource::Zerostate(state) => proof.check_with_master_state(state)?,
            BootstrapSource::KeyBlock(previous) => {
                proof.check_with_prev_key_block_proof(previous)?
            }
        }
        Ok(VerifiedMasterchainProof {
            proof,
            anchor: self.anchor.clone(),
            global_id: self.global_id,
        })
    }

    pub(crate) fn advance_key_block(
        &self,
        expected: &BlockIdExt,
        proof: BlockProofStuff,
    ) -> Result<Self> {
        let verified = self.authenticate_block(expected, proof)?;
        // Authority can advance only after signatures authenticate the new block,
        // and its actual header/config qualify it as a governing key block.
        verified.proof.check_trusted_checkpoint(expected)?;
        Ok(Self {
            anchor: verified.anchor,
            global_id: verified.global_id,
            source: BootstrapSource::KeyBlock(verified.proof),
        })
    }
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct BlockProofStuff {
    proof: BlockProof,
    root: Cell,
    is_link: bool,
    id: BlockIdExt,
    data: Arc<Vec<u8>>,
}

impl BlockProofStuff {
    pub fn deserialize(block_id: &BlockIdExt, data: Vec<u8>, is_link: bool) -> Result<Self> {
        let data = Arc::new(data);
        let root = BocReader::new().read(&*data)?.withdraw_single_root()?;
        let proof = BlockProof::construct_from_cell(root.clone())?;
        if &proof.proof_for != block_id {
            fail!(NodeError::InvalidData(format!(
                "proof for another block (found: {}, expected: {})",
                proof.proof_for, block_id
            )))
        }
        if !block_id.is_masterchain() && !is_link {
            fail!(NodeError::InvalidData(format!("proof for non-masterchain block {}", block_id)))
        }
        Ok(BlockProofStuff { proof, root, is_link, id: block_id.clone(), data })
    }

    pub fn new(proof: BlockProof, is_link: bool) -> Result<Self> {
        let id = proof.proof_for.clone();
        if !id.is_masterchain() && !is_link {
            fail!(NodeError::InvalidData(format!("proof for non-masterchain block {}", id)))
        }
        let cell = proof.serialize()?;
        let data = Arc::new(write_boc(&cell)?);
        Ok(Self { root: proof.serialize()?, proof, is_link, id, data })
    }

    #[cfg(test)]
    pub fn read_from_file(block_id: &BlockIdExt, filename: &str, is_link: bool) -> Result<Self> {
        let data = std::fs::read(filename)?;
        Self::deserialize(block_id, data, is_link)
    }

    #[cfg(test)]
    pub fn fake(id: &BlockIdExt) -> Result<Self> {
        let proof = BlockProof { proof_for: id.clone(), root: Cell::default(), signatures: None };
        let cell = proof.serialize()?;
        let data = Arc::new(write_boc(&cell)?);
        Ok(Self {
            root: proof.serialize()?,
            proof,
            is_link: !id.shard().is_masterchain(),
            id: id.clone(),
            data,
        })
    }

    // Unused
    //    pub fn root(&self) -> &Cell {
    //        &self.root
    //    }

    pub fn merkle_proof_root_cell(&self) -> &Cell {
        &self.proof.root
    }

    pub fn root_cell(&self) -> &Cell {
        &self.root
    }

    pub fn virtualize_block(&self) -> Result<(Block, Cell)> {
        let merkle_proof = MerkleProof::construct_from_cell(self.proof.root.clone())?;
        let block_virt_root = merkle_proof.proof.clone().virtualize(1);
        if *self.proof.proof_for.root_hash() != *block_virt_root.repr_hash() {
            fail!(NodeError::InvalidData(format!(
                "merkle proof has invalid virtual hash (found: {:x}, expected: {})",
                block_virt_root.repr_hash(),
                self.proof.proof_for
            )))
        }
        if *block_virt_root.repr_hash() != self.id().root_hash {
            fail!(NodeError::InvalidData(format!(
                "proof for block {} contains a Merkle proof with incorrect root hash: \
                expected {:x}, found: {:x} ",
                self.id(),
                self.id().root_hash,
                block_virt_root.repr_hash()
            )))
        }
        Ok((Block::construct_from_cell(block_virt_root.clone())?, block_virt_root))
    }

    pub fn get_config_params(&self) -> Result<ConfigParams> {
        let (virt_block, _) = self.virtualize_block()?;
        self.read_config_params(&virt_block)
    }

    pub fn is_link(&self) -> bool {
        self.is_link
    }

    pub fn id(&self) -> &BlockIdExt {
        &self.id
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn drain_signatures(self) -> Result<BlockSignaturesVariant> {
        self.proof.signatures.ok_or_else(|| error!("Proof doesn't contain signatures"))
    }

    /// The caller must authenticate the previous key block against its network
    /// anchor/history before using it as governing authority here.
    pub fn check_with_prev_key_block_proof(
        &self,
        prev_key_block_proof: &BlockProofStuff,
    ) -> Result<()> {
        let now = std::time::Instant::now();
        log::trace!("Checking proof for block: {}", self.id());

        let (virt_block, virt_block_info) = self.pre_check_block_proof()?;

        self.check_with_prev_key_block_proof_(prev_key_block_proof, &virt_block, &virt_block_info)?;

        log::trace!(
            "Checked proof for block: {}   TIME {}ms",
            self.id(),
            now.elapsed().as_millis()
        );
        Ok(())
    }

    /// The caller must supply a master state authenticated against its selected
    /// network/history. A decoded state alone is not a trust anchor.
    pub fn check_with_master_state(&self, master_state: &ShardStateStuff) -> Result<()> {
        let now = std::time::Instant::now();
        log::trace!("Checking proof for block: {}", self.id());

        if self.is_link {
            fail!(NodeError::InvalidOperation(format!(
                "Can't verify block {}: can't call `check_with_master_state` for proof link",
                self.id()
            )))
        }

        let (virt_block, virt_block_info) = self.pre_check_block_proof()?;

        self.check_with_master_state_(master_state, &virt_block, &virt_block_info)?;

        log::trace!(
            "Checked proof for block: {}   TIME {}ms",
            self.id(),
            now.elapsed().as_millis()
        );
        Ok(())
    }

    /// Authenticate checkpoint contents against an explicitly trusted local pin.
    /// The pin itself is an out-of-band trust decision, not derived from this
    /// proof, a peer response, or a database resume cursor. This does not verify
    /// history before the checkpoint or the original full block's file bytes.
    pub(crate) fn check_trusted_checkpoint(&self, expected: &BlockIdExt) -> Result<()> {
        if self.id() != expected || !expected.shard().is_masterchain_ext() || expected.seq_no == 0 {
            fail!("Checkpoint proof differs from the explicitly pinned masterchain identity");
        }
        let (block, info) = self.pre_check_block_proof()?;
        if !info.key_block() {
            fail!("Checkpoint must be a key block");
        }
        self.pre_check_key_block_proof(&block)?;
        let config = self.read_config_params(&block)?;
        match config.config(19)? {
            Some(rtos_block::ConfigParamEnum::ConfigParam19(id))
                if id == block.global_id() as u32 => {}
            _ => fail!("Checkpoint global_id disagrees with missing or mismatched Param19"),
        }
        Ok(())
    }

    pub fn check_proof_as_link(&self) -> Result<()> {
        let now = std::time::Instant::now();
        log::trace!("Checking proof for block: {}", self.id());

        if self.is_link {
            fail!(NodeError::InvalidOperation(format!(
                "Can't call `check_proof_as_link` not for proof, block {}",
                self.id()
            )))
        }
        self.pre_check_block_proof()?;
        log::trace!(
            "Checked proof as link for block: {}   TIME {}ms",
            self.id(),
            now.elapsed().as_millis()
        );
        Ok(())
    }

    pub fn check_proof_link(&self) -> Result<()> {
        let now = std::time::Instant::now();
        log::trace!("Checking proof for block: {}", self.id());

        if !self.is_link {
            fail!(NodeError::InvalidOperation(format!(
                "Can't call `check_proof_link` not for proof link, block {}",
                self.id()
            )))
        }
        self.pre_check_block_proof()?;
        log::trace!(
            "Checked proof link for block: {}   TIME {}ms",
            self.id(),
            now.elapsed().as_millis()
        );
        Ok(())
    }

    pub async fn check_proof(&self, engine: &dyn EngineOperations) -> Result<()> {
        if self.is_link() {
            self.check_proof_link()?;
        } else {
            let now = std::time::Instant::now();
            log::trace!("Checking proof for block: {}", self.id());

            let (virt_block, virt_block_info) = self.pre_check_block_proof()?;
            let prev_key_block_seqno = virt_block_info.prev_key_block_seqno();

            if prev_key_block_seqno == 0 {
                let zerostate = engine.load_mc_zero_state().await?;
                zerostate.verify_zerostate(engine.zerostate_id()?)?;
                self.check_with_master_state_(&zerostate, &virt_block, &virt_block_info)?;
            } else {
                let state = engine.load_last_applied_mc_state().await?;
                let prev_key_block_id =
                    state.find_block_id(prev_key_block_seqno).map_err(|err| {
                        error!(
                            "Couldn't find previous MC key block by seq_no = {}: {}",
                            prev_key_block_seqno, err
                        )
                    })?;
                let handle = engine.load_block_handle(&prev_key_block_id)?.ok_or_else(|| {
                    error!(
                        "Couldn't load handle for previous MC key block by seq_no = {}",
                        prev_key_block_seqno
                    )
                })?;
                let prev_key_block_proof = engine.load_block_proof(&handle, false).await?;
                self.check_with_prev_key_block_proof_(
                    &prev_key_block_proof,
                    &virt_block,
                    &virt_block_info,
                )?;
            }

            log::trace!(
                "Checked proof for block: {}   TIME {}ms",
                self.id(),
                now.elapsed().as_millis()
            );
        }
        Ok(())
    }

    // Unused
    //    pub fn get_cur_validators_set(&self) -> Result<(ValidatorSet, CatchainConfig)> {
    //        let (virt_key_block, prev_key_block_info) = self.pre_check_block_proof()?;
    //        if !prev_key_block_info.key_block() {
    //            fail!(NodeError::InvalidData(format!(
    //                "proof for key block {} contains a Merkle proof which declares non key block",
    //                self.id(),
    //            )))
    //        }
    //        let (cur_validator_set, cc_config) = virt_key_block.read_cur_validator_set_and_cc_conf()
    //            .map_err(|err| {
    //                NodeError::InvalidData(format!(
    //                    "Сan't extract config params from key block's proof {}: {}",
    //                    self.id, err
    //                ))
    //            })?;
    //        Ok((cur_validator_set, cc_config))
    //    }

    fn check_with_prev_key_block_proof_(
        &self,
        prev_key_block_proof: &BlockProofStuff,
        virt_block: &Block,
        virt_block_info: &BlockInfo,
    ) -> Result<()> {
        if !self.id().is_masterchain() {
            fail!(NodeError::InvalidData(format!(
                "Can't verify non masterchain block {} using previous key masterchain block",
                self.id()
            )))
        }
        if !prev_key_block_proof.id().is_masterchain() {
            fail!(NodeError::InvalidData(format!(
                "Invalid previous key block: it's id {} doesn't belong to the masterchain",
                prev_key_block_proof.id()
            )))
        }
        let prev_key_block_seqno = virt_block.read_info()?.prev_key_block_seqno();
        if prev_key_block_proof.id().seq_no != prev_key_block_seqno {
            fail!(NodeError::InvalidData(format!(
                "Can't verify block {} using key block {} \
                because the block declares different previous key block seqno {}",
                self.id(),
                prev_key_block_proof.id(),
                prev_key_block_seqno
            )))
        }
        if prev_key_block_proof.id().seq_no >= self.id().seq_no {
            fail!(NodeError::InvalidData(format!(
                "Can't verify block {} using key block {} with larger or equal seqno",
                self.id(),
                prev_key_block_proof.id()
            )))
        }

        let (subset, virt_prev_key_block) =
            self.process_prev_key_block_proof(prev_key_block_proof)?;

        if virt_prev_key_block.read_info()?.gen_utime() > virt_block_info.gen_utime() {
            fail!(NodeError::InvalidData(format!(
                "Can't verify block {} using key block {} with larger gen_utime",
                self.id(),
                prev_key_block_proof.id()
            )))
        }

        if virt_block_info.key_block() {
            self.pre_check_key_block_proof(virt_block)?;
        }

        if let Some(BlockSignaturesVariant::SimplexPq(carrier)) = &self.proof.signatures {
            if virt_block.global_id() != virt_prev_key_block.global_id() {
                fail!("PQ target global_id differs from governing key block");
            }
            let config = prev_key_block_proof.read_config_params(&virt_prev_key_block)?;
            let context = rtos_api::pq_finality::PqVerificationContext::from_governing_config(
                virt_prev_key_block.global_id(),
                &config,
                self.id.clone(),
                virt_block_info.vert_seq_no(),
                virt_block_info.prev_key_block_seqno(),
                carrier.validator_info.catchain_seqno,
            )?;
            context.verify_final(carrier)?;
            return Ok(());
        }
        self.check_signatures(&subset)
    }

    fn check_with_master_state_(
        &self,
        master_state: &ShardStateStuff,
        virt_block: &Block,
        virt_block_info: &BlockInfo,
    ) -> Result<()> {
        if virt_block_info.key_block() {
            self.pre_check_key_block_proof(virt_block)?;
        }
        let subset = self.process_given_state(master_state, virt_block_info)?;
        if let Some(BlockSignaturesVariant::SimplexPq(carrier)) = &self.proof.signatures {
            let extra = master_state.shard_state_extra()?;
            let governing_key_seqno = if extra.after_key_block {
                master_state.block_id().seq_no
            } else {
                extra.last_key_block.as_ref().map(|key| key.seq_no).unwrap_or(0)
            };
            if governing_key_seqno != virt_block_info.prev_key_block_seqno() {
                fail!("PQ governing state belongs to a different key-block epoch");
            }
            let global_id = master_state.state()?.global_id();
            if virt_block.global_id() != global_id {
                fail!("PQ target global_id differs from governing state");
            }
            let context = rtos_api::pq_finality::PqVerificationContext::from_governing_config(
                global_id,
                master_state.config_params()?,
                self.id.clone(),
                virt_block_info.vert_seq_no(),
                virt_block_info.prev_key_block_seqno(),
                carrier.validator_info.catchain_seqno,
            )?;
            context.verify_final(carrier)?;
            return Ok(());
        }
        self.check_signatures(&subset)
    }

    fn pre_check_block_proof(&self) -> Result<(Block, BlockInfo)> {
        if !self.id().is_masterchain() && self.proof.signatures.is_some() {
            fail!(NodeError::InvalidData(format!(
                "proof for non-master block {} can't contain signatures",
                self.id(),
            )))
        }
        let (virt_block, virt_block_root) = self.virtualize_block()?;
        let info = Self::pre_check_virtual_block(self.id(), &virt_block, &virt_block_root)?;
        Ok((virt_block, info))
    }

    fn pre_check_virtual_block(
        id: &BlockIdExt,
        virt_block: &Block,
        virt_block_root: &Cell,
    ) -> Result<BlockInfo> {
        if *virt_block_root.repr_hash() != id.root_hash {
            fail!(NodeError::InvalidData(format!(
                "proof for block {} contains a Merkle proof with incorrect root hash: \
                expected {:x}, found: {:x} ",
                id,
                id.root_hash,
                virt_block_root.repr_hash()
            )))
        }

        let info = virt_block.read_info()?;
        let value_flow = virt_block.read_value_flow()?;
        value_flow
            .read_in_full_depth()
            .map_err(|e| error!("Can't read value flow in full depth: {}", e))?;
        let _state_update = virt_block.read_state_update()?;

        if info.version() != 0 {
            fail!(NodeError::InvalidData(format!(
                "proof for block {} contains a Merkle proof \
                with incorrect block info's version {}",
                id,
                info.version()
            )))
        }

        if info.seq_no() != id.seq_no {
            fail!(NodeError::InvalidData(format!(
                "proof for block {} contains a Merkle proof with seq_no {}, but {} is expected",
                id,
                info.seq_no(),
                id.seq_no
            )))
        }

        if info.shard() != id.shard() {
            fail!(NodeError::InvalidData(format!(
                "proof for block {} contains a Merkle proof with shard id {}, but {} is expected",
                id,
                info.shard(),
                id.shard()
            )))
        }

        if info.read_master_ref()?.is_some() == info.shard().is_masterchain() {
            fail!(NodeError::InvalidData(format!(
                "proof for block {} contains a Merkle proof \
                with invalid not_master flag in block info",
                id,
            )))
        }

        if id.is_masterchain() && (info.after_merge() || info.before_split() || info.after_split())
        {
            fail!(NodeError::InvalidData(format!(
                "proof for block {} contains a Merkle proof with a block info \
                which declares split/merge for a masterchain block",
                id,
            )))
        }

        if info.after_merge() && info.after_split() {
            fail!(NodeError::InvalidData(format!(
                "proof for block {} contains a Merkle proof with a block info \
                which declares both after merge and after split flags",
                id,
            )))
        }

        if info.after_split() && (info.shard().is_full()) {
            fail!(NodeError::InvalidData(format!(
                "proof for block {} contains a Merkle proof with a block info \
                which declares both after_split flag and non zero shard prefix",
                id,
            )))
        }

        if info.after_merge() && !info.shard().can_split() {
            fail!(NodeError::InvalidData(format!(
                "proof for block {} contains a Merkle proof with a block info \
                which declares both after_merge flag and shard prefix which can't split anymore",
                id,
            )))
        }

        if info.key_block() && !id.is_masterchain() {
            fail!(NodeError::InvalidData(format!(
                "proof for block {} contains a Merkle proof \
                which declares non master chain but key block",
                id,
            )))
        }

        if info.gen_utime() == 0 {
            fail!(NodeError::InvalidData(format!(
                "proof for block {} contains a Merkle proof with zero gen_utime",
                id,
            )))
        }

        Ok(info)
    }

    fn read_config_params(&self, virt_block: &Block) -> Result<ConfigParams> {
        let extra = virt_block.read_extra()?;
        let mut mc_extra = extra.read_custom()?.ok_or_else(|| {
            NodeError::InvalidData(format!(
                "proof for key block {} contains a Merkle proof without masterchain block extra",
                self.id(),
            ))
        })?;
        let config = mc_extra.config_mut().take().ok_or_else(|| {
            NodeError::InvalidData(format!(
                "proof for key block {} contains a Merkle proof without config params",
                self.id(),
            ))
        })?;
        Ok(config)
    }

    fn pre_check_key_block_proof(&self, virt_block: &Block) -> Result<()> {
        let config = self.read_config_params(virt_block)?;
        let _cur_validator_set = config.config(34)?.ok_or_else(|| {
            NodeError::InvalidData(format!(
                "proof for key block {} contains a Merkle proof \
                without current validators config param (34)",
                self.id(),
            ))
        })?;
        for i_config in 32..=38 {
            let _val_set = config.config(i_config)?;
        }
        let _catchain_config = config.config(28)?;

        Ok(())
    }

    fn process_prev_key_block_proof(
        &self,
        prev_key_block_proof: &BlockProofStuff,
    ) -> Result<(ValidatorSubsetInfo, Block)> {
        let (virt_key_block, prev_key_block_info) = prev_key_block_proof.pre_check_block_proof()?;

        if !prev_key_block_info.key_block() {
            fail!(NodeError::InvalidData(format!(
                "proof for key block {} contains a Merkle proof which declares non key block",
                prev_key_block_proof.id(),
            )))
        }

        let (validator_set, _cc_config) =
            virt_key_block.read_cur_validator_set_and_cc_conf().map_err(|err| {
                NodeError::InvalidData(format!(
                    "While checking proof for {}: \
                    can't extract config params from key block's proof {}: {}",
                    self.id,
                    prev_key_block_proof.id(),
                    err
                ))
            })?;

        let config = virt_key_block
            .read_extra()?
            .read_custom()?
            .and_then(|custom| custom.config().cloned())
            .ok_or_else(|| {
                error!(NodeError::InvalidArg("State doesn't contain `custom` field".to_string()))
            })?;

        let subset = calc_subset_for_masterchain(
            &validator_set,
            &config,
            self.proof.signatures.as_ref().map(|s| s.validator_info().catchain_seqno).unwrap_or(0),
        )?;

        Ok((subset, virt_key_block))
    }

    fn check_signatures(&self, subset: &ValidatorSubsetInfo) -> Result<()> {
        // Pre checks
        if self.proof.signatures.is_none() {
            fail!(NodeError::InvalidData(format!(
                "Proof for {} doesn't have signatures to check",
                self.id(),
            )));
        }
        let signatures = self.proof.signatures.as_ref().unwrap();
        if signatures.validator_info().validator_list_hash_short != subset.short_hash {
            fail!(NodeError::InvalidData(format!(
                "Bad validator set hash in proof for block {}, calculated: {}, found: {}",
                self.id(),
                subset.short_hash,
                signatures.validator_info().validator_list_hash_short
            )));
        }
        let expected_count = signatures.pure_signatures()?.count() as usize;
        let count = signatures.pure_signatures()?.signatures().count(expected_count)?;
        if expected_count != count {
            fail!(NodeError::InvalidData(format!(
                "Proof for {}: signature count mismatch: declared: {}, calculated: {}",
                self.id(),
                expected_count,
                count
            )));
        }

        // Generate checked_data based on signature variant
        let checked_data = build_checked_data(signatures, &self.id).map_err(|err| {
            NodeError::InvalidData(format!(
                "Proof for {}: failed to build checked_data: {err}",
                self.id()
            ))
        })?;

        let total_weight: u64 =
            rtos_block::checked_validator_weight_sum(subset.validators.iter().map(|v| v.weight))?;
        let weight = signatures
            .pure_signatures()?
            .check_signatures(&subset.validators, &checked_data)
            .map_err(|err| {
                NodeError::InvalidData(format!(
                    "Proof for {}: error while check signatures: {err}",
                    self.id()
                ))
            })?;

        // Check weight
        if weight != signatures.pure_signatures()?.weight() {
            fail!(NodeError::InvalidData(format!(
                "Proof for {}: total signature weight mismatch: declared: {}, calculated: {}",
                self.id(),
                signatures.pure_signatures()?.weight(),
                weight
            )));
        }

        if !rtos_block::has_quorum(weight, total_weight) {
            fail!(NodeError::InvalidData(format!(
                "Proof for {}: too small signatures weight",
                self.id(),
            )));
        }

        Ok(())
    }

    fn process_given_state(
        &self,
        state: &ShardStateStuff,
        block_info: &BlockInfo,
    ) -> Result<ValidatorSubsetInfo> {
        // Checks
        if !state.block_id().is_masterchain() {
            fail!(NodeError::InvalidData(format!(
                "Can't check proof for {}: given state {} doesn't belong masterchain",
                self.id(),
                state.block_id()
            )));
        }
        if !self.id().is_masterchain() {
            fail!(NodeError::InvalidData(format!(
                "Can't check proof for non master block {} using master state",
                self.id(),
            )));
        }
        if state.block_id().seq_no < block_info.prev_key_block_seqno() {
            fail!(NodeError::InvalidData(format!(
                "Can't check proof for block {} using master state {}, \
                because it is older than the previous key block with seqno {}",
                self.id(),
                state.block_id(),
                block_info.prev_key_block_seqno()
            )));
        }
        if state.block_id().seq_no >= self.id().seq_no {
            fail!(NodeError::InvalidData(format!(
                "Can't check proof for block {} using newer master state {}",
                self.id(),
                state.block_id(),
            )));
        }

        let (cur_validator_set, _cc_config) =
            state.state()?.read_cur_validator_set_and_cc_conf()?;

        calc_subset_for_masterchain(
            &cur_validator_set,
            state.config_params()?,
            self.proof.signatures.as_ref().map(|s| s.validator_info().catchain_seqno).unwrap_or(0),
        )
    }
}
