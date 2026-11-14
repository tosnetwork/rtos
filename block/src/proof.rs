// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Structural proof operations. Decoding never authenticates a governing key block.
use crate::{
    fail, Block, BlockIdExt, BlockInfo, BuilderData, Cell, Deserializable, IBitstring, MerkleProof,
    Result, Serializable, SliceData, UInt256,
};

impl crate::ConfigParams {
    /// Legacy key-proof configuration profile. Missing or non-unpackable
    /// Param28/29 uses the C++ factory defaults; unavailable proof cells remain
    /// errors. Strict node configuration accessors are independent.
    pub fn legacy_proof_consensus_parameters(
        &self,
    ) -> Result<(crate::CatchainConfig, crate::ConsensusConfig)> {
        let cell = |index: u32| -> Result<Option<Cell>> {
            let cell = self
                .config_params
                .get(index.write_to_bitstring()?)?
                .map(|value| value.reference(0))
                .transpose()?;
            if cell.as_ref().is_some_and(|cell| cell.cell_type() == crate::CellType::PrunedBranch) {
                fail!(crate::BlockError::PrunedCellAccess("legacy proof config is pruned".into()));
            }
            Ok(cell)
        };
        let mut catchain = crate::CatchainConfig {
            mc_catchain_lifetime: 200,
            shard_catchain_lifetime: 200,
            shard_validators_lifetime: 3000,
            shard_validators_num: 7,
            ..Default::default()
        };
        if let Some(cell) = cell(28)? {
            // Load outside the optional decoder: a pruned cell is unavailable,
            // not an ordinary malformed configuration eligible for fallback.
            let mut slice = SliceData::load_cell(cell.clone())?;
            let tag = slice.get_next_byte().ok();
            let flags_valid =
                tag != Some(0xc2) || slice.get_next_byte().is_ok_and(|flags| flags & !1 == 0);
            if flags_valid {
                if let Ok(value) = crate::CatchainConfig::construct_from_full_cell(cell) {
                    catchain = value;
                }
            }
        }
        let mut consensus = crate::ConsensusConfig {
            round_candidates: 3,
            next_candidate_delay_ms: 2000,
            consensus_timeout_ms: 16000,
            fast_attempts: 4,
            attempt_duration: 16,
            catchain_max_deps: 4,
            max_block_bytes: 4 << 20,
            max_collated_bytes: 4 << 20,
            ..Default::default()
        };
        if let Some(cell) = cell(29)? {
            SliceData::load_cell(cell.clone())?;
            if let Ok(value) = crate::ConsensusConfig::construct_from_full_cell(cell) {
                consensus = value;
            }
        }
        Ok((catchain, consensus))
    }
}

// Handwritten unpack is stricter than validate_skip: depth <=60 and all
// low bits, including the future tag bit, must be zero in the stored prefix.
pub(crate) fn unpack_shard_ident(slice: &mut SliceData) -> Result<crate::ShardIdent> {
    let bits = slice.get_next_byte()?;
    if bits > 60 {
        fail!("invalid proof shard depth or tag");
    }
    let workchain = slice.get_next_u32()? as i32;
    let prefix = slice.get_next_u64()?;
    if prefix & (u64::MAX >> bits) != 0 {
        fail!("invalid proof shard prefix");
    }
    crate::ShardIdent::with_prefix_len(bits, workchain, prefix)
}

/// Keep the signature cell opaque until the consumer reaches signature decoding.
/// This preserves the header-before-signatures boundary of the lite proof reader.
#[derive(Clone, Debug, Default)]
pub struct BlockProofEnvelope {
    pub proof_for: BlockIdExt,
    pub root: Cell,
    pub signatures: Option<Cell>,
}

impl Deserializable for BlockProofEnvelope {
    fn construct_from(slice: &mut SliceData) -> Result<Self> {
        if slice.get_next_byte()? != 0xc3 {
            fail!("invalid BlockProof");
        }
        let shard = unpack_shard_ident(slice)?;
        let proof_for = BlockIdExt::with_params(
            shard,
            slice.get_next_u32()?,
            UInt256::construct_from(slice)?,
            UInt256::construct_from(slice)?,
        );
        let root = slice.checked_drain_reference()?;
        let signatures =
            if slice.get_next_bit()? { Some(slice.checked_drain_reference()?) } else { None };
        Ok(Self { proof_for, root, signatures })
    }
}

impl Serializable for BlockProofEnvelope {
    fn write_to(&self, builder: &mut BuilderData) -> Result<()> {
        builder.append_u8(0xc3)?;
        self.proof_for.write_to(builder)?;
        builder.checked_append_reference(self.root.clone())?;
        builder.append_bit_bool(self.signatures.is_some())?;
        if let Some(cell) = &self.signatures {
            builder.checked_append_reference(cell.clone())?;
        }
        Ok(())
    }
}

impl BlockProofEnvelope {
    pub fn virtual_root(&self) -> Result<Cell> {
        if self.root.level() != 0 || self.root.cell_type() != crate::CellType::MerkleProof {
            fail!("invalid top-level Merkle proof");
        }
        let proof = MerkleProof::construct_from_full_cell(self.root.clone())?;
        Ok(proof.proof.virtualize(1))
    }
}

/// C++ check_block_header boundary: identity and header shape, without value-flow
/// traversal, transaction execution or signature verification.
pub fn check_block_header(root: &Cell, id: &BlockIdExt) -> Result<(Block, BlockInfo)> {
    if root.cell_type() == crate::CellType::PrunedBranch {
        fail!(crate::BlockError::PrunedCellAccess("block header is pruned".into()));
    }
    let block = Block::construct_from_full_cell(root.clone())?;
    let info = BlockInfo::construct_header_from_cell(block.info_cell())?;
    if info.version() != 0 {
        fail!("cannot unpack block header");
    }
    if info.seq_no() != id.seq_no() || info.shard() != id.shard() {
        fail!("block header contains block id different from expected");
    }
    if root.repr_hash() != id.root_hash() {
        fail!("block header has incorrect root hash");
    }
    if info.not_master() == info.shard().is_masterchain() {
        fail!("block has invalid not_master flag");
    }
    Ok((block, info))
}
