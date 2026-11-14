// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Structural proof operations. Decoding never authenticates a governing key block.
use crate::{
    fail, Block, BlockIdExt, BlockInfo, BuilderData, Cell, Deserializable, IBitstring, MerkleProof,
    Result, Serializable, SliceData, UInt256,
};

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
