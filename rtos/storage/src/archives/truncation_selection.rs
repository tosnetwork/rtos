// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Owned, versioned archive truncation inputs shared by both archive maps.
use crate::traits::Serializable;
use rtos_block::{error, fail, BlockIdExt, Result};
use std::{io::{Read, Write}, sync::Arc};

const PREDICATE_VERSION: u16 = 1;
const _: () = assert!(BlockIdExt::SIZE == 80);
const PREFIX_BYTES: u64 = 2 + BlockIdExt::SIZE as u64 + 8;

#[derive(Debug)]
pub struct TruncationSelection {
    cutoff: BlockIdExt,
    top_blocks: Arc<[BlockIdExt]>,
}

impl TruncationSelection {
    pub fn new(cutoff: BlockIdExt, top_blocks: impl Into<Arc<[BlockIdExt]>>) -> Result<Self> {
        if !cutoff.shard().is_masterchain() {
            fail!("Archive truncation cutoff must be a masterchain block");
        }
        Ok(Self { cutoff, top_blocks: top_blocks.into() })
    }

    pub fn cutoff(&self) -> &BlockIdExt {
        &self.cutoff
    }

    pub fn top_blocks(&self) -> &[BlockIdExt] {
        &self.top_blocks
    }

    /// Preserve the original InternalDb predicate, including its asymmetric
    /// masterchain >= and intersecting-shard > comparisons.
    pub fn should_delete(&self, id: &BlockIdExt) -> bool {
        if id.shard().is_masterchain() {
            id.seq_no() >= self.cutoff.seq_no()
        } else {
            self.top_blocks.iter().any(|top| {
                id.shard().intersect_with(top.shard()) && id.seq_no() > top.seq_no()
            })
        }
    }

    pub(crate) fn encoded_len(&self) -> Result<u64> {
        predicate_len(u64::try_from(self.top_blocks.len())?)
    }

    /// Writes one predicate record's body; the containing manifest supplies
    /// framing/digest and its owned executor supplies mutation authority.
    pub(crate) fn write_predicate(&self, writer: &mut impl Write) -> Result<()> {
        self.encoded_len()?;
        writer.write_all(&PREDICATE_VERSION.to_le_bytes())?;
        writer.write_all(&self.cutoff.serialize())?;
        writer.write_all(&u64::try_from(self.top_blocks.len())?.to_le_bytes())?;
        for id in self.top_blocks.iter() {
            writer.write_all(&id.serialize())?;
        }
        Ok(())
    }
}

fn predicate_len(count: u64) -> Result<u64> {
    count.checked_mul(BlockIdExt::SIZE as u64)
        .and_then(|bytes| PREFIX_BYTES.checked_add(bytes))
        .ok_or_else(|| error!("Archive truncation predicate length overflow"))
}

/// Streams full IDs to the manifest validator/scratch index. It never allocates
/// a collection from the on-disk count or consumes the next manifest record.
pub(crate) fn read_predicate(
    reader: &mut impl Read,
    encoded_len: u64,
    mut visit: impl FnMut(BlockIdExt) -> Result<()>,
) -> Result<BlockIdExt> {
    if encoded_len < PREFIX_BYTES {
        fail!("Truncated archive predicate prefix");
    }
    let mut reader = reader.take(encoded_len);
    let mut version = [0; 2];
    reader.read_exact(&mut version)?;
    if u16::from_le_bytes(version) != PREDICATE_VERSION {
        fail!("Unsupported archive truncation predicate version");
    }
    let mut block = [0; BlockIdExt::SIZE];
    reader.read_exact(&mut block)?;
    let cutoff = BlockIdExt::deserialize(&block)?;
    if !cutoff.shard().is_masterchain() {
        fail!("Archive truncation cutoff must be a masterchain block");
    }
    let mut count = [0; 8];
    reader.read_exact(&mut count)?;
    let count = u64::from_le_bytes(count);
    if predicate_len(count)? != encoded_len {
        fail!("Archive truncation predicate framing mismatch");
    }
    for _ in 0..count {
        reader.read_exact(&mut block)?;
        visit(BlockIdExt::deserialize(&block)?)?;
    }
    Ok(cutoff)
}

#[cfg(test)]
#[path = "../tests/test_truncation_selection.rs"]
mod tests;
