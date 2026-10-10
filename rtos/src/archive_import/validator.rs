/*
 * RTOS project modifications (2026-10-10): project and crate naming.
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::{
    block_proof::{BlockProofStuff, BootstrapAuthority},
    shard_state::ShardStateStuff,
};
use rtos_block::{fail, BlockIdExt, BlockInfo, Result};
use std::{future::Future, sync::Arc};

#[derive(Clone)]
pub struct ValidatorState {
    authority: BootstrapAuthority,
}

impl ValidatorState {
    pub fn new(pin: &BlockIdExt, zerostate: Arc<ShardStateStuff>) -> Result<Self> {
        Ok(Self { authority: BootstrapAuthority::from_zerostate(pin, zerostate)? })
    }

    pub(crate) fn current_key_block_proof(&self) -> Option<&BlockProofStuff> {
        self.authority.key_block_proof()
    }

    pub(crate) fn authenticate_mc_proof(
        &self,
        expected: &BlockIdExt,
        proof: &BlockProofStuff,
    ) -> Result<()> {
        self.authority.authenticate_block(expected, proof.clone())?;
        Ok(())
    }

    pub fn validate_mc_proof(
        &mut self,
        expected: &BlockIdExt,
        proof: &BlockProofStuff,
    ) -> Result<BlockInfo> {
        let info = proof.virtualize_block()?.0.read_info()?;
        if info.key_block() {
            self.authority = self.authority.advance_key_block(expected, proof.clone())?;
        } else {
            self.authenticate_mc_proof(expected, proof)?;
        }
        Ok(info)
    }

    /// Reconstruct the governing history at the actual resume boundary. Archive
    /// indexes only locate data; a later key proof never becomes a resume root.
    /// Discovery retains IDs, then reloads and authenticates proofs forwards.
    pub(crate) async fn restore_to<F, Fut>(
        &mut self,
        seqno: u32,
        mut lookup: F,
    ) -> Result<BlockIdExt>
    where
        F: FnMut(u32) -> Fut,
        Fut: Future<Output = Result<BlockProofStuff>>,
    {
        if seqno == self.authority.id().seq_no {
            return Ok(self.authority.id().clone());
        }
        let target = lookup(seqno).await?;
        if target.id().seq_no != seqno || !target.id().shard().is_masterchain_ext() {
            fail!("Archive resume proof has the wrong requested position");
        }
        let mut epoch = target.virtualize_block()?.0.read_info()?.prev_key_block_seqno();
        if epoch >= seqno {
            fail!("Archive resume epoch must precede the target");
        }
        let mut ids = Vec::new();
        while epoch > self.authority.id().seq_no {
            let proof = lookup(epoch).await?;
            if proof.id().seq_no != epoch || !proof.id().shard().is_masterchain_ext() {
                fail!("Archive key index returned the wrong requested position");
            }
            let info = proof.virtualize_block()?.0.read_info()?;
            if !info.key_block() || info.prev_key_block_seqno() >= epoch {
                fail!("Archive governing history is not a descending key-block chain");
            }
            ids.push(proof.id().clone());
            epoch = info.prev_key_block_seqno();
        }
        if epoch != self.authority.id().seq_no {
            fail!("Archive resume predates its authenticated authority");
        }
        let mut staged = self.clone();
        for id in ids.into_iter().rev() {
            let proof = lookup(id.seq_no).await?;
            staged.validate_mc_proof(&id, &proof)?;
        }
        staged.validate_mc_proof(target.id(), &target)?;
        *self = staged;
        Ok(target.id().clone())
    }
}
