// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded evidence trace owned by one fresh authentication, never a manifest capability.
use crate::{block_proof::BlockProofStuff, history_read_budget::HistoryReadBudget};
use rtos_block::{
    error, fail,
    merkle_apply_budget::{require_materialized, BudgetMap, BudgetStack, MerkleApplyBudget},
    BlockIdExt, Cell, Result, UInt256,
};
use serde_derive::{Deserialize, Serialize};
use storage::bounded_cell::CellReadBudget;

pub(crate) const MAX_DEPENDENCIES: usize = 260;
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Dependency {
    pub kind: String,
    pub id: String,
    pub digest: String,
    pub bytes: u64,
    pub root: Option<String>,
}
impl Dependency {
    pub(crate) fn validate(&self) -> Result<BlockIdExt> {
        let id: BlockIdExt = self.id.parse()?;
        if !id.shard().is_masterchain() || self.digest.len() != 64 || self.bytes > 128 << 20 {
            fail!("Invalid repair dependency identity/size");
        }
        let _: UInt256 = self.digest.parse()?;
        match self.kind.as_str() {
            "state" | "capsule-state" => {
                let _: UInt256 =
                    self.root.as_ref().ok_or_else(|| error!("Missing dependency root"))?.parse()?;
            }
            "block" | "proof" | "proof-link" if self.root.is_none() => (),
            _ => fail!("Unsupported repair dependency kind"),
        }
        Ok(id)
    }
}
#[derive(Default)]
pub(crate) struct Trace {
    dependencies: Vec<Dependency>,
    proofs: Vec<BlockProofStuff>,
}
impl Trace {
    fn insert(&mut self, entry: Dependency, budget: &HistoryReadBudget) -> Result<()> {
        entry.validate()?;
        for previous in &self.dependencies {
            budget.step()?;
            if previous.kind == entry.kind && previous.id == entry.id {
                if previous != &entry {
                    fail!("Conflicting authenticated repair dependency");
                }
                return Ok(());
            }
        }
        if self.dependencies.len() >= MAX_DEPENDENCIES {
            fail!("Repair dependency count exceeds bound");
        }
        budget.metadata(1024)?;
        self.dependencies.try_reserve_exact(1)?;
        self.dependencies.push(entry);
        Ok(())
    }
    pub(crate) fn proof(
        &mut self,
        proof: &BlockProofStuff,
        budget: &HistoryReadBudget,
    ) -> Result<()> {
        let kind = if proof.is_link() { "proof-link" } else { "proof" };
        self.insert(
            Dependency {
                kind: kind.into(),
                id: proof.id().to_string(),
                digest: format!("{:x}", UInt256::calc_file_hash(proof.data())),
                bytes: proof.data().len() as u64,
                root: None,
            },
            budget,
        )?;
        if !self.proofs.iter().any(|p| p.id() == proof.id() && p.is_link() == proof.is_link()) {
            budget.metadata(std::mem::size_of::<BlockProofStuff>())?;
            self.proofs.try_reserve_exact(1)?;
            self.proofs.push(proof.clone());
        }
        Ok(())
    }
    pub(crate) fn bytes(
        &mut self,
        kind: &str,
        id: &BlockIdExt,
        bytes: &[u8],
        root: Option<&UInt256>,
        budget: &HistoryReadBudget,
    ) -> Result<()> {
        self.insert(
            Dependency {
                kind: kind.into(),
                id: id.to_string(),
                digest: format!("{:x}", UInt256::calc_file_hash(bytes)),
                bytes: bytes.len() as u64,
                root: root.map(|r| format!("{r:x}")),
            },
            budget,
        )
    }
    /// Canonical DFS of actual stored-cell bytes. The digest commits to every
    /// cell once, including references; length is physical cell payload bytes,
    /// not an alternative BOC serialization or allocator/RSS measurement.
    pub(crate) fn state(
        &mut self,
        id: &BlockIdExt,
        root: &Cell,
        budget: &HistoryReadBudget,
    ) -> Result<()> {
        if let Some(old) =
            self.dependencies.iter().find(|d| d.kind == "state" && d.id == id.to_string())
        {
            if old.root.as_deref() != Some(format!("{:x}", root.repr_hash()).as_str()) {
                fail!("Conflicting repair state root");
            }
            return Ok(());
        }
        let mut seen = BudgetMap::new(budget.limits().cells);
        let mut stack = BudgetStack::new(usize::from(budget.limits().depth) * 4 + 1);
        stack.push(root.clone(), budget)?;
        let mut digest = UInt256::default();
        let mut bytes = 0u64;
        while let Some(cell) = stack.pop() {
            budget.step()?;
            require_materialized(&cell)?;
            if seen.get(cell.repr_hash(), budget)?.is_some() {
                continue;
            }
            seen.insert(cell.repr_hash().clone(), (), budget)?;
            budget.workspace(1024)?;
            let raw = storage::types::serialize_stored_cell(&cell)?;
            bytes = bytes
                .checked_add(raw.len() as u64)
                .ok_or_else(|| error!("State length overflow"))?;
            let mut piece = [0u8; 96];
            piece[..32].copy_from_slice(digest.as_slice());
            piece[32..64].copy_from_slice(cell.repr_hash().as_slice());
            piece[64..].copy_from_slice(UInt256::calc_file_hash(&raw).as_slice());
            digest = UInt256::calc_file_hash(&piece);
            for i in (0..cell.references_count()).rev() {
                stack.push(cell.reference(i)?, budget)?;
            }
        }
        self.insert(
            Dependency {
                kind: "state".into(),
                id: id.to_string(),
                digest: format!("{digest:x}"),
                bytes,
                root: Some(format!("{:x}", root.repr_hash())),
            },
            budget,
        )
    }
    pub(crate) fn take(&mut self) -> (Vec<Dependency>, Vec<BlockProofStuff>) {
        self.dependencies.sort();
        (std::mem::take(&mut self.dependencies), std::mem::take(&mut self.proofs))
    }
}
