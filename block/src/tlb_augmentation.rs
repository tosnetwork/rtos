// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Handwritten augmentation checks run after all typed children have passed
//! their structural checks under the shared visit budget.
use super::*;
use crate::{
    Augmentable, Augmentation, CommonMsgInfo, DepthBalanceInfo, Deserializable, Result,
    Serializable, ShardAccount,
};

#[path = "tlb_currency_merge.rs"]
mod currency_merge;

#[derive(Clone, Copy, Debug)]
pub(crate) enum AugKind {
    Accounts,
    OutQueue,
}

impl AugKind {
    fn types(self) -> (TlbType, TlbType) {
        match self {
            Self::Accounts => (TlbType::ShardAccount, TlbType::DepthBalance),
            Self::OutQueue => (TlbType::EnqueuedMsg, TlbType::Bits(64)),
        }
    }
}

fn encoded_slice(value: &impl Serializable) -> Result<SliceData> {
    // Currency augmentations may reference an extra-currency dictionary.
    // write_to_bitstring deliberately rejects references.
    SliceData::load_builder(value.write_to_new_cell()?)
}

fn extra_prefix(mut slice: SliceData, kind: AugKind) -> Result<SliceData> {
    let before = slice.clone();
    match kind {
        AugKind::Accounts => {
            DepthBalanceInfo::construct_from(&mut slice)?;
        }
        AugKind::OutQueue => {
            slice.get_next_int(64)?;
        }
    }
    let mut extra = before.clone();
    extra.shrink(
        ..before.remaining_bits() - slice.remaining_bits(),
        ..before.remaining_references() - slice.remaining_references(),
    );
    Ok(extra)
}

fn node_extra(cell: Cell, n: usize, kind: AugKind) -> Result<SliceData> {
    let mut slice = SliceData::load_cell(cell)?;
    let label =
        hm_label(&mut slice, n).ok_or_else(|| crate::error!("invalid augmentation label"))?;
    if label != n {
        slice.checked_drain_reference()?;
        slice.checked_drain_reference()?;
    }
    extra_prefix(slice, kind)
}

impl Walker {
    pub(crate) fn handwritten_aug_hashmap_e(
        &mut self,
        slice: &mut SliceData,
        n: usize,
        kind: AugKind,
    ) -> bool {
        let Some(present) = bool_bit(slice) else {
            return false;
        };
        let expected = if present {
            let Ok(root) = slice.reference(0) else {
                return false;
            };
            if !self.push_ref(slice, Node::HandwrittenAugHashmap(n, kind)) {
                return false;
            }
            node_extra(root, n, kind)
        } else {
            match kind {
                AugKind::Accounts => encoded_slice(&DepthBalanceInfo::default()),
                AugKind::OutQueue => encoded_slice(&0u64),
            }
        };
        let Ok(actual) = extra_prefix(slice.clone(), kind) else {
            return false;
        };
        self.typed(kind.types().1, TlbProfile::Handwritten, slice)
            && expected.is_ok_and(|expected| expected == actual)
    }

    pub(crate) fn handwritten_aug_hashmap(
        &mut self,
        slice: &mut SliceData,
        n: usize,
        kind: AugKind,
    ) -> bool {
        let Some(cell) = slice.cell_opt().cloned() else {
            return false;
        };
        let Some(label) = hm_label(slice, n) else {
            return false;
        };
        let Some(rest) = n.checked_sub(label) else {
            return false;
        };
        // LIFO: all references pushed below are checked before this task.
        // This task is not a new cell visit and must not consume budget.
        self.pending.push((cell, Node::CheckAugmentation(n, kind)));
        let (value, extra) = kind.types();
        if rest == 0 {
            self.typed(extra, TlbProfile::Handwritten, slice)
                && self.typed(value, TlbProfile::Handwritten, slice)
        } else {
            self.push_ref(slice, Node::HandwrittenAugHashmap(rest - 1, kind))
                && self.push_ref(slice, Node::HandwrittenAugHashmap(rest - 1, kind))
                && self.typed(extra, TlbProfile::Handwritten, slice)
        }
    }
}

pub(crate) fn check_augmented_cell(cell: Cell, n: usize, kind: AugKind) -> Result<bool> {
    let mut slice = SliceData::load_cell(cell.clone())?;
    let label =
        hm_label(&mut slice, n).ok_or_else(|| crate::error!("invalid augmentation label"))?;
    let rest = n.checked_sub(label).ok_or_else(|| crate::error!("invalid augmentation depth"))?;
    let expected = if rest == 0 {
        let actual = extra_prefix(slice.clone(), kind)?;
        slice.move_by(actual.remaining_bits())?;
        for _ in 0..actual.remaining_references() {
            slice.checked_drain_reference()?;
        }
        match kind {
            AugKind::Accounts => {
                let shard = ShardAccount::construct_from(&mut slice)?;
                let account = shard.read_account()?;
                if account.get_addr().is_none() {
                    return Ok(false);
                }
                encoded_slice(&account.aug()?)?
            }
            AugKind::OutQueue => encoded_slice(&envelope_emitted_lt(slice.reference(0)?)?)?,
        }
    } else {
        let left = node_extra(slice.checked_drain_reference()?, rest - 1, kind)?;
        let right = node_extra(slice.checked_drain_reference()?, rest - 1, kind)?;
        match kind {
            AugKind::Accounts => {
                let mut value = DepthBalanceInfo::construct_from(&mut left.clone())?;
                let mut rhs = DepthBalanceInfo::construct_from(&mut right.clone())?;
                let mut left_balance = value.balance().clone();
                let mut right_balance = rhs.balance().clone();
                let left_other = std::mem::take(&mut left_balance.other);
                let right_other = std::mem::take(&mut right_balance.other);
                value.set_balance(left_balance);
                rhs.set_balance(right_balance);
                if !value.calc(&rhs)? {
                    return Ok(false);
                }
                let root = currency_merge::combine(
                    left_other.root().cloned(),
                    right_other.root().cloned(),
                )?;
                let mut balance = value.balance().clone();
                balance.other = crate::ExtraCurrencyCollection::with_hashmap(root);
                value.set_balance(balance);
                encoded_slice(&value)?
            }
            AugKind::OutQueue => {
                encoded_slice(&left.clone().get_next_int(64)?.min(right.clone().get_next_int(64)?))?
            }
        }
    };
    // Re-extract the original extra, not the value remainder used above.
    let actual = node_extra(cell, n, kind)?;
    Ok(actual == expected)
}

fn envelope_emitted_lt(cell: Cell) -> Result<u64> {
    let mut slice = SliceData::load_cell(cell)?;
    let tag = slice.get_next_int(4)?;
    if !intermediate_address(&mut slice)
        || !intermediate_address(&mut slice)
        || !var(&mut slice, 16, TlbProfile::Generated, false)
    {
        crate::fail!("invalid envelope header");
    }
    let message = slice.checked_drain_reference()?;
    if tag == 5 && slice.get_next_bit()? {
        return slice.get_next_int(64);
    }
    let mut message = SliceData::load_cell(message)?;
    match CommonMsgInfo::construct_from(&mut message)? {
        CommonMsgInfo::IntMsgInfo(header) => Ok(header.created_lt),
        CommonMsgInfo::ExtOutMsgInfo(header) => Ok(header.created_lt),
        _ => crate::fail!("queued message has no created logical time"),
    }
}
