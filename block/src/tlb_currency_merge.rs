// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! CPP's dictionary-combine strategy for augmentation currency sums. Reuse the
//! native label decoder/builders and retain untouched subtrees byte-for-byte.
//! Inputs have already passed the shared structural budget. Key width is 32,
//! so recursive merge depth is at most32, independently of cell DAG depth.
use crate::{
    AddSub, Cell, Deserializable, HashmapE, HashmapType, LabelReader, Result, Serializable,
    SliceData, VarUInteger32,
};

pub(super) fn combine(left: Option<Cell>, right: Option<Cell>) -> Result<Option<Cell>> {
    match (left, right) {
        (None, other) | (other, None) => Ok(other),
        (Some(left), Some(right)) => Ok(Some(combine_cells(left, right, 32)?)),
    }
}

fn combine_cells(left: Cell, right: Cell, n: usize) -> Result<Cell> {
    let mut cursor = SliceData::load_cell(right)?;
    let label = LabelReader::read_label(&mut cursor, n)?;
    let rest = n
        .checked_sub(label.remaining_bits())
        .ok_or_else(|| crate::error!("invalid currency label"))?;
    combine_partial(left, n, cursor, label, rest)
}

fn combine_partial(
    left: Cell,
    n: usize,
    mut cursor2: SliceData,
    label2: SliceData,
    rest2: usize,
) -> Result<Cell> {
    let mut cursor1 = SliceData::load_cell(left)?;
    let label1 = LabelReader::read_label(&mut cursor1, n)?;
    let rest1 = n
        .checked_sub(label1.remaining_bits())
        .ok_or_else(|| crate::error!("invalid currency label"))?;
    match SliceData::common_prefix(&label1, &label2) {
        (_, None, None) if rest1 == 0 => {
            // Equal subtrees must still be combined: equal values are added,
            // not treated as an unchanged dictionary union.
            let mut value = VarUInteger32::construct_from(&mut cursor1)?;
            let rhs = VarUInteger32::construct_from(&mut cursor2)?;
            if !value.add(&rhs)? {
                crate::fail!("currency augmentation overflow");
            }
            let value = value.write_to_bitstring()?;
            HashmapE::make_cell_with_remainder(&label1, n, &value)?.into_cell()
        }
        (_, None, None) => {
            let child =
                rest1.checked_sub(1).ok_or_else(|| crate::error!("invalid currency fork"))?;
            let left = combine_cells(
                cursor1.checked_drain_reference()?,
                cursor2.checked_drain_reference()?,
                child,
            )?;
            let right = combine_cells(
                cursor1.checked_drain_reference()?,
                cursor2.checked_drain_reference()?,
                child,
            )?;
            HashmapE::make_fork(&label1, n, left, right, false)?.0.into_cell()
        }
        (prefix, Some(mut rem1), Some(mut rem2)) => {
            let branch = rem1.get_next_bit_int()?;
            rem2.get_next_bit_int()?;
            let prefix = prefix.unwrap_or_default();
            let child = n
                .checked_sub(prefix.remaining_bits() + 1)
                .ok_or_else(|| crate::error!("invalid currency fork"))?;
            let left = HashmapE::make_cell_with_remainder(&rem1, child, &cursor1)?.into_cell()?;
            let right = HashmapE::make_cell_with_remainder(&rem2, child, &cursor2)?.into_cell()?;
            HashmapE::make_fork(&prefix, n, left, right, branch != 0)?.0.into_cell()
        }
        (_, Some(mut rem1), None) => {
            let child =
                rest2.checked_sub(1).ok_or_else(|| crate::error!("invalid currency fork"))?;
            let branch = rem1.get_next_bit_int()?;
            let next = combine_partial(cursor2.reference(branch)?, child, cursor1, rem1, rest1)?;
            let other = cursor2.reference(1 - branch)?;
            HashmapE::make_fork(&label2, n, next, other, branch != 0)?.0.into_cell()
        }
        (_, None, Some(mut rem2)) => {
            let child =
                rest1.checked_sub(1).ok_or_else(|| crate::error!("invalid currency fork"))?;
            let branch = rem2.get_next_bit_int()?;
            let next = combine_partial(cursor1.reference(branch)?, child, cursor2, rem2, rest2)?;
            let other = cursor1.reference(1 - branch)?;
            HashmapE::make_fork(&label1, n, next, other, branch != 0)?.0.into_cell()
        }
    }
}
