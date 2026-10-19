/*
 * Copyright (C) 2019-2023 EverX. All Rights Reserved.
 * Modifications Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This file has been modified from its original version.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use super::{
    hm_label, BuilderData, Cell, HashmapRemover, HashmapType, IBitstring, Leaf, SliceData, ADD,
    REPLACE,
};
use crate::{fail, ExceptionCode, GasConsumer, LabelReader, Mask, Result};
use std::fmt;

#[derive(Clone, Debug)]
pub struct PfxHashmapE {
    bit_len: usize,
    data: Option<Cell>,
}

impl fmt::Display for PfxHashmapE {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.data() {
            Some(cell) => write!(f, "PfxHashmap: {}", cell),
            None => write!(f, "Empty PfxHashmap"),
        }
    }
}

impl PfxHashmapE {
    /// constructs with bit_len
    pub const fn with_bit_len(bit_len: usize) -> Self {
        Self::with_hashmap(bit_len, None)
    }
    /// construct with bit_len and root representing Hashmap
    pub const fn with_hashmap(bit_len: usize, data: Option<Cell>) -> Self {
        Self { bit_len, data }
    }
    /// gets value from hahsmap
    pub fn get(&self, key: SliceData) -> Leaf {
        self.hashmap_get(key, &mut 0)
    }
    pub fn get_with_gas(&self, key: SliceData, gas_consumer: &mut dyn GasConsumer) -> Leaf {
        self.hashmap_get(key, gas_consumer)
    }
    /// sets value as SliceData
    pub fn set(&mut self, key: SliceData, value: &SliceData) -> Leaf {
        self.hashmap_set_with_mode(key, &value.as_builder()?, &mut 0, ADD | REPLACE)
    }
    pub fn set_builder(&mut self, key: SliceData, value: &BuilderData) -> Leaf {
        self.hashmap_set_with_mode(key, value, &mut 0, ADD | REPLACE)
    }
    pub fn set_with_gas(
        &mut self,
        key: SliceData,
        value: &SliceData,
        gas_consumer: &mut dyn GasConsumer,
    ) -> Leaf {
        self.hashmap_set_with_mode(key, &value.as_builder()?, gas_consumer, ADD | REPLACE)
    }
    pub fn set_builder_with_gas(
        &mut self,
        key: SliceData,
        value: &BuilderData,
        gas_consumer: &mut dyn GasConsumer,
    ) -> Leaf {
        self.hashmap_set_with_mode(key, value, gas_consumer, ADD | REPLACE)
    }
    pub fn replace_with_gas(
        &mut self,
        key: SliceData,
        value: &SliceData,
        gas_consumer: &mut dyn GasConsumer,
    ) -> Leaf {
        self.hashmap_set_with_mode(key, &value.as_builder()?, gas_consumer, REPLACE)
    }
    pub fn replace_builder_with_gas(
        &mut self,
        key: SliceData,
        value: &BuilderData,
        gas_consumer: &mut dyn GasConsumer,
    ) -> Leaf {
        self.hashmap_set_with_mode(key, value, gas_consumer, REPLACE)
    }
    /// sets value as reference in empty SliceData
    pub fn setref(&mut self, key: SliceData, value: Cell) -> Leaf {
        self.hashmap_setref_with_mode(key, value, &mut 0, ADD | REPLACE)
    }
    pub fn setref_with_gas(
        &mut self,
        key: SliceData,
        value: Cell,
        gas_consumer: &mut dyn GasConsumer,
    ) -> Leaf {
        self.hashmap_setref_with_mode(key, value, gas_consumer, ADD | REPLACE)
    }
    pub fn replaceref_with_gas(
        &mut self,
        key: SliceData,
        value: Cell,
        gas_consumer: &mut dyn GasConsumer,
    ) -> Leaf {
        self.hashmap_setref_with_mode(key, value, gas_consumer, REPLACE)
    }
    /// removes item
    pub fn remove(&mut self, key: SliceData) -> Leaf {
        self.hashmap_remove(key, &mut 0)
    }
    pub fn remove_with_gas(&mut self, key: SliceData, gas_consumer: &mut dyn GasConsumer) -> Leaf {
        self.hashmap_remove(key, gas_consumer)
    }
    /// true if key is prefix of any item in PfxHashmap
    pub fn is_prefix(&self, mut key: SliceData) -> Result<bool> {
        let mut bit_len = self.bit_len;
        let mut cursor = match self.data() {
            Some(root) if !key.is_empty_bitstring() => SliceData::load_cell_ref(root)?,
            _ => return Ok(false),
        };
        let mut label = LabelReader::read_label(&mut cursor, bit_len)?;
        loop {
            match SliceData::common_prefix(&label, &key) {
                (_, None, None) => (),                         // label == key
                (_, None, Some(remainder)) => key = remainder, // usual case
                (_, _, None) => return Ok(true),               // key is prefix
                (_, Some(_), Some(_)) => return Ok(false),
            }
            if Self::is_leaf(&mut cursor) {
                return Ok(false);
            }
            let next_index = key.get_next_bit_int()?;
            if next_index >= cursor.remaining_references() || bit_len < label.remaining_bits() + 1 {
                debug_assert!(false);
                return Ok(false); // problem
            }
            cursor = SliceData::load_cell(cursor.reference(next_index)?)?;
            bit_len -= label.remaining_bits() + 1;
            label = LabelReader::read_label(&mut cursor, bit_len)?;
        }
    }
    /// finds item in PfxHashmap which key is prefix of key and returns value with path and suffix
    pub fn get_prefix_leaf_with_gas(
        &self,
        mut key: SliceData,
        gas_consumer: &mut dyn GasConsumer,
    ) -> Result<(SliceData, Option<SliceData>, SliceData)> {
        let mut bit_len = self.bit_len;
        let mut cursor = match self.data().cloned() {
            Some(root) if !key.is_empty_bitstring() => gas_consumer.load_cell(root)?,
            _ => return Ok((SliceData::default(), None, key)),
        };
        let mut path = BuilderData::default();
        let mut label = LabelReader::read_label(&mut cursor, bit_len)?;
        loop {
            path.append_bytestring(&label)?;
            match SliceData::common_prefix(&label, &key) {
                (_, None, None) => {
                    // label == key
                    key.clear_all_bits();
                }
                (_, None, Some(remainder)) => key = remainder, // usual case
                (_, _, None) => {
                    return Ok((SliceData::load_bitstring(path)?, None, SliceData::default()))
                } // key is prefix
                (_, Some(_), Some(remainder)) => {
                    return Ok((SliceData::load_bitstring(path)?, None, remainder))
                }
            }
            if Self::is_leaf(&mut cursor) {
                return Ok((SliceData::load_bitstring(path)?, Some(cursor), key));
            } else if key.is_empty_bitstring() {
                return Ok((SliceData::load_bitstring(path)?, None, key));
            }
            let next_index = key.get_next_bit_int()?;
            if next_index >= cursor.remaining_references() || bit_len < label.remaining_bits() + 1 {
                debug_assert!(false);
                return Ok((SliceData::load_bitstring(path)?, None, key)); // problem
            }
            path.append_bit_bool(next_index == 1)?;
            cursor = gas_consumer.load_cell(cursor.reference(next_index)?)?;
            bit_len -= label.remaining_bits() + 1;
            label = LabelReader::read_label(&mut cursor, bit_len)?;
        }
    }
    #[allow(dead_code)]
    pub fn get_leaf_by_prefix(
        &self,
        mut key: SliceData,
    ) -> Result<(SliceData, Option<SliceData>, SliceData)> {
        let mut bit_len = self.bit_len;
        let mut cursor = match self.data() {
            Some(root) if !key.is_empty_bitstring() => SliceData::load_cell_ref(root)?,
            _ => return Ok((SliceData::default(), None, key)),
        };
        let mut path = BuilderData::default();
        let mut label = LabelReader::read_label(&mut cursor, bit_len)?;
        loop {
            path.checked_append_references_and_data(&label)?;
            match SliceData::common_prefix(&label, &key) {
                (_, None, None) => {
                    // label == key
                    key.clear_all_bits();
                }
                (_, None, Some(remainder)) => key = remainder, // usual case
                (_, _, None) => break,                         // key is prefix
                (_, Some(_), Some(remainder)) => {
                    return Ok((SliceData::load_bitstring(path)?, None, remainder))
                }
            }
            if Self::is_leaf(&mut cursor) {
                return Ok((SliceData::load_bitstring(path)?, Some(cursor), key));
            }
            let next_index = key.get_next_bit_int()?;
            if next_index >= cursor.remaining_references() || bit_len < label.remaining_bits() + 1 {
                debug_assert!(false);
                return Ok((SliceData::load_bitstring(path)?, None, key)); // problem
            }
            path.append_bit_bool(next_index == 1)?;
            cursor = SliceData::load_cell(cursor.reference(next_index)?)?;
            bit_len -= label.remaining_bits() + 1;
            label = LabelReader::read_label(&mut cursor, bit_len)?;
        }
        key = SliceData::default();
        loop {
            if Self::is_leaf(&mut cursor) {
                return Ok((SliceData::load_bitstring(path)?, Some(cursor), key));
            }
            let next_index = 0;
            if next_index >= cursor.remaining_references() {
                return Ok((SliceData::load_bitstring(path)?, None, key)); // problem
            }
            path.append_bit_bool(next_index == 1)?;
            cursor = SliceData::load_cell(cursor.reference(next_index)?)?;
            if bit_len < label.remaining_bits() + 1 {
                return Ok((SliceData::load_bitstring(path)?, None, key)); // problem
            }
            bit_len -= label.remaining_bits() + 1;
            label = LabelReader::read_label(&mut cursor, bit_len)?;
            path.checked_append_references_and_data(&label)?;
        }
    }
}

/// Number of leading bits `a` and `b` have in common.
fn common_prefix_len(a: &SliceData, b: &SliceData) -> Result<usize> {
    let len = a.remaining_bits().min(b.remaining_bits());
    for i in 0..len {
        if a.get_bit(i)? != b.get_bit(i)? {
            return Ok(i);
        }
    }
    Ok(len)
}

/// `len` bits of `key` starting at `from`.
fn sub_key(key: &SliceData, from: usize, len: usize) -> Result<SliceData> {
    let mut sub = key.clone();
    sub.move_by(from)?;
    if sub.remaining_bits() < len {
        fail!(ExceptionCode::CellUnderflow)
    }
    sub.shrink_data(..len);
    sub.shrink_references(..0)?;
    Ok(sub)
}

/// The bits of `key` from `from` to its end.
fn key_tail(key: &SliceData, from: usize) -> Result<SliceData> {
    let len = key.remaining_bits().checked_sub(from).ok_or(ExceptionCode::CellUnderflow)?;
    sub_key(key, from, len)
}

/// Reads the node constructor after a label: `false` for a leaf, `true` for a
/// fork, which must hold no further bits and exactly two references.
fn read_constructor(cursor: &mut SliceData) -> Result<bool> {
    if cursor.remaining_bits() == 0 {
        fail!(ExceptionCode::DictionaryError, "no node constructor in a prefix code dictionary")
    }
    if !cursor.get_next_bit()? {
        return Ok(false);
    }
    if cursor.remaining_bits() != 0 || cursor.remaining_references() != 2 {
        fail!(ExceptionCode::DictionaryError, "invalid fork node in a prefix code dictionary")
    }
    Ok(true)
}

fn pfx_leaf(
    key: &SliceData,
    n: usize,
    value: &BuilderData,
    gas_consumer: &mut dyn GasConsumer,
) -> Result<Cell> {
    let mut builder = hm_label(key, n)?;
    builder.append_bit_zero()?;
    builder.append_builder(value)?;
    gas_consumer.finalize_cell(builder)
}

fn pfx_fork(
    label: &SliceData,
    n: usize,
    left: Cell,
    right: Cell,
    gas_consumer: &mut dyn GasConsumer,
) -> Result<Cell> {
    let mut builder = hm_label(label, n)?;
    builder.append_bit_one()?;
    builder.checked_append_reference(left)?;
    builder.checked_append_reference(right)?;
    gas_consumer.finalize_cell(builder)
}

/// Sets `key` (of at most `n` bits) in the subtree `cell`, following the
/// reference prefix-code dictionary rules; `None` when the dictionary is
/// unchanged (a fork or another key in the way, or the mode forbids it).
fn pfx_set(
    cell: Option<Cell>,
    key: &SliceData,
    n: usize,
    value: &BuilderData,
    mode: u8,
    gas_consumer: &mut dyn GasConsumer,
) -> Result<Option<Cell>> {
    let m = key.remaining_bits();
    if m > n {
        return Ok(None);
    }
    let Some(cell) = cell else {
        if !mode.bit(ADD) {
            return Ok(None);
        }
        return Ok(Some(pfx_leaf(key, n, value, gas_consumer)?));
    };
    let mut cursor = gas_consumer.load_cell(cell)?;
    let label = LabelReader::read_label(&mut cursor, n)?;
    let label_len = label.remaining_bits();
    let l = common_prefix_len(&label, key)?;
    if l < label_len {
        if l == m || !mode.bit(ADD) {
            return Ok(None);
        }
        // split the edge: a new leaf for the key and the lower part of the old edge
        let q = l.checked_add(1).ok_or(ExceptionCode::CellUnderflow)?;
        let rest_n = n.checked_sub(q).ok_or(ExceptionCode::CellUnderflow)?;
        let new_leaf = pfx_leaf(&key_tail(key, q)?, rest_n, value, gas_consumer)?;
        let mut builder = hm_label(&key_tail(&label, q)?, rest_n)?;
        builder.checked_append_references_and_data(&cursor)?;
        let old_edge = gas_consumer.finalize_cell(builder)?;
        let (left, right) =
            if key.get_bit(l)? { (old_edge, new_leaf) } else { (new_leaf, old_edge) };
        return Ok(Some(pfx_fork(&sub_key(key, 0, l)?, n, left, right, gas_consumer)?));
    }
    if !read_constructor(&mut cursor)? {
        if l != m || !mode.bit(REPLACE) {
            return Ok(None);
        }
        return Ok(Some(pfx_leaf(key, n, value, gas_consumer)?));
    }
    if m == l {
        return Ok(None);
    }
    let bit = usize::from(key.get_bit(l)?);
    let next = l.checked_add(1).ok_or(ExceptionCode::CellUnderflow)?;
    let child_n = n.checked_sub(next).ok_or(ExceptionCode::CellUnderflow)?;
    let mut children = [cursor.reference(0)?, cursor.reference(1)?];
    let child = children[bit].clone();
    let Some(new_child) =
        pfx_set(Some(child), &key_tail(key, next)?, child_n, value, mode, gas_consumer)?
    else {
        return Ok(None);
    };
    children[bit] = new_child;
    let [left, right] = children;
    Ok(Some(pfx_fork(&sub_key(key, 0, l)?, n, left, right, gas_consumer)?))
}

/// The old value and the new subtree after a deletion.
type Deleted = (SliceData, Option<Cell>);

/// Deletes `key` from the subtree `cell`, following the reference rules;
/// `None` when the key is absent.
fn pfx_delete(
    cell: Option<Cell>,
    key: &SliceData,
    n: usize,
    gas_consumer: &mut dyn GasConsumer,
) -> Result<Option<Deleted>> {
    let Some(cell) = cell else {
        return Ok(None);
    };
    let m = key.remaining_bits();
    let mut cursor = gas_consumer.load_cell(cell)?;
    let label = LabelReader::read_label(&mut cursor, n)?;
    let label_len = label.remaining_bits();
    let l = common_prefix_len(&label, key)?;
    if l < label_len {
        return Ok(None);
    }
    if !read_constructor(&mut cursor)? {
        if l < m {
            return Ok(None);
        }
        return Ok(Some((cursor, None)));
    }
    if l == m {
        return Ok(None);
    }
    let bit = usize::from(key.get_bit(l)?);
    let next = l.checked_add(1).ok_or(ExceptionCode::CellUnderflow)?;
    let child_n = n.checked_sub(next).ok_or(ExceptionCode::CellUnderflow)?;
    let mut children = [Some(cursor.reference(0)?), Some(cursor.reference(1)?)];
    let Some((old, new_child)) =
        pfx_delete(children[bit].take(), &key_tail(key, next)?, child_n, gas_consumer)?
    else {
        return Ok(None);
    };
    children[bit] = new_child;
    if let [Some(left), Some(right)] = children {
        let fork = pfx_fork(&sub_key(key, 0, l)?, n, left, right, gas_consumer)?;
        return Ok(Some((old, Some(fork))));
    }
    // merge this edge with the edge of the remaining child
    let other = children[1 - bit].take().ok_or(ExceptionCode::FatalError)?;
    let mut rest = gas_consumer.load_cell(other)?;
    let rest_label = LabelReader::read_label(&mut rest, child_n)?;
    let mut merged = sub_key(key, 0, l)?.as_builder()?;
    merged.append_bit_bool(bit == 0)?;
    merged.append_bytestring(&rest_label)?;
    let mut builder = hm_label(&SliceData::load_bitstring(merged)?, n)?;
    builder.checked_append_references_and_data(&rest)?;
    Ok(Some((old, Some(gas_consumer.finalize_cell(builder)?))))
}

impl PfxHashmapE {
    /// The longest stored key that is a prefix of `key`, looked up as the
    /// reference prefix-code dictionary does: its value and its length.
    pub fn lookup_prefix_with_gas(
        &self,
        key: &SliceData,
        gas_consumer: &mut dyn GasConsumer,
    ) -> Result<Option<(SliceData, usize)>> {
        let Some(mut cell) = self.data().cloned() else {
            return Ok(None);
        };
        let mut n = self.bit_len;
        let mut pos = 0;
        loop {
            let mut cursor = gas_consumer.load_cell(cell)?;
            let label = LabelReader::read_label(&mut cursor, n)?;
            let label_len = label.remaining_bits();
            if common_prefix_len(&label, &key_tail(key, pos)?)? < label_len {
                return Ok(None);
            }
            n = n.checked_sub(label_len).ok_or(ExceptionCode::CellUnderflow)?;
            pos = pos.checked_add(label_len).ok_or(ExceptionCode::CellUnderflow)?;
            if cursor.remaining_bits() == 0 {
                fail!(
                    ExceptionCode::DictionaryError,
                    "no node constructor in a prefix code dictionary"
                )
            }
            if !cursor.get_next_bit()? {
                return Ok(Some((cursor, pos)));
            }
            if n == 0 {
                fail!(
                    ExceptionCode::DictionaryError,
                    "a fork node in a prefix code dictionary with zero remaining key length"
                )
            }
            if cursor.remaining_bits() != 0 || cursor.remaining_references() != 2 {
                fail!(
                    ExceptionCode::DictionaryError,
                    "invalid fork node in a prefix code dictionary"
                )
            }
            if pos == key.remaining_bits() {
                return Ok(None);
            }
            let bit = usize::from(key.get_bit(pos)?);
            pos = pos.checked_add(1).ok_or(ExceptionCode::CellUnderflow)?;
            n = n.checked_sub(1).ok_or(ExceptionCode::CellUnderflow)?;
            cell = cursor.reference(bit)?;
        }
    }

    /// Sets (`ADD | REPLACE`), replaces (`REPLACE`) or adds (`ADD`) a key as
    /// the reference does; `false` when the dictionary is unchanged.
    pub fn set_with_mode_and_gas(
        &mut self,
        key: &SliceData,
        value: &BuilderData,
        mode: u8,
        gas_consumer: &mut dyn GasConsumer,
    ) -> Result<bool> {
        match pfx_set(self.data.clone(), key, self.bit_len, value, mode, gas_consumer)? {
            Some(root) => {
                self.data = Some(root);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Deletes a key as the reference does; `false` when it is absent.
    pub fn lookup_delete_with_gas(
        &mut self,
        key: &SliceData,
        gas_consumer: &mut dyn GasConsumer,
    ) -> Result<bool> {
        if key.remaining_bits() > self.bit_len {
            return Ok(false);
        }
        match pfx_delete(self.data.clone(), key, self.bit_len, gas_consumer)? {
            Some((_, root)) => {
                self.data = root;
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

// phm_edge#_ {n:#} {X:Type} {l:#} {m:#} label:(HmLabel ~l n)
// {n = (~m) + l} node:(PfxHashmapNode m X) = PfxHashmap n X;
// phmn_leaf$0 {n:#} {X:Type} value:X = PfxHashmapNode n X;
// phmn_fork$1 {n:#} {X:Type} left:^(PfxHashmap n X)
// right:^(PfxHashmap n X) = PfxHashmapNode (n+1) X;
impl HashmapType for PfxHashmapE {
    fn check_key(bit_len: usize, key: &SliceData) -> bool {
        bit_len >= key.remaining_bits()
    }
    /// Prefix dictionary nodes start with a leaf/fork constructor bit after the
    /// label; their shape is checked where that bit is read.
    fn check_node(_remainder: &SliceData, _label_len: usize, _bit_len: usize) -> Result<()> {
        Ok(())
    }
    fn make_cell_with_label(key: &SliceData, max: usize) -> Result<BuilderData> {
        let mut builder = hm_label(key, max)?;
        builder.append_bit_one()?;
        Ok(builder)
    }
    fn make_cell_with_label_and_data(
        key: &SliceData,
        max: usize,
        is_leaf: bool,
        data: &SliceData,
    ) -> Result<BuilderData> {
        let mut builder = hm_label(key, max)?;
        builder.append_bit_bool(!is_leaf)?;
        builder.checked_append_references_and_data(data)?;
        Ok(builder)
    }
    fn make_cell_with_label_and_builder(
        key: &SliceData,
        max: usize,
        is_leaf: bool,
        data: &BuilderData,
    ) -> Result<BuilderData> {
        let mut builder = hm_label(key, max)?;
        builder.append_bit_bool(!is_leaf)?;
        builder.append_builder(data)?;
        Ok(builder)
    }
    fn make_fork(
        key: &SliceData,
        bit_len: usize,
        mut left: Cell,
        mut right: Cell,
        swap: bool,
    ) -> Result<(BuilderData, BuilderData)> {
        let mut builder = hm_label(key, bit_len)?;
        let mut remainder = BuilderData::new();
        remainder.append_bit_one()?;
        if swap {
            std::mem::swap(&mut left, &mut right);
        }
        remainder.checked_append_reference(left)?;
        remainder.checked_append_reference(right)?;
        builder.append_builder(&remainder)?;
        Ok((builder, remainder))
    }
    fn make_leaf(key: &SliceData, bit_len: usize, value: &SliceData) -> Result<BuilderData> {
        let mut builder = hm_label(key, bit_len)?;
        builder.checked_append_references_and_data(value)?;
        builder.append_bit_zero()?;
        Ok(builder)
    }
    fn is_fork(slice: &mut SliceData) -> Result<bool> {
        Ok(slice.get_next_bit()? && slice.remaining_references() > 1)
    }
    fn is_leaf(slice: &mut SliceData) -> bool {
        matches!(slice.get_next_bit_opt(), Some(0))
    }
    fn inner(self) -> Option<Cell> {
        self.data
    }
    fn data(&self) -> Option<&Cell> {
        self.data.as_ref()
    }
    fn data_mut(&mut self) -> &mut Option<Cell> {
        &mut self.data
    }
    fn bit_len(&self) -> usize {
        self.bit_len
    }
}

impl HashmapRemover for PfxHashmapE {}

#[cfg(test)]
#[path = "tests/test_pfxhashmap.rs"]
mod tests;
