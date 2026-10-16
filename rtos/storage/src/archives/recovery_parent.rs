// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Typed parent-map commands for the Ready manifest. Parsing does not authorize
//! replay: the complete manifest, old/new inventories and custody must be checked
//! before any batch is applied. Old CBOR is preserved and compared as raw bytes.
use super::{package_index_db::PackageIndexEntry, recovery_manifest::{ManifestWriter, Record}};
use rtos_block::{error, fail, Result, Sha256};
use std::io::{Read, Write};

const PREFIX: u64 = 24;
pub(crate) const BATCH_LIMIT: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Map { Files = 1, KeyFiles = 2 }
impl Map {
    pub(crate) fn name(self) -> &'static str {
        match self { Self::Files => "files", Self::KeyFiles => "key_files" }
    }
    fn decode(tag: u8) -> Result<Self> {
        match tag { 1 => Ok(Self::Files), 2 => Ok(Self::KeyFiles), _ => fail!("Unknown recovery parent map") }
    }
}

/// Raw U32Key bytes, ordered in the same byte order as the native DB iterator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Key { pub map: Map, pub bytes: [u8; 4] }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Action { Reset = 1, Delete = 2 }

/// Captured once for a selected operation, then emitted verbatim for its
/// boundary rows. Existing old CBOR is never reconstructed from a HashMap.
pub(crate) struct ResetValue(Vec<u8>);
impl ResetValue {
    pub(crate) fn capture() -> Result<Self> {
        Ok(Self(serde_cbor::to_vec(&PackageIndexEntry::new())?))
    }
}

pub(crate) fn write_command<W: Write>(
    writer: &mut ManifestWriter<W>, key: Key, old: &[u8], reset: Option<&ResetValue>,
) -> Result<()> {
    if old.is_empty() { fail!("Missing recovery parent old value"); }
    let old_len = u64::try_from(old.len())?;
    let new = reset.map_or(&[][..], |value| value.0.as_slice());
    let new_len = u64::try_from(new.len())?;
    let length = PREFIX.checked_add(old_len).and_then(|v| v.checked_add(new_len))
        .ok_or_else(|| error!("Recovery parent record length overflow"))?;
    writer.record_with(Record::ParentMutation, length, |out| {
        out.write_all(&1u16.to_le_bytes())?;
        out.write_all(&[key.map as u8, if reset.is_some() { Action::Reset as u8 } else { Action::Delete as u8 }])?;
        out.write_all(&key.bytes)?;
        out.write_all(&old_len.to_le_bytes())?;
        out.write_all(&new_len.to_le_bytes())?;
        out.write_all(old)?;
        out.write_all(new)?;
        Ok(())
    })
}

#[derive(Debug)]
pub(crate) struct Command {
    pub key: Key,
    /// None means delete; Some contains the exact validated manifest bytes.
    pub new: Option<Vec<u8>>,
}
impl Command {
    fn footprint(&self) -> Result<usize> {
        // Bound payload plus Rust command storage and conservative native batch
        // framing. Old native pinned values are separate caller-owned resources.
        std::mem::size_of::<Self>().checked_add(32)
            .and_then(|n| n.checked_add(self.new.as_ref().map_or(0, Vec::capacity)))
            .ok_or_else(|| error!("Recovery parent batch size overflow"))
    }
}

/// The old-value visitor must compare the complete bytes with the selected
/// native row (or the matching original selection record on resumed replay).
/// Its native pin must be accounted for and released before retaining a batch.
pub(crate) fn read_command(
    input: &mut dyn Read, length: u64,
    visit_old: impl FnOnce(Key, Action, u64, &mut dyn Read) -> Result<()>,
) -> Result<Command> {
    if length < PREFIX { fail!("Truncated recovery parent prefix"); }
    let mut input = input.take(length);
    let mut prefix = [0; PREFIX as usize];
    input.read_exact(&mut prefix)?;
    if prefix[..2] != [1, 0] { fail!("Unsupported recovery parent version"); }
    let map = Map::decode(prefix[2])?;
    let action = match prefix[3] {
        1 => Action::Reset, 2 => Action::Delete, _ => fail!("Unknown recovery parent action"),
    };
    let key = Key { map, bytes: prefix[4..8].try_into()? };
    let old_len = u64::from_le_bytes(prefix[8..16].try_into()?);
    let new_len = u64::from_le_bytes(prefix[16..24].try_into()?);
    if old_len == 0 || PREFIX.checked_add(old_len).and_then(|n| n.checked_add(new_len)) != Some(length) {
        fail!("Recovery parent lengths mismatch");
    }
    if (action == Action::Delete && new_len != 0)
        || (action == Action::Reset && new_len == 0)
        || new_len > (BATCH_LIMIT - std::mem::size_of::<Command>() - 32) as u64 {
        fail!("Recovery parent new value exceeds command budget or action");
    }
    let mut old = (&mut input).take(old_len);
    visit_old(key, action, old_len, &mut old)?;
    if old.limit() != 0 { fail!("Recovery parent old value not fully checked"); }
    let new = if action == Action::Reset {
        let mut bytes = vec![0; usize::try_from(new_len)?];
        input.read_exact(&mut bytes)?;
        // Use a bounded schema without a HashMap allocation from CBOR counts.
        // A reset has exactly three known fields and an empty ranges map.
        validate_reset(&bytes)?;
        Some(bytes)
    } else { None };
    Ok(Command { key, new })
}

fn validate_reset(bytes: &[u8]) -> Result<()> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Reset {
        deleted: bool,
        finalized: bool,
        #[serde(deserialize_with = "empty_ranges")]
        blocks_ranges: (),
    }
    fn empty_ranges<'de, D: serde::Deserializer<'de>>(deserializer: D) -> std::result::Result<(), D::Error> {
        struct Empty;
        impl<'de> serde::de::Visitor<'de> for Empty {
            type Value = ();
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an empty archive block-ranges map")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> std::result::Result<(), A::Error> {
                if map.next_key::<serde::de::IgnoredAny>()?.is_some() {
                    return Err(serde::de::Error::custom("nonempty recovery reset ranges"));
                }
                Ok(())
            }
        }
        deserializer.deserialize_map(Empty)
    }
    let reset: Reset = serde_cbor::from_slice(bytes)?;
    let () = reset.blocks_ranges;
    if reset.deleted || reset.finalized { fail!("Recovery boundary value is not reset"); }
    Ok(())
}

/// Canonical complete map inventory. Raw keys and values are hashed without
/// CBOR reserialization. Both maps are covered even when either map is empty.
pub(crate) struct MapInventory {
    last: Option<Key>, count: u64, digest: Sha256,
}
impl MapInventory {
    pub(crate) fn new() -> Self {
        Self { last: None, count: 0, digest: Sha256::new() }
    }
    pub(crate) fn row(&mut self, key: Key, value: &[u8]) -> Result<()> {
        self.begin_row(key, u64::try_from(value.len())?)?;
        self.digest.update(value);
        Ok(())
    }
    fn begin_row(&mut self, key: Key, length: u64) -> Result<()> {
        if self.last.is_some_and(|last| last >= key) { fail!("Unordered archive inventory row"); }
        let count = self.count.checked_add(1).ok_or_else(|| error!("Archive inventory count overflow"))?;
        self.digest.update([key.map as u8]);
        self.digest.update(key.bytes);
        self.digest.update(length.to_le_bytes());
        self.count = count;
        self.last = Some(key);
        Ok(())
    }
    pub(crate) fn finish(self) -> super::recovery_root::Inventory {
        super::recovery_root::Inventory { count: self.count, digest: self.digest.finalize() }
    }
}

/// Caller must hold the operation's closed admission/custody across both map
/// scans. This does not establish a concurrent two-map snapshot by itself.
/// Raw iterator values are borrowed one at a time, never copied into a table.
pub(crate) fn native_inventory(
    db: &rocksdb::DBWithThreadMode<rocksdb::MultiThreaded>,
) -> Result<super::recovery_root::Inventory> {
    let mut inventory = MapInventory::new();
    for map in [Map::Files, Map::KeyFiles] {
        let cf = db.cf_handle(map.name()).ok_or_else(|| error!("Missing recovery parent map {}", map.name()))?;
        let mut rows = db.raw_iterator_cf(&cf);
        rows.seek_to_first();
        while rows.valid() {
            let key = rows.key().ok_or_else(|| error!("Missing native parent key"))?;
            let value = rows.value().ok_or_else(|| error!("Missing native parent value"))?;
            inventory.row(Key { map, bytes: key.try_into()? }, value)?;
            rows.next();
        }
        rows.status()?;
    }
    Ok(inventory.finish())
}

/// Expectations must come from the fully validated, immutable operation
/// selection/Ready records, never from the current (possibly partly replayed)
/// database. This preflight performs no writes and grants no execution custody.
pub(crate) struct ReplayMaps {
    pub operation: [u8; 16],
    pub ready: super::recovery_root::Sidecar,
    pub selection_digest: [u8; 32],
    pub original: super::recovery_root::Inventory,
    pub final_maps: super::recovery_root::Inventory,
}

type NativeDb = rocksdb::DBWithThreadMode<rocksdb::MultiThreaded>;
struct NativeRows<'a> {
    rows: [rocksdb::DBRawIteratorWithThreadMode<'a, NativeDb>; 2],
}
impl<'a> NativeRows<'a> {
    fn new(db: &'a NativeDb) -> Result<Self> {
        let files = db.cf_handle(Map::Files.name()).ok_or_else(|| error!("Missing recovery files map"))?;
        let keys = db.cf_handle(Map::KeyFiles.name()).ok_or_else(|| error!("Missing recovery key map"))?;
        let mut rows = [db.raw_iterator_cf(&files), db.raw_iterator_cf(&keys)];
        for row in &mut rows { row.seek_to_first(); }
        Ok(Self { rows })
    }
    fn peek(&self) -> Result<Option<(Key, &[u8])>> {
        for (index, map) in [Map::Files, Map::KeyFiles].into_iter().enumerate() {
            let row = &self.rows[index];
            if row.valid() {
                return Ok(Some((Key { map, bytes: row.key().ok_or_else(|| error!("Missing native key"))?.try_into()? },
                    row.value().ok_or_else(|| error!("Missing native value"))?)));
            }
            row.status()?;
        }
        Ok(None)
    }
    fn next(&mut self) {
        if self.rows[0].valid() { self.rows[0].next(); } else { self.rows[1].next(); }
    }
}

/// Validate the whole Ready stream and both complete maps before replay starts.
/// A selected row may contain exactly its old bytes or its specified new bytes
/// (absence for a delete). Unselected rows must agree with both inventories.
/// Reconstructing original/final digests catches extra, missing and altered rows
/// even after any prefix of commands has already been applied.
///
/// The caller validates all non-parent records with `visit_other`, then finishes
/// its own provider/child completeness checks. It must keep admission closed
/// across this scan and replay. Native iterator values remain borrowed resources
/// that the operation must budget; old manifest payloads use a 64 KiB buffer,
/// never a collection of all rows. This is not a concurrent database snapshot.
pub(crate) fn validate_replay_maps(
    db: &NativeDb, ready: impl Read, expected: &ReplayMaps,
    mut visit_other: impl FnMut(Record, u64, &mut dyn Read) -> Result<()>,
) -> Result<()> {
    use super::recovery_manifest::{read_manifest, Kind};
    let mut native = NativeRows::new(db)?;
    let mut original = MapInventory::new();
    let mut final_maps = MapInventory::new();
    let mut last_command = None;
    read_manifest(ready, Kind::Ready, expected.operation, expected.ready, |record, length, input| {
        if record == Record::SelectionDigest {
            if length != 32 { fail!("Invalid Ready selection digest length"); }
            let mut digest = [0; 32]; input.read_exact(&mut digest)?;
            if digest != expected.selection_digest { fail!("Ready selection digest mismatch"); }
        } else if record == Record::ParentMutation {
            let mut old_matches = false;
            let command = read_command(input, length, |key, _, old_len, old| {
                if last_command.is_some_and(|last| last >= key) {
                    fail!("Duplicate or unordered recovery parent command");
                }
                last_command = Some(key);
                while let Some((current_key, value)) = native.peek()? {
                    if current_key >= key { break; }
                    original.row(current_key, value)?;
                    final_maps.row(current_key, value)?;
                    native.next();
                }
                let current = native.peek()?.filter(|(current_key, _)| *current_key == key).map(|(_, value)| value);
                old_matches = current.is_some_and(|value| value.len() as u64 == old_len);
                // Stream the original row using exactly MapInventory's encoding.
                original.begin_row(key, old_len)?;
                let mut remaining = old_len;
                let mut offset = 0usize;
                let mut buffer = [0; 64 * 1024];
                while remaining != 0 {
                    let n = remaining.min(buffer.len() as u64) as usize;
                    old.read_exact(&mut buffer[..n])?;
                    original.digest.update(&buffer[..n]);
                    if old_matches {
                        let value = current.expect("matching native value");
                        if value.get(offset..offset + n) != Some(&buffer[..n]) { old_matches = false; }
                        offset += n;
                    }
                    remaining -= n as u64;
                }
                Ok(())
            })?;
            let current = native.peek()?.filter(|(key, _)| *key == command.key).map(|(_, value)| value);
            if !old_matches && current != command.new.as_deref() {
                fail!("Recovery parent row is neither its old nor new value");
            }
            if let Some(value) = &command.new { final_maps.row(command.key, value)?; }
            if current.is_some() { native.next(); }
        } else { visit_other(record, length, input)?; }
        Ok(())
    })?;
    while let Some((key, value)) = native.peek()? {
        original.row(key, value)?; final_maps.row(key, value)?; native.next();
    }
    if original.finish() != expected.original { fail!("Recovery original parent inventory mismatch"); }
    if final_maps.finish() != expected.final_maps { fail!("Recovery final parent inventory mismatch"); }
    Ok(())
}

/// Streaming ordering/budget state. Batches are only data; emitting them does
/// not confer authority to write or certify the as-yet-unread manifest tail.
#[derive(Default)]
pub(crate) struct Batches {
    last: Option<Key>, pending: Vec<Command>, bytes: usize, failed: bool,
}
impl Batches {
    pub(crate) fn push(&mut self, command: Command, emit: &mut impl FnMut(Vec<Command>) -> Result<()>) -> Result<()> {
        if self.failed { fail!("Recovery parent batch stream failed"); }
        self.failed = true;
        if self.last.is_some_and(|last| last >= command.key) {
            fail!("Duplicate or unordered recovery parent command");
        }
        let size = command.footprint()?;
        if size > BATCH_LIMIT { fail!("Recovery parent command exceeds batch budget"); }
        if self.bytes > BATCH_LIMIT - size {
            emit(std::mem::take(&mut self.pending))?;
            self.bytes = 0;
        }
        self.last = Some(command.key);
        self.bytes += size;
        self.pending.push(command);
        self.failed = false;
        Ok(())
    }
    pub(crate) fn finish(mut self, emit: &mut impl FnMut(Vec<Command>) -> Result<()>) -> Result<()> {
        if self.failed { fail!("Recovery parent batch stream failed"); }
        if !self.pending.is_empty() { emit(std::mem::take(&mut self.pending))?; }
        Ok(())
    }
}

#[cfg(test)]
#[path = "../tests/test_recovery_parent.rs"]
mod tests;
