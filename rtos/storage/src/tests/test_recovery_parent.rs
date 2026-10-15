// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::archives::recovery_manifest::{Kind, read_manifest};
use std::io;

fn key(map: Map, n: u32) -> Key { Key { map, bytes: n.to_le_bytes() } }
fn ready() -> ManifestWriter<Vec<u8>> {
    let mut writer = ManifestWriter::new(Vec::new(), Kind::Ready, [9; 16]).unwrap();
    writer.record(Record::SelectionDigest, 32, &mut &[8; 32][..]).unwrap();
    writer
}
fn command_body(old: &[u8], reset: Option<&ResetValue>) -> Vec<u8> {
    let mut writer = ready();
    write_command(&mut writer, key(Map::Files, 7), old, reset).unwrap();
    let (bytes, descriptor) = writer.finish().unwrap();
    let mut body = Vec::new();
    read_manifest(&bytes[..], Kind::Ready, [9; 16], descriptor, |tag, _, input| {
        if tag == Record::ParentMutation { input.read_to_end(&mut body)?; }
        else { io::copy(input, &mut io::sink())?; }
        Ok(())
    }).unwrap();
    body
}
fn consume_old(_: Key, _: Action, _: u64, input: &mut dyn Read) -> Result<()> {
    io::copy(input, &mut io::sink())?;
    Ok(())
}

#[test]
fn parent_commands_match_native_rows_and_replay_both_maps() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let mut options = rocksdb::Options::default();
    options.create_if_missing(true);
    options.create_missing_column_families(true);
    let db = rocksdb::DBWithThreadMode::<rocksdb::MultiThreaded>::open_cf(&options, directory.path(), ["files", "key_files"])?;
    let reset = ResetValue::capture()?;
    // Actual PackageIndexEntry serialization, preserving the exact old bytes.
    let old = serde_cbor::to_vec(&PackageIndexEntry::with_data(true, true, &lockfree::map::Map::new()))?;
    let mut writer = ready();
    for map in [Map::Files, Map::KeyFiles] {
        let cf = db.cf_handle(map.name()).unwrap();
        for n in [0, 1] {
            let key = key(map, n);
            db.put_cf(&cf, key.bytes, &old)?;
            let pin = db.get_pinned_cf(&cf, key.bytes)?.unwrap();
            write_command(&mut writer, key, &pin, if n == 0 { Some(&reset) } else { None })?;
        }
    }
    db.flush_wal(true)?;
    let original_inventory = native_inventory(&db)?;
    assert_eq!(original_inventory.count, 4);
    let (bytes, descriptor) = writer.finish()?;
    // Validate the whole immutable stream before issuing any native mutation.
    read_manifest(&bytes[..], Kind::Ready, [9; 16], descriptor, |tag, len, input| {
        if tag == Record::ParentMutation {
            read_command(input, len, |key, _, len, input| {
                let cf = db.cf_handle(key.map.name()).unwrap();
                let pin = db.get_pinned_cf(&cf, key.bytes)?.unwrap();
                assert_eq!(pin.len() as u64, len);
                let mut offset = 0;
                let mut buffer = [0; 32];
                loop {
                    let n = input.read(&mut buffer)?;
                    if n == 0 { break; }
                    assert_eq!(&buffer[..n], &pin[offset..offset+n]);
                    offset += n;
                }
                assert_eq!(offset, pin.len());
                Ok(())
            })?;
        } else { io::copy(input, &mut io::sink())?; }
        Ok(())
    })?;
    // Fixture-only application, not a production recovery authority.
    let mut batches = Batches::default();
    let mut apply = |commands: Vec<Command>| -> Result<()> {
        let mut batch = rocksdb::WriteBatch::default();
        for command in commands {
            let cf = db.cf_handle(command.key.map.name()).unwrap();
            match command.new {
                Some(value) => batch.put_cf(&cf, command.key.bytes, value),
                None => batch.delete_cf(&cf, command.key.bytes),
            }
        }
        db.write(batch)?;
        db.flush_wal(true)?;
        Ok(())
    };
    read_manifest(&bytes[..], Kind::Ready, [9; 16], descriptor, |tag, len, input| {
        if tag == Record::ParentMutation { batches.push(read_command(input, len, consume_old)?, &mut apply)?; }
        else { io::copy(input, &mut io::sink())?; }
        Ok(())
    })?;
    batches.finish(&mut apply)?;
    drop(db);
    let db = rocksdb::DBWithThreadMode::<rocksdb::MultiThreaded>::open_cf(&options, directory.path(), ["files", "key_files"])?;
    let mut expected_inventory = MapInventory::new();
    for map in [Map::Files, Map::KeyFiles] {
        expected_inventory.row(key(map, 0), &reset.0)?;
        let cf = db.cf_handle(map.name()).unwrap();
        assert_eq!(db.get_cf(&cf, 0u32.to_le_bytes())?.unwrap(), reset.0);
        assert!(db.get_cf(&cf, 1u32.to_le_bytes())?.is_none());
        assert_eq!(db.iterator_cf(&cf, rocksdb::IteratorMode::Start).count(), 1);
    }
    let expected_inventory = expected_inventory.finish();
    assert_eq!(native_inventory(&db)?, expected_inventory);
    assert_ne!(expected_inventory, original_inventory);
    let cf = db.cf_handle("key_files").unwrap();
    db.put_cf(&cf, 2u32.to_le_bytes(), &reset.0)?;
    assert_ne!(native_inventory(&db)?, expected_inventory);
    db.delete_cf(&cf, 2u32.to_le_bytes())?;
    db.delete_cf(&cf, 0u32.to_le_bytes())?;
    assert_ne!(native_inventory(&db)?, expected_inventory);
    db.put_cf(&cf, 0u32.to_le_bytes(), b"different raw value")?;
    assert_ne!(native_inventory(&db)?, expected_inventory);
    db.put_cf(&cf, b"invalid key length", b"x")?;
    assert!(native_inventory(&db).is_err());
    Ok(())
}

#[test]
fn parent_framing_rejects_unknown_targets_lengths_and_actions_before_old_visit() {
    let reset = ResetValue::capture().unwrap();
    let body = command_body(b"old", Some(&reset));
    for index in [0, 2, 3] {
        let mut bad = body.clone(); bad[index] = 255;
        assert!(read_command(&mut &bad[..], bad.len() as u64, |_, _, _, _| panic!("visited malformed header")).is_err());
    }
    for (offset, value) in [(8, 0u64), (8, u64::MAX), (16, u64::MAX), (16, 0)] {
        let mut bad = body.clone(); bad[offset..offset+8].copy_from_slice(&value.to_le_bytes());
        assert!(read_command(&mut &bad[..], bad.len() as u64, |_, _, _, _| panic!("visited malformed lengths")).is_err());
    }
    for end in 0..body.len() {
        assert!(read_command(&mut &body[..end], body.len() as u64, consume_old).is_err());
    }
    assert!(read_command(&mut &body[..], body.len() as u64, |_, _, _, _| Ok(())).is_err());
    let mut trailing = body.clone(); trailing.push(0);
    assert!(read_command(&mut &trailing[..], trailing.len() as u64, consume_old).is_err());
}

#[test]
fn reset_schema_rejects_nonempty_or_unrecognized_state() {
    let reset = ResetValue::capture().unwrap();
    validate_reset(&reset.0).unwrap();
    for text in [
        r#"{"deleted":true,"finalized":false,"blocks_ranges":{}}"#,
        r#"{"deleted":false,"finalized":true,"blocks_ranges":{}}"#,
        r#"{"deleted":false,"finalized":false,"blocks_ranges":{"x":0}}"#,
        r#"{"deleted":false,"finalized":false,"blocks_ranges":{},"extra":0}"#,
        r#"{"deleted":false,"blocks_ranges":{}}"#,
    ] {
        let value: serde_json::Value = serde_json::from_str(text).unwrap();
        assert!(validate_reset(&serde_cbor::to_vec(&value).unwrap()).is_err());
    }
    let mut extra = reset.0.clone(); extra.push(0);
    assert!(validate_reset(&extra).is_err());
}

#[test]
fn batches_bound_payloads_preserve_order_and_latch_sink_failures() -> Result<()> {
    let mut batches = Batches::default();
    let mut emitted = 0;
    let mut rows = 0;
    let mut sink = |commands: Vec<Command>| -> Result<()> {
        assert!(commands.iter().map(|c| c.footprint().unwrap()).sum::<usize>() <= BATCH_LIMIT);
        rows += commands.len(); emitted += 1; Ok(())
    };
    // Sorted native byte keys; synthetic large payloads exercise batch accounting.
    for n in 0u32..12 {
        batches.push(Command { key: Key { map: Map::Files, bytes: n.to_be_bytes() }, new: Some(vec![7; 1024*1024]) }, &mut sink)?;
    }
    batches.finish(&mut sink)?;
    assert_eq!(rows, 12); assert_eq!(emitted, 4);
    let mut batches = Batches::default();
    let k = key(Map::Files, 0);
    batches.push(Command { key: k, new: None }, &mut |_| Ok(()))?;
    assert!(batches.push(Command { key: k, new: None }, &mut |_| Ok(())).is_err());
    assert!(batches.finish(&mut |_| panic!("must not emit after duplicate")).is_err());
    let mut batches = Batches::default();
    batches.push(Command { key: key(Map::Files, 0), new: Some(vec![0; BATCH_LIMIT/2]) }, &mut |_| Ok(()))?;
    assert!(batches.push(Command { key: key(Map::Files, 1), new: Some(vec![0; BATCH_LIMIT/2]) }, &mut |_| Err(error!("sink failure"))).is_err());
    assert!(batches.finish(&mut |_| panic!("must not emit after failure")).is_err());
    Ok(())
}
