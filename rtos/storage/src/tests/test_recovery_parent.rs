// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::archives::recovery_manifest::{read_manifest, Kind};
use std::io;

fn key(map: Map, n: u32) -> Key {
    Key { map, bytes: n.to_le_bytes() }
}
fn ready() -> ManifestWriter<Vec<u8>> {
    let mut writer = ManifestWriter::new(Vec::new(), Kind::Ready, [9; 16]).unwrap();
    writer.record(Record::SelectionDigest, 32, &mut &[8; 32][..]).unwrap();
    writer
}
fn ready_with_inventory(
    inventory: super::super::recovery_root::Inventory,
) -> ManifestWriter<Vec<u8>> {
    let mut writer = ready();
    write_inventory(&mut writer, InventoryRole::Final, inventory).unwrap();
    writer
}
fn command_body(old: &[u8], reset: Option<&ResetValue>) -> Vec<u8> {
    let mut writer = ready();
    write_command(&mut writer, key(Map::Files, 7), old, reset).unwrap();
    let (bytes, descriptor) = writer.finish().unwrap();
    let mut body = Vec::new();
    read_manifest(&bytes[..], Kind::Ready, [9; 16], descriptor, |tag, _, input| {
        if tag == Record::ParentMutation {
            input.read_to_end(&mut body)?;
        } else {
            io::copy(input, &mut io::sink())?;
        }
        Ok(())
    })
    .unwrap();
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
    let db = rocksdb::DBWithThreadMode::<rocksdb::MultiThreaded>::open_cf(
        &options,
        directory.path(),
        ["files", "key_files"],
    )?;
    let reset = ResetValue::capture()?;
    // Actual PackageIndexEntry serialization, preserving the exact old bytes.
    let old =
        serde_cbor::to_vec(&PackageIndexEntry::with_data(true, true, &lockfree::map::Map::new()))?;
    let mut final_inventory = MapInventory::new();
    for map in [Map::Files, Map::KeyFiles] {
        final_inventory.row(key(map, 0), &reset.0)?;
    }
    let mut writer = ready_with_inventory(final_inventory.finish());
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
    let expected = ReplayMaps {
        operation: [9; 16],
        ready: descriptor,
        selection_digest: [8; 32],
        original: original_inventory,
    };
    // The same preflight accepts original state before any native write and
    // the durable final state after the fixture's replay and cold reopen.
    validate_replay_maps(&db, &bytes[..], &expected, |_, _, _| fail!("unexpected record"))?;
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
        if tag == Record::ParentMutation {
            batches.push(read_command(input, len, consume_old)?, &mut apply)?;
        } else {
            io::copy(input, &mut io::sink())?;
        }
        Ok(())
    })?;
    batches.finish(&mut apply)?;
    drop(db);
    let db = rocksdb::DBWithThreadMode::<rocksdb::MultiThreaded>::open_cf(
        &options,
        directory.path(),
        ["files", "key_files"],
    )?;
    validate_replay_maps(&db, &bytes[..], &expected, |_, _, _| fail!("unexpected record"))?;
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
        let mut bad = body.clone();
        bad[index] = 255;
        assert!(read_command(&mut &bad[..], bad.len() as u64, |_, _, _, _| panic!(
            "visited malformed header"
        ))
        .is_err());
    }
    for (offset, value) in [(8, 0u64), (8, u64::MAX), (16, u64::MAX), (16, 0)] {
        let mut bad = body.clone();
        bad[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        assert!(read_command(&mut &bad[..], bad.len() as u64, |_, _, _, _| panic!(
            "visited malformed lengths"
        ))
        .is_err());
    }
    for end in 0..body.len() {
        assert!(read_command(&mut &body[..end], body.len() as u64, consume_old).is_err());
    }
    assert!(read_command(&mut &body[..], body.len() as u64, |_, _, _, _| Ok(())).is_err());
    let mut trailing = body.clone();
    trailing.push(0);
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
    let mut extra = reset.0.clone();
    extra.push(0);
    assert!(validate_reset(&extra).is_err());
}

#[test]
fn batches_bound_payloads_preserve_order_and_latch_sink_failures() -> Result<()> {
    let mut batches = Batches::default();
    let mut emitted = 0;
    let mut rows = 0;
    let mut sink = |commands: Vec<Command>| -> Result<()> {
        assert!(commands.iter().map(|c| c.footprint().unwrap()).sum::<usize>() <= BATCH_LIMIT);
        rows += commands.len();
        emitted += 1;
        Ok(())
    };
    // Sorted native byte keys; synthetic large payloads exercise batch accounting.
    for n in 0u32..12 {
        batches.push(
            Command {
                key: Key { map: Map::Files, bytes: n.to_be_bytes() },
                new: Some(vec![7; 1024 * 1024]),
            },
            &mut sink,
        )?;
    }
    batches.finish(&mut sink)?;
    assert_eq!(rows, 12);
    assert_eq!(emitted, 4);
    let mut batches = Batches::default();
    let k = key(Map::Files, 0);
    batches.push(Command { key: k, new: None }, &mut |_| Ok(()))?;
    assert!(batches.push(Command { key: k, new: None }, &mut |_| Ok(())).is_err());
    assert!(batches.finish(&mut |_| panic!("must not emit after duplicate")).is_err());
    let mut batches = Batches::default();
    batches.push(
        Command { key: key(Map::Files, 0), new: Some(vec![0; BATCH_LIMIT / 2]) },
        &mut |_| Ok(()),
    )?;
    assert!(batches
        .push(Command { key: key(Map::Files, 1), new: Some(vec![0; BATCH_LIMIT / 2]) }, &mut |_| {
            Err(error!("sink failure"))
        })
        .is_err());
    assert!(batches.finish(&mut |_| panic!("must not emit after failure")).is_err());
    Ok(())
}

#[test]
fn replay_preflight_accepts_every_old_new_combination_and_rejects_unexpected_rows() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let mut options = rocksdb::Options::default();
    options.create_if_missing(true);
    options.create_missing_column_families(true);
    let db = NativeDb::open_cf(&options, directory.path(), ["files", "key_files"])?;
    let old =
        serde_cbor::to_vec(&PackageIndexEntry::with_data(true, true, &lockfree::map::Map::new()))?;
    let reset = ResetValue::capture()?;
    let mut final_maps = MapInventory::new();
    for map in [Map::Files, Map::KeyFiles] {
        final_maps.row(key(map, 0), &old)?;
        final_maps.row(key(map, 1), &reset.0)?;
        final_maps.row(key(map, 3), &old)?;
    }
    let final_maps = final_maps.finish();
    let mut writer = ready_with_inventory(final_maps);
    let mut original = MapInventory::new();
    for map in [Map::Files, Map::KeyFiles] {
        for n in 0..4 {
            let k = key(map, n);
            original.row(k, &old)?;
            match n {
                1 => write_command(&mut writer, k, &old, Some(&reset))?,
                2 => write_command(&mut writer, k, &old, None)?,
                _ => {}
            }
        }
    }
    let (bytes, descriptor) = writer.finish()?;
    let expected = ReplayMaps {
        operation: [9; 16],
        ready: descriptor,
        selection_digest: [8; 32],
        original: original.finish(),
    };
    let validate =
        || validate_replay_maps(&db, &bytes[..], &expected, |_, _, _| panic!("unexpected record"));
    for mask in 0..16 {
        for (index, map) in [Map::Files, Map::KeyFiles].into_iter().enumerate() {
            let cf = db.cf_handle(map.name()).unwrap();
            for n in 0..4 {
                db.put_cf(&cf, key(map, n).bytes, &old)?;
            }
            if mask & (1 << (index * 2)) != 0 {
                db.put_cf(&cf, key(map, 1).bytes, &reset.0)?;
            }
            if mask & (2 << (index * 2)) != 0 {
                db.delete_cf(&cf, key(map, 2).bytes)?;
            }
        }
        let before = native_inventory(&db)?;
        validate()?;
        assert_eq!(native_inventory(&db)?, before, "preflight must not mutate");
    }
    let cf = db.cf_handle("key_files").unwrap();
    for n in [0, 1, 2, 3, 4] {
        let k = key(Map::KeyFiles, n);
        let saved = db.get_cf(&cf, k.bytes)?;
        db.put_cf(&cf, k.bytes, b"unexpected raw bytes")?;
        let before = native_inventory(&db)?;
        assert!(validate().is_err(), "must reject changed/extra row {n}");
        assert_eq!(native_inventory(&db)?, before);
        match saved {
            Some(value) => db.put_cf(&cf, k.bytes, value)?,
            None => db.delete_cf(&cf, k.bytes)?,
        }
    }
    for n in [0, 1, 3] {
        let k = key(Map::KeyFiles, n);
        let saved = db.get_cf(&cf, k.bytes)?.unwrap();
        db.delete_cf(&cf, k.bytes)?;
        assert!(validate().is_err());
        db.put_cf(&cf, k.bytes, saved)?;
    }
    validate()?;
    let mut corrupt = bytes.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(validate_replay_maps(&db, &corrupt[..], &expected, |_, _, _| Ok(())).is_err());
    let mut wrong_selection = ReplayMaps { selection_digest: [7; 32], ..expected };
    assert!(validate_replay_maps(&db, &bytes[..], &wrong_selection, |_, _, _| Ok(())).is_err());
    wrong_selection.selection_digest = [8; 32];
    wrong_selection.original.count += 1;
    assert!(validate_replay_maps(&db, &bytes[..], &wrong_selection, |_, _, _| Ok(())).is_err());
    Ok(())
}

#[test]
fn replay_preflight_streams_large_old_rows_and_checks_original_bytes_after_replay() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let mut options = rocksdb::Options::default();
    options.create_if_missing(true);
    options.create_missing_column_families(true);
    let db = NativeDb::open_cf(&options, directory.path(), ["files", "key_files"])?;
    let k = key(Map::Files, 7);
    let old = vec![42; 8 * 1024 * 1024 + 9];
    let mut original = MapInventory::new();
    original.row(k, &old)?;
    let mut writer = ready_with_inventory(MapInventory::new().finish());
    write_command(&mut writer, k, &old, None)?;
    let (bytes, descriptor) = writer.finish()?;
    let expected = ReplayMaps {
        operation: [9; 16],
        ready: descriptor,
        selection_digest: [8; 32],
        original: original.finish(),
    };
    // Current absence is the already-applied delete; the old inventory still
    // has to be reconstructed from the complete original stream.
    validate_replay_maps(&db, &bytes[..], &expected, |_, _, _| Ok(()))?;
    let cf = db.cf_handle("files").unwrap();
    db.put_cf(&cf, k.bytes, &old)?;
    validate_replay_maps(&db, &bytes[..], &expected, |_, _, _| Ok(()))?;
    db.delete_cf(&cf, k.bytes)?;
    let mut wrong_old = old;
    *wrong_old.last_mut().unwrap() ^= 1;
    let mut writer = ready_with_inventory(MapInventory::new().finish());
    write_command(&mut writer, k, &wrong_old, None)?;
    let (wrong, descriptor) = writer.finish()?;
    let wrong_expected = ReplayMaps { ready: descriptor, ..expected };
    assert!(validate_replay_maps(&db, &wrong[..], &wrong_expected, |_, _, _| Ok(())).is_err());
    Ok(())
}

#[test]
fn replay_preflight_checks_noop_maps_command_order_and_other_records() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let mut options = rocksdb::Options::default();
    options.create_if_missing(true);
    options.create_missing_column_families(true);
    let db = NativeDb::open_cf(&options, directory.path(), ["files", "key_files"])?;
    let empty = MapInventory::new().finish();
    let (bytes, descriptor) = ready_with_inventory(empty).finish()?;
    let mut expected = ReplayMaps {
        operation: [9; 16],
        ready: descriptor,
        selection_digest: [8; 32],
        original: empty,
    };
    validate_replay_maps(&db, &bytes[..], &expected, |_, _, _| Ok(()))?;
    for keys in [[2, 1], [1, 1]] {
        let mut writer = ready_with_inventory(MapInventory::new().finish());
        for n in keys {
            write_command(&mut writer, key(Map::Files, n), b"old", None)?;
        }
        let (bytes, descriptor) = writer.finish()?;
        expected.ready = descriptor;
        let error = validate_replay_maps(&db, &bytes[..], &expected, |_, _, _| Ok(())).unwrap_err();
        assert!(error.to_string().contains("unordered"), "{error}");
    }
    let mut writer = ready_with_inventory(MapInventory::new().finish());
    writer.record(Record::Tail, 4, &mut &b"tail"[..])?;
    let (bytes, descriptor) = writer.finish()?;
    expected.ready = descriptor;
    let mut visited = false;
    assert!(validate_replay_maps(&db, &bytes[..], &expected, |tag, _, _| {
        assert_eq!(tag, Record::Tail);
        visited = true;
        fail!("invalid tail")
    })
    .is_err());
    assert!(visited);
    Ok(())
}

#[test]
fn inventory_records_reject_wrong_role_version_length_and_empty_digest() -> Result<()> {
    let inventory = MapInventory::new().finish();
    let mut writer = ready_with_inventory(inventory);
    write_command(&mut writer, key(Map::Files, 7), b"old", None)?;
    let (bytes, descriptor) = writer.finish()?;
    let mut body = Vec::new();
    read_manifest(&bytes[..], Kind::Ready, [9; 16], descriptor, |tag, _, input| {
        if tag == Record::MapInventory {
            input.read_to_end(&mut body)?;
        } else {
            io::copy(input, &mut io::sink())?;
        }
        Ok(())
    })?;
    assert_eq!(read_inventory(&mut &body[..], body.len() as u64, InventoryRole::Final)?, inventory);
    assert!(read_inventory(&mut &body[..], body.len() as u64, InventoryRole::Original).is_err());
    for index in [0, 2, 11] {
        let mut bad = body.clone();
        bad[index] ^= 1;
        assert!(read_inventory(&mut &bad[..], bad.len() as u64, InventoryRole::Final).is_err());
    }
    for n in 0..body.len() {
        assert!(read_inventory(&mut &body[..n], body.len() as u64, InventoryRole::Final).is_err());
    }
    assert!(read_inventory(&mut &body[..], body.len() as u64 + 1, InventoryRole::Final).is_err());
    assert!(write_inventory(&mut ready(), InventoryRole::Final, Default::default()).is_err());
    let directory = tempfile::tempdir()?;
    let mut options = rocksdb::Options::default();
    options.create_if_missing(true);
    options.create_missing_column_families(true);
    let db = NativeDb::open_cf(&options, directory.path(), ["files", "key_files"])?;
    for count in [0, 2] {
        let mut writer = ready();
        for _ in 0..count {
            write_inventory(&mut writer, InventoryRole::Final, inventory)?;
        }
        let (bytes, ready) = writer.finish()?;
        let expected = ReplayMaps {
            operation: [9; 16],
            ready,
            selection_digest: [8; 32],
            original: inventory,
        };
        assert!(validate_replay_maps(&db, &bytes[..], &expected, |_, _, _| Ok(())).is_err());
    }
    let mut incorrect_final = inventory;
    incorrect_final.count = 1;
    let (bytes, ready) = ready_with_inventory(incorrect_final).finish()?;
    let expected =
        ReplayMaps { operation: [9; 16], ready, selection_digest: [8; 32], original: inventory };
    let error = validate_replay_maps(&db, &bytes[..], &expected, |_, _, _| Ok(())).unwrap_err();
    assert!(error.to_string().contains("final parent inventory mismatch"), "{error}");
    Ok(())
}

#[tokio::test]
async fn selection_persisted_maps_bind_predicate_complete_providers_and_ready_replay() -> Result<()>
{
    use crate::{
        archives::{
            recovery_participant::Provider,
            recovery_providers::RecoveryProviders,
            recovery_root::{Inventory, Policy, RootHeader, Sidecar, State, ROOT_KEY},
            truncation_selection::TruncationSelection,
        },
        db::rocksdb::{AccessType, RocksDb},
    };
    use rtos_block::{BlockIdExt, ShardIdent};
    let directory = tempfile::tempdir()?;
    let db = RocksDb::new(directory.path(), "db", None, AccessType::ReadWrite)?;
    for map in [Map::Files, Map::KeyFiles] {
        db.db().create_cf(map.name(), &rocksdb::Options::default())?;
    }
    let identity = db.db().get_db_identity()?;
    let provider = Provider::main(directory.path(), false, &identity)?;
    let cutoff =
        BlockIdExt::with_params(ShardIdent::masterchain(), 100, [1; 32].into(), [2; 32].into());
    let top = BlockIdExt::with_params(ShardIdent::full(0), 88, [3; 32].into(), [4; 32].into());
    let selection = TruncationSelection::new(cutoff.clone(), vec![top.clone()])?;
    let inventory = native_inventory(db.db())?;
    let build = |provider_count, inventory_count| -> Result<_> {
        let mut writer = ManifestWriter::new(Vec::new(), Kind::Selection, [9; 16])?;
        writer.record_with(Record::Predicate, selection.encoded_len()?, |out| {
            selection.write_predicate(out)
        })?;
        for _ in 0..provider_count {
            writer.record_with(Record::Provider, provider.encoded_len()?, |out| {
                provider.write(out)
            })?;
        }
        for _ in 0..inventory_count {
            write_inventory(&mut writer, InventoryRole::Original, inventory)?;
        }
        writer.finish()
    };
    let (bytes, descriptor) = build(1, 1)?;
    let mut root = RootHeader {
        state: State::Building,
        policy: Policy::Node,
        aborted: false,
        operation: [9; 16],
        database_identity_bytes: identity.len() as u64,
        database_identity_digest: rtos_block::sha256_digest(identity),
        selection: descriptor,
        ready: Sidecar::default(),
        providers: Inventory::default(),
        maps: Inventory::default(),
        data: Inventory::default(),
    };
    db.db().put(ROOT_KEY, root.encode()?)?;
    let providers =
        RecoveryProviders::inspect(db.clone(), &root, None, db.repair_protection()).await?;
    let mut tops = Vec::new();
    let parsed = read_selection_maps(
        &providers,
        &root,
        &bytes[..],
        |id| {
            tops.push(id);
            Ok(())
        },
        |_, _, _| fail!("unexpected disposition"),
    )?;
    assert_eq!(parsed.cutoff, cutoff);
    assert_eq!(tops, vec![top]);
    assert_eq!(parsed.original, inventory);
    let mut writer = ManifestWriter::new(Vec::new(), Kind::Ready, root.operation)?;
    writer.record(Record::SelectionDigest, 32, &mut descriptor.digest.as_slice())?;
    writer.record_with(Record::Provider, provider.encoded_len()?, |out| provider.write(out))?;
    write_inventory(&mut writer, InventoryRole::Final, inventory)?;
    let (ready_bytes, ready) = writer.finish()?;
    let expected = ReplayMaps {
        operation: root.operation,
        ready,
        selection_digest: descriptor.digest,
        original: parsed.original,
    };
    let mut checker = providers.checker();
    let checked_final =
        validate_replay_maps(db.db(), &ready_bytes[..], &expected, |tag, len, input| {
            assert_eq!(tag, Record::Provider);
            checker.record(input, len)
        })?;
    assert_eq!(checked_final, inventory);
    checker.finish()?;
    for (provider_count, inventory_count) in [(0, 1), (2, 1), (1, 0), (1, 2)] {
        let (bytes, descriptor) = build(provider_count, inventory_count)?;
        root.selection = descriptor;
        db.db().put(ROOT_KEY, root.encode()?)?;
        assert!(read_selection_maps(&providers, &root, &bytes[..], |_| Ok(()), |_, _, _| Ok(()))
            .is_err());
        assert_eq!(native_inventory(db.db())?, inventory);
        assert_eq!(db.db().get(ROOT_KEY)?.as_deref(), Some(root.encode()?.as_slice()));
    }
    Ok(())
}
