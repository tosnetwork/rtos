// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{
    archives::{
        package_id::PackageId,
        recovery_manifest::ManifestWriter,
        recovery_participant::{Backlink, Identity},
        recovery_root::{Policy, Sidecar, PARTICIPANT_KEY, ROOT_KEY},
        truncation_selection::TruncationSelection,
    },
    db::rocksdb::{AccessType, RocksDb},
};
use rtos_block::{sha256_digest, BlockIdExt, UInt256};

fn record(writer: &mut ManifestWriter<fs::File>, tag: Record, bytes: &[u8]) -> Result<()> {
    writer.record(tag, bytes.len() as u64, &mut &bytes[..])
}
fn identity(provider: [u8; 32], id: u32) -> [u8; 52] {
    let mut value = [0; 52];
    value[..3].copy_from_slice(&[1, 0, 1]);
    value[4..8].copy_from_slice(&id.to_le_bytes());
    value[8..12].copy_from_slice(&(-1i32).to_le_bytes());
    value[12..20].copy_from_slice(&(1u64 << 63).to_le_bytes());
    value[20..].copy_from_slice(&provider);
    value
}
fn row(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

// This exercises the native worker and its resumable data transitions. It is
// deliberately not the actual-node acceptance test or a production producer.
async fn exercise(interruption: u8) -> Result<()> {
    let dir = tempfile::tempdir()?;
    let db = RocksDb::new(dir.path(), "db", None, AccessType::ReadWrite)?;
    for name in ["files", "key_files"] {
        db.db().create_cf(name, &rocksdb::Options::default())?;
        let cf = db.db().cf_handle(name).unwrap();
        db.db().put_cf(&cf, 1u32.to_le_bytes(), b"original parent row")?;
    }
    for kind in TABLES {
        for id in 0..2 {
            db.db().create_cf(&format!("{kind}_db_{id}"), &rocksdb::Options::default())?;
        }
    }
    let offsets = db.db().cf_handle("offsets_db_0").unwrap();
    db.db().put_cf(&offsets, b"entry", b"old offset")?;
    drop(offsets);
    let package = PackageId::for_block(0).full_path(dir.path(), &ShardIdent::masterchain())?;
    let tail = PackageId::for_block(1).full_path(dir.path(), &ShardIdent::masterchain())?;
    fs::create_dir_all(package.parent().unwrap())?;
    fs::write(&package, b"old package")?;
    fs::write(&tail, b"tail package")?;
    let native = db.db().get_db_identity()?;
    let mut root = RootHeader {
        state: State::Building,
        policy: Policy::Node,
        aborted: false,
        operation: [29; 16],
        database_identity_bytes: native.len() as u64,
        database_identity_digest: sha256_digest(native),
        selection: Sidecar { bytes: 1, records: 1, digest: [1; 32] },
        ready: Sidecar::default(),
        providers: Inventory::default(),
        maps: Inventory::default(),
        data: Inventory::default(),
    };
    db.db().put(ROOT_KEY, root.encode()?)?;
    let providers =
        RecoveryProviders::inspect(db.clone(), &root, None, db.repair_protection()).await?;
    let provider = providers.participants[0].descriptor.digest()?;
    let stage_id = identity(provider, 0);
    let stage = super::super::recovery_stages::Stage::decode(&providers, &mut &stage_id[..], 52)?;
    let operation = super::super::recovery_stages::operation(&providers, &root, 0)?;
    fs::create_dir_all(&operation)?;
    let original_data = recovery_data::inventory(&providers)?;
    let maps = recovery_parent::native_inventory(db.db())?;
    let selection = TruncationSelection::new(
        BlockIdExt::with_params(
            ShardIdent::masterchain(),
            2,
            UInt256::from([1; 32]),
            UInt256::from([2; 32]),
        ),
        Vec::<BlockIdExt>::new(),
    )?;
    let mut writer = ManifestWriter::new(
        fs::File::create(operation.join("selection.v1"))?,
        Kind::Selection,
        root.operation,
    )?;
    writer.record_with(Record::Predicate, selection.encoded_len()?, |out| {
        selection.write_predicate(out)
    })?;
    let descriptor = &providers.participants[0].descriptor;
    writer.record_with(Record::Provider, descriptor.encoded_len()?, |out| descriptor.write(out))?;
    recovery_parent::write_inventory(&mut writer, InventoryRole::Original, maps)?;
    let mut inventory = vec![1, 0, root.policy as u8];
    inventory.extend_from_slice(&original_data.count.to_le_bytes());
    inventory.extend_from_slice(&original_data.digest);
    record(&mut writer, Record::ArchiveInventory, &inventory)?;
    record(&mut writer, Record::Child, &stage_id)?;
    let (file, selection) = writer.finish()?;
    file.sync_all()?;
    drop(file);
    root.selection = selection;
    fs::write(stage.path(&providers, &root)?, b"new package")?;
    let mut writer = ManifestWriter::new(
        fs::File::create(operation.join("ready.v1"))?,
        Kind::Ready,
        root.operation,
    )?;
    record(&mut writer, Record::SelectionDigest, &root.selection.digest)?;
    writer.record_with(Record::Provider, descriptor.encoded_len()?, |out| descriptor.write(out))?;
    let final_maps = recovery_parent::MapInventory::new().finish();
    recovery_parent::write_inventory(&mut writer, InventoryRole::Final, final_maps)?;
    for (tag, kind) in TABLES.iter().enumerate() {
        for id in 0..2u32 {
            let mut child = vec![1, 0, 1, 0];
            child.extend_from_slice(&id.to_le_bytes());
            child.push(tag as u8);
            child.extend_from_slice(&provider);
            child.push(u8::from(id == 0));
            let has_row = *kind == "offsets" && id == 0;
            child.extend_from_slice(&u64::from(has_row).to_le_bytes());
            if has_row {
                row(&mut child, b"entry");
                child.push(1);
                row(&mut child, b"old offset");
                child.push(1);
                row(&mut child, b"new offset");
            }
            record(&mut writer, Record::Child, &child)?;
        }
    }
    for (id, old) in [(0, b"old package".as_slice()), (1, b"tail package".as_slice())] {
        let mut child = vec![1, 0, 2];
        child.extend_from_slice(&identity(provider, id));
        child.extend_from_slice(&(old.len() as u64).to_le_bytes());
        child.extend_from_slice(&sha256_digest(old));
        child.push(u8::from(id == 0));
        if id == 0 {
            child.extend_from_slice(&11u64.to_le_bytes());
            child.extend_from_slice(&sha256_digest(b"new package"));
        }
        record(&mut writer, Record::Child, &child)?;
    }
    for map in [recovery_parent::Map::Files, recovery_parent::Map::KeyFiles] {
        recovery_parent::write_command(
            &mut writer,
            recovery_parent::Key { map, bytes: 1u32.to_le_bytes() },
            b"original parent row",
            None,
        )?;
    }
    let (file, ready) = writer.finish()?;
    file.sync_all()?;
    drop(file);
    root.ready = ready;
    root.state = State::Ready;
    let backlink = Backlink {
        operation: root.operation,
        main: Identity {
            bytes: root.database_identity_bytes,
            digest: root.database_identity_digest,
        },
        selection: root.selection.digest,
        provider,
    };
    db.db().put(PARTICIPANT_KEY, backlink.encode()?)?;
    db.db().put(ROOT_KEY, root.encode()?)?;
    db.sync_wal()?;
    let expected = prepare(&providers, &root)?.new;
    if interruption >= 3 {
        if interruption == 3 {
            let cf = db.db().cf_handle("offsets_db_0").unwrap();
            db.db().put_cf(&cf, b"undeclared", b"preserve")?;
        } else {
            fs::write(stage.path(&providers, &root)?, b"wrong stage")?;
        }
        let before = db.db().get(ROOT_KEY)?;
        let stage_path = stage.path(&providers, &root)?;
        assert!(super::super::recovery_worker::recover_cleaned(providers, root).is_err());
        assert_eq!(db.db().get(ROOT_KEY)?, before);
        assert_eq!(fs::read(&package)?, b"old package");
        assert!(stage_path.exists());
        assert!(tail.exists());
        return Ok(());
    }
    if interruption >= 1 {
        fs::rename(stage.path(&providers, &root)?, &package)?;
    }
    if interruption >= 2 {
        let offsets = db.db().cf_handle("offsets_db_0").unwrap();
        db.db().put_cf(&offsets, b"entry", b"new offset")?;
        drop(offsets);
        for name in ["files", "key_files"] {
            let cf = db.db().cf_handle(name).unwrap();
            db.db().delete_cf(&cf, 1u32.to_le_bytes())?;
        }
        root.state = State::Committed;
        root.maps = final_maps;
        db.db().put(ROOT_KEY, root.encode()?)?;
        db.sync_wal()?;
        db.db().drop_cf("block_index_db_1")?; // Interrupted between individual CF drops.
        assert!(recovery_data::inventory(&providers).is_err());
    }
    let protection = db.repair_protection().clone();
    let _deletion = protection.deletion().await;
    let _mutation = protection.artifact_mutation().await;
    super::super::recovery_worker::recover_cleaned(providers, root)?;
    assert_eq!(fs::read(&package)?, b"new package");
    assert!(!tail.exists());
    assert!(db.db().get(ROOT_KEY)?.is_none());
    assert!(db.db().get(PARTICIPANT_KEY)?.is_none());
    assert!(!operation.exists());
    let offsets = db.db().cf_handle("offsets_db_0").unwrap();
    assert_eq!(db.db().get_cf(&offsets, b"entry")?.as_deref(), Some(b"new offset".as_slice()));
    for kind in TABLES {
        assert!(db.db().cf_handle(&format!("{kind}_db_1")).is_none());
    }
    assert_eq!(recovery_parent::native_inventory(db.db())?, final_maps);
    assert_ne!(original_data, expected);
    Ok(())
}
#[tokio::test]
async fn ready_replays_files_rows_and_cleans_tail() -> Result<()> {
    exercise(0).await
}
#[tokio::test]
async fn ready_resumes_after_canonical_rename() -> Result<()> {
    exercise(1).await
}
#[tokio::test]
async fn committed_resumes_between_tail_family_drops() -> Result<()> {
    exercise(2).await
}

#[tokio::test]
async fn extra_native_row_refuses_before_effects() -> Result<()> {
    exercise(3).await
}
#[tokio::test]
async fn damaged_stage_refuses_before_effects() -> Result<()> {
    exercise(4).await
}
