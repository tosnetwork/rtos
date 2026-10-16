// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{archives::{recovery_manifest::{ManifestWriter, Record}, recovery_root::{Inventory, Policy, ROOT_KEY},
    truncation_selection::TruncationSelection}, db::rocksdb::{RocksDb, AccessType}};
use rtos_block::{BlockIdExt, ShardIdent};
use std::{path::PathBuf, sync::Arc};

async fn fixture(path: &Path, aborted: bool) -> Result<(Arc<RocksDb>, RecoveryProviders, RootHeader, PathBuf)> {
    let db = RocksDb::new(path, "db", None, AccessType::ReadWrite)?;
    for name in ["files", "key_files"] { db.db().create_cf(name, &rocksdb::Options::default())?; }
    let operation = [9;16];
    let selection = TruncationSelection::new(BlockIdExt::with_params(ShardIdent::masterchain(), 100, [1;32].into(), [2;32].into()), Vec::new())?;
    let mut writer = ManifestWriter::new(Vec::new(), Kind::Selection, operation)?;
    writer.record_with(Record::Predicate, selection.encoded_len()?, |out| selection.write_predicate(out))?;
    let (selection_bytes, selection_descriptor) = writer.finish()?;
    let id = db.db().get_db_identity()?;
    let mut root = RootHeader { state: State::Building, policy: Policy::Node, aborted: false, operation,
        database_identity_bytes: id.len() as u64, database_identity_digest: rtos_block::sha256_digest(id),
        selection: selection_descriptor, ready: Sidecar::default(), providers: Inventory::default(),
        maps: Inventory::default(), data: Inventory::default() };
    db.db().put(ROOT_KEY, root.encode()?)?;
    let providers = RecoveryProviders::inspect(db.clone(), &root, None, db.repair_protection()).await?;
    root.state = State::Cleaned; root.aborted = aborted;
    root.providers = providers.inventory()?;
    root.maps = crate::archives::recovery_parent::native_inventory(db.db())?;
    root.data = crate::archives::recovery_data::inventory(&providers)?;
    let controls = path.join("archive/recovery").join(hex::encode(operation));
    fs::create_dir_all(&controls)?;
    fs::write(controls.join("selection.v1"), selection_bytes)?;
    if !aborted {
        let mut writer = ManifestWriter::new(Vec::new(), Kind::Ready, operation)?;
        writer.record(Record::SelectionDigest, 32, &mut root.selection.digest.as_slice())?;
        let (bytes, descriptor) = writer.finish()?;
        root.ready = descriptor; fs::write(controls.join("ready.v1"), bytes)?;
    }
    db.db().put(ROOT_KEY, root.encode()?)?; db.sync_wal()?;
    Ok((db, providers, root, controls))
}
#[tokio::test]
async fn every_sidecar_removal_boundary_still_validates_cleaned_state() -> Result<()> {
    for aborted in [true, false] {
        let dir = tempfile::tempdir()?;
        let (db, providers, root, controls) = fixture(dir.path(), aborted).await?;
        validate_cleaned(&providers, &root)?;
        let inspected = RecoveryProviders::inspect(db.clone(), &root, None, db.repair_protection()).await?;
        drop(inspected);
        fs::remove_file(controls.join("selection.v1"))?;
        validate_cleaned(&providers, &root)?;
        if !aborted { fs::remove_file(controls.join("ready.v1"))?; validate_cleaned(&providers, &root)?; }
        fs::remove_dir(&controls)?; validate_cleaned(&providers, &root)?;
        fs::remove_dir(controls.parent().unwrap())?; validate_cleaned(&providers, &root)?;
        assert_eq!(db.db().get(ROOT_KEY)?.as_deref(), Some(root.encode()?.as_slice()));
    }
    Ok(())
}
#[tokio::test]
async fn unknown_artifacts_and_other_operations_are_preserved() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (db, providers, root, controls) = fixture(dir.path(), false).await?;
    let unknown = controls.join("unexpected-stage"); fs::write(&unknown, b"preserve")?;
    assert!(validate_cleaned(&providers, &root).is_err());
    assert!(RecoveryProviders::inspect(db.clone(), &root, None, db.repair_protection()).await.is_err());
    assert_eq!(fs::read(&unknown)?, b"preserve"); fs::remove_file(&unknown)?;
    let other = controls.parent().unwrap().join(hex::encode([8;16])); fs::create_dir(&other)?;
    assert!(validate_cleaned(&providers, &root).is_err()); assert!(other.is_dir());
    assert_eq!(db.db().get(ROOT_KEY)?.as_deref(), Some(root.encode()?.as_slice()));
    Ok(())
}
#[tokio::test]
async fn sidecar_corruption_truncation_alias_and_abort_ready_refuse() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (_db, providers, root, controls) = fixture(dir.path(), true).await?;
    let path = controls.join("selection.v1"); let original = fs::read(&path)?;
    let mut corrupt = original.clone(); corrupt[40] ^= 1; fs::write(&path, &corrupt)?;
    assert!(validate_cleaned(&providers, &root).is_err()); assert_eq!(fs::read(&path)?, corrupt);
    fs::write(&path, &original[..original.len()-1])?; assert!(validate_cleaned(&providers, &root).is_err());
    fs::remove_file(&path)?;
    let target = dir.path().join("saved-selection"); fs::write(&target, &original)?;
    std::os::unix::fs::symlink(&target, &path)?;
    assert!(validate_cleaned(&providers, &root).is_err()); fs::remove_file(&path)?;
    fs::write(&path, original)?;
    fs::write(controls.join("ready.v1"), b"not allowed in aborted Cleaned")?;
    assert!(validate_cleaned(&providers, &root).is_err());
    Ok(())
}
#[tokio::test]
async fn control_directory_symlink_and_nonterminal_root_refuse() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (_db, providers, root, controls) = fixture(dir.path(), true).await?;
    let saved = dir.path().join("saved-controls"); fs::rename(&controls, &saved)?;
    std::os::unix::fs::symlink(&saved, &controls)?;
    assert!(validate_cleaned(&providers, &root).is_err());
    assert!(saved.join("selection.v1").is_file());
    let mut building = root; building.state = State::Building; building.aborted = false;
    building.providers = Inventory::default(); building.maps = Inventory::default(); building.data = Inventory::default();
    assert!(validate_cleaned(&providers, &building).is_err());
    Ok(())
}

#[tokio::test]
async fn epoch_control_artifacts_must_be_absent_before_cleaned_cleanup() -> Result<()> {
    use crate::archives::epoch::{ArchivalModeConfig, EpochEntry, EpochMeta, write_epoch_meta};
    let dir = tempfile::tempdir()?;
    let external = tempfile::tempdir()?;
    let (db, initial, mut root, _) = fixture(dir.path(), true).await?;
    drop(initial);
    write_epoch_meta(external.path(), &EpochMeta { mc_seq_no_start: 0, mc_seq_no_end: 19_999 }).await?;
    drop(RocksDb::new(external.path(), "archive_db", None, AccessType::ReadWrite)?);
    let config = ArchivalModeConfig { epoch_size: 20_000,
        new_epochs_path: dir.path().join("epochs"),
        existing_epochs: vec![EpochEntry { path: external.path().into() }] };
    root.state = State::Building; root.aborted = false;
    root.providers = Inventory::default(); root.maps = Inventory::default(); root.data = Inventory::default();
    db.db().put(ROOT_KEY, root.encode()?)?;
    let providers = RecoveryProviders::inspect(db.clone(), &root, Some(&config), db.repair_protection()).await?;
    assert_eq!(providers.participants.len(), 2);
    root.state = State::Cleaned; root.aborted = true;
    root.providers = providers.inventory()?;
    root.maps = crate::archives::recovery_parent::native_inventory(db.db())?;
    root.data = crate::archives::recovery_data::inventory(&providers)?;
    db.db().put(ROOT_KEY, root.encode()?)?; db.sync_wal()?;
    let controls = external.path().join("archive/recovery").join(hex::encode(root.operation));
    fs::create_dir_all(&controls)?;
    validate_cleaned(&providers, &root)?;
    let artifact = controls.join("selection.v1");
    fs::write(&artifact, b"epoch residue")?;
    assert!(validate_cleaned(&providers, &root).is_err());
    assert_eq!(fs::read(&artifact)?, b"epoch residue");
    drop(providers);
    assert!(RecoveryProviders::inspect(db.clone(), &root, Some(&config), db.repair_protection()).await.is_err());
    assert_eq!(fs::read(&artifact)?, b"epoch residue");
    assert_eq!(db.db().get(ROOT_KEY)?.as_deref(), Some(root.encode()?.as_slice()));
    fs::remove_file(artifact)?;
    drop(RecoveryProviders::inspect(db.clone(), &root, Some(&config), db.repair_protection()).await?);
    Ok(())
}
