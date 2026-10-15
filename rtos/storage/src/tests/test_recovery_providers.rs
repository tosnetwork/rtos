// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::archives::{epoch::{EpochEntry, EpochMeta, write_epoch_meta}, recovery_root::{State, Policy, Sidecar}};
use crate::db::rocksdb::AccessType;
use std::path::Path;
fn root(db: &RocksDb) -> RootHeader {
    let identity = db.db().get_db_identity().unwrap();
    RootHeader { state: State::Building, policy: Policy::Node, aborted: false, operation: [1;16],
        database_identity_bytes: identity.len() as u64, database_identity_digest: rtos_block::sha256_digest(identity),
        selection: Sidecar { bytes: 100, records: 1, digest: [2;32] }, ready: Sidecar::default(),
        providers: Inventory::default(), maps: Inventory::default(), data: Inventory::default() }
}
async fn seed(path: &Path, start: u32) {
    std::fs::create_dir_all(path).unwrap();
    write_epoch_meta(path, &EpochMeta { mc_seq_no_start: start, mc_seq_no_end: start+19_999 }).await.unwrap();
    let db = RocksDb::new(path, "archive_db", None, AccessType::ReadWrite).unwrap();
    db.db().put(b"unchanged", b"data").unwrap(); db.sync_wal().unwrap();
}
fn bytes(provider: &Provider) -> Vec<u8> {
    let mut bytes = Vec::new(); provider.write(&mut bytes).unwrap(); bytes
}
#[tokio::test]
async fn complete_set_includes_main_key_alias_and_noop_external_epochs() -> Result<()> {
    let dir = tempfile::tempdir()?; let external = tempfile::tempdir()?;
    let discovered = dir.path().join("epochs/epoch_1");
    seed(external.path(), 0).await; seed(&discovered, 20_000).await;
    let main = RocksDb::new(dir.path(), "db", None, AccessType::ReadWrite)?;
    let protection = main.repair_protection().clone();
    let config = ArchivalModeConfig { epoch_size: 20_000, new_epochs_path: dir.path().join("epochs"),
        existing_epochs: vec![EpochEntry { path: external.path().into() }] };
    let set = RecoveryProviders::inspect(main.clone(), &root(&main), Some(&config), &protection).await?;
    assert!(Arc::ptr_eq(&set.protection, &protection));
    assert_eq!(set.participants.len(), 3);
    assert_eq!(set.participants[0].descriptor.roles, 3);
    assert!(Arc::ptr_eq(&set.participants[0].database, &main));
    assert_eq!(set.inventory()?.count, 3);
    assert!(RocksDb::new(external.path(), "archive_db", None, AccessType::ReadWrite).is_err());
    let records: Vec<_> = set.participants.iter().map(|p| bytes(&p.descriptor)).collect();
    let mut checker = set.checker();
    for record in &records { checker.record(&mut &record[..], record.len() as u64)?; }
    checker.finish()?;
    let mut missing = set.checker();
    missing.record(&mut &records[0][..], records[0].len() as u64)?;
    assert!(missing.finish().is_err());
    let mut duplicate = set.checker();
    duplicate.record(&mut &records[0][..], records[0].len() as u64)?;
    assert!(duplicate.record(&mut &records[0][..], records[0].len() as u64).is_err());
    assert!(duplicate.finish().is_err());
    let mut extra = set.checker();
    for record in &records { extra.record(&mut &record[..], record.len() as u64)?; }
    assert!(extra.record(&mut &records[0][..], records[0].len() as u64).is_err());
    assert!(extra.finish().is_err());
    let inventory = set.inventory()?;
    drop(set);
    let reopened = RecoveryProviders::inspect(main.clone(), &root(&main), Some(&config), &protection).await?;
    assert_eq!(inventory, reopened.inventory()?);
    for participant in reopened.participants.iter().skip(1) {
        assert_eq!(participant.database.db().get(b"unchanged")?.as_deref(), Some(b"data".as_slice()));
    }
    Ok(())
}
#[tokio::test]
async fn single_provider_main_roles_are_merged_and_wrong_protection_refuses() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let main = RocksDb::new(dir.path(), "db", None, AccessType::ReadWrite)?;
    let set = RecoveryProviders::inspect(main.clone(), &root(&main), None, main.repair_protection()).await?;
    assert_eq!(set.participants.len(), 1); assert_eq!(set.participants[0].descriptor.roles, 7);
    assert!(RecoveryProviders::inspect(main.clone(), &root(&main), None, &Arc::new(RepairProtection::default())).await.is_err());
    Ok(())
}
#[tokio::test]
async fn recovery_enumeration_refuses_metadata_only_and_unknown_directories() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let main = RocksDb::new(dir.path(), "db", None, AccessType::ReadWrite)?;
    let epoch = dir.path().join("epochs/epoch_0"); std::fs::create_dir_all(&epoch)?;
    write_epoch_meta(&epoch, &EpochMeta { mc_seq_no_start: 0, mc_seq_no_end: 19_999 }).await?;
    let config = ArchivalModeConfig { epoch_size: 20_000, new_epochs_path: dir.path().join("epochs"), existing_epochs: vec![] };
    assert!(RecoveryProviders::inspect(main.clone(), &root(&main), Some(&config), main.repair_protection()).await.is_err());
    assert!(!epoch.join("archive_db").exists());
    seed(&epoch, 0).await;
    std::fs::create_dir(config.new_epochs_path.join("unknown"))?;
    assert!(RecoveryProviders::inspect(main.clone(), &root(&main), Some(&config), main.repair_protection()).await.is_err());
    // Rejection did not retain a partial native owner.
    RocksDb::new(&epoch, "archive_db", None, AccessType::ReadWrite)?;
    Ok(())
}
#[tokio::test]
async fn copied_native_provider_refuses_and_releases_partial_owners() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let main = RocksDb::new(dir.path(), "db", None, AccessType::ReadWrite)?;
    let first = dir.path().join("epochs/first"); let second = dir.path().join("epochs/second");
    seed(&first, 0).await; std::fs::create_dir_all(&second)?;
    write_epoch_meta(&second, &EpochMeta { mc_seq_no_start: 20_000, mc_seq_no_end: 39_999 }).await?;
    {
        let source = RocksDb::new(&first, "archive_db", None, AccessType::ReadWrite)?;
        rocksdb::checkpoint::Checkpoint::new(source.db())?.create_checkpoint(second.join("archive_db"))?;
    }
    let config = ArchivalModeConfig { epoch_size: 20_000, new_epochs_path: dir.path().join("epochs"), existing_epochs: vec![] };
    let error = RecoveryProviders::inspect(main.clone(), &root(&main), Some(&config), main.repair_protection()).await.err().unwrap();
    assert!(error.to_string().contains("Duplicate recovery provider"), "{error}");
    for path in [first, second] {
        let db = RocksDb::new(path, "archive_db", None, AccessType::ReadWrite)?;
        assert_eq!(db.db().get(b"unchanged")?.as_deref(), Some(b"data".as_slice()));
    }
    Ok(())
}
