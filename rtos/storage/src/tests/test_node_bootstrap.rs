// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::archives::recovery_root::{Inventory, Policy, RootHeader, Sidecar, State, ROOT_KEY};
fn seed(db: &RocksDb, policy: Policy) -> Vec<u8> {
    let identity = db.db().get_db_identity().unwrap();
    RootHeader {
        state: State::Building,
        policy,
        aborted: false,
        operation: [4; 16],
        database_identity_bytes: identity.len() as u64,
        database_identity_digest: sha256_digest(identity),
        selection: Sidecar { bytes: 100, records: 1, digest: [8; 32] },
        ready: Sidecar::default(),
        providers: Inventory::default(),
        maps: Inventory::default(),
        data: Inventory::default(),
    }
    .encode()
    .unwrap()
    .to_vec()
}
#[test]
fn pending_node_root_requires_existing_ledger_and_stays_closed() {
    let dir = tempfile::tempdir().unwrap();
    let config = CellsDbConfig::default();
    let db = open_node_db(dir.path(), &config, AccessType::ReadWrite).unwrap();
    let bytes = seed(&db, Policy::Node);
    db.db().put(ROOT_KEY, &bytes).unwrap();
    db.sync_wal().unwrap();
    drop(db);
    assert!(open_node_db_for_bootstrap(dir.path(), &config, AccessType::ReadWrite).is_err());
    let db = open_node_db(dir.path(), &config, AccessType::ReadWrite).unwrap();
    assert!(db.db().cf_handle("repair_dependency_leases_v1").is_none());
    db.db().create_cf("repair_dependency_leases_v1", &rocksdb::Options::default()).unwrap();
    drop(db);
    let bootstrap = open_node_db_for_bootstrap(dir.path(), &config, AccessType::ReadWrite).unwrap();
    assert!(bootstrap.requires_recovery());
    assert_eq!(bootstrap.database().db().get(ROOT_KEY).unwrap().as_deref(), Some(bytes.as_slice()));
    assert!(bootstrap.finish().is_err());
    assert!(open_node_db_for_bootstrap(dir.path(), &config, AccessType::ReadOnly).is_err());
}
#[test]
fn node_bootstrap_refuses_factory_downgrade_and_wrong_database() {
    let dir = tempfile::tempdir().unwrap();
    let config = CellsDbConfig::default();
    for policy in [Policy::StandaloneWithoutLedger, Policy::StandaloneWithLedger] {
        let db = open_node_db(dir.path(), &config, AccessType::ReadWrite).unwrap();
        db.db().put(ROOT_KEY, seed(&db, policy)).unwrap();
        db.sync_wal().unwrap();
        drop(db);
        assert!(open_node_db_for_bootstrap(dir.path(), &config, AccessType::ReadWrite).is_err());
    }
    let db = open_node_db(dir.path(), &config, AccessType::ReadWrite).unwrap();
    db.db().create_cf("repair_dependency_leases_v1", &rocksdb::Options::default()).unwrap();
    let mut root = RootHeader::decode(&seed(&db, Policy::Node)).unwrap();
    root.database_identity_digest[0] ^= 1;
    db.db().put(ROOT_KEY, root.encode().unwrap()).unwrap();
    db.sync_wal().unwrap();
    drop(db);
    assert!(open_node_db_for_bootstrap(dir.path(), &config, AccessType::ReadWrite).is_err());
}
#[test]
fn ordinary_bootstrap_returns_same_provider_without_creating_dynamic_families() {
    let dir = tempfile::tempdir().unwrap();
    let config = CellsDbConfig::default();
    let bootstrap = open_node_db_for_bootstrap(dir.path(), &config, AccessType::ReadWrite).unwrap();
    assert!(!bootstrap.requires_recovery());
    let db = bootstrap.database().clone();
    assert!(Arc::ptr_eq(&db, &bootstrap.finish().unwrap()));
    assert!(db.db().cf_handle(CELLS_CF_NAME).is_none());
    assert!(db.db().cf_handle(CELLSCOUNTERS_CF_NAME).is_none());
}

#[cfg(unix)]
#[test]
fn ordinary_alias_bootstrap_preserves_owner_but_pending_recovery_refuses_alias() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let config = CellsDbConfig::default();
    let real = dir.path().join("real");
    let alias = dir.path().join("alias");
    let db = open_node_db(&real, &config, AccessType::ReadWrite).unwrap();
    db.db().put(b"unchanged", b"value").unwrap();
    db.sync_wal().unwrap();
    drop(db);
    symlink(&real, &alias).unwrap();
    let bootstrap = open_node_db_for_bootstrap(&alias, &config, AccessType::ReadWrite).unwrap();
    assert!(!bootstrap.requires_recovery());
    assert!(open_node_db(&real, &config, AccessType::ReadWrite).is_err());
    let db = bootstrap.finish().unwrap();
    assert_eq!(db.db().get(b"unchanged").unwrap().as_deref(), Some(b"value".as_slice()));
    db.db().create_cf("repair_dependency_leases_v1", &rocksdb::Options::default()).unwrap();
    let bytes = seed(&db, Policy::Node);
    db.db().put(ROOT_KEY, &bytes).unwrap();
    db.sync_wal().unwrap();
    drop(db);
    assert!(open_node_db_for_bootstrap(&alias, &config, AccessType::ReadWrite).is_err());
    let bootstrap = open_node_db_for_bootstrap(&real, &config, AccessType::ReadWrite).unwrap();
    assert!(bootstrap.requires_recovery());
    assert_eq!(bootstrap.database().db().get(ROOT_KEY).unwrap().as_deref(), Some(bytes.as_slice()));
    assert!(bootstrap.finish().is_err());
}

#[test]
fn ordinary_parent_components_remain_compatible_without_pending_root() {
    let dir = tempfile::tempdir().unwrap();
    let config = CellsDbConfig::default();
    let real = dir.path().join("real");
    std::fs::create_dir(dir.path().join("unused")).unwrap();
    drop(open_node_db(&real, &config, AccessType::ReadWrite).unwrap());
    let ordinary = dir.path().join("unused/../real");
    let bootstrap = open_node_db_for_bootstrap(&ordinary, &config, AccessType::ReadWrite).unwrap();
    assert!(!bootstrap.requires_recovery());
    let db = bootstrap.finish().unwrap();
    db.db().create_cf("repair_dependency_leases_v1", &rocksdb::Options::default()).unwrap();
    db.db().put(ROOT_KEY, seed(&db, Policy::Node)).unwrap();
    db.sync_wal().unwrap();
    drop(db);
    assert!(open_node_db_for_bootstrap(&ordinary, &config, AccessType::ReadWrite).is_err());
    assert!(open_node_db_for_bootstrap(&real, &config, AccessType::ReadWrite)
        .unwrap()
        .requires_recovery());
}

#[test]
fn orphan_selection_refuses_bootstrap_before_ledger_or_service_initialization() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let config = CellsDbConfig::default();
    let db = open_node_db(dir.path(), &config, AccessType::ReadWrite)?;
    db.db().put(b"keep", b"native value")?;
    db.sync_wal()?;
    let names = db.cfs().expect("open database column families");
    drop(db);
    let operation = dir.path().join("archive/recovery").join(hex::encode([4; 16]));
    std::fs::create_dir_all(&operation)?;
    for populated in [false, true] {
        if populated {
            std::fs::write(operation.join("selection.v1"), b"durable selection before Building")?;
        }
        for access in [AccessType::ReadWrite, AccessType::ReadOnly] {
            let error = open_node_db_for_bootstrap(dir.path(), &config, access)
                .err()
                .expect("orphan must refuse bootstrap");
            assert!(
                error.is::<crate::archives::recovery_guard::ArchiveRecoveryRequired>(),
                "{error:#}"
            );
        }
        let db = open_node_db(dir.path(), &config, AccessType::ReadWrite)?;
        assert_eq!(db.cfs().expect("open database column families"), names);
        assert!(db.db().cf_handle("repair_dependency_leases_v1").is_none());
        assert!(db.db().get(ROOT_KEY)?.is_none());
        assert_eq!(db.db().get(b"keep")?.as_deref(), Some(b"native value".as_slice()));
        assert!(operation.is_dir());
    }
    assert_eq!(
        std::fs::read(operation.join("selection.v1"))?,
        b"durable selection before Building"
    );
    std::fs::remove_file(operation.join("selection.v1"))?;
    std::fs::remove_dir(&operation)?;
    let bootstrap = open_node_db_for_bootstrap(dir.path(), &config, AccessType::ReadWrite)?;
    assert!(!bootstrap.requires_recovery());
    drop(bootstrap.finish()?);
    Ok(())
}

#[cfg(unix)]
#[test]
fn ordinary_readonly_alias_allows_empty_control_directory() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let config = CellsDbConfig::default();
    let real = dir.path().join("real");
    let alias = dir.path().join("alias");
    drop(open_node_db(&real, &config, AccessType::ReadWrite)?);
    let controls = real.join("archive/recovery");
    std::fs::create_dir_all(&controls)?;
    std::os::unix::fs::symlink(&real, &alias)?;
    let bootstrap = open_node_db_for_bootstrap(&alias, &config, AccessType::ReadOnly)?;
    assert!(!bootstrap.requires_recovery());
    drop(bootstrap.finish()?);
    let artifact = controls.join("orphan");
    std::fs::write(&artifact, b"keep")?;
    let error = open_node_db_for_bootstrap(&alias, &config, AccessType::ReadOnly)
        .err()
        .expect("orphan through alias");
    assert!(error.is::<crate::archives::recovery_guard::ArchiveRecoveryRequired>());
    assert_eq!(std::fs::read(artifact)?, b"keep");
    Ok(())
}
