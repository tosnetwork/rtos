// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::archives::recovery_root::{RootHeader, State, Policy, Sidecar, Inventory, ROOT_KEY};
fn seed(db: &RocksDb, policy: Policy) -> Vec<u8> {
    let identity = db.db().get_db_identity().unwrap();
    RootHeader {
        state: State::Building, policy, aborted: false, operation: [4; 16],
        database_identity_bytes: identity.len() as u64, database_identity_digest: sha256_digest(identity),
        selection: Sidecar { bytes: 100, records: 1, digest: [8; 32] },
        ready: Sidecar::default(), providers: Inventory::default(), maps: Inventory::default(), data: Inventory::default(),
    }.encode().unwrap().to_vec()
}
#[test]
fn pending_node_root_requires_existing_ledger_and_stays_closed() {
    let dir = tempfile::tempdir().unwrap(); let config = CellsDbConfig::default();
    let db = open_node_db(dir.path(), &config, AccessType::ReadWrite).unwrap();
    let bytes = seed(&db, Policy::Node);
    db.db().put(ROOT_KEY, &bytes).unwrap(); db.sync_wal().unwrap(); drop(db);
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
    let dir = tempfile::tempdir().unwrap(); let config = CellsDbConfig::default();
    for policy in [Policy::StandaloneWithoutLedger, Policy::StandaloneWithLedger] {
        let db = open_node_db(dir.path(), &config, AccessType::ReadWrite).unwrap();
        db.db().put(ROOT_KEY, seed(&db, policy)).unwrap(); db.sync_wal().unwrap(); drop(db);
        assert!(open_node_db_for_bootstrap(dir.path(), &config, AccessType::ReadWrite).is_err());
    }
    let db = open_node_db(dir.path(), &config, AccessType::ReadWrite).unwrap();
    db.db().create_cf("repair_dependency_leases_v1", &rocksdb::Options::default()).unwrap();
    let mut root = RootHeader::decode(&seed(&db, Policy::Node)).unwrap(); root.database_identity_digest[0] ^= 1;
    db.db().put(ROOT_KEY, root.encode().unwrap()).unwrap(); db.sync_wal().unwrap(); drop(db);
    assert!(open_node_db_for_bootstrap(dir.path(), &config, AccessType::ReadWrite).is_err());
}
#[test]
fn ordinary_bootstrap_returns_same_provider_without_creating_dynamic_families() {
    let dir = tempfile::tempdir().unwrap(); let config = CellsDbConfig::default();
    let bootstrap = open_node_db_for_bootstrap(dir.path(), &config, AccessType::ReadWrite).unwrap();
    assert!(!bootstrap.requires_recovery());
    let db = bootstrap.database().clone();
    assert!(Arc::ptr_eq(&db, &bootstrap.finish().unwrap()));
    assert!(db.db().cf_handle(CELLS_CF_NAME).is_none());
    assert!(db.db().cf_handle(CELLSCOUNTERS_CF_NAME).is_none());
}
