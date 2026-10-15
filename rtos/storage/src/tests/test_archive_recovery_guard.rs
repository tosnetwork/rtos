// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{
    archives::{
        archive_slice::ArchiveSlice,
        db_provider::{ArchiveDbProvider, EpochDbProvider, SingleDbProvider},
        epoch::{ArchivalModeConfig, EpochRouter},
        file_maps::FileMap,
        package_id::PackageType,
        package_index_db::PackageIndexEntry,
    },
    db::rocksdb::{AccessType, RocksDb, LAST_UNNEEDED_KEY_BLOCK, NODE_STATE_DB_NAME},
    traits::Serializable,
    StorageAlloc,
};
use rocksdb::Options;
use rtos_block::{BlockIdExt, ShardIdent, UInt256};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};

fn snapshot(db: &RocksDb) -> BTreeMap<String, Vec<(Vec<u8>, Vec<u8>)>> {
    db.cfs()
        .unwrap()
        .into_iter()
        .map(|name| {
            let iter = if name == "default" {
                db.db().iterator(IteratorMode::Start)
            } else {
                let cf = db.db().cf_handle(&name).unwrap();
                db.db().iterator_cf(&cf, IteratorMode::Start)
            };
            let rows = iter
                .map(|row| {
                    let (k, v) = row.unwrap();
                    (k.to_vec(), v.to_vec())
                })
                .collect();
            (name, rows)
        })
        .collect()
}
fn package_bytes(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut result = BTreeMap::new();
    let mut pending = vec![root.join("archive")];
    while let Some(path) = pending.pop() {
        if !path.exists() {
            continue;
        }
        if path.is_dir() {
            pending.extend(fs::read_dir(path).unwrap().map(|e| e.unwrap().path()));
        } else {
            result.insert(path.clone(), fs::read(path).unwrap());
        }
    }
    result
}
fn typed(error: anyhow::Error) {
    assert!(
        error.is::<ArchiveRecoveryRequired>(),
        "constructor recovery error type lost: {error:#}"
    );
    assert!(error.context("actual startup caller context").is::<ArchiveRecoveryRequired>());
}
async fn seed(db: &Arc<RocksDb>, root: &Arc<PathBuf>, kind: PackageType) {
    drop(
        ArchiveSlice::new_empty(
            db.clone(),
            root.clone(),
            0,
            kind,
            0,
            #[cfg(feature = "telemetry")]
            Arc::new(crate::StorageTelemetry::default()),
            Arc::new(StorageAlloc::default()),
        )
        .await
        .unwrap(),
    );
}
fn marker(db: &RocksDb, kind: PackageType, key: &[u8]) {
    let name =
        if matches!(kind, PackageType::KeyBlocks) { "status_key_db_0" } else { "status_db_0" };
    db.db().put_cf(&db.db().cf_handle(name).unwrap(), key, b"pending").unwrap();
}
fn staging(root: &Path) {
    let dir = root.join("archive/packages/arch0000");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("archive.00000.pack.new"), b"retain staged bytes").unwrap();
}

async fn constructor_case(mode: &str) {
    for kind in [PackageType::Blocks, PackageType::KeyBlocks] {
        for pending in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let root = Arc::new(dir.path().to_path_buf());
            let db = RocksDb::new(&*root, "db", None, AccessType::ReadWrite).unwrap();
            seed(&db, &root, kind).await;
            // An ordinary reopen could truncate this uncommitted tail.
            use std::io::Write;
            for path in package_bytes(&root).keys() {
                fs::OpenOptions::new()
                    .append(true)
                    .open(path)
                    .unwrap()
                    .write_all(b"uncommitted-tail")
                    .unwrap();
            }
            if pending {
                marker(&db, kind, b"RepackRecovery");
            } else {
                staging(&root);
            }
            let before = snapshot(&db);
            let files = package_bytes(&root);
            match mode {
                "with_data" => {
                    for cleanup in [false, true] {
                        typed(
                            ArchiveSlice::with_data(
                                db.repair_protection().clone(),
                                db.clone(),
                                root.clone(),
                                0,
                                kind,
                                false,
                                cleanup,
                                #[cfg(feature = "telemetry")]
                                Arc::new(crate::StorageTelemetry::default()),
                                Arc::new(StorageAlloc::default()),
                            )
                            .await
                            .err()
                            .expect("startup must refuse"),
                        );
                        assert_eq!(snapshot(&db), before);
                        assert_eq!(package_bytes(&root), files);
                    }
                }
                "new_empty" => typed(
                    ArchiveSlice::new_empty(
                        db.clone(),
                        root.clone(),
                        0,
                        kind,
                        0,
                        #[cfg(feature = "telemetry")]
                        Arc::new(crate::StorageTelemetry::default()),
                        Arc::new(StorageAlloc::default()),
                    )
                    .await
                    .err()
                    .expect("new must refuse"),
                ),
                "new_for_import" => typed(
                    ArchiveSlice::new_for_import(
                        db.clone(),
                        root.clone(),
                        0,
                        kind,
                        0,
                        #[cfg(feature = "telemetry")]
                        Arc::new(crate::StorageTelemetry::default()),
                        Arc::new(StorageAlloc::default()),
                    )
                    .await
                    .err()
                    .expect("import must refuse"),
                ),
                _ => unreachable!(),
            }
            assert_eq!(snapshot(&db), before);
            assert_eq!(package_bytes(&root), files);
        }
    }
}
#[tokio::test]
async fn constructors_with_data_preserve_inputs() {
    constructor_case("with_data").await;
}
#[tokio::test]
async fn constructors_new_empty_preserve_inputs() {
    constructor_case("new_empty").await;
}
#[tokio::test]
async fn constructors_new_for_import_preserve_inputs() {
    constructor_case("new_for_import").await;
}

#[tokio::test]
async fn file_map_preserves_live_index_for_main_and_epoch_providers() {
    for epoch_mode in [false, true] {
        for kind in [PackageType::Blocks, PackageType::KeyBlocks] {
            for unneeded in [false, true] {
                let dir = tempfile::tempdir().unwrap();
                let root = Arc::new(dir.path().to_path_buf());
                let main = RocksDb::new(&*root, "db", None, AccessType::ReadWrite).unwrap();
                let provider: Arc<dyn ArchiveDbProvider> =
                    if epoch_mode && matches!(kind, PackageType::Blocks) {
                        let router = EpochRouter::new(&ArchivalModeConfig {
                            epoch_size: 20000,
                            new_epochs_path: root.join("epochs"),
                            existing_epochs: vec![],
                        })
                        .await
                        .unwrap();
                        Arc::new(EpochDbProvider::new(Arc::new(router)))
                    } else {
                        Arc::new(SingleDbProvider::new(main.clone(), root.clone()))
                    };
                let (db, slice_root) = provider.db_for_archive(0).await.unwrap();
                seed(&db, &slice_root, kind).await;
                marker(&db, kind, b"FutureRecoveryVersion");
                let name =
                    if matches!(kind, PackageType::KeyBlocks) { "key_files" } else { "files" };
                main.db().create_cf(name, &Options::default()).unwrap();
                main.db()
                    .put_cf(
                        &main.db().cf_handle(name).unwrap(),
                        0u32.to_le_bytes(),
                        serde_cbor::to_vec(&PackageIndexEntry::new()).unwrap(),
                    )
                    .unwrap();
                let before_main = snapshot(&main);
                let before_slice = snapshot(&db);
                let files = package_bytes(&slice_root);
                let error = FileMap::new(
                    main.clone(),
                    &provider,
                    name,
                    kind,
                    if unneeded { 100 } else { 0 },
                    #[cfg(feature = "telemetry")]
                    &Arc::new(crate::StorageTelemetry::default()),
                    &Arc::new(StorageAlloc::default()),
                )
                .await
                .err()
                .expect("FileMap must propagate recovery error");
                typed(error);
                assert_eq!(snapshot(&main), before_main);
                assert_eq!(snapshot(&db), before_slice);
                assert_eq!(package_bytes(&slice_root), files);
            }
        }
    }
}

#[tokio::test]
async fn legacy_cleanup_preserves_unresolved_inputs_and_clean_control_drops() {
    for mode in ["ordinary", "key", "unknown", "staging", "clean"] {
        let dir = tempfile::tempdir().unwrap();
        let root = Arc::new(dir.path().to_path_buf());
        let db = RocksDb::new(&*root, "db", None, AccessType::ReadWrite).unwrap();
        seed(&db, &root, PackageType::Blocks).await;
        seed(&db, &root, PackageType::KeyBlocks).await;
        db.db().create_cf(NODE_STATE_DB_NAME, &Options::default()).unwrap();
        let id = BlockIdExt::with_params(
            ShardIdent::masterchain(),
            100,
            UInt256::default(),
            UInt256::default(),
        );
        db.db()
            .put_cf(
                &db.db().cf_handle(NODE_STATE_DB_NAME).unwrap(),
                LAST_UNNEEDED_KEY_BLOCK,
                id.serialize(),
            )
            .unwrap();
        for i in 0..105 {
            db.db().create_cf(&format!("guard_padding_{i}"), &Options::default()).unwrap();
        }
        match mode {
            "ordinary" => marker(&db, PackageType::Blocks, b"RepackRecovery"),
            "key" => marker(&db, PackageType::KeyBlocks, b"RepackRecovery"),
            "unknown" => marker(&db, PackageType::Blocks, b"UnknownRecoveryVersion"),
            "staging" => staging(&root),
            _ => {}
        }
        let before = snapshot(&db);
        let files = package_bytes(&root);
        db.sync_wal().unwrap();
        drop(db);
        let db = RocksDb::new(&*root, "db", None, AccessType::ReadWrite).unwrap();
        if mode == "clean" {
            assert!(db.db().cf_handle("status_db_0").is_none());
            assert!(db.db().cf_handle("entry_meta_db_0").is_none());
        } else {
            assert_eq!(snapshot(&db), before, "unresolved cleanup changed archive CF contents");
        }
        assert_eq!(package_bytes(&root), files);
    }
}

#[test]
fn inspection_errors_are_typed_and_never_report_clear() {
    let dir = tempfile::tempdir().unwrap();
    let db = RocksDb::new(dir.path(), "db", None, AccessType::ReadWrite).unwrap();
    typed(ensure_provider_clear(db.db(), dir.path(), &["status_db_0".into()]).unwrap_err());
    fs::write(dir.path().join("archive"), b"not a directory").unwrap();
    typed(ensure_slice_clear(db.db(), dir.path(), 0, false).unwrap_err());
    assert_eq!(fs::read(dir.path().join("archive")).unwrap(), b"not a directory");
}

#[cfg(unix)]
#[tokio::test]
async fn dangling_package_ancestors_preserve_cleanup_inputs() {
    use std::os::unix::fs::symlink;
    for ancestor in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let root = Arc::new(dir.path().to_path_buf());
        let db = RocksDb::new(&*root, "db", None, AccessType::ReadWrite).unwrap();
        for name in ["entry_meta_db_0", "offsets_db_0", "status_db_0", NODE_STATE_DB_NAME] {
            db.db().create_cf(name, &Options::default()).unwrap();
        }
        let id = BlockIdExt::with_params(
            ShardIdent::masterchain(),
            100,
            UInt256::default(),
            UInt256::default(),
        );
        db.db()
            .put_cf(
                &db.db().cf_handle(NODE_STATE_DB_NAME).unwrap(),
                LAST_UNNEEDED_KEY_BLOCK,
                id.serialize(),
            )
            .unwrap();
        for i in 0..105 {
            db.db().create_cf(&format!("padding_{i}"), &Options::default()).unwrap();
        }
        let link = if ancestor {
            root.join("archive")
        } else {
            fs::create_dir(root.join("archive")).unwrap();
            root.join("archive/packages")
        };
        symlink(root.join("missing-target"), &link).unwrap();
        let before = snapshot(&db);
        drop(db);
        let db = RocksDb::new(&*root, "db", None, AccessType::ReadWrite).unwrap();
        assert_eq!(snapshot(&db), before);
        typed(ensure_slice_clear(db.db(), &root, 0, false).unwrap_err());
        assert_eq!(fs::read_link(link).unwrap(), root.join("missing-target"));
    }
}
