// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{
    archives::{db_provider::SingleDbProvider, recovery_guard::ArchiveRecoveryRequired},
    db::rocksdb::AccessType,
};
use rocksdb::{IteratorMode, Options};
use std::{collections::BTreeMap, fs, path::Path};

type Rows = BTreeMap<String, Vec<(Vec<u8>, Vec<u8>)>>;
fn rows(db: &RocksDb) -> Rows {
    db.cfs()
        .unwrap()
        .into_iter()
        .map(|name| {
            let iter = if name == "default" {
                db.db().iterator(IteratorMode::Start)
            } else {
                db.db().iterator_cf(&db.db().cf_handle(&name).unwrap(), IteratorMode::Start)
            };
            (
                name,
                iter.map(|r| {
                    let (k, v) = r.unwrap();
                    (k.to_vec(), v.to_vec())
                })
                .collect(),
            )
        })
        .collect()
}
#[derive(Debug, PartialEq, Eq)]
enum Entry {
    Directory,
    File(Vec<u8>),
    Link(PathBuf),
}
fn tree(root: &Path) -> BTreeMap<PathBuf, Entry> {
    let mut result = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => panic!("{e}"),
        };
        let entry = if meta.file_type().is_symlink() {
            Entry::Link(fs::read_link(&path).unwrap())
        } else if meta.is_dir() {
            pending.extend(fs::read_dir(&path).unwrap().map(|e| e.unwrap().path()));
            Entry::Directory
        } else {
            Entry::File(fs::read(&path).unwrap())
        };
        result.insert(path, entry);
    }
    result
}
async fn manager(db: &Arc<RocksDb>, root: &Arc<PathBuf>) -> Result<ArchiveManager> {
    let binding = db.bind_archive_domain(crate::archives::context::ArchiveDomain::new())?;
    let startup = binding.view()?.enter()?;
    ArchiveManager::with_data(
        binding.clone(),
        &startup,
        root.clone(),
        Arc::new(SingleDbProvider::new(binding, root.clone())),
        0,
        Arc::new(AtomicU8::new(0)),
        #[cfg(feature = "telemetry")]
        Arc::new(StorageTelemetry::default()),
        Arc::new(StorageAlloc::default()),
    )
    .await
}
fn pending(db: &RocksDb, id: &PackageId) {
    let name = format!(
        "status_{}db_{}",
        if matches!(id.package_type(), PackageType::KeyBlocks) { "key_" } else { "" },
        id.id()
    );
    db.db().create_cf(&name, &Options::default()).unwrap();
    db.db().put_cf(&db.db().cf_handle(&name).unwrap(), b"RepackRecovery", b"pending").unwrap();
}

async fn manager_entry_case(import: bool) {
    for key in [false, true] {
        for mode in ["pending", "packages-link", "archive-link"] {
            if !cfg!(unix) && mode != "pending" {
                continue;
            }
            let dir = tempfile::tempdir().unwrap();
            let external = tempfile::tempdir().unwrap();
            let root = Arc::new(dir.path().to_path_buf());
            let db = RocksDb::new(&*root, "db", None, AccessType::ReadWrite).unwrap();
            let manager = manager(&db, &root).await.unwrap();
            let id =
                if key { PackageId::for_key_block(10000000) } else { PackageId::for_block(100000) };
            match mode {
                "pending" => pending(&db, &id),
                #[cfg(unix)]
                "packages-link" => {
                    std::os::unix::fs::symlink(external.path(), root.join("archive/packages"))
                        .unwrap()
                }
                #[cfg(unix)]
                "archive-link" => {
                    fs::remove_dir_all(root.join("archive")).unwrap();
                    std::os::unix::fs::symlink(external.path(), root.join("archive")).unwrap();
                }
                _ => unreachable!(),
            }
            let before = rows(&db);
            let files = tree(&root.join("archive"));
            let outside = tree(external.path());
            let error = if import {
                manager.get_or_create_import_desc(&id, 0).await.err()
            } else {
                manager.get_file_desc(&id, true).await.err()
            }
            .expect("manager must refuse");
            assert!(error.is::<ArchiveRecoveryRequired>(), "{error:#}");
            assert_eq!(
                tree(&root.join("archive")),
                files,
                "manager changed package directory inventory"
            );
            assert_eq!(tree(external.path()), outside, "manager changed symlink target inventory");
            assert_eq!(rows(&db), before, "manager changed CF or index contents");
        }
    }
}

#[tokio::test]
async fn manager_creation_preserves_inputs() {
    manager_entry_case(false).await;
}
#[tokio::test]
async fn manager_import_preserves_inputs() {
    manager_entry_case(true).await;
}

#[tokio::test]
async fn manager_startup_preserves_unresolved_inputs() {
    for mode in ["pending", "archive-link"] {
        if !cfg!(unix) && mode != "pending" {
            continue;
        }
        let dir = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let root = Arc::new(dir.path().to_path_buf());
        let db = RocksDb::new(&*root, "db", None, AccessType::ReadWrite).unwrap();
        if mode == "pending" {
            pending(&db, &PackageId::for_block(0));
        }
        #[cfg(unix)]
        if mode == "archive-link" {
            std::os::unix::fs::symlink(external.path(), root.join("archive")).unwrap();
        }
        let before = rows(&db);
        let files = tree(&root.join("archive"));
        let outside = tree(external.path());
        let error = manager(&db, &root).await.err().expect("manager startup must refuse");
        assert!(error.is::<ArchiveRecoveryRequired>(), "{error:#}");
        assert_eq!(tree(&root.join("archive")), files);
        assert_eq!(tree(external.path()), outside);
        assert_eq!(rows(&db), before, "manager startup changed CF or index contents");
    }
}
