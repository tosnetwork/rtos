// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{archives::{recovery_root::{RootHeader, State, Policy, Sidecar, ROOT_KEY},
    recovery_providers::RecoveryProviders}, db::rocksdb::{RocksDb, AccessType}};
use std::sync::Arc;
fn header(db: &RocksDb) -> RootHeader {
    let id = db.db().get_db_identity().unwrap();
    RootHeader { state: State::Building, policy: Policy::Node, aborted: false, operation: [5;16],
        database_identity_bytes: id.len() as u64, database_identity_digest: rtos_block::sha256_digest(id),
        selection: Sidecar { bytes: 100, records: 1, digest: [6;32] }, ready: Sidecar::default(),
        providers: Inventory::default(), maps: Inventory::default(), data: Inventory::default() }
}
async fn fixture(root: &Path) -> Result<(Arc<RocksDb>, RecoveryProviders, RootHeader)> {
    let db = RocksDb::new(root, "db", None, AccessType::ReadWrite)?;
    let header = header(&db); db.db().put(ROOT_KEY, header.encode()?)?;
    let providers = RecoveryProviders::inspect(db.clone(), &header, None, db.repair_protection()).await?;
    Ok((db, providers, header))
}
fn package(root: &Path, id: u32, bytes: &[u8]) -> Result<PathBuf> {
    let path = PackageId::for_block(id).full_path(root, &ShardIdent::masterchain())?;
    fs::create_dir_all(path.parent().unwrap())?; fs::write(&path, bytes)?; Ok(path)
}
#[tokio::test]
async fn package_bytes_paths_and_metadata_rows_all_change_inventory() -> Result<()> {
    let dir = tempfile::tempdir()?; let (db, providers, _) = fixture(dir.path()).await?;
    let empty = inventory(&providers)?;
    assert_eq!(empty, Inventory { count: 0, digest: rtos_block::sha256_digest([]) });
    let path = package(dir.path(), 0, b"first package bytes")?;
    let first = inventory(&providers)?; assert_eq!(first.count, 1); assert_ne!(first, empty);
    fs::write(&path, b"other package bytes")?; assert_ne!(inventory(&providers)?, first);
    fs::write(&path, b"first package bytes")?; assert_eq!(inventory(&providers)?, first);
    let other = package(dir.path(), 1, b"first package bytes")?;
    assert_eq!(inventory(&providers)?.count, 2);
    fs::remove_file(&path)?; assert_ne!(inventory(&providers)?, first);
    fs::rename(other, &path)?; assert_eq!(inventory(&providers)?, first);
    for kind in ["block_index", "entry_meta", "offsets", "status"] {
        db.db().create_cf(&format!("{kind}_db_0"), &rocksdb::Options::default())?;
    }
    let metadata = inventory(&providers)?; assert_eq!(metadata.count, 5);
    let cf = db.db().cf_handle("offsets_db_0").unwrap();
    db.db().put_cf(&cf, b"entry", b"offset")?;
    let row = inventory(&providers)?; assert_eq!(row.count, 6); assert_ne!(row, metadata);
    db.db().put_cf(&cf, b"entry", b"changed")?; assert_ne!(inventory(&providers)?, row);
    db.db().delete_cf(&cf, b"entry")?; assert_eq!(inventory(&providers)?, metadata);
    db.db().drop_cf("status_db_0")?; assert!(inventory(&providers).is_err());
    Ok(())
}
#[tokio::test]
async fn staging_symlinks_and_unknown_status_are_preserved_and_refused() -> Result<()> {
    let dir = tempfile::tempdir()?; let (db, providers, _) = fixture(dir.path()).await?;
    let path = package(dir.path(), 0, b"original")?;
    let staging = path.with_extension("pack.new"); fs::write(&staging, b"stage")?;
    assert!(inventory(&providers).is_err()); assert_eq!(fs::read(&staging)?, b"stage"); fs::remove_file(staging)?;
    let alias = PackageId::for_block(1).full_path(dir.path(), &ShardIdent::masterchain())?;
    std::os::unix::fs::symlink(&path, &alias)?;
    assert!(inventory(&providers).is_err()); fs::remove_file(alias)?;
    for kind in ["block_index", "entry_meta", "offsets", "status"] {
        db.db().create_cf(&format!("{kind}_db_0"), &rocksdb::Options::default())?;
    }
    let cf = db.db().cf_handle("status_db_0").unwrap();
    db.db().put_cf(&cf, b"unrecognized-control", b"preserve")?;
    assert!(inventory(&providers).is_err());
    assert_eq!(db.db().get_cf(&cf, b"unrecognized-control")?.as_deref(), Some(b"preserve".as_slice()));
    Ok(())
}
#[test]
fn bounded_directory_batches_visit_each_name_in_order() -> Result<()> {
    let dir = tempfile::tempdir()?;
    for n in (0..1100).rev() { fs::write(dir.path().join(format!("{n:04}")), [])?; }
    let mut next = 0;
    sorted_entries(dir.path(), |path| {
        assert_eq!(path.file_name().unwrap().to_str().unwrap(), format!("{next:04}")); next += 1; Ok(())
    })?;
    assert_eq!(next, 1100);
    Ok(())
}
#[tokio::test]
async fn cleaned_bootstrap_checks_actual_data_without_sidecars() -> Result<()> {
    let dir = tempfile::tempdir()?; let (db, providers, mut root) = fixture(dir.path()).await?;
    for name in ["files", "key_files"] { db.db().create_cf(name, &rocksdb::Options::default())?; }
    let path = package(dir.path(), 0, b"canonical data")?;
    root.state = State::Cleaned; root.aborted = true;
    root.providers = providers.inventory()?;
    root.maps = crate::archives::recovery_parent::native_inventory(db.db())?;
    root.data = inventory(&providers)?;
    db.db().put(ROOT_KEY, root.encode()?)?; db.sync_wal()?; drop(providers);
    let checked = RecoveryProviders::inspect(db.clone(), &root, None, db.repair_protection()).await?; drop(checked);
    assert!(!dir.path().join("archive/recovery").exists());
    fs::write(&path, b"different data")?;
    let error = RecoveryProviders::inspect(db.clone(), &root, None, db.repair_protection()).await.err().unwrap();
    assert!(error.to_string().contains("data inventory mismatch"), "{error}");
    assert_eq!(db.db().get(ROOT_KEY)?.as_deref(), Some(root.encode()?.as_slice()));
    assert_eq!(fs::read(path)?, b"different data");
    Ok(())
}

#[test]
fn large_file_digest_matches_independent_stream_hash() -> Result<()> {
    use std::io::Write;
    let dir = tempfile::tempdir()?; let path = dir.path().join("large");
    let mut file = fs::File::create(&path)?;
    let mut expected = Sha256::new(); let chunk = [93u8;4096];
    for _ in 0..2049 { file.write_all(&chunk)?; expected.update(chunk); }
    file.sync_all()?; drop(file);
    let (length, digest) = file_digest(&path)?;
    assert_eq!(length, 2049*4096); assert_eq!(digest, expected.finalize());
    Ok(())
}
#[tokio::test]
async fn impossible_empty_bucket_and_misplaced_package_refuse() -> Result<()> {
    let dir = tempfile::tempdir()?; let (_db, providers, _) = fixture(dir.path()).await?;
    let wrong = dir.path().join("archive/packages/arch4294967295");
    fs::create_dir_all(&wrong)?; assert!(inventory(&providers).is_err()); fs::remove_dir(&wrong)?;
    let path = package(dir.path(), 0, b"preserve")?;
    let bucket = dir.path().join("archive/packages/arch0001"); fs::create_dir(&bucket)?;
    let moved = bucket.join(path.file_name().unwrap()); fs::rename(&path, &moved)?;
    assert!(inventory(&providers).is_err()); assert_eq!(fs::read(moved)?, b"preserve");
    Ok(())
}
