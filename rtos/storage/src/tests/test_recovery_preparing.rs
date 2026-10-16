// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{archives::{recovery_root::{Inventory, Policy, Sidecar, ROOT_KEY}, recovery_parent}, db::rocksdb::{AccessType, RocksDb}};
use rtos_block::sha256_digest;

async fn exercise(unknown: bool) -> Result<()> {
    let directory = tempfile::tempdir()?;
    let db = RocksDb::new(directory.path(), "db", None, AccessType::ReadWrite)?;
    for name in ["files", "key_files"] { db.db().create_cf(name, &rocksdb::Options::default())?; }
    let native = db.db().get_db_identity()?;
    let mut root = RootHeader {
        state: State::Building, policy: Policy::Node, aborted: false, operation: [31; 16],
        database_identity_bytes: native.len() as u64, database_identity_digest: sha256_digest(native),
        selection: Sidecar { bytes: 1, records: 1, digest: [1; 32] }, ready: Sidecar::default(),
        providers: Inventory::default(), maps: Inventory::default(), data: Inventory::default(),
    };
    db.db().put(ROOT_KEY, root.encode()?)?;
    let providers = RecoveryProviders::inspect(db.clone(), &root, None, db.repair_protection()).await?;
    root.state = State::Preparing;
    root.selection = Sidecar::default();
    root.providers = providers.inventory()?;
    root.maps = recovery_parent::native_inventory(db.db())?;
    root.data = recovery_data::inventory(&providers)?;
    db.db().put(ROOT_KEY, root.encode()?)?;
    db.sync_wal()?;
    let operation = crate::archives::recovery_stages::operation(&providers, &root, 0)?;
    fs::create_dir_all(&operation)?;
    let selection = operation.join("selection.v1");
    fs::write(&selection, b"unfinished selection")?;
    if unknown {
        fs::write(operation.join("ready.v1"), b"unowned")?;
        assert!(discard_selection(&providers, &root).is_err());
        assert_eq!(fs::read(&selection)?, b"unfinished selection");
        assert_eq!(db.db().get(ROOT_KEY)?.unwrap(), root.encode()?);
    } else {
        let cleaned = prepare_abort(&providers, &root)?;
        discard_selection(&providers, &root)?;
        assert!(!selection.exists());
        assert_eq!(prepare_abort(&providers, &root)?, cleaned);
        crate::archives::recovery_worker::recover_cleaned(providers, root)?;
        assert!(db.db().get(ROOT_KEY)?.is_none());
        assert!(!operation.exists());
    }
    Ok(())
}
#[tokio::test]
async fn partial_selection_abort_resumes_after_removal() -> Result<()> { exercise(false).await }
#[tokio::test]
async fn preparing_rejects_unowned_artifacts_before_removal() -> Result<()> { exercise(true).await }
