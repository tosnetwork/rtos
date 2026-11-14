// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{
    archives::{
        context::{ArchiveContextError, ArchiveDomain},
        epoch::ArchivalModeConfig,
        file_maps::FileMap,
        package_id::PackageType,
        package_index_db::PackageIndexEntry,
    },
    db::rocksdb::{AccessType, RocksDb},
    StorageAlloc,
};

fn factory() -> (tempfile::TempDir, ArchiveProvider, ArchiveOperation) {
    let dir = tempfile::tempdir().unwrap();
    let db = RocksDb::new(dir.path(), "main", None, AccessType::ReadWrite).unwrap();
    let binding = db.bind_archive_domain(ArchiveDomain::new()).unwrap();
    let operation = binding.view().unwrap().enter().unwrap();
    (dir, binding, operation)
}
fn config(root: &std::path::Path) -> ArchivalModeConfig {
    ArchivalModeConfig {
        epoch_size: 20000,
        new_epochs_path: root.join("epochs"),
        existing_epochs: vec![],
    }
}

#[tokio::test]
async fn epoch_read_resolution_does_not_create_and_pins_cached_destination_during_close() {
    let (dir, binding, operation) = factory();
    let config = config(dir.path());
    let router = Arc::new(EpochRouter::new(&config, &operation).await.unwrap());
    let provider = EpochDbProvider::new(router.clone());
    let missing = provider.resolve_for_read(&operation, 0).await.unwrap();
    assert_eq!(
        std::fs::read_dir(&config.new_epochs_path).unwrap().count(),
        0,
        "readonly epoch lookup created directory or DB"
    );
    assert!(missing.is_none());
    drop(missing);
    let seeded = provider.db_for_archive(&operation, 0).await.unwrap();
    let weak = Arc::downgrade(seeded.provider.db());
    assert!(Arc::ptr_eq(seeded.provider.domain(), binding.domain()));
    drop(seeded);
    let closed = binding.domain().close(0).unwrap();
    let resolved = provider.resolve_for_read(&operation, 100).await.unwrap().unwrap();
    assert!(Arc::ptr_eq(resolved.provider.db(), router.resolve(0).unwrap().db()));
    let missing = provider.resolve_for_read(&operation, 20000).await.unwrap();
    assert!(
        !config.new_epochs_path.join("epoch_1").exists(),
        "readonly epoch lookup created directory or DB"
    );
    assert!(missing.is_none());
    drop(missing);
    assert_eq!(binding.domain().outstanding(), 2);
    drop(router);
    drop(provider);
    drop(operation);
    let ResolvedArchive { provider, root_path: _, operation } = resolved;
    drop(provider);
    assert!(weak.upgrade().is_some(), "destination DB must be held by inherited operation");
    let mut wait = Box::pin(closed.wait());
    assert!(futures::poll!(&mut wait).is_pending());
    drop(wait);
    drop(operation);
    closed.wait().await;
    assert!(weak.upgrade().is_none());
}

#[tokio::test]
async fn providers_refuse_wrong_domain_and_recovery_on_cache_hit_and_miss() {
    let (dir, binding, operation) = factory();
    let (_other_dir, _other_binding, other) = factory();
    let router = Arc::new(EpochRouter::new(&config(dir.path()), &operation).await.unwrap());
    let epoch: Arc<dyn ArchiveDbProvider> = Arc::new(EpochDbProvider::new(router));
    let single: Arc<dyn ArchiveDbProvider> =
        Arc::new(SingleDbProvider::new(binding.clone(), Arc::new(dir.path().to_path_buf())));
    drop(epoch.db_for_archive(&operation, 0).await.unwrap());
    for provider in [&epoch, &single] {
        for id in [0, 20000] {
            let error = provider
                .resolve_for_read(&other, id)
                .await
                .err()
                .expect("cross-domain lookup admitted");
            assert_eq!(
                error.downcast_ref::<ArchiveContextError>(),
                Some(&ArchiveContextError::BindingConflict)
            );
        }
    }
    drop(operation.child().handoff(()));
    for provider in [&epoch, &single] {
        for id in [0, 20000] {
            let error = provider
                .resolve_for_read(&operation, id)
                .await
                .err()
                .expect("recovery-latched read admitted");
            assert_eq!(
                error.downcast_ref::<ArchiveContextError>(),
                Some(&ArchiveContextError::RecoveryRequired(0))
            );
            let error = provider
                .db_for_archive(&operation, id)
                .await
                .err()
                .expect("recovery-latched creation admitted");
            assert_eq!(
                error.downcast_ref::<ArchiveContextError>(),
                Some(&ArchiveContextError::RecoveryRequired(0))
            );
        }
    }
    assert!(!dir.path().join("epochs/epoch_1").exists());
}

#[tokio::test]
async fn file_map_missing_epoch_preserves_index_without_creation() {
    let (dir, binding, operation) = factory();
    let config = config(dir.path());
    let router = Arc::new(EpochRouter::new(&config, &operation).await.unwrap());
    let provider: Arc<dyn ArchiveDbProvider> = Arc::new(EpochDbProvider::new(router));
    let db = binding.db();
    db.db().create_cf("files", &rocksdb::Options::default()).unwrap();
    let row = serde_cbor::to_vec(&PackageIndexEntry::new()).unwrap();
    let cf = db.db().cf_handle("files").unwrap();
    db.db().put_cf(&cf, 0u32.to_le_bytes(), &row).unwrap();
    let error = FileMap::new(
        db.clone(),
        &operation,
        &provider,
        "files",
        PackageType::Blocks,
        100,
        #[cfg(feature = "telemetry")]
        &Arc::new(crate::StorageTelemetry::default()),
        &Arc::new(StorageAlloc::default()),
    )
    .await
    .err()
    .expect("missing indexed epoch must refuse startup");
    assert!(error.to_string().contains("no existing epoch provider"));
    assert_eq!(db.db().get_cf(&cf, 0u32.to_le_bytes()).unwrap().unwrap(), row);
    assert_eq!(std::fs::read_dir(&config.new_epochs_path).unwrap().count(), 0);
}

#[tokio::test]
async fn failed_startup_refuses_router_before_directory_creation() {
    let (dir, _binding, operation) = factory();
    drop(operation.child().handoff(()));
    let config = config(dir.path());
    let error =
        EpochRouter::new(&config, &operation).await.err().expect("failed context admitted startup");
    assert_eq!(
        error.downcast_ref::<ArchiveContextError>(),
        Some(&ArchiveContextError::RecoveryRequired(0))
    );
    assert!(!config.new_epochs_path.exists());
}

#[tokio::test]
async fn file_map_context_refusal_never_deletes_unneeded_index() {
    struct FailAfterResolve(SingleDbProvider);
    #[async_trait::async_trait]
    impl ArchiveDbProvider for FailAfterResolve {
        fn main_binding(&self) -> &ArchiveProvider {
            self.0.main_binding()
        }
        async fn resolve_for_read(
            &self,
            parent: &ArchiveOperation,
            id: u32,
        ) -> Result<Option<ResolvedArchive>> {
            let resolved = self.0.resolve_for_read(parent, id).await?;
            drop(parent.child().handoff(()));
            Ok(resolved)
        }
        async fn db_for_archive(
            &self,
            parent: &ArchiveOperation,
            id: u32,
        ) -> Result<ResolvedArchive> {
            self.0.db_for_archive(parent, id).await
        }
        fn memory_usage(&self) -> crate::RocksDbMemoryUsage {
            Default::default()
        }
    }
    let (dir, binding, operation) = factory();
    let provider: Arc<dyn ArchiveDbProvider> = Arc::new(FailAfterResolve(SingleDbProvider::new(
        binding.clone(),
        Arc::new(dir.path().to_path_buf()),
    )));
    let db = binding.db();
    db.db().create_cf("files", &rocksdb::Options::default()).unwrap();
    let row = serde_cbor::to_vec(&PackageIndexEntry::new()).unwrap();
    let cf = db.db().cf_handle("files").unwrap();
    db.db().put_cf(&cf, 0u32.to_le_bytes(), &row).unwrap();
    let opened = FileMap::new(
        db.clone(),
        &operation,
        &provider,
        "files",
        PackageType::Blocks,
        100,
        #[cfg(feature = "telemetry")]
        &Arc::new(crate::StorageTelemetry::default()),
        &Arc::new(StorageAlloc::default()),
    )
    .await;
    assert_eq!(
        db.db().get_cf(&cf, 0u32.to_le_bytes()).unwrap(),
        Some(row.clone()),
        "context refusal deleted indexed slice"
    );
    let error = opened.err().expect("context refusal was swallowed by FileMap cleanup");
    assert_eq!(
        error.downcast_ref::<ArchiveContextError>(),
        Some(&ArchiveContextError::RecoveryRequired(0))
    );
    assert_eq!(db.db().get_cf(&cf, 0u32.to_le_bytes()).unwrap().unwrap(), row);
    assert!(!dir.path().join("archive").exists());
}
