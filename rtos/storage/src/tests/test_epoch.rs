/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use super::*;

#[tokio::test]
async fn test_epoch_router_validation() {
    let dir = tempfile::tempdir().unwrap();
    let main = RocksDb::new(dir.path(), "main", None, AccessType::ReadWrite).unwrap();
    let binding = main.bind_archive_domain(crate::archives::context::ArchiveDomain::new()).unwrap();
    let startup = binding.view().unwrap().enter().unwrap();

    let config = ArchivalModeConfig {
        epoch_size: 0,
        new_epochs_path: dir.path().to_path_buf(),
        existing_epochs: vec![],
    };
    assert!(EpochRouter::new(&config, &startup).await.is_err());

    let config = ArchivalModeConfig {
        epoch_size: 10_000, // not a multiple of ARCHIVE_SLICE_SIZE
        new_epochs_path: dir.path().to_path_buf(),
        existing_epochs: vec![],
    };
    assert!(EpochRouter::new(&config, &startup).await.is_err());
}

#[tokio::test]
async fn test_epoch_router_resolve_and_create() {
    let dir = tempfile::tempdir().unwrap();
    let main = RocksDb::new(dir.path(), "main", None, AccessType::ReadWrite).unwrap();
    let binding = main.bind_archive_domain(crate::archives::context::ArchiveDomain::new()).unwrap();
    let startup = binding.view().unwrap().enter().unwrap();
    let new_epochs_path = dir.path().join("new_epochs");

    let config = ArchivalModeConfig {
        epoch_size: 40_000,
        new_epochs_path: new_epochs_path.clone(),
        existing_epochs: vec![],
    };

    let router = EpochRouter::new(&config, &startup).await.unwrap();

    // No epochs exist yet
    assert!(router.resolve(0).is_none());
    assert!(router.resolve(39_999).is_none());

    // Create epoch for mc_seq_no 0
    let epoch = router.resolve_or_create(0).await.unwrap();
    assert_eq!(epoch.mc_seq_no_start(), 0);
    assert_eq!(epoch.mc_seq_no_end(), 39_999);
    assert!(epoch.path().starts_with(&new_epochs_path));

    // Resolve same epoch
    let epoch2 = router.resolve(20_000).unwrap();
    assert_eq!(epoch2.mc_seq_no_start(), 0);

    // Create second epoch
    let epoch3 = router.resolve_or_create(50_000).await.unwrap();
    assert_eq!(epoch3.mc_seq_no_start(), 40_000);
    assert_eq!(epoch3.mc_seq_no_end(), 79_999);

    // Verify both exist
    assert!(router.resolve(0).is_some());
    assert!(router.resolve(50_000).is_some());
    assert!(router.resolve(80_000).is_none());
}

#[tokio::test]
async fn test_epoch_router_with_existing_epochs() {
    let dir = tempfile::tempdir().unwrap();
    let main = RocksDb::new(dir.path(), "main", None, AccessType::ReadWrite).unwrap();
    let binding = main.bind_archive_domain(crate::archives::context::ArchiveDomain::new()).unwrap();
    let startup = binding.view().unwrap().enter().unwrap();
    let epoch0_path = dir.path().join("epoch_0");
    let epoch1_path = dir.path().join("epoch_1");
    let new_epochs_path = dir.path().join("new_epochs");

    std::fs::create_dir_all(&epoch0_path).unwrap();
    std::fs::create_dir_all(&epoch1_path).unwrap();

    // Write metadata for existing epochs
    let meta0 = EpochMeta { mc_seq_no_start: 0, mc_seq_no_end: 39_999 };
    let meta1 = EpochMeta { mc_seq_no_start: 40_000, mc_seq_no_end: 79_999 };
    write_epoch_meta(&epoch0_path, &meta0).await.unwrap();
    write_epoch_meta(&epoch1_path, &meta1).await.unwrap();

    let config = ArchivalModeConfig {
        epoch_size: 40_000,
        new_epochs_path,
        existing_epochs: vec![EpochEntry { path: epoch0_path }, EpochEntry { path: epoch1_path }],
    };

    let router = EpochRouter::new(&config, &startup).await.unwrap();

    let e0 = router.resolve(0).unwrap();
    assert_eq!(e0.mc_seq_no_start(), 0);
    assert_eq!(e0.mc_seq_no_end(), 39_999);

    let e1 = router.resolve(40_000).unwrap();
    assert_eq!(e1.mc_seq_no_start(), 40_000);
    assert_eq!(e1.mc_seq_no_end(), 79_999);

    assert!(router.resolve(80_000).is_none());
}

#[tokio::test]
async fn test_epoch_router_rejects_misaligned_existing() {
    let dir = tempfile::tempdir().unwrap();
    let main = RocksDb::new(dir.path(), "main", None, AccessType::ReadWrite).unwrap();
    let binding = main.bind_archive_domain(crate::archives::context::ArchiveDomain::new()).unwrap();
    let startup = binding.view().unwrap().enter().unwrap();
    let epoch_path = dir.path().join("bad_epoch");
    std::fs::create_dir_all(&epoch_path).unwrap();

    // Epoch with wrong size (60_000 != 40_000)
    let meta = EpochMeta { mc_seq_no_start: 0, mc_seq_no_end: 59_999 };
    write_epoch_meta(&epoch_path, &meta).await.unwrap();

    let config = ArchivalModeConfig {
        epoch_size: 40_000,
        new_epochs_path: dir.path().join("new_epochs"),
        existing_epochs: vec![EpochEntry { path: epoch_path }],
    };

    assert!(EpochRouter::new(&config, &startup).await.is_err());
}

#[tokio::test]
async fn test_epoch_router_discovers_on_restart() {
    let dir = tempfile::tempdir().unwrap();
    let main = RocksDb::new(dir.path(), "main", None, AccessType::ReadWrite).unwrap();
    let binding = main.bind_archive_domain(crate::archives::context::ArchiveDomain::new()).unwrap();
    let startup = binding.view().unwrap().enter().unwrap();
    let new_epochs_path = dir.path().join("new_epochs");

    // First "run": create epochs dynamically
    let config = ArchivalModeConfig {
        epoch_size: 40_000,
        new_epochs_path: new_epochs_path.clone(),
        existing_epochs: vec![],
    };
    let router = EpochRouter::new(&config, &startup).await.unwrap();
    router.resolve_or_create(0).await.unwrap();
    router.resolve_or_create(50_000).await.unwrap();
    assert!(router.resolve(0).is_some());
    assert!(router.resolve(50_000).is_some());
    drop(router);

    // Second "run": new router should discover epochs from new_epochs_path
    let config2 = ArchivalModeConfig {
        epoch_size: 40_000,
        new_epochs_path: new_epochs_path.clone(),
        existing_epochs: vec![],
    };
    let router2 = EpochRouter::new(&config2, &startup).await.unwrap();
    let e0 = router2.resolve(0).unwrap();
    assert_eq!(e0.mc_seq_no_start(), 0);
    assert_eq!(e0.mc_seq_no_end(), 39_999);

    let e1 = router2.resolve(50_000).unwrap();
    assert_eq!(e1.mc_seq_no_start(), 40_000);
    assert_eq!(e1.mc_seq_no_end(), 79_999);

    assert!(router2.resolve(80_000).is_none());
}

#[tokio::test]
async fn scan_rejects_conflicting_ranges_before_native_creation() {
    let dir = tempfile::tempdir().unwrap();
    let discovery = dir.path().join("discovery");
    let configured = dir.path().join("configured");
    let duplicate = discovery.join("duplicate");
    for path in [&configured, &duplicate] {
        std::fs::create_dir_all(path).unwrap();
        write_epoch_meta(path, &EpochMeta { mc_seq_no_start: 0, mc_seq_no_end: 39_999 }).await.unwrap();
    }
    let config = ArchivalModeConfig { epoch_size: 40_000, new_epochs_path: discovery,
        existing_epochs: vec![EpochEntry { path: configured.clone() }] };
    assert!(scan_existing(&config, true).await.is_err());
    let main = RocksDb::new(dir.path(), "main", None, AccessType::ReadWrite).unwrap();
    let binding = main.bind_archive_domain(crate::archives::context::ArchiveDomain::new()).unwrap();
    let startup = binding.view().unwrap().enter().unwrap();
    assert!(EpochRouter::new(&config, &startup).await.is_err());
    assert!(!configured.join("archive_db").exists());
    assert!(!duplicate.join("archive_db").exists());
}

#[tokio::test]
async fn scan_deduplicates_same_path_and_preserves_external_explicit_anchor() {
    let dir = tempfile::tempdir().unwrap();
    let external = tempfile::tempdir().unwrap();
    let discovery = dir.path().join("discovery");
    let shared = discovery.join("epoch_0");
    std::fs::create_dir_all(&shared).unwrap();
    write_epoch_meta(&shared, &EpochMeta { mc_seq_no_start: 0, mc_seq_no_end: 39_999 }).await.unwrap();
    write_epoch_meta(external.path(), &EpochMeta { mc_seq_no_start: 40_000, mc_seq_no_end: 79_999 }).await.unwrap();
    let mut config = ArchivalModeConfig { epoch_size: 40_000, new_epochs_path: discovery,
        existing_epochs: vec![EpochEntry { path: external.path().into() }, EpochEntry { path: shared.clone() }] };
    let first = scan_existing(&config, true).await.unwrap();
    config.existing_epochs.reverse();
    let second = scan_existing(&config, true).await.unwrap();
    assert_eq!(first.len(), 2);
    for (a, b) in first.iter().zip(&second) {
        assert_eq!(a.path, b.path); assert_eq!(a.meta.mc_seq_no_start, b.meta.mc_seq_no_start);
        assert!(a.explicit && b.explicit);
        assert!(!a.path.join("archive_db").exists());
    }
    assert_eq!(first[0].path, shared);
    assert_eq!(first[1].path, external.path());
}

#[tokio::test]
async fn complete_scan_refuses_unknown_entries_and_does_not_create_missing_root() {
    let dir = tempfile::tempdir().unwrap();
    let discovery = dir.path().join("discovery");
    let config = ArchivalModeConfig { epoch_size: 40_000, new_epochs_path: discovery.clone(), existing_epochs: vec![] };
    assert!(scan_existing(&config, true).await.unwrap().is_empty());
    assert!(!discovery.exists());
    std::fs::create_dir_all(discovery.join("unknown")).unwrap();
    assert!(scan_existing(&config, true).await.is_err());
    assert!(scan_existing(&config, false).await.unwrap().is_empty());
    std::fs::remove_dir(discovery.join("unknown")).unwrap();
    std::fs::write(discovery.join("unknown"), b"preserve").unwrap();
    assert!(scan_existing(&config, true).await.is_err());
    assert_eq!(std::fs::read(discovery.join("unknown")).unwrap(), b"preserve");
}

#[cfg(unix)]
#[tokio::test]
async fn scan_refuses_symlink_ancestors_and_metadata() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    std::fs::create_dir(&real).unwrap();
    write_epoch_meta(&real, &EpochMeta { mc_seq_no_start: 0, mc_seq_no_end: 39_999 }).await.unwrap();
    symlink(&real, dir.path().join("alias")).unwrap();
    let mut config = ArchivalModeConfig { epoch_size: 40_000, new_epochs_path: dir.path().join("absent"),
        existing_epochs: vec![EpochEntry { path: dir.path().join("alias") }] };
    assert!(scan_existing(&config, true).await.is_err());
    config.existing_epochs[0].path = real.clone();
    std::fs::rename(real.join(EPOCH_META_FILENAME), dir.path().join("saved_meta")).unwrap();
    symlink(dir.path().join("saved_meta"), real.join(EPOCH_META_FILENAME)).unwrap();
    assert!(scan_existing(&config, true).await.is_err());
    assert!(!real.join("archive_db").exists());
}

#[tokio::test]
async fn terminal_epoch_overflow_refuses_before_directory_creation() {
    let dir = tempfile::tempdir().unwrap();
    let main = RocksDb::new(dir.path(), "main", None, AccessType::ReadWrite).unwrap();
    let binding = main.bind_archive_domain(crate::archives::context::ArchiveDomain::new()).unwrap();
    let startup = binding.view().unwrap().enter().unwrap();
    let config = ArchivalModeConfig { epoch_size: 40_000, new_epochs_path: dir.path().join("epochs"), existing_epochs: vec![] };
    let router = EpochRouter::new(&config, &startup).await.unwrap();
    assert!(router.resolve_or_create(u32::MAX).await.is_err());
    assert_eq!(std::fs::read_dir(&config.new_epochs_path).unwrap().count(), 0);
    let start = (u32::MAX / 40_000) * 40_000;
    assert!(EpochRouter::validate_epoch_meta(&EpochMeta { mc_seq_no_start: start, mc_seq_no_end: u32::MAX }, 40_000, dir.path()).is_err());
}

#[tokio::test]
async fn missing_discovery_ancestor_does_not_hide_parent_traversal() {
    let dir = tempfile::tempdir().unwrap();
    let config = ArchivalModeConfig { epoch_size: 40_000,
        new_epochs_path: dir.path().join("missing/../existing"), existing_epochs: vec![] };
    assert!(scan_existing(&config, true).await.is_err());
    assert!(!dir.path().join("missing").exists());
}

#[tokio::test]
async fn copied_native_identity_refuses_router_publication() {
    let dir = tempfile::tempdir().unwrap();
    let main = RocksDb::new(dir.path(), "main", None, AccessType::ReadWrite).unwrap();
    let binding = main.bind_archive_domain(crate::archives::context::ArchiveDomain::new()).unwrap();
    let startup = binding.view().unwrap().enter().unwrap();
    let paths = [dir.path().join("first"), dir.path().join("second")];
    for (i, path) in paths.iter().enumerate() {
        std::fs::create_dir_all(path).unwrap();
        let start = i as u32 * 40_000;
        write_epoch_meta(path, &EpochMeta { mc_seq_no_start: start, mc_seq_no_end: start+39_999 }).await.unwrap();
        let db = RocksDb::new(path, "archive_db", None, AccessType::ReadWrite).unwrap();
        db.db().put(b"preserve", b"old bytes").unwrap(); db.sync_wal().unwrap();
    }
    // Modern RocksDB restores identity from its manifest. Copy an actual
    // checkpoint, not just the legacy IDENTITY file.
    std::fs::remove_dir_all(paths[1].join("archive_db")).unwrap();
    {
        let source = RocksDb::new(&paths[0], "archive_db", None, AccessType::ReadWrite).unwrap();
        rocksdb::checkpoint::Checkpoint::new(source.db()).unwrap()
            .create_checkpoint(paths[1].join("archive_db")).unwrap();
        let copied = RocksDb::new(&paths[1], "archive_db", None, AccessType::ReadWrite).unwrap();
        assert_eq!(source.db().get_db_identity().unwrap(), copied.db().get_db_identity().unwrap());
    }
    let config = ArchivalModeConfig { epoch_size: 40_000, new_epochs_path: dir.path().join("absent"),
        existing_epochs: paths.iter().map(|path| EpochEntry { path: path.clone() }).collect() };
    let error = EpochRouter::new(&config, &startup).await.err().unwrap();
    assert!(error.to_string().contains("Duplicate native identity"), "{error}");
    assert!(!config.new_epochs_path.exists());
    for path in paths {
        let db = RocksDb::new(path, "archive_db", None, AccessType::ReadWrite).unwrap();
        assert_eq!(db.db().get(b"preserve").unwrap().as_deref(), Some(b"old bytes".as_slice()));
    }
}

#[tokio::test]
async fn discovered_provider_binding_survives_actual_restart() {
    let dir = tempfile::tempdir().unwrap();
    let main = RocksDb::new(dir.path(), "main", None, AccessType::ReadWrite).unwrap();
    let binding = main.bind_archive_domain(crate::archives::context::ArchiveDomain::new()).unwrap();
    let startup = binding.view().unwrap().enter().unwrap();
    let config = ArchivalModeConfig { epoch_size: 40_000, new_epochs_path: dir.path().join("epochs"), existing_epochs: vec![] };
    let router = EpochRouter::new(&config, &startup).await.unwrap();
    let before = {
        let epoch = router.resolve_or_create(45_000).await.unwrap();
        let provider = epoch.recovery_provider();
        assert_eq!(provider.anchor, Anchor::Discovery);
        assert_eq!(provider.range, Some((40_000, 79_999)));
        assert_eq!(provider.relative, PathBuf::from("epoch_1"));
        assert_eq!(provider.database, Identity::native(&epoch.db().db().get_db_identity().unwrap()).unwrap());
        provider.digest().unwrap()
    };
    drop(router);
    let router = EpochRouter::new(&config, &startup).await.unwrap();
    assert_eq!(router.resolve(45_000).unwrap().recovery_provider().digest().unwrap(), before);
}

#[tokio::test]
async fn epoch_cannot_reuse_main_native_identity() {
    let dir = tempfile::tempdir().unwrap();
    let main = RocksDb::new(dir.path(), "main", None, AccessType::ReadWrite).unwrap();
    let binding = main.bind_archive_domain(crate::archives::context::ArchiveDomain::new()).unwrap();
    let startup = binding.view().unwrap().enter().unwrap();
    let epoch_path = dir.path().join("epoch"); std::fs::create_dir(&epoch_path).unwrap();
    write_epoch_meta(&epoch_path, &EpochMeta { mc_seq_no_start: 0, mc_seq_no_end: 39_999 }).await.unwrap();
    rocksdb::checkpoint::Checkpoint::new(main.db()).unwrap()
        .create_checkpoint(epoch_path.join("archive_db")).unwrap();
    {
        let copied = RocksDb::new(&epoch_path, "archive_db", None, AccessType::ReadWrite).unwrap();
        assert_eq!(main.db().get_db_identity().unwrap(), copied.db().get_db_identity().unwrap());
    }
    let config = ArchivalModeConfig { epoch_size: 40_000, new_epochs_path: dir.path().join("absent"), existing_epochs: vec![EpochEntry { path: epoch_path }] };
    let error = EpochRouter::new(&config, &startup).await.err().unwrap();
    assert!(error.to_string().contains("Duplicate native identity"), "{error}");
}
