/*
 * RTOS project modifications (2026-10-10): archive group allocation and resume regression tests.
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
#[cfg(feature = "telemetry")]
use crate::StorageTelemetry;
use crate::{
    archives::{
        archive_manager::ArchiveManager,
        db_provider::{ArchiveDbProvider, EpochDbProvider, SingleDbProvider},
        epoch::{ArchivalModeConfig, EpochRouter},
        package_entry_id::{GetFileName, PackageEntryId},
        ARCHIVE_PACKAGE_SIZE, ARCHIVE_SLICE_SIZE,
    },
    block_handle_db::{BlockHandleStorage, FLAG_KEY_BLOCK},
    db::rocksdb::{destroy_rocks_db, AccessType, RocksDb},
    tests::utils::create_block_handle_storage,
    types::BlockMeta,
    StorageAlloc,
};
use rtos_block::{error, AccountIdPrefixFull, BlockIdExt, Result, ShardIdent, UInt256};
use std::{
    collections::HashMap,
    path::Path,
    sync::{atomic::AtomicU8, Arc},
};

const DB_PATH: &str = "../../target/test";

const TESTDATA_PATH: &str = "src/tests/testdata/";
const ARCHIVE_00000_GOLD: &str = "archive.00000-2.pack.gold";
const ARCHIVE_00100_GOLD: &str = "archive.00100.pack.gold";
const ARCHIVE_00200_GOLD: &str = "archive.00200.pack.gold";

async fn create_manager(
    root: &str,
    name: &str,
    cleanup: bool,
) -> Result<(ArchiveManager, Arc<RocksDb>)> {
    let path = Path::new(root).join(name);
    if cleanup {
        std::fs::remove_dir_all(&path).ok();
    }
    let db = RocksDb::new(root, name, None, AccessType::ReadWrite)?;
    let db_root_path = Arc::new(path);
    let db_provider = Arc::new(SingleDbProvider::new(db.clone(), db_root_path.clone()));
    let manager = ArchiveManager::with_data(
        db.clone(),
        db_root_path,
        db_provider,
        0,
        Arc::new(AtomicU8::new(0)),
        #[cfg(feature = "telemetry")]
        Arc::new(StorageTelemetry::default()),
        Arc::new(StorageAlloc::default()),
    )
    .await?;
    Ok((manager, db))
}

async fn test_downloading(manager: &ArchiveManager, mc_seq_no: u32, gold_path: &str) -> Result<()> {
    let archive_id = manager.get_archive_id(mc_seq_no, &ShardIdent::masterchain()).await.unwrap();
    let mut data = Vec::new();
    let mut offset = 0;
    const ARCHIVE_PACKAGE_SIZE: u32 = 1024;
    loop {
        let slice = manager.get_archive_slice(archive_id, offset, ARCHIVE_PACKAGE_SIZE).await?;
        data.extend_from_slice(&slice[..]);
        if slice.len() < ARCHIVE_PACKAGE_SIZE as usize {
            break;
        }
        offset += slice.len() as u64;
    }
    assert_eq!(
        &data[..],
        tokio::fs::read(Path::new(TESTDATA_PATH).join(gold_path)).await.unwrap().as_slice()
    );
    Ok(())
}

#[tokio::test]
async fn test_scenario() -> Result<()> {
    const DB_NAME: &str = "test_archive_manager_scenario";

    let (manager, db) = create_manager(DB_PATH, DB_NAME, true).await?;
    let (block_handle_storage, _) = create_block_handle_storage(db.clone());

    let data = vec![1, 2, 3, 4, 5];
    for mc_seq_no in 0..250 {
        let block_id = BlockIdExt::with_params(
            ShardIdent::masterchain(),
            mc_seq_no,
            UInt256::with_array([mc_seq_no as u8; 32]),
            UInt256::default(),
        );
        let meta = BlockMeta::with_data(0, 0, 0, 0, 0);
        let handle = block_handle_storage
            .create_handle(block_id.clone(), meta, None)?
            .ok_or_else(|| error!("Cannot create handle for block {}", block_id))?;

        let entry_id = PackageEntryId::Proof(&block_id);
        manager.add_file(&entry_id, &data).await?;
        handle.set_proof();
        handle.set_block_applied();
        manager.move_to_archive(&handle, || Ok(())).await?;
    }

    let shard = ShardIdent::masterchain();
    for mc_seq_no in 0..300 {
        assert_eq!(
            manager.get_archive_id(mc_seq_no, &shard).await,
            Some(((mc_seq_no - mc_seq_no % ARCHIVE_PACKAGE_SIZE) as u64) << 32),
            "mc_seq_no = {}",
            mc_seq_no
        );
    }

    assert!(manager.get_archive_id(300, &shard).await.is_none());

    test_downloading(&manager, 0, ARCHIVE_00000_GOLD).await?;
    test_downloading(&manager, 100, ARCHIVE_00100_GOLD).await?;
    test_downloading(&manager, 222, ARCHIVE_00200_GOLD).await?;

    drop(block_handle_storage);
    drop(manager);
    drop(db);
    destroy_rocks_db(DB_PATH, DB_NAME).await?;
    Ok(())
}

#[tokio::test]
async fn test_scenario_keyblocks_10m() -> Result<()> {
    const DB_NAME: &str = "test_scenario_keyblocks_10m";

    let (manager, db) = create_manager(DB_PATH, DB_NAME, true).await?;
    let (block_handle_storage, _) = create_block_handle_storage(db.clone());

    let data = vec![1, 2, 3, 4, 5];
    let numbers = vec![7, 43, 560, 5480, 95480, 134354, 3548755, 10174254, 101574254, 1343548755];

    for mc_seq_no in numbers {
        let block_id = BlockIdExt::with_params(
            ShardIdent::masterchain(),
            mc_seq_no,
            UInt256::from_le_bytes(&mc_seq_no.to_le_bytes()),
            UInt256::default(),
        );
        let meta = BlockMeta::with_data(FLAG_KEY_BLOCK, 0, 0, 0, 0);

        let entry_id = PackageEntryId::Proof(&block_id);

        manager.add_file(&entry_id, &data).await?;

        let handle = block_handle_storage
            .create_handle(block_id.clone(), meta, None)?
            .ok_or_else(|| error!("Cannot create handle for block {}", block_id))?;

        handle.set_proof();
        handle.set_block_applied();
        manager.move_to_archive(&handle, || Ok(())).await?;
        handle.set_archived();
        assert!(handle.is_key_block()?);
        assert!(handle.has_proof());
        assert!(handle.is_archived());
        block_handle_storage.save_handle(&handle, None)?;

        tokio::time::sleep(std::time::Duration::from_millis(1)).await;

        let block_id = BlockIdExt::with_params(
            ShardIdent::masterchain(),
            mc_seq_no,
            UInt256::from_le_bytes(&mc_seq_no.to_le_bytes()),
            UInt256::default(),
        );
        let handle = block_handle_storage
            .load_handle_by_id(&block_id)?
            .ok_or_else(|| error!("Cannot load handle for block {}", block_id))?;
        assert!(handle.has_proof());
        assert!(handle.is_archived());
        assert!(handle.is_key_block()?);

        let entry_id = PackageEntryId::Proof(&block_id);
        manager.get_file(&handle, &entry_id).await?;
    }

    drop(block_handle_storage);
    drop(manager);
    drop(db);
    destroy_rocks_db(DB_PATH, DB_NAME).await.unwrap();
    Ok(())
}

fn generate_block_id(workchain_id: i32, shard_prefix_tagged: u64, seq_no: u32) -> BlockIdExt {
    let shard_id = ShardIdent::with_tagged_prefix(workchain_id, shard_prefix_tagged).unwrap();
    BlockIdExt::with_params(shard_id, seq_no, UInt256::rand(), UInt256::rand())
}

fn generate_short_filename(id: &BlockIdExt) -> String {
    PackageEntryId::ProofLink(id).filename_short()
}

#[tokio::test]
async fn test_clean_unapplied_files() -> Result<()> {
    const DB_NAME: &str = "clean_db";

    let (manager, db) = create_manager(DB_PATH, DB_NAME, true).await?;

    let id = generate_block_id(555, 0xF8000000_00000000, 100);
    let filename = generate_short_filename(&id);
    let path = manager.unapplied_files_path().join(filename);

    std::fs::write(&path, "test").unwrap();

    let id = generate_block_id(555, 0xF8000000_00000000, 99);
    manager.clean_unapplied_files(&[id]).await;

    assert!(path.exists(), "file {:?} must not be removed", path);

    let id = generate_block_id(333, 0xF8000000_00000000, 101);
    manager.clean_unapplied_files(&[id]).await;

    assert!(path.exists(), "file {:?} must not be removed", path);

    let id = generate_block_id(555, 0xE8000000_00000000, 101);
    manager.clean_unapplied_files(&[id]).await;

    assert!(path.exists(), "file {:?} must not be removed", path);

    let id = generate_block_id(555, 0xF8000000_00000000, 101);
    manager.clean_unapplied_files(&[id]).await;

    assert!(!path.exists(), "file {:?} must be removed", path);

    drop(manager);
    drop(db);
    destroy_rocks_db(DB_PATH, DB_NAME).await.unwrap();
    Ok(())
}

#[allow(dead_code)]
struct TestArchiveManager {
    db: Arc<RocksDb>,
    archive_manager: ArchiveManager,
    block_handle_storage: BlockHandleStorage,
}

impl TestArchiveManager {
    async fn new(root: &str, name: &str) -> Result<Self> {
        let (archive_manager, db) = create_manager(root, name, true).await?;
        let (block_handle_storage, _) = create_block_handle_storage(db.clone());
        Ok(Self { db, archive_manager, block_handle_storage })
    }

    fn master_block_id(mc_seq_no: u32, version: u8) -> BlockIdExt {
        BlockIdExt::with_params(
            ShardIdent::masterchain(),
            mc_seq_no,
            UInt256::from_le_bytes(&mc_seq_no.to_le_bytes()),
            UInt256::from_le_bytes(&[version]),
        )
    }

    async fn add_entries(
        &self,
        range: impl IntoIterator<Item = u32>,
        version: u8,
        key_blocks: &[u32],
    ) {
        for mc_seq_no in range {
            let block_id = Self::master_block_id(mc_seq_no, version);
            let flags = if key_blocks.contains(&mc_seq_no) { FLAG_KEY_BLOCK } else { 0 };
            let meta = BlockMeta::with_data(flags, 0, 0, 0, 0);
            let handle = self
                .block_handle_storage
                .create_handle(block_id.clone(), meta, None)
                .unwrap()
                .unwrap();
            let entry_id = PackageEntryId::Block(&block_id);
            self.archive_manager.add_file(&entry_id, &[1, 2, 3, 4, 5]).await.unwrap();
            handle.set_data();
            let entry_id = PackageEntryId::Proof(&block_id);
            self.archive_manager.add_file(&entry_id, &[6, 7, 8, 9]).await.unwrap();
            handle.set_proof();
            handle.set_block_applied();
            self.archive_manager.move_to_archive(&handle, || Ok(())).await.unwrap();
            handle.set_archived();
            assert!(handle.is_archived());
            self.block_handle_storage.save_handle(&handle, None).unwrap();
        }
    }

    async fn trunc_with_check(&self, mc_seq_no: u32, version: u8) {
        let trunc_block_id = Self::master_block_id(mc_seq_no, version);
        println!("trunc on {}", trunc_block_id);
        self.archive_manager
            .trunc(&trunc_block_id, &|id: &BlockIdExt| id.seq_no() >= trunc_block_id.seq_no())
            .await
            .unwrap();

        let block_id = Self::master_block_id(mc_seq_no - 1, version);
        let handle = self.block_handle_storage.load_handle_by_id(&block_id).unwrap().unwrap();
        let entry_id = PackageEntryId::Block(&block_id);
        self.archive_manager.get_file(&handle, &entry_id).await.unwrap();
        let entry_id = PackageEntryId::Proof(&block_id);
        self.archive_manager.get_file(&handle, &entry_id).await.unwrap();

        let handle = self.block_handle_storage.load_handle_by_id(&trunc_block_id).unwrap().unwrap();
        let entry_id = PackageEntryId::Block(&trunc_block_id);
        self.archive_manager
            .get_file(&handle, &entry_id)
            .await
            .expect_err("block should not be read");
        let entry_id = PackageEntryId::Proof(&trunc_block_id);
        self.archive_manager
            .get_file(&handle, &entry_id)
            .await
            .expect_err("proof should not be read");

        let block_id = Self::master_block_id(mc_seq_no + 1, version);
        let handle = self.block_handle_storage.load_handle_by_id(&block_id).unwrap().unwrap();
        let entry_id = PackageEntryId::Block(&block_id);
        self.archive_manager
            .get_file(&handle, &entry_id)
            .await
            .expect_err("block should not be read");
        let entry_id = PackageEntryId::Proof(&block_id);
        self.archive_manager
            .get_file(&handle, &entry_id)
            .await
            .expect_err("proof should not be read");
    }
}

#[tokio::test]
async fn test_archive_truncate() {
    const DB_NAME: &str = "node_db_slices";
    destroy_rocks_db(DB_PATH, DB_NAME).await.ok();

    let manager = TestArchiveManager::new(DB_PATH, DB_NAME).await.unwrap();

    manager.add_entries(1..306, 0, &[53]).await;
    manager.trunc_with_check(54, 0).await;
    manager.trunc_with_check(53, 0).await;
    manager.trunc_with_check(52, 0).await;

    manager.add_entries(500..700, 1, &[500]).await;

    manager.add_entries(10_000_000..10_000_070, 1, &[10_000_000, 10_000_053]).await;
    manager.trunc_with_check(10_000_054, 1).await;
    manager.trunc_with_check(10_000_053, 1).await;
    manager.trunc_with_check(10_000_001, 1).await;

    drop(manager);
    destroy_rocks_db(DB_PATH, DB_NAME).await.unwrap()
}

#[tokio::test]
async fn test_block_index() -> Result<()> {
    // crate::tests::utils::init_test_log();
    // std::env::set_var("RUST_BACKTRACE", "full");

    fn make_data(id: &BlockIdExt) -> Vec<u8> {
        let mut data = id.shard().shard_prefix_with_tag().to_le_bytes().to_vec();
        data.extend_from_slice(&id.seq_no().to_le_bytes());
        data
    }
    fn make_proof(id: &BlockIdExt) -> Vec<u8> {
        let mut data = id.shard().shard_prefix_with_tag().to_be_bytes().to_vec();
        data.extend_from_slice(&id.seq_no().to_be_bytes());
        data
    }

    const DB_NAME: &str = "test_block_index";

    let cleanup = true;
    let (manager, db) = create_manager(DB_PATH, DB_NAME, cleanup).await?;
    let (block_handle_storage, _) = create_block_handle_storage(db.clone());

    let total_mc_blocks = 41_000;
    let init_utime = 1760361100;
    let mut gen_utime = init_utime;
    let mut lt = 1_000_000;

    if cleanup {
        let mut shards_seqno = HashMap::new();
        shards_seqno.insert(ShardIdent::with_tagged_prefix(0, 0x4000_0000_0000_0000)?, 1);
        shards_seqno.insert(ShardIdent::with_tagged_prefix(0, 0xc000_0000_0000_0000)?, 1);
        for mc_seqno in 1..total_mc_blocks {
            let id = generate_block_id(-1, 0x8000_0000_0000_0000, mc_seqno);
            manager.add_file(&PackageEntryId::Block(&id), &make_data(&id)).await?;
            manager.add_file(&PackageEntryId::Proof(&id), &make_proof(&id)).await?;
            let flags = if rand::random::<u16>() % 12345 == 0 { FLAG_KEY_BLOCK } else { 0 };
            let block_meta = BlockMeta::with_data(flags, gen_utime, lt, mc_seqno, 0);
            let handle = block_handle_storage.create_handle(id.clone(), block_meta, None)?.unwrap();
            handle.set_data();
            handle.set_proof();
            handle.set_state();
            manager.move_to_archive(&handle, || Ok(())).await?;
            handle.set_block_applied();
            block_handle_storage.save_handle(&handle, None)?;

            for (shard_id, seqno) in shards_seqno.iter_mut() {
                for i in 0..rand::random::<u8>() % 2 {
                    let id = generate_block_id(
                        shard_id.workchain_id(),
                        shard_id.shard_prefix_with_tag(),
                        *seqno,
                    );
                    manager.add_file(&PackageEntryId::Block(&id), &make_data(&id)).await?;
                    manager.add_file(&PackageEntryId::ProofLink(&id), &make_proof(&id)).await?;
                    let block_meta =
                        BlockMeta::with_data(0, gen_utime, lt + i as u64 * 1_000_000, mc_seqno, 0);
                    let handle =
                        block_handle_storage.create_handle(id.clone(), block_meta, None)?.unwrap();
                    handle.set_data();
                    handle.set_proof_link();
                    handle.set_state();
                    manager.move_to_archive(&handle, || Ok(())).await?;
                    handle.set_block_applied();
                    block_handle_storage.save_handle(&handle, None)?;
                    *seqno += 1;
                }
                if rand::random::<u16>() % 3 != 0 {
                    gen_utime += 1;
                }
            }

            gen_utime += 1;
            lt += 4_000_000;

            if mc_seqno % 1_000 == 0 {
                println!("Added {} mc blocks", mc_seqno);
            }
        }
    } else {
        lt = 4_000_000 * (total_mc_blocks - 1) as u64;
        gen_utime = init_utime + (total_mc_blocks);
    }

    for _ in 0..20_000 {
        let lt = rand::random::<u64>() % (lt - 4_000_000);
        log::info!("lookup by lt {}", lt);
        let prefix = AccountIdPrefixFull { workchain_id: -1, prefix: rand::random::<u64>() };
        let (id, data) = manager.lookup_block_by_lt(&prefix, lt).await?.unwrap();
        assert_eq!(data, make_data(&id));

        let seqno = rand::random::<u32>() % (total_mc_blocks - 1) + 1;
        log::info!("lookup by seqno {}", seqno);
        let prefix = AccountIdPrefixFull { workchain_id: -1, prefix: rand::random::<u64>() };
        let (id, data) = manager.lookup_block_by_seqno(&prefix, seqno).await?.unwrap();
        assert_eq!(data, make_data(&id));
        let (id, data) = manager.lookup_proof_by_seqno(&prefix, seqno).await?.unwrap();
        assert_eq!(data, make_proof(&id));

        let mut found = 0;
        let mut ids = vec![];
        let utime = init_utime + (rand::random::<u32>() % (gen_utime - init_utime)) - 100;
        log::info!("lookup by utime {}", utime);
        let prefix = AccountIdPrefixFull { workchain_id: 0, prefix: rand::random::<u64>() };
        manager
            .lookup_blocks_by_utime(
                &prefix,
                utime,
                Box::new(|id, data| {
                    assert_eq!(data, make_data(&id));
                    found += 1;
                    ids.push(id);
                    Ok(true)
                }),
            )
            .await?;
        assert!(found > 0);
        for id in ids {
            let (id, data) = manager
                .lookup_proof_by_seqno(&id.shard().account_id_prefix(), id.seq_no())
                .await?
                .unwrap();
            assert_eq!(data, make_proof(&id));
        }
    }
    assert_eq!(manager.get_max_mc_seqno().await, Some(total_mc_blocks - 1));

    drop(block_handle_storage);
    drop(manager);
    drop(db);

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    let (manager, db) = create_manager(DB_PATH, DB_NAME, false).await?;

    let lt = 1_000_000 + 19_998 * 4_000_000 + 100;
    log::info!("lookup by lt {}", lt);
    let prefix = AccountIdPrefixFull { workchain_id: -1, prefix: rand::random::<u64>() };
    let (id, data) = manager.lookup_block_by_lt(&prefix, lt).await?.unwrap();
    assert_eq!(data, make_data(&id));
    assert_eq!(id.seq_no(), 20_000);

    let lt = 1_000_000 + 19_999 * 4_000_000 - 100;
    log::info!("lookup by lt {}", lt);
    let prefix = AccountIdPrefixFull { workchain_id: -1, prefix: rand::random::<u64>() };
    let (id, data) = manager.lookup_block_by_lt(&prefix, lt).await?.unwrap();
    assert_eq!(data, make_data(&id));
    assert_eq!(id.seq_no(), 20_000);

    assert_eq!(manager.get_max_mc_seqno().await, Some(total_mc_blocks - 1));

    for _ in 0..20_000 {
        let lt = rand::random::<u64>() % lt;
        log::info!("lookup by lt {}", lt);
        let prefix = AccountIdPrefixFull { workchain_id: 0, prefix: rand::random::<u64>() };
        let (id, data) = manager.lookup_block_by_lt(&prefix, lt).await?.unwrap();
        assert_eq!(data, make_data(&id));

        let seqno = rand::random::<u32>() % (total_mc_blocks * 4);
        log::info!("lookup by seqno {}", seqno);
        let prefix = AccountIdPrefixFull { workchain_id: -1, prefix: rand::random::<u64>() };
        if let Some((id, data)) = manager.lookup_block_by_seqno(&prefix, seqno).await? {
            assert_eq!(data, make_data(&id));
        }
        if let Some((id, data)) = manager.lookup_proof_by_seqno(&prefix, seqno).await? {
            assert_eq!(data, make_proof(&id));
        }

        let mut found = 0;
        let mut ids = vec![];
        let utime = init_utime + rand::random::<u32>() % (gen_utime - init_utime) - 100;
        log::info!("lookup by utime {}", utime);
        let prefix = AccountIdPrefixFull { workchain_id: -1, prefix: rand::random::<u64>() };
        manager
            .lookup_blocks_by_utime(
                &prefix,
                utime,
                Box::new(|id, data| {
                    assert_eq!(data, make_data(&id));
                    found += 1;
                    ids.push(id);
                    Ok(true)
                }),
            )
            .await?;
        assert!(found > 0);
        for id in ids {
            let (id, data) = manager
                .lookup_proof_by_seqno(&id.shard().account_id_prefix(), id.seq_no())
                .await?
                .unwrap();
            assert_eq!(data, make_proof(&id));
        }
    }

    drop(manager);
    drop(db);
    destroy_rocks_db(DB_PATH, DB_NAME).await.unwrap();
    Ok(())
}

// --- Archival mode (epoch-based) tests ---

fn mc_block_id(mc_seq_no: u32) -> BlockIdExt {
    BlockIdExt::with_params(
        ShardIdent::masterchain(),
        mc_seq_no,
        UInt256::from_le_bytes(&mc_seq_no.to_le_bytes()),
        UInt256::default(),
    )
}

async fn write_blocks(
    manager: &ArchiveManager,
    bhs: &BlockHandleStorage,
    range: std::ops::Range<u32>,
    data: &[u8],
) -> Result<()> {
    for mc_seq_no in range {
        let block_id = mc_block_id(mc_seq_no);
        let meta = BlockMeta::with_data(0, 0, 0, 0, 0);
        let handle = bhs
            .create_handle(block_id.clone(), meta, None)?
            .ok_or_else(|| error!("Cannot create handle for block {}", block_id))?;
        manager.add_file(&PackageEntryId::Proof(&block_id), data).await?;
        handle.set_proof();
        handle.set_block_applied();
        manager.move_to_archive(&handle, || Ok(())).await?;
        handle.set_archived();
        bhs.save_handle(&handle, None)?;
    }
    Ok(())
}

async fn read_block(
    manager: &ArchiveManager,
    bhs: &BlockHandleStorage,
    mc_seq_no: u32,
) -> Result<Vec<u8>> {
    let block_id = mc_block_id(mc_seq_no);
    let handle = bhs.load_handle_by_id(&block_id)?.unwrap();
    manager.get_file(&handle, &PackageEntryId::Proof(&block_id)).await
}

async fn create_epoch_manager(
    dir: &Path,
) -> Result<(ArchiveManager, Arc<RocksDb>, Arc<EpochRouter>)> {
    let db_root = dir.join("main_db");
    let new_epochs_path = dir.join("new_epochs");

    let config = ArchivalModeConfig {
        epoch_size: ARCHIVE_SLICE_SIZE,
        new_epochs_path,
        existing_epochs: vec![],
    };

    let db = RocksDb::new(&db_root, "db", None, AccessType::ReadWrite)?;
    let db_root_path = Arc::new(db_root);

    let router = Arc::new(EpochRouter::new(&config).await?);
    let db_provider: Arc<dyn ArchiveDbProvider> = Arc::new(EpochDbProvider::new(router.clone()));

    let manager = ArchiveManager::with_data(
        db.clone(),
        db_root_path,
        db_provider,
        0,
        Arc::new(AtomicU8::new(0)),
        #[cfg(feature = "telemetry")]
        Arc::new(StorageTelemetry::default()),
        Arc::new(StorageAlloc::default()),
    )
    .await?;

    Ok((manager, db, router))
}

#[tokio::test]
async fn test_archival_mode_minimal() -> Result<()> {
    let dir = tempfile::tempdir().unwrap();
    let (manager, db, router) = create_epoch_manager(dir.path()).await?;
    let (bhs, _) = create_block_handle_storage(db.clone());
    router.resolve_or_create(0).await?;

    write_blocks(&manager, &bhs, 50..51, &[1, 2, 3]).await?;

    let result = read_block(&manager, &bhs, 50).await?;
    assert_eq!(result, vec![1, 2, 3]);
    Ok(())
}

#[tokio::test]
async fn test_archival_mode_write_and_read() -> Result<()> {
    let dir = tempfile::tempdir().unwrap();
    let (manager, db, router) = create_epoch_manager(dir.path()).await?;
    let (bhs, _) = create_block_handle_storage(db.clone());
    router.resolve_or_create(0).await?;

    let data = vec![1, 2, 3, 4, 5];
    write_blocks(&manager, &bhs, 0..150, &data).await?;

    for mc_seq_no in 0..150 {
        assert_eq!(read_block(&manager, &bhs, mc_seq_no).await?, data);
    }

    // Verify .pack files are in epoch directory, not main db
    let epoch_dir = dir.path().join("new_epochs").join("epoch_0");
    assert!(epoch_dir.exists(), "Epoch directory should exist");
    assert!(
        epoch_dir.join("archive").join("packages").exists(),
        "Pack files should be in epoch directory"
    );

    Ok(())
}

#[tokio::test]
async fn test_archival_mode_multiple_epochs() -> Result<()> {
    let dir = tempfile::tempdir().unwrap();
    let (manager, db, router) = create_epoch_manager(dir.path()).await?;
    let (bhs, _) = create_block_handle_storage(db.clone());

    router.resolve_or_create(0).await?;
    router.resolve_or_create(20_000).await?;

    let data_epoch0 = vec![10, 20, 30];
    let data_epoch1 = vec![40, 50, 60];

    write_blocks(&manager, &bhs, 0..100, &data_epoch0).await?;
    assert_eq!(read_block(&manager, &bhs, 50).await?, data_epoch0);

    write_blocks(&manager, &bhs, 20_000..20_100, &data_epoch1).await?;

    assert_eq!(read_block(&manager, &bhs, 50).await?, data_epoch0);
    assert_eq!(read_block(&manager, &bhs, 20_050).await?, data_epoch1);

    assert!(dir.path().join("new_epochs").join("epoch_0").exists());
    assert!(dir.path().join("new_epochs").join("epoch_1").exists());

    Ok(())
}

#[tokio::test]
async fn test_archival_mode_restart_preserves_data() -> Result<()> {
    let dir = tempfile::tempdir().unwrap();
    let data = vec![7, 8, 9];

    // First "run": write some blocks
    let db = {
        let (manager, db, router) = create_epoch_manager(dir.path()).await?;
        let (bhs, _bh_db) = create_block_handle_storage(db.clone());
        router.resolve_or_create(0).await?;
        write_blocks(&manager, &bhs, 0..50, &data).await?;
        db
    };

    // BlockHandleStorage has background task which holds RocksDB instance
    while Arc::strong_count(&db) > 1 {
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    drop(db);

    // Second "run": recreate manager, verify data is accessible
    let (manager, db, _router) = create_epoch_manager(dir.path()).await?;
    let (bhs, _) = create_block_handle_storage(db.clone());

    for mc_seq_no in 0..50 {
        assert_eq!(
            read_block(&manager, &bhs, mc_seq_no).await?,
            data,
            "Block {} data mismatch after restart",
            mc_seq_no
        );
    }

    Ok(())
}

// Exercise the worst valid scheduling order (WC first), concurrent allocation,
// ordinary groups sharing a slice, and retry after reopening an empty reservation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_import_group_boundary_and_resume() -> Result<()> {
    use crate::archives::{
        archive_manager::{ImportBlockMeta, ImportEntry},
        package::Package,
        package_entry::PackageEntry,
    };
    const NAME: &str = "test_import_group_boundary_and_resume";
    let (manager, db) = create_manager(DB_PATH, NAME, true).await?;
    manager.prepare_import_group(1, true).await?;
    drop(manager);
    drop(db);
    let (manager, db) = create_manager(DB_PATH, NAME, false).await?;
    let (handles, _) = create_block_handle_storage(db.clone());
    let mut expected = Vec::new();
    for (seq, key) in [(1u32, true), (101, false), (150, true)] {
        // Multiple reservations must select one descriptor, including on resume.
        let (a, b) = tokio::join!(
            manager.prepare_import_group(seq, key),
            manager.prepare_import_group(seq, key),
        );
        a?;
        b?;
        let mut inputs = Vec::new();
        for wc in [true, false] {
            let shard =
                if wc { ShardIdent::with_workchain_id(0)? } else { ShardIdent::masterchain() };
            let id = BlockIdExt::with_params(
                shard.clone(),
                seq + 1,
                UInt256::with_array([(seq as u8).wrapping_add(wc as u8); 32]),
                UInt256::with_array([wc as u8; 32]),
            );
            let data = format!("group={seq}, workchain={wc}").into_bytes();
            let path = Path::new(DB_PATH).join(NAME).join(format!("source-{seq}-{wc}.pack"));
            let package = Package::open(path.clone(), false, true).await?;
            let mut offset = 0;
            package
                .append_entry(
                    &PackageEntry::with_data(PackageEntryId::Block(&id).filename(), data.clone()),
                    |pos, _| {
                        offset = pos;
                        Ok(())
                    },
                )
                .await?;
            drop(package);
            let entries = vec![ImportEntry {
                entry_id: PackageEntryId::Block(id.clone()),
                offset,
                block_meta: Some(ImportBlockMeta {
                    seq_no: seq + 1,
                    shard: shard.clone(),
                    gen_utime: seq,
                    end_lt: seq as u64,
                    mc_ref_seq_no: seq + 1,
                }),
            }];
            // Read an ordinary member of the group; key-only archives are a separate API.
            let handle = handles
                .create_handle(
                    id.clone(),
                    BlockMeta::with_data(0, seq, seq as u64, seq + 1, 0),
                    None,
                )?
                .unwrap();
            handle.set_data();
            handle.set_archived();
            handle.set_block_applied();
            handles.save_handle(&handle, None)?;
            expected.push((handle, id, data));
            inputs.push((path, shard, entries, key && !wc));
        }
        let import = |i: usize| {
            let (path, shard, entries, key) = &inputs[i];
            manager.import_package(path, seq, shard, entries, false, *key)
        };
        if seq == 1 {
            // Before the fix this puts WC in slice 0, then MC creates slice 1.
            import(0).await?;
            import(1).await?;
        } else {
            let (wc, mc) = tokio::join!(import(0), import(1));
            wc?;
            mc?;
        }
        let expected_slice = if seq < 150 { 1 } else { 150 };
        assert_eq!(manager.file_maps.files().get_closest_id(seq).await, Some(expected_slice));
        for (handle, id, data) in &expected {
            assert_eq!(
                &manager.get_file(handle, &PackageEntryId::Block(id)).await?,
                data,
                "before retry: {id}"
            );
        }
        // Reimport the same durable inputs as a retry after an interrupted group.
        import(0).await?;
        import(1).await?;
    }
    drop(manager);
    drop(handles);
    drop(db);
    let (manager, reopened_db) = create_manager(DB_PATH, NAME, false).await?;
    for (handle, id, data) in expected {
        assert_eq!(manager.get_file(&handle, &PackageEntryId::Block(&id)).await?, data, "{id}");
    }
    drop(manager);
    drop(reopened_db);
    Ok(())
}

#[tokio::test]
async fn bounded_archive_manager_preserves_flags_and_reads_loose_and_packed() -> Result<()> {
    use crate::archives::bounded_read::{ArchiveReadLimitExceeded, ArchiveReadLimits};
    let dir = tempfile::tempdir()?;
    let (manager, db) = create_manager(dir.path().to_str().unwrap(), "bounded", false).await?;
    let (handles, _) = create_block_handle_storage(db.clone());
    let id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        1,
        UInt256::with_array([7; 32]),
        UInt256::with_array([8; 32]),
    );
    let handle =
        handles.create_handle(id.clone(), BlockMeta::with_data(0, 0, 0, 0, 0), None)?.unwrap();
    let entry = PackageEntryId::Proof(&id);
    manager.add_file(&entry, b"proof").await?;
    handle.set_proof();
    handle.set_block_applied();
    let limits = ArchiveReadLimits { data_bytes: 5, filename_bytes: 1024 };
    for packed in [false, true] {
        if packed {
            manager.move_to_archive(&handle, || Ok(())).await?;
            handle.set_archived();
        }
        assert_eq!(manager.get_file_bounded(&handle, &entry, limits).await?, b"proof");
        let error = manager
            .get_file_bounded(&handle, &entry, ArchiveReadLimits { data_bytes: 4, ..limits })
            .await
            .unwrap_err();
        assert!(error.downcast_ref::<ArchiveReadLimitExceeded>().is_some());
        assert_eq!(handle.is_archived(), packed);
        assert!(handle.has_proof());
        let error = manager
            .get_file_bounded(&handle, &entry, ArchiveReadLimits { filename_bytes: 1, ..limits })
            .await
            .unwrap_err();
        assert!(error.downcast_ref::<ArchiveReadLimitExceeded>().is_some());
        assert_eq!(manager.get_file(&handle, &entry).await?, b"proof");
    }
    drop(handle);
    drop(handles);
    drop(manager);
    drop(db);
    // TempDir owns cleanup; avoid destroy_rocks_db removing its empty parent.
    Ok(())
}

#[tokio::test]
async fn persistent_repair_custody_archive_logical_protection_survives_pack_and_actual_gc(
) -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (manager, db) = create_manager(dir.path().to_str().unwrap(), "custody", false).await?;
    let (handles, _) = create_block_handle_storage(db.clone());
    let mut saved = Vec::new();
    for (index, seq) in [1, ARCHIVE_SLICE_SIZE + 1].into_iter().enumerate() {
        let id = BlockIdExt::with_params(
            ShardIdent::masterchain(),
            seq,
            UInt256::from([index as u8 + 1; 32]),
            UInt256::from([index as u8 + 3; 32]),
        );
        let handle =
            handles.create_handle(id.clone(), BlockMeta::with_data(0, 0, 0, 0, 0), None)?.unwrap();
        manager.add_file(&PackageEntryId::Proof(&id), b"proof").await?;
        handle.set_proof();
        handle.set_block_applied();
        if index == 0 {
            let authentication = db.repair_protection().authentication().await?;
            db.repair_protection().protect([], [id.clone()]);
            db.repair_protection().protect_artifact_digest(
                id.clone(),
                "proof",
                UInt256::calc_file_hash(b"proof"),
            )?;
            drop(authentication);
            manager.remove_file(&handle).await?;
            assert_eq!(manager.get_file(&handle, &PackageEntryId::Proof(&id)).await?, b"proof");
            assert!(manager
                .replace_file_durable(&PackageEntryId::Proof(&id), b"other")
                .await
                .is_err());
        }
        manager.move_to_archive(&handle, || Ok(())).await?;
        handle.set_archived();
        saved.push((id, handle));
    }
    let cutoff = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        ARCHIVE_SLICE_SIZE * 2,
        UInt256::default(),
        UInt256::default(),
    );
    manager.gc(&cutoff).await;
    assert_eq!(manager.get_file(&saved[0].1, &PackageEntryId::Proof(&saved[0].0)).await?, b"proof");
    assert!(
        manager.get_file(&saved[1].1, &PackageEntryId::Proof(&saved[1].0)).await.is_err(),
        "unprotected package must really be destroyed"
    );
    Ok(())
}

#[tokio::test]
async fn archive_migration_error_retry_and_live_repair_remigration() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (manager, db) = create_manager(dir.path().to_str().unwrap(), "remigration", false).await?;
    let (handles, _) = create_block_handle_storage(db);
    let id = BlockIdExt::with_params(ShardIdent::masterchain(), 1,
        UInt256::from([1; 32]), UInt256::from([2; 32]));
    let handle = handles.create_handle(id.clone(), BlockMeta::with_data(0, 0, 0, 0, 0), None)?.unwrap();
    let entry = PackageEntryId::Proof(&id);
    manager.add_file(&entry, b"original-proof").await?;
    handle.set_proof();
    let loose = manager.unapplied_files_path().join(entry.filename_short());
    let error = manager.move_to_archive(&handle, || Err(error!("injected metadata failure"))).await.unwrap_err();
    assert!(error.to_string().contains("injected metadata failure"));
    assert!(loose.exists(), "failed transition must retain its loose evidence");
    manager.move_to_archive(&handle, || { handle.set_archived(); Ok(()) }).await?;
    assert!(handle.is_archived());
    assert!(!loose.exists());
    assert_eq!(manager.get_file(&handle, &entry).await?, b"original-proof");
    manager.move_to_archive(&handle, || panic!("already archived must be idempotent")).await?;
    // Exercise actual file replacement and routing reset in the same live owner.
    // These storage bytes are not an authentication/custody fixture.
    manager.replace_file_durable(&entry, b"repaired-proof").await?;
    handle.reset_archived();
    assert_eq!(std::fs::read(&loose)?, b"repaired-proof");
    manager.move_to_archive(&handle, || { handle.set_archived(); Ok(()) }).await?;
    assert!(handle.is_archived());
    assert!(!loose.exists());
    assert_eq!(manager.get_file(&handle, &entry).await?, b"repaired-proof");
    Ok(())
}

#[tokio::test]
async fn archive_unleased_startup_still_recovers_uncommitted_tail_and_appends() -> Result<()> {
    use crate::archives::{archive_slice::ArchiveSlice, package_id::{PackageId, PackageType}};
    use std::io::Write;
    let dir = tempfile::tempdir()?;
    let (manager, db) = create_manager(dir.path().to_str().unwrap(), "tail-control", false).await?;
    let (handles, _) = create_block_handle_storage(db.clone());
    let id = BlockIdExt::with_params(ShardIdent::masterchain(), 1,
        UInt256::from([1; 32]), UInt256::from([2; 32]));
    let handle = handles.create_handle(id.clone(), BlockMeta::with_data(0, 0, 0, 0, 0), None)?.unwrap();
    let entry = PackageEntryId::Proof(&id);
    manager.add_file(&entry, b"original-proof").await?;
    handle.set_proof();
    manager.move_to_archive(&handle, || { handle.set_archived(); Ok(()) }).await?;
    let root = Arc::new(dir.path().join("tail-control"));
    let path = PackageId::for_block(0).full_path(root.as_path(), id.shard())?;
    let original = std::fs::read(&path)?;
    drop(manager);
    let mut file = std::fs::OpenOptions::new().append(true).open(&path)?;
    file.write_all(b"uncommitted-tail")?;
    file.sync_all()?;
    drop(file);
    assert!(std::fs::metadata(&path)?.len() > original.len() as u64);
    let slice = ArchiveSlice::with_data(db.repair_protection().clone(), db.clone(), root,
        0, PackageType::Blocks, false, false,
        #[cfg(feature = "telemetry")]
        Arc::new(StorageTelemetry::default()), Arc::new(StorageAlloc::default())).await?;
    assert_eq!(std::fs::read(&path)?, original, "unleased normal recovery must still trim its uncommitted tail");
    slice.add_file(&handle, &entry, b"next-proof".to_vec()).await?;
    assert_eq!(slice.get_file(&handle, &entry).await?.unwrap().data(), b"next-proof");
    Ok(())
}

#[tokio::test]
async fn archive_protected_key_package_append_metadata_cold_reopen() -> Result<()> {
    use crate::archives::{archive_slice::ArchiveSlice, package_id::PackageType};
    let dir = tempfile::tempdir()?;
    let (manager, db) = create_manager(dir.path().to_str().unwrap(), "key-reopen", false).await?;
    let (handles, _) = create_block_handle_storage(db.clone());
    let id = BlockIdExt::with_params(ShardIdent::masterchain(), 3,
        UInt256::from([3; 32]), UInt256::from([4; 32]));
    let handle = handles.create_handle(id.clone(), BlockMeta::with_data(FLAG_KEY_BLOCK, 0, 0, 0, 0), None)?.unwrap();
    let entry = PackageEntryId::Proof(&id);
    manager.add_file(&entry, b"key-proof").await?;
    handle.set_proof();
    manager.move_to_archive(&handle, || { handle.set_archived(); Ok(()) }).await?;
    drop(manager);
    // Storage predicate fixture only; real authenticated custody is covered by Engine.
    db.repair_protection().protect([], [id.clone()]);
    let root = Arc::new(dir.path().join("key-reopen"));
    for bytes in [b"key-proof".as_slice(), b"appended-key-proof".as_slice()] {
        let slice = ArchiveSlice::with_data(db.repair_protection().clone(), db.clone(), root.clone(),
            0, PackageType::KeyBlocks, false, false,
            #[cfg(feature = "telemetry")]
            Arc::new(StorageTelemetry::default()), Arc::new(StorageAlloc::default())).await?;
        assert_eq!(slice.get_file(&handle, &entry).await?.unwrap().data(), bytes);
        slice.add_file(&handle, &entry, b"appended-key-proof".to_vec()).await?;
    }
    Ok(())
}
