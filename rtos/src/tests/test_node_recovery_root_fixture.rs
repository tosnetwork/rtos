// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Independent wire fixture, intentionally not a production recovery producer.
//! Only used in a child process against its freshly imported temporary database.
use super::*;
use rtos_block::{sha256_digest, Sha256};
use storage::db::{node::open_node_db, rocksdb::AccessType};

const OPERATION: [u8; 16] = [0x35; 16];
struct Provider {
    root: PathBuf,
    descriptor: Vec<u8>,
    db: Arc<RocksDb>,
}
fn descriptor(
    root: &Path,
    roles: u8,
    anchor: u8,
    relative: &Path,
    range: Option<(u32, u32)>,
    db: &RocksDb,
) -> Result<Vec<u8>> {
    let canonical = fs::canonicalize(root)?;
    let mut digest = Sha256::new();
    digest.update(b"RTOS archive recovery anchor v1");
    digest.update([anchor]);
    let bytes = canonical.as_os_str().as_encoded_bytes();
    digest.update((bytes.len() as u64).to_le_bytes());
    digest.update(bytes);
    let identity = db.db().get_db_identity()?;
    let mut out = vec![0u8; 93];
    out[..4].copy_from_slice(&[1, 0, roles, anchor]);
    out[4..36].copy_from_slice(&digest.finalize());
    out[36..44].copy_from_slice(&(identity.len() as u64).to_le_bytes());
    out[44..76].copy_from_slice(&sha256_digest(identity));
    if let Some((start, end)) = range {
        out[76] = 1;
        out[77..81].copy_from_slice(&start.to_le_bytes());
        out[81..85].copy_from_slice(&end.to_le_bytes());
    }
    let relative = relative.as_os_str().as_encoded_bytes();
    out[85..93].copy_from_slice(&(relative.len() as u64).to_le_bytes());
    out.extend_from_slice(relative);
    Ok(out)
}
fn record(hash: &mut Sha256, count: &mut u64, tag: u8, provider: &[u8; 32], parts: &[&[u8]]) {
    *count += 1;
    hash.update([tag]);
    hash.update(provider);
    for part in parts {
        hash.update((part.len() as u64).to_le_bytes());
        hash.update(part);
    }
}
fn files(root: &Path) -> Result<BTreeMap<PathBuf, Vec<u8>>> {
    fn visit(root: &Path, path: &Path, rows: &mut BTreeMap<PathBuf, Vec<u8>>) -> Result<()> {
        if !path.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                visit(root, &entry.path(), rows)?;
            } else {
                rows.insert(entry.path().strip_prefix(root)?.to_owned(), fs::read(entry.path())?);
            }
        }
        Ok(())
    }
    let mut rows = BTreeMap::new();
    visit(root, &root.join("archive/packages"), &mut rows)?;
    Ok(rows)
}

pub(super) fn write_and_hold(root: &Path) -> Result<()> {
    let node = root.join("node_db");
    let main = open_node_db(&node, &Default::default(), AccessType::ReadWrite)?;
    let mut providers = vec![Provider {
        root: node.clone(),
        descriptor: descriptor(&node, 3, 1, Path::new(""), None, &main)?,
        db: main.clone(),
    }];
    let epochs = root.join("epochs");
    for entry in fs::read_dir(&epochs)? {
        let path = entry?.path();
        let meta: serde_json::Value =
            serde_json::from_slice(&fs::read(path.join("epoch_meta.json"))?)?;
        assert!(
            path.join("archive_db/CURRENT").is_file(),
            "fixture must not create a missing epoch DB"
        );
        let db = RocksDb::new(&path, "archive_db", None, AccessType::ReadWrite)?;
        let range = (
            u32::try_from(meta["mc_seq_no_start"].as_u64().unwrap())?,
            u32::try_from(meta["mc_seq_no_end"].as_u64().unwrap())?,
        );
        let descriptor = descriptor(&epochs, 4, 3, path.strip_prefix(&epochs)?, Some(range), &db)?;
        providers.push(Provider { root: path, descriptor, db });
    }
    assert_eq!(providers.len(), 2, "fixture must exercise main and one separate epoch provider");
    // Roles 3 (main/key) sort before roles 4 (epoch) in the wire inventory.
    let mut provider_hash = Sha256::new();
    let mut data_hash = Sha256::new();
    let mut data_count = 0;
    for provider in &providers {
        let identity = sha256_digest(&provider.descriptor);
        provider_hash.update((provider.descriptor.len() as u64).to_le_bytes());
        provider_hash.update(identity);
        let db = provider.db.db();
        let mut names = storage::sst_native_test::DB::list_cf(&Default::default(), db.path())?;
        names.sort();
        for name in names {
            if !["block_index_", "entry_meta_", "offsets_", "status_"]
                .iter()
                .any(|prefix| name.starts_with(prefix))
            {
                continue;
            }
            record(&mut data_hash, &mut data_count, 1, &identity, &[name.as_bytes()]);
            let cf = db.cf_handle(&name).expect("existing fixture CF");
            let mut rows = db.raw_iterator_cf(&cf);
            rows.seek_to_first();
            while rows.valid() {
                record(
                    &mut data_hash,
                    &mut data_count,
                    2,
                    &identity,
                    &[name.as_bytes(), rows.key().unwrap(), rows.value().unwrap()],
                );
                rows.next();
            }
            rows.status()?;
        }
        for (path, bytes) in files(&provider.root)? {
            record(
                &mut data_hash,
                &mut data_count,
                3,
                &identity,
                &[
                    path.as_os_str().as_encoded_bytes(),
                    &(bytes.len() as u64).to_le_bytes(),
                    &sha256_digest(&bytes),
                ],
            );
        }
    }
    assert!(data_count > 0);
    let mut map_hash = Sha256::new();
    let mut map_count = 0u64;
    for (tag, name) in [(1u8, "files"), (2u8, "key_files")] {
        let cf = main
            .db()
            .cf_handle(name)
            .ok_or_else(|| rtos_block::error!("Missing fixture map {name}"))?;
        let mut rows = main.db().raw_iterator_cf(&cf);
        rows.seek_to_first();
        while rows.valid() {
            let key = rows.key().unwrap();
            let value = rows.value().unwrap();
            assert_eq!(key.len(), 4);
            map_hash.update([tag]);
            map_hash.update(key);
            map_hash.update((value.len() as u64).to_le_bytes());
            map_hash.update(value);
            map_count += 1;
            rows.next();
        }
        rows.status()?;
    }
    let mut header = vec![0u8; 316];
    header[..8].copy_from_slice(b"RTOSATR1");
    header[8..12].copy_from_slice(&[1, 0, 4, 3]);
    header[12..28].copy_from_slice(&OPERATION);
    header[28..68].copy_from_slice(&providers[0].descriptor[36..76]);
    header[68..76].copy_from_slice(&100u64.to_le_bytes());
    header[76..84].copy_from_slice(&1u64.to_le_bytes());
    header[84..116].fill(8);
    header[164..172].copy_from_slice(&(providers.len() as u64).to_le_bytes());
    header[172..204].copy_from_slice(&provider_hash.finalize());
    header[204..212].copy_from_slice(&map_count.to_le_bytes());
    header[212..244].copy_from_slice(&map_hash.finalize());
    header[244..252].copy_from_slice(&data_count.to_le_bytes());
    header[252..284].copy_from_slice(&data_hash.finalize());
    let checksum = sha256_digest(&header[..284]);
    header[284..].copy_from_slice(&checksum);
    for provider in &providers {
        let mut backlink = vec![0u8; 164];
        backlink[..8].copy_from_slice(b"RTOSATP1");
        backlink[8] = 1;
        backlink[12..68].copy_from_slice(&header[12..68]);
        backlink[68..100].copy_from_slice(&header[84..116]);
        backlink[100..132].copy_from_slice(&sha256_digest(&provider.descriptor));
        let checksum = sha256_digest(&backlink[..132]);
        backlink[132..].copy_from_slice(&checksum);
        provider.db.db().put(b"ArchiveTruncationParticipantV1", backlink)?;
        provider.db.sync_wal()?;
        let operation = provider.root.join("archive/recovery").join(hex::encode(OPERATION));
        fs::create_dir_all(&operation)?;
        for dir in [
            &operation,
            operation.parent().unwrap(),
            operation.parent().unwrap().parent().unwrap(),
            provider.root.as_path(),
        ] {
            fs::File::open(dir)?.sync_all()?;
        }
    }
    main.db().put(b"ArchiveTruncationRootV1", header)?;
    main.sync_wal()?;
    fs::write(root.join("cleaned-ready"), b"durable")?;
    // Hold every actual provider until the parent sends SIGKILL.
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}
