// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Prepare a valid sparse-retention fixture before any actual node boot.
use super::*;
use std::hash::{Hash, Hasher};
use storage::{
    archives::{package_entry_id::PackageEntryId, package_id::PackageId},
    db::rocksdb::{AccessType, RocksDb},
};

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct Meta {
    entry_size: u64,
    info: Option<Vec<u8>>,
    version: u32,
}

pub(super) async fn prepare(root: &Path) -> Result<()> {
    let mut prepared = 0;
    for epoch in fs::read_dir(root.join("epochs"))? {
        let epoch = epoch?.path();
        if !epoch.join("archive_db").is_dir() {
            continue;
        }
        let db = RocksDb::new(&epoch, "archive_db", None, AccessType::ReadWrite)?;
        if let Some(metadata) = db.db().cf_handle("entry_meta_db_3") {
            let originals = [
                db.db().get_cf(&metadata, 0u32.to_le_bytes())?.unwrap(),
                db.db().get_cf(&metadata, 1u32.to_le_bytes())?.unwrap(),
            ];
            assert!(db.db().get_cf(&metadata, 2u32.to_le_bytes())?.is_none());
            for (ordinal, original) in originals.iter().enumerate() {
                let shard = if ordinal == 0 {
                    rtos_block::ShardIdent::masterchain()
                } else {
                    rtos_block::ShardIdent::with_tagged_prefix(0, rtos_block::SHARD_FULL)?
                };
                let mut retained: Meta = serde_cbor::from_slice(original)?;
                let mut removed = retained.clone();
                let info = removed.info.as_mut().unwrap();
                assert_eq!(&info[..4], &3u32.to_le_bytes());
                info[..4].copy_from_slice(&4u32.to_le_bytes());
                let path = PackageId::for_block(3).full_path(&epoch, &shard)?;
                let bytes = fs::read(&path)?;
                assert_eq!(retained.entry_size, bytes.len() as u64 - 4);
                let offsets = db.db().cf_handle("offsets_db_3").unwrap();
                let mut position = 4usize;
                let mut split = None;
                let mut moved = 0;
                while position < bytes.len() {
                    assert_eq!(&bytes[position..position + 2], &0x1E8Bu16.to_le_bytes());
                    let name_len =
                        u16::from_le_bytes(bytes[position + 2..position + 4].try_into()?) as usize;
                    let body_len =
                        u32::from_le_bytes(bytes[position + 4..position + 8].try_into()?) as usize;
                    let name = std::str::from_utf8(&bytes[position + 8..position + 8 + name_len])?;
                    let entry = PackageEntryId::<rtos_block::BlockIdExt>::from_filename(name)?;
                    let id = match &entry {
                        PackageEntryId::Block(id)
                        | PackageEntryId::Proof(id)
                        | PackageEntryId::ProofLink(id) => id,
                        _ => rtos_block::fail!("Unexpected MC fixture entry"),
                    };
                    assert_eq!(id.shard(), &shard);
                    if id.seq_no() == 4 {
                        let boundary = *split.get_or_insert(position);
                        let mut hasher = std::collections::hash_map::DefaultHasher::new();
                        entry.hash(&mut hasher);
                        let key = hasher.finish().to_le_bytes();
                        let old: u64 =
                            serde_cbor::from_slice(&db.db().get_cf(&offsets, key)?.unwrap())?;
                        assert_eq!(old, position as u64 - 4);
                        db.db().put_cf(
                            &offsets,
                            key,
                            serde_cbor::to_vec(&((position - boundary) as u64))?,
                        )?;
                        moved += 1;
                    } else {
                        assert_eq!(id.seq_no(), 3);
                        assert!(split.is_none());
                    }
                    position += 8 + name_len + body_len;
                }
                assert_eq!(position, bytes.len());
                assert_eq!(moved, 2, "move actual block 4 and its proof together");
                let split = split.unwrap();
                let index = db.db().cf_handle("block_index_db_3").unwrap();
                let mut rows = db.db().raw_iterator_cf(&index);
                rows.seek_to_first();
                let mut updated = 0;
                while rows.valid() {
                    let key = rows.key().unwrap();
                    let key_text = std::str::from_utf8(key)?;
                    let parts: Vec<_> = key_text.split(':').collect();
                    assert!(matches!(parts[0], "sn" | "lt" | "ut"));
                    let mut value = rows.value().unwrap().to_vec();
                    let old = u32::from_le_bytes(value[..4].try_into()?);
                    if parts[1].parse::<i32>()? == shard.workchain_id() && old == (split - 4) as u32
                    {
                        value[..4].copy_from_slice(&0u32.to_le_bytes());
                        value[4..].copy_from_slice(&4u32.to_le_bytes());
                        db.db().put_cf(&index, key, value)?;
                        updated += 1;
                    }
                    rows.next();
                }
                rows.status()?;
                assert_eq!(updated, 3, "move sequence, LT and time readers together");
                let target = PackageId::for_block(4).full_path(&epoch, &shard)?;
                assert!(!target.exists());
                let mut tail = bytes[..4].to_vec();
                tail.extend_from_slice(&bytes[split..]);
                fs::write(&target, &tail)?;
                fs::File::open(&target)?.sync_all()?;
                fs::write(&path, &bytes[..split])?;
                fs::File::open(&path)?.sync_all()?;
                fs::File::open(path.parent().unwrap())?.sync_all()?;
                retained.entry_size = split as u64 - 4;
                removed.entry_size = tail.len() as u64 - 4;
                db.db().put_cf(
                    &metadata,
                    (ordinal as u32 * 2).to_le_bytes(),
                    serde_cbor::to_vec(&retained)?,
                )?;
                db.db().put_cf(
                    &metadata,
                    (ordinal as u32 * 2 + 1).to_le_bytes(),
                    serde_cbor::to_vec(&removed)?,
                )?;
            }
            let status = db.db().cf_handle("status_db_3").unwrap();
            db.db().put_cf(&status, b"TotalSlices", 4u32.to_le_bytes())?;
            db.db().put_cf(&status, b"SliceSize", 1u32.to_le_bytes())?;
            db.sync_wal()?;
            prepared += 1;
        }
        tokio::time::timeout(Duration::from_secs(30), wait_for_db_release(db)).await?;
    }
    assert_eq!(prepared, 1);
    eprintln!("Prepared MC3 / MC4 / WC3 / WC4 package ordinals before node boot; retaining height 3 removes the middle ordinal");
    Ok(())
}
