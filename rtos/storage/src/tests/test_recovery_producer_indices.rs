// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Native metadata projection and staged bytes; actual-node acceptance is separate.
use super::*;
use crate::{
    archives::{context::ArchiveDomain, package_entry_id::GetFileName},
    db::rocksdb::{AccessType, RocksDb},
};
use rtos_block::UInt256;

fn block(seq: u32) -> BlockIdExt {
    BlockIdExt::with_params(
        ShardIdent::masterchain(),
        seq,
        UInt256::from([1; 32]),
        UInt256::from([2; 32]),
    )
}

fn exercise(separated: bool, sequences: &[u32], expected: &[u32]) -> Result<()> {
    let dir = tempfile::tempdir()?;
    let db = RocksDb::new(dir.path(), "db", None, AccessType::ReadWrite)?;
    for name in ["files", "key_files", "status_db_0", "entry_meta_db_0"] {
        db.db().create_cf(name, &rocksdb::Options::default())?;
    }
    db.db().put_cf(&db.db().cf_handle("files").unwrap(), 0u32.to_le_bytes(), b"parent")?;
    let status = db.db().cf_handle("status_db_0").unwrap();
    db.db().put_cf(&status, b"SlicedMode", [1])?;
    db.db().put_cf(&status, b"SliceSize", 2u32.to_le_bytes())?;
    db.db().put_cf(&status, b"TotalSlices", (sequences.len() as u32).to_le_bytes())?;
    if separated {
        db.db().put_cf(&status, b"ShardSplitDepth", [0])?;
    }
    let metadata = db.db().cf_handle("entry_meta_db_0").unwrap();
    let mut originals = Vec::new();
    for (index, &seq) in sequences.iter().enumerate() {
        let info = PackageEntryInfo { seqno: index as u32 * 2, shard: ShardIdent::masterchain() };
        let name = PackageEntryId::Block(block(seq)).filename();
        let mut bytes = 0xAE8F_DD01u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&0x1E8Bu16.to_le_bytes());
        bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(name.as_bytes());
        bytes.push(seq as u8);
        let path = PackageId::for_block(info.seqno).full_path(dir.path(), &info.shard)?;
        fs::create_dir_all(path.parent().unwrap())?;
        fs::write(&path, &bytes)?;
        let value = serde_cbor::to_vec(&PackageEntryMeta::with_data(
            bytes.len() as u64 - 4,
            1,
            separated.then_some(&info),
        ))?;
        db.db().put_cf(&metadata, (index as u32).to_le_bytes(), &value)?;
        originals.push((path, bytes, value));
    }
    let binding = db.bind_archive_domain(ArchiveDomain::new())?;
    let set = RecoveryProviders::from_live(&binding, dir.path(), None)?;
    let selection = TruncationSelection::new(block(3), Vec::<BlockIdExt>::new())?;
    let plan = Plan::new(&set.providers, &selection)?;
    let archive = plan.archive(0, false, 0)?;
    let total = plan
        .row(&archive, "status", b"TotalSlices", &(sequences.len() as u32).to_le_bytes())?
        .unwrap();
    assert_eq!(u32::from_le_bytes(total.try_into().unwrap()), expected.len() as u32);
    for (index, (_, _, old)) in originals.iter().enumerate() {
        let projected = plan.row(&archive, "entry_meta", &(index as u32).to_le_bytes(), old)?;
        if let Some(&source) = expected.get(index) {
            let meta: PackageEntryMeta =
                serde_cbor::from_slice(&projected.expect("retained metadata"))?;
            assert_eq!(meta.version(), 1);
            if separated {
                assert_eq!(meta.get_info()?.unwrap().seqno, source * 2);
            } else {
                assert!(meta.get_info()?.is_none());
            }
            let source = source as usize;
            let removed = sequences[source] >= 3;
            assert_eq!(
                meta.entry_size(),
                if removed { 0 } else { originals[source].1.len() as u64 - 4 }
            );
            let member = plan.member(
                plan.archive(0, false, 0)?,
                &(source as u32).to_le_bytes(),
                &originals[source].2,
            )?;
            assert!(plan.decision(&member)?.retained);
            let stage = dir.path().join(format!("stage-{index}"));
            plan.write_stage(&member, &stage)?;
            assert_eq!(
                fs::read(stage)?,
                if removed {
                    originals[source].1[..4].to_vec()
                } else {
                    originals[source].1.clone()
                }
            );
        } else {
            assert!(projected.is_none(), "obsolete ordinal survived");
        }
    }
    for (path, bytes, _) in originals {
        assert_eq!(fs::read(path)?, bytes, "planning changed canonical data");
    }
    Ok(())
}

#[test]
fn separated_compacts_middle_and_leading_holes() -> Result<()> {
    exercise(true, &[1, 4, 2, 5], &[0, 2])?;
    exercise(true, &[4, 1, 5, 2], &[1, 3])
}
#[test]
fn legacy_preserves_interior_identity_and_removes_empty_suffix() -> Result<()> {
    exercise(false, &[1, 4, 2, 5], &[0, 1, 2])?;
    exercise(false, &[4, 1, 5, 2], &[0, 1, 2, 3])
}
#[test]
fn both_formats_remove_all_selected_packages() -> Result<()> {
    exercise(true, &[4, 5], &[])?;
    exercise(false, &[4, 5], &[])
}
