// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Source finality files under a full disk (P5-07.12 phase 1, S1–S3). Run only
//! inside the disk-full harness: an unprivileged mount namespace whose
//! `RTOS_ENOSPC_ROOT` is a size- or inode-limited tmpfs, traced from outside.
//! Each failure is followed by a cold reopen before any retry, so the
//! reopen sees exactly what the failure left. With `RTOS_ENOSPC_CONTROL=1`
//! the case runs its positive control: the same write with ample space.
use super::tests::fixture_seqno;
use super::*;
use rtos_block::ShardIdent;

fn enospc_root() -> PathBuf {
    PathBuf::from(std::env::var_os("RTOS_ENOSPC_ROOT").expect("run inside the disk-full harness"))
}

fn control() -> bool {
    std::env::var("RTOS_ENOSPC_CONTROL").as_deref() == Ok("1")
}

/// Exhausts free blocks or free inodes on the filesystem holding `dir`;
/// `free` gives them back.
struct Filler(Vec<PathBuf>);

impl Filler {
    fn blocks(dir: &Path) -> Self {
        let path = dir.join("enospc-filler");
        let mut file = File::create(&path).unwrap();
        for chunk in [1 << 16, 1 << 12, 1 << 9, 1] {
            let bytes = vec![0u8; chunk];
            while file.write_all(&bytes).is_ok() {}
        }
        Self(vec![path])
    }
    fn inodes(dir: &Path) -> Self {
        let mut paths = Vec::new();
        loop {
            let path = dir.join(format!("enospc-inode-{}", paths.len()));
            match File::create(&path) {
                Ok(_) => paths.push(path),
                Err(error) if error.raw_os_error() == Some(28) => break,
                Err(error) => panic!("inode filler failed unexpectedly: {error}"),
            }
        }
        Self(paths)
    }
    fn free(self) {
        for path in self.0 {
            std::fs::remove_file(path).unwrap();
        }
    }
}

fn records() -> (Arc<AuthenticatedSessionRuntime>, PendingFinalityRecord, PendingFinalityRecord) {
    let (runtime, first) = fixture_seqno(true, ShardIdent::masterchain(), 2);
    let (_, second) = fixture_seqno(true, ShardIdent::masterchain(), 3);
    let first = PendingFinalityRecord::from_draft(&runtime, &first).unwrap();
    let second = PendingFinalityRecord::from_draft(&runtime, &second).unwrap();
    assert_ne!(first.id().unwrap(), second.id().unwrap());
    (runtime, first, second)
}

/// The final file for `record`, if present, is complete and exact.
fn absent_or_complete(directory: &Path, record: &PendingFinalityRecord) -> bool {
    let path = directory.join(format!("{}.json", record.id().unwrap().to_hex_string()));
    if !path.exists() {
        return false;
    }
    let read = PendingFinalityRecord::read(&path).expect("a present final file is complete");
    assert_eq!(read.encode().unwrap(), record.encode().unwrap());
    true
}

/// A cold scan after a failure: it restores the acknowledged records, and
/// the failed one only if complete; or it refuses (fails closed) on a
/// leftover partial temporary. A partial temporary is never served.
fn cold_scan(root: &Path, expected: usize) -> &'static str {
    match scan_pending_finality(root) {
        Ok(restored) => {
            assert_eq!(restored.len(), expected, "only acknowledged or complete records");
            "restored"
        }
        Err(error) => {
            eprintln!("cold scan refused: {error:#}");
            "refused"
        }
    }
}

fn retain_on_full_disk(case: &str, inodes: bool) {
    let root = enospc_root().join(case);
    std::fs::create_dir_all(&root).unwrap();
    let (runtime, first, second) = records();
    let namespace = PathBuf::from(runtime.runtime_directory(root.to_str().unwrap()).unwrap());
    let store = PendingFinalityStore::open(&namespace).unwrap();
    store.retain(&first).unwrap();
    let directory = store.directory.clone();
    if control() {
        assert_eq!(store.retain(&second).unwrap().encode().unwrap(), second.encode().unwrap());
        assert!(absent_or_complete(&directory, &second));
        eprintln!("ENOSPC-CASE {case} control ok");
        return;
    }
    let first_path = directory.join(format!("{}.json", first.id().unwrap().to_hex_string()));
    let first_bytes = std::fs::read(&first_path).unwrap();
    let filler = if inodes { Filler::inodes(&root) } else { Filler::blocks(&root) };
    let error = store.retain(&second).unwrap_err();
    assert!(format!("{error:#}").contains("No space left on device"), "{error:#}");
    drop(store);
    filler.free();
    // Cold reopen before any retry: acknowledged bytes intact, the failed
    // record absent or whole, no partial temporary served.
    assert_eq!(std::fs::read(&first_path).unwrap(), first_bytes);
    let present = absent_or_complete(&directory, &second);
    let scan = cold_scan(&root, 1 + usize::from(present));
    // The documented retry on the reopened store succeeds.
    let reopened = PendingFinalityStore::open(&namespace).unwrap();
    assert_eq!(reopened.retain(&second).unwrap().encode().unwrap(), second.encode().unwrap());
    drop(reopened);
    assert_eq!(scan_pending_finality(&root).unwrap().len(), 2);
    assert_eq!(std::fs::read(&first_path).unwrap(), first_bytes);
    eprintln!("ENOSPC-CASE {case} present_after_failure={present} cold_scan={scan}");
}

#[test]
#[ignore = "disk-full harness only"]
fn disk_full_source_retain_data_write() {
    retain_on_full_disk("retain-blocks", false);
}

#[test]
#[ignore = "disk-full harness only"]
fn disk_full_source_retain_file_creation() {
    retain_on_full_disk("retain-inodes", true);
}

#[test]
#[ignore = "disk-full harness only"]
fn disk_full_source_compact_reference_write() {
    let root = enospc_root().join("compact");
    std::fs::create_dir_all(&root).unwrap();
    let (runtime, draft) = fixture_seqno(true, ShardIdent::masterchain(), 2);
    let record = PendingFinalityRecord::from_draft(&runtime, &draft).unwrap();
    let namespace = PathBuf::from(runtime.runtime_directory(root.to_str().unwrap()).unwrap());
    // The real flow: retained, handed to the node, acknowledged as `.acked`.
    let sink = Arc::new(super::tests::HeldSink::default());
    let source = SourceFinalityDelivery::open(runtime.clone(), &namespace, sink.clone()).unwrap();
    source.poll(draft).unwrap();
    let (_, complete) = sink.0.lock().unwrap().pop().unwrap();
    let receipt = UInt256::from([4; 32]);
    complete(Ok(receipt.clone()));
    let store = source.store.clone();
    let id = record.id().unwrap().to_hex_string();
    let acked = store.directory.join(format!("{id}.acked"));
    let reference = store.reference_path(&record.id().unwrap());
    assert!(acked.exists(), "acknowledged by the node");
    if control() {
        store.compact(&record, receipt).unwrap();
        CanonicalReference::read(&reference).unwrap().matches(&record).unwrap();
        eprintln!("ENOSPC-CASE compact control ok");
        return;
    }
    let acked_bytes = std::fs::read(&acked).unwrap();
    let filler = Filler::blocks(&root);
    let error = store.compact(&record, receipt.clone()).unwrap_err();
    assert!(format!("{error:#}").contains("No space left on device"), "{error:#}");
    drop(store);
    drop(source);
    filler.free();
    // Cold reopen before any retry: the acknowledged record is untouched and
    // no partial reference is final.
    assert_eq!(std::fs::read(&acked).unwrap(), acked_bytes);
    if reference.exists() {
        CanonicalReference::read(&reference).expect("a present reference is complete");
    }
    let reopened = PendingFinalityStore::open(&namespace).unwrap();
    // The documented retry on the reopened store completes the compaction.
    reopened.compact(&record, receipt).unwrap();
    assert!(reference.exists() && !acked.exists());
    drop(reopened);
    let cold = PendingFinalityStore::open(&namespace).unwrap();
    CanonicalReference::read(&cold.reference_path(&record.id().unwrap()))
        .unwrap()
        .matches(&record)
        .unwrap();
    eprintln!("ENOSPC-CASE compact ok");
}
