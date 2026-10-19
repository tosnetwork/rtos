// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Child-process crash-cut tests for the ordered handle writer and for
//! durable publication of unapplied artifacts.
//!
//! The parent re-executes this test binary as a child that performs a
//! scripted write sequence, prints an `ACK <n>` receipt on stdout after each
//! durable acknowledgement it receives, and aborts at an armed cut point.
//! The parent then reopens the databases and checks what survived.
//!
//! Limits: the child runs with the buffered-WAL crash model
//! (`manual_wal_flush`), which loses unsynced WAL bytes at abort. Other flush
//! activity can still write such bytes, and abort leaves the filesystem cache
//! intact, so these tests show buffered-WAL loss and ordering, not full
//! power-loss equivalence.
#[cfg(feature = "telemetry")]
use crate::StorageTelemetry;
use crate::{
    archives::archive_manager::{UnappliedDirectory, UNAPPLIED_TEMPORARY_SUFFIX},
    block_handle_db::{BlockHandleDb, BlockHandleStorage, NodeStateDb},
    db::rocksdb::{AccessType, RocksDb},
    traits::Serializable,
    types::BlockMeta,
    StorageAlloc,
};
use rtos_block::{BlockIdExt, ShardIdent, UInt256};
use std::{
    collections::BTreeSet,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

const CHILD_SCENARIO: &str = "RTOS_CRASH_CHILD";
const CHILD_DIR: &str = "RTOS_CRASH_DIR";
const CHILD_TEST: &str = "tests::test_durability_crash_cut::crash_cut_child_entry";
/// Writes in the stream scenario. Every fourth one waits for a durable ack.
const STREAM_WRITES: u32 = 32;
const ARTIFACT: &[u8] = b"unapplied artifact bytes, several of them";

fn block_id(index: u32) -> BlockIdExt {
    let mut hash = [0u8; 32];
    hash[..4].copy_from_slice(&index.to_be_bytes());
    hash[31] = 0x5a;
    BlockIdExt::with_params(
        ShardIdent::masterchain(),
        index,
        UInt256::from(hash),
        UInt256::default(),
    )
}

fn open_storage(dir: &Path) -> (BlockHandleStorage, Arc<RocksDb>, Arc<RocksDb>) {
    let main = RocksDb::new(dir, "db", None, AccessType::ReadWrite).unwrap();
    let catchain = RocksDb::new(dir, "catchains", None, AccessType::ReadWrite).unwrap();
    let storage = BlockHandleStorage::with_dbs(
        Arc::new(BlockHandleDb::with_db(main.clone(), "block_handles", true).unwrap()),
        Arc::new(NodeStateDb::with_db(main.clone(), "full_node_states", true).unwrap()),
        Arc::new(NodeStateDb::with_db(catchain.clone(), "validator_states", true).unwrap()),
        #[cfg(feature = "telemetry")]
        Arc::new(StorageTelemetry::default()),
        Arc::new(StorageAlloc::default()),
    );
    (storage, main, catchain)
}

fn receipt(line: &str) {
    // Leading newline: the test harness's own progress line has no newline yet.
    let mut out = std::io::stdout().lock();
    writeln!(out, "\n{line}").unwrap();
    out.flush().unwrap();
}

/// Write `index` of the stream scenario: kinds rotate over a handle, a
/// full-node pointer, a validator-state pointer (separate physical DB) and a
/// durably acknowledged full-node pointer. Each write has its own key.
async fn stream_write(storage: &BlockHandleStorage, index: u32) {
    let id = block_id(index);
    match index % 4 {
        0 => storage.save_validator_state(format!("V{index}"), &id).unwrap(),
        1 => {
            storage.create_handle(id, BlockMeta::default(), None).unwrap().unwrap();
        }
        2 => storage.save_full_node_state(format!("F{index}"), &id).unwrap(),
        _ => {
            storage.save_full_node_state_durable(format!("F{index}"), &id).await.unwrap();
            receipt(&format!("ACK {index}"));
        }
    }
    if index % 6 == 0 {
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
}

fn stream_presence(dir: &Path) -> Vec<bool> {
    let main = RocksDb::new(dir, "db", None, AccessType::ReadWrite).unwrap();
    let catchain = RocksDb::new(dir, "catchains", None, AccessType::ReadWrite).unwrap();
    let handles = BlockHandleDb::with_db(main.clone(), "block_handles", true).unwrap();
    let full_node = NodeStateDb::with_db(main.clone(), "full_node_states", true).unwrap();
    let validator = NodeStateDb::with_db(catchain.clone(), "validator_states", true).unwrap();
    (1..=STREAM_WRITES)
        .map(|index| match index % 4 {
            0 => validator.try_get_raw(format!("V{index}").as_bytes()).unwrap().is_some(),
            1 => handles.try_get_raw(block_id(index).root_hash().as_slice()).unwrap().is_some(),
            _ => full_node.try_get_raw(format!("F{index}").as_bytes()).unwrap().is_some(),
        })
        .collect()
}

async fn child_stream(dir: &Path) {
    let (storage, _main, _catchain) = open_storage(dir);
    for index in 1..=STREAM_WRITES {
        stream_write(&storage, index).await;
    }
    storage.sync_pending().await.unwrap();
    receipt("DONE");
}

/// Harness self-check: one synced write, then one unsynced direct write.
async fn child_self_check(dir: &Path) {
    let main = RocksDb::new(dir, "db", None, AccessType::ReadWrite).unwrap();
    main.db().put(b"synced", b"1").unwrap();
    main.sync_wal().unwrap();
    main.db().put(b"unsynced", b"1").unwrap();
    receipt("WROTE");
    std::process::abort();
}

async fn child_unapplied(dir: &Path) {
    let root = dir.to_path_buf();
    let unapplied = root.join("archive").join("unapplied");
    std::fs::create_dir_all(&unapplied).unwrap();
    let directory = UnappliedDirectory::open(unapplied, root).await.unwrap();
    for index in 1..=3u32 {
        directory
            .publish(std::ffi::OsStr::new(&format!("artifact{index}")), ARTIFACT)
            .await
            .unwrap();
        receipt(&format!("ACK {index}"));
    }
    receipt("DONE");
}

/// Entry point of the child process; a no-op in an ordinary test run.
#[test]
fn crash_cut_child_entry() {
    let Some(scenario) = std::env::var_os(CHILD_SCENARIO) else { return };
    let dir = PathBuf::from(std::env::var_os(CHILD_DIR).unwrap());
    let runtime =
        tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    runtime.block_on(async {
        match scenario.to_str().unwrap() {
            "stream" => child_stream(&dir).await,
            "self-check" => child_self_check(&dir).await,
            "unapplied" => child_unapplied(&dir).await,
            other => panic!("unknown crash scenario {other}"),
        }
    });
    // Leave without destructors: a clean exit must not add flushes the
    // scenario did not ask for.
    std::process::exit(0);
}

struct ChildRun {
    receipts: Vec<String>,
    completed: bool,
    aborted: bool,
}

impl ChildRun {
    fn acked(&self) -> BTreeSet<u32> {
        self.receipts.iter().filter_map(|line| line.strip_prefix("ACK ")?.parse().ok()).collect()
    }
}

fn run_child(scenario: &str, dir: &Path, cut: Option<&str>, buffered_wal: bool) -> ChildRun {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([CHILD_TEST, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD_SCENARIO, scenario)
        .env(CHILD_DIR, dir)
        .env_remove("RTOS_CRASH_CUT")
        .env_remove("RTOS_CRASH_BUFFERED_WAL");
    if let Some(cut) = cut {
        command.env("RTOS_CRASH_CUT", cut);
    }
    if buffered_wal {
        command.env("RTOS_CRASH_BUFFERED_WAL", "1");
    }
    let output = command.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let receipts: Vec<String> = stdout
        .lines()
        .filter(|line| line.starts_with("ACK ") || *line == "DONE" || *line == "WROTE")
        .map(str::to_owned)
        .collect();
    let completed = receipts.iter().any(|line| line == "DONE");
    let aborted = String::from_utf8_lossy(&output.stderr).contains("CRASH_CUT");
    ChildRun { receipts, completed, aborted }
}

/// The buffered-WAL model must actually lose an unsynced write at abort and
/// keep a synced one. Without the model the page cache keeps both, which is
/// why process kill alone proves nothing about WAL durability.
#[test]
fn crash_cut_harness_self_check() {
    if std::env::var_os(CHILD_SCENARIO).is_some() {
        return;
    }
    for buffered in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let run = run_child("self-check", dir.path(), None, buffered);
        assert_eq!(run.receipts, ["WROTE"]);
        let main = RocksDb::new(dir.path(), "db", None, AccessType::ReadWrite).unwrap();
        assert!(main.db().get(b"synced").unwrap().is_some(), "synced write lost");
        let unsynced = main.db().get(b"unsynced").unwrap().is_some();
        assert_eq!(
            unsynced,
            !buffered,
            "buffered-WAL model {} did not behave as modelled",
            if buffered { "on" } else { "off" }
        );
    }
}

fn check_stream(dir: &Path, run: &ChildRun, label: &str) -> u32 {
    let present = stream_presence(dir);
    // FIFO prefix of the ordered writer's stream, across both databases.
    let prefix = present.iter().take_while(|present| **present).count() as u32;
    for (offset, present) in present.iter().enumerate() {
        let index = offset as u32 + 1;
        assert!(
            !*present || index <= prefix,
            "{label}: write {index} survived but write {} before it did not",
            prefix + 1
        );
    }
    // Every acknowledged write survived.
    for acked in run.acked() {
        assert!(acked <= prefix, "{label}: acknowledged write {acked} lost (prefix {prefix})");
    }
    if run.completed {
        assert_eq!(prefix, STREAM_WRITES, "{label}: completed run lost writes");
        assert_eq!(run.acked().len() as u32, STREAM_WRITES / 4, "{label}: receipts not parsed");
    }
    prefix
}

/// Every cut point of the ordered writer, at every arrival: acknowledged
/// writes survive, and what survives is a prefix of the writer's stream.
#[test]
fn crash_cut_ordered_writer_matrix() {
    if std::env::var_os(CHILD_SCENARIO).is_some() {
        return;
    }
    let mut rows = Vec::new();
    for point in ["handles.before_commit", "handles.between_runs", "handles.after_commit"] {
        let mut nth = 1u32;
        loop {
            let dir = tempfile::tempdir().unwrap();
            let cut = format!("{point}:{nth}");
            let run = run_child("stream", dir.path(), Some(&cut), true);
            let prefix = check_stream(dir.path(), &run, &cut);
            rows.push(format!(
                "{cut} aborted={} acked={} survived_prefix={prefix}",
                run.aborted,
                run.acked().len()
            ));
            if !run.aborted {
                assert!(run.completed, "{cut}: child neither aborted nor completed");
                break;
            }
            nth += 1;
            assert!(nth <= 64, "{point}: more arrivals than writes");
        }
    }
    for row in &rows {
        eprintln!("CRASH_MATRIX {row}");
    }
}

/// Every cut point of unapplied-artifact publication: a final name is either
/// absent or holds the complete artifact, an acknowledged artifact exists,
/// and reopening removes interrupted temporaries.
#[test]
fn crash_cut_unapplied_publication_matrix() {
    if std::env::var_os(CHILD_SCENARIO).is_some() {
        return;
    }
    let points = [
        "unapplied.after_write",
        "unapplied.after_file_sync",
        "unapplied.after_rename",
        "unapplied.after_dir_sync",
    ];
    for point in points {
        for nth in 1..=3u32 {
            let dir = tempfile::tempdir().unwrap();
            let cut = format!("{point}:{nth}");
            let run = run_child("unapplied", dir.path(), Some(&cut), true);
            assert!(run.aborted, "{cut}: cut point not reached");
            let unapplied = dir.path().join("archive").join("unapplied");
            for index in 1..=3u32 {
                let path = unapplied.join(format!("artifact{index}"));
                match std::fs::read(&path) {
                    Ok(bytes) => assert_eq!(bytes, ARTIFACT, "{cut}: partial artifact {index}"),
                    Err(error) => {
                        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
                        assert!(
                            !run.acked().contains(&index),
                            "{cut}: acknowledged artifact {index} missing"
                        );
                    }
                }
            }
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime
                .block_on(UnappliedDirectory::open(unapplied.clone(), dir.path().to_path_buf()))
                .unwrap();
            let leftovers = std::fs::read_dir(&unapplied)
                .unwrap()
                .filter(|entry| {
                    entry
                        .as_ref()
                        .unwrap()
                        .file_name()
                        .to_str()
                        .unwrap()
                        .ends_with(UNAPPLIED_TEMPORARY_SUFFIX)
                })
                .count();
            assert_eq!(leftovers, 0, "{cut}: interrupted temporary survived reopening");
            eprintln!("CRASH_MATRIX {cut} acked={:?}", run.acked());
        }
    }
}

/// A failed commit poisons the writer: no later write is acknowledged as
/// durable, even one that would itself succeed.
#[tokio::test]
async fn failed_commit_refuses_later_durable_acks() {
    let dir = tempfile::tempdir().unwrap();
    let (storage, main, _catchain) = open_storage(dir.path());
    storage.save_full_node_state_durable("before".to_owned(), &block_id(1)).await.unwrap();
    main.drop_table("block_handles").unwrap();
    let handle = storage.create_handle(block_id(2), BlockMeta::default(), None);
    // Admission succeeds; the physical commit fails. Wait for that failure so
    // the next write is a separate commit that would succeed on its own.
    assert!(handle.is_ok());
    assert!(storage.sync_pending().await.is_err());
    let later = storage.save_full_node_state_durable("after".to_owned(), &block_id(3)).await;
    assert!(later.is_err(), "write after a failed commit was acknowledged durable");
    let states = NodeStateDb::with_db(main.clone(), "full_node_states", false).unwrap();
    assert!(states.try_get_raw(b"after").unwrap().is_none(), "poisoned writer kept writing");
    assert!(states.try_get_raw(b"before").unwrap().is_some());
}

/// A direct synchronized write is never overwritten by an older queued write
/// of the same key that commits after it.
#[tokio::test]
async fn direct_write_supersedes_older_queued_write() {
    struct Hold {
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }
    #[async_trait::async_trait]
    impl crate::block_handle_db::Callback for Hold {
        async fn invoke(&self, _job: crate::block_handle_db::StoreJob, _ok: bool) {
            self.entered.notify_one();
            self.release.notified().await;
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let (storage, _main, _catchain) = open_storage(dir.path());
    let hold = Arc::new(Hold { entered: Default::default(), release: Default::default() });
    let blocker = storage.create_handle(block_id(9), BlockMeta::default(), None).unwrap().unwrap();
    storage.save_handle(&blocker, Some(hold.clone())).unwrap();
    hold.entered.notified().await;
    // Queued behind the held callback: an older value of the key.
    storage.save_validator_state("Rotation".to_owned(), &block_id(100)).unwrap();
    // The authoritative value, written directly while the old one is queued.
    let value = block_id(7).serialize().to_vec();
    storage
        .write_validator_state_batch_sync(&[("Rotation".to_owned(), value.clone())], &[])
        .unwrap();
    hold.release.notify_one();
    storage.sync_pending().await.unwrap();
    assert_eq!(storage.load_validator_state_raw("Rotation").unwrap(), Some(value));
    assert_eq!(storage.load_validator_state("Rotation").unwrap().unwrap().seq_no(), 7);
}

/// Durable acknowledgement latency with an idle writer and behind a backlog
/// of queued writes. Measurement only; prints its numbers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement; run explicitly"]
async fn durability_profile_ack_latency() {
    let dir = tempfile::tempdir().unwrap();
    let (storage, main, _catchain) = open_storage(dir.path());
    storage.sync_pending().await.unwrap();
    let mut idle = Vec::new();
    for index in 0..200u32 {
        let started = std::time::Instant::now();
        storage.save_full_node_state_durable("Idle".to_owned(), &block_id(index)).await.unwrap();
        idle.push(started.elapsed());
    }
    let before = main.wal_synced_count();
    let mut backlog = Vec::new();
    for round in 0..20u32 {
        for index in 0..500u32 {
            storage
                .save_full_node_state(format!("Q{index}"), &block_id(round * 500 + index))
                .unwrap();
        }
        let started = std::time::Instant::now();
        storage.save_full_node_state_durable("Behind".to_owned(), &block_id(round)).await.unwrap();
        backlog.push(started.elapsed());
    }
    let after = main.wal_synced_count();
    let summary = |samples: &mut Vec<std::time::Duration>| {
        samples.sort();
        let at =
            |q: f64| samples[((samples.len() as f64 - 1.0) * q) as usize].as_secs_f64() * 1000.0;
        format!("p50={:.3}ms p99={:.3}ms max={:.3}ms", at(0.5), at(0.99), at(1.0))
    };
    eprintln!(
        "ACK_LATENCY idle({}) backlog500({}) backlog_wal_syncs_for_10000_writes={:?}",
        summary(&mut idle),
        summary(&mut backlog),
        before.zip(after).map(|(b, a)| a - b)
    );
}
