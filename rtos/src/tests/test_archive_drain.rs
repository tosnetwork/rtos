// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{
    archive_import::ImportConfig,
    config::TonNodeConfig,
    engine::{Engine, EngineFlags, Stopper},
    internal_db::{
        InternalDb, ARCHIVES_GC_BLOCK, LAST_APPLIED_MC_BLOCK, PSS_KEEPER_MC_BLOCK,
        SHARD_CLIENT_MC_BLOCK,
    },
    shard_state::ShardStateStuff,
};
use rtos_block::*;
use std::{
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
    time::Duration,
};
use tokio::sync::{Notify, Semaphore};

#[path = "test_archive_import_fixture.rs"]
mod authenticated_fixture;
use authenticated_fixture::Fixture;

// Required by the shared fixture's offline assertion helper.
async fn check_imported_block(db: &InternalDb, id: &BlockIdExt) -> Result<Option<BlockStuff>> {
    let handle = db.load_block_handle(id)?.ok_or_else(|| error!("missing block"))?;
    assert!(handle.is_applied());
    if id.seq_no == 0 {
        Ok(None)
    } else {
        Ok(Some(db.load_block_data(&handle).await?))
    }
}

struct Gate {
    stage: u8,
    entered: Notify,
    release: Semaphore,
}
fn gates() -> &'static Mutex<HashMap<usize, Arc<Gate>>> {
    static GATES: OnceLock<Mutex<HashMap<usize, Arc<Gate>>>> = OnceLock::new();
    GATES.get_or_init(Default::default)
}
fn key(engine: &Arc<dyn EngineOperations>) -> usize {
    Arc::as_ptr(engine) as *const () as usize
}
pub(super) async fn hold(engine: &Arc<dyn EngineOperations>, stage: u8) -> Result<()> {
    let gate = gates().lock().unwrap().get(&key(engine)).cloned();
    if let Some(gate) = gate.filter(|gate| gate.stage == stage) {
        gate.entered.notify_one();
        gate.release.acquire().await.unwrap().forget();
    }
    Ok(())
}

struct GateRegistration {
    key: usize,
    gate: Arc<Gate>,
}
impl Drop for GateRegistration {
    fn drop(&mut self) {
        gates().lock().unwrap().remove(&self.key);
        // Unblock an accepted real worker before TestEngine's shutdown guard runs.
        self.gate.release.add_permits(1);
    }
}
fn install(engine: &Arc<dyn EngineOperations>, gate: &Arc<Gate>) -> GateRegistration {
    gates().lock().unwrap().insert(key(engine), gate.clone());
    GateRegistration { key: key(engine), gate: gate.clone() }
}

// Ensure assertion failures and causal controls also close real OS workers before
// the test runtime drops. This guard owns no fabricated completion condition.
struct TestEngine(Arc<Engine>);
impl std::ops::Deref for TestEngine {
    type Target = Arc<Engine>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Drop for TestEngine {
    fn drop(&mut self) {
        let engine = self.0.clone();
        let runtime = tokio::runtime::Handle::current();
        let joined = std::thread::spawn(move || {
            runtime.block_on(async {
                tokio::time::timeout(Duration::from_secs(30), engine.wait_stop()).await
            })
        })
        .join();
        if !matches!(joined, Ok(Ok(_))) {
            eprintln!("archive fixture cleanup failed: {joined:?}");
        }
    }
}

async fn open(dir: &Path) -> TestEngine {
    let config =
        TonNodeConfig::from_file(dir.to_str().unwrap(), "config.json", None, "config.json", None)
            .await
            .unwrap();
    TestEngine(
        Engine::new(
            config,
            EngineFlags { initial_sync_disabled: true, force_check_db: false, truncate_db: None },
            Arc::new(Stopper::new()),
        )
        .await
        .unwrap(),
    )
}
async fn prepare(dir: &Path, fixture: &Fixture, wrong_pin: bool) -> TestEngine {
    fixture.prepare(dir, &dir.join("archives")).await.unwrap();
    let (adnl, _) =
        adnl::node::AdnlNodeConfig::with_ip_address_and_private_key_tags("127.0.0.1:0", vec![1, 2])
            .unwrap();
    let mut adnl = serde_json::to_value(adnl).unwrap();
    adnl["ip_address_quic"] = serde_json::json!("127.0.0.1:0");
    if wrong_pin {
        let path = dir.join("authenticated-global.json");
        let mut global: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        global["validator"]["zero_state"]["file_hash"] =
            serde_json::json!(UInt256::from([93; 32]).as_base64(false));
        std::fs::write(path, serde_json::to_vec(&global).unwrap()).unwrap();
    }
    std::fs::write(
        dir.join("config.json"),
        serde_json::to_vec(&serde_json::json!({
            "ton_global_config_name":"authenticated-global.json", "boot_from_zerostate":true,
            "internal_db_path":dir.join("db"), "restore_db":false, "sync_by_archives":false,
            "adnl_node":adnl, "validator_keys":[], "validator_key_ring":{}, "json_rpc_server":null,
            "control_server":null, "lite_server":null,
            "test_bundles_config":{"collator":{"path":""},"validator":{"path":""}}
        }))
        .unwrap(),
    )
    .unwrap();
    let engine = open(dir).await;
    for wc in [false, true] {
        let id = fixture.id(0, wc);
        let bytes = std::fs::read(dir.join(if wc {
            "authenticated-wc-zero.boc"
        } else {
            "authenticated-mc-zero.boc"
        }))
        .unwrap();
        let state = ShardStateStuff::deserialize_zerostate(
            id,
            &bytes,
            #[cfg(feature = "telemetry")]
            engine.engine_telemetry(),
            engine.engine_allocated(),
        )
        .unwrap();
        // Use the same verified zerostate initialization as boot::download_zerostate.
        // No imported nonzero block is ever marked applied by the fixture.
        let (_, handle) = engine.store_zerostate(state, &bytes).await.unwrap();
        engine.set_applied(&handle, 0).await.unwrap();
    }
    engine.save_last_applied_mc_block_id(&fixture.id(0, false)).unwrap();
    engine.save_shard_client_mc_block_id(&fixture.id(0, false)).unwrap();
    engine
}
async fn maps(dir: &Path) -> BlockMaps {
    read_package(&std::fs::read(dir.join("archives/archive.00001.pack")).unwrap()).await.unwrap()
}
async fn import_first(
    engine: Arc<dyn EngineOperations>,
    mut maps: BlockMaps,
    previous: BlockIdExt,
) -> Result<()> {
    // Enter the production archive MC loop with one authenticated successor.
    maps.mc_blocks_ids = Arc::new(
        maps.mc_blocks_ids
            .iter()
            .filter(|(seq, _)| **seq == 1)
            .map(|(seq, id)| (*seq, id.clone()))
            .collect(),
    );
    let (wait, _) = Wait::new();
    let mut context = SyncContext { concurrency: 1, downloads: 1, engine, wait };
    let archive = ArchiveContext {
        absent_shards: Default::default(),
        loaded_shards: Default::default(),
        master: Some(maps),
        need_shards: false,
        shards_count: 0,
    };
    import_mc_blocks(&mut context, &Arc::new(previous), &archive).await
}
async fn stop(engine: Arc<Engine>) {
    tokio::time::timeout(Duration::from_secs(30), engine.wait_stop()).await.unwrap().unwrap();
}
async fn assert_applied(engine: &Arc<Engine>, fixture: &Fixture) {
    let id = fixture.id(1, false);
    let handle = engine.load_block_handle(&id).unwrap().unwrap();
    assert!(handle.is_applied(), "accepted import did not complete normal apply");
    let state = engine.load_state(&id).await.unwrap();
    let data: serde_json::Value =
        serde_json::from_str(include_str!("static/archive-mc-wc.json")).unwrap();
    let expected = read_single_root_boc(
        &hex::decode(data["cases"][0]["state_boc"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(state.root_cell().repr_hash(), expected.repr_hash());
    assert_eq!(engine.load_last_applied_mc_block_id().unwrap().unwrap().as_ref(), &id);
    engine.load_block_proof(&handle, false).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn archive_drain_cancel_before_admission_has_no_block_writes() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    let engine = prepare(dir.path(), &fixture, false).await;
    let ops: Arc<dyn EngineOperations> = engine.clone();
    let gate = Arc::new(Gate { stage: 0, entered: Notify::new(), release: Semaphore::new(0) });
    let _registration = install(&ops, &gate);
    let maps = maps(dir.path()).await;
    let id = fixture.id(1, false);
    let worker = tokio::spawn({
        let ops = ops.clone();
        let previous = fixture.id(0, false);
        async move { import_first(ops, maps, previous).await }
    });
    tokio::time::timeout(Duration::from_secs(30), gate.entered.notified()).await.unwrap();
    worker.abort();
    assert!(worker.await.unwrap_err().is_cancelled());
    assert!(engine.load_block_handle(&id).unwrap().is_none());
    gates().lock().unwrap().remove(&key(&ops));
    drop(ops);
    stop(engine.clone()).await;
    drop(engine);
    let reopened = open(dir.path()).await;
    assert!(reopened.load_block_handle(&id).unwrap().is_none());
    stop(reopened.clone()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn archive_drain_cancel_after_store_waits_for_real_apply_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    let engine = prepare(dir.path(), &fixture, false).await;
    let ops: Arc<dyn EngineOperations> = engine.clone();
    let gate = Arc::new(Gate { stage: 1, entered: Notify::new(), release: Semaphore::new(0) });
    let _registration = install(&ops, &gate);
    let maps = maps(dir.path()).await;
    let id = fixture.id(1, false);
    let worker = tokio::spawn({
        let ops = ops.clone();
        let previous = fixture.id(0, false);
        async move { import_first(ops, maps, previous).await }
    });
    tokio::time::timeout(Duration::from_secs(30), gate.entered.notified()).await.unwrap();
    let handle = engine.load_block_handle(&id).unwrap().unwrap();
    assert!(handle.has_data());
    assert!(!handle.is_applied());
    drop(handle);
    worker.abort();
    assert!(worker.await.unwrap_err().is_cancelled());
    let shutting = tokio::spawn(stop(engine.clone()));
    while !engine.check_stop() {
        tokio::task::yield_now().await;
    }
    assert!(!shutting.is_finished());
    gate.release.add_permits(1);
    shutting.await.unwrap();
    assert_applied(&engine, &fixture).await;
    gates().lock().unwrap().remove(&key(&ops));
    drop(ops);
    drop(engine);
    let reopened = open(dir.path()).await;
    assert_applied(&reopened, &fixture).await;
    stop(reopened.clone()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn archive_drain_bad_proof_and_wrong_pin_do_not_write_first_block() {
    for wrong_pin in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let fixture = Fixture::new();
        let engine = prepare(dir.path(), &fixture, wrong_pin).await;
        let ops: Arc<dyn EngineOperations> = engine.clone();
        let mut maps = maps(dir.path()).await;
        let id = fixture.id(1, false);
        let entry = maps.blocks.get_mut(&id).unwrap();
        if !wrong_pin {
            let root = read_single_root_boc(entry.proof.as_ref().unwrap().data()).unwrap();
            let mut proof = BlockProof::construct_from_cell(root).unwrap();
            let Some(BlockSignaturesVariant::SimplexPq(signatures)) = proof.signatures.as_mut()
            else {
                panic!("fixture must carry PQ signatures")
            };
            signatures.signatures[0].signature[0] ^= 1;
            entry.proof = Some(Arc::new(BlockProofStuff::new(proof, false).unwrap()));
        }
        assert!(import_first(ops.clone(), maps, fixture.id(0, false)).await.is_err());
        assert!(engine.load_block_handle(&id).unwrap().is_none());
        drop(ops);
        stop(engine.clone()).await;
        drop(engine);
        let reopened = open(dir.path()).await;
        assert!(reopened.load_block_handle(&id).unwrap().is_none());
        stop(reopened.clone()).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn archive_drain_shutdown_rejects_authenticated_but_unaccepted_block() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    let engine = prepare(dir.path(), &fixture, false).await;
    let ops: Arc<dyn EngineOperations> = engine.clone();
    let gate = Arc::new(Gate { stage: 0, entered: Notify::new(), release: Semaphore::new(0) });
    let _registration = install(&ops, &gate);
    let maps = maps(dir.path()).await;
    let previous = fixture.id(0, false);
    let worker = tokio::spawn({
        let ops = ops.clone();
        async move { import_first(ops, maps, previous).await }
    });
    tokio::time::timeout(Duration::from_secs(30), gate.entered.notified()).await.unwrap();
    stop(engine.clone()).await;
    gate.release.add_permits(1);
    let error = worker.await.unwrap().unwrap_err();
    assert!(error.to_string().contains("stopp"), "unexpected rejection: {error:#}");
    assert!(engine.load_block_handle(&fixture.id(1, false)).unwrap().is_none());
    gates().lock().unwrap().remove(&key(&ops));
    drop(ops);
    drop(engine);
    let reopened = open(dir.path()).await;
    assert!(reopened.load_block_handle(&fixture.id(1, false)).unwrap().is_none());
    stop(reopened.clone()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn archive_drain_corrupt_package_fails_before_admission() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    let engine = prepare(dir.path(), &fixture, false).await;
    let mut bytes = std::fs::read(dir.path().join("archives/archive.00001.pack")).unwrap();
    // Corrupt the package framing, not the trusted zero states.
    bytes[0] ^= 0xff;
    assert!(read_package(&bytes).await.is_err());
    assert!(engine.load_block_handle(&fixture.id(1, false)).unwrap().is_none());
    stop(engine.clone()).await;
    drop(engine);
    let reopened = open(dir.path()).await;
    assert!(reopened.load_block_handle(&fixture.id(1, false)).unwrap().is_none());
    stop(reopened.clone()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn archive_drain_unobserved_accepted_failure_is_sticky_and_retryable_after_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    let engine = prepare(dir.path(), &fixture, false).await;
    let ops: Arc<dyn EngineOperations> = engine.clone();
    let gate = Arc::new(Gate { stage: 1, entered: Notify::new(), release: Semaphore::new(0) });
    let _registration = install(&ops, &gate);
    let package_maps = maps(dir.path()).await;
    let previous = fixture.id(0, false);
    let worker = tokio::spawn({
        let ops = ops.clone();
        async move { import_first(ops, package_maps, previous).await }
    });
    tokio::time::timeout(Duration::from_secs(30), gate.entered.notified()).await.unwrap();
    use storage::archives::package_entry_id::{GetFileName, PackageEntryId};
    let obstruction = dir
        .path()
        .join("db/archive/unapplied")
        .join(PackageEntryId::Proof(fixture.id(1, false)).filename_short());
    std::fs::create_dir(&obstruction).unwrap();
    worker.abort();
    assert!(worker.await.unwrap_err().is_cancelled());
    gate.release.add_permits(1);
    let error = tokio::time::timeout(Duration::from_secs(30), engine.clone().wait_stop())
        .await
        .unwrap()
        .unwrap_err();
    assert!(error.to_string().contains("Unobserved archive import failure"), "{error:#}");
    assert!(
        error.to_string().contains("Is a directory"),
        "expected actual proof file I/O failure: {error:#}"
    );
    assert_eq!(
        engine.load_last_applied_mc_block_id().unwrap().unwrap().as_ref(),
        &fixture.id(0, false)
    );
    assert!(!engine.load_block_handle(&fixture.id(1, false)).unwrap().unwrap().is_applied());
    gates().lock().unwrap().remove(&key(&ops));
    drop(ops);
    drop(engine);
    std::fs::remove_dir(&obstruction).unwrap();
    let reopened = open(dir.path()).await;
    import_first(reopened.clone(), maps(dir.path()).await, fixture.id(0, false)).await.unwrap();
    assert_applied(&reopened, &fixture).await;
    stop(reopened.clone()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn archive_drain_received_error_requires_acknowledgement() {
    for cancel_before_ack in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let fixture = Fixture::new();
        let engine = prepare(dir.path(), &fixture, false).await;
        let ops: Arc<dyn EngineOperations> = engine.clone();
        let gate = Arc::new(Gate { stage: 2, entered: Notify::new(), release: Semaphore::new(0) });
        let _registration = install(&ops, &gate);
        use storage::archives::package_entry_id::{GetFileName, PackageEntryId};
        let obstruction = dir
            .path()
            .join("db/archive/unapplied")
            .join(PackageEntryId::Proof(fixture.id(1, false)).filename_short());
        std::fs::create_dir(&obstruction).unwrap();
        let package_maps = maps(dir.path()).await;
        let previous = fixture.id(0, false);
        let worker = tokio::spawn({
            let ops = ops.clone();
            async move { import_first(ops, package_maps, previous).await }
        });
        tokio::time::timeout(Duration::from_secs(30), gate.entered.notified()).await.unwrap();
        if cancel_before_ack {
            worker.abort();
            assert!(worker.await.unwrap_err().is_cancelled());
            let error = engine.clone().wait_stop().await.unwrap_err();
            assert!(error.to_string().contains("Unobserved archive import failure"), "{error:#}");
        } else {
            gate.release.add_permits(1);
            let error = worker.await.unwrap().unwrap_err();
            assert!(error.to_string().contains("Is a directory"), "{error:#}");
            // The error was returned in the same poll that acknowledged it;
            // normal sync retry errors must not poison Engine shutdown.
            stop(engine.clone()).await;
        }
        assert!(!engine.load_block_handle(&fixture.id(1, false)).unwrap().unwrap().is_applied());
    }
}

async fn shard_archive(dir: &Path) -> ArchiveContext {
    let mut master = maps(dir).await;
    master.mc_blocks_ids = Arc::new(
        master
            .mc_blocks_ids
            .iter()
            .filter(|(seq, _)| **seq == 1)
            .map(|(seq, id)| (*seq, id.clone()))
            .collect(),
    );
    let shard = read_package(
        &std::fs::read(dir.join("archives/archive.00001.0:8000000000000000.pack")).unwrap(),
    )
    .await
    .unwrap();
    ArchiveContext {
        absent_shards: Default::default(),
        loaded_shards: HashMap::from([(ShardIdent::full(0), shard)]),
        master: Some(master),
        need_shards: true,
        shards_count: 1,
    }
}
async fn import_shards(engine: Arc<dyn EngineOperations>, archive: ArchiveContext) -> Result<()> {
    let (wait, _) = Wait::new();
    let mut context = SyncContext { concurrency: 1, downloads: 1, engine, wait };
    assert!(import_shard_blocks(&mut context, 1, archive).await?.is_none());
    Ok(())
}
async fn assert_shard_applied(engine: &Arc<Engine>, fixture: &Fixture) {
    let id = fixture.id(1, true);
    let handle = engine.load_block_handle(&id).unwrap().unwrap();
    assert!(handle.is_applied(), "accepted shard import did not complete normal apply");
    let state = engine.load_state(&id).await.unwrap();
    let data: serde_json::Value =
        serde_json::from_str(include_str!("static/archive-mc-wc.json")).unwrap();
    let expected = read_single_root_boc(
        &hex::decode(data["cases"][0]["wc_state_boc"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(state.root_cell().repr_hash(), expected.repr_hash());
    engine.load_block_proof(&handle, true).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn archive_drain_shard_cancel_drains_apply_and_recovers_cursor() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    let engine = prepare(dir.path(), &fixture, false).await;
    import_first(engine.clone(), maps(dir.path()).await, fixture.id(0, false)).await.unwrap();
    let ops: Arc<dyn EngineOperations> = engine.clone();
    let gate = Arc::new(Gate { stage: 3, entered: Notify::new(), release: Semaphore::new(0) });
    let _registration = install(&ops, &gate);
    let archive = shard_archive(dir.path()).await;
    let worker = tokio::spawn({
        let ops = ops.clone();
        async move { import_shards(ops, archive).await }
    });
    tokio::time::timeout(Duration::from_secs(30), gate.entered.notified()).await.unwrap();
    worker.abort();
    assert!(worker.await.unwrap_err().is_cancelled());
    let shutting = tokio::spawn(engine.clone().wait_stop());
    while !engine.check_stop() {
        tokio::task::yield_now().await;
    }
    assert!(!shutting.is_finished());
    gate.release.add_permits(1);
    shutting.await.unwrap().unwrap();
    assert_shard_applied(&engine, &fixture).await;
    // Cancellation interrupted the consumer cursor update, not accepted apply.
    assert_eq!(
        engine.load_shard_client_mc_block_id().unwrap().unwrap().as_ref(),
        &fixture.id(0, false)
    );
    gates().lock().unwrap().remove(&key(&ops));
    drop(ops);
    drop(engine);
    let reopened = open(dir.path()).await;
    assert_shard_applied(&reopened, &fixture).await;
    import_shards(reopened.clone(), shard_archive(dir.path()).await).await.unwrap();
    assert_eq!(
        reopened.load_shard_client_mc_block_id().unwrap().unwrap().as_ref(),
        &fixture.id(1, false)
    );
    stop(reopened.clone()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn archive_drain_shard_unobserved_file_failure_is_sticky_and_retryable() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    let engine = prepare(dir.path(), &fixture, false).await;
    import_first(engine.clone(), maps(dir.path()).await, fixture.id(0, false)).await.unwrap();
    let ops: Arc<dyn EngineOperations> = engine.clone();
    let gate = Arc::new(Gate { stage: 3, entered: Notify::new(), release: Semaphore::new(0) });
    let _registration = install(&ops, &gate);
    let archive = shard_archive(dir.path()).await;
    let worker = tokio::spawn({
        let ops = ops.clone();
        async move { import_shards(ops, archive).await }
    });
    tokio::time::timeout(Duration::from_secs(30), gate.entered.notified()).await.unwrap();
    use storage::archives::package_entry_id::{GetFileName, PackageEntryId};
    let obstruction = dir
        .path()
        .join("db/archive/unapplied")
        .join(PackageEntryId::ProofLink(fixture.id(1, true)).filename_short());
    let proof = std::fs::read(&obstruction).unwrap();
    std::fs::remove_file(&obstruction).unwrap();
    std::fs::create_dir(&obstruction).unwrap();
    worker.abort();
    assert!(worker.await.unwrap_err().is_cancelled());
    gate.release.add_permits(1);
    let error = tokio::time::timeout(Duration::from_secs(30), engine.clone().wait_stop())
        .await
        .unwrap()
        .unwrap_err();
    assert!(
        error.to_string().contains("Unobserved archive import failure (archive shard import)"),
        "{error:#}"
    );
    assert!(error.to_string().contains("Is a directory"), "{error:#}");
    assert!(!engine.load_block_handle(&fixture.id(1, true)).unwrap().unwrap().is_applied());
    assert_eq!(
        engine.load_shard_client_mc_block_id().unwrap().unwrap().as_ref(),
        &fixture.id(0, false)
    );
    gates().lock().unwrap().remove(&key(&ops));
    drop(ops);
    drop(engine);
    std::fs::remove_dir(&obstruction).unwrap();
    std::fs::write(&obstruction, proof).unwrap();
    let reopened = open(dir.path()).await;
    import_shards(reopened.clone(), shard_archive(dir.path()).await).await.unwrap();
    assert_shard_applied(&reopened, &fixture).await;
    assert_eq!(
        reopened.load_shard_client_mc_block_id().unwrap().unwrap().as_ref(),
        &fixture.id(1, false)
    );
    stop(reopened.clone()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn archive_drain_aggregate_cancel_does_not_ack_buffered_error() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    let engine = prepare(dir.path(), &fixture, false).await;
    let ops: Arc<dyn EngineOperations> = engine.clone();
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Semaphore::new(0));
    let path = dir.path().to_path_buf();
    let first = spawn_archive_task(&ops, "buffered archive error", async move {
        // A real filesystem error reaches the same retained result path.
        tokio::fs::read(path).await?;
        Ok(())
    })
    .unwrap();
    let second = spawn_archive_task(&ops, "held archive sibling", {
        let release = release.clone();
        async move {
            release.acquire().await.unwrap().forget();
            Ok(())
        }
    })
    .unwrap();
    let aggregate = tokio::spawn({
        let entered = entered.clone();
        async move {
            use futures::FutureExt;
            let first = first
                .map(move |result| {
                    entered.notify_one();
                    result
                })
                .boxed();
            futures::future::try_join_all(vec![first, second.boxed()]).await
        }
    });
    tokio::time::timeout(Duration::from_secs(30), entered.notified()).await.unwrap();
    // The first Err is now buffered as a receipt inside try_join_all.
    aggregate.abort();
    assert!(matches!(aggregate.await,Err(error) if error.is_cancelled()));
    release.add_permits(1);
    let error = tokio::time::timeout(Duration::from_secs(30), engine.clone().wait_stop())
        .await
        .unwrap()
        .unwrap_err();
    assert!(
        error.to_string().contains("Unobserved archive import failure (buffered archive error)"),
        "{error:#}"
    );
    assert!(error.to_string().contains("Is a directory"), "{error:#}");
}
