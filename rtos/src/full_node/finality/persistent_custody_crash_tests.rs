// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Two real authenticated-custody WAL cut points. The child is killed without
//! Engine/DB teardown; the cold parent exercises actual GC before reauthentication.
use super::*;
use crate::publication_dependency_leases::LeaseState;
use std::{
    fs,
    process::{Child, Command, Stdio},
    time::Instant,
};

const ROOT_ENV: &str = "RTOS_CUSTODY_CRASH_ROOT";
const PHASE_ENV: &str = "RTOS_CUSTODY_CRASH_PHASE";

fn write_synced(path: &Path, bytes: &[u8]) {
    use std::io::Write;
    let temporary = path.with_extension("pending");
    let mut file = fs::File::create(&temporary).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    drop(file);
    fs::rename(&temporary, path).unwrap();
    fs::File::open(path.parent().unwrap()).unwrap().sync_all().unwrap();
}

struct KillAndJoin(Child);
impl Drop for KillAndJoin {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "subprocess fixture: parent supplies owned directory and WAL phase"]
async fn persistent_repair_custody_process_crash_child() {
    let root = PathBuf::from(std::env::var_os(ROOT_ENV).expect("parent-owned crash directory"));
    let phase = std::env::var(PHASE_ENV).unwrap();
    assert!(matches!(phase.as_str(), "protecting" | "durable"));
    let fixture = gc_fixture_in(Some(&root)).await;
    let exact = gc_binding(&fixture);
    let Fixture { dir, engine, parent, target, request } = fixture;
    // The actual workchain zero belongs to the same pinned genesis and
    // collectable prefix, but is not an MC repair lease dependency. Its
    // original authenticated BOC remains separately retained after collection.
    let control = super::super::super::super::native_gc_fixture::workchain_zero_id();
    assert!(!control.shard().is_masterchain());
    assert_eq!(control.seq_no(), 0);
    assert_ne!(&control, parent.id());
    let state = engine.db().load_shard_state_dynamic(&control).unwrap();
    assert_eq!(state.block_id(), &control);
    assert_eq!(state.root_cell().repr_hash(), &control.root_hash);
    drop(state);
    engine.db().sync_publication_state().await.unwrap();
    assert!(engine.db().test_contains_dynamic_state_record(&control).unwrap());
    write_synced(
        &root.join("fixture.json"),
        &serde_json::to_vec(&serde_json::json!({
            "directory":dir.path(), "binding":exact.encode().unwrap(),
            "parent":parent.id().to_string(), "target":target.id().to_string(),
            "control":control.to_string(),
        }))
        .unwrap(),
    );
    let ready = root.join("phase.json");
    engine.db().repair_leases().set_commit_hook(Arc::new(move |record| {
        let selected = if phase == "protecting" {
            record.state == LeaseState::Protecting
        } else {
            record.state == LeaseState::DurableCustody
        };
        if selected {
            write_synced(&ready, &serde_json::to_vec(record).unwrap());
            // The parent owns kill/join. Never unwind, close RocksDB, or return a cap.
            loop {
                std::thread::park();
            }
        }
    }));
    let result = obtain_durable_mc_custody(engine.clone(), request, exact).await;
    // Unexpected return must report its real cause and drain Engine tasks, so
    // a failed setup cannot hang the subprocess runtime until the kill timeout.
    let detail = match result {
        Ok(cap) => {
            drop(cap);
            "unexpected successful return".to_owned()
        }
        Err(error) => format!("{error:#}"),
    };
    close(engine).await;
    drop(dir);
    panic!("custody child did not stop at its selected sync cut point: {detail}");
}

async fn crash_window(phase: &str) {
    let root = tempfile::tempdir().unwrap();
    let log_path = root.path().join("child.log");
    let log = fs::File::create(&log_path).unwrap();
    let test = format!(
        "{}::persistent_repair_custody_process_crash_child",
        module_path!().split_once("::").unwrap().1
    );
    let mut child = KillAndJoin(
        Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", &test, "--nocapture"])
            .env(ROOT_ENV, root.path())
            .env(PHASE_ENV, phase)
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(180);
    while !root.path().join("phase.json").exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "child failed before sync phase: {}",
            fs::read_to_string(&log_path).unwrap()
        );
        assert!(
            Instant::now() < deadline,
            "child sync phase timed out: {}",
            fs::read_to_string(&log_path).unwrap()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    child.0.kill().unwrap();
    let status = child.0.wait().unwrap();
    assert!(!status.success());
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(9), "must be SIGKILL, not graceful teardown");
    }
    let fixture: serde_json::Value =
        serde_json::from_slice(&fs::read(root.path().join("fixture.json")).unwrap()).unwrap();
    let record: crate::publication_dependency_leases::LeaseRecord =
        serde_json::from_slice(&fs::read(root.path().join("phase.json")).unwrap()).unwrap();
    assert_eq!(
        record.state,
        if phase == "protecting" { LeaseState::Protecting } else { LeaseState::DurableCustody }
    );
    let exact = RepairLeaseBinding::decode(
        &serde_json::from_value::<Vec<u8>>(fixture["binding"].clone()).unwrap(),
    )
    .unwrap();
    let directory = PathBuf::from(fixture["directory"].as_str().unwrap());
    let parent: BlockIdExt = fixture["parent"].as_str().unwrap().parse().unwrap();
    let target: BlockIdExt = fixture["target"].as_str().unwrap().parse().unwrap();
    let control: BlockIdExt = fixture["control"].as_str().unwrap().parse().unwrap();
    let digest: UInt256 = record.dependency_digest.parse().unwrap();
    let engine = open_engine(&directory).await;
    let run = std::panic::AssertUnwindSafe(async {
        let budget = crate::history_read_budget::HistoryReadBudget::new(Default::default());
        let cold = engine.db().repair_leases().lookup(record.generation, &budget).unwrap();
        assert_eq!(cold.state, record.state);
        assert_eq!(cold.binding, exact.encode().unwrap());
        assert!(
            engine.db().test_contains_dynamic_state_record(&control).unwrap(),
            "control must exist before this cold GC opportunity"
        );
        // First cold operation is a genuine GC opportunity, not capability
        // authentication or recreation of the killed child's temporary pins.
        assert!(
            !engine.shard_states_keeper().allow_state_gc(&control).unwrap(),
            "arm the batch observation before the control becomes GC eligible"
        );
        engine.db().test_watch_state_gc_batch(&control);
        super::super::super::super::native_gc_fixture::establish_floor(&engine);
        engine.shard_states_keeper().test_retire_history_state(&target);
        assert!(!engine.shard_states_keeper().allow_state_gc(&parent).unwrap());
        assert!(!engine.shard_states_keeper().allow_state_gc(&target).unwrap());
        tokio::time::timeout(Duration::from_secs(30), async {
            while engine.db().test_contains_dynamic_state_record(&control).unwrap()
                || !engine.db().test_watched_state_gc_batch_completed()
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("same-cutoff control must be physically deleted and its exact GC batch completed");
        assert!(engine.shard_states_keeper().allow_state_gc(&control).unwrap());
        engine.db().archive_gc(&target).await.unwrap();
        for id in [&parent, &target] {
            assert!(
                engine.db().test_contains_dynamic_state_record(id).unwrap(),
                "leased physical state {id} disappeared after the control GC batch completed"
            );
            // Cold physical graph traversal: root/index presence alone is insufficient.
            let state = engine.load_state(id).await.unwrap();
            assert!(!write_boc(state.root_cell()).unwrap().is_empty());
            let dependency = cold
                .dependencies
                .iter()
                .find(|d| d.kind == "state" && d.id == id.to_string())
                .unwrap();
            assert_eq!(
                dependency.root.as_deref(),
                Some(format!("{:x}", state.root_cell().repr_hash()).as_str())
            );
            let block =
                engine.load_block(&engine.load_block_handle(id).unwrap().unwrap()).await.unwrap();
            assert_eq!(block.id(), id);
            engine
                .load_block_proof(&engine.load_block_handle(id).unwrap().unwrap(), false)
                .await
                .unwrap();
        }
        if phase == "protecting" {
            assert!(
                reopen_durable_mc_custody(
                    engine.clone(),
                    record.generation,
                    exact.clone(),
                    digest.clone()
                )
                .await
                .is_err(),
                "a recovered Protecting marker must not mint DurableCustody"
            );
            let d = &exact.domain;
            let request = McFinalRepairRequest {
                pin: SessionNetworkPin { global_id: d.global_id, zerostate: d.zerostate.clone() },
                history_init: d.history_init.clone(),
                block_id: target.clone(),
                session_id: d.session_id.clone(),
                profile: d.profile.clone(),
                protocol: d.protocol,
                carrier_version: d.carrier_version,
                wire_profile: d.wire_profile,
            };
            let cap =
                obtain_durable_mc_custody(engine.clone(), request, exact.clone()).await.unwrap();
            assert_eq!(cap.lease_generation(), record.generation);
            assert_eq!(cap.dependency_digest(), &digest);
        } else {
            let cap = reopen_durable_mc_custody(
                engine.clone(),
                record.generation,
                exact.clone(),
                digest.clone(),
            )
            .await
            .unwrap();
            assert_eq!(cap.binding(), &exact);
        }
    })
    .catch_unwind()
    .await;
    close(engine).await;
    run.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persistent_repair_protecting_sigkill_cold_actual_gc_then_authentication() {
    crash_window("protecting").await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persistent_repair_durable_sigkill_before_offer_cold_actual_gc_then_authentication() {
    crash_window("durable").await;
}
