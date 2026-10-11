// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Real constructor rejection and physical preservation, not an observation of
//! whether a GC thread was scheduled. Ledger loading precedes storage consumers
//! in InternalDb::new; this test verifies its externally observable boundary.
use super::*;
use crate::{
    config::TonNodeConfig,
    engine::{EngineFlags, Stopper},
};
use std::collections::BTreeMap;

fn physical_state(db: &Arc<RocksDb>) -> BTreeMap<String, BTreeMap<Vec<u8>, Vec<u8>>> {
    ["cells_db_v6", "cells_db_v6_counters", crate::internal_db::SHARDSTATE_DB_NAME]
        .into_iter()
        .map(|name| {
            let table = db.clone().table::<String>(name, false).unwrap();
            let mut records = BTreeMap::new();
            table
                .for_each(&mut |key, bytes| {
                    records.insert(key.to_vec(), bytes.to_vec());
                    Ok(true)
                })
                .unwrap();
            assert!(!records.is_empty(), "actual {name} fixture must exist");
            (name.to_owned(), records)
        })
        .collect()
}
fn archive_bytes(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();
    let mut pending = vec![root.join("archives")];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                pending.push(entry.path());
            } else {
                assert!(kind.is_file());
                files.insert(
                    entry.path().strip_prefix(root).unwrap().to_owned(),
                    std::fs::read(entry.path()).unwrap(),
                );
            }
        }
    }
    assert!(!files.is_empty(), "actual archive artifacts must exist");
    files
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persistent_repair_corrupt_ledger_rejects_engine_and_preserves_physical_dependencies() {
    let fixture = fixture(true).await;
    let exact = binding(&fixture);
    let Fixture { dir, engine, parent, target, request } = fixture;
    let setup = std::panic::AssertUnwindSafe(async {
        let cap = obtain_durable_mc_custody(engine.clone(), request, exact.clone()).await.unwrap();
        let result = (
            PathBuf::from(engine.db_root_dir().unwrap()),
            cap.lease_generation(),
            cap.dependency_digest().clone(),
        );
        drop(cap);
        result
    })
    .catch_unwind()
    .await;
    close(engine).await;
    let (root, generation, digest) = setup.unwrap_or_else(|p| std::panic::resume_unwind(p));
    let db = open_cells_for_fault_injection(&root);
    let table = db.clone().table::<String>("repair_dependency_leases_v1", false).unwrap();
    let key = format!("lease/{generation:020}");
    let original = table.get(&key).unwrap().to_vec();
    let states_before = physical_state(&db);
    let files_before = archive_bytes(&root);
    table.put_raw_sync(key.as_bytes(), b"{invalid-ledger-json").unwrap();
    drop(table);
    drop(db);

    let config = TonNodeConfig::from_file(
        dir.path().to_str().unwrap(),
        "config.json",
        None,
        "config.json",
        None,
    )
    .await
    .unwrap();
    let stopper = Arc::new(Stopper::new());
    let result = Engine::new(
        config,
        EngineFlags { initial_sync_disabled: true, force_check_db: false, truncate_db: None },
        stopper.clone(),
    )
    .await;
    let error = match result {
        Ok(engine) => {
            close(engine).await;
            None
        }
        Err(error) => Some(error),
    };
    let drained = tokio::time::timeout(Duration::from_secs(20), async {
        while Arc::strong_count(&stopper) != 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    // Reacquiring RocksDB also checks that failed construction released its
    // actual DB ownership. Restore the exact valid lease before assertions.
    let db = open_cells_for_fault_injection(&root);
    let states_after = physical_state(&db);
    let files_after = archive_bytes(&root);
    let table = db.clone().table::<String>("repair_dependency_leases_v1", false).unwrap();
    let damaged = table.get(&key).unwrap().to_vec();
    table.put_raw_sync(key.as_bytes(), &original).unwrap();
    assert_eq!(table.get(&key).unwrap().to_vec(), original);
    drop(table);
    drop(db);
    drained.expect("failed Engine constructor must release its owned network/DB tasks");
    let error = error.expect("damaged ledger must reject real Engine construction");
    assert!(
        error.chain().any(|cause| cause.downcast_ref::<serde_json::Error>().is_some()),
        "failure must come from actual ledger JSON decoding: {error:#}"
    );
    assert_eq!(damaged, b"{invalid-ledger-json");
    assert_eq!(states_after, states_before);
    assert_eq!(files_after, files_before);

    let engine = open_engine(dir.path()).await;
    let verify = std::panic::AssertUnwindSafe(async {
        for id in [parent.id(), target.id()] {
            assert!(engine.db().test_contains_dynamic_state_record(id).unwrap());
            let state = engine.load_state(id).await.unwrap();
            assert!(!write_boc(state.root_cell()).unwrap().is_empty());
            let handle = engine.load_block_handle(id).unwrap().unwrap();
            assert_eq!(engine.load_block(&handle).await.unwrap().id(), id);
            engine.load_block_proof(&handle, false).await.unwrap();
        }
        let custody = reopen_durable_mc_custody(engine.clone(), generation, exact.clone(), digest)
            .await
            .unwrap();
        assert_eq!(custody.binding(), &exact);
        drop(custody);
    })
    .catch_unwind()
    .await;
    close(engine).await;
    verify.unwrap_or_else(|p| std::panic::resume_unwind(p));
}
