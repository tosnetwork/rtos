// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use consensus_common::session_runtime::{AuthenticatedSessionRuntime, SessionNetworkPin};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retired_history_real_gc_and_cold_reopen_preserve_authenticated_state() {
    let pair = Pair::with_gc_options("included", false, true, true).await;
    let (master_task, shard_task) = pair.apply_by_normal_clients().await;
    let result = std::panic::AssertUnwindSafe(async {
        let state = pair.receiver.load_state(&pair.anchor).await.unwrap();
        let config = state.config_params().unwrap();
        let (committee, _) = config
            .validator_set()
            .unwrap()
            .calc_subset(&config.catchain_config().unwrap(), SHARD_FULL, 0, 7)
            .unwrap();
        let runtime = Arc::new(
            AuthenticatedSessionRuntime::from_authenticated_config(
                SessionNetworkPin {
                    global_id: state.state().unwrap().global_id(),
                    zerostate: pair.anchor.clone(),
                },
                config,
                rtos_api::session_identity::SessionCoordinates {
                    shard: pair.shard.id().shard(),
                    catchain_seqno: 7,
                    vertical_seqno: 0,
                    last_key_block_seqno: 0,
                    new_catchain_ids: false,
                },
                committee,
                rtos_block::KeyId::from_data([0x91; 32]),
            )
            .unwrap()
            .bind_recovery_anchor(pair.anchor.clone())
            .unwrap(),
        );
        crate::retired_history::prepare(pair.receiver.clone(), runtime, pair.master.id().clone())
            .await
            .unwrap();
        assert_eq!(
            crate::retired_history::authenticate_state(pair.receiver.as_ref(), pair.master.id())
                .await
                .unwrap()
                .state()
                .root_cell()
                .repr_hash(),
            &pair.master_state_root
        );
    })
    .catch_unwind()
    .await;
    pair.receiver.clone().wait_stop().await.unwrap();
    master_task.await.unwrap();
    shard_task.await.unwrap();
    pair.provider.clone().wait_stop().await.unwrap();
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    let Pair { _dir: directory, receiver, provider, master, master_state_root, .. } = pair;
    drop(receiver);
    drop(provider);

    let engine = open_engine(&directory.path().join("receiver")).await;
    let result = std::panic::AssertUnwindSafe(async {
        assert!(engine.db().test_contains_dynamic_state_record(master.id()).unwrap());
        native_gc_fixture::establish_floor(&engine);
        engine.shard_states_keeper().test_retire_history_state(master.id());
        tokio::time::timeout(Duration::from_secs(20), async {
            while engine.db().test_contains_dynamic_state_record(master.id()).unwrap() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("actual GC worker must physically remove the state record");
        assert!(
            engine.load_state(master.id()).await.is_err(),
            "ordinary GC-eligible state load unexpectedly succeeded"
        );
        let state =
            crate::retired_history::authenticate_state(engine.as_ref(), master.id()).await.unwrap();
        assert_eq!(state.state().root_cell().repr_hash(), &master_state_root);
    })
    .catch_unwind()
    .await;
    engine.clone().wait_stop().await.unwrap();
    drop(engine);
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));

    let engine = open_engine(&directory.path().join("receiver")).await;
    let result = std::panic::AssertUnwindSafe(async {
        assert!(!engine.db().test_contains_dynamic_state_record(master.id()).unwrap());
        assert_eq!(
            crate::retired_history::authenticate_state(engine.as_ref(), master.id())
                .await
                .unwrap()
                .state()
                .root_cell()
                .repr_hash(),
            &master_state_root
        );
        // Preserve a valid BOC/header and recompute its storage checksum. The
        // unchanged authentic block proof must still reject the altered root.
        let verified =
            crate::retired_history::authenticate_state(engine.as_ref(), master.id()).await.unwrap();
        let mut altered = verified.state().state().unwrap().clone();
        altered.set_gen_time(altered.gen_time() + 1);
        let bytes = rtos_block::write_boc(&altered.serialize().unwrap()).unwrap();
        let hash = UInt256::calc_file_hash(&bytes).to_hex_string();
        let root =
            std::path::PathBuf::from(engine.db_root_dir().unwrap()).join("retired-history-v1");
        std::fs::write(root.join(format!("{hash}.blob")), bytes).unwrap();
        let mut changed = false;
        for entry in std::fs::read_dir(&root).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|e| e == "json") {
                let mut record: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                if record["id"] == master.id().to_string() {
                    record["state"] = hash.clone().into();
                    std::fs::write(path, serde_json::to_vec(&record).unwrap()).unwrap();
                    changed = true;
                }
            }
        }
        assert!(changed);
        assert!(crate::retired_history::authenticate_state(engine.as_ref(), master.id())
            .await
            .is_err());
    })
    .catch_unwind()
    .await;
    engine.clone().wait_stop().await.unwrap();
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}
