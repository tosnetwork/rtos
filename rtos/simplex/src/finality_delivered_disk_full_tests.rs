// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! The source Delivered marker under a full disk (P5-07.12 phase 1, S4).
//! Run only inside the disk-full harness (`RTOS_ENOSPC_ROOT` on a tmpfs).
use super::*;

fn fill(dir: &Path) -> PathBuf {
    use std::io::Write;
    let path = dir.join("enospc-filler");
    let mut file = File::create(&path).unwrap();
    for chunk in [1 << 16, 1 << 12, 1 << 9, 1] {
        let bytes = vec![0u8; chunk];
        while file.write_all(&bytes).is_ok() {}
    }
    path
}

#[test]
#[ignore = "disk-full harness only"]
fn disk_full_source_delivered_marker() {
    let root = PathBuf::from(
        std::env::var_os("RTOS_ENOSPC_ROOT").expect("run inside the disk-full harness"),
    )
    .join("delivered");
    std::fs::create_dir_all(&root).unwrap();
    let (runtime, draft) = super::super::tests::fixture();
    let namespace = PathBuf::from(runtime.runtime_directory(root.to_str().unwrap()).unwrap());
    let open = || {
        let store = PendingFinalityStore::open(&namespace).unwrap();
        *store.runtime_binding.lock().unwrap() =
            runtime.recovery_binding().map(DiskRecoveryBinding::from_binding);
        store
    };
    let store = open();
    let record = PendingFinalityRecord::from_draft(&runtime, &draft).unwrap();
    store.retain(&record).unwrap();
    let receipt = UInt256::from([0x44; 32]);
    let id = record.id().unwrap();
    store.acknowledge(&id, receipt.clone()).unwrap();
    let mut request = record.close_request(receipt).unwrap();
    request.domain = FinalityCloseDomain::from_runtime(&runtime);
    let offer = CloseOffer { request, generation: 1 };
    let reference = store.close_locator(&id).unwrap().unwrap().reference;
    let delivered = store.delivered_path(&id);
    if std::env::var("RTOS_ENOSPC_CONTROL").as_deref() == Ok("1") {
        drop(store.commit_delivered(&runtime, &reference, &offer).unwrap());
        assert_eq!(DeliveredDisk::read(&delivered).unwrap().offer().unwrap(), offer);
        eprintln!("ENOSPC-CASE delivered control ok");
        return;
    }
    let filler = fill(&root);
    let error = store.commit_delivered(&runtime, &reference, &offer).err().expect("full disk");
    assert!(format!("{error:#}").contains("No space left on device"), "{error:#}");
    // No partial marker is authoritative: absent, or complete and exact.
    if delivered.exists() {
        assert_eq!(DeliveredDisk::read(&delivered).unwrap().offer().unwrap(), offer);
    }
    std::fs::remove_file(filler).unwrap();
    // In process the store latches "reopen required": it fails closed.
    let in_process = store.commit_delivered(&runtime, &reference, &offer).map(drop);
    let message = format!("{:#}", in_process.expect_err("the store latches after a failed write"));
    assert!(message.contains("reopen required"), "{message}");
    drop(store);
    // Cold reopen before any further retry: no partial marker is final.
    if delivered.exists() {
        assert_eq!(DeliveredDisk::read(&delivered).unwrap().offer().unwrap(), offer);
    }
    let reopened_store = open();
    if !delivered.exists() {
        drop(reopened_store.commit_delivered(&runtime, &reference, &offer).unwrap());
    }
    drop(reopened_store);
    let store = open();
    assert_eq!(DeliveredDisk::read(&store.delivered_path(&id)).unwrap().offer().unwrap(), offer);
    eprintln!("ENOSPC-CASE delivered latched, recovered after reopen");
}
