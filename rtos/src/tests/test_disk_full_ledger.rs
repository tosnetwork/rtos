// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Lease ledger under a full disk (P5-07.12 phase 1, cases L1/L2). These run
//! only inside the disk-full harness: an unprivileged mount namespace whose
//! `RTOS_ENOSPC_ROOT` is a size-limited tmpfs, traced from outside. With
//! `RTOS_ENOSPC_CONTROL=1` each case runs its positive control instead: the
//! same target write with ample space, which must succeed.
use super::*;
use crate::history_read_budget::HistoryReadBudget;

/// Fills the filesystem holding `dir` until a write fails with ENOSPC, so
/// the next allocation of any store on it fails; `free` gives it back.
pub(crate) struct Filler(std::path::PathBuf);

impl Filler {
    pub(crate) fn fill(dir: &std::path::Path) -> Self {
        use std::io::Write;
        let path = dir.join("enospc-filler");
        let mut file = std::fs::File::create(&path).unwrap();
        for chunk in [1 << 16, 1 << 12, 1 << 9, 1] {
            let bytes = vec![0u8; chunk];
            loop {
                match file.write_all(&bytes) {
                    Ok(()) => {}
                    Err(error) if error.raw_os_error() == Some(28) => break,
                    Err(error) => panic!("filler write failed unexpectedly: {error}"),
                }
            }
        }
        Self(path)
    }
    pub(crate) fn free(self) {
        std::fs::remove_file(&self.0).unwrap();
    }
}

pub(crate) fn enospc_root() -> std::path::PathBuf {
    std::path::PathBuf::from(
        std::env::var_os("RTOS_ENOSPC_ROOT").expect("run inside the disk-full harness"),
    )
}

/// The positive-control run of a case: its target write with ample space.
pub(crate) fn control() -> bool {
    std::env::var("RTOS_ENOSPC_CONTROL").as_deref() == Ok("1")
}

fn other_binding(record_id: u64) -> crate::repair_lease_binding::RepairLeaseBinding {
    let mut binding = super::tests::binding_for_disk_full();
    binding.record_id = record_id;
    binding.close_generation = record_id;
    binding
}

/// Flushes the ledger's column family so RocksDB switches to a fresh, empty
/// WAL: the next write must allocate, so a full disk fails it for real.
fn rotate_wal(db: &RocksDb) {
    let raw = db.db();
    let family = raw.cf_handle("repair_dependency_leases_v1").expect("ledger column family");
    raw.flush_cf(&family).expect("flush before filling");
}

/// The lease's state reference count matches the durable ledger after reopen.
fn protection_matches(leases: &DependencyLeases, present: usize) {
    let state = super::tests::dependency_block_for_disk_full();
    assert_eq!(
        leases.protection.references(&state).0,
        present as u32,
        "protection rebuilt exactly"
    );
}

/// Present and complete — binding, dependencies, digest and state exactly
/// as written — or absent.
fn absent_or_complete(
    leases: &DependencyLeases,
    generation: u64,
    expected: &crate::repair_lease_binding::RepairLeaseBinding,
    state: LeaseState,
) -> bool {
    let budget = HistoryReadBudget::new(Default::default());
    let deps = super::tests::dependencies_for_disk_full();
    match leases.lookup(generation, &budget) {
        Ok(record) => {
            assert_eq!(record.generation, generation);
            assert_eq!(&record.binding().unwrap(), expected, "complete binding");
            assert_eq!(record.dependencies, deps, "complete dependencies");
            assert_eq!(
                record.dependency_digest,
                format!("{:x}", dependency_digest(&deps).unwrap()),
                "complete digest"
            );
            assert_eq!(record.state, state, "complete state");
            true
        }
        Err(_) => false,
    }
}

#[tokio::test]
#[ignore = "disk-full harness only"]
async fn disk_full_ledger_begin_poisons_and_cold_reopen_is_previous_or_complete() -> Result<()> {
    let root = enospc_root().join("ledger-begin");
    std::fs::create_dir_all(&root)?;
    let budget = HistoryReadBudget::new(Default::default());
    let deps = super::tests::dependencies_for_disk_full();
    let (db, leases) = super::tests::open_for_disk_full(&root)?;
    let first = leases.begin(&other_binding(1), deps.clone(), &budget)?;
    rotate_wal(&db);
    if control() {
        let second = leases.begin(&other_binding(2), deps, &budget)?;
        assert!(absent_or_complete(&leases, second, &other_binding(2), LeaseState::Protecting));
        eprintln!("ENOSPC-CASE L1 control ok");
        return Ok(());
    }
    let filler = Filler::fill(&root);
    let error = leases.begin(&other_binding(2), deps.clone(), &budget).unwrap_err();
    assert!(format!("{error:#}").contains("No space left on device"), "{error:#}");
    // The failed commit poisons the ledger: nothing further is acknowledged,
    // even once space is back.
    filler.free();
    assert!(leases.begin(&other_binding(3), deps.clone(), &budget).is_err());
    drop(leases);
    drop(db);
    let (_db, reopened) = super::tests::open_for_disk_full(&root)?;
    assert!(
        absent_or_complete(&reopened, first, &other_binding(1), LeaseState::Protecting),
        "acknowledged lease survives"
    );
    let second =
        absent_or_complete(&reopened, first + 1, &other_binding(2), LeaseState::Protecting);
    protection_matches(&reopened, 1 + usize::from(second));
    // Recovery: a new lease is acknowledged after the reopen.
    reopened.begin(&other_binding(4), deps, &budget)?;
    eprintln!("ENOSPC-CASE L1 second_present={second}");
    Ok(())
}

#[tokio::test]
#[ignore = "disk-full harness only"]
async fn disk_full_ledger_release_poisons_and_keeps_protection() -> Result<()> {
    let root = enospc_root().join("ledger-release");
    std::fs::create_dir_all(&root)?;
    let budget = HistoryReadBudget::new(Default::default());
    let deps = super::tests::dependencies_for_disk_full();
    let digest = dependency_digest(&deps)?;
    let binding = other_binding(1);
    let binding_digest = UInt256::calc_file_hash(&binding.encode()?);
    let (db, leases) = super::tests::open_for_disk_full(&root)?;
    let generation = leases.begin(&binding, deps.clone(), &budget)?;
    leases.durable(generation, &budget)?;
    rotate_wal(&db);
    if control() {
        let released = leases.release_checked(generation, &binding_digest, &digest, |_| None)?;
        assert_eq!(released, LeaseRelease::Released);
        protection_matches(&leases, 0);
        eprintln!("ENOSPC-CASE L2 control ok");
        return Ok(());
    }
    let filler = Filler::fill(&root);
    let error = leases.release_checked(generation, &binding_digest, &digest, |_| None);
    assert!(!matches!(error, Ok(LeaseRelease::Released)), "never acknowledged: {error:?}");
    assert!(format!("{:#}", error.unwrap_err()).contains("No space left on device"));
    // Protection is never dropped by an unacknowledged release.
    assert!(leases.protection.state(&super::tests::dependency_block_for_disk_full()));
    filler.free();
    assert!(leases.release_checked(generation, &binding_digest, &digest, |_| None).is_err());
    drop(leases);
    drop(db);
    let (_db, reopened) = super::tests::open_for_disk_full(&root)?;
    let present = absent_or_complete(&reopened, generation, &binding, LeaseState::DurableCustody);
    protection_matches(&reopened, usize::from(present));
    // Recovery: the release is retried and acknowledged, or found done.
    let retried = reopened.release_checked(generation, &binding_digest, &digest, |_| None)?;
    assert!(matches!(retried, LeaseRelease::Released | LeaseRelease::AbsentAlreadyReleased));
    protection_matches(&reopened, 0);
    eprintln!("ENOSPC-CASE L2 present_after_reopen={present}");
    Ok(())
}
