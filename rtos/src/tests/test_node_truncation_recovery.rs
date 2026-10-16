// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Actual node recovery must not publish rollback progress after truncation fails.
use super::*;
use crate::{
    history_read_budget::HistoryReadBudget,
    publication_dependency_leases::{dependency_digest, sst_fixture_for_test, LeaseRelease},
    repair_lease_binding::RepairLeaseBinding,
    repair_provenance::Dependency,
};
use rtos_block::UInt256;

pub(super) struct Lease {
    binding: RepairLeaseBinding,
    generation: u64,
    digest: UInt256,
    retained: u32,
}
pub(super) async fn prepare(db: &InternalDb, fixture: &Fixture, retained: u32) -> Result<Lease> {
    let (mut binding, _, _) = sst_fixture_for_test();
    binding.domain.zerostate = fixture.id(0, false);
    binding.domain.history_init = fixture.id(0, false);
    binding.domain.source_recovery_anchor = fixture.id(0, false);
    binding.canonical.block_id = fixture.id(4, false);
    let handle = db.load_block_handle(&fixture.id(4, false))?.unwrap();
    let block = db.load_block_data(&handle).await?;
    let dependencies = vec![Dependency {
        kind: "block".into(),
        id: fixture.id(4, false).to_string(),
        digest: format!("{:x}", UInt256::calc_file_hash(block.data())),
        bytes: block.data().len() as u64,
        root: None,
    }];
    let digest = dependency_digest(&dependencies)?;
    let generation = db.repair_leases().begin(
        &binding,
        dependencies,
        &HistoryReadBudget::new(Default::default()),
    )?;
    db.save_full_node_state(SHARD_CLIENT_MC_BLOCK, &fixture.id(retained, false))?;
    let (physical, catchain) = db.sst_databases_for_test();
    drop(catchain);
    physical.sync_wal()?;
    Ok(Lease { binding, generation, digest, retained })
}
fn spawn(binary: &Path, root: &Path, zero: &Path, path: &Path) -> Result<Process> {
    let log = fs::File::create(path)?;
    Ok(Process(
        Command::new(binary)
            .env("TOKIO_WORKER_THREADS", "2")
            .arg("--configs")
            .arg(root)
            .arg("--zerostate")
            .arg(zero)
            .arg("--initial-sync-disabled")
            .current_dir(root)
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()?,
    ))
}
pub(super) async fn run(
    binary: &Path,
    root: &Path,
    zero: &Path,
    fixture: &Fixture,
    before: BTreeMap<PathBuf, [u8; 32]>,
    lease: Lease,
    interrupt: Option<&str>,
) -> Result<()> {
    let retained = lease.retained;
    let path = root.join("truncation-refused.log");
    let mut node = spawn(binary, root, zero, &path)?;
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let output = fs::read_to_string(&path)?;
        if output.contains("Node services started.") {
            keep_evidence(root, &path)?;
            rtos_block::fail!("Actual node started despite failed archive truncation: {output}");
        }
        if let Some(status) = node.0.try_wait()? {
            assert!(!status.success(), "{output}");
            break;
        }
        if Instant::now() >= deadline {
            keep_evidence(root, &path)?;
            rtos_block::fail!("Truncation refusal timeout: {output}");
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    keep_evidence(root, &path)?;
    let output = fs::read_to_string(path)?;
    assert!(output.contains("Archive truncation conflicts with repair custody"), "{output}");
    assert!(root.join("node_db/ton_node.restoring").is_file(), "failed restore cleared its beacon");
    assert_eq!(package_inventory(root)?, before, "failed truncation changed archives");
    let db = open_db(root).await?;
    for key in [LAST_APPLIED_MC_BLOCK, PSS_KEEPER_MC_BLOCK, ARCHIVES_GC_BLOCK] {
        assert_eq!(
            db.load_full_node_state(key)?.as_deref(),
            Some(&fixture.id(4, false)),
            "failed restore rewrote {key}"
        );
    }
    assert_eq!(
        db.load_full_node_state(SHARD_CLIENT_MC_BLOCK)?.as_deref(),
        Some(&fixture.id(retained, false))
    );
    fixture.assert_history(&db, 4).await?;
    assert!(db.repair_leases().protection().artifact(&fixture.id(4, false)));
    assert_eq!(
        db.repair_leases().release(lease.generation, &lease.binding, &lease.digest)?,
        LeaseRelease::Released
    );
    let (physical, catchain) = db.sst_databases_for_test();
    drop(catchain);
    db.stop_states_db().await?;
    drop(db);
    tokio::time::timeout(Duration::from_secs(30), wait_for_db_release(physical)).await?;
    eprintln!("Failed actual truncation preserved four cursors, full history and restoring beacon; exact synthetic lease released");
    if let Some(cut) = interrupt {
        let statement = match cut {
            "truncation-before-progress" => {
                "db.save_full_node_state(SHARD_CLIENT_MC_BLOCK, last_mc_block.id())?;"
            }
            "repack-before-rename" => {
                "tokio::fs::rename(new_package.get_path(), old_package.get_path()).await?;"
            }
            _ => rtos_block::fail!("Unknown truncation cut {cut}"),
        };
        interrupt_actual_recovery(binary, root, zero, cut, statement).await?;
        assert!(root.join("node_db/ton_node.restoring").is_file());
        if cut == "truncation-before-progress" {
            assert_ne!(package_inventory(root)?, before, "cut preceded actual archive mutation");
            let output = fs::read_to_string(root.join(format!("cut-{cut}.log")))?;
            assert!(
                output.contains(&format!(
                    "Database was truncated at {}",
                    fixture.id(retained + 1, false)
                )),
                "{output}"
            );
        }
    }
    for attempt in 0..2 {
        let path = root.join(format!("truncation-retry-{attempt}.log"));
        let mut node = spawn(binary, root, zero, &path)?;
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let output = fs::read_to_string(&path)?;
            if let Some(status) = node.0.try_wait()? {
                keep_evidence(root, &path)?;
                rtos_block::fail!("Truncation retry {status}: {output}");
            }
            if output.contains("Node services started.") {
                if attempt == 0 && interrupt != Some("truncation-before-progress") {
                    assert!(
                        output.contains(&format!(
                            "Database was truncated at {}",
                            fixture.id(retained + 1, false)
                        )),
                        "retry did not execute real truncation: {output}"
                    );
                }
                break;
            }
            if Instant::now() >= deadline {
                keep_evidence(root, &path)?;
                rtos_block::fail!("Truncation retry timeout: {output}");
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        node.0.kill()?;
        assert!(!node.0.wait()?.success());
        keep_evidence(root, &path)?;
    }
    assert!(!root.join("node_db/ton_node.restoring").exists());
    assert_ne!(
        package_inventory(root)?,
        before,
        "successful retry did not change canonical packages"
    );
    let db = open_db(root).await?;
    fixture.assert_imported(&db, retained).await?;
    for seq in 1..=retained {
        for wc in [false, true] {
            let id = fixture.id(seq, wc);
            let prefix = if wc {
                rtos_block::AccountIdPrefixFull::workchain(0, rtos_block::SHARD_FULL)
            } else {
                rtos_block::AccountIdPrefixFull::any_masterchain()
            };
            let handle = db.load_block_handle(&id)?.unwrap();
            let block = db.load_block_data(&handle).await?;
            let (indexed_id, bytes) = db
                .lookup_block_by_lt(&prefix, handle.end_lt().saturating_sub(1))
                .await?
                .unwrap_or_else(|| panic!("missing retained LT index for {id}"));
            assert_eq!(indexed_id, id);
            assert_eq!(bytes, block.data());
            let mut timed = Vec::new();
            db.lookup_blocks_by_utime(
                &prefix,
                handle.gen_utime(),
                Box::new(|found, bytes| {
                    if found == id {
                        assert_eq!(bytes, block.data());
                    }
                    timed.push(found);
                    Ok(true)
                }),
            )
            .await?;
            assert!(timed.contains(&id), "missing retained time index for {id}");
            assert!(timed.iter().all(|id| id.seq_no() <= retained));
        }
    }
    for seq in retained + 1..=4 {
        for wc in [false, true] {
            let prefix = if wc {
                rtos_block::AccountIdPrefixFull::workchain(0, rtos_block::SHARD_FULL)
            } else {
                rtos_block::AccountIdPrefixFull::any_masterchain()
            };
            assert!(
                db.lookup_block_by_seqno(&prefix, seq).await?.is_none(),
                "truncated block still indexed"
            );
        }
    }
    db.stop_states_db().await?;
    eprintln!("Actual node retried real truncation to height {retained}, restarted twice, retained MC/WC data consistent and tail indexes removed");
    Ok(())
}
