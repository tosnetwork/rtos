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

#[path = "test_node_io_failure.rs"]
mod io_failure;

pub(super) struct Lease {
    binding: RepairLeaseBinding,
    generation: u64,
    digest: UInt256,
    retained: u32,
    dependencies: Vec<Dependency>,
}
pub(super) async fn prepare(db: &InternalDb, fixture: &Fixture, retained: u32, defer_begin: bool) -> Result<Lease> {
    let root = Path::new(db.db_root_dir()?).parent().unwrap();
    let marker = root.join("forced-truncation-fixture");
    fs::write(&marker, b"Explicit forced-recovery fixture; not read by production node")?;
    fs::File::open(&marker)?.sync_all()?;
    fs::File::open(root)?.sync_all()?;
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
    let generation = if defer_begin { 0 } else {
        db.repair_leases().begin(&binding, dependencies.clone(), &HistoryReadBudget::new(Default::default()))?
    };
    db.save_full_node_state(SHARD_CLIENT_MC_BLOCK, &fixture.id(retained, false))?;
    let (physical, catchain) = db.sst_databases_for_test();
    drop(catchain);
    physical.sync_wal()?;
    Ok(Lease { binding, generation, digest, retained, dependencies })
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
            .arg("--initial-sync-disabled").args(forced_cursor_fixture_args(root))
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
    mut lease: Lease,
    interrupt: Option<&str>,
) -> Result<()> {
    let retained = lease.retained;
    let unconfirmed = matches!(interrupt, Some("state-auto-state-sync-eio" | "state-auto-rebuild-startup-sync-eio"));
    let startup_sync_fault = matches!(interrupt, Some("state-auto-startup-sync-eio" | "state-auto-rebuild-startup-sync-eio"));
    let automatic = interrupt.is_some_and(|cut| cut.starts_with("state-auto-"));
    let automatic_fault = interrupt.and_then(|cut| cut.strip_prefix("state-auto-"))
        .filter(|mode| *mode != "cache-loss" && *mode != "state-sync-eio" && *mode != "startup-sync-eio" && *mode != "rebuild-startup-sync-eio");
    let state_cut = automatic || interrupt == Some("state-cache-loss");
    if state_cut {
        if unconfirmed { state_cache_loss::refuse_and_interrupt(root).await?; }
        else { state_cache_loss::write_and_interrupt(root).await?; }
        assert_eq!(package_inventory(root)?, before, "state restoration changed canonical packages");
    }
    let acquire_cut = interrupt == Some("lease-acquire-cache-loss");
    if acquire_cut {
        lease_cache_loss::acquire_and_interrupt(root, &mut lease).await?;
        assert_eq!(package_inventory(root)?, before, "lease acquisition changed canonical packages");
    }
    let custody_cut = interrupt == Some("lease-custody-cache-loss");
    let expected_custody = if custody_cut {
        let record = lease_cache_loss::durable_and_interrupt(root, &lease).await?;
        assert_eq!(package_inventory(root)?, before, "custody transition changed canonical packages");
        Some(record)
    } else { None };
    let outbox_cut = interrupt == Some("validator-outbox-cache-loss");
    if outbox_cut {
        outbox_cache_loss::write_and_interrupt(root).await?;
        assert_eq!(package_inventory(root)?, before, "outbox update changed canonical packages");
    }
    let persistent_failure_mode = interrupt.and_then(|v| v.strip_prefix("persistent-")?.strip_suffix("-eio")?.rsplit_once('-'));
    if let Some((mode, phase)) = persistent_failure_mode {
        persistent_failure::write_and_interrupt(root, mode, phase).await?;
        assert_eq!(package_inventory(root)?, before, "failed persistent write changed canonical packages");
    }
    let persistent_mode = match interrupt {
        Some("persistent-fast-cache-loss") => Some("fast"), Some("persistent-head-cache-loss") => Some("head"),
        Some("persistent-whole-cache-loss") => Some("whole"), Some("persistent-raw-cache-loss") => Some("raw"),
        _ => None,
    };
    if let Some(mode) = persistent_mode {
        persistent_cache_loss::write_and_interrupt(root, mode).await?;
        assert_eq!(package_inventory(root)?, before, "persistent write changed canonical packages");
    }
    let floor_cut = interrupt == Some("validator-floor-cache-loss");
    if floor_cut {
        validator_cache_loss::write_and_interrupt(root, &fixture.id(retained, false)).await?;
        assert_eq!(package_inventory(root)?, before, "validator floor write changed canonical packages");
    }
    let validator_batch = match interrupt {
        Some("validator-prune-cache-loss") => Some(validator_retirement_loss::BatchKind::Prune),
        Some("validator-prune-empty-cache-loss") => Some(validator_retirement_loss::BatchKind::PruneEmpty),
        Some("validator-retirement-cache-loss") => Some(validator_retirement_loss::BatchKind::Retirement),
        Some("validator-claim-cache-loss") => Some(validator_retirement_loss::BatchKind::Claim),
        Some("validator-journal-cache-loss") => Some(validator_retirement_loss::BatchKind::Journal),
        Some("validator-incarnation-cache-loss") => Some(validator_retirement_loss::BatchKind::Incarnation),
        _ => None,
    };
    if let Some(kind) = validator_batch {
        validator_retirement_loss::write_and_interrupt(root, &fixture.id(retained, false), kind).await?;
        assert_eq!(package_inventory(root)?, before, "retirement batch changed canonical packages");
    }
    let lease_cut = interrupt == Some("lease-release-cache-loss");
    if automatic {
        assert_eq!(lease.generation, 0, "automatic recovery must not acquire a fixture lease");
        // Preserve the first loss report; the second cut will record recovery WALs.
        let first = root.join("cache-loss.json");
        if first.try_exists()? {
            let saved = root.join("state-publication-cache-loss.json");
            fs::copy(first, &saved)?;
            keep_evidence(root, &saved)?;
        }
        eprintln!("Automatic dynamic recovery begins with no fixture lease or manual repair");
    } else {
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
        if let Some(expected) = expected_custody {
            eprintln!("Actual node lease protection preserved full history and progress after custody cut");
            let cold = serde_json::to_value(db.repair_leases().lookup(lease.generation,
                &HistoryReadBudget::new(Default::default()))?)?;
            let report = root.join("lease-custody-cold.json");
            fs::write(&report, serde_json::to_vec(&cold)?)?;
            keep_evidence(root, &report)?;
            assert_eq!(cold, expected, "Acknowledged custody record lost after actual node restart");
            eprintln!("Acknowledged DurableCustody record survived actual node restart byte-for-byte in canonical JSON");
        }
        if state_cut { state_cache_loss::verify(root, &db, "guarded-startup")?; }
        if floor_cut {
            eprintln!("Actual node preserved protected history and progress after validator floor cut");
            validator_cache_loss::verify(root, &db, &fixture.id(retained, false), "guarded-startup")?;
        }
        if let Some((mode, phase)) = persistent_failure_mode {
            persistent_failure::verify_and_retry(root, &db, mode, phase).await?;
        }
        if let Some(mode) = persistent_mode {
            eprintln!("Actual node preserved protected history and progress after persistent cut");
            persistent_cache_loss::verify(root, &db, mode, "guarded-startup").await?;
        }
        if outbox_cut {
            eprintln!("Actual node preserved protected history and progress after outbox cut");
            outbox_cache_loss::verify(root, &db, "guarded-startup")?;
        }
        if let Some(kind) = validator_batch {
            eprintln!("Actual node preserved protected history and progress after {} cut", kind.name());
            validator_retirement_loss::verify(root, &db, &fixture.id(retained, false), "guarded-startup", kind)?;
        }
        if !lease_cut {
            assert_eq!(db.repair_leases().release(lease.generation, &lease.binding, &lease.digest)?,
                LeaseRelease::Released);
        }
        let (physical, catchain) = db.sst_databases_for_test();
        drop(catchain);
        db.stop_states_db().await?;
        drop(db);
        tokio::time::timeout(Duration::from_secs(30), wait_for_db_release(physical)).await?;
        if lease_cut {
            lease_cache_loss::release_and_interrupt(root, &lease).await?;
            assert_eq!(package_inventory(root)?, before, "lease release cache loss changed canonical packages");
        }
        eprintln!("Failed actual truncation preserved four cursors, full history and restoring beacon; exact synthetic lease release acknowledged");
    }
    if startup_sync_fault {
        startup_sync::refuse(binary, root, zero, unconfirmed).await?;
        let config = state_cache_loss::generated_config(root)?;
        match std::env::var("RTOS_TEST_CACHE_LOSS_ENABLED")?.as_str() {
            "1" => cache_loss::clear(root).await?,
            "0" => (),
            _ => rtos_block::fail!("Invalid startup sync cache-loss mode"),
        }
        state_cache_loss::verify_generated_config(root, &config)?;
        if unconfirmed && root.join("cache-loss.json").try_exists()? {
            let saved = root.join("startup-failure-cache-loss.json");
            fs::copy(root.join("cache-loss.json"), &saved)?;
            keep_evidence(root, &saved)?;
        }
    }
    let interrupt = if unconfirmed || startup_sync_fault { None } else if let Some(mode) = automatic_fault {
        Some(mode)
    } else if automatic {
        Some(match std::env::var("RTOS_TEST_CACHE_LOSS_ENABLED")?.as_str() {
            "1" => "forward-after-row-sync-cache-loss",
            "0" => "forward-after-row-sync",
            _ => rtos_block::fail!("Invalid automatic recovery cache-loss mode"),
        })
    } else if state_cut || lease_cut || acquire_cut || custody_cut || floor_cut || outbox_cut || persistent_mode.is_some() || persistent_failure_mode.is_some() || validator_batch.is_some() { None } else { interrupt };
    if let Some(mode @ ("selection-enospc" | "selection-sync-eio" | "ready-enospc" | "ready-sync-eio" | "operation-sync-eio" | "publish-rename-eio" | "publish-sync-eio" | "wal-ready-sync-eio" | "wal-publish-sync-eio" | "wal-epoch-enrollment-eio" | "publish-directory-sync-eio" | "stage-enospc" | "stage-sync-eio")) = interrupt {
        io_failure::recovery_fault(binary, root, zero, mode).await?;
        if matches!(mode, "publish-sync-eio" | "wal-publish-sync-eio" | "publish-directory-sync-eio") {
            assert_ne!(package_inventory(root)?, before, "sync fault must follow actual canonical replacement");
        } else {
            assert_eq!(package_inventory(root)?, before, "failed recovery IO changed canonical packages");
        }
        assert!(root.join("node_db/ton_node.restoring").is_file());
        if automatic {
            let config = state_cache_loss::generated_config(root)?;
            match std::env::var("RTOS_TEST_CACHE_LOSS_ENABLED")?.as_str() {
                "1" => cache_loss::clear(root).await?,
                "0" => (),
                _ => rtos_block::fail!("Invalid automatic recovery cache-loss mode"),
            }
            state_cache_loss::verify_generated_config(root, &config)?;
        }
    } else if let Some(cut) = interrupt {
        if cut.ends_with("-cache-loss") { cache_loss::sync_fixture(root)?; }
        let statement = match cut {
            "truncation-before-progress" => {
                "db.save_full_node_state(SHARD_CLIENT_MC_BLOCK, shard_client_progress)?;"
            }
            "repack-before-rename" => {
                "sync_child(source.last().unwrap(), &old)?;"
            }
            "repack-after-rename" => {
                "sync_child(destination.last().unwrap(), &new)"
            }
            "root-last-cache-loss" => "custody.complete();",
            "forward-cleaned-cache-loss" => "Ok(cleaned)",
            "forward-before-prepare-cache-loss" => "let expected = prepare(providers, root)?;",
            "forward-before-cleanup" | "forward-committed-cache-loss" => "scan(providers, &committed, Pass::Cleanup)?;",
            "forward-after-row-sync" | "forward-after-row-sync-cache-loss" => "let applied = scan(providers, root, Pass::Committed)?;",
            "producer-selection-before-finish" | "producer-selection-cache-loss" => "let (file, selection) = writer.finish()?;",
            "producer-ready-before-finish" | "producer-ready-cache-loss" => "let (file, ready) = writer.finish()?;",
            _ => rtos_block::fail!("Unknown truncation cut {cut}"),
        };
        interrupt_actual_recovery(binary, root, zero, cut, statement).await?;
        let generated_config = if automatic {
            Some(state_cache_loss::generated_config(root)?)
        } else { None };
        if cut == "producer-selection-cache-loss" {
            assert_eq!(package_inventory(root)?, before, "Selection production changed canonical packages");
            let selection = cache_loss::unfinished_selection(root).await?;
            assert_eq!(package_inventory(root)?, before, "Selection cache loss changed canonical packages");
            interrupt_actual_recovery(binary, root, zero, "building-before-cleaned",
                "main.database.db().put(ROOT_KEY, cleaned.encode()?)?;").await?;
            assert!(!selection.exists(), "Preparing abort did not remove Selection");
            assert_eq!(package_inventory(root)?, before, "Preparing abort changed canonical packages");
            eprintln!("Preparing abort removed Selection before Cleaned publication; second actual interruption preserved canonical packages");
        } else if cut == "producer-ready-cache-loss" {
            assert_eq!(package_inventory(root)?, before, "producer cut changed canonical packages");
            cache_loss::unfinished_ready(root).await?;
            assert_eq!(package_inventory(root)?, before, "cache loss changed canonical packages");
        } else if cut == "forward-before-prepare-cache-loss" {
            assert_eq!(package_inventory(root)?, before, "preflight cut changed canonical packages");
            cache_loss::staged_packages(root).await?;
            assert_eq!(package_inventory(root)?, before, "staging cache loss changed canonical packages");
            if std::env::var("RTOS_TEST_OMIT_MANIFEST_SYNC_FILE").as_deref() == Ok("ready-wal")
                && std::env::var("RTOS_TEST_CACHE_LOSS_ENABLED").as_deref() == Ok("1") {
                interrupt_actual_recovery(binary, root, zero, "building-before-cleaned",
                    "main.database.db().put(ROOT_KEY, cleaned.encode()?)?;").await?;
                let mut ready = Vec::new();
                let mut stages = 0;
                find_ready_staging(root, &mut ready, &mut stages)?;
                assert!(ready.is_empty(), "Building abort left Ready intent");
                assert_eq!(stages, 0, "Building abort left replacement stages");
                assert_eq!(package_inventory(root)?, before, "Building abort changed canonical packages");
                eprintln!("Lost Ready WAL publication recovered through Building abort; second actual interruption preserved canonical packages");
            }
        } else if cut == "forward-committed-cache-loss" {
            let published = package_inventory(root)?;
            assert_ne!(published, before, "Committed cut preceded package publication");
            let loss = match std::env::var("RTOS_TEST_CACHE_LOSS_ENABLED")?.as_str() {
                "1" => true, "0" => false,
                _ => rtos_block::fail!("Invalid cache-loss mode"),
            };
            if loss { cache_loss::clear(root).await?; }
            assert_eq!(package_inventory(root)?, published, "cache loss changed published packages");
            eprintln!("Committed cut cache-loss={loss}: published canonical packages preserved");
            if loss && std::env::var("RTOS_TEST_OMIT_MANIFEST_SYNC_FILE").as_deref() == Ok("committed-wal") {
                // Reaching this branch requires replay of Ready, not Committed.
                interrupt_actual_recovery(binary, root, zero, "forward-after-row-sync",
                    "let applied = scan(providers, root, Pass::Committed)?;").await?;
                assert_eq!(package_inventory(root)?, published, "Ready replay changed final packages");
                eprintln!("Lost Committed WAL publication replayed Ready; second actual interruption preserved final packages");
            }
        } else if cut == "forward-cleaned-cache-loss" {
            let published = package_inventory(root)?;
            assert_ne!(published, before, "Cleaned cut preceded package publication");
            let mut ready = Vec::new();
            let mut stages = 0;
            find_ready_staging(root, &mut ready, &mut stages)?;
            assert_eq!(ready.len(), 1, "Cleaned publication must precede control cleanup");
            assert_eq!(stages, 0, "Cleaned publication preceded stage cleanup");
            let loss = match std::env::var("RTOS_TEST_CACHE_LOSS_ENABLED")?.as_str() {
                "1" => true, "0" => false,
                _ => rtos_block::fail!("Invalid cache-loss mode"),
            };
            if loss { cache_loss::clear(root).await?; }
            assert_eq!(package_inventory(root)?, published, "cache loss changed cleaned packages");
            eprintln!("Cleaned cut cache-loss={loss}: final packages preserved and no stages remain");
            if loss && std::env::var("RTOS_TEST_OMIT_MANIFEST_SYNC_FILE").as_deref() == Ok("cleaned-wal") {
                interrupt_actual_recovery(binary, root, zero, "forward-verify-committed",
                    "let expected = prepare(providers, root)?;").await?;
                assert_eq!(package_inventory(root)?, published, "Committed reopen changed final packages");
                eprintln!("Lost Cleaned WAL publication reopened Committed; second actual interruption preserved final packages");
            }
        } else if cut == "root-last-cache-loss" {
            let published = package_inventory(root)?;
            assert_ne!(published, before, "root deletion preceded package publication");
            let mut ready = Vec::new();
            let mut stages = 0;
            find_ready_staging(root, &mut ready, &mut stages)?;
            assert!(ready.is_empty(), "root deletion preceded Ready cleanup");
            assert_eq!(stages, 0, "root deletion preceded stage cleanup");
            let loss = match std::env::var("RTOS_TEST_CACHE_LOSS_ENABLED")?.as_str() {
                "1" => true, "0" => false,
                _ => rtos_block::fail!("Invalid cache-loss mode"),
            };
            if loss { cache_loss::clear(root).await?; }
            assert_eq!(package_inventory(root)?, published, "cache loss changed final packages");
            eprintln!("Root-last cut cache-loss={loss}: final packages preserved and controls removed");
            if loss && std::env::var("RTOS_TEST_OMIT_MANIFEST_SYNC_FILE").as_deref() == Ok("root-wal") {
                interrupt_actual_recovery(binary, root, zero, "root-verify-cleaned",
                    "let providers = Arc::new(providers);").await?;
                assert_eq!(package_inventory(root)?, published, "Cleaned reopen changed final packages");
                eprintln!("Lost root deletion reopened Cleaned; second actual interruption preserved final packages");
            }
        } else if cut.ends_with("-cache-loss") { cache_loss::clear(root).await?; }
        if let Some(expected) = generated_config {
            state_cache_loss::verify_generated_config(root, &expected)?;
        }
        assert!(root.join("node_db/ton_node.restoring").is_file());
        if cut == "forward-before-cleanup" {
            assert_ne!(package_inventory(root)?, before, "Committed cut preceded canonical replacement");
            let mut ready = Vec::new();
            let mut stages = 0;
            find_ready_staging(root, &mut ready, &mut stages)?;
            assert_eq!(ready.len(), 1, "Committed recovery must retain its Ready manifest");
            let ready_before = fs::read(&ready[0])?;
            keep_evidence(root, &ready[0])?;
            // Restart through the real Committed replay and interrupt after
            // cleanup, before publishing Cleaned. No native test edits intervene.
            interrupt_actual_recovery(binary, root, zero, "forward-before-cleaned",
                "store_successor(providers, &committed, &cleaned)?;").await?;
            let mut remaining = Vec::new();
            let mut remaining_stages = 0;
            find_ready_staging(root, &mut remaining, &mut remaining_stages)?;
            assert_eq!(remaining.len(), 1, "Ready must remain until Cleaned publication");
            assert_eq!(remaining_stages, 0, "owned stages survived Committed cleanup");
            assert_eq!(ready_before, fs::read(&remaining[0])?);
            eprintln!("Actual node interrupted before Committed cleanup and again before Cleaned publication");
        }
        if cut == "producer-selection-before-finish" {
            assert_eq!(package_inventory(root)?, before, "Selection production changed canonical packages");
            let mut ready = Vec::new();
            let mut stages = 0;
            find_ready_staging(root, &mut ready, &mut stages)?;
            assert!(ready.is_empty(), "Ready existed before Selection completed");
            assert_eq!(stages, 0, "package stages existed before Selection completed");
            fn selections(path: &Path, found: &mut Vec<std::path::PathBuf>) -> Result<()> {
                for entry in fs::read_dir(path)? {
                    let entry = entry?;
                    if entry.file_type()?.is_dir() { selections(&entry.path(), found)?; }
                    else if entry.file_name() == "selection.v1" { found.push(entry.path()); }
                }
                Ok(())
            }
            let mut partial = Vec::new();
            selections(&root.join("node_db/archive/recovery"), &mut partial)?;
            assert_eq!(partial.len(), 1);
            let bytes = fs::read(&partial[0])?;
            assert!(bytes.len() > 28 && &bytes[..8] == b"RTOSAMF1");
            let mut position = 28usize;
            let mut records = 0;
            while position < bytes.len() {
                assert_ne!(bytes[position], 0, "Selection already has a completion trailer");
                assert!(bytes.len() - position >= 9);
                let length = u64::from_le_bytes(bytes[position + 1..position + 9].try_into()?);
                position = position.checked_add(9).and_then(|value| value.checked_add(usize::try_from(length).ok()?))
                    .ok_or_else(|| rtos_block::error!("Selection framing overflow"))?;
                assert!(position <= bytes.len());
                records += 1;
            }
            assert!(records > 0);
            keep_evidence(root, &partial[0])?;
            interrupt_actual_recovery(binary, root, zero, "building-before-cleaned",
                "main.database.db().put(ROOT_KEY, cleaned.encode()?)?;").await?;
            assert!(!partial[0].exists(), "partial Selection survived abort cleanup");
            assert_eq!(package_inventory(root)?, before, "Preparing abort changed canonical packages");
        }
        if cut == "producer-ready-before-finish" {
            assert_eq!(package_inventory(root)?, before, "Building changed canonical packages");
            let mut ready = Vec::new();
            let mut stages = 0;
            find_ready_staging(root, &mut ready, &mut stages)?;
            assert_eq!(ready.len(), 1, "expected one production Ready staging file");
            assert!(stages > 0, "producer cut preceded replacement staging");
            let bytes = fs::read(&ready[0])?;
            assert!(bytes.len() > 28 && &bytes[..8] == b"RTOSAMF1");
            // Independent framing check: body records are complete, but the
            // terminating tag/count/checksum trailer has not been written.
            let mut position = 28usize;
            let mut records = 0;
            while position < bytes.len() {
                assert_ne!(bytes[position], 0, "Ready already has a completion trailer");
                assert!(bytes.len() - position >= 9, "short Ready record header");
                let length = u64::from_le_bytes(bytes[position + 1..position + 9].try_into()?);
                position = position.checked_add(9).and_then(|value| value.checked_add(usize::try_from(length).ok()?))
                    .ok_or_else(|| rtos_block::error!("Ready framing overflow"))?;
                assert!(position <= bytes.len(), "short Ready record payload");
                records += 1;
            }
            assert!(records > 0);
            keep_evidence(root, &ready[0])?;
            // Interrupt the real bootstrap abort too, after stage/partial-Ready
            // disposal but before durable Cleaned publication. No test DB open
            // or native-data edits occur between either kill and restart.
            interrupt_actual_recovery(binary, root, zero, "building-before-cleaned",
                "main.database.db().put(ROOT_KEY, cleaned.encode()?)?;").await?;
            assert_eq!(package_inventory(root)?, before, "Building abort changed canonical packages");
            let mut remaining = Vec::new();
            let mut remaining_stages = 0;
            find_ready_staging(root, &mut remaining, &mut remaining_stages)?;
            assert!(remaining.is_empty(), "partial Ready survived abort cleanup");
            assert_eq!(remaining_stages, 0, "owned stages survived abort cleanup");
            eprintln!("Actual producer left a trailer-less Ready; real bootstrap discarded it and stages before a second interruption; canonical packages stayed unchanged");
        }
        if cut == "repack-after-rename" {
            assert_ne!(
                package_inventory(root)?,
                before,
                "after-rename cut did not replace canonical bytes"
            );
            fn no_stage(path: &Path) -> Result<()> {
                for entry in fs::read_dir(path)? {
                    let entry = entry?;
                    if entry.file_type()?.is_dir() {
                        no_stage(&entry.path())?;
                    } else {
                        assert!(
                            !entry.file_name().to_string_lossy().ends_with(".pack.new"),
                            "after-rename cut has an undeclared legacy stage: {}",
                            entry.path().display()
                        );
                    }
                }
                Ok(())
            }
            no_stage(root)?;
        }
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
                if unconfirmed && std::env::var("RTOS_TEST_CACHE_LOSS_ENABLED")?.as_str() == "1" {
                    keep_evidence(root, &path)?;
                    let missing = output.contains(&format!("Can't load state for {} from DB, but handle.has_saved_state() == true", fixture.id(3, false)));
                    if attempt == 0 && !startup_sync_fault {
                        assert!(missing, "Actual node did not encounter the lost unconfirmed state: {output}");
                    } else if attempt != 0 {
                        assert!(!missing, "Recovered state was not durable before services started");
                    }
                }
                if attempt == 0 && !startup_sync_fault && interrupt != Some("truncation-before-progress") {
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
        if unconfirmed && attempt == 0 {
            let config = state_cache_loss::generated_config(root)?;
            if std::env::var("RTOS_TEST_CACHE_LOSS_ENABLED")?.as_str() == "1" { cache_loss::clear(root).await?; }
            state_cache_loss::verify_generated_config(root, &config)?;
        }
    }
    assert!(!root.join("node_db/ton_node.restoring").exists());
    assert_ne!(
        package_inventory(root)?,
        before,
        "successful retry did not change canonical packages"
    );
    let db = open_db(root).await?;
    fixture.assert_imported(&db, retained).await?;
    if unconfirmed { state_cache_loss::verify_reconstructed(root, &db, "two-boots")?; }
    else if state_cut { state_cache_loss::verify(root, &db, "two-boots")?; }
    if let Some((mode, phase)) = persistent_failure_mode {
        persistent_cache_loss::verify(root, &db, mode, "two-boots").await?;
        eprintln!("Persistent {mode}-{phase} failure recovered after two-boots");
    }
    if let Some(mode) = persistent_mode { persistent_cache_loss::verify(root, &db, mode, "two-boots").await?; }
    if outbox_cut { outbox_cache_loss::verify(root, &db, "two-boots")?; }
    if let Some(kind) = validator_batch {
        validator_retirement_loss::verify(root, &db, &fixture.id(retained, false), "two-boots", kind)?;
    }
    if floor_cut {
        validator_cache_loss::verify(root, &db, &fixture.id(retained, false), "two-boots")?;
    }
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
    if automatic {
        assert!(!db.repair_leases().protection().artifact(&fixture.id(4, false)));
        assert!(!db.repair_leases().protection().state(&fixture.id(3, false)));
        let report = root.join("state-automatic-recovery.json");
        fs::write(&report, serde_json::to_vec(&serde_json::json!({
            "fixture_lease_acquired": false, "manual_lease_release": false,
            "native_reopen_between_recovery_kill_and_boot": false,
            "actual_recovery_interrupted": !unconfirmed || startup_sync_fault, "complete_boots": 2,
            "retained_height": retained, "exact_state_graph": true,
        }))?)?;
        keep_evidence(root, &report)?;
        if unconfirmed {
            eprintln!("Actual dynamic node recovered unconfirmed state; no manual lease release or data repair");
        } else {
            eprintln!("Actual dynamic node recovered automatically after recovery interruption; no manual lease release or data repair");
        }
    }
    db.stop_states_db().await?;
    eprintln!("Actual node retried real truncation to height {retained}, restarted twice, retained MC/WC data consistent and tail indexes removed");
    Ok(())
}


pub(super) fn find_ready_staging(path: &Path, ready: &mut Vec<PathBuf>, stages: &mut usize) -> Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            find_ready_staging(&entry.path(), ready, stages)?;
        } else if entry.file_type()?.is_file() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == "ready.v1" { ready.push(entry.path()); }
            if name.starts_with("stage-") && name.ends_with(".pack") { *stages += 1; }
        }
    }
    Ok(())
}

#[path = "test_node_lease_cache_loss.rs"]
mod lease_cache_loss;

#[path = "test_node_validator_cache_loss.rs"]
mod validator_cache_loss;

#[path = "test_node_validator_retirement_loss.rs"]
mod validator_retirement_loss;

#[path = "test_node_outbox_cache_loss.rs"]
mod outbox_cache_loss;

#[path = "test_node_persistent_cache_loss.rs"]
mod persistent_cache_loss;

#[path = "test_node_persistent_failure.rs"]
mod persistent_failure;

#[path = "test_node_state_cache_loss.rs"]
pub(super) mod state_cache_loss;

#[path = "test_node_startup_sync.rs"]
mod startup_sync;
