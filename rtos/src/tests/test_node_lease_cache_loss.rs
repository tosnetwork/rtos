// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Abrupt native lease writer death followed by actual executable recovery.
use super::*;

#[tokio::test]
#[ignore = "internal child; requires owned lease fixture"]
async fn mutation_child() -> Result<()> {
    let root = PathBuf::from(std::env::var("RTOS_TEST_LEASE_CHILD_ROOT")?);
    let request: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("lease-mutation-input.json"))?)?;
    let binding = RepairLeaseBinding::decode(&serde_json::from_value::<Vec<u8>>(
        request["binding"].clone(),
    )?)?;
    let digest: UInt256 = request["digest"].as_str().unwrap().parse()?;
    let db = open_db(&root).await?;
    if let Ok(arm) = std::env::var("RTOS_TEST_ROOT_WAL_ARM") {
        fs::write(arm, b"lease mutation armed after native open\n")?;
    }
    let operation = request["operation"].as_str().unwrap();
    let expected = request["generation"].as_u64().unwrap();
    let mut acknowledged_record = None;
    let (generation, result) = match operation {
        "release" => {
            assert_eq!(
                db.repair_leases().release(expected, &binding, &digest)?,
                LeaseRelease::Released
            );
            (expected, "Released")
        }
        "acquire" => {
            let dependencies: Vec<Dependency> =
                serde_json::from_value(request["dependencies"].clone())?;
            assert_eq!(dependency_digest(&dependencies)?, digest);
            let generation = db.repair_leases().begin(
                &binding,
                dependencies,
                &HistoryReadBudget::new(Default::default()),
            )?;
            assert_eq!(generation, expected);
            (generation, "Protecting")
        }
        "custody" => {
            let record = db
                .repair_leases()
                .durable(expected, &HistoryReadBudget::new(Default::default()))?;
            assert_eq!(record.generation, expected);
            assert_eq!(record.binding, binding.encode()?);
            assert_eq!(record.dependency_digest, format!("{:x}", digest));
            assert_eq!(
                record.state,
                crate::publication_dependency_leases::LeaseState::DurableCustody
            );
            acknowledged_record = Some(serde_json::to_value(record)?);
            (expected, "DurableCustody")
        }
        _ => rtos_block::fail!("Unknown lease mutation"),
    };
    let receipt = root.join("lease-mutation-ack.json");
    fs::write(
        &receipt,
        serde_json::to_vec(&serde_json::json!({
            "generation": generation, "binding": request["binding"], "digest": request["digest"],
            "result": result, "operation": operation, "native_owner_alive": true,
            "record": acknowledged_record,
        }))?,
    )?;
    fs::File::open(&receipt)?.sync_all()?;
    // Parent kills/reaps this process. Never drop the native owner or close its WAL.
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

pub(super) async fn release_and_interrupt(root: &Path, lease: &Lease) -> Result<()> {
    mutate_and_interrupt(root, lease, "release").await.map(|_| ())
}

pub(super) async fn acquire_and_interrupt(root: &Path, lease: &mut Lease) -> Result<()> {
    assert_eq!(lease.generation, 0, "acquisition fixture already owns a lease");
    lease.generation = mutate_and_interrupt(root, lease, "acquire").await?.0;
    Ok(())
}

pub(super) async fn durable_and_interrupt(root: &Path, lease: &Lease) -> Result<serde_json::Value> {
    mutate_and_interrupt(root, lease, "custody")
        .await?
        .1
        .ok_or_else(|| rtos_block::error!("Missing acknowledged custody record"))
}

async fn mutate_and_interrupt(
    root: &Path,
    lease: &Lease,
    operation: &str,
) -> Result<(u64, Option<serde_json::Value>)> {
    let generation = if operation == "acquire" { 1 } else { lease.generation };
    let result = match operation {
        "acquire" => "Protecting",
        "custody" => "DurableCustody",
        _ => "Released",
    };
    fs::write(
        root.join("lease-mutation-input.json"),
        serde_json::to_vec(&serde_json::json!({
            "generation": generation, "binding": lease.binding.encode()?,
            "operation": operation, "dependencies": lease.dependencies,
            "digest": format!("{:x}", lease.digest),
        }))?,
    )?;
    cache_loss::sync_fixture(root)?;
    let path = root.join("lease-mutation-child.log");
    let log = fs::File::create(&path)?;
    let mut child = Process(Command::new(std::env::current_exe()?)
        .args(["--exact", "--ignored", "--nocapture", "--test-threads=1",
            "archive_import::tests::node_process_recovery::truncation_recovery::lease_cache_loss::mutation_child"])
        .env("RTOS_TEST_LEASE_CHILD_ROOT", root)
        .stdout(Stdio::from(log.try_clone()?)).stderr(Stdio::from(log)).spawn()?);
    let receipt = root.join("lease-mutation-ack.json");
    let deadline = Instant::now() + Duration::from_secs(60);
    let acknowledged_record;
    loop {
        if receipt.exists() {
            if let Ok(bytes) = fs::read(&receipt) {
                if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                    assert_eq!(value["generation"].as_u64(), Some(generation));
                    assert_eq!(value["binding"], serde_json::json!(lease.binding.encode()?));
                    assert_eq!(
                        value["digest"].as_str(),
                        Some(format!("{:x}", lease.digest).as_str())
                    );
                    assert_eq!(value["result"], result);
                    assert_eq!(value["operation"], operation);
                    assert_eq!(value["native_owner_alive"], true);
                    acknowledged_record = value.get("record").cloned().filter(|v| !v.is_null());
                    if operation == "custody" {
                        let record = acknowledged_record.as_ref().expect("missing custody record");
                        assert_eq!(record["generation"].as_u64(), Some(generation));
                        assert_eq!(record["binding"], serde_json::json!(lease.binding.encode()?));
                        assert_eq!(record["dependencies"], serde_json::json!(lease.dependencies));
                        assert_eq!(record["dependency_digest"], format!("{:x}", lease.digest));
                        assert_eq!(record["state"], "DurableCustody");
                    }
                    break;
                }
            }
        }
        if let Some(status) = child.0.try_wait()? {
            keep_evidence(root, &path)?;
            rtos_block::fail!("Lease child exited before release acknowledgement: {status}");
        }
        if Instant::now() >= deadline {
            keep_evidence(root, &path)?;
            rtos_block::fail!("Lease release acknowledgement timeout");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(child.0.try_wait()?.is_none(), "lease writer closed before interruption");
    child.0.kill()?;
    let status = child.0.wait()?;
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(status.signal(), Some(9));
    keep_evidence(root, &path)?;
    keep_evidence(root, &receipt)?;
    let loss = match std::env::var("RTOS_TEST_CACHE_LOSS_ENABLED")?.as_str() {
        "1" => true,
        "0" => false,
        _ => rtos_block::fail!("Invalid cache-loss mode"),
    };
    if loss {
        cache_loss::clear(root).await?;
    }
    eprintln!(
        "Acknowledged lease {operation} writer killed without native close; cache-loss={loss}"
    );
    Ok((generation, acknowledged_record))
}
