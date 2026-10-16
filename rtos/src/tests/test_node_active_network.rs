// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Four real executables: a surviving quorum progresses while one validator restarts.
use super::*;
use rtos_api::{IntoBoxed, Signing};
use rtos_block::{Ed25519KeyOption, KeyOption, UInt256, ZeroizingBytes};

fn copy_fixture(source: &Path, destination: &Path) -> Result<()> {
    if source.is_dir() {
        fs::create_dir(destination)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            assert!(!entry.file_type()?.is_symlink());
            copy_fixture(&entry.path(), &destination.join(entry.file_name()))?;
        }
    } else { fs::copy(source, destination)?; }
    Ok(())
}

fn launch(binary: &Path, root: &Path, boot: usize, fault: Option<&Fault>) -> Result<(Process, PathBuf)> {
    let path = root.join(format!("network-boot-{boot}.log"));
    let file = fs::File::create(&path)?;
    let mut command = Command::new(binary);
    command.env("TOKIO_WORKER_THREADS", "2")
        .arg("--configs").arg(root).arg("--zerostate").arg(root.join("zero"))
        .arg("--initial-sync-disabled").current_dir(root)
        .stdout(Stdio::from(file.try_clone()?)).stderr(Stdio::from(file));
    if let Some(fault) = fault {
        command.env("LD_PRELOAD", &fault.library).env("RTOS_TEST_SOURCE_FAULT_MODE", &fault.mode)
            .env("RTOS_TEST_SOURCE_FAULT_DIRECTORY", &fault.directory)
            .env("RTOS_TEST_SOURCE_FAULT_ARM", &fault.arm).env("RTOS_TEST_SOURCE_FAULT_MARKER", &fault.marker);
    }
    let child = command.spawn()?;
    Ok((Process(child), path))
}

fn keep_node_evidence(node: &Path, path: &Path) -> Result<()> {
    if let Some(evidence) = std::env::var_os("RTOS_NODE_RECOVERY_EVIDENCE_DIR") {
        let fixture = node.parent().unwrap().parent().unwrap();
        let destination = PathBuf::from(evidence).join(fixture.file_name().unwrap()).join(node.file_name().unwrap());
        fs::create_dir_all(&destination)?;
        fs::copy(path, destination.join(path.file_name().unwrap()))?;
    }
    Ok(())
}

fn observe(root: &Path, process: &mut Process, log: &Path) -> Result<u32> {
    keep_node_evidence(root, log)?;
    if let Some(status) = process.0.try_wait()? { rtos_block::fail!("Network node exited {status}: {}", log.display()); }
    let output = fs::read_to_string(log)?;
    if !output.contains("Node services started.") { return Ok(0); }
    Ok(output.lines().filter_map(|l| l.strip_prefix("Processing masterblock "))
        .filter_map(|s| s.parse::<u32>().ok()).max().unwrap_or(0))
}

async fn wait_for(nodes: &mut [Option<(Process, PathBuf)>], roots: &[PathBuf], floor: u32) -> Result<Vec<u32>> {
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let heights = nodes.iter_mut().zip(roots).filter_map(|(node, root)| node.as_mut()
            .map(|(process, log)| observe(root, process, log))).collect::<Result<Vec<_>>>()?;
        if heights.iter().all(|h| *h >= floor) { return Ok(heights); }
        if Instant::now() >= deadline { rtos_block::fail!("Actual network failed to reach MC{floor}; observed {heights:?}"); }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

fn interrupt(node: &mut Option<(Process, PathBuf)>, root: &Path) -> Result<()> {
    let (mut process, log) = node.take().unwrap();
    process.0.kill()?;
    assert!(!process.0.wait()?.success());
    keep_node_evidence(root, &log)?;
    Ok(())
}

pub(super) async fn run(binary: &Path, root: &Path, fixture: &Fixture, fault_mode: Option<&str>) -> Result<()> {
    // Clone only closed, authenticated MC4 stores. Each process gets its own
    // physical DB, owner directory, PQ custody and ADNL/DHT identities.
    let entries = fs::read_dir(root)?.map(|e| e.map(|e| e.path())).collect::<std::io::Result<Vec<_>>>()?;
    let network = root.join("network"); fs::create_dir(&network)?;
    let mut roots = Vec::new();
    let mut sockets = Vec::new();
    let mut peers = Vec::new();
    let mut fault = None;
    let mut expiry = None;
    let expiring = fault_mode.is_some_and(|m| m.starts_with("signer-expiry"));
    let io_mode = match fault_mode {
        Some("signer-expiry-write-enospc") => Some("write-enospc"),
        Some("signer-expiry-sync-eio") => Some("sync-eio"),
        Some("signer-expiry") => None, other => other,
    };
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs() as i32;
    for i in 0..4u8 {
        let node = network.join(format!("node-{i}")); fs::create_dir(&node)?;
        for source in &entries { copy_fixture(source, &node.join(source.file_name().unwrap()))?; }
        let adnl = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let quic = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let port = adnl.local_addr()?.port();
        let mut config: serde_json::Value = serde_json::from_slice(&fs::read(node.join("default_config.json"))?)?;
        config["internal_db_path"] = serde_json::json!(node.join("node_db"));
        config["ip_address"] = adnl.local_addr()?.to_string().into();
        config["ip_address_quic"] = quic.local_addr()?.to_string().into();
        fs::write(node.join("default_config.json"), serde_json::to_vec(&config)?)?;
        let expire_at = if i == 0 && expiring { unix_now()?.checked_add(45).unwrap() } else { u32::MAX };
        let runtime = active_validator::provision_with_expiry(&node, fixture, 0xa0 + i, 0x61 + i, expire_at).await?;
        assert_eq!(runtime.catchain_seqno(), 7, "MC4 must hand off from historical session 6");
        if i == 0 {
            let namespace = PathBuf::from(runtime.runtime_directory(node.join("node_db/catchains").to_str().unwrap())?);
            if expiring { expiry = Some(Expiry::prepare(&node, &namespace, runtime.session_id(), expire_at)?); }
            if let Some(mode) = io_mode { fault = Some(Fault::prepare(root, &namespace, mode)?); }
        }
        let (dht_json, key) = Ed25519KeyOption::<ZeroizingBytes>::from_private_key_with_json(&[0x71 + i; 32])?;
        let addr_list = rtos_api::ton::adnl::addresslist::AddressList {
            addrs: vec![rtos_api::ton::adnl::address::address::Udp { ip: 0x7f000001, port: i32::from(port) }.into_boxed()],
            version: now, reinit_date: now, priority: 0, expire_at: 0,
        };
        let signed = rtos_api::ton::dht::node::Node {
            id: (&key).try_into()?, addr_list, version: now, signature: vec![],
        }.sign(&key)?;
        peers.push(serde_json::json!({"@type":"dht.node","id":{"@type":"pub.ed25519","key":rtos_block::base64_encode(key.pub_key()?)},
            "addr_list":{"@type":"adnl.addressList","addrs":[{"@type":"adnl.address.udp","ip":0x7f000001,"port":port}],
                "version":now,"reinit_date":now,"priority":0,"expire_at":0},"version":now,"signature":rtos_block::base64_encode(&signed.signature)}));
        let mut config: serde_json::Value = serde_json::from_slice(&fs::read(node.join("config.json"))?)?;
        for entry in config["adnl_node"]["keys"].as_array_mut().unwrap() {
            if entry["tag"] == crate::network::node_network::NodeNetwork::TAG_DHT_KEY { entry["data"] = serde_json::to_value(&dht_json)?; }
        }
        fs::write(node.join("config.json"), serde_json::to_vec(&config)?)?;
        roots.push(node); sockets.push((adnl, quic));
    }
    for node in &roots {
        let path = node.join("authenticated-global.json");
        let mut global: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
        global["dht"]["static_nodes"]["nodes"] = serde_json::json!(peers);
        fs::write(path, serde_json::to_vec(&global)?)?;
    }
    drop(sockets);
    let mut nodes = roots.iter().enumerate().map(|(i, root)| launch(binary, root, 0, if i == 0 { fault.as_ref() } else { None }).map(Some)).collect::<Result<Vec<_>>>()?;
    let initial = wait_for(&mut nodes, &roots, 5).await?;
    let mut expiry_report = if let Some(expiry) = &expiry {
        assert!(unix_now()? < expiry.deadline, "expiry occurred before authenticated active participation");
        let deadline = Instant::now() + Duration::from_secs(90);
        let refused_heights = loop {
            let heights = nodes.iter_mut().zip(&roots).map(|(node, root)| {
                let (process, path) = node.as_mut().unwrap(); observe(root, process, path)
            }).collect::<Result<Vec<_>>>()?;
            let output = fs::read_to_string(&nodes[0].as_ref().unwrap().1)?;
            if unix_now()? >= expiry.deadline && output.contains("signing generation expired and retired") { break heights; }
            if Instant::now() >= deadline { rtos_block::fail!("Actual signer did not reach expiry retirement"); }
            tokio::time::sleep(Duration::from_millis(200)).await;
        };
        let live_survivors = wait_for(&mut nodes[1..], &roots[1..], refused_heights.iter().max().unwrap() + 2).await?;
        eprintln!("Actual signer expired at {}; refused at {refused_heights:?}; live quorum advanced to {live_survivors:?}", expiry.deadline);
        Some(serde_json::json!({"expire_at":expiry.deadline,"expiry_refusal_observed":true,
            "refused_heights":refused_heights,"live_surviving_heights":live_survivors,
            "real_system_clock":true,"expiry_profile_extended":false}))
    } else { None };
    let failed_source = if let Some(fault) = &fault {
        fs::write(&fault.arm, b"armed after all four actual nodes applied MC5\n")?;
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            let (process, path) = nodes[0].as_mut().unwrap();
            observe(&roots[0], process, path)?;
            let output = fs::read_to_string(path)?;
            if fault.marker.exists() && output.contains("Node WAL durable but source ACK needs retry:")
                && output.contains(if fault.mode == "sync-eio" { "Input/output error" } else { "No space left on device" }) { break; }
            if Instant::now() >= deadline { rtos_block::fail!("Live network source IO fault did not reach native ACK error"); }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let marker = fs::read_to_string(&fault.marker)?;
        assert_eq!(marker.lines().count(), 1);
        let target = PathBuf::from(marker.trim_end().strip_prefix(&format!("source {}: ", fault.mode)).unwrap());
        assert_eq!(target.parent(), Some(fault.directory.as_path()));
        let name = target.file_name().unwrap().to_str().unwrap().strip_suffix(".ack.tmp").unwrap();
        let pending = fault.directory.join(format!("{name}.json"));
        let original = fs::read(&pending)?;
        assert!(!fault.directory.join(format!("{name}.acked")).exists());
        let bytes = fs::metadata(&target)?.len();
        assert_eq!(bytes > 0, fault.mode == "sync-eio");
        for path in [&fault.arm, &fault.marker] { keep_evidence(root, path)?; }
        let report = root.join("network-source-io.json");
        fs::write(&report, serde_json::to_vec_pretty(&serde_json::json!({"mode":fault.mode,
            "target":target,"pending_bytes":original.len(),"pending_sha256":UInt256::calc_file_hash(&original).to_hex_string(),
            "temporary_bytes":bytes,"node_wal_durable_error_observed":true,"source_acknowledged":false,
            "fault_scope":"persistent ACK temporary-file operation in node 0 only, removed on restart"}))?)?;
        keep_evidence(root, &report)?;
        Some((pending, original))
    } else { None };
    let cut_heights = nodes.iter_mut().zip(&roots).map(|(node, root)| {
        let (process, path) = node.as_mut().unwrap(); observe(root, process, path)
    }).collect::<Result<Vec<_>>>()?;
    let baseline = *cut_heights.iter().max().unwrap();
    interrupt(&mut nodes[0], &roots[0])?;
    if let Some((pending, original)) = failed_source { assert_eq!(fs::read(pending)?, original, "failed source must survive process interruption"); }
    let surviving = wait_for(&mut nodes, &roots, baseline + 2).await?;
    let survivor_floor = *surviving.iter().min().unwrap();
    eprintln!("Four actual nodes reached {initial:?}; node 0 SIGKILL; surviving quorum advanced to {surviving:?}");
    nodes[0] = Some(launch(binary, &roots[0], 1, None)?);
    let recovered = wait_for(&mut nodes, &roots, survivor_floor + 1).await?;
    if let Some(report) = &mut expiry_report {
        let output = fs::read_to_string(&nodes[0].as_ref().unwrap().1)?;
        // History recovery may still own this namespace while public block
        // synchronization has already caught up. The authoritative retirement
        // and fresh-certificate checks below do not depend on retry log timing.
        report["expired_profile_refusal_logged"] = output.contains(
            "Isolated custody key differs from authenticated descriptor or has expired").into();
    }
    for (node, root) in nodes.iter_mut().zip(&roots) { interrupt(node, root)?; }
    let common_height = *recovered.iter().min().unwrap();
    let retirement = expiry.as_ref().map(Expiry::verify_retired).transpose()?;
    if let Some(report) = &mut expiry_report {
        report["retirement"] = retirement.as_ref().unwrap().clone();
        report["old_signing_generation_stayed_retired"] = true.into();
    }
    let mut common: Option<(rtos_block::BlockIdExt, UInt256)> = None;
    let mut reports = Vec::new();
    for node in &roots {
        let db = open_db(node).await?;
        fixture.assert_history(&db, 4).await?;
        let head = db.load_full_node_state(LAST_APPLIED_MC_BLOCK)?.unwrap();
        assert!(head.seq_no() >= common_height);
        let governing = db.load_shard_state_dynamic(&fixture.id(4, false))?;
        let mut current = (*head).clone();
        let mut verified = 0;
        while current.seq_no() > 4 {
            let handle = db.load_block_handle(&current)?.unwrap(); assert!(handle.is_applied());
            let block = db.load_block_data(&handle).await?;
            let state = db.load_shard_state_dynamic(&current)?;
            assert_eq!(state.root_cell().repr_hash(), &block.block()?.read_state_update()?.new_hash);
            let proof = db.load_block_proof(&handle, false).await?;
            proof.check_with_master_state(&governing)?;
            let rtos_block::BlockSignaturesVariant::SimplexPq(carrier) = proof.drain_signatures()? else { panic!("missing PQ finality") };
            assert_eq!(carrier.validator_info.catchain_seqno, 7);
            assert!(carrier.sig_count >= 3 && carrier.sig_weight >= 3);
            if current.seq_no() == common_height {
                if let Some(retirement) = &retirement {
                    assert!(u64::from(carrier.slot) > retirement["max_signed_finalize_slot"].as_u64().unwrap());
                    assert!(carrier.signatures.iter().all(|s| s.validator_id != UInt256::from([1; 32])),
                        "fresh final certificate contains expired validator");
                }
                let identity = (current.clone(), state.root_cell().repr_hash().clone());
                if let Some(expected) = &common { assert_eq!(&identity, expected); } else { common = Some(identity); }
            }
            let parent = db.load_block_prev1(&current)?;
            assert_eq!(parent.seq_no() + 1, current.seq_no());
            assert_eq!(db.load_block_next1(&parent)?, current);
            current = parent; verified += 1;
        }
        assert_eq!(current, fixture.id(4, false));
        for key in [ARCHIVES_GC_BLOCK, PSS_KEEPER_MC_BLOCK, SHARD_CLIENT_MC_BLOCK] {
            assert!(db.load_full_node_state(key)?.unwrap().seq_no() <= head.seq_no());
        }
        reports.push(serde_json::json!({"head":head.seq_no(),"verified_new_blocks":verified}));
        let (physical, _) = db.sst_databases_for_test();
        drop(governing); db.stop_states_db().await?; drop(db);
        tokio::time::timeout(Duration::from_secs(30), wait_for_db_release(physical)).await?;
    }
    let (id, state) = common.unwrap();
    let report = root.join("active-network-recovery.json");
    fs::write(&report, serde_json::to_vec_pretty(&serde_json::json!({
        "scenario":fault_mode,"source_io_fault":io_mode,"signer_expiry":expiry_report,"node_count":4,"total_weight":4,"interrupted_weight":1,"surviving_weight":3,
        "initial_heights":initial,"interruption_heights":cut_heights,"surviving_heights":surviving,"recovered_heights":recovered,
        "common_height":common_height,"common_block":id.to_string(),"common_state_root":state.to_hex_string(),
        "native_reopen_between_boots":false,"nodes":reports,
    }))?)?;
    keep_evidence(root, &report)?;
    Ok(())
}

struct Fault {
    mode: String,
    library: PathBuf,
    directory: PathBuf,
    arm: PathBuf,
    marker: PathBuf,
}
impl Fault {
    fn prepare(root: &Path, namespace: &Path, mode: &str) -> Result<Self> {
        assert!(matches!(mode, "write-enospc" | "sync-eio"));
        let source = root.join("network-source-fault.c");
        let library = root.join("network-source-fault.so");
        fs::write(&source, include_str!("finality_source_fault.c"))?;
        let built = Command::new("cc").args(["-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror"])
            .arg(&source).arg("-o").arg(&library).output()?;
        assert!(built.status.success(), "{}", String::from_utf8_lossy(&built.stderr));
        for path in [&source, &library] { keep_evidence(root, path)?; }
        Ok(Self { mode: mode.into(), library, directory: namespace.join("finality-pending"),
            arm: root.join("network-source-io.arm"), marker: root.join("network-source-io.reached") })
    }
}

fn unix_now() -> Result<u32> {
    Ok(u32::try_from(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs())?)
}

struct Expiry {
    deadline: u32,
    journal: PathBuf,
    originals: Vec<(PathBuf, Vec<u8>)>,
}
impl Expiry {
    fn prepare(node: &Path, namespace: &Path, session: &UInt256, deadline: u32) -> Result<Self> {
        let owners = fs::read_dir(node.join("isolated-owner"))?.map(|e| e.map(|e| e.path()))
            .collect::<std::io::Result<Vec<_>>>()?;
        assert_eq!(owners.len(), 1);
        let mut paths = vec![namespace.join(simplex::isolated_signing::PROFILE_FILE),
            node.join("isolated-custody/public-test-seed")];
        paths.extend(owners);
        let originals = paths.into_iter().map(|p| fs::read(&p).map(|b| (p, b))).collect::<std::io::Result<_>>()?;
        Ok(Self { deadline, journal: namespace.join(session.to_hex_string()), originals })
    }
    fn verify_retired(&self) -> Result<serde_json::Value> {
        for (path, original) in &self.originals { assert_eq!(&fs::read(path)?, original, "expired custody/profile/owner was changed"); }
        // Only after all actual processes stopped. No native DB is reopened
        // between the interruption and the executable restart.
        let db = storage::db::rocksdb::RocksDb::new(self.journal.parent().unwrap(),
            self.journal.file_name().unwrap().to_str().unwrap(), None,
            storage::db::rocksdb::AccessType::ReadOnly)?;
        let bytes = db.db().get(b"RSJ1H")?.unwrap();
        let header: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(header["retired"], true);
        assert_eq!(header["binding"]["expire_at"], self.deadline);
        assert_eq!(header["binding"]["generation"], 1);
        assert_eq!(header["binding"]["validator"], serde_json::json!(vec![1u8; 32]));
        let mut iterator = db.db().raw_iterator(); iterator.seek(b"RSJ1D");
        let mut signed = 0; let mut candidates = 0; let mut max_finalize = None;
        while iterator.valid() && iterator.key().unwrap().starts_with(b"RSJ1D") {
            let record: serde_json::Value = serde_json::from_slice(iterator.value().unwrap())?;
            if !record["signed"].is_null() {
                signed += 1;
                if record["decision"]["kind"] == 3 { candidates += 1; }
                if record["decision"]["kind"] == 1 {
                    let slot = record["decision"]["slot"].as_u64().unwrap();
                    max_finalize = Some(max_finalize.map_or(slot, |old: u64| old.max(slot)));
                }
            }
            iterator.next();
        }
        iterator.status()?;
        assert!(signed > 0 && candidates > 0, "expired validator never actively signed");
        let max_finalize = max_finalize.expect("expired validator never signed finality before expiry");
        Ok(serde_json::json!({"persisted_retired":true,"generation":1,"own_signed_decisions":signed,
            "own_signed_candidates":candidates,"max_signed_finalize_slot":max_finalize,
            "profile_key_owner_unchanged":true,"journal_header_sha256":UInt256::calc_file_hash(&bytes).to_hex_string()}))
    }
}
