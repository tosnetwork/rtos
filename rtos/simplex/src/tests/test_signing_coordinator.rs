// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{pq_fixture as f, session_description::SessionDescription, SessionOptions};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
pub(crate) fn description() -> Arc<SessionDescription> {
    description_with_profile(rtos_api::WireProfile::Legacy)
}
pub(crate) fn description_with_profile(
    wire_profile: rtos_api::WireProfile,
) -> Arc<SessionDescription> {
    let (nodes, keys) = f::members();
    Arc::new(
        SessionDescription::new(
            &SessionOptions { wire_profile, ..Default::default() },
            f::session(),
            42,
            &nodes,
            keys[1].clone(),
            &ShardIdent::masterchain(),
            SystemTime::now(),
            None,
        )
        .unwrap()
        .bind_pq_session(7)
        .unwrap(),
    )
}
pub(crate) fn binding(d: &SessionDescription) -> SigningBinding {
    let identity = d.get_source_public_key(d.get_self_idx());
    let key = identity.pq_key().unwrap();
    SigningBinding {
        schema: 2,
        wire_profile: d.opts().wire_profile as u8,
        global_id: -777,
        zerostate_workchain: -1,
        zerostate_root: [11; 32],
        zerostate_file: [12; 32],
        profile: [13; 32],
        session: *d.get_session_id().as_array(),
        committee: *d.committee_digest().as_array(),
        validator: *identity.id().data(),
        algorithm: key.algorithm_id as u32,
        key_id: *key.key_id.as_array(),
        public_key: key.public_key.clone(),
        generation: 1,
        expire_at: 0,
        shard_workchain: -1,
        shard_prefix: 0x8000000000000000,
        protocol: 0,
        simplex_protocol: None,
        local_adnl: None,
        local_index: 1,
        validator_count: 2,
        slots_per_window: 1,
    }
}
pub(crate) fn signer(count: Arc<AtomicUsize>) -> Signer {
    Signer::PublicTest(Box::new(move |message| {
        count.fetch_add(1, Ordering::SeqCst);
        // Public, fixed test signatures. The real verifier still authenticates
        // every result; there is no test-only verification bypass.
        let mut fixture = f::data();
        fixture["rows"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::from_str(include_str!("data/own-signing-full.json")).unwrap());
        let found = fixture["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| {
                r["index"] == 1 && r["context"] == f::CONTEXT && f::bytes(r, "preimage") == message
            })
            .map(|r| f::bytes(r, "signature"))
            .ok_or_else(|| error!("unknown public test preimage {}", hex::encode(message)));
        if let Err(ref error) = found {
            eprintln!("{error}");
        }
        found
    }))
}
pub(crate) fn custody_descriptor(
    store: &rtos_pq_consensus::ConsensusKeyStore,
) -> rtos_block::ValidatorDescr {
    let (_, keys) = f::members();
    rtos_block::ValidatorDescr::with_pq_params(
        UInt256::from([2; 32]),
        store.consensus_key().clone(),
        2,
        UInt256::from(*keys[1].id().data()),
    )
}
pub(crate) fn custody_description(
    profile: rtos_api::WireProfile,
    store: &rtos_pq_consensus::ConsensusKeyStore,
) -> Arc<SessionDescription> {
    let (mut nodes, keys) = f::members();
    nodes[1] = crate::SimplexSessionNode::from_descriptor(&custody_descriptor(store)).unwrap();
    Arc::new(
        SessionDescription::new(
            &SessionOptions { wire_profile: profile, ..Default::default() },
            f::session(),
            42,
            &nodes,
            keys[1].clone(),
            &ShardIdent::masterchain(),
            SystemTime::now(),
            None,
        )
        .unwrap()
        .bind_pq_session(7)
        .unwrap(),
    )
}
pub(crate) fn custody_backend(
    description: &SessionDescription,
    store: Arc<rtos_pq_consensus::ConsensusKeyStore>,
) -> Signer {
    let mut custody = rtos_pq_consensus::PqConsensusCustody::default();
    custody.install(UInt256::from([2; 32]), store.clone(), 0, store.expire_at()).unwrap();
    let signer =
        Signer::from_test_custody(&custody, &UInt256::from([2; 32]), &custody_descriptor(&store))
            .unwrap();
    assert_eq!(
        description.get_source_public_key(description.get_self_idx()).pq_key().unwrap(),
        store.consensus_key()
    );
    signer
}
pub(crate) struct Harness {
    pub root: PathBuf,
    pub db: SimplexDbPtr,
    pub description: Arc<SessionDescription>,
    pub coordinator: Arc<SigningCoordinator>,
    pub calls: Arc<AtomicUsize>,
    pub store: Option<Arc<rtos_pq_consensus::ConsensusKeyStore>>,
}
impl Harness {
    pub fn new() -> Self {
        Self::new_with_profile(rtos_api::WireProfile::Legacy)
    }
    pub fn new_with_profile(wire_profile: rtos_api::WireProfile) -> Self {
        let root = std::env::temp_dir().join(format!("rtos-signing-{}", UInt256::rand()));
        std::fs::create_dir(&root).unwrap();
        let db = crate::database::SimplexDb::open(root.join("db"), "own-signing").unwrap();
        let description = description_with_profile(wire_profile);
        let calls = Arc::new(AtomicUsize::new(0));
        let coordinator = Arc::new(
            SigningCoordinator::open(
                db.clone(),
                binding(&description),
                description.get_source_public_key(description.get_self_idx()).clone(),
                &root,
                true,
                signer(calls.clone()),
            )
            .unwrap(),
        );
        Self { root, db, description, coordinator, calls, store: None }
    }
    pub fn signature_count(&self) -> usize {
        self.store
            .as_ref()
            .map(|store| store.consensus_signatures_produced() as usize)
            .unwrap_or_else(|| self.calls.load(Ordering::SeqCst))
    }
    pub fn custody(wire_profile: rtos_api::WireProfile) -> Self {
        Self::custody_with_key(wire_profile, [0x91; 32], 0)
    }
    pub fn custody_with_key(
        wire_profile: rtos_api::WireProfile,
        seed: [u8; 32],
        expire_at: u32,
    ) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("rtos-custody-journal-{}", UInt256::rand()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let seed_path = root.join("public-test.seed");
        std::fs::write(&seed_path, seed).unwrap();
        std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let custody = rtos_pq_consensus::PqConsensusCustody::load(
            UInt256::from([2; 32]),
            &[rtos_pq_consensus::ConfiguredKey { key_file: seed_path, valid_from: 0, expire_at }],
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32,
        )
        .unwrap();
        let store =
            custody.held_keys(&UInt256::from([2; 32])).values().next().unwrap().store.clone();
        let description = custody_description(wire_profile, &store);
        let db = crate::database::SimplexDb::open(root.join("db"), "own-signing").unwrap();
        let mut journal_binding = binding(&description);
        journal_binding.expire_at = u64::from(store.expire_at());
        let coordinator = Arc::new(
            SigningCoordinator::open(
                db.clone(),
                journal_binding,
                description.get_source_public_key(description.get_self_idx()).clone(),
                &root,
                true,
                custody_backend(&description, store.clone()),
            )
            .unwrap(),
        );
        Self {
            root,
            db,
            description,
            coordinator,
            calls: Arc::new(AtomicUsize::new(0)),
            store: Some(store),
        }
    }
    pub fn reopen(self) -> Self {
        let Self { root, db, description, coordinator, calls, store } = self;
        let wire_profile = description.opts().wire_profile;
        drop(coordinator);
        drop(description);
        db.close(None).unwrap();
        drop(db);
        let db = crate::database::SimplexDb::open(root.join("db"), "own-signing").unwrap();
        let description = match &store {
            Some(store) => custody_description(wire_profile, store),
            None => description_with_profile(wire_profile),
        };
        let backend = match &store {
            Some(store) => custody_backend(&description, store.clone()),
            None => signer(calls.clone()),
        };
        let mut journal_binding = binding(&description);
        if let Some(store) = &store {
            journal_binding.expire_at = u64::from(store.expire_at());
        }
        let coordinator = Arc::new(
            SigningCoordinator::open(
                db.clone(),
                journal_binding,
                description.get_source_public_key(description.get_self_idx()).clone(),
                &root,
                false,
                backend,
            )
            .unwrap(),
        );
        Self { root, db, description, coordinator, calls, store }
    }
}
pub(crate) fn vote(role: &str) -> Vote {
    utils::extract_vote(&f::vote(
        if role == "skip" { "skip" } else { "empty" },
        role,
        1,
        f::CONTEXT,
    ))
    .unwrap()
}
pub(crate) fn empty() -> CandidateData {
    rtos_api::ton::consensus::candidatedata::Empty {
        slot: 99,
        parent: rtos_api::ton::consensus::candidateid::CandidateId {
            slot: 98,
            hash: UInt256::from([5; 32]),
        }
        .into_boxed(),
        block: f::block_id("empty"),
        signature: vec![],
    }
    .into_boxed()
}
#[test]
fn own_journal_restart_exact_bytes_and_conflicts() {
    for (a, b, ok) in [
        ("notarize", "skip", true),
        ("skip", "notarize", true),
        ("notarize", "finalize", true),
        ("finalize", "notarize", true),
        ("finalize", "skip", false),
        ("skip", "finalize", false),
    ] {
        let h = Harness::new();
        let first = h.coordinator.vote(&vote(a)).unwrap();
        assert_eq!(h.calls.load(Ordering::SeqCst), 1);
        let h = h.reopen();
        assert_eq!(
            rtos_api::serialize_boxed(&first.into_boxed()).unwrap(),
            rtos_api::serialize_boxed(&h.coordinator.vote(&vote(a)).unwrap().into_boxed()).unwrap()
        );
        assert_eq!(h.calls.load(Ordering::SeqCst), 1);
        assert_eq!(h.coordinator.vote(&vote(b)).is_ok(), ok);
        assert_eq!(h.calls.load(Ordering::SeqCst), if ok { 2 } else { 1 });
    }
}
#[test]
fn own_journal_every_commit_boundary() {
    for stage in [
        "before_intent",
        "after_intent",
        "before_sign",
        "after_sign",
        "before_signed",
        "after_signed",
    ] {
        for candidate in [false, true] {
            let h = Harness::new();
            *h.coordinator.fail_at.lock().unwrap() = Some(stage);
            let result = if candidate {
                h.coordinator.candidate(empty()).map(|_| ())
            } else {
                h.coordinator.vote(&vote("notarize")).map(|_| ())
            };
            assert!(result.is_err(), "{stage}");
            let n = h.calls.load(Ordering::SeqCst);
            assert_eq!(
                n,
                usize::from(matches!(stage, "after_sign" | "before_signed" | "after_signed"))
            );
            *h.coordinator.fail_at.lock().unwrap() = None;
            assert!(
                h.coordinator.vote(&vote("notarize")).is_err(),
                "failure must stop current coordinator"
            );
            let h = h.reopen();
            if candidate {
                h.coordinator.candidate(empty()).unwrap();
            } else {
                h.coordinator.vote(&vote("notarize")).unwrap();
            }
            assert_eq!(h.calls.load(Ordering::SeqCst), n + usize::from(stage != "after_signed"));
        }
    }
}
#[test]
fn own_journal_candidate_body_conflict_and_raw_loader() {
    let h = Harness::new();
    let first = h.coordinator.candidate(empty()).unwrap();
    let h = h.reopen();
    assert_eq!(
        rtos_api::serialize_boxed(&first).unwrap(),
        rtos_api::serialize_boxed(&h.coordinator.candidate(empty()).unwrap()).unwrap()
    );
    assert_eq!(h.calls.load(Ordering::SeqCst), 1);
    let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let bootstrap = h.db.load_pq_bootstrap_cancellable(&cancel, Duration::from_millis(10)).unwrap();
    h.coordinator.verify_bootstrap(&bootstrap.own_journal).unwrap();
    assert!(h.description.verify_own_journal(&bootstrap.own_journal).is_err());
    let mut other = empty();
    if let CandidateData::Consensus_Empty(ref mut c) = other {
        c.block.seq_no += 1;
    }
    assert!(h.coordinator.candidate(other).is_err());
    assert_eq!(h.calls.load(Ordering::SeqCst), 1);
}
#[test]
fn own_journal_disabled_owner_binding_and_storage_errors() {
    let h = Harness::new();
    let b = binding(&h.description);
    let identity = h.description.get_source_public_key(h.description.get_self_idx()).clone();
    assert!(SigningCoordinator::open(
        h.db.clone(),
        b.clone(),
        identity.clone(),
        &h.root,
        false,
        Signer::Disabled
    )
    .is_err());
    let alternate =
        crate::database::SimplexDb::open(h.root.join("alternate"), "alternate").unwrap();
    assert!(
        SigningCoordinator::open(alternate, b, identity, &h.root, false, Signer::Disabled).is_err()
    );
    h.db.close(None).unwrap();
    assert!(h.coordinator.vote(&vote("notarize")).is_err());
    assert_eq!(h.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn own_journal_process_probe() {
    let Ok(root) = std::env::var("RTOS_SIGNING_PROBE_ROOT") else { return };
    let root = PathBuf::from(root);
    let initialize = std::env::var("RTOS_SIGNING_PROBE_MODE").unwrap() == "initialize";
    let profile = match std::env::var("RTOS_SIGNING_PROBE_WIRE_PROFILE").as_deref() {
        Ok("target") => rtos_api::WireProfile::T0,
        Err(_) | Ok("legacy") => rtos_api::WireProfile::Legacy,
        _ => panic!("unknown isolated probe wire profile"),
    };
    let custody_mode = std::env::var("RTOS_SIGNING_PROBE_CUSTODY").is_ok();
    let store = custody_mode.then(|| load_probe_custody(&root, initialize));
    let d = store
        .as_ref()
        .map(|store| custody_description(profile, store))
        .unwrap_or_else(|| description_with_profile(profile));
    let db = crate::database::SimplexDb::open(root.join("db"), "own-signing").unwrap();
    let count_path = root.join("sign-count");
    let signer = if let Some(store) = &store {
        custody_backend(&d, store.clone())
    } else {
        Signer::PublicTest(Box::new(move |message| {
            let n = std::fs::read_to_string(&count_path)
                .unwrap_or_else(|_| "0".to_owned())
                .parse::<u32>()
                .unwrap()
                + 1;
            let mut file = File::create(&count_path)?;
            write!(file, "{n}")?;
            file.sync_all()?;
            signer(Arc::new(AtomicUsize::new(0))).sign(message)
        }))
    };
    let c = SigningCoordinator::open(
        db,
        binding(&d),
        d.get_source_public_key(d.get_self_idx()).clone(),
        &root,
        initialize,
        signer,
    )
    .unwrap();
    {
        let state = c.state.lock().unwrap();
        eprintln!(
            "SIGNING_ADMITTED records={} signed={}",
            state.records.len(),
            state.records.values().filter(|r| r.signed.is_some()).count()
        );
    }
    let candidate = std::env::var("RTOS_SIGNING_PROBE_CANDIDATE").is_ok();
    let full_candidate = std::env::var("RTOS_SIGNING_PROBE_FULL").is_ok();
    let role = std::env::var("RTOS_SIGNING_PROBE_ROLE").unwrap_or_else(|_| "notarize".into());
    let result = if candidate {
        c.candidate(if full_candidate { full() } else { empty() })
            .and_then(|v| profile.serialize(&v))
    } else {
        c.vote(&vote(&role)).and_then(|v| profile.serialize(&v.into_boxed()))
    };
    match result {
        Ok(bytes) => {
            assert!(
                c.state
                    .lock()
                    .unwrap()
                    .records
                    .values()
                    .any(|record| record.signed.as_ref() == Some(&bytes)),
                "probe publication must equal a complete durable carrier"
            );
            if candidate && !full_candidate {
                let expected = if profile == rtos_api::WireProfile::T0 {
                    0x0740558cu32
                } else {
                    0xf117f8ffu32
                };
                assert_eq!(&bytes[..4], &expected.to_le_bytes());
            }
            let mut file = File::create(root.join("published")).unwrap();
            file.write_all(&bytes).unwrap();
            file.sync_all().unwrap();
            eprintln!(
                "SIGNING_PUBLISHED {}",
                hex::encode(UInt256::calc_file_hash(&bytes).as_slice())
            );
        }
        Err(error) => {
            eprintln!("SIGNING_REFUSED {error}");
            assert!(std::env::var("RTOS_SIGNING_EXPECT_FAILURE").is_ok());
        }
    }
    // Deliberately bypass all destructors to test recovery from real process exit.
    std::process::exit(77);
}

#[test]
fn own_journal_expiry_and_retirement_survive_clock_rollback() {
    for after_sign in [false, true] {
        let root = std::env::temp_dir().join(format!("rtos-expiry-{}", UInt256::rand()));
        std::fs::create_dir(&root).unwrap();
        let d = description();
        let mut b = binding(&d);
        b.expire_at = 200;
        let db = crate::database::SimplexDb::open(root.join("db"), "expiry").unwrap();
        let clock = Arc::new(std::sync::atomic::AtomicU64::new(if after_sign { 100 } else { 200 }));
        let calls = Arc::new(AtomicUsize::new(0));
        let clock_copy = clock.clone();
        let calls_copy = calls.clone();
        let test_signer = Signer::PublicTest(Box::new(move |bytes| {
            let sig = signer(calls_copy.clone()).sign(bytes)?;
            clock_copy.store(200, Ordering::SeqCst);
            Ok(sig)
        }));
        let mut c = SigningCoordinator::open(
            db.clone(),
            b.clone(),
            d.get_source_public_key(d.get_self_idx()).clone(),
            &root,
            true,
            test_signer,
        )
        .unwrap();
        c.test_time = clock.clone();
        assert!(c.vote(&vote("notarize")).is_err());
        assert_eq!(calls.load(Ordering::SeqCst), usize::from(after_sign));
        let rows = db.storage.get_by_prefix(PREFIX.to_vec(), None).wait().unwrap();
        for (key, value) in rows {
            if key != HEADER {
                assert!(
                    decode::<Record>(&value).unwrap().signed.is_none(),
                    "expiry crossed during signing must discard signature before commit"
                );
            }
        }
        clock.store(100, Ordering::SeqCst);
        assert!(c.vote(&vote("notarize")).is_err());
        drop(c);
        assert!(
            SigningCoordinator::open(
                db,
                b,
                d.get_source_public_key(d.get_self_idx()).clone(),
                &root,
                false,
                signer(calls.clone())
            )
            .is_err(),
            "retirement must be durable before any clock rollback"
        );
    }
}

#[test]
fn own_journal_rejects_every_binding_change_and_damaged_records() {
    let h = Harness::new();
    h.coordinator.vote(&vote("notarize")).unwrap();
    let Harness { root, db, description, coordinator, calls, .. } = h;
    drop(coordinator);
    let original = binding(&description);
    let identity = description.get_source_public_key(description.get_self_idx()).clone();
    for field in [
        "schema",
        "wire_profile",
        "global_id",
        "zerostate_workchain",
        "zerostate_root",
        "zerostate_file",
        "profile",
        "session",
        "committee",
        "validator",
        "algorithm",
        "key_id",
        "public_key",
        "generation",
        "expire_at",
        "shard_workchain",
        "shard_prefix",
        "protocol",
        "local_index",
        "validator_count",
        "slots_per_window",
    ] {
        let mut value = serde_json::to_value(&original).unwrap();
        if let Some(array) = value[field].as_array_mut() {
            array[0] = serde_json::json!(array[0].as_u64().unwrap() ^ 1);
        } else {
            value[field] = serde_json::json!(value[field].as_i64().map(|v| v + 1).unwrap_or(1));
        }
        let changed = serde_json::from_value(value).unwrap();
        assert!(
            SigningCoordinator::open(
                db.clone(),
                changed,
                identity.clone(),
                &root,
                false,
                signer(calls.clone())
            )
            .is_err(),
            "{field}"
        );
    }
    let raw = db.storage.get_by_prefix(PREFIX.to_vec(), None).wait().unwrap();
    let (k, v) = raw.iter().find(|(k, _)| k != HEADER).unwrap();
    for mode in 0..5 {
        let mut record: Record = decode(v).unwrap();
        let mut key = k.clone();
        match mode {
            0 => record.binding[0] ^= 1,
            1 => {
                let bytes = record.signed.as_mut().unwrap();
                let n = bytes.len();
                bytes[n - 8] ^= 1;
            }
            2 => record.sequence = 0,
            3 => record.decision.kind = 19,
            _ => key[5] ^= 1,
        }
        if mode == 4 {
            db.storage.erase(k.clone(), None).wait().unwrap();
        }
        db.storage.set(key.clone(), encode(&record).unwrap(), None).wait().unwrap();
        assert!(
            SigningCoordinator::open(
                db.clone(),
                original.clone(),
                identity.clone(),
                &root,
                false,
                signer(calls.clone())
            )
            .is_err(),
            "mode={mode}"
        );
        if key != *k {
            db.storage.erase(key, None).wait().unwrap();
        }
        db.storage.set(k.clone(), v.clone(), None).wait().unwrap();
    }
    let mut bad = v.clone();
    bad.push(b' ');
    db.storage.set(k.clone(), bad, None).wait().unwrap();
    let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
    assert!(db.load_pq_bootstrap_cancellable(&cancel, Duration::from_millis(10)).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn own_journal_pending_intent_is_a_durable_conflict_tombstone() {
    for candidate in [false, true] {
        let h = Harness::new();
        *h.coordinator.fail_at.lock().unwrap() = Some("after_intent");
        if candidate {
            assert!(h.coordinator.candidate(empty()).is_err());
        } else {
            assert!(h.coordinator.vote(&vote("notarize")).is_err());
        }
        let h = h.reopen();
        if candidate {
            let mut other = empty();
            if let CandidateData::Consensus_Empty(ref mut c) = other {
                c.block.seq_no += 1;
            }
            assert!(h.coordinator.candidate(other).is_err());
        } else {
            let other =
                utils::extract_vote(&f::vote("ordinary", "notarize", 1, f::CONTEXT)).unwrap();
            assert!(h.coordinator.vote(&other).is_err());
        }
        assert_eq!(
            h.calls.load(Ordering::SeqCst),
            0,
            "a durable conflicting intent must refuse before the signer"
        );
    }
    for (a, b) in [
        ("notarize", "notarize"),
        ("notarize", "finalize"),
        ("finalize", "notarize"),
        ("finalize", "finalize"),
    ] {
        let h = Harness::new();
        h.coordinator.vote(&vote(a)).unwrap();
        let h = h.reopen();
        let other = utils::extract_vote(&f::vote("ordinary", b, 1, f::CONTEXT)).unwrap();
        assert!(h.coordinator.vote(&other).is_err());
        assert_eq!(h.calls.load(Ordering::SeqCst), 1);
    }
}

pub(crate) fn full() -> CandidateData {
    let (data, size) = consensus_common::compression::compress_candidate_data(
        &f::bytes(&f::data(), "block_boc"),
        &[],
    )
    .unwrap();
    let candidate = rtos_api::ton::validator_session::candidate::CompressedCandidate {
        src: UInt256::default(),
        round: 42,
        root_hash: f::block_id("ordinary").root_hash,
        data,
        decompressed_size: size as i32,
    }
    .into_boxed();
    rtos_api::ton::consensus::candidatedata::Block {
        slot: 99,
        candidate: rtos_api::serialize_boxed(&candidate).unwrap(),
        parent: rtos_api::ton::consensus::CandidateParent::Consensus_CandidateWithoutParents,
        signature: vec![],
    }
    .into_boxed()
}
#[test]
fn own_journal_detects_removed_nonterminal_intent() {
    let h = Harness::new();
    h.coordinator.vote(&vote("notarize")).unwrap();
    h.coordinator.vote(&vote("skip")).unwrap();
    let Harness { root, db, description, coordinator, calls, .. } = h;
    drop(coordinator);
    let rows = db.storage.get_by_prefix(PREFIX.to_vec(), None).wait().unwrap();
    let key = rows
        .into_iter()
        .find(|(k, v)| k != HEADER && decode::<Record>(v).unwrap().sequence == 1)
        .unwrap()
        .0;
    db.storage.erase(key, None).wait().unwrap();
    assert!(SigningCoordinator::open(
        db,
        binding(&description),
        description.get_source_public_key(description.get_self_idx()).clone(),
        &root,
        false,
        signer(calls.clone())
    )
    .is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn own_journal_failed_retirement_needs_external_monotonic_anchor() {
    // Boundary characterization, NOT a safety acceptance: a retirement that
    // cannot reach storage has no durable monotonic effect across restarts.
    let root = std::env::temp_dir().join(format!("rtos-retirement-gap-{}", UInt256::rand()));
    std::fs::create_dir(&root).unwrap();
    let description = description();
    let mut binding = binding(&description);
    binding.expire_at = 200;
    let identity = description.get_source_public_key(description.get_self_idx()).clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let db = crate::database::SimplexDb::open(root.join("db"), "retirement-gap").unwrap();
    let c = SigningCoordinator::open(
        db.clone(),
        binding.clone(),
        identity.clone(),
        &root,
        true,
        signer(calls.clone()),
    )
    .unwrap();
    c.test_time.store(200, Ordering::SeqCst);
    db.close(None).unwrap();
    assert!(c.vote(&vote("notarize")).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    drop(c);
    drop(db);
    let db = crate::database::SimplexDb::open(root.join("db"), "retirement-gap").unwrap();
    let c = SigningCoordinator::open(db, binding, identity, &root, false, signer(calls.clone()))
        .unwrap();
    c.test_time.store(100, Ordering::SeqCst);
    assert!(
        c.vote(&vote("notarize")).is_ok(),
        "known limitation: old active header plus clock rollback cannot prove prior expiry"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn wire_profile_binding_refuses_old_headers_and_alternate_namespace_without_mutation() {
    let h = Harness::new();
    h.coordinator.candidate(empty()).unwrap();
    let Harness { root, db, description, coordinator, calls, .. } = h;
    let b = binding(&description);
    let identity = description.get_source_public_key(description.get_self_idx()).clone();
    let owner = root.join(format!("{}.signer", hex::encode(b.validator)));
    let owner_bytes = std::fs::read(&owner).unwrap();
    drop(coordinator);
    let before = db.storage.get_by_prefix(Vec::new(), None).wait().unwrap();
    let mut target = b.clone();
    target.wire_profile = rtos_api::WireProfile::T0 as u8;
    for initialize in [false, true] {
        assert!(SigningCoordinator::open(
            db.clone(),
            target.clone(),
            identity.clone(),
            &root,
            initialize,
            signer(calls.clone())
        )
        .is_err());
        assert_eq!(std::fs::read(&owner).unwrap(), owner_bytes);
        assert_eq!(db.storage.get_by_prefix(Vec::new(), None).wait().unwrap(), before);
    }
    let alternate =
        crate::database::SimplexDb::open(root.join("target-namespace"), "alternate-target")
            .unwrap();
    for initialize in [false, true] {
        assert!(SigningCoordinator::open(
            alternate.clone(),
            target.clone(),
            identity.clone(),
            &root,
            initialize,
            signer(calls.clone())
        )
        .is_err());
        assert_eq!(std::fs::read(&owner).unwrap(), owner_bytes);
        assert!(alternate.storage.get_by_prefix(Vec::new(), None).wait().unwrap().is_empty());
    }
    let original_header = before.iter().find(|(key, _)| key == HEADER).unwrap().1.clone();
    for mode in 0..3 {
        let mut header: Header = decode(&original_header).unwrap();
        let expected;
        let bad = match mode {
            0 => {
                header.binding.schema = 1;
                expected = "unsupported signing header schema";
                encode(&header).unwrap()
            }
            1 => {
                header.binding.wire_profile = 99;
                expected = "unknown signing wire profile";
                encode(&header).unwrap()
            }
            _ => {
                let mut value = serde_json::to_value(&header).unwrap();
                value["binding"].as_object_mut().unwrap().remove("wire_profile");
                expected = "missing field";
                serde_json::to_vec(&value).unwrap()
            }
        };
        db.storage.set(HEADER.to_vec(), bad.clone(), None).wait().unwrap();
        let snapshot = db.storage.get_by_prefix(Vec::new(), None).wait().unwrap();
        let error = SigningCoordinator::open(
            db.clone(),
            b.clone(),
            identity.clone(),
            &root,
            false,
            signer(calls.clone()),
        )
        .err()
        .unwrap();
        assert!(error.to_string().contains(expected), "{error}");
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        assert!(db.load_pq_bootstrap_cancellable(&cancelled, Duration::from_millis(10)).is_err());
        assert_eq!(db.storage.get_by_prefix(Vec::new(), None).wait().unwrap(), snapshot);
        assert_eq!(std::fs::read(&owner).unwrap(), owner_bytes);
        assert!(validate_record(HEADER, &bad).is_err());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn target_candidate_reuses_exact_durable_wire_after_restart() {
    let h = Harness::new_with_profile(rtos_api::WireProfile::T0);
    let signed = h.coordinator.candidate(empty()).unwrap();
    let wire = rtos_api::WireProfile::T0.serialize(&signed).unwrap();
    assert_eq!(&wire[..4], &0x0740558cu32.to_le_bytes());
    assert_ne!(wire, rtos_api::serialize_boxed(&signed).unwrap());
    let raw = h.db.storage.get_by_prefix(PREFIX.to_vec(), None).wait().unwrap();
    let record: Record = decode(&raw.iter().find(|(key, _)| key != HEADER).unwrap().1).unwrap();
    assert_eq!(record.signed.as_ref(), Some(&wire));
    let h = h.reopen();
    let again = h.coordinator.candidate(empty()).unwrap();
    assert_eq!(rtos_api::WireProfile::T0.serialize(&again).unwrap(), wire);
    assert_eq!(h.calls.load(Ordering::SeqCst), 1);
    assert!(h.coordinator.check_session(&description()).is_err());
}

// Public isolated test material; no external secrets or runtime loading switch.
pub(crate) fn load_probe_custody(
    root: &Path,
    initialize: bool,
) -> Arc<rtos_pq_consensus::ConsensusKeyStore> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let seed_path = root.join("public-test.seed");
    if initialize {
        let mut file =
            OpenOptions::new().write(true).create_new(true).mode(0o600).open(&seed_path).unwrap();
        file.write_all(&[0x91; 32]).unwrap();
        file.sync_all().unwrap();
    }
    let custody = rtos_pq_consensus::PqConsensusCustody::load(
        UInt256::from([2; 32]),
        &[rtos_pq_consensus::ConfiguredKey { key_file: seed_path, valid_from: 0, expire_at: 0 }],
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32,
    )
    .unwrap();
    custody.held_keys(&UInt256::from([2; 32])).values().next().unwrap().store.clone()
}

#[test]
fn custody_binding_rejects_wrong_backend_before_journal_creation() {
    use rtos_pq_consensus::ConsensusKeyStore;
    for mismatch in ["key", "validator", "algorithm", "deadline"] {
        let store = Arc::new(ConsensusKeyStore::from_seed(&[0x94; 32], 0).unwrap());
        let d = custody_description(rtos_api::WireProfile::T0, &store);
        let mut b = binding(&d);
        let mut backend = custody_backend(&d, store.clone());
        match mismatch {
            "key" => {
                let other = Arc::new(ConsensusKeyStore::from_seed(&[0x95; 32], 0).unwrap());
                if let Signer::Custody(signer) = &mut backend {
                    signer.store = other;
                }
            }
            "validator" => {
                if let Signer::Custody(signer) = &mut backend {
                    signer.validator = [9; 32];
                }
            }
            "algorithm" => {
                if let Signer::Custody(signer) = &mut backend {
                    signer.algorithm = 99;
                }
            }
            "deadline" => b.expire_at = 4_000_000_000,
            _ => unreachable!(),
        }
        let root = std::env::temp_dir().join(format!("rtos-custody-binding-{}", UInt256::rand()));
        std::fs::create_dir(&root).unwrap();
        let db = crate::database::SimplexDb::open(root.join("db"), "binding").unwrap();
        let result = SigningCoordinator::open(
            db.clone(),
            b.clone(),
            d.get_source_public_key(d.get_self_idx()).clone(),
            &root,
            true,
            backend,
        );
        assert!(result.is_err(), "{mismatch}");
        assert!(!root.join(format!("{}.signer", hex::encode(b.validator))).exists());
        assert!(db.storage.get_by_prefix(PREFIX.to_vec(), None).wait().unwrap().is_empty());
        assert_eq!(store.consensus_signatures_produced(), 0);
        db.close(None).unwrap();
        drop(db);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn custody_randomized_signatures_require_exact_journal_replay() {
    let h = Harness::custody(rtos_api::WireProfile::T0);
    let b = binding(&h.description);
    let preimage = h.coordinator.preimage(&b, &vote_decision(&vote("notarize")).unwrap()).unwrap();
    let store = h.store.as_ref().unwrap();
    let first = store.sign_consensus(&preimage).unwrap();
    let second = store.sign_consensus(&preimage).unwrap();
    assert_ne!(
        first.bytes, second.bytes,
        "real OS-randomized backend must not be replaced by a canned fixture"
    );
    let initial = h.coordinator.vote(&vote("notarize")).unwrap();
    assert_eq!(h.signature_count(), 3);
    let h = h.reopen();
    let replay = h.coordinator.vote(&vote("notarize")).unwrap();
    assert_eq!(
        rtos_api::serialize_boxed(&initial.into_boxed()).unwrap(),
        rtos_api::serialize_boxed(&replay.into_boxed()).unwrap()
    );
    assert_eq!(h.signature_count(), 3);
}

#[test]
fn custody_pending_intent_is_a_durable_conflict_tombstone() {
    for candidate in [false, true] {
        let h = Harness::custody(rtos_api::WireProfile::T0);
        *h.coordinator.fail_at.lock().unwrap() = Some("after_intent");
        if candidate {
            assert!(h.coordinator.candidate(empty()).is_err());
        } else {
            assert!(h.coordinator.vote(&vote("notarize")).is_err());
        }
        let h = h.reopen();
        if candidate {
            let mut other = empty();
            if let CandidateData::Consensus_Empty(ref mut c) = other {
                c.block.seq_no += 1;
            }
            assert!(h.coordinator.candidate(other).is_err());
        } else {
            let other =
                utils::extract_vote(&f::vote("ordinary", "notarize", 1, f::CONTEXT)).unwrap();
            assert!(h.coordinator.vote(&other).is_err());
        }
        assert_eq!(
            h.signature_count(),
            0,
            "a durable conflicting intent must refuse before the signer"
        );
    }
    for (a, b) in [
        ("notarize", "notarize"),
        ("notarize", "finalize"),
        ("finalize", "notarize"),
        ("finalize", "finalize"),
    ] {
        let h = Harness::custody(rtos_api::WireProfile::T0);
        h.coordinator.vote(&vote(a)).unwrap();
        let h = h.reopen();
        let other = utils::extract_vote(&f::vote("ordinary", b, 1, f::CONTEXT)).unwrap();
        assert!(h.coordinator.vote(&other).is_err());
        assert_eq!(h.signature_count(), 1);
    }
}

#[test]
fn schema3_binds_typed_and_carrier_domains_without_upgrading_schema2() {
    let description = description();
    let identity = description.get_source_public_key(description.get_self_idx()).clone();
    let legacy = binding(&description);
    let legacy_bytes = encode(&legacy).unwrap();
    assert!(!String::from_utf8(legacy_bytes.clone()).unwrap().contains("simplex_protocol"));
    assert_eq!(encode(&decode::<SigningBinding>(&legacy_bytes).unwrap()).unwrap(), legacy_bytes);
    let root = std::env::temp_dir().join(format!("rtos-schema3-{}", UInt256::rand()));
    std::fs::create_dir(&root).unwrap();
    let db = crate::database::SimplexDb::open(root.join("db"), "schema3").unwrap();
    let mut v3 = legacy.clone();
    v3.schema = 3;
    v3.simplex_protocol = Some(description.opts().protocol.version());
    v3.local_adnl = Some(*description.get_source_adnl_id(description.get_self_idx()).data());
    let calls = Arc::new(AtomicUsize::new(0));
    let open = |binding, initialize| {
        SigningCoordinator::open(
            db.clone(),
            binding,
            identity.clone(),
            &root,
            initialize,
            signer(calls.clone()),
        )
    };
    let coordinator = open(v3.clone(), true).unwrap();
    coordinator.check_session(&description).unwrap();
    coordinator.vote(&vote("notarize")).unwrap();
    drop(coordinator);
    let owner_path = root.join(format!("{}.signer", hex::encode(v3.validator)));
    let owner_before = std::fs::read(&owner_path).unwrap();
    let before = db.storage.get_by_prefix(Vec::new(), None).wait().unwrap();
    for mode in 0..6 {
        let mut mismatch = v3.clone();
        match mode {
            0 => mismatch.simplex_protocol = Some(1),
            1 => mismatch.protocol = 1,
            2 => mismatch.local_adnl = Some([88; 32]),
            3 => mismatch.simplex_protocol = None,
            4 => mismatch = legacy.clone(),
            _ => mismatch.generation += 1,
        }
        assert!(open(mismatch, false).is_err(), "mode {mode}");
        assert_eq!(std::fs::read(&owner_path).unwrap(), owner_before);
        assert_eq!(db.storage.get_by_prefix(Vec::new(), None).wait().unwrap(), before);
    }
    let coordinator = open(v3, false).unwrap();
    coordinator.check_session(&description).unwrap();
    coordinator.vote(&vote("notarize")).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1, "recovery must reuse exact bytes");
    drop(coordinator);
    db.close(None).unwrap();
    drop(db);
    std::fs::remove_dir_all(root).unwrap();
}
