// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! The production consensus signer and its namespace-owned schema-4 journal.
use super::{tests::vote, *};
use crate::authenticated_fixture::{runtime_with_members_at_key, TestDirectory};
use consensus_common::session_runtime::AuthenticatedSessionRuntime;
use rtos_pq_consensus::{ConsensusKeyStore, PqConsensusCustody};
use std::sync::Arc;

const VALIDATOR: [u8; 32] = [2; 32];

struct Node {
    store: Arc<ConsensusKeyStore>,
    custody: PqConsensusCustody,
}
fn node(seed: u8, expire_at: u32) -> Node {
    let store = Arc::new(ConsensusKeyStore::from_seed(&[seed; 32], expire_at).unwrap());
    let mut custody = PqConsensusCustody::default();
    custody.install(UInt256::from(VALIDATOR), store.clone(), 0, expire_at).unwrap();
    Node { store, custody }
}
fn unix_now() -> u32 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32
}
fn runtime_on(
    store: &ConsensusKeyStore,
    shard: ShardIdent,
    key_seqno: u32,
) -> Arc<AuthenticatedSessionRuntime> {
    let (mut nodes, keys) = crate::pq_fixture::members();
    nodes[1] = crate::SimplexSessionNode::from_descriptor(&super::tests::custody_descriptor(store))
        .unwrap();
    let members = nodes.iter().map(|node| node.descriptor.clone().unwrap()).collect();
    // With new catchain ids the key epoch enters the session identity, so a
    // later key epoch is a distinct (next-set) session.
    runtime_with_members_at_key(members, keys[1].clone(), shard, key_seqno, true).0
}
fn runtime(store: &ConsensusKeyStore) -> Arc<AuthenticatedSessionRuntime> {
    runtime_on(store, ShardIdent::masterchain(), 0)
}
fn signer(node: &Node, runtime: &AuthenticatedSessionRuntime) -> SessionSigner {
    SessionSigner::from_custody_match(
        &node.custody,
        &UInt256::from(VALIDATOR),
        &runtime.committee()[1],
        unix_now(),
    )
    .unwrap()
}
fn open_db(path: &Path) -> SimplexDbPtr {
    crate::database::SimplexDb::open(path, "production").unwrap()
}
fn rows(db: &SimplexDbPtr) -> Vec<(Vec<u8>, Vec<u8>)> {
    db.storage.get_by_prefix(PREFIX.to_vec(), None).wait().unwrap()
}
fn header_text(db: &SimplexDbPtr) -> String {
    let rows = rows(db);
    let (_, header) = rows.iter().find(|(key, _)| key == HEADER).unwrap();
    String::from_utf8(header.clone()).unwrap()
}
fn identity(runtime: &AuthenticatedSessionRuntime) -> ValidatorIdentity {
    ValidatorIdentity::from_descriptor(&runtime.committee()[1]).unwrap()
}
/// A signature is checked by verifying it over the independently rebuilt
/// preimage under the descriptor key, never by comparing it with another
/// randomized signature.
fn assert_vote_verifies(
    runtime: &AuthenticatedSessionRuntime,
    vote: &Vote,
    signed: &simplex::vote::Vote,
) {
    let unsigned = utils::serialize_unsigned_vote(&utils::vote_to_tl_unsigned(vote).unwrap());
    let preimage = utils::create_data_to_sign(runtime.session_id(), &unsigned);
    let decision = vote_decision(vote).unwrap();
    let binding = SigningBinding::production(runtime).unwrap();
    assert_eq!(SigningCoordinator::preimage(&binding, &decision).unwrap(), preimage);
    assert_eq!(utils::serialize_unsigned_vote(&signed.vote), unsigned);
    identity(runtime).verify_simplex(&preimage, &signed.signature).unwrap();
    let mut forged = signed.signature.clone();
    forged[7] ^= 1;
    assert!(identity(runtime).verify_simplex(&preimage, &forged).is_err());
}

#[test]
fn production_signer_comes_only_from_the_exact_custody_match() {
    let held = node(0xd1, 0);
    let other = node(0xd2, 0);
    let runtime = runtime(&held.store);
    let now = unix_now();
    let member = &runtime.committee()[1];
    let validator = UInt256::from(VALIDATOR);
    let signer = SessionSigner::from_custody_match(&held.custody, &validator, member, now).unwrap();
    assert!(Arc::ptr_eq(signer.store(), &held.store));
    assert_eq!(signer.validator(), &validator);
    // Another held key, another validator identity, or no custody: no signer.
    assert!(SessionSigner::from_custody_match(&other.custody, &validator, member, now).is_err());
    assert!(SessionSigner::from_custody_match(&held.custody, &UInt256::from([3; 32]), member, now)
        .is_err());
    assert!(SessionSigner::from_custody_match(
        &PqConsensusCustody::default(),
        &validator,
        member,
        now
    )
    .is_err());
    // A signer selected for one descriptor cannot open a session whose local
    // member records another key, nor an observer session.
    let directory = TestDirectory::new();
    let db = open_db(&directory.path().join("ns"));
    assert!(signer
        .open(&runtime_on(&other.store, ShardIdent::masterchain(), 0), db.clone())
        .is_err());
    let (observer, _, _) = crate::authenticated_fixture::runtime(false);
    assert!(signer.open(&observer, db.clone()).is_err());
    assert!(rows(&db).is_empty(), "a refused open writes nothing");
    assert!(!db.get_path().join(OWNER_FILE).exists());
    db.close(None).unwrap();
}

#[test]
fn production_journal_binds_the_session_without_deadline_or_retirement() {
    let held = node(0xd3, unix_now() + 3600);
    let runtime = runtime(&held.store);
    let directory = TestDirectory::new();
    let db = open_db(&directory.path().join("ns"));
    let coordinator = signer(&held, &runtime).open(&runtime, db.clone()).unwrap();
    let before = held.store.consensus_signatures_produced();
    let signed = coordinator.vote(&vote("notarize")).unwrap();
    assert_eq!(held.store.consensus_signatures_produced(), before + 1);
    assert_vote_verifies(&runtime, &vote("notarize"), &signed);
    let header = header_text(&db);
    assert!(header.contains("\"schema\":4"), "{header}");
    assert!(!header.contains("expire_at") && !header.contains("retired"), "{header}");
    assert!(header.contains("\"generation\":1"));
    let binding = SigningBinding::production(&runtime).unwrap();
    assert_eq!(binding.session, *runtime.session_id().as_array());
    assert_eq!(binding.committee, *runtime.committee_digest().unwrap().as_array());
    assert_eq!(binding.local_adnl, Some(*runtime.local_adnl().data()));
    assert_eq!(binding.global_id, runtime.pin().global_id);
    // The ownership marker binds the same session and the namespace database.
    let owner = std::fs::read(db.get_path().join(OWNER_FILE)).unwrap();
    assert_eq!(owner, SigningCoordinator::ownership(&db, &binding).unwrap());
    drop(coordinator);
    db.close(None).unwrap();
}

#[test]
fn production_restart_replays_committed_bytes_without_signing() {
    let held = node(0xd4, 0);
    let runtime = runtime(&held.store);
    let directory = TestDirectory::new();
    let path = directory.path().join("ns");
    let db = open_db(&path);
    let first = signer(&held, &runtime).open(&runtime, db.clone()).unwrap();
    let signed = first.vote(&vote("notarize")).unwrap();
    drop(first);
    db.close(None).unwrap();
    drop(db);
    let db = open_db(&path);
    let count = held.store.consensus_signatures_produced();
    let again = signer(&held, &runtime).open(&runtime, db.clone()).unwrap();
    assert_eq!(again.vote(&vote("notarize")).unwrap(), signed, "committed bytes, not a re-sign");
    assert_eq!(held.store.consensus_signatures_produced(), count);
    // A conflicting decision for the same slot is still refused durably.
    assert!(again.vote(&vote("skip")).is_ok());
    assert!(again.vote(&vote("finalize")).is_err());
    drop(again);
    db.close(None).unwrap();
}

#[test]
fn production_namespace_initialization_recovers_from_every_crash_cut() {
    let held = node(0xd5, 0);
    let runtime = runtime(&held.store);
    for cut in ["owner_locked", "owner_partial", "owner_committed", "header_committed"] {
        let directory = TestDirectory::new();
        let db = open_db(&directory.path().join("ns"));
        let owner_path = db.get_path().join(OWNER_FILE);
        *NAMESPACE_CUT.lock().unwrap() = Some((db.get_path().to_path_buf(), cut));
        let crashed = signer(&held, &runtime).open(&runtime, db.clone());
        *NAMESPACE_CUT.lock().unwrap() = None;
        assert!(crashed.is_err(), "{cut}");
        let expected =
            SigningCoordinator::ownership(&db, &SigningBinding::production(&runtime).unwrap())
                .unwrap();
        let persisted = std::fs::read(&owner_path).unwrap();
        match cut {
            "owner_locked" => assert!(persisted.is_empty()),
            "owner_partial" => {
                assert!(!persisted.is_empty() && persisted.len() < expected.len());
                assert!(expected.starts_with(&persisted));
            }
            _ => assert_eq!(persisted, expected, "{cut}"),
        }
        assert_eq!(rows(&db).len(), usize::from(cut == "header_committed"), "{cut}");
        let recovered = signer(&held, &runtime).open(&runtime, db.clone()).unwrap();
        assert_eq!(std::fs::read(&owner_path).unwrap(), expected, "{cut}");
        let signed = recovered.vote(&vote("notarize")).unwrap();
        assert_vote_verifies(&runtime, &vote("notarize"), &signed);
        drop(recovered);
        let reopened = signer(&held, &runtime).open(&runtime, db.clone()).unwrap();
        assert_eq!(reopened.vote(&vote("notarize")).unwrap(), signed, "{cut}");
        drop(reopened);
        db.close(None).unwrap();
    }
}

#[test]
fn production_namespace_refuses_conflicting_or_incompatible_state_without_rewriting() {
    let held = node(0xd6, 0);
    let runtime = runtime(&held.store);
    let other_runtime = runtime_on(&held.store, ShardIdent::masterchain(), 1);
    assert_ne!(runtime.session_id(), other_runtime.session_id());
    let open = |db: &SimplexDbPtr| signer(&held, &runtime).open(&runtime, db.clone());
    let fresh = || {
        let directory = TestDirectory::new();
        let db = open_db(&directory.path().join("ns"));
        (directory, db)
    };
    let initialized = || {
        let (directory, db) = fresh();
        open(&db).unwrap().vote(&vote("notarize")).unwrap();
        (directory, db)
    };
    // A complete marker for another binding is never replaced, even with an
    // empty journal.
    {
        let (_directory, db) = fresh();
        let foreign = SigningCoordinator::ownership(
            &db,
            &SigningBinding::production(&other_runtime).unwrap(),
        )
        .unwrap();
        std::fs::write(db.get_path().join(OWNER_FILE), &foreign).unwrap();
        assert!(open(&db).is_err());
        assert_eq!(std::fs::read(db.get_path().join(OWNER_FILE)).unwrap(), foreign);
        assert!(rows(&db).is_empty());
        db.close(None).unwrap();
    }
    // A journal whose marker is missing or incomplete is refused, and no
    // marker is created or completed for it.
    for damage in ["missing", "partial"] {
        let (_directory, db) = initialized();
        let owner_path = db.get_path().join(OWNER_FILE);
        let complete = std::fs::read(&owner_path).unwrap();
        match damage {
            "missing" => std::fs::remove_file(&owner_path).unwrap(),
            _ => std::fs::write(&owner_path, &complete[..complete.len() / 2]).unwrap(),
        }
        let before = rows(&db);
        assert!(open(&db).is_err(), "{damage}");
        assert_eq!(rows(&db), before);
        match damage {
            "missing" => assert!(!owner_path.exists()),
            _ => assert_eq!(std::fs::read(&owner_path).unwrap(), &complete[..complete.len() / 2]),
        }
        db.close(None).unwrap();
    }
    // Records without a header.
    {
        let (_directory, db) = initialized();
        db.storage.erase(HEADER.to_vec(), None).wait().unwrap();
        let before = rows(&db);
        assert!(open(&db).is_err());
        assert_eq!(rows(&db), before);
        db.close(None).unwrap();
    }
    // A production header for another binding.
    {
        let (_directory, db) = initialized();
        let mut header: Header =
            decode(&rows(&db).into_iter().find(|(key, _)| key == HEADER).unwrap().1).unwrap();
        header.binding.global_id += 1;
        db.storage.set(HEADER.to_vec(), encode(&header).unwrap(), None).wait().unwrap();
        let before = rows(&db);
        assert!(open(&db).is_err());
        assert_eq!(rows(&db), before);
        db.close(None).unwrap();
    }
    // Schema-3 journals, active or retired, are not migrated or erased: with
    // no production marker the namespace is refused before anything is
    // created; beside a production marker the schema itself is refused.
    for (retired, marker) in [(false, false), (true, false), (false, true), (true, true)] {
        let (_directory, db) = fresh();
        let owner_path = db.get_path().join(OWNER_FILE);
        if marker {
            let production = SigningBinding::production(&runtime).unwrap();
            std::fs::write(&owner_path, SigningCoordinator::ownership(&db, &production).unwrap())
                .unwrap();
        }
        let mut header =
            Header::new(SigningBinding::from_authenticated_runtime(&runtime, 1, 0).unwrap());
        header.retired = Some(retired);
        db.storage.set(HEADER.to_vec(), encode(&header).unwrap(), None).wait().unwrap();
        let before = rows(&db);
        let marker_before = std::fs::read(&owner_path).ok();
        let refused = open(&db).err().unwrap().to_string();
        if marker {
            assert!(refused.contains("not the production schema"), "{refused}");
        }
        assert_eq!(rows(&db), before, "a schema-3 journal is left exactly as it was");
        assert_eq!(std::fs::read(&owner_path).ok(), marker_before);
        db.close(None).unwrap();
    }
}

#[test]
fn production_namespace_has_one_writer_and_concurrent_sessions_sign_independently() {
    let held = node(0xd7, 0);
    let directory = TestDirectory::new();
    // One namespace, two writers: the second is refused while the first lives.
    let runtime_mc = runtime(&held.store);
    let db = open_db(&directory.path().join("mc"));
    let first = signer(&held, &runtime_mc).open(&runtime_mc, db.clone()).unwrap();
    let duplicate = signer(&held, &runtime_mc).open(&runtime_mc, db.clone());
    assert!(duplicate.err().unwrap().to_string().contains("another writer"));
    let retained = first.clone();
    drop(first);
    assert!(
        signer(&held, &runtime_mc).open(&runtime_mc, db.clone()).is_err(),
        "ownership lasts as long as any holder of the coordinator"
    );
    drop(retained);
    let mc = signer(&held, &runtime_mc).open(&runtime_mc, db.clone()).unwrap();

    // Masterchain, shard and next-set sessions of one validator run at once,
    // each in its own namespace, sharing one custody store.
    let shard = ShardIdent::with_tagged_prefix(0, 0x8000_0000_0000_0000).unwrap();
    let runtime_shard = runtime_on(&held.store, shard, 0);
    let runtime_next = runtime_on(&held.store, ShardIdent::masterchain(), 1);
    let db_shard = open_db(&directory.path().join("shard"));
    let db_next = open_db(&directory.path().join("next"));
    let shard_signer =
        signer(&held, &runtime_shard).open(&runtime_shard, db_shard.clone()).unwrap();
    let next_signer = signer(&held, &runtime_next).open(&runtime_next, db_next.clone()).unwrap();
    let ids = [runtime_mc.session_id(), runtime_shard.session_id(), runtime_next.session_id()];
    assert!(ids[0] != ids[1] && ids[0] != ids[2] && ids[1] != ids[2], "three distinct sessions");
    let sessions = [
        (runtime_mc.clone(), mc.clone()),
        (runtime_shard.clone(), shard_signer.clone()),
        (runtime_next.clone(), next_signer.clone()),
    ];
    let before = held.store.consensus_signatures_produced();
    let signed: Vec<_> = std::thread::scope(|scope| {
        let handles: Vec<_> = sessions
            .iter()
            .map(|(_, coordinator)| scope.spawn(|| coordinator.vote(&vote("notarize")).unwrap()))
            .collect();
        handles.into_iter().map(|handle| handle.join().unwrap()).collect()
    });
    assert_eq!(held.store.consensus_signatures_produced(), before + 3);
    for ((runtime, _), signed) in sessions.iter().zip(&signed) {
        assert_vote_verifies(runtime, &vote("notarize"), signed);
    }
    drop((mc, shard_signer, next_signer, sessions));
    for db in [db, db_shard, db_next] {
        db.close(None).unwrap();
    }
}

#[test]
fn production_replay_signs_an_intent_once_and_drops_only_a_refused_one() {
    // Signed and intent-only records with a usable key.
    {
        let held = node(0xd8, 0);
        let runtime = runtime(&held.store);
        let directory = TestDirectory::new();
        let path = directory.path().join("ns");
        let db = open_db(&path);
        let coordinator = signer(&held, &runtime).open(&runtime, db.clone()).unwrap();
        let notarize = coordinator.vote(&vote("notarize")).unwrap();
        *coordinator.fail_at.lock().unwrap() = Some("after_intent");
        assert!(coordinator.vote(&vote("skip")).is_err());
        drop(coordinator);
        let local = crate::block::ValidatorIndex::new(1);
        let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut replayed = Vec::new();
        for round in 0..2 {
            let coordinator = signer(&held, &runtime).open(&runtime, db.clone()).unwrap();
            let mut bootstrap =
                db.load_pq_bootstrap_cancellable(&cancel, Duration::from_millis(10)).unwrap();
            let before = held.store.consensus_signatures_produced();
            coordinator.recover_bootstrap(&mut bootstrap, local).unwrap();
            assert_eq!(
                held.store.consensus_signatures_produced(),
                before + u64::from(round == 0),
                "only the intent-only record is signed, once"
            );
            let own: Vec<_> = bootstrap
                .votes
                .iter()
                .filter(|v| v.node_idx == local)
                .map(|v| v.data.clone())
                .collect();
            assert_eq!(own.len(), 2);
            let exact = rtos_api::serialize_boxed(&notarize.clone().into_boxed()).unwrap();
            assert!(own.iter().any(|bytes| bytes.as_slice() == exact.as_slice()));
            replayed.push(own);
            drop(coordinator);
        }
        assert_eq!(replayed[0], replayed[1], "the replayed intent is committed and reused");
        db.close(None).unwrap();
    }
    // A key that expires before the replay: committed bytes are still used as
    // stored, the unsigned intent is dropped, and the journal keeps working.
    {
        let held = node(0xd9, unix_now() + 2);
        let runtime = runtime(&held.store);
        let selected = signer(&held, &runtime);
        let directory = TestDirectory::new();
        let db = open_db(&directory.path().join("ns"));
        let coordinator = selected.open(&runtime, db.clone()).unwrap();
        let notarize = coordinator.vote(&vote("notarize")).unwrap();
        *coordinator.fail_at.lock().unwrap() = Some("after_intent");
        assert!(coordinator.vote(&vote("skip")).is_err());
        drop(coordinator);
        while !held.store.expired_now() {
            std::thread::sleep(Duration::from_millis(50));
        }
        let count = held.store.consensus_signatures_produced();
        // Opening checks no deadline: the store checks it around signing only.
        let coordinator = selected.open(&runtime, db.clone()).unwrap();
        let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut bootstrap =
            db.load_pq_bootstrap_cancellable(&cancel, Duration::from_millis(10)).unwrap();
        let local = crate::block::ValidatorIndex::new(1);
        coordinator.recover_bootstrap(&mut bootstrap, local).unwrap();
        let own: Vec<_> = bootstrap.votes.iter().filter(|v| v.node_idx == local).collect();
        assert_eq!(own.len(), 1, "the refused intent is not applied");
        assert_eq!(
            own[0].data.as_slice(),
            rtos_api::serialize_boxed(&notarize.clone().into_boxed()).unwrap().as_slice()
        );
        assert_eq!(held.store.consensus_signatures_produced(), count);
        assert!(
            !coordinator.state.lock().unwrap().poisoned,
            "a refused signature drops one decision"
        );
        // Committed bytes are released after the deadline; no new signature is.
        assert_eq!(coordinator.vote(&vote("notarize")).unwrap(), notarize);
        assert!(coordinator.vote(&vote("skip")).is_err());
        assert!(!coordinator.state.lock().unwrap().poisoned);
        assert_eq!(held.store.consensus_signatures_produced(), count);
        drop(coordinator);
        db.close(None).unwrap();
    }
}

#[test]
fn production_journal_adds_no_deadline_rule_of_its_own() {
    let held = node(0xda, unix_now() + 3600);
    let runtime = runtime(&held.store);
    let directory = TestDirectory::new();
    let db = open_db(&directory.path().join("ns"));
    let coordinator = signer(&held, &runtime).open(&runtime, db.clone()).unwrap();
    // Even with the coordinator's own clock far past the key's deadline, only
    // the store's deadline governs, and it has not passed.
    coordinator.test_time.store(u64::from(u32::MAX), std::sync::atomic::Ordering::SeqCst);
    let signed = coordinator.vote(&vote("notarize")).unwrap();
    assert_vote_verifies(&runtime, &vote("notarize"), &signed);
    drop(coordinator);
    db.close(None).unwrap();
}

const ROLLBACK_CHILD: &str = "RTOS_PRODUCTION_ROLLBACK_CHILD";
const ROLLBACK_SEED: u8 = 0xdb;

/// Retirement is process-global and never persisted, as in the reference: in
/// this process an expired key stays retired across stores, custody re-adds,
/// sessions and an earlier clock; a fresh process whose clock is earlier than
/// the deadline may sign again under the same journal.
#[test]
fn production_rollback_same_process_stays_retired_fresh_process_may_sign() {
    if std::env::var_os(ROLLBACK_CHILD).is_some() {
        return;
    }
    let held = node(ROLLBACK_SEED, unix_now() + 2);
    let runtime = runtime(&held.store);
    let selected = signer(&held, &runtime);
    let directory = TestDirectory::new();
    let path = directory.path().join("ns");
    let db = open_db(&path);
    let coordinator = selected.open(&runtime, db.clone()).unwrap();
    let notarize = coordinator.vote(&vote("notarize")).unwrap();
    while !held.store.expired_now() {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(coordinator.vote(&vote("skip")).is_err());
    drop(coordinator);
    // Same process: no new store, custody entry or session can sign again.
    assert!(ConsensusKeyStore::from_seed(&[ROLLBACK_SEED; 32], unix_now() + 3600).is_err());
    let mut readd = PqConsensusCustody::default();
    assert!(readd
        .install(UInt256::from(VALIDATOR), held.store.clone(), 0, held.store.expire_at())
        .is_err());
    assert!(SessionSigner::from_custody_match(
        &held.custody,
        &UInt256::from(VALIDATOR),
        &runtime.committee()[1],
        1
    )
    .is_err());
    let reopened = selected.open(&runtime, db.clone()).unwrap();
    assert!(reopened.vote(&vote("skip")).is_err(), "the store stays retired at any clock");
    drop(reopened);
    db.close(None).unwrap();
    drop(db);

    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "signing_coordinator::production_tests::production_rollback_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(ROLLBACK_CHILD, &path)
        .output()
        .unwrap();
    assert!(
        output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "fresh process: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let db = open_db(&path);
    let records: Vec<Record> = rows(&db)
        .into_iter()
        .filter(|(key, _)| key != HEADER)
        .map(|(_, value)| decode(&value).unwrap())
        .collect();
    assert!(records.iter().all(|record| record.signed.is_some()));
    assert!(
        records.iter().any(|record| record.decision.kind == 2),
        "the fresh process signed skip"
    );
    let stored = records.iter().find(|record| record.decision.kind == 0).unwrap();
    assert_eq!(
        stored.signed.as_deref(),
        Some(rtos_api::serialize_boxed(&notarize.into_boxed()).unwrap().as_slice()),
        "the fresh process kept the committed bytes"
    );
    db.close(None).unwrap();
}

#[test]
fn production_rollback_child() {
    let Some(path) = std::env::var_os(ROLLBACK_CHILD) else {
        return;
    };
    // A fresh process has no retirement record, and the key's window has not
    // closed by its clock (modelled by a later deadline for the same seed).
    let held = node(ROLLBACK_SEED, unix_now() + 3600);
    let runtime = runtime(&held.store);
    let db = open_db(Path::new(&path));
    let coordinator = signer(&held, &runtime).open(&runtime, db.clone()).unwrap();
    let skip = coordinator.vote(&vote("skip")).unwrap();
    assert_vote_verifies(&runtime, &vote("skip"), &skip);
    drop(coordinator);
    db.close(None).unwrap();
}
