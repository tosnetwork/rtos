// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use rtos_block::{UInt256, ValidatorDescr};
use rtos_pq_crypto::{verify, MAX_MESSAGE_BYTES};
use std::{cell::Cell, sync::Arc};

fn store(seed: u8, expiry: u32) -> Arc<ConsensusKeyStore> {
    Arc::new(ConsensusKeyStore::from_seed(&[seed; 32], expiry).unwrap())
}
fn validator() -> UInt256 {
    UInt256::from([1; 32])
}
fn descriptor(store: &ConsensusKeyStore) -> ValidatorDescr {
    ValidatorDescr::with_pq_params(
        validator(),
        store.consensus_key().clone(),
        1,
        UInt256::from([2; 32]),
    )
}

#[test]
fn keygen_matches_fixed_reference_public_kat_and_openssl_seed() {
    let kat: serde_json::Value =
        serde_json::from_str(include_str!("testdata/keygen.json")).unwrap();
    let key = ConsensusKeyStore::from_seed(&hex::decode(kat["seed"].as_str().unwrap()).unwrap(), 0)
        .unwrap();
    assert_eq!(
        key.consensus_key().public_key,
        hex::decode(kat["public_key"].as_str().unwrap()).unwrap()
    );
    let openssl: serde_json::Value =
        serde_json::from_str(include_str!("../../pq-crypto/tests/data/openssl-mldsa44.json"))
            .unwrap();
    let a = store(0x42, 0);
    assert_eq!(
        a.consensus_key().public_key,
        hex::decode(openssl["publicKeyHex"].as_str().unwrap()).unwrap()
    );
    assert_eq!(a.consensus_key(), store(0x42, 0).consensus_key());
    assert_ne!(a.consensus_key().key_id, store(0x43, 0).consensus_key().key_id);
    for n in [0, 31, 33] {
        assert!(
            matches!(ConsensusKeyStore::from_seed(&vec![0; n], 0), Err(Error::SeedLength(m)) if m == n)
        );
    }
}

#[test]
fn real_randomized_signatures_bind_each_consensus_surface() {
    let key = ConsensusKeyStore::generate(0).unwrap();
    let message = b"public consensus preimage";
    let signatures = [
        key.sign_consensus(message).unwrap(),
        key.sign_config_vote(message).unwrap(),
        key.sign_election(message).unwrap(),
    ];
    let contexts = [
        SIMPLEX_CONTEXT,
        CONFIG_VOTE_CONTEXT,
        ELECTION_CONTEXT,
        b"TOS-CONFIG-ADMIN-v1",
        b"tos.pq.wallet.v1",
        b"",
    ];
    for (i, signature) in signatures.iter().enumerate() {
        for (j, context) in contexts.iter().enumerate() {
            assert_eq!(
                verify(message, context, &signature.bytes, &key.consensus_key().public_key),
                Ok(i == j)
            );
        }
        assert_eq!(
            verify(
                b"another message",
                contexts[i],
                &signature.bytes,
                &key.consensus_key().public_key
            ),
            Ok(false)
        );
        let mut changed = signature.bytes;
        changed[0] ^= 1;
        assert_eq!(
            verify(message, contexts[i], &changed, &key.consensus_key().public_key),
            Ok(false)
        );
    }
    assert_eq!(key.consensus_signatures_produced(), 1);
    assert_ne!(signatures[0], key.sign_consensus(message).unwrap());
    assert_eq!(key.consensus_signatures_produced(), 2);
    for message in [vec![], vec![3; MAX_MESSAGE_BYTES]] {
        let signature = key.sign_consensus(&message).unwrap();
        assert_eq!(
            verify(&message, SIMPLEX_CONTEXT, &signature.bytes, &key.consensus_key().public_key),
            Ok(true)
        );
    }
    let count = key.consensus_signatures_produced();
    assert_eq!(key.sign_consensus(&vec![0; MAX_MESSAGE_BYTES + 1]), Err(Error::MessageTooLong));
    assert_eq!(key.consensus_signatures_produced(), count);
}

#[test]
fn deadline_crossed_inside_real_signing_discards_signature_and_retires_reload() {
    let key = store(81, 100);
    let calls = Cell::new(0);
    let clock = || {
        let before = calls.get();
        calls.set(before + 1);
        Some(if before == 0 { 99 } else { 100 })
    };
    assert_eq!(
        key.sign_within_deadline(
            b"cross expiry",
            SIMPLEX_CONTEXT,
            clock,
            crate::store::native_sign
        ),
        Err(Error::Expired)
    );
    assert_eq!(calls.get(), 2);
    assert!(key.retired());
    assert!(key.expired_at(1), "clock rollback must not revive a store");
    assert!(
        matches!(ConsensusKeyStore::from_seed(&[81; 32], 0), Err(Error::Retired)),
        "reloading without an expiry cannot revive an identity"
    );
    assert_eq!(key.signatures_refused_after_expiry(), 1);
    assert_eq!(key.consensus_signatures_produced(), 0);
}

#[test]
fn deadline_refuses_before_native_entry_and_every_public_surface() {
    let key = store(82, 100);
    let result = key.sign_within_deadline(
        b"expired",
        SIMPLEX_CONTEXT,
        || Some(100),
        |_, _, _| panic!("native signing must not run"),
    );
    assert_eq!(result, Err(Error::Expired));
    assert_eq!(key.sign_consensus(b"x"), Err(Error::Expired));
    assert_eq!(key.sign_election(b"x"), Err(Error::Expired));
    assert_eq!(key.sign_config_vote(b"x"), Err(Error::Expired));
    assert_eq!(key.signatures_refused_after_expiry(), 4);
    let negative_clock = store(83, 100);
    assert_eq!(
        negative_clock.sign_within_deadline(b"x", SIMPLEX_CONTEXT, || None, |_, _, _| panic!()),
        Err(Error::Expired)
    );
    let unlimited = store(84, 0);
    assert!(unlimited
        .sign_within_deadline(b"x", SIMPLEX_CONTEXT, || None, crate::store::native_sign)
        .is_ok());
}

#[test]
fn custody_matches_full_descriptor_and_not_stake_valid_from() {
    let key = store(91, 200);
    let mut custody = PqConsensusCustody::default();
    custody.install(validator(), key.clone(), 100, 200).unwrap();
    let original = descriptor(&key);
    assert!(
        Arc::ptr_eq(&key, &custody.get_matching_store(&validator(), &original, 1).unwrap()),
        "valid_from is only an election constraint"
    );
    let mut changed = original.clone();
    if let rtos_block::ValidatorKey::Pq(pq) = &mut changed.key {
        pq.public_key[0] ^= 1;
    }
    assert!(custody.get_matching_store(&validator(), &changed, 1).is_none());
    let mut changed = original.clone();
    if let rtos_block::ValidatorKey::Pq(pq) = &mut changed.key {
        pq.algorithm_id = 2;
    }
    assert!(custody.get_matching_store(&validator(), &changed, 1).is_none());
    let mut changed = original.clone();
    if let rtos_block::ValidatorKey::Pq(pq) = &mut changed.key {
        pq.key_id = UInt256::from([9; 32]);
    }
    assert!(custody.get_matching_store(&validator(), &changed, 1).is_none());
    assert!(custody.get_matching_store(&UInt256::from([5; 32]), &original, 1).is_none());
    assert!(custody.get_matching_store(&validator(), &ValidatorDescr::default(), 1).is_none());
    assert!(custody.get_matching_store(&validator(), &original, 200).is_none());
    custody.remove(&validator());
    assert_eq!(custody.install(validator(), key, 100, 200), Err(Error::Retired));
    assert!(matches!(ConsensusKeyStore::from_seed(&[91; 32], 0), Err(Error::Retired)));
}

#[test]
fn rotation_selects_descriptor_or_election_without_old_key_fallback() {
    let a = store(92, 0);
    let b = store(93, 300);
    let mut custody = PqConsensusCustody::default();
    custody.install(validator(), a.clone(), 0, 0).unwrap();
    custody.install(validator(), b.clone(), 100, 300).unwrap();
    assert!(Arc::ptr_eq(&a, &custody.select_stake_store(&validator(), 99, 1, None).unwrap()));
    assert!(Arc::ptr_eq(&b, &custody.select_stake_store(&validator(), 100, 1, None).unwrap()));
    assert!(custody
        .select_stake_store(&validator(), 100, 1, Some(a.consensus_key().key_id.as_array()))
        .is_err());
    assert!(custody.select_stake_store(&validator(), 300, 1, None).is_err());
    assert!(custody.select_stake_store(&validator(), 100, 300, None).is_err());
    assert!(
        custody.select_stake_store(&validator(), 100, 1, None).is_err(),
        "retired scheduled key cannot fall back after clock rollback"
    );
    assert!(custody.get_matching_store(&validator(), &descriptor(&a), 300).is_some());
    assert!(custody.get_matching_store(&validator(), &descriptor(&b), 1).is_none());
    custody.record_unloaded(validator(), 400, 500).unwrap();
    assert!(custody.select_stake_store(&validator(), 400, 600, None).is_err());
    assert!(
        custody.select_stake_store(&validator(), 400, 1, None).is_err(),
        "unloaded window must remain in the schedule"
    );
}

#[test]
fn schedule_validation_and_failed_install_leave_custody_unchanged() {
    let a = store(94, 0);
    let b = store(95, 0);
    let mut custody = PqConsensusCustody::default();
    assert_eq!(custody.install(validator(), a.clone(), 0, 3), Err(Error::DeadlineMismatch));
    custody.install(validator(), a.clone(), 0, 0).unwrap();
    assert!(custody.install(validator(), b.clone(), 0, 0).is_err());
    assert_eq!(custody.held_keys(&validator()).len(), 1);
    assert!(Arc::ptr_eq(&a, &custody.select_stake_store(&validator(), 0, 0, None).unwrap()));
    assert!(validate_windows(&[]).is_err());
    assert!(validate_windows(&[KeyWindow { key_id: None, valid_from: 5, expire_at: 5 }]).is_err());
    let windows: Vec<_> = (0..9)
        .map(|i| KeyWindow { key_id: Some([i; 32]), valid_from: u32::from(i), expire_at: 0 })
        .collect();
    assert!(validate_schedule(&windows[..8]).is_ok());
    assert!(validate_schedule(&windows).is_err());
    let mut duplicate = windows[..2].to_vec();
    duplicate[1].key_id = duplicate[0].key_id;
    assert!(validate_schedule(&duplicate).is_err());
    assert!(custody.install(UInt256::default(), b, 1, 0).is_err());
}

#[test]
fn removal_and_status_latch_expiry_and_keep_a_usable_key() {
    let a = store(96, 100);
    let b = store(97, 200);
    let mut custody = PqConsensusCustody::default();
    custody.install(validator(), a.clone(), 0, 100).unwrap();
    custody.install(validator(), b.clone(), 100, 200).unwrap();
    let set = [descriptor(&a)];
    let id = a.consensus_key().key_id.as_array();
    assert!(custody.removal_refusal(&validator(), id, 50, &[&set]).is_some());
    assert!(custody.report_expired(&validator(), Some(id), 100, 100));
    assert!(custody.report_expired(&validator(), Some(id), 100, 1));
    assert!(custody.removal_refusal(&validator(), id, 100, &[&set]).is_none());
    assert!(custody.removal_refusal(&validator(), id, 200, &[&set]).is_some());
    assert!(custody.usable_key_ids(&validator(), 1).is_empty());
}

#[cfg(unix)]
mod files {
    use super::*;
    use std::{
        ffi::CString,
        fs,
        os::unix::{
            ffi::OsStrExt,
            fs::{symlink, PermissionsExt},
        },
        path::Path,
    };
    fn seed(path: &Path, byte: u8) {
        fs::write(path, [byte; 32]).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[test]
    fn protected_seed_refuses_links_fifo_directory_permissions_and_lengths() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("consensus.seed");
        seed(&path, 101);
        assert_eq!(
            load_consensus_key(&path, 0).unwrap().consensus_key(),
            store(101, 0).consensus_key()
        );
        let link = dir.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(matches!(
            load_consensus_key(link, 0),
            Err(Error::KeyFile(KeyFileError::CannotOpen))
        ));
        let fifo = dir.path().join("fifo");
        let cpath = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
        assert!(matches!(
            load_consensus_key(fifo, 0),
            Err(Error::KeyFile(KeyFileError::NotRegular))
        ));
        assert!(matches!(
            load_consensus_key(dir.path(), 0),
            Err(Error::KeyFile(KeyFileError::WritableDirectory | KeyFileError::NotRegular))
        ));
        for mode in [0o604, 0o610, 0o620, 0o601] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            assert!(matches!(
                load_consensus_key(&path, 0),
                Err(Error::KeyFile(KeyFileError::GroupOrWorldAccess))
            ));
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o720)).unwrap();
        assert!(matches!(
            load_consensus_key(&path, 0),
            Err(Error::KeyFile(KeyFileError::WritableDirectory))
        ));
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        for size in [0, 31, 33, 64] {
            fs::write(&path, vec![0; size]).unwrap();
            assert!(matches!(
                load_consensus_key(&path, 0),
                Err(Error::KeyFile(KeyFileError::WrongSize))
            ));
        }
    }
    #[test]
    fn protected_seed_rejects_actual_wrong_owner() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("other-owner");
        let uid = unsafe { libc::geteuid() };
        let target = if uid == 0 {
            seed(&path, 103);
            let cpath = CString::new(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::chown(cpath.as_ptr(), 65534, 65534) }, 0);
            path.as_path()
        } else {
            // A public system file: rejection happens at fstat owner checking,
            // before any bytes are read or interpreted as a seed.
            Path::new("/etc/passwd")
        };
        assert_ne!(fs::metadata(target).unwrap().uid(), uid);
        assert!(matches!(
            load_consensus_key(target, 0),
            Err(Error::KeyFile(KeyFileError::WrongOwner))
        ));
    }

    #[test]
    fn configured_load_refuses_duplicate_paths_seeds_and_all_expired() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        seed(&a, 102);
        seed(&b, 102);
        let entry = ConfiguredKey { key_file: a.clone(), valid_from: 0, expire_at: 0 };
        let second = ConfiguredKey { key_file: b, valid_from: 100, expire_at: 0 };
        assert!(PqConsensusCustody::load(validator(), &[entry.clone(), second], 0).is_err());
        let duplicate = ConfiguredKey { valid_from: 100, ..entry.clone() };
        assert!(plan_key_load(&[entry.clone(), duplicate], 0).is_err());
        let expired = ConfiguredKey {
            key_file: dir.path().join("deleted-expired-seed"),
            valid_from: 100,
            expire_at: 200,
        };
        assert!(plan_key_load(&[expired.clone()], 200).is_err());
        let custody = PqConsensusCustody::load(validator(), &[entry, expired], 200).unwrap();
        assert!(custody.select_stake_store(&validator(), 150, 200, None).is_err());
        assert!(custody.select_stake_store(&validator(), 150, 1, None).is_err());
        assert_eq!(custody.held_keys(&validator()).len(), 1);
        assert!(PqConsensusCustody::load(
            validator(),
            &[ConfiguredKey {
                key_file: dir.path().join("missing-live"),
                valid_from: 0,
                expire_at: 0
            }],
            0
        )
        .is_err());
    }
}

/// Case tables ported from the reference node's membership and key-rotation
/// tests. Every check keeps the reference case name; a failing run lists them.
mod reference_cases {
    use super::*;
    use rtos_block::{SigPubKey, ValidatorKey};
    use std::collections::BTreeSet;

    struct Checks(Vec<&'static str>);
    impl Checks {
        fn new() -> Self {
            Self(Vec::new())
        }
        fn check(&mut self, name: &'static str, ok: bool) {
            if !ok {
                self.0.push(name);
            }
        }
        fn expect(&mut self, name: &'static str, got: (bool, bool), has: bool, member: bool) {
            self.check(name, got == (has, member));
        }
        fn finish(self) {
            assert!(self.0.is_empty(), "failed reference cases: {:?}", self.0);
        }
    }
    fn filled(byte: u8) -> UInt256 {
        let mut bytes = [0; 32];
        bytes[0] = byte;
        UInt256::from(bytes)
    }
    fn id_bytes(byte: u8) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[0] = byte;
        bytes
    }
    fn key_from(seed: u8, expire_at: u32) -> Arc<ConsensusKeyStore> {
        Arc::new(ConsensusKeyStore::from_seed(&[seed; 32], expire_at).unwrap())
    }
    fn key_id(store: &ConsensusKeyStore) -> [u8; 32] {
        *store.consensus_key().key_id.as_array()
    }
    fn pq_descriptor(id: &UInt256, store: &ConsensusKeyStore, addr: u8) -> ValidatorDescr {
        ValidatorDescr::with_pq_params(id.clone(), store.consensus_key().clone(), 1, filled(addr))
    }
    fn classical(byte: u8) -> ValidatorDescr {
        let mut bytes = [0; 32];
        bytes[0] = byte;
        ValidatorDescr::with_params(SigPubKey::with_bytes(bytes), 1, None)
    }
    fn none() -> BTreeSet<UInt256> {
        BTreeSet::new()
    }
    fn window(id: u8, valid_from: u32, expire_at: u32) -> KeyWindow {
        KeyWindow { key_id: Some(id_bytes(id)), valid_from, expire_at }
    }
    fn configured(path: &str, valid_from: u32, expire_at: u32) -> ConfiguredKey {
        ConfiguredKey { key_file: path.into(), valid_from, expire_at }
    }
    fn refused_with<T>(result: Result<T, Error>, phrase: &str) -> bool {
        matches!(result, Err(error) if error.to_string().contains(phrase))
    }
    /// A scripted wall clock: each reading takes the next value, the last repeats.
    fn scripted(values: &[u64]) -> impl Fn() -> Option<u64> + '_ {
        let next = Cell::new(0usize);
        move || {
            let index = next.get().min(values.len() - 1);
            next.set(next.get() + 1);
            Some(values[index])
        }
    }
    fn sign_at(store: &ConsensusKeyStore, values: &[u64]) -> bool {
        store.sign_consensus_with(b"scripted", scripted(values), crate::store::native_sign).is_ok()
    }
    fn sign_election_at(store: &ConsensusKeyStore, values: &[u64]) -> bool {
        store
            .sign_within_deadline(
                b"scripted",
                ELECTION_CONTEXT,
                scripted(values),
                crate::store::native_sign,
            )
            .is_ok()
    }
    fn index_of(result: Result<usize, Error>) -> i64 {
        result.map(|index| index as i64).unwrap_or(-1)
    }

    #[test]
    fn test_node_consensus_membership() {
        let mut c = Checks::new();
        let member = classical(0x11);
        let outsider = classical(0x22);
        let set = vec![member.clone()];
        let member_key = member.validator_id().unwrap();
        let outsider_key = outsider.validator_id().unwrap();
        let empty = PqConsensusCustody::default();
        const NOW: u32 = 1_000_000;

        let temp = BTreeSet::from([member_key.clone()]);
        c.expect(
            "member_temp_key_in_set",
            node_validator_membership(&set, &temp, &none(), &empty, NOW),
            true,
            true,
        );
        let temp = BTreeSet::from([outsider_key.clone()]);
        c.expect(
            "configured_non_member_not_in_set",
            node_validator_membership(&set, &temp, &none(), &empty, NOW),
            true,
            false,
        );
        c.expect(
            "no_local_keys_unknown",
            node_validator_membership(&set, &none(), &none(), &empty, NOW),
            false,
            false,
        );
        let perm = BTreeSet::from([member_key.clone()]);
        c.expect(
            "member_permanent_key_in_set",
            node_validator_membership(&set, &none(), &perm, &empty, NOW),
            true,
            true,
        );

        let held_store = key_from(0x01, 0);
        let other_store = key_from(0x02, 0);
        let pq_id = filled(0xa0);
        let held_key = key_id(&held_store);
        let pq_set = vec![pq_descriptor(&pq_id, &held_store, 0xc0)];

        let mut holding = PqConsensusCustody::default();
        c.check(
            "custody_install_accepts_a_key",
            holding.install(pq_id.clone(), held_store.clone(), 0, 0).is_ok(),
        );
        c.expect(
            "pq_custodied_key_is_member",
            node_validator_membership(&pq_set, &none(), &none(), &holding, NOW),
            true,
            true,
        );
        let mut stale = PqConsensusCustody::default();
        c.check(
            "custody_install_accepts_a_rotated_key",
            stale.install(pq_id.clone(), other_store.clone(), 0, 0).is_ok(),
        );
        c.expect(
            "pq_stale_key_is_not_member",
            node_validator_membership(&pq_set, &none(), &none(), &stale, NOW),
            true,
            false,
        );
        let every_ed25519 = BTreeSet::from([
            member_key.clone(),
            outsider_key.clone(),
            pq_id.clone(),
            UInt256::from(held_key),
        ]);
        c.expect(
            "ed25519_keys_alone_are_not_pq_membership",
            node_validator_membership(&pq_set, &every_ed25519, &every_ed25519, &empty, NOW),
            true,
            false,
        );
        // A store that failed to load cannot be offered: custody takes the store
        // itself. The nearest refusal is a store whose deadline is not its window.
        let mut absent = PqConsensusCustody::default();
        c.check(
            "absent_key_store_is_refused",
            absent.install(pq_id.clone(), held_store.clone(), 0, 1).is_err(),
        );
        c.check("refused_store_is_not_custodied", absent.is_empty());
        c.expect(
            "absent_key_store_is_not_membership",
            node_validator_membership(&pq_set, &none(), &none(), &absent, NOW),
            false,
            false,
        );
        let mut elsewhere = PqConsensusCustody::default();
        c.check(
            "custody_install_accepts_another_validators_key",
            elsewhere.install(filled(0xa9), held_store.clone(), 0, 0).is_ok(),
        );
        c.expect(
            "custody_of_another_validator_is_not_membership",
            node_validator_membership(&pq_set, &none(), &none(), &elsewhere, NOW),
            true,
            false,
        );

        let matched = pq_descriptor(&pq_id, &held_store, 0xc0);
        c.check(
            "matching_store_returns_the_held_store",
            holding
                .get_matching_store(&pq_id, &matched, NOW)
                .is_some_and(|s| Arc::ptr_eq(&s, &held_store)),
        );
        let other_id = pq_descriptor(&filled(0xb0), &held_store, 0xc0);
        c.check(
            "matching_store_refuses_a_validator_id_mismatch",
            holding.get_matching_store(&pq_id, &other_id, NOW).is_none(),
        );
        let rotated = pq_descriptor(&pq_id, &other_store, 0xc0);
        c.check(
            "matching_store_refuses_a_key_id_mismatch",
            holding.get_matching_store(&pq_id, &rotated, NOW).is_none(),
        );
        let mut tampered = matched.clone();
        if let ValidatorKey::Pq(key) = &mut tampered.key {
            key.public_key[0] ^= 1;
        }
        c.check(
            "matching_store_refuses_a_public_key_mismatch",
            holding.get_matching_store(&pq_id, &tampered, NOW).is_none(),
        );
        let mut wrong_algo = matched.clone();
        if let ValidatorKey::Pq(key) = &mut wrong_algo.key {
            key.algorithm_id = 2;
        }
        c.check(
            "matching_store_refuses_a_wrong_algorithm",
            holding.get_matching_store(&pq_id, &wrong_algo, NOW).is_none(),
        );
        c.check(
            "matching_store_refuses_a_classical_descriptor",
            holding.get_matching_store(&pq_id, &member, NOW).is_none(),
        );
        c.check(
            "matching_store_refuses_when_nothing_is_custodied",
            empty.get_matching_store(&pq_id, &matched, NOW).is_none(),
        );
        // Membership stays generic: a classical member of a mixed set is still
        // reported. Refusing such a set a group is the admission check's job.
        let mixed = vec![member.clone(), matched.clone()];
        c.check(
            "classical_member_of_a_mixed_set_is_reported",
            local_consensus_member(
                &mixed,
                &BTreeSet::from([member_key.clone()]),
                &none(),
                &empty,
                NOW,
            ) == Some(member_key.clone()),
        );
        c.check(
            "pq_member_of_a_mixed_set_is_reported",
            local_consensus_member(&mixed, &none(), &none(), &holding, NOW) == Some(pq_id.clone()),
        );
        c.check(
            "classical_descriptor_by_its_own_key_only",
            local_consensus_descriptor(
                &member,
                &BTreeSet::from([member_key]),
                &none(),
                &holding,
                NOW,
            ) && !local_consensus_descriptor(&member, &none(), &none(), &holding, NOW),
        );
        c.finish();
    }

    #[test]
    fn schedule_checks() {
        let mut c = Checks::new();
        c.check("schedule_refuses_no_key", refused_with(validate_windows(&[]), "no consensus key"));
        let mut nine: Vec<_> = (0..9).map(|i| window(i, u32::from(i) * 100, 0)).collect();
        c.check(
            "schedule_refuses_more_than_the_capacity",
            refused_with(validate_windows(&nine), "at most 8"),
        );
        nine.pop();
        c.check("schedule_accepts_exactly_the_capacity", validate_schedule(&nine).is_ok());
        c.check(
            "schedule_refuses_a_window_that_closes_before_it_opens",
            refused_with(validate_windows(&[window(1, 100, 100)]), "not after its window"),
        );
        c.check(
            "schedule_refuses_two_keys_from_one_election",
            refused_with(
                validate_windows(&[window(1, 0, 0), window(2, 0, 0)]),
                "same election date",
            ),
        );
        c.check(
            "schedule_refuses_one_key_twice",
            refused_with(
                validate_schedule(&[window(1, 0, 0), window(1, 100, 0)]),
                "configured twice",
            ),
        );
        c.check(
            "schedule_accepts_a_rotation",
            validate_schedule(&[window(1, 0, 0), window(2, 1000, 0)]).is_ok(),
        );

        c.check(
            "load_refuses_an_empty_file_name",
            refused_with(plan_key_load(&[configured("", 0, 0)], 10), "no key file"),
        );
        c.check(
            "load_refuses_a_repeated_file",
            refused_with(
                plan_key_load(&[configured("/k/a", 0, 0), configured("/k/a", 100, 0)], 10),
                "configured twice",
            ),
        );
        c.check(
            "load_refuses_when_every_key_expired",
            refused_with(
                plan_key_load(&[configured("/k/a", 0, 50), configured("/k/b", 60, 70)], 100),
                "every configured",
            ),
        );
        c.check(
            "load_refuses_an_ambiguous_schedule",
            refused_with(
                plan_key_load(&[configured("/k/a", 5, 0), configured("/k/b", 5, 0)], 1),
                "same election date",
            ),
        );
        // The reference order: a repeated path is refused before an ambiguous window.
        c.check(
            "load_refuses_a_repeated_file_before_its_windows",
            refused_with(
                plan_key_load(&[configured("/k/a", 5, 0), configured("/k/a", 5, 0)], 1),
                "configured twice",
            ),
        );
        c.check(
            "load_skips_an_expired_key",
            plan_key_load(&[configured("/k/a", 0, 50), configured("/k/b", 40, 0)], 100)
                == Ok(vec![1]),
        );
        c.check(
            "load_keeps_a_single_unbounded_key",
            plan_key_load(&[configured("/k/a", 0, 0)], 4_000_000_000).map(|v| v.len()) == Ok(1),
        );

        let one = [window(1, 0, 0)];
        c.check(
            "single_key_signs_any_election",
            index_of(select_stake_key(&one, 0, 5, None)) == 0
                && index_of(select_stake_key(&one, 4_000_000_000, 5, None)) == 0,
        );
        let ab = [window(0xa, 0, 0), window(0xb, 1000, 0)];
        c.check(
            "before_the_successor_window_the_old_key_signs",
            index_of(select_stake_key(&ab, 999, 5, None)) == 0,
        );
        c.check(
            "from_the_successor_window_the_successor_signs",
            index_of(select_stake_key(&ab, 1000, 5, None)) == 1,
        );
        c.check(
            "later_elections_stay_with_the_successor",
            index_of(select_stake_key(&ab, 9000, 5, None)) == 1,
        );
        let ba = [window(0xb, 1000, 0), window(0xa, 0, 0)];
        c.check(
            "listing_order_decides_nothing",
            index_of(select_stake_key(&ba, 1000, 5, None)) == 0
                && index_of(select_stake_key(&ba, 999, 5, None)) == 1,
        );
        let (a, b, unknown) = (id_bytes(0xa), id_bytes(0xb), id_bytes(0xc));
        c.check(
            "naming_the_scheduled_key_signs_with_it",
            index_of(select_stake_key(&ab, 9000, 5, Some(&b))) == 1
                && index_of(select_stake_key(&ab, 999, 5, Some(&a))) == 0,
        );
        c.check(
            "naming_another_held_key_is_refused_with_the_scheduled_key",
            select_stake_key(&ab, 9000, 5, Some(&a)) == Err(Error::UnexpectedScheduledKey),
        );
        c.check(
            "naming_a_key_before_its_window_is_refused",
            select_stake_key(&ab, 999, 5, Some(&b)) == Err(Error::UnexpectedScheduledKey),
        );
        c.check(
            "naming_an_unheld_key_is_refused",
            select_stake_key(&ab, 9000, 5, Some(&unknown)) == Err(Error::UnexpectedScheduledKey),
        );
        c.check(
            "no_key_covers_an_election_before_every_window",
            select_stake_key(&[window(1, 500, 0)], 499, 5, None) == Err(Error::NoScheduledKey),
        );
        let b_expired = [window(0xa, 0, 0), window(0xb, 1000, 2000)];
        c.check(
            "an_expired_scheduled_key_is_refused_not_replaced",
            select_stake_key(&b_expired, 9000, 2500, None) == Err(Error::UnavailableScheduledKey),
        );
        c.check(
            "a_named_expired_key_is_refused",
            select_stake_key(&b_expired, 1500, 2500, Some(&b))
                == Err(Error::UnavailableScheduledKey),
        );
        c.check(
            "a_key_expiring_by_the_election_is_refused",
            select_stake_key(&b_expired, 2000, 1500, None) == Err(Error::UnavailableScheduledKey),
        );
        c.check(
            "an_unexpired_key_before_its_expiry_signs",
            index_of(select_stake_key(&b_expired, 1500, 1200, None)) == 1,
        );
        c.finish();
    }

    #[test]
    fn custody_checks() {
        let mut c = Checks::new();
        let key_a = key_from(0x0a, 0);
        let key_b = key_from(0x0b, 0);
        let key_c = key_from(0x0c, 0);
        let (id_a, id_b) = (key_id(&key_a), key_id(&key_b));
        let validator_id = filled(0x51);
        const NOW: u32 = 1_000_000;

        let mut custody = PqConsensusCustody::default();
        c.check(
            "custody_holds_the_old_key",
            custody.install(validator_id.clone(), key_a.clone(), 0, 0).is_ok(),
        );
        c.check(
            "custody_holds_the_successor_beside_it",
            custody.install(validator_id.clone(), key_b.clone(), NOW + 100, 0).is_ok(),
        );
        c.check(
            "custody_holds_both",
            custody.holds(&validator_id, &id_a, NOW)
                && custody.holds(&validator_id, &id_b, NOW)
                && custody.usable_key_ids(&validator_id, NOW).len() == 2,
        );
        c.check(
            "custody_refuses_an_ambiguous_window",
            custody.install(validator_id.clone(), key_c.clone(), NOW + 100, 0).is_err()
                && custody.held_keys(&validator_id).len() == 2,
        );
        c.check(
            "custody_refuses_an_absent_store",
            custody.install(validator_id.clone(), key_c.clone(), 7, 1).is_err(),
        );
        c.check(
            "custody_reinstall_replaces_the_window",
            custody.install(validator_id.clone(), key_b.clone(), NOW + 200, 0).is_ok()
                && custody.held_keys(&validator_id).len() == 2
                && custody.held_keys(&validator_id)[&id_b].valid_from == NOW + 200,
        );

        let set_with_a = vec![
            pq_descriptor(&validator_id, &key_a, 0xc0),
            pq_descriptor(&filled(0x52), &key_c, 0xc1),
        ];
        c.check(
            "a_set_listing_a_counts_the_node_as_its_member",
            node_validator_membership(&set_with_a, &none(), &none(), &custody, NOW).1,
        );
        c.check(
            "the_group_for_a_set_listing_a_signs_with_a",
            custody
                .get_matching_store(&validator_id, &set_with_a[0], NOW)
                .is_some_and(|s| Arc::ptr_eq(&s, &key_a)),
        );
        let vote_signer = pq_signer_for_set(&set_with_a, &validator_id, &custody, NOW);
        c.check(
            "a_vote_counted_by_a_set_listing_a_is_signed_with_a",
            vote_signer.as_ref().is_ok_and(|s| Arc::ptr_eq(&s.signer, &key_a) && s.index == 0),
        );
        let election = NOW + 300;
        let stake_signer = custody.select_stake_store(&validator_id, election, NOW, None);
        c.check(
            "the_stake_for_the_next_election_is_signed_with_b",
            stake_signer.as_ref().is_ok_and(|s| Arc::ptr_eq(s, &key_b)),
        );
        if let Ok(signer) = &stake_signer {
            // The stake preimage is built by the election caller; what custody
            // decides is which key signs it under the election context.
            let preimage = b"stake authorization preimage";
            let signed = signer.sign_election(preimage);
            c.check("the_stake_signature_is_made", signed.is_ok());
            if let Ok(signed) = signed {
                c.check("the_stake_names_key_b", key_id(signer) == id_b);
                c.check(
                    "the_stake_verifies_under_b",
                    verify(
                        preimage,
                        ELECTION_CONTEXT,
                        &signed.bytes,
                        &key_b.consensus_key().public_key,
                    ) == Ok(true),
                );
                c.check(
                    "the_stake_does_not_verify_under_a",
                    verify(
                        preimage,
                        ELECTION_CONTEXT,
                        &signed.bytes,
                        &key_a.consensus_key().public_key,
                    ) == Ok(false),
                );
            }
        }
        c.check(
            "naming_a_for_bs_election_is_refused",
            custody.select_stake_store(&validator_id, election, NOW, Some(&id_a)).err()
                == Some(Error::UnexpectedScheduledKey),
        );
        c.check(
            "naming_b_for_its_election_signs_with_b",
            custody
                .select_stake_store(&validator_id, election, NOW, Some(&id_b))
                .is_ok_and(|s| Arc::ptr_eq(&s, &key_b)),
        );
        c.check(
            "the_stake_before_bs_window_is_signed_with_a",
            custody
                .select_stake_store(&validator_id, NOW, NOW, None)
                .is_ok_and(|s| Arc::ptr_eq(&s, &key_a)),
        );
        let set_with_b = vec![pq_descriptor(&validator_id, &key_b, 0xc0)];
        c.check(
            "the_group_for_a_set_listing_b_signs_with_b",
            custody
                .get_matching_store(&validator_id, &set_with_b[0], NOW)
                .is_some_and(|s| Arc::ptr_eq(&s, &key_b)),
        );
        // valid_from schedules stakes only: B's window opens at NOW + 200, yet a
        // set that already lists B gets B as its signer and counts us a member.
        c.check(
            "a_set_listing_a_key_before_its_valid_from_signs_with_it",
            custody.held_keys(&validator_id)[&id_b].valid_from > NOW
                && pq_signer_for_set(&set_with_b, &validator_id, &custody, NOW)
                    .is_ok_and(|s| Arc::ptr_eq(&s.signer, &key_b))
                && node_validator_membership(&set_with_b, &none(), &none(), &custody, NOW).1,
        );

        let mut only_b = PqConsensusCustody::default();
        c.check(
            "custody_of_b_alone",
            only_b.install(validator_id.clone(), key_b.clone(), 0, 0).is_ok(),
        );
        c.check(
            "a_set_listing_an_unheld_key_gets_no_group_signer",
            only_b.get_matching_store(&validator_id, &set_with_a[0], NOW).is_none(),
        );
        c.check(
            "a_set_listing_an_unheld_key_gets_no_vote_signer",
            only_b.get_matching_store(&validator_id, &set_with_a[0], NOW).is_none()
                && pq_signer_for_set(&set_with_a, &validator_id, &only_b, NOW)
                    .err()
                    .is_some_and(|e| matches!(e, Error::UnheldSetKey(id) if id == id_a)),
        );
        c.check(
            "a_set_listing_an_unheld_key_is_not_membership",
            !node_validator_membership(&set_with_a, &none(), &none(), &only_b, NOW).1,
        );
        c.check(
            "a_set_not_naming_the_validator_gets_no_vote_signer",
            pq_signer_for_set(&set_with_a, &filled(0x53), &custody, NOW).err()
                == Some(Error::NotSetValidator),
        );

        {
            let mut expiring = PqConsensusCustody::default();
            c.check(
                "custody_refuses_a_store_without_the_windows_deadline",
                expiring.install(validator_id.clone(), key_from(0x3a, 0), 0, NOW).is_err()
                    && expiring.is_empty(),
            );
            let key_x = key_from(0x3a, NOW);
            let key_y = key_from(0x3b, 0);
            let id_x = key_id(&key_x);
            let set_with_x = vec![pq_descriptor(&validator_id, &key_x, 0xc0)];
            c.check(
                "custody_of_an_expiring_x",
                expiring.install(validator_id.clone(), key_x.clone(), 0, NOW).is_ok(),
            );
            c.check(
                "custody_of_y_beside_it",
                expiring.install(validator_id.clone(), key_y, 10, 0).is_ok(),
            );
            c.check(
                "an_unexpired_key_still_signs",
                expiring
                    .get_matching_store(&validator_id, &set_with_x[0], NOW - 1)
                    .is_some_and(|s| Arc::ptr_eq(&s, &key_x)),
            );
            c.check(
                "an_expired_key_signs_no_group",
                expiring.get_matching_store(&validator_id, &set_with_x[0], NOW).is_none(),
            );
            c.check(
                "an_expired_key_is_not_held_for_use",
                !expiring.holds(&validator_id, &id_x, NOW)
                    && expiring.usable_key_ids(&validator_id, NOW).len() == 1,
            );
            c.check(
                "an_expired_key_is_not_membership",
                !node_validator_membership(&set_with_x, &none(), &none(), &expiring, NOW).1,
            );
            c.check(
                "an_expired_key_signs_no_vote",
                pq_signer_for_set(&set_with_x, &validator_id, &expiring, NOW).is_err(),
            );
            c.check(
                "an_expired_key_signs_no_named_stake",
                expiring.select_stake_store(&validator_id, 5, NOW, Some(&id_x)).is_err(),
            );
            c.check(
                "an_expired_key_is_still_listed_for_removal",
                expiring.held_keys(&validator_id).contains_key(&id_x),
            );
            c.check(
                "custody_observation_retires_the_identity",
                key_x.retired() && consensus_key_retired(&id_x),
            );
            c.check(
                "an_expired_key_stays_expired_when_asked_with_an_earlier_time",
                expiring.get_matching_store(&validator_id, &set_with_x[0], NOW - 1).is_none()
                    && !expiring.holds(&validator_id, &id_x, NOW - 1),
            );
        }

        let mut restarted = PqConsensusCustody::default();
        c.check(
            "restart_holds_a",
            restarted.install(validator_id.clone(), key_a.clone(), 0, 0).is_ok(),
        );
        c.check(
            "restart_records_the_expired_successor",
            restarted.record_unloaded(validator_id.clone(), 1, 2).is_ok(),
        );
        c.check(
            "restart_refuses_the_stake_the_expired_successor_was_scheduled_for",
            restarted.select_stake_store(&validator_id, 2_000_000_000, NOW, None).is_err(),
        );
        c.check(
            "restart_still_signs_an_election_before_the_successor_with_a",
            restarted
                .select_stake_store(&validator_id, 0, NOW, None)
                .is_ok_and(|s| Arc::ptr_eq(&s, &key_a)),
        );
        c.check(
            "restart_refuses_an_unloaded_window_that_repeats_a_date",
            restarted.record_unloaded(validator_id.clone(), 1, 5).is_err()
                && restarted.install(validator_id.clone(), key_c.clone(), 1, 0).is_err(),
        );
        c.check(
            "restart_refuses_a_zero_key_id_request",
            restarted
                .select_stake_store(&validator_id, 2_000_000_000, NOW, Some(&[0; 32]))
                .is_err(),
        );

        {
            let mut crossing = PqConsensusCustody::default();
            let key_p = key_from(0x3c, 0);
            let key_q = key_from(0x3d, 100);
            let (id_p, id_q) = (key_id(&key_p), key_id(&key_q));
            c.check(
                "crossing_holds_p",
                crossing.install(validator_id.clone(), key_p.clone(), 0, 0).is_ok(),
            );
            c.check(
                "crossing_holds_q_until_100",
                crossing.install(validator_id.clone(), key_q, 50, 100).is_ok(),
            );
            let listing_p = [pq_descriptor(&validator_id, &key_p, 0xc0)];
            c.check(
                "removal_of_a_listed_key_is_refused",
                crossing.removal_refusal(&validator_id, &id_p, 99, &[&listing_p]).is_some(),
            );
            c.check(
                "removal_of_p_admitted_while_q_is_usable",
                crossing.removal_refusal(&validator_id, &id_p, 99, &[]).is_none(),
            );
            c.check(
                "removal_of_p_refused_once_q_expired",
                crossing.removal_refusal(&validator_id, &id_p, 100, &[])
                    == Some("removal would leave no usable consensus key"),
            );
            c.check(
                "removal_of_expired_q_is_admitted",
                crossing.removal_refusal(&validator_id, &id_q, 100, &[]).is_none(),
            );
            c.check(
                "removal_of_p_still_refused_at_99_once_q_was_seen_expired",
                crossing.removal_refusal(&validator_id, &id_p, 99, &[]).is_some(),
            );
            c.check(
                "removal_of_an_absent_key_is_refused",
                crossing.removal_refusal(&validator_id, &key_id(&key_c), 99, &[]).is_some(),
            );
        }

        c.check(
            "removing_a_key_keeps_the_other",
            custody.remove_key(&validator_id, &id_a)
                && !custody.holds(&validator_id, &id_a, NOW)
                && custody.holds(&validator_id, &id_b, NOW),
        );
        c.check("removing_an_absent_key_reports_it", !custody.remove_key(&validator_id, &id_a));
        c.check(
            "removing_the_last_key_empties_custody",
            custody.remove_key(&validator_id, &id_b) && custody.is_empty(),
        );
        c.finish();
    }

    #[test]
    fn deadline_checks() {
        let mut c = Checks::new();
        let unix_now = || {
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
                as u32
        };
        let now = unix_now();
        let store = key_from(0x0d, now + 2);
        c.check("deadline_boundary_before", !store.expired_at(u64::from(now + 1)));
        // Observing the boundary retires the identity, so ask a twin with the same
        // deadline rather than the store the signing cases below still need.
        let twin = key_from(0x1d, now + 2);
        c.check(
            "deadline_boundary_at",
            twin.expired_at(u64::from(now + 2)) && twin.expired_at(u64::from(now + 3)),
        );
        c.check(
            "deadline_signs_before_it",
            store.sign_consensus(b"before").is_ok()
                && store.sign_config_vote(b"before").is_ok()
                && store.sign_election(b"before").is_ok(),
        );
        c.check("deadline_refused_nothing_before_it", store.signatures_refused_after_expiry() == 0);
        while unix_now() < now + 2 {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        c.check("deadline_is_reached", store.expired_now());
        c.check("deadline_refuses_a_consensus_signature", store.sign_consensus(b"after").is_err());
        c.check("deadline_refuses_a_config_vote", store.sign_config_vote(b"after").is_err());
        c.check("deadline_refuses_an_election_signature", store.sign_election(b"after").is_err());
        c.check("deadline_counts_each_refusal", store.signatures_refused_after_expiry() == 3);
        c.check("deadline_refuses_a_stake", store.sign_election(b"stake").is_err());
        let moved = Arc::try_unwrap(store).ok().unwrap();
        c.check(
            "deadline_survives_a_move",
            moved.expired_now() && moved.sign_consensus(b"moved").is_err(),
        );
        let unbounded = key_from(0x0e, 0);
        c.check(
            "no_deadline_signs",
            !unbounded.expired_now() && unbounded.sign_consensus(b"x").is_ok(),
        );

        let crossing = key_from(0x0f, 105);
        c.check(
            "a_signature_finishing_after_the_deadline_is_discarded",
            !sign_at(&crossing, &[104, 106]),
        );
        c.check("a_discarded_signature_retires_the_key", crossing.retired());
        c.check(
            "a_clock_stepped_back_does_not_revive_the_key",
            !sign_at(&crossing, &[104])
                && !sign_election_at(&crossing, &[104])
                && crossing.expired_with_clock(|| Some(104)),
        );
        let stepped = key_from(0x10, 105);
        c.check("refused_at_106", !sign_at(&stepped, &[106]));
        c.check("still_refused_after_the_clock_goes_back_to_104", !sign_at(&stepped, &[104]));
        let fresh = key_from(0x11, 105);
        c.check(
            "a_key_never_seen_expired_signs_at_104",
            sign_at(&fresh, &[104]) && !fresh.retired(),
        );

        {
            let validator_id = filled(0x71);
            let key_a = key_from(0x21, 0);
            let key_b = key_from(0x22, 100);
            let mut custody = PqConsensusCustody::default();
            c.check(
                "latch_custody_holds_a",
                custody.install(validator_id.clone(), key_a.clone(), 0, 0).is_ok(),
            );
            c.check(
                "latch_custody_holds_b",
                custody.install(validator_id.clone(), key_b.clone(), 50, 100).is_ok(),
            );
            c.check("latch_b_refused_at_100", !sign_at(&key_b, &[100]));
            c.check(
                "removing_a_is_refused_while_b_is_retired_though_the_clock_says_99",
                custody.removal_refusal(&validator_id, &key_id(&key_a), 99, &[])
                    == Some("removal would leave no usable consensus key"),
            );
            c.check(
                "a_retired_key_is_not_held_for_use_at_99",
                !custody.holds(&validator_id, &key_id(&key_b), 99),
            );
        }
        {
            let validator_id = filled(0x72);
            let key_d = key_from(0x23, 105);
            let key_e = key_from(0x24, 0);
            let mut custody = PqConsensusCustody::default();
            c.check(
                "readd_custody_holds_e",
                custody.install(validator_id.clone(), key_e, 0, 0).is_ok(),
            );
            c.check(
                "readd_custody_holds_d",
                custody.install(validator_id.clone(), key_d.clone(), 50, 105).is_ok(),
            );
            c.check("readd_d_refused_at_106", !sign_at(&key_d, &[106]));
            c.check("readd_d_removed", custody.remove_key(&validator_id, &key_id(&key_d)));
            // A store of a retired identity cannot even be built here; the
            // reference builds one that then signs nothing. Either way it is inert.
            c.check(
                "a_new_store_from_the_same_seed_signs_nothing_at_104",
                matches!(ConsensusKeyStore::from_seed(&[0x23; 32], 105), Err(Error::Retired))
                    && key_d.retired()
                    && !sign_at(&key_d, &[104]),
            );
            c.check(
                "a_retired_key_cannot_be_held_again",
                custody.install(validator_id.clone(), key_d.clone(), 50, 105)
                    == Err(Error::Retired),
            );
        }
        c.finish();
    }

    #[test]
    fn registry_checks() {
        let mut c = Checks::new();
        {
            let validator_id = filled(0x81);
            let r0 = key_from(0x40, 0);
            let r1 = key_from(0x41, 100);
            let id_r1 = key_id(&r1);
            let mut custody = PqConsensusCustody::default();
            c.check(
                "observe_holds_r0",
                custody.install(validator_id.clone(), r0.clone(), 0, 0).is_ok(),
            );
            c.check(
                "observe_holds_r1",
                custody.install(validator_id.clone(), r1.clone(), 50, 100).is_ok(),
            );
            c.check(
                "observe_custody_sees_r1_expired_at_100",
                !custody.holds(&validator_id, &id_r1, 100),
            );
            c.check("observe_r1_removed", custody.remove_key(&validator_id, &id_r1));
            c.check(
                "observe_readding_r1_at_99_is_refused",
                custody.install(validator_id.clone(), r1.clone(), 50, 100).is_err(),
            );
            c.check(
                "observe_readding_r1_with_no_expiry_is_refused",
                ConsensusKeyStore::from_seed(&[0x41; 32], 0).is_err(),
            );
            c.check("observe_a_new_r1_store_signs_nothing_at_99", !sign_at(&r1, &[99]));
            c.check(
                "retiring_one_key_leaves_the_other",
                !r0.retired()
                    && r0.sign_consensus(b"r0").is_ok()
                    && custody.holds(&validator_id, &key_id(&r0), 99),
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempfile::tempdir().unwrap();
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let (first, second) = (dir.path().join("first.seed"), dir.path().join("second.seed"));
            for path in [&first, &second] {
                std::fs::write(path, [0x44; 32]).unwrap();
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            let a = load_consensus_key(&first, 100);
            let b = load_consensus_key(&second, 100);
            c.check("path_two_files_load", a.is_ok() && b.is_ok());
            if let (Ok(a), Ok(b)) = (a, b) {
                let (from_first, from_second) = (Arc::new(a), Arc::new(b));
                c.check("path_first_file_refused_at_100", !sign_at(&from_first, &[100]));
                let mut custody = PqConsensusCustody::default();
                c.check(
                    "path_second_file_is_the_same_retired_key",
                    custody.install(filled(0x82), from_second.clone(), 50, 100).is_err()
                        && !sign_at(&from_second, &[99]),
                );
            }
        }
        {
            let validator_id = filled(0x83);
            let a = key_from(0x48, 0);
            let b = key_from(0x49, 100);
            let id_b = key_id(&b);
            let mut custody = PqConsensusCustody::default();
            c.check(
                "readers_hold_a",
                custody.install(validator_id.clone(), a.clone(), 0, 0).is_ok(),
            );
            c.check(
                "readers_hold_b",
                custody.install(validator_id.clone(), b.clone(), 50, 100).is_ok(),
            );
            let set_with_b = vec![pq_descriptor(&validator_id, &b, 0xc0)];
            c.check(
                "readers_b_signs_before_its_deadline",
                custody
                    .get_matching_store(&validator_id, &set_with_b[0], 99)
                    .is_some_and(|s| Arc::ptr_eq(&s, &b)),
            );
            c.check("readers_b_refused_at_100", !sign_election_at(&b, &[100]));
            c.check(
                "readers_membership_refused_at_99",
                !node_validator_membership(&set_with_b, &none(), &none(), &custody, 99).1,
            );
            c.check(
                "readers_usable_keys_at_99_are_only_a",
                custody.usable_key_ids(&validator_id, 99) == vec![key_id(&a)],
            );
            c.check("readers_holds_refuses_b_at_99", !custody.holds(&validator_id, &id_b, 99));
            c.check(
                "readers_report_b_expired_at_99",
                custody.report_expired(&validator_id, Some(&id_b), 100, 99),
            );
            c.check(
                "readers_descriptor_matching_refused_at_99",
                custody.get_matching_store(&validator_id, &set_with_b[0], 99).is_none(),
            );
            c.check(
                "readers_vote_signer_refused_at_99",
                pq_signer_for_set(&set_with_b, &validator_id, &custody, 99).is_err(),
            );
            c.check(
                "readers_stake_for_bs_election_refused_without_falling_back_to_a",
                custody.select_stake_store(&validator_id, 60, 99, None).err()
                    == Some(Error::Expired),
            );
            c.check(
                "readers_stake_for_as_election_still_signed_with_a",
                custody
                    .select_stake_store(&validator_id, 40, 99, None)
                    .is_ok_and(|s| Arc::ptr_eq(&s, &a)),
            );
            c.check(
                "readers_b_listed_by_a_set_is_removable_once_retired",
                custody.removal_refusal(&validator_id, &id_b, 99, &[&set_with_b]).is_none()
                    && custody.key_expired(&validator_id, &id_b, 99),
            );
            c.check(
                "readers_fresh_store_refuses_consensus",
                ConsensusKeyStore::from_seed(&[0x49; 32], 0).is_err()
                    && b.sign_consensus(b"x").is_err(),
            );
            c.check("readers_fresh_store_refuses_config_votes", b.sign_config_vote(b"x").is_err());
            c.check("readers_fresh_store_refuses_election", b.sign_election(b"x").is_err());
        }
        {
            let validator_id = filled(0x85);
            let keep = key_from(0x4c, 0);
            let c_key = key_from(0x4d, 100);
            let id_c = key_id(&c_key);
            let mut custody = PqConsensusCustody::default();
            c.check("report_holds_keep", custody.install(validator_id.clone(), keep, 0, 0).is_ok());
            c.check(
                "report_holds_c",
                custody.install(validator_id.clone(), c_key.clone(), 50, 100).is_ok(),
            );
            c.check(
                "report_c_not_expired_at_99_before",
                !custody.report_expired(&validator_id, Some(&id_c), 100, 99),
            );
            c.check(
                "report_c_expired_at_100",
                custody.report_expired(&validator_id, Some(&id_c), 100, 100),
            );
            c.check(
                "report_c_signs_nothing_after_the_clock_goes_back",
                !sign_at(&c_key, &[99]) && c_key.retired(),
            );
            c.check(
                "report_c_not_usable_at_99",
                custody.usable_key_ids(&validator_id, 99).len() == 1,
            );
            c.check(
                "report_unheld_key_by_timestamp",
                custody.report_expired(&validator_id, None, 100, 100)
                    && !custody.report_expired(&validator_id, None, 100, 99),
            );
        }
        {
            use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
            let validator_id = filled(0x84);
            let first = key_from(0x4a, 300);
            let second = key_from(0x4a, 300);
            let mut custody = PqConsensusCustody::default();
            c.check(
                "threads_hold_first",
                custody.install(validator_id.clone(), first.clone(), 0, 300).is_ok(),
            );
            let retired_done = AtomicBool::new(false);
            let before = AtomicUsize::new(0);
            let after_signed = AtomicUsize::new(0);
            let after_refused = AtomicUsize::new(0);
            let mut retired_by_custody = false;
            std::thread::scope(|scope| {
                scope.spawn(|| {
                    for _ in 0..2000 {
                        if after_refused.load(Ordering::SeqCst) >= 3 {
                            break;
                        }
                        let done = retired_done.load(Ordering::Acquire);
                        let signed = sign_at(&second, &[104]);
                        if !done {
                            before.fetch_add(usize::from(signed), Ordering::SeqCst);
                        } else if signed {
                            after_signed.fetch_add(1, Ordering::SeqCst);
                        } else {
                            after_refused.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                });
                while before.load(Ordering::SeqCst) < 2 {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                retired_by_custody = !custody.holds(&validator_id, &key_id(&first), 300);
                retired_done.store(true, Ordering::Release);
            });
            c.check("threads_custody_retires_at_300", retired_by_custody);
            c.check("threads_the_other_store_signed_before", before.load(Ordering::SeqCst) >= 2);
            c.check(
                "threads_the_other_store_never_signs_after",
                after_signed.load(Ordering::SeqCst) == 0
                    && after_refused.load(Ordering::SeqCst) >= 1,
            );
        }
        // allocation_failure_aborts_before_returning is store::tests::poisoned_registry_aborts.
        c.finish();
    }

    /// A load in the reference order reports every derived identity, and refuses
    /// the same seed under two paths only once both seeds are loaded.
    #[cfg(unix)]
    #[test]
    fn load_reports_derived_identities_in_reference_order() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let write = |name: &str, byte: u8| {
            let path = dir.path().join(name);
            std::fs::write(&path, [byte; 32]).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            path
        };
        let a = write("a", 0xe1);
        let b = write("b", 0xe2);
        let config = [
            ConfiguredKey { key_file: a.clone(), valid_from: 0, expire_at: 0 },
            ConfiguredKey { key_file: b.clone(), valid_from: 100, expire_at: 0 },
            ConfiguredKey { key_file: dir.path().join("gone"), valid_from: 50, expire_at: 60 },
        ];
        let (custody, ids) =
            PqConsensusCustody::load_with_key_ids(filled(0x91), &config, 70).unwrap();
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[&a], *store(0xe1, 0).consensus_key().key_id.as_array());
        assert_eq!(ids[&b], *store(0xe2, 0).consensus_key().key_id.as_array());
        assert_eq!(custody.usable_key_ids(&filled(0x91), 70).len(), 2);
        assert!(
            custody.select_stake_store(&filled(0x91), 55, 70, None).is_err(),
            "the unloaded window stays in the schedule"
        );
        let twin = write("twin", 0xe1);
        let duplicate = [
            ConfiguredKey { key_file: a, valid_from: 0, expire_at: 0 },
            ConfiguredKey { key_file: twin, valid_from: 100, expire_at: 0 },
        ];
        assert!(refused_with(
            PqConsensusCustody::load(filled(0x91), &duplicate, 70),
            "configured twice"
        ));
        let missing = dir.path().join("missing");
        let unreadable = [
            ConfiguredKey { key_file: missing.clone(), valid_from: 0, expire_at: 0 },
            ConfiguredKey { key_file: missing, valid_from: 5, expire_at: 0 },
        ];
        assert!(
            refused_with(
                PqConsensusCustody::load(filled(0x91), &unreadable, 70),
                "configured twice"
            ),
            "the path plan is refused before any seed is opened"
        );
        assert_eq!(
            PqConsensusCustody::load(UInt256::default(), &config, 70).err(),
            Some(Error::InvalidValidator)
        );
    }
}
