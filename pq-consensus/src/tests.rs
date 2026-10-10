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
