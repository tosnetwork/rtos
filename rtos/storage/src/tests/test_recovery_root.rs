use super::*;

fn fixture(state: State, aborted: bool, policy: Policy) -> RootHeader {
    let empty = Inventory { count: 0, digest: sha256_digest([]) };
    RootHeader {
        state,
        policy,
        aborted,
        operation: [7; 16],
        database_identity_bytes: 36,
        database_identity_digest: [8; 32],
        selection: if state == State::Preparing {
            Sidecar::default()
        } else {
            Sidecar { bytes: 1024, records: 5, digest: [9; 32] }
        },
        ready: if matches!(state, State::Preparing | State::Building) || aborted {
            Sidecar::default()
        } else {
            Sidecar { bytes: 2048, records: 7, digest: [10; 32] }
        },
        providers: if matches!(state, State::Preparing | State::Cleaned) {
            empty
        } else {
            Inventory::default()
        },
        maps: if matches!(state, State::Preparing | State::Committed | State::Cleaned) {
            empty
        } else {
            Inventory::default()
        },
        data: if matches!(state, State::Preparing | State::Cleaned) {
            empty
        } else {
            Inventory::default()
        },
    }
}

fn rechecksum(bytes: &mut [u8; HEADER_SIZE]) {
    let checksum = sha256_digest(&bytes[..284]);
    bytes[284..].copy_from_slice(&checksum);
}

#[test]
fn root_header_checks_every_policy_state_combination() -> Result<()> {
    for state in [State::Preparing, State::Building, State::Ready, State::Committed, State::Cleaned]
    {
        for flags in 0u8..=u8::MAX {
            let aborted = state == State::Cleaned && flags & 1 != 0;
            let mut bytes = fixture(state, aborted, Policy::Node).encode()?;
            bytes[11] = flags;
            rechecksum(&mut bytes);
            let result = RootHeader::decode(&bytes);
            let allowed = matches!(flags, 2 | 4 | 6)
                || (state == State::Cleaned && matches!(flags, 3 | 5 | 7));
            assert_eq!(result.is_ok(), allowed, "state {state:?}, flags {flags}");
            if let Ok(header) = result {
                assert_eq!(header.encode()?, bytes);
            }
        }
    }
    Ok(())
}

#[test]
fn root_header_rejects_truncation_trailing_bytes_and_corruption() -> Result<()> {
    let bytes = fixture(State::Committed, false, Policy::Node).encode()?;
    for length in 0..HEADER_SIZE {
        assert!(RootHeader::decode(&bytes[..length]).is_err(), "length {length}");
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(RootHeader::decode(&trailing).is_err());
    for offset in 0..HEADER_SIZE {
        let mut corrupt = bytes;
        corrupt[offset] ^= 1;
        assert!(RootHeader::decode(&corrupt).is_err(), "offset {offset}");
    }
    // Correct checksum cannot hide wrong magic/version/state or absent identity.
    for (start, end) in
        [(0, 8), (8, 10), (10, 11), (12, 28), (28, 36), (36, 68), (68, 116), (204, 244)]
    {
        let mut corrupt = bytes;
        corrupt[start..end].fill(0);
        rechecksum(&mut corrupt);
        assert!(RootHeader::decode(&corrupt).is_err(), "field {start}..{end}");
    }
    Ok(())
}

#[test]
fn cleaned_policy_cannot_downgrade_factory_or_missing_ledger() -> Result<()> {
    for aborted in [false, true] {
        for policy in [Policy::Node, Policy::StandaloneWithoutLedger, Policy::StandaloneWithLedger]
        {
            // No sidecar is read: policy survives solely in the fixed header.
            let header = RootHeader::decode(&fixture(State::Cleaned, aborted, policy).encode()?)?;
            for mode in [FactoryMode::Node, FactoryMode::Standalone] {
                for exists in [false, true] {
                    let allowed = match policy {
                        Policy::Node => mode == FactoryMode::Node && exists,
                        Policy::StandaloneWithoutLedger => {
                            mode == FactoryMode::Standalone && !exists
                        }
                        Policy::StandaloneWithLedger => mode == FactoryMode::Standalone && exists,
                    };
                    assert_eq!(header.policy.check_environment(mode, exists).is_ok(), allowed);
                }
            }
        }
    }
    Ok(())
}

#[test]
fn root_transitions_bind_identity_and_committed_map_inventory() -> Result<()> {
    let building = fixture(State::Building, false, Policy::Node);
    let ready = fixture(State::Ready, false, Policy::Node);
    let committed = fixture(State::Committed, false, Policy::Node);
    let cleaned = fixture(State::Cleaned, false, Policy::Node);
    let aborted = fixture(State::Cleaned, true, Policy::Node);
    let states = [&building, &ready, &committed, &cleaned, &aborted];
    for (from, a) in states.iter().enumerate() {
        for (to, b) in states.iter().enumerate() {
            let allowed = from == to || matches!((from, to), (0, 1) | (1, 2) | (2, 3) | (0, 4));
            assert_eq!(a.check_successor(b).is_ok(), allowed, "transition {from}->{to}");
        }
    }
    let mut other = ready.clone();
    other.policy = Policy::StandaloneWithLedger;
    assert!(building.check_successor(&other).is_err());
    other = ready.clone();
    other.operation[0] ^= 1;
    assert!(building.check_successor(&other).is_err());
    other = ready.clone();
    other.selection.digest[0] ^= 1;
    assert!(building.check_successor(&other).is_err());
    other = cleaned;
    other.maps.digest[0] ^= 1;
    assert!(committed.check_successor(&other).is_err());
    Ok(())
}

#[test]
fn root_inventory_and_descriptor_presence_follow_durable_states() -> Result<()> {
    let ready_descriptor = fixture(State::Ready, false, Policy::Node).ready;
    let inventory = Inventory { count: 0, digest: sha256_digest([]) };
    for state in [State::Preparing, State::Building, State::Ready, State::Committed, State::Cleaned]
    {
        for aborted in [false, true] {
            let header = fixture(state, aborted, Policy::Node);
            if aborted && state != State::Cleaned {
                assert!(header.encode().is_err());
                continue;
            }
            let mut changed = header.clone();
            changed.ready = if header.ready == Sidecar::default() {
                ready_descriptor
            } else {
                Sidecar::default()
            };
            assert!(changed.encode().is_err());
            for field in 0..3 {
                let mut changed = header.clone();
                let value = match field {
                    0 => &mut changed.providers,
                    1 => &mut changed.maps,
                    _ => &mut changed.data,
                };
                *value =
                    if *value == Inventory::default() { inventory } else { Inventory::default() };
                assert!(changed.encode().is_err(), "{state:?} aborted={aborted} inventory={field}");
            }
        }
    }
    Ok(())
}

#[test]
fn pending_root_and_orphan_participant_preserve_native_records() -> Result<()> {
    use crate::{
        archives::recovery_guard::{self, ArchiveRecoveryRequired},
        db::rocksdb::{AccessType, RocksDb},
    };
    let directory = tempfile::tempdir()?;
    let db = RocksDb::new(directory.path(), "db", None, AccessType::ReadWrite)?;
    for state in [State::Preparing, State::Building, State::Ready, State::Committed, State::Cleaned]
    {
        let bytes = fixture(state, false, Policy::Node).encode()?;
        db.db().put(ROOT_KEY, bytes)?;
        db.sync_wal()?;
        let error =
            recovery_guard::ensure_open_provider_clear(db.db(), directory.path()).unwrap_err();
        assert!(error.is::<ArchiveRecoveryRequired>());
        let error =
            recovery_guard::ensure_slice_clear(db.db(), directory.path(), 0, false).unwrap_err();
        assert!(error.is::<ArchiveRecoveryRequired>());
        assert_eq!(db.db().get(ROOT_KEY)?.as_deref(), Some(bytes.as_slice()));
    }
    db.db().put(ROOT_KEY, b"unrecognized root bytes")?;
    assert!(recovery_guard::ensure_root_controls_clear(db.db()).is_err());
    assert_eq!(db.db().get(ROOT_KEY)?.as_deref(), Some(b"unrecognized root bytes".as_slice()));
    db.db().delete(ROOT_KEY)?;
    db.db().put(PARTICIPANT_KEY, b"orphan participant")?;
    assert!(recovery_guard::ensure_root_controls_clear(db.db()).is_err());
    assert_eq!(db.db().get(PARTICIPANT_KEY)?.as_deref(), Some(b"orphan participant".as_slice()));
    db.db().delete(PARTICIPANT_KEY)?;
    recovery_guard::ensure_open_provider_clear(db.db(), directory.path())?;
    Ok(())
}

#[test]
fn preparing_transitions_preserve_original_inventories() -> Result<()> {
    let preparing = fixture(State::Preparing, false, Policy::Node);
    preparing.check_successor(&fixture(State::Building, false, Policy::Node))?;
    assert!(preparing.check_successor(&fixture(State::Ready, false, Policy::Node)).is_err());
    let mut aborted = preparing.clone();
    aborted.state = State::Cleaned;
    aborted.aborted = true;
    preparing.check_successor(&aborted)?;
    assert_eq!(RootHeader::decode(&aborted.encode()?)?, aborted);
    for field in 0..3 {
        let mut changed = aborted.clone();
        match field {
            0 => changed.providers.digest[0] ^= 1,
            1 => changed.maps.digest[0] ^= 1,
            _ => changed.data.digest[0] ^= 1,
        }
        assert!(preparing.check_successor(&changed).is_err());
    }
    Ok(())
}
