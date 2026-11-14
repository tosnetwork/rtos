// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::archives::recovery_root::{Inventory, Policy, RootHeader, Sidecar, State};

fn provider(anchor: Anchor) -> Provider {
    Provider {
        roles: if anchor == Anchor::Node { 7 } else { 4 },
        anchor,
        anchor_identity: [3; 32],
        database: Identity::native(b"native database identity").unwrap(),
        range: if anchor == Anchor::Node { None } else { Some((100, 199)) },
        relative: if anchor == Anchor::Discovery { "epoch_1".into() } else { PathBuf::new() },
    }
}
fn root() -> RootHeader {
    let identity = provider(Anchor::Node).database;
    RootHeader {
        state: State::Building,
        policy: Policy::Node,
        aborted: false,
        operation: [4; 16],
        database_identity_bytes: identity.bytes,
        database_identity_digest: identity.digest,
        selection: Sidecar { bytes: 100, records: 1, digest: [5; 32] },
        ready: Sidecar::default(),
        providers: Inventory::default(),
        maps: Inventory::default(),
        data: Inventory::default(),
    }
}
fn backlink(root: &RootHeader, provider: &Provider) -> Backlink {
    Backlink {
        operation: root.operation,
        main: Identity {
            bytes: root.database_identity_bytes,
            digest: root.database_identity_digest,
        },
        selection: root.selection.digest,
        provider: provider.digest().unwrap(),
    }
}

#[test]
fn trusted_provider_comparison_binds_all_fields_without_consuming_next_record() -> Result<()> {
    for anchor in [Anchor::Node, Anchor::ExplicitEpoch, Anchor::Discovery] {
        let provider = provider(anchor);
        let mut bytes = Vec::new();
        provider.write(&mut bytes)?;
        assert_eq!(provider.encoded_len()?, bytes.len() as u64);
        assert_eq!(provider.digest()?, sha256_digest(&bytes));
        for index in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[index] ^= 1;
            assert!(provider.check_record(&mut &changed[..], changed.len() as u64).is_err());
        }
        for end in 0..bytes.len() {
            assert!(provider.check_record(&mut &bytes[..end], bytes.len() as u64).is_err());
        }
        assert!(provider.check_record(&mut &bytes[..], u64::MAX).is_err());
        let length = bytes.len() as u64;
        bytes.extend_from_slice(b"next");
        let mut input = &bytes[..];
        provider.check_record(&mut input, length)?;
        assert_eq!(input, b"next");
    }
    Ok(())
}

#[test]
fn paths_roles_ranges_and_opaque_identity_are_checked() {
    for path in ["/absolute", "../escape", "a/../b", "./a", "a/./b", "a//b", "a/", "a\0b"] {
        let mut provider = provider(Anchor::Discovery);
        provider.relative = path.into();
        assert!(provider.digest().is_err(), "{path:?}");
    }
    for roles in 0..=255 {
        let mut main = provider(Anchor::Node);
        main.roles = roles;
        assert_eq!(main.digest().is_ok(), matches!(roles, 3 | 7));
        let mut epoch = provider(Anchor::ExplicitEpoch);
        epoch.roles = roles;
        assert_eq!(epoch.digest().is_ok(), roles == 4);
    }
    let mut epoch = provider(Anchor::ExplicitEpoch);
    epoch.range = Some((200, 100));
    assert!(epoch.digest().is_err());
    epoch.range = None;
    assert!(epoch.digest().is_err());
    assert!(Identity::native(b"").is_err());
    assert_eq!(Identity::native(&[0, 255, 128]).unwrap().bytes, 3);
}

#[test]
fn backlink_corruption_and_cross_operation_or_provider_binding_refuse() -> Result<()> {
    let root = root();
    let provider = provider(Anchor::Node);
    let link = backlink(&root, &provider);
    let bytes = link.encode()?;
    assert_eq!(Backlink::decode(&bytes)?, link);
    link.check(&root, &provider)?;
    for index in 0..bytes.len() {
        let mut changed = bytes;
        changed[index] ^= 1;
        assert!(Backlink::decode(&changed).is_err());
    }
    for end in 0..bytes.len() {
        assert!(Backlink::decode(&bytes[..end]).is_err());
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(Backlink::decode(&trailing).is_err());
    for field in 0..5 {
        let mut changed = link.clone();
        match field {
            0 => changed.operation[0] ^= 1,
            1 => changed.main.bytes += 1,
            2 => changed.main.digest[0] ^= 1,
            3 => changed.selection[0] ^= 1,
            _ => changed.provider[0] ^= 1,
        }
        let changed = Backlink::decode(&changed.encode()?)?;
        assert!(changed.check(&root, &provider).is_err());
    }
    let mut moved = provider;
    moved.relative = "different".into();
    assert!(link.check(&root, &moved).is_err());
    moved.database = Identity::native(b"another native identity")?;
    let recaptured = backlink(&root, &moved);
    assert!(recaptured.check(&root, &moved).is_err());
    Ok(())
}

#[test]
fn actual_native_participant_is_preserved_by_ordinary_open_guard() -> Result<()> {
    use crate::{
        archives::{recovery_guard, recovery_root::PARTICIPANT_KEY},
        db::rocksdb::{AccessType, RocksDb},
    };
    let dir = tempfile::tempdir()?;
    let db = RocksDb::new(dir.path(), "db", None, AccessType::ReadWrite)?;
    let mut provider = provider(Anchor::Node);
    provider.database = Identity::native(&db.db().get_db_identity()?)?;
    let mut root = root();
    root.database_identity_bytes = provider.database.bytes;
    root.database_identity_digest = provider.database.digest;
    let link = backlink(&root, &provider);
    link.check(&root, &provider)?;
    let bytes = link.encode()?;
    db.db().put(PARTICIPANT_KEY, bytes)?;
    db.sync_wal()?;
    assert!(recovery_guard::ensure_root_controls_clear(db.db()).is_err());
    assert_eq!(db.db().get(PARTICIPANT_KEY)?.as_deref(), Some(bytes.as_slice()));
    db.db().delete(PARTICIPANT_KEY)?;
    db.sync_wal()?;
    recovery_guard::ensure_root_controls_clear(db.db())?;
    Ok(())
}
