// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Root-bound, complete old/new child inventories. Decode and verify every
//! input before replay; replay uses a second pass and bounded native batches.
use super::{
    recovery_artifacts::read_sidecar,
    recovery_data::{self, Digest},
    recovery_manifest::{Kind, Record},
    recovery_parent::{self, InventoryRole},
    recovery_participant::Anchor,
    recovery_providers::RecoveryProviders,
    recovery_root::{Inventory, RootHeader, State},
};
use rtos_block::{error, fail, Result, ShardIdent};
use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

const MAX_ROW: usize = recovery_parent::BATCH_LIMIT / 4;
const MAX_KEY: usize = 65536;
const TABLES: [&str; 4] = ["block_index", "entry_meta", "offsets", "status"];

fn bytes<const N: usize>(input: &mut dyn Read) -> Result<[u8; N]> {
    let mut value = [0; N];
    input.read_exact(&mut value)?;
    Ok(value)
}
fn flag(input: &mut dyn Read) -> Result<bool> {
    match bytes::<1>(input)?[0] {
        0 => Ok(false),
        1 => Ok(true),
        _ => fail!("Invalid forward flag"),
    }
}
fn blob(input: &mut dyn Read, maximum: usize) -> Result<Vec<u8>> {
    let length = u32::from_le_bytes(bytes(input)?) as usize;
    if length > maximum {
        fail!("Forward record exceeds row budget");
    }
    let mut value = vec![0; length];
    input.read_exact(&mut value)?;
    Ok(value)
}
fn value(input: &mut dyn Read) -> Result<Option<Vec<u8>>> {
    if flag(input)? {
        Ok(Some(blob(input, MAX_ROW)?))
    } else {
        Ok(None)
    }
}
fn provider(providers: &RecoveryProviders, digest: [u8; 32]) -> Result<usize> {
    for (index, participant) in providers.participants.iter().enumerate() {
        if participant.descriptor.digest()? == digest {
            return Ok(index);
        }
    }
    fail!("Unknown forward provider")
}
fn route(providers: &RecoveryProviders, index: usize, key: bool, id: u32) -> Result<()> {
    let p = &providers.participants[index].descriptor;
    if (key && p.roles & 2 == 0)
        || (!key && p.roles & 4 == 0)
        || p.range.is_some_and(|(start, end)| key || id < start || id > end)
    {
        fail!("Forward child outside provider routing");
    }
    Ok(())
}
fn main(providers: &RecoveryProviders) -> Result<usize> {
    providers
        .participants
        .iter()
        .position(|p| p.descriptor.anchor == Anchor::Node)
        .ok_or_else(|| error!("Missing forward main provider"))
}
fn sidecar_path(providers: &RecoveryProviders, root: &RootHeader, ready: bool) -> Result<PathBuf> {
    Ok(super::recovery_stages::operation(providers, root, main(providers)?)?.join(if ready {
        "ready.v1"
    } else {
        "selection.v1"
    }))
}

pub(super) struct Original {
    pub maps: Inventory,
    pub data: Inventory,
    pub stages: u64,
}
/// Selection is retained through Committed; its digests describe the original
/// state, never a digest reconstructed from partially replayed native data.
pub(super) fn original(providers: &RecoveryProviders, root: &RootHeader) -> Result<Original> {
    let mut providers_check = providers.checker();
    let mut maps = None;
    let mut data = None;
    let mut stages = super::recovery_stages::StageInventory::new();
    let mut predicate = false;
    read_sidecar(
        &sidecar_path(providers, root, false)?,
        Kind::Selection,
        root,
        root.selection,
        |tag, length, input| {
            match tag {
                Record::Predicate => {
                    super::truncation_selection::read_predicate(input, length, |_| Ok(()))?;
                    predicate = true;
                }
                Record::Provider => providers_check.record(input, length)?,
                Record::MapInventory => {
                    if maps.is_some() {
                        fail!("Duplicate original parent inventory");
                    }
                    maps = Some(recovery_parent::read_inventory(
                        input,
                        length,
                        InventoryRole::Original,
                    )?);
                }
                Record::ArchiveInventory => {
                    if data.is_some() || length != 43 {
                        fail!("Invalid original data inventory");
                    }
                    let raw = bytes::<43>(input)?;
                    if raw[..2] != [1, 0] || raw[2] != root.policy as u8 || raw[11..] == [0; 32] {
                        fail!("Original policy mismatch");
                    }
                    data = Some(Inventory {
                        count: u64::from_le_bytes(raw[3..11].try_into()?),
                        digest: raw[11..].try_into()?,
                    });
                }
                Record::ReadyIntent => {
                    if length != 2 || bytes::<2>(input)? != [1, 0] {
                        fail!("Invalid Ready intent");
                    }
                }
                Record::Child => {
                    let stage = super::recovery_stages::Stage::decode(providers, input, length)?;
                    stages.record(stage.provider, stage.identity)?;
                }
                _ => fail!("Unsupported forward selection record"),
            }
            Ok(())
        },
    )?;
    providers_check.finish()?;
    if !predicate {
        fail!("Missing forward predicate");
    }
    Ok(Original {
        maps: maps.ok_or_else(|| error!("Missing original maps"))?,
        data: data.ok_or_else(|| error!("Missing original data"))?,
        stages: stages.finish().count,
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Pass {
    Inspect,
    Apply,
    Committed,
    Cleanup,
}
struct Scan {
    old: Digest,
    new: Digest,
    current: Digest,
    last: Option<(usize, u8, Vec<u8>)>,
    stages: u64,
}
impl Scan {
    fn new() -> Self {
        Self {
            old: Digest::new(),
            new: Digest::new(),
            current: Digest::new(),
            last: None,
            stages: 0,
        }
    }
    fn ordered(&mut self, key: (usize, u8, Vec<u8>)) -> Result<()> {
        if self.last.as_ref().is_some_and(|previous| previous >= &key) {
            fail!("Duplicate or unordered forward child");
        }
        self.last = Some(key);
        Ok(())
    }
}

/// Complete table rows are in native key order. Absent old/new values express
/// insertion/deletion. New table absence defers exact CF removal until Committed.
fn table(
    input: &mut dyn Read,
    providers: &RecoveryProviders,
    root: &RootHeader,
    scan: &mut Scan,
    pass: Pass,
) -> Result<()> {
    let key_archive = flag(input)?;
    let archive = u32::from_le_bytes(bytes(input)?);
    let table = bytes::<1>(input)?[0] as usize;
    let kind = TABLES.get(table).ok_or_else(|| error!("Unknown forward table"))?;
    let identity = bytes(input)?;
    let index = provider(providers, identity)?;
    route(providers, index, key_archive, archive)?;
    let name = format!("{kind}_{}db_{archive}", if key_archive { "key_" } else { "" });
    scan.ordered((index, 0, name.as_bytes().to_vec()))?;
    let retained = flag(input)?;
    if matches!(pass, Pass::Inspect | Pass::Committed) {
        family_disposition(providers, root, identity, key_archive, archive, retained)?;
    }
    let count = u64::from_le_bytes(bytes(input)?);
    let database = &providers.participants[index].database;
    let db = database.db();
    let cf = db.cf_handle(&name);
    if cf.is_none() && (retained || matches!(pass, Pass::Inspect | Pass::Apply)) {
        fail!("Missing forward table {name}");
    }
    scan.old.record(1, identity, &[name.as_bytes()])?;
    if retained {
        scan.new.record(1, identity, &[name.as_bytes()])?;
    }
    if cf.is_some() {
        scan.current.record(1, identity, &[name.as_bytes()])?;
    }
    let mut last = None;
    let mut batch = rocksdb::WriteBatch::default();
    let mut batch_bytes = 0usize;
    for _ in 0..count {
        let key = blob(input, MAX_KEY)?;
        if last.as_ref().is_some_and(|previous: &Vec<u8>| previous >= &key) {
            fail!("Unordered forward row");
        }
        let old = value(input)?;
        let new = value(input)?;
        if (old.is_none() && new.is_none()) || (!retained && new.is_some()) {
            fail!("Invalid forward row disposition");
        }
        if kind == &"status" && !super::recovery_guard::known_status_key(&key) {
            fail!("Unknown forward status row");
        }
        if let Some(old) = &old {
            scan.old.record(2, identity, &[name.as_bytes(), &key, old])?;
        }
        if let Some(new) = &new {
            scan.new.record(2, identity, &[name.as_bytes(), &key, new])?;
        }
        let actual = cf.as_ref().map(|cf| db.get_pinned_cf(cf, &key)).transpose()?.flatten();
        if let Some(actual) = &actual {
            scan.current.record(2, identity, &[name.as_bytes(), &key, actual])?;
        }
        if !retained
            && matches!(pass, Pass::Inspect | Pass::Apply)
            && actual.as_deref() != old.as_deref()
        {
            fail!("Tail table changed before Committed");
        }
        if retained || cf.is_some() {
            if actual.as_deref() != old.as_deref() && actual.as_deref() != new.as_deref() {
                fail!("Forward row is neither original nor final: {name}");
            }
            if matches!(pass, Pass::Committed | Pass::Cleanup)
                && retained
                && actual.as_deref() != new.as_deref()
            {
                fail!("Committed child metadata is incomplete: {name}");
            }
        }
        if pass == Pass::Apply && retained && actual.as_deref() != new.as_deref() {
            let size = key.len() + new.as_ref().map_or(0, Vec::len) + 64;
            if batch_bytes > recovery_parent::BATCH_LIMIT - size {
                db.write(std::mem::take(&mut batch))?;
                database.sync_wal()?;
                batch_bytes = 0;
            }
            let cf = cf.as_ref().expect("retained table exists");
            match &new {
                Some(value) => batch.put_cf(cf, &key, value),
                None => batch.delete_cf(cf, &key),
            }
            batch_bytes += size;
        }
        last = Some(key);
    }
    if batch_bytes != 0 {
        db.write(batch)?;
        database.sync_wal()?;
    }
    drop(cf);
    if pass == Pass::Cleanup && !retained && db.cf_handle(&name).is_some() {
        db.drop_cf(&name)?;
        database.sync_wal()?;
    }
    Ok(())
}

fn canonical_file(
    providers: &RecoveryProviders,
    identity: &[u8; 52],
) -> Result<(usize, PathBuf, super::recovery_stages::Stage)> {
    let stage = super::recovery_stages::Stage::decode(providers, &mut &identity[..], 52)?;
    let key = identity[3] == 1;
    let id = u32::from_le_bytes(identity[4..8].try_into()?);
    let shard = ShardIdent::with_tagged_prefix(
        i32::from_le_bytes(identity[8..12].try_into()?),
        u64::from_le_bytes(identity[12..20].try_into()?),
    )?;
    let base = providers.participants[stage.provider].archive_root.as_path();
    let package = if key {
        super::package_id::PackageId::for_key_block(id)
    } else {
        super::package_id::PackageId::for_block(id)
    };
    Ok((stage.provider, package.full_path(base, &shard)?, stage))
}
fn optional_digest(path: &Path) -> Result<Option<(u64, [u8; 32])>> {
    match fs::symlink_metadata(path) {
        Ok(_) => recovery_data::file_digest(path).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}
fn declared_stage(
    providers: &RecoveryProviders,
    root: &RootHeader,
    identity: &[u8; 52],
) -> Result<()> {
    let mut found = false;
    read_sidecar(
        &sidecar_path(providers, root, false)?,
        Kind::Selection,
        root,
        root.selection,
        |tag, length, input| {
            if tag == Record::Child {
                if length != 52 {
                    fail!("Unknown forward stage declaration");
                }
                if bytes::<52>(input)? == *identity {
                    found = true;
                }
            } else {
                io::copy(input, &mut io::sink())?;
            }
            Ok(())
        },
    )?;
    if !found {
        fail!("Forward package has no selected stage");
    }
    Ok(())
}
fn package(
    input: &mut dyn Read,
    providers: &RecoveryProviders,
    root: &RootHeader,
    scan: &mut Scan,
    pass: Pass,
) -> Result<()> {
    let identity = bytes::<52>(input)?;
    let (index, path, stage) = canonical_file(providers, &identity)?;
    let provider = providers.participants[index].descriptor.digest()?;
    let base = providers.participants[index].archive_root.as_path();
    let relative = path.strip_prefix(base)?.as_os_str().as_encoded_bytes();
    scan.ordered((index, 1, relative.to_vec()))?;
    let old = (u64::from_le_bytes(bytes(input)?), bytes::<32>(input)?);
    let new = if flag(input)? {
        Some((u64::from_le_bytes(bytes(input)?), bytes::<32>(input)?))
    } else {
        None
    };
    let actual = optional_digest(&path)?;
    if new.is_none() && matches!(pass, Pass::Inspect | Pass::Apply) && actual != Some(old) {
        fail!("Tail package removed before Committed");
    }
    if actual != Some(old) && actual != new {
        fail!("Forward package is neither original nor final");
    }
    if matches!(pass, Pass::Committed | Pass::Cleanup) && new.is_some() && actual != new {
        fail!("Committed package is incomplete");
    }
    scan.old.record(3, provider, &[relative, &old.0.to_le_bytes(), &old.1])?;
    if let Some(new) = new {
        scan.new.record(3, provider, &[relative, &new.0.to_le_bytes(), &new.1])?;
    }
    if let Some(actual) = actual {
        scan.current.record(3, provider, &[relative, &actual.0.to_le_bytes(), &actual.1])?;
    }
    if new.is_some_and(|new| new != old) {
        scan.stages = scan.stages.checked_add(1).ok_or_else(|| error!("Stage count overflow"))?;
        declared_stage(providers, root, &identity)?;
        let staged = stage.path(providers, root)?;
        let staged_digest = optional_digest(&staged)?;
        if let Some(staged_digest) = staged_digest {
            if !super::recovery_stages::present(&staged)? || Some(staged_digest) != new {
                fail!("Forward stage does not match final package");
            }
        } else if actual != new {
            fail!("Missing forward stage before publication");
        }
        if pass == Pass::Apply {
            publish_package(&staged, &path, actual != new)?;
        }
    }
    if pass == Pass::Cleanup && new.is_none() {
        remove_package(&path)?;
    }
    Ok(())
}

// Keep directory descriptors alive from the filesystem root through the exact
// package parent. Relative native operations never follow a path-component
// symlink; both directory chains receive explicit sync/close receipts.
fn directories(path: &Path) -> Result<Vec<fs::File>> {
    use std::os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::OpenOptionsExt,
    };
    let mut opened = vec![fs::File::options()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open("/")?];
    for component in path.components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(name) => {
                let name = std::ffi::CString::new(name.as_encoded_bytes())?;
                let fd = unsafe {
                    libc::openat(
                        opened.last().unwrap().as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    return Err(io::Error::last_os_error().into());
                }
                opened.push(unsafe { fs::File::from_raw_fd(fd) });
            }
            _ => fail!("Noncanonical recovery directory path"),
        }
    }
    if !path.is_absolute() {
        fail!("Recovery directory must be absolute");
    }
    Ok(opened)
}
fn close_directories(opened: Vec<fs::File>) -> Result<()> {
    let mut failure = None;
    for file in opened.into_iter().rev() {
        if let Err(error) = super::recovery_worker::sync_close(file) {
            if failure.is_none() {
                failure = Some(error);
            }
        }
    }
    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}
fn file_name(path: &Path) -> Result<std::ffi::CString> {
    Ok(std::ffi::CString::new(
        path.file_name().ok_or_else(|| error!("Missing package filename"))?.as_encoded_bytes(),
    )?)
}
fn sync_child(parent: &fs::File, name: &std::ffi::CStr) -> Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    super::recovery_worker::sync_close(unsafe { fs::File::from_raw_fd(fd) })
}
fn publish_package(stage: &Path, target: &Path, rename: bool) -> Result<()> {
    use std::os::fd::AsRawFd;
    let source = directories(stage.parent().ok_or_else(|| error!("Missing stage parent"))?)?;
    let destination =
        directories(target.parent().ok_or_else(|| error!("Missing package parent"))?)?;
    let old = file_name(stage)?;
    let new = file_name(target)?;
    let outcome = (|| {
        if rename {
            sync_child(source.last().unwrap(), &old)?;
            if unsafe {
                libc::renameat(
                    source.last().unwrap().as_raw_fd(),
                    old.as_ptr(),
                    destination.last().unwrap().as_raw_fd(),
                    new.as_ptr(),
                )
            } != 0
            {
                return Err(io::Error::last_os_error().into());
            }
        }
        // Also sync an already-renamed target on restart: its prior fsync or
        // directory sync may have been interrupted even if bytes match.
        sync_child(destination.last().unwrap(), &new)
    })();
    let destination_closed = close_directories(destination);
    let source_closed = close_directories(source);
    outcome?;
    destination_closed?;
    source_closed
}
fn remove_package(path: &Path) -> Result<()> {
    use std::os::fd::AsRawFd;
    let parent = directories(path.parent().ok_or_else(|| error!("Missing tail parent"))?)?;
    let name = file_name(path)?;
    let outcome: Result<()> =
        if unsafe { libc::unlinkat(parent.last().unwrap().as_raw_fd(), name.as_ptr(), 0) } == 0 {
            Ok(())
        } else {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(error.into())
            }
        };
    let closed = close_directories(parent);
    outcome?;
    closed
}

struct Outcome {
    old: Inventory,
    new: Inventory,
    current: Inventory,
    stages: u64,
    maps: Inventory,
}
fn scan(providers: &RecoveryProviders, root: &RootHeader, pass: Pass) -> Result<Outcome> {
    let mut scan = Scan::new();
    let mut participants = providers.checker();
    let mut maps = None;
    read_sidecar(
        &sidecar_path(providers, root, true)?,
        Kind::Ready,
        root,
        root.ready,
        |tag, length, input| {
            match tag {
                Record::SelectionDigest => {
                    if length != 32 || bytes::<32>(input)? != root.selection.digest {
                        fail!("Forward selection digest mismatch");
                    }
                }
                Record::Provider => participants.record(input, length)?,
                Record::MapInventory => {
                    if maps.is_some() {
                        fail!("Duplicate forward map inventory");
                    }
                    maps =
                        Some(recovery_parent::read_inventory(input, length, InventoryRole::Final)?);
                }
                Record::Child => {
                    if length < 3 || bytes::<2>(input)? != [1, 0] {
                        fail!("Unsupported forward child version");
                    }
                    match bytes::<1>(input)?[0] {
                        1 => table(input, providers, root, &mut scan, pass)?,
                        2 => package(input, providers, root, &mut scan, pass)?,
                        _ => fail!("Unsupported forward child kind"),
                    }
                }
                Record::ParentMutation => {
                    io::copy(input, &mut io::sink())?;
                }
                _ => fail!("Unsupported Ready record"),
            }
            Ok(())
        },
    )?;
    participants.finish()?;
    Ok(Outcome {
        old: scan.old.finish(),
        new: scan.new.finish(),
        current: scan.current.finish(),
        stages: scan.stages,
        maps: maps.ok_or_else(|| error!("Missing final map inventory"))?,
    })
}

/// Check every artifact remaining in the operation directories. An inventory
/// of canonical data cannot prove ownership of an extra temporary file.
fn controls(providers: &RecoveryProviders, root: &RootHeader) -> Result<()> {
    use super::recovery_artifacts::directory;
    for (index, participant) in providers.participants.iter().enumerate() {
        let operation = super::recovery_stages::operation(providers, root, index)?;
        let parent = operation.parent().ok_or_else(|| error!("Missing control parent"))?;
        let archive = parent.parent().ok_or_else(|| error!("Missing archive parent"))?;
        if !directory(archive)? || !directory(parent)? {
            continue;
        }
        for entry in fs::read_dir(parent)? {
            if entry?.file_name() != operation.file_name().unwrap() {
                fail!("Unexpected recovery operation directory");
            }
        }
        if !directory(&operation)? {
            continue;
        }
        recovery_data::sorted_entries(&operation, |path| {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| error!("Invalid recovery artifact name"))?;
            if participant.descriptor.anchor == Anchor::Node
                && matches!(name, "selection.v1" | "ready.v1")
            {
                return Ok(());
            }
            let mut declared = false;
            read_sidecar(
                &sidecar_path(providers, root, false)?,
                Kind::Selection,
                root,
                root.selection,
                |tag, length, input| {
                    if tag == Record::Child {
                        let stage =
                            super::recovery_stages::Stage::decode(providers, input, length)?;
                        if stage.provider == index && stage.name() == name {
                            declared = true;
                        }
                    } else {
                        io::copy(input, &mut io::sink())?;
                    }
                    Ok(())
                },
            )?;
            if !declared || !super::recovery_stages::present(&path)? {
                fail!("Unowned or invalid remaining forward artifact");
            }
            Ok(())
        })?;
    }
    Ok(())
}

fn parent_inventory(
    providers: &RecoveryProviders,
    root: &RootHeader,
    original: Inventory,
) -> Result<Inventory> {
    let expected = recovery_parent::ReplayMaps {
        operation: root.operation,
        ready: root.ready,
        selection_digest: root.selection.digest,
        original,
    };
    super::recovery_artifacts::inspect_sidecar(
        &sidecar_path(providers, root, true)?,
        root.ready,
        |file| {
            recovery_parent::validate_replay_maps(
                providers.participants[main(providers)?].database.db(),
                file,
                &expected,
                |_, _, input| {
                    io::copy(input, &mut io::sink())?;
                    Ok(())
                },
            )
        },
    )
}

/// Entire old/current inventories are checked before any write. The current
/// digest includes all native rows and package files, so omitted extras and
/// absent rows cannot be hidden by the Ready stream's projection.
fn prepare(providers: &RecoveryProviders, root: &RootHeader) -> Result<Outcome> {
    root.validate()?;
    if !matches!(root.state, State::Ready | State::Committed) {
        fail!("Expected forward recovery state");
    }
    if providers.protection.archive_range(0, None) {
        fail!("Archive recovery conflicts with persistent repair custody");
    }
    providers.validate_controls(root)?;
    providers.verify_provider_and_map_inventories(root)?;
    let original = original(providers, root)?;
    controls(providers, root)?;
    let pass = if root.state == State::Ready { Pass::Inspect } else { Pass::Committed };
    let result = scan(providers, root, pass)?;
    if result.old != original.data || result.stages != original.stages {
        fail!("Forward selection data or stage inventory mismatch");
    }
    let current = if root.state == State::Committed {
        recovery_data::inventory_during_cleanup(providers)?
    } else {
        recovery_data::inventory(providers)?
    };
    if result.current != current {
        fail!("Forward current data inventory mismatch");
    }
    if parent_inventory(providers, root, original.maps)? != result.maps {
        fail!("Forward parent inventory mismatch");
    }
    Ok(result)
}

fn replay_parents(providers: &RecoveryProviders, root: &RootHeader) -> Result<()> {
    let database = &providers.participants[main(providers)?].database;
    let mut batches = recovery_parent::Batches::default();
    let mut emit = |commands: Vec<recovery_parent::Command>| -> Result<()> {
        let mut batch = rocksdb::WriteBatch::default();
        for command in commands {
            let cf = database
                .db()
                .cf_handle(command.key.map.name())
                .ok_or_else(|| error!("Missing parent map during replay"))?;
            match command.new {
                Some(value) => batch.put_cf(&cf, command.key.bytes, value),
                None => batch.delete_cf(&cf, command.key.bytes),
            }
        }
        database.db().write(batch)?;
        database.sync_wal()
    };
    read_sidecar(
        &sidecar_path(providers, root, true)?,
        Kind::Ready,
        root,
        root.ready,
        |tag, length, input| {
            if tag == Record::ParentMutation {
                let command = recovery_parent::read_command(input, length, |_, _, _, old| {
                    io::copy(old, &mut io::sink())?;
                    Ok(())
                })?;
                batches.push(command, &mut emit)?;
            } else {
                io::copy(input, &mut io::sink())?;
            }
            Ok(())
        },
    )?;
    batches.finish(&mut emit)
}

fn store_successor(
    providers: &RecoveryProviders,
    old: &RootHeader,
    next: &RootHeader,
) -> Result<()> {
    old.check_successor(next)?;
    let database = &providers.participants[main(providers)?].database;
    database.db().put(super::recovery_root::ROOT_KEY, next.encode()?)?;
    database.sync_wal()
}

/// Caller must hold the domain closed and the deletion/artifact guards. Keep
/// custody of every native provider through all effects and durability checks.
/// Root-last control cleanup is performed by the common recovery worker.
pub(super) fn recover(providers: &RecoveryProviders, root: &RootHeader) -> Result<RootHeader> {
    let expected = prepare(providers, root)?;
    let mut committed = root.clone();
    if root.state == State::Ready {
        scan(providers, root, Pass::Apply)?;
        replay_parents(providers, root)?;
        // Re-sync even if replay found every value already final: the prior
        // writer may have stopped between its native write and WAL sync.
        for participant in &providers.participants {
            participant.database.sync_wal()?;
        }
        let applied = scan(providers, root, Pass::Committed)?;
        if applied.new != expected.new
            || applied.current != recovery_data::inventory(providers)?
            || recovery_parent::native_inventory(
                providers.participants[main(providers)?].database.db(),
            )? != expected.maps
        {
            fail!("Forward replay did not establish final retained data and parent maps");
        }
        committed.state = State::Committed;
        committed.maps = expected.maps;
        store_successor(providers, root, &committed)?;
    }
    scan(providers, &committed, Pass::Cleanup)?;
    // An already-published stage can remain after replay only if its canonical
    // target has the exact final digest. The scans above establish that fact.
    read_sidecar(
        &sidecar_path(providers, &committed, false)?,
        Kind::Selection,
        &committed,
        committed.selection,
        |tag, length, input| {
            if tag == Record::Child {
                let stage = super::recovery_stages::Stage::decode(providers, input, length)?;
                let base = providers.participants[stage.provider].archive_root.as_path();
                super::recovery_worker::clean_stage(
                    base,
                    &committed,
                    &std::ffi::CString::new(stage.name())?,
                )?;
            } else {
                io::copy(input, &mut io::sink())?;
            }
            Ok(())
        },
    )?;
    if recovery_data::inventory(providers)? != expected.new {
        fail!("Final archive data inventory mismatch");
    }
    let mut cleaned = committed.clone();
    cleaned.state = State::Cleaned;
    cleaned.data = expected.new;
    cleaned.providers = providers.inventory()?;
    for participant in &providers.participants {
        participant.database.sync_wal()?;
    }
    store_successor(providers, &committed, &cleaned)?;
    Ok(cleaned)
}

fn family_disposition(
    providers: &RecoveryProviders,
    root: &RootHeader,
    provider: [u8; 32],
    key: bool,
    archive: u32,
    retained: bool,
) -> Result<()> {
    let mut mask = 0u8;
    read_sidecar(
        &sidecar_path(providers, root, true)?,
        Kind::Ready,
        root,
        root.ready,
        |tag, length, input| {
            if tag == Record::Child {
                if length < 3 || bytes::<2>(input)? != [1, 0] {
                    fail!("Unknown child schema");
                }
                match bytes::<1>(input)?[0] {
                    1 => {
                        let row_key = flag(input)?;
                        let row_archive = u32::from_le_bytes(bytes(input)?);
                        let table = bytes::<1>(input)?[0];
                        let row_provider = bytes::<32>(input)?;
                        let row_retained = flag(input)?;
                        if row_key == key && row_archive == archive && row_provider == provider {
                            if table >= 4 || mask & (1 << table) != 0 || row_retained != retained {
                                fail!("Inconsistent final archive family disposition");
                            }
                            mask |= 1 << table;
                        }
                    }
                    2 => {}
                    _ => fail!("Unknown child schema"),
                }
            }
            io::copy(input, &mut io::sink())?;
            Ok(())
        },
    )?;
    if mask != 15 {
        fail!("Incomplete forward archive family declarations");
    }
    Ok(())
}

pub(super) fn validate(providers: &RecoveryProviders, root: &RootHeader) -> Result<()> {
    prepare(providers, root).map(|_| ())
}

#[cfg(test)]
#[path = "../tests/test_recovery_forward.rs"]
mod tests;

pub(super) fn sync_directory_path(path: &Path) -> Result<()> {
    close_directories(directories(path)?)
}
