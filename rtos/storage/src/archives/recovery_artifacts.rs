// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Validate the remaining control files of a durable Cleaned operation before
//! cleanup. This module performs no deletion and grants no mutation authority.
use super::{recovery_manifest::{read_manifest, Kind}, recovery_participant::Anchor,
    recovery_providers::RecoveryProviders, recovery_root::{RootHeader, Sidecar, State}};
use rtos_block::{fail, Result};
use std::{fs, io, os::{fd::IntoRawFd, unix::fs::{MetadataExt, OpenOptionsExt}}, path::Path};

pub(super) fn directory(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => Ok(true),
        Ok(_) => fail!("Invalid recovery control directory {}", path.display()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}
fn identity(meta: &fs::Metadata) -> (u64,u64,u64,i64,i64,i64,i64) {
    (meta.dev(), meta.ino(), meta.len(), meta.mtime(), meta.mtime_nsec(), meta.ctime(), meta.ctime_nsec())
}
pub(crate) fn read_sidecar(
    path: &Path, kind: Kind, root: &RootHeader, expected: Sidecar,
    visit: impl FnMut(super::recovery_manifest::Record, u64, &mut dyn io::Read) -> Result<()>,
) -> Result<()> {
    inspect_sidecar(path, expected, |file| {
        read_manifest(file, kind, root.operation, expected, visit)
    })
}

/// Hold and verify the same native sidecar descriptor through a full semantic
/// scan, including close errors. A successful callback alone is not a receipt.
pub(super) fn inspect_sidecar<T>(
    path: &Path, expected: Sidecar,
    inspect: impl FnOnce(&mut fs::File) -> Result<T>,
) -> Result<T> {
    let before = fs::symlink_metadata(path)?;
    if !before.is_file() || before.file_type().is_symlink() || before.len() != expected.bytes {
        fail!("Recovery sidecar type or length mismatch");
    }
    let mut file = fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path)?;
    let outcome = (|| {
        if identity(&file.metadata()?) != identity(&before) { fail!("Recovery sidecar changed during open"); }
        // Root-bound whole-file digest, framing, operation, counts and EOF are
        // checked. Cleaned inventories supply canonical-state evidence; this is
        // not a replacement for the earlier full selection/Ready semantics.
        let result = inspect(&mut file)?;
        if identity(&file.metadata()?) != identity(&before)
            || identity(&fs::symlink_metadata(path)?) != identity(&before) {
            fail!("Recovery sidecar changed during inspection");
        }
        Ok(result)
    })();
    let fd = file.into_raw_fd();
    // SAFETY: this uniquely owned descriptor is consumed once; never retry a
    // failed close, and never certify the sidecar after a close error.
    if unsafe { libc::close(fd) } != 0 { return Err(io::Error::last_os_error().into()); }
    outcome
}

fn sidecar(path: &Path, kind: Kind, root: &RootHeader, expected: Sidecar) -> Result<()> {
    read_sidecar(path, kind, root, expected, |_, _, payload| {
        io::copy(payload, &mut io::sink())?; Ok(())
    })
}

pub(crate) fn validate_unstaged_building(providers: &RecoveryProviders, root: &RootHeader) -> Result<()> {
    if root.state != State::Building { fail!("Expected Building root"); }
    validate_remaining(providers, root)
}

pub(crate) fn validate_cleaned(providers: &RecoveryProviders, root: &RootHeader) -> Result<()> {
    if root.state != State::Cleaned { fail!("Control cleanup inspection requires Cleaned root"); }
    validate_remaining(providers, root)
}

fn validate_remaining(providers: &RecoveryProviders, root: &RootHeader) -> Result<()> {
    root.validate()?;
    let operation = hex::encode(root.operation);
    for participant in &providers.participants {
        let archive = participant.archive_root.join("archive");
        if !directory(&archive)? { continue; }
        let controls = archive.join("recovery");
        if !directory(&controls)? { continue; }
        for entry in fs::read_dir(&controls)? {
            let entry = entry?;
            if entry.file_name() != std::ffi::OsStr::new(&operation) {
                fail!("Unrecognized operation in recovery control directory");
            }
            let path = entry.path();
            if !directory(&path)? { fail!("Recovery operation directory disappeared"); }
            for artifact in fs::read_dir(path)? {
                let artifact = artifact?;
                if participant.descriptor.anchor != Anchor::Node {
                    fail!("Unexpected remaining epoch recovery artifact");
                }
                match artifact.file_name().to_str() {
                    Some("selection.v1") => sidecar(&artifact.path(), Kind::Selection, root, root.selection)?,
                    Some("ready.v1") if root.state == State::Cleaned && !root.aborted => sidecar(&artifact.path(), Kind::Ready, root, root.ready)?,
                    _ => fail!("Unrecognized remaining recovery artifact"),
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/test_recovery_artifacts.rs"]
mod tests;
