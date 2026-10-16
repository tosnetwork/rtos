// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Native bootstrap recovery. Cleaned cleanup is resumable and clears root last.
use super::{recovery_artifacts, recovery_data, recovery_participant::{Anchor, Backlink},
    recovery_providers::RecoveryProviders, recovery_root::{RootHeader, State, ROOT_KEY, PARTICIPANT_KEY}};
use rtos_block::{error, fail, Result};
use std::{ffi::{CStr, CString}, fs::File, io, os::{fd::{AsRawFd, FromRawFd, IntoRawFd}, unix::fs::OpenOptionsExt}, path::Path, sync::Arc};

fn child_directory(parent: &File, name: &CStr) -> Result<Option<File>> {
    // SAFETY: fixed relative names, live parent fd, and no symlink following.
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if fd < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound { return Ok(None); }
        return Err(error.into());
    }
    Ok(Some(unsafe { File::from_raw_fd(fd) }))
}
fn unlink(parent: &File, name: &CStr, directory: bool) -> Result<()> {
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), if directory { libc::AT_REMOVEDIR } else { 0 }) } != 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::NotFound { return Err(error.into()); }
    }
    Ok(())
}
fn sync_close(file: File) -> Result<()> {
    let synced = file.sync_all();
    let fd = file.into_raw_fd();
    // A failed close is never retried; the caller's quarantine owns providers.
    if unsafe { libc::close(fd) } != 0 { return Err(io::Error::last_os_error().into()); }
    Ok(synced?)
}
fn clean_controls(path: &Path, main: bool, root: &RootHeader) -> Result<()> {
    let base = File::options().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW).open(path)?;
    if let Some(archive) = child_directory(&base, c"archive")? {
        if let Some(controls) = child_directory(&archive, c"recovery")? {
            let operation = CString::new(hex::encode(root.operation))?;
            if let Some(directory) = child_directory(&controls, &operation)? {
                if main {
                    unlink(&directory, c"selection.v1", false)?;
                    if !root.aborted { unlink(&directory, c"ready.v1", false)?; }
                }
                sync_close(directory)?;
                unlink(&controls, &operation, true)?;
            }
            // Sync even when absent: a prior unlink may have preceded a crash.
            sync_close(controls)?;
        }
        sync_close(archive)?;
    }
    sync_close(base)
}
fn verify(providers: &RecoveryProviders, root: &RootHeader) -> Result<()> {
    providers.validate_controls(root)?;
    providers.verify_provider_and_map_inventories(root)?;
    if recovery_data::inventory(providers)? != root.data { fail!("Cleaned archive data inventory mismatch"); }
    recovery_artifacts::validate_cleaned(providers, root)
}

pub(crate) fn recover_cleaned(providers: RecoveryProviders, root: RootHeader) -> Result<()> {
    if root.state != State::Cleaned { fail!("Archive recovery state is not implemented yet: {:?}", root.state); }
    verify(&providers, &root)?;
    let providers = Arc::new(providers);
    let custody = super::package::retirement::reserve_resources(&providers)?;
    for participant in &providers.participants {
        clean_controls(participant.database.db().path().parent().ok_or_else(|| error!("Missing provider root"))?,
            participant.descriptor.anchor == Anchor::Node, &root)?;
    }
    for participant in &providers.participants {
        let db = participant.database.db();
        if let Some(bytes) = db.get(PARTICIPANT_KEY)? {
            Backlink::decode(&bytes)?.check(&root, &participant.descriptor)?;
            db.delete(PARTICIPANT_KEY)?;
        }
        participant.database.sync_wal()?;
    }
    verify(&providers, &root)?;
    let main = providers.participants.iter().find(|p| p.descriptor.anchor == Anchor::Node)
        .ok_or_else(|| error!("Missing main recovery provider"))?;
    main.database.db().delete(ROOT_KEY)?;
    main.database.sync_wal()?;
    custody.complete();
    Ok(())
}
