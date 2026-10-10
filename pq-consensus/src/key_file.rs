// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use crate::{ConsensusKeyStore, Error, SEED_BYTES};
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyFileError {
    CannotOpen,
    NotRegular,
    WrongOwner,
    GroupOrWorldAccess,
    WritableDirectory,
    WrongSize,
    ReadFailed,
    UnsupportedPlatform,
}
impl std::fmt::Display for KeyFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::CannotOpen => "cannot open the configured file without following a symlink",
            Self::NotRegular => "the seed is not a regular file",
            Self::WrongOwner => "the seed is owned by another user",
            Self::GroupOrWorldAccess => "the seed has group or world permission bits",
            Self::WritableDirectory => "the parent directory is writable by group or others",
            Self::WrongSize => "the seed file must contain exactly 32 bytes",
            Self::ReadFailed => "the seed could not be read completely",
            Self::UnsupportedPlatform => "protected seed loading is unavailable on this platform",
        })
    }
}
impl std::error::Error for KeyFileError {}

/// Opens a separate consensus seed, never an ADNL or wallet keyring entry.
#[cfg(unix)]
pub fn load_consensus_key(
    path: impl AsRef<Path>,
    expire_at: u32,
) -> Result<ConsensusKeyStore, Error> {
    use std::{
        ffi::CString,
        fs::{File, OpenOptions},
        io::Read,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{
                ffi::OsStrExt,
                fs::{MetadataExt, OpenOptionsExt},
            },
        },
    };
    use zeroize::Zeroizing;
    let path = path.as_ref();
    let name = path.file_name().ok_or(KeyFileError::CannotOpen)?;
    let name = CString::new(name.as_bytes()).map_err(|_| KeyFileError::CannotOpen)?;
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    // Keep the checked parent open and open the seed relative to that fd, so a
    // rename between the permission check and open cannot redirect the lookup.
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(parent)
        .map_err(|_| KeyFileError::CannotOpen)?;
    let directory_metadata = directory.metadata().map_err(|_| KeyFileError::CannotOpen)?;
    if directory_metadata.mode() & 0o022 != 0 {
        return Err(KeyFileError::WritableDirectory.into());
    }
    // SAFETY: live directory fd and NUL-terminated basename. Nonblocking avoids
    // waiting on a FIFO before fstat can reject it. No creation flags are used.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(KeyFileError::CannotOpen.into());
    }
    // SAFETY: openat returned a new owned descriptor, wrapped exactly once.
    let mut file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata().map_err(|_| KeyFileError::CannotOpen)?;
    if !metadata.is_file() {
        return Err(KeyFileError::NotRegular.into());
    }
    // SAFETY: geteuid has no inputs or memory effects.
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(KeyFileError::WrongOwner.into());
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(KeyFileError::GroupOrWorldAccess.into());
    }
    if metadata.len() != SEED_BYTES as u64 {
        return Err(KeyFileError::WrongSize.into());
    }
    let mut seed = Zeroizing::new([0; SEED_BYTES]);
    file.read_exact(seed.as_mut()).map_err(|_| KeyFileError::ReadFailed)?;
    let mut extra = Zeroizing::new([0; 1]);
    if file.read(extra.as_mut()).map_err(|_| KeyFileError::ReadFailed)? != 0 {
        return Err(KeyFileError::WrongSize.into());
    }
    // Also reject growth or permission changes observed while reading.
    let final_metadata = file.metadata().map_err(|_| KeyFileError::ReadFailed)?;
    if final_metadata.len() != metadata.len()
        || final_metadata.mode() != metadata.mode()
        || final_metadata.uid() != metadata.uid()
    {
        return Err(KeyFileError::ReadFailed.into());
    }
    ConsensusKeyStore::from_seed(seed.as_ref(), expire_at)
}

#[cfg(not(unix))]
pub fn load_consensus_key(_: impl AsRef<Path>, _: u32) -> Result<ConsensusKeyStore, Error> {
    Err(KeyFileError::UnsupportedPlatform.into())
}
