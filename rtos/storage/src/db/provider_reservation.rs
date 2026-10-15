// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Process-local exclusion for wrapper-managed writable databases. External
//! directory replacement while an operation is live is outside this guarantee.
use std::{
    fmt,
    fs::{self, File},
    io,
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard, OnceLock},
};

#[derive(Debug)]
pub enum ReservationError {
    Busy(PathBuf),
    IdentityChanged(PathBuf),
    UnsupportedIdentity,
    Poisoned,
    Exhausted,
    InvalidPath(PathBuf),
    Io(io::Error),
}
impl fmt::Display for ReservationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy(p) => write!(f, "Writable provider reservation busy: {}", p.display()),
            Self::IdentityChanged(p) => {
                write!(f, "Provider directory identity changed: {}", p.display())
            }
            Self::UnsupportedIdentity => {
                write!(f, "Stable provider directory identity is unsupported")
            }
            Self::Poisoned => write!(f, "Provider reservation registry poisoned"),
            Self::Exhausted => write!(f, "Provider reservation identifiers exhausted"),
            Self::InvalidPath(p) => write!(f, "Invalid provider directory: {}", p.display()),
            Self::Io(e) => fmt::Display::fmt(e, f),
        }
    }
}
impl std::error::Error for ReservationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}
impl From<io::Error> for ReservationError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
type Result<T> = std::result::Result<T, ReservationError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity {
    volume: u64,
    object: u128,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Intent {
    Open,
    Destroy,
}
struct Entry {
    token: u64,
    path: PathBuf,
    identity: Option<Identity>,
    intent: Intent,
}
#[derive(Default)]
struct Registry {
    next: u64,
    entries: Vec<Entry>,
}
static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
fn registry() -> &'static Mutex<Registry> {
    REGISTRY.get_or_init(Default::default)
}
fn lock_registry() -> Result<MutexGuard<'static, Registry>> {
    registry().lock().map_err(|_| ReservationError::Poisoned)
}

#[cfg(not(windows))]
fn component_eq(a: &std::ffi::OsStr, b: &std::ffi::OsStr) -> bool {
    a == b
}
#[cfg(windows)]
fn component_eq(a: &std::ffi::OsStr, b: &std::ffi::OsStr) -> bool {
    use std::os::windows::ffi::OsStrExt;
    let a: Vec<u16> = a.encode_wide().collect();
    let b: Vec<u16> = b.encode_wide().collect();
    let (Ok(an), Ok(bn)) = (i32::try_from(a.len()), i32::try_from(b.len())) else { return false };
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CompareStringOrdinal(
            a: *const u16,
            an: i32,
            b: *const u16,
            bn: i32,
            ignore_case: i32,
        ) -> i32;
    }
    // SAFETY: both buffers remain valid for their explicit lengths.
    unsafe { CompareStringOrdinal(a.as_ptr(), an, b.as_ptr(), bn, 1) == 2 }
}
fn ancestor(a: &Path, b: &Path) -> bool {
    let mut other = b.components();
    a.components().all(|part| {
        other.next().is_some_and(|value| component_eq(part.as_os_str(), value.as_os_str()))
    })
}
fn same_path(a: &Path, b: &Path) -> bool {
    ancestor(a, b) && ancestor(b, a)
}
fn conflicts(path: &Path, identity: Option<Identity>, intent: Intent, other: &Entry) -> bool {
    same_path(path, &other.path)
        || identity.is_some_and(|id| other.identity == Some(id))
        || ((intent == Intent::Destroy || other.intent == Intent::Destroy)
            && (ancestor(path, &other.path) || ancestor(&other.path, path)))
}

/// Resolve existing ancestors before reserving a possibly missing path. IO is
/// outside the registry lock; creation cannot occur until path intent exists.
fn normalize(path: &Path) -> Result<PathBuf> {
    let mut probe =
        if path.is_absolute() { path.to_path_buf() } else { std::env::current_dir()?.join(path) };
    let mut missing = Vec::new();
    loop {
        match fs::canonicalize(&probe) {
            Ok(mut canonical) => {
                for component in missing.into_iter().rev() {
                    canonical.push(component);
                }
                return Ok(canonical);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let component = probe
                    .file_name()
                    .ok_or_else(|| ReservationError::InvalidPath(path.to_path_buf()))?
                    .to_os_string();
                missing.push(component);
                if !probe.pop() {
                    return Err(ReservationError::InvalidPath(path.to_path_buf()));
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(unix)]
fn open_directory(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    Ok(fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(path)?)
}
#[cfg(windows)]
fn open_directory(path: &Path) -> Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    let file = fs::OpenOptions::new()
        .access_mode(0x80)
        .share_mode(7)
        .custom_flags(0x02000000)
        .open(path)?;
    if !file.metadata()?.is_dir() {
        return Err(ReservationError::InvalidPath(path.to_path_buf()));
    }
    Ok(file)
}
#[cfg(not(any(unix, windows)))]
fn open_directory(_: &Path) -> Result<File> {
    Err(ReservationError::UnsupportedIdentity)
}
#[cfg(unix)]
fn identity(file: &File) -> Result<Identity> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    Ok(Identity { volume: metadata.dev(), object: metadata.ino().into() })
}
#[cfg(windows)]
fn identity(file: &File) -> Result<Identity> {
    use std::os::windows::io::AsRawHandle;
    #[repr(C)]
    struct FileIdInfo {
        volume: u64,
        file_id: [u8; 16],
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandleEx(
            handle: *mut std::ffi::c_void,
            class: i32,
            output: *mut std::ffi::c_void,
            size: u32,
        ) -> i32;
    }
    let mut info = std::mem::MaybeUninit::<FileIdInfo>::uninit();
    // SAFETY: the directory handle is live and the output buffer has the exact
    // FILE_ID_INFO layout/size. FileIdInfo is information class 18.
    let success = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            18,
            info.as_mut_ptr().cast(),
            std::mem::size_of::<FileIdInfo>() as u32,
        )
    };
    if success == 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: successful API completion initialized the complete output.
    let info = unsafe { info.assume_init() };
    Ok(Identity { volume: info.volume, object: u128::from_le_bytes(info.file_id) })
}
#[cfg(not(any(unix, windows)))]
fn identity(_: &File) -> Result<Identity> {
    Err(ReservationError::UnsupportedIdentity)
}

struct PathIntent {
    token: u64,
}
impl PathIntent {
    fn reserve(path: PathBuf, intent: Intent) -> Result<Self> {
        let mut registry = lock_registry()?;
        if registry.entries.iter().any(|e| conflicts(&path, None, intent, e)) {
            return Err(ReservationError::Busy(path));
        }
        let token = registry.next.checked_add(1).ok_or(ReservationError::Exhausted)?;
        registry.next = token;
        registry.entries.push(Entry { token, path, identity: None, intent });
        Ok(Self { token })
    }
}
impl Drop for PathIntent {
    fn drop(&mut self) {
        registry()
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .entries
            .retain(|e| e.token != self.token);
    }
}

/// Existing-directory ownership for initial bootstrap inspection. Unlike the
/// recovery owner it retains ordinary configured aliases until root inspection.
pub(crate) struct BootstrapReservation(ProviderReservation);
impl BootstrapReservation {
    pub(crate) fn into_owner(self) -> ProviderReservation { self.0 }
}

pub(crate) struct ProviderReservation {
    // Registry exclusion ends only after the caller has closed native resources.
    // The pinned directory stays alive until after exclusion is unregistered.
    slot: PathIntent,
    directory: File,
    requested: PathBuf,
    path: PathBuf,
    identity: Identity,
    strict_existing: bool,
}
impl ProviderReservation {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let canonical = normalize(path)?;
        let slot = PathIntent::reserve(canonical.clone(), Intent::Open)?;
        fs::create_dir_all(&canonical)?;
        Self::finish(slot, path, canonical)
    }
    /// Reserve an existing directory without creating it or resolving through
    /// symlinks. The resulting owner must outlive native DB open/close.
    pub(crate) fn open_existing(path: &Path) -> Result<Self> {
        Self::check_existing_path(&if path.is_absolute() { path.to_path_buf() }
            else { std::env::current_dir()?.join(path) })?;
        let mut owner = Self::inspect_existing(path)?.into_owner();
        owner.require_strict_path()?;
        Ok(owner)
    }
    /// No creation or cleanup. The requested alias remains part of verification
    /// so changing its target cannot silently switch the owned provider.
    pub(crate) fn inspect_existing(path: &Path) -> Result<BootstrapReservation> {
        let canonical = fs::canonicalize(path)?;
        let slot = PathIntent::reserve(canonical.clone(), Intent::Open)?;
        Ok(BootstrapReservation(Self::finish(slot, path, canonical)?))
    }
    pub(crate) fn require_strict_path(&mut self) -> Result<()> {
        Self::check_existing_path(&self.requested)?;
        self.strict_existing = true;
        self.verify()
    }
    fn check_existing_path(path: &Path) -> Result<()> {
        let mut prefix = PathBuf::new();
        for component in path.components() {
            if matches!(component, std::path::Component::ParentDir) {
                return Err(ReservationError::InvalidPath(path.to_path_buf()));
            }
            prefix.push(component.as_os_str());
            let metadata = fs::symlink_metadata(&prefix)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(ReservationError::InvalidPath(prefix));
            }
        }
        Ok(())
    }
    pub(crate) fn verify_existing(&self) -> Result<()> {
        if !self.strict_existing { return Err(ReservationError::InvalidPath(self.requested.clone())); }
        self.verify()
    }
    pub(crate) fn destroy(path: &Path) -> Result<Option<Self>> {
        let canonical = normalize(path)?;
        let slot = PathIntent::reserve(canonical.clone(), Intent::Destroy)?;
        match fs::symlink_metadata(path) {
            Ok(_) => Self::finish(slot, path, canonical).map(Some),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
    fn finish(slot: PathIntent, requested: &Path, path: PathBuf) -> Result<Self> {
        let directory = open_directory(&path)?;
        let id = identity(&directory)?;
        let requested = if requested.is_absolute() {
            requested.to_path_buf()
        } else {
            std::env::current_dir()?.join(requested)
        };
        let actual = fs::canonicalize(&requested)?;
        if !same_path(&actual, &path) {
            return Err(ReservationError::IdentityChanged(requested));
        }
        {
            let mut registry = lock_registry()?;
            let intent = registry
                .entries
                .iter()
                .find(|e| e.token == slot.token)
                .ok_or(ReservationError::Poisoned)?
                .intent;
            if registry
                .entries
                .iter()
                .any(|e| e.token != slot.token && conflicts(&path, Some(id), intent, e))
            {
                return Err(ReservationError::Busy(path));
            }
            registry
                .entries
                .iter_mut()
                .find(|e| e.token == slot.token)
                .ok_or(ReservationError::Poisoned)?
                .identity = Some(id);
        }
        let result = Self { slot, directory, requested, path, identity: id, strict_existing: false };
        result.verify()?;
        Ok(result)
    }
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
    pub(crate) fn verify(&self) -> Result<()> {
        if self.strict_existing { Self::check_existing_path(&self.requested)?; }
        let actual = fs::canonicalize(&self.requested)
            .map_err(|_| ReservationError::IdentityChanged(self.requested.clone()))?;
        if !same_path(&actual, &self.path) || identity(&self.directory)? != self.identity {
            return Err(ReservationError::IdentityChanged(self.requested.clone()));
        }
        let current = open_directory(&self.path)?;
        if identity(&current)? != self.identity {
            return Err(ReservationError::IdentityChanged(self.path.clone()));
        }
        Ok(())
    }
    pub(crate) fn begin_destroy(&self) -> Result<()> {
        self.verify()?;
        let mut registry = lock_registry()?;
        if registry.entries.iter().any(|e| {
            e.token != self.slot.token
                && conflicts(&self.path, Some(self.identity), Intent::Destroy, e)
        }) {
            return Err(ReservationError::Busy(self.path.clone()));
        }
        registry
            .entries
            .iter_mut()
            .find(|e| e.token == self.slot.token)
            .ok_or(ReservationError::Poisoned)?
            .intent = Intent::Destroy;
        Ok(())
    }
    /// Native destroy may already remove the directory. Never remove a new
    /// directory inode that subsequently appears at the reserved pathname.
    pub(crate) fn remove_directory_if_present(&self) -> Result<()> {
        match fs::symlink_metadata(&self.path) {
            Ok(_) => {
                self.verify()?;
                fs::remove_dir_all(&self.path)?;
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

#[cfg(test)]
#[path = "../tests/test_provider_reservation.rs"]
mod tests;

#[cfg(test)]
struct CleanupGate {
    entered: tokio::sync::oneshot::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
    finished: tokio::sync::oneshot::Sender<()>,
}
#[cfg(test)]
static CLEANUP_GATES: OnceLock<Mutex<std::collections::HashMap<PathBuf, CleanupGate>>> =
    OnceLock::new();
#[cfg(test)]
pub(crate) struct CleanupCompletion(Option<tokio::sync::oneshot::Sender<()>>);
#[cfg(test)]
impl Drop for CleanupCompletion {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}
#[cfg(test)]
pub(crate) fn test_pause_cleanup(path: &Path) -> Option<CleanupCompletion> {
    let gate = CLEANUP_GATES.get_or_init(Default::default).lock().unwrap().remove(path);
    gate.map(|gate| {
        let completion = CleanupCompletion(Some(gate.finished));
        let _ = gate.entered.send(());
        gate.release
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("cleanup owner was not released");
        completion
    })
}
