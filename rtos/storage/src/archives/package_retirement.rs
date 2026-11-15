// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Idle writer retirement. Uncertain closes retain their provider until restart.
use super::*;
use std::sync::Mutex;

const QUARANTINE_CAPACITY: usize = 64;
struct Quarantine {
    slots: Mutex<[Option<Arc<dyn Send + Sync>>; QUARANTINE_CAPACITY]>,
    restart: AtomicBool,
}
impl Quarantine {
    const fn new() -> Self {
        Self {
            slots: Mutex::new([const { None }; QUARANTINE_CAPACITY]),
            restart: AtomicBool::new(false),
        }
    }
    fn reserve<T: Send + Sync + 'static>(&self, state: &Arc<T>) -> Result<Reservation<'_>> {
        if self.restart.load(Ordering::Acquire) {
            fail!("Package close requires process restart");
        }
        let mut slots = self.slots.lock().map_err(|_| {
            self.restart.store(true, Ordering::Release);
            error!("Package close quarantine poisoned")
        })?;
        if self.restart.load(Ordering::Acquire) {
            fail!("Package close requires process restart");
        }
        let Some(index) = slots.iter().position(Option::is_none) else {
            self.restart.store(true, Ordering::Release);
            fail!("Package close quarantine is full; process restart required");
        };
        slots[index] = Some(state.clone());
        Ok(Reservation { quarantine: self, index, complete: false })
    }
}
static QUARANTINE: Quarantine = Quarantine::new();
pub(super) fn restart_required() -> bool {
    QUARANTINE.restart.load(Ordering::Acquire)
}

// Reservation precedes taking the actual file. An error or unwind leaves a
// strong provider pin in a preallocated process slot; there is no retry/drop of
// an ambiguous raw descriptor. The global slots never drain during shutdown.
pub(in crate::archives) struct Reservation<'a> {
    quarantine: &'a Quarantine,
    index: usize,
    complete: bool,
}
impl Reservation<'_> {
    pub(in crate::archives) fn complete(mut self) {
        let retained =
            self.quarantine.slots.lock().unwrap_or_else(|e| e.into_inner())[self.index].take();
        self.complete = true;
        drop(retained);
    }
}
impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.quarantine.restart.store(true, Ordering::Release);
        }
    }
}

impl PackageState {
    pub(in crate::archives) fn retire_native(self: &Arc<Self>) -> Result<bool> {
        self.retire_with(&QUARANTINE)
    }
    fn retire_with(self: &Arc<Self>, quarantine: &Quarantine) -> Result<bool> {
        // Called only by a drained RecoveryExecution native phase. This lock
        // is outside the registry mutex and retains the exact writer identity.
        let mut writer = self.write_mutex.clone().blocking_lock_owned();
        if self.retired.load(Ordering::Acquire) {
            return Ok(false);
        }
        #[cfg(not(target_os = "linux"))]
        if writer.is_some() {
            fail!("Observable package close retirement requires Linux");
        }
        let reservation = quarantine.reserve(self)?;
        self.retired.store(true, Ordering::Release);
        #[cfg(test)]
        if let Some(probe) = self.retirement_probe.lock().unwrap().take() {
            probe.started.send(()).map_err(|e| error!("Retirement probe receiver: {e}"))?;
            probe.release.recv_timeout(std::time::Duration::from_secs(10))?;
        }
        let had_file = writer.is_some();
        #[cfg(target_os = "linux")]
        if let Some(file) = writer.take() {
            close_once(file)?;
            #[cfg(test)]
            if self.fail_retirement_close.swap(false, Ordering::AcqRel) {
                fail!("Injected uncertain result after actual close");
            }
        }
        reservation.complete();
        Ok(had_file)
    }
}

#[cfg(target_os = "linux")]
fn close_once(file: std::fs::File) -> Result<()> {
    use std::os::fd::IntoRawFd;
    unsafe extern "C" {
        fn close(fd: std::ffi::c_int) -> std::ffi::c_int;
    }
    let fd = file.into_raw_fd();
    // SAFETY: sole ownership was transferred into this function. Linux close
    // is attempted once, including EINTR; the descriptor may already be reused.
    if unsafe { close(fd) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
#[path = "../tests/test_package_retirement.rs"]
mod tests;

pub(in crate::archives) fn reserve_resources<T: Send + Sync + 'static>(
    owner: &Arc<T>,
) -> Result<Reservation<'static>> {
    QUARANTINE.reserve(owner)
}
