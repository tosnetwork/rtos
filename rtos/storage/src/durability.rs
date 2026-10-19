// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Optional observation/failure injection at real synchronization boundaries.
//! Returning Ok never bypasses the synchronization call that follows.
use rtos_block::Result;
use std::{path::Path, sync::Arc};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncPoint {
    File,
    Directory,
    Wal,
}
pub type SyncObserver = dyn Fn(SyncPoint, &Path) -> Result<()> + Send + Sync;
pub type SyncObservation = Option<Arc<SyncObserver>>;
#[cfg(test)]
pub(crate) type LateIndexGate = Arc<dyn Fn() -> Result<()> + Send + Sync>;
pub fn before(observer: Option<&SyncObserver>, point: SyncPoint, path: &Path) -> Result<()> {
    if let Some(observer) = observer {
        observer(point, path)?;
    }
    Ok(())
}

/// Test-only crash model for child-process crash-cut tests.
///
/// `RTOS_CRASH_BUFFERED_WAL=1` makes RocksDB providers opened by that process
/// keep unsynced WAL bytes in process memory (`manual_wal_flush`), so an abort
/// loses them as a power cut loses unsynced WAL. Other flush activity can still
/// write such bytes, and an abort leaves the filesystem cache intact, so this
/// models loss of buffered WAL only; it is not a complete power-loss model.
///
/// `RTOS_CRASH_CUT=<point>:<n>` aborts the process at the n-th (1-based)
/// arrival at the named cut point.
#[cfg(any(test, feature = "integration-test-support"))]
pub mod crash_model {
    use std::sync::{
        atomic::{AtomicU32, Ordering},
        OnceLock,
    };

    struct Armed {
        point: String,
        nth: u32,
        arrivals: AtomicU32,
    }

    fn armed() -> Option<&'static Armed> {
        static ARMED: OnceLock<Option<Armed>> = OnceLock::new();
        ARMED
            .get_or_init(|| {
                let spec = std::env::var("RTOS_CRASH_CUT").ok()?;
                let (point, nth) = spec.rsplit_once(':')?;
                let nth = nth.parse::<u32>().ok().filter(|nth| *nth > 0)?;
                Some(Armed { point: point.to_owned(), nth, arrivals: AtomicU32::new(0) })
            })
            .as_ref()
    }

    pub fn buffered_wal() -> bool {
        std::env::var_os("RTOS_CRASH_BUFFERED_WAL").is_some_and(|value| value == "1")
    }

    /// Abort the process here when this is the armed arrival at `point`.
    pub fn reach(point: &str) {
        let Some(armed) = armed() else { return };
        if armed.point != point {
            return;
        }
        let arrival = armed.arrivals.fetch_add(1, Ordering::SeqCst).saturating_add(1);
        if arrival == armed.nth {
            eprintln!("CRASH_CUT {point} {arrival}");
            std::process::abort();
        }
    }
}

/// Crash-cut hook; a no-op outside test builds.
#[inline]
pub fn crash_point(point: &str) {
    #[cfg(any(test, feature = "integration-test-support"))]
    crash_model::reach(point);
    #[cfg(not(any(test, feature = "integration-test-support")))]
    let _ = point;
}
