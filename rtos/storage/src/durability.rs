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
pub fn before(observer: Option<&SyncObserver>, point: SyncPoint, path: &Path) -> Result<()> {
    if let Some(observer) = observer {
        observer(point, path)?;
    }
    Ok(())
}
