// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Tracks actual archive operation and queued metadata owners through shutdown.
use rtos_block::{error, Result};
use std::sync::Mutex;
use tokio_util::task::{task_tracker::TaskTrackerToken, TaskTracker};

pub struct ArchiveIoOwners {
    open: Mutex<bool>,
    tracker: TaskTracker,
}
impl Default for ArchiveIoOwners {
    fn default() -> Self {
        Self { open: Mutex::new(true), tracker: TaskTracker::new() }
    }
}
impl ArchiveIoOwners {
    pub fn enter(&self) -> Result<ArchiveIoTicket> {
        let open = self.open.lock().map_err(|_| error!("Archive IO admission poisoned"))?;
        if !*open {
            return Err(error!("Archive IO admission stopped"));
        }
        Ok(ArchiveIoTicket { _token: self.tracker.token() })
    }
    pub fn close(&self) {
        // Even an unexpected poisoned admission lock must not reopen entry.
        let mut open = self.open.lock().unwrap_or_else(|error| error.into_inner());
        *open = false;
        self.tracker.close();
    }
    pub async fn wait(&self) {
        self.close();
        self.tracker.wait().await;
    }
    pub fn outstanding(&self) -> usize {
        self.tracker.len()
    }
}

/// A real owner may transfer clones to its children even after root admission
/// closes. The parent exists until a clone is registered, preventing a false
/// zero-owner interval. An idle cached descriptor must never retain this ticket.
#[derive(Clone)]
pub struct ArchiveIoTicket {
    _token: TaskTrackerToken,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn closing_preserves_admitted_children_and_cancelled_waiters() {
        let owners = ArchiveIoOwners::default();
        let parent = owners.enter().unwrap();
        owners.close();
        assert!(owners.enter().is_err());
        let child = parent.clone();
        drop(parent);
        assert_eq!(owners.outstanding(), 1);
        let mut wait = Box::pin(owners.wait());
        assert!(futures::poll!(&mut wait).is_pending());
        drop(wait);
        assert_eq!(owners.outstanding(), 1);
        drop(child);
        owners.wait().await;
        owners.wait().await;
        assert_eq!(owners.outstanding(), 0);
        assert!(owners.enter().is_err());
    }
}
