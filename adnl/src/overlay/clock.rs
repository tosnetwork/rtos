// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
use std::time::{SystemTime, UNIX_EPOCH};

/// Wall time for broadcast dates, source-certificate expiry and Plumtree messages.
/// Each overlay node owns its clock; one node cannot change another node's time.
/// Transport deadlines and rate-limit windows continue to use monotonic time.
pub trait BroadcastClock: Send + Sync {
    fn unix_seconds(&self) -> f64;
}

pub struct SystemBroadcastClock;
impl BroadcastClock for SystemBroadcastClock {
    fn unix_seconds(&self) -> f64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64())
    }
}
