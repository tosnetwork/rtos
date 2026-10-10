// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later

use super::tasks::QuicTasks;
use std::{future::Future, pin::Pin, sync::Arc};

/// Quinn's endpoint and connection drivers must outlive application draining,
/// but must themselves be joined before the socket is reported released.
pub(super) struct OwnedRuntime(pub Arc<QuicTasks>);

impl std::fmt::Debug for OwnedRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OwnedQuicRuntime")
    }
}

impl quinn::Runtime for OwnedRuntime {
    fn new_timer(&self, instant: std::time::Instant) -> Pin<Box<dyn quinn::AsyncTimer>> {
        quinn::Runtime::new_timer(&quinn::TokioRuntime, instant)
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        self.0.spawn("Quinn driver", future);
    }

    fn wrap_udp_socket(
        &self,
        socket: std::net::UdpSocket,
    ) -> std::io::Result<Arc<dyn quinn::AsyncUdpSocket>> {
        quinn::Runtime::wrap_udp_socket(&quinn::TokioRuntime, socket)
    }
}
