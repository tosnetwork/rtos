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
        self.0.spawn_cancelable("Quinn driver", future);
    }

    fn wrap_udp_socket(
        &self,
        socket: std::net::UdpSocket,
    ) -> std::io::Result<Arc<dyn quinn::AsyncUdpSocket>> {
        quinn::Runtime::wrap_udp_socket(&quinn::TokioRuntime, socket)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_util::sync::CancellationToken;

    struct Dropped(tokio::sync::oneshot::Sender<()>);

    impl Drop for Dropped {
        fn drop(&mut self) {
            let (unused, _) = tokio::sync::oneshot::channel();
            let _ = std::mem::replace(&mut self.0, unused).send(());
        }
    }

    #[tokio::test]
    async fn quic_owned_driver_shutdown_joins_a_driver_that_never_becomes_idle() {
        let owner = QuicTasks::new(tokio::runtime::Handle::current(), CancellationToken::new());
        let (entered, started) = tokio::sync::oneshot::channel();
        let (dropped, finished) = tokio::sync::oneshot::channel();
        quinn::Runtime::spawn(
            &OwnedRuntime(owner.clone()),
            Box::pin(async move {
                let _drop = Dropped(dropped);
                entered.send(()).unwrap();
                std::future::pending::<()>().await;
            }),
        );
        started.await.unwrap();
        owner.close();
        tokio::time::timeout(std::time::Duration::from_secs(1), owner.wait())
            .await
            .unwrap()
            .unwrap();
        // A completed supervisor must mean the actual driver future was dropped.
        finished.await.unwrap();
        owner.wait().await.unwrap();
    }
}
