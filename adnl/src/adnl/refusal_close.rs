// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0
//! Ordered refusal close, following TOS AdnlExtConnection::closing_loop.
use super::AdnlStream;
use crate::preauth::preauth_source;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Mutex, OnceLock},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const CHUNK: usize = 64 * 1024;
// TOS adnl-ext-limits.h: shared input allowance and one-eighth source share.
// These bound closing scratch space only, not all existing ADNL allocations.
const TOTAL: usize = 256 * 1024 * 1024;
const PER_SOURCE: usize = TOTAL / 8;
const DEADLINE: Duration = Duration::from_secs(2);

#[derive(Default)]
struct Usage {
    bytes: usize,
    sources: HashMap<SocketAddr, usize>,
}
struct Budget {
    total: usize,
    per_source: usize,
    usage: Mutex<Usage>,
}
impl Budget {
    fn new(total: usize, per_source: usize) -> Self {
        Self { total, per_source, usage: Mutex::new(Usage::default()) }
    }
    fn reserve(&self, source: SocketAddr) -> Option<Permit<'_>> {
        let mut usage = self.usage.lock().unwrap_or_else(|error| error.into_inner());
        let held = usage.sources.get(&source).copied().unwrap_or(0);
        if usage.bytes > self.total.saturating_sub(CHUNK)
            || held > self.per_source.saturating_sub(CHUNK)
            || self.total < CHUNK
            || self.per_source < CHUNK
        {
            return None;
        }
        usage.bytes += CHUNK;
        usage.sources.insert(source, held + CHUNK);
        Some(Permit { budget: self, source })
    }
}
struct Permit<'a> {
    budget: &'a Budget,
    source: SocketAddr,
}
impl Drop for Permit<'_> {
    fn drop(&mut self) {
        let mut usage = self.budget.usage.lock().unwrap_or_else(|error| error.into_inner());
        usage.bytes -= CHUNK;
        let held = usage.sources.get_mut(&self.source).expect("owned closing source");
        *held -= CHUNK;
        if *held == 0 {
            usage.sources.remove(&self.source);
        }
    }
}

impl AdnlStream {
    /// Preserve prior writes; discard without parsing, within one fixed deadline.
    /// Reserve process/source scratch credit before allocation. Exhaustion waits
    /// for credit within that same deadline, never resets it or allocates anyway.
    pub(crate) async fn close_after_refusal(&mut self) {
        static BUDGET: OnceLock<Budget> = OnceLock::new();
        self.close_with_budget(BUDGET.get_or_init(|| Budget::new(TOTAL, PER_SOURCE))).await;
    }
    async fn close_with_budget(&mut self, budget: &Budget) {
        let _ = tokio::time::timeout(DEADLINE, async {
            self.stream.as_mut().shutdown().await?;
            let source = preauth_source(self.stream.as_ref().get_ref().get_ref().peer_addr()?);
            let _permit = loop {
                if let Some(permit) = budget.reserve(source) {
                    break permit;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            };
            let mut discard = vec![0u8; CHUNK];
            loop {
                if self.stream.as_mut().read(&mut discard).await? == 0 {
                    return Ok::<(), std::io::Error>(());
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::Timeouts;
    use std::sync::Arc;
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn closing_budget_bounds_total_source_and_releases_credit() {
        let budget = Budget::new(2 * CHUNK, CHUNK);
        let a: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let b: SocketAddr = "127.0.0.2:0".parse().unwrap();
        let c: SocketAddr = "127.0.0.3:0".parse().unwrap();
        let first = budget.reserve(a).unwrap();
        assert!(budget.reserve(a).is_none());
        let second = budget.reserve(b).unwrap();
        assert!(budget.reserve(c).is_none());
        assert_eq!(budget.usage.lock().unwrap().bytes, 2 * CHUNK);
        drop(first);
        let third = budget.reserve(c).unwrap();
        drop((second, third));
        let usage = budget.usage.lock().unwrap();
        assert_eq!(usage.bytes, 0);
        assert!(usage.sources.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn closing_budget_exhaustion_keeps_deadline_and_other_source_progress() {
        let budget = Arc::new(Budget::new(2 * CHUNK, CHUNK));
        let source: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let held = budget.reserve(source).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (mut client, server) =
            tokio::try_join!(TcpStream::connect(listener.local_addr().unwrap()), async {
                listener.accept().await.map(|(s, _)| s)
            })
            .unwrap();
        let mut stream = AdnlStream::from_stream_with_timeouts(server, &Timeouts::default());
        stream.write(&mut vec![42; 1024]).await.unwrap();
        let task_budget = budget.clone();
        let start = std::time::Instant::now();
        let closing = tokio::spawn(async move { stream.close_with_budget(&task_budget).await });
        let mut reply = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, vec![42; 1024]);
        let other: SocketAddr = "127.0.0.2:0".parse().unwrap();
        let other_permit = budget.reserve(other).expect("busy source cannot consume other share");
        assert_eq!(budget.usage.lock().unwrap().bytes, 2 * CHUNK);
        tokio::time::timeout(Duration::from_secs(4), closing).await.unwrap().unwrap();
        assert!(start.elapsed() >= Duration::from_millis(1800));
        drop((held, other_permit));
        let usage = budget.usage.lock().unwrap();
        assert_eq!(usage.bytes, 0);
        assert!(usage.sources.is_empty());
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn closing_budget_returns_credit_on_eof_timeout_and_cancellation() {
        for finish in ["eof", "timeout", "cancel"] {
            let budget = Arc::new(Budget::new(CHUNK, CHUNK));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let (mut client, server) =
                tokio::try_join!(TcpStream::connect(listener.local_addr().unwrap()), async {
                    listener.accept().await.map(|(s, _)| s)
                })
                .unwrap();
            let mut stream = AdnlStream::from_stream_with_timeouts(server, &Timeouts::default());
            let task_budget = budget.clone();
            let closing = tokio::spawn(async move { stream.close_with_budget(&task_budget).await });
            tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    if budget.usage.lock().unwrap().bytes == CHUNK {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            match finish {
                "eof" => client.shutdown().await.unwrap(),
                "cancel" => closing.abort(),
                _ => {}
            }
            let result = tokio::time::timeout(Duration::from_secs(4), closing).await.unwrap();
            if finish == "cancel" {
                assert!(result.unwrap_err().is_cancelled());
            } else {
                result.unwrap();
            }
            let usage = budget.usage.lock().unwrap();
            assert_eq!(usage.bytes, 0, "{finish}");
            assert!(usage.sources.is_empty(), "{finish}");
        }
    }
}
