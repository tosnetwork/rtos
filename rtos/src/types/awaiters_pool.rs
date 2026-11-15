/*
 * RTOS project modifications (2026-10-10): naming and cancellation-safe operation ownership.
 * Copyright (C) 2019-2024 EverX. All Rights Reserved.
 * Modifications Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This file has been modified from its original version.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
#[cfg(feature = "telemetry")]
use crate::engine_traits::EngineTelemetry;
use crate::{
    engine_traits::EngineAlloc,
    error::{AuthPolicyRefused, NodeError},
};
use adnl::{
    common::{add_counted_object_to_map, CountedObject, Counter},
    declare_counted,
};
use rtos_block::{error, Result};
use std::{
    cmp::Ord,
    fmt::Display,
    hash::Hash,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
    time::Duration,
};

#[cfg(test)]
#[path = "tests/test_awaiters_pool.rs"]
mod tests;

#[cfg(test)]
#[path = "../tests/test_awaiters_pool_typed_errors.rs"]
mod typed_error_tests;

const OP_IDLE: u8 = 0;
const OP_STARTED: u8 = 1;
const OP_RETIRED: u8 = 2;

declare_counted!(
    struct OperationAwaiters<R> {
        state: AtomicU8,
        tx: tokio::sync::watch::Sender<Option<Result<R>>>,
        rx: tokio::sync::watch::Receiver<Option<Result<R>>>,
    }
);

impl<R: Clone> OperationAwaiters<R> {
    fn new(
        is_started: bool,
        #[cfg(feature = "telemetry")] telemetry: &Arc<EngineTelemetry>,
        allocated: &Arc<EngineAlloc>,
    ) -> Arc<Self> {
        let (tx, rx) = tokio::sync::watch::channel(None);
        let ret = Self {
            state: AtomicU8::new(if is_started { OP_STARTED } else { OP_IDLE }),
            tx,
            rx,
            counter: allocated.awaiters.clone().into(),
        };
        #[cfg(feature = "telemetry")]
        telemetry.awaiters.update(allocated.awaiters.load(Ordering::Relaxed));
        Arc::new(ret)
    }
}

// The error type is not Clone, so every observer of a published failure gets a
// reconstruction. Classifications that callers act on survive it; any other
// error keeps its message only, as before.
fn clone_published_error(error: &rtos_block::Error) -> rtos_block::Error {
    match error.downcast_ref::<AuthPolicyRefused>() {
        Some(refused) => refused.clone().into(),
        None => error!("{}", error),
    }
}

// Cancellation and panic must release an operation's ownership just like its
// ordinary completion. The closure borrows the exact entry, never only its key.
struct OperationCleanup<F: FnOnce()>(Option<F>);
impl<F: FnOnce()> Drop for OperationCleanup<F> {
    fn drop(&mut self) {
        if let Some(cleanup) = self.0.take() {
            cleanup();
        }
    }
}

pub struct AwaitersPool<I, R> {
    ops_awaiters: lockfree::map::Map<I, Arc<OperationAwaiters<R>>>,
    description: &'static str,
    #[cfg(feature = "telemetry")]
    telemetry: Arc<EngineTelemetry>,
    allocated: Arc<EngineAlloc>,
}

impl<I, R> AwaitersPool<I, R>
where
    I: Ord + Hash + Clone + Display,
    R: Clone,
{
    pub fn new(
        description: &'static str,
        #[cfg(feature = "telemetry")] telemetry: Arc<EngineTelemetry>,
        allocated: Arc<EngineAlloc>,
    ) -> Self {
        Self {
            ops_awaiters: lockfree::map::Map::new(),
            description,
            #[cfg(feature = "telemetry")]
            telemetry,
            allocated,
        }
    }

    pub async fn do_or_wait_with_owned_key(
        &self,
        id: I,
        wait_timeout_ms: Option<u64>,
        operation: impl futures::Future<Output = Result<R>>,
    ) -> Result<Option<R>> {
        self.do_or_wait(&id, wait_timeout_ms, operation).await
    }

    pub async fn do_or_wait(
        &self,
        id: &I,
        wait_timeout_ms: Option<u64>,
        operation: impl futures::Future<Output = Result<R>>,
    ) -> Result<Option<R>> {
        loop {
            if let Some(op_awaiters) = self.ops_awaiters.get(id) {
                let state = op_awaiters.1.state.compare_exchange(
                    OP_IDLE,
                    OP_STARTED,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                );
                if state.is_ok() {
                    return Some(self.do_operation(id, operation, &op_awaiters.1).await)
                        .transpose();
                } else if state == Err(OP_RETIRED) {
                    self.remove_matching(id, &op_awaiters.1);
                    continue;
                } else {
                    return self
                        .wait_operation(id, wait_timeout_ms, &op_awaiters.1, || Ok(false))
                        .await;
                }
            } else {
                let new_awaiters = OperationAwaiters::new(
                    true,
                    #[cfg(feature = "telemetry")]
                    &self.telemetry,
                    &self.allocated,
                );
                if add_counted_object_to_map(&self.ops_awaiters, id.clone(), || {
                    Ok(new_awaiters.clone())
                })? {
                    return Some(self.do_operation(id, operation, &new_awaiters).await).transpose();
                }
            }
        }
    }

    pub async fn wait(
        &self,
        id: &I,
        timeout_ms: Option<u64>,
        check_complete: impl Fn() -> Result<bool>,
    ) -> Result<Option<R>> {
        loop {
            if let Some(op_awaiters) = self.ops_awaiters.get(id) {
                return self.wait_operation(id, timeout_ms, &op_awaiters.1, check_complete).await;
            } else {
                let new_awaiters = OperationAwaiters::new(
                    false,
                    #[cfg(feature = "telemetry")]
                    &self.telemetry,
                    &self.allocated,
                );
                if add_counted_object_to_map(&self.ops_awaiters, id.clone(), || {
                    Ok(new_awaiters.clone())
                })? {
                    return self
                        .wait_operation(id, timeout_ms, &new_awaiters, check_complete)
                        .await;
                }
            }
        }
    }

    pub fn shunt(&self, id: &I, operation: impl Fn() -> Result<R>) -> Result<()> {
        if let Some(op_awaiters) = self.ops_awaiters.get(id) {
            let r = operation()?;
            self.finalize(id, &op_awaiters.1, Ok(r));
        }
        Ok(())
    }

    /// Publish the same successful external result to matching policies. Each
    /// finalize still removes only the exact operation instance it observed.
    pub fn shunt_matching(
        &self,
        matches: impl Fn(&I) -> bool,
        operation: impl FnOnce() -> Result<R>,
    ) -> Result<()> {
        let mut result = None;
        let mut operation = Some(operation);
        for entry in self.ops_awaiters.iter() {
            if matches(entry.key()) {
                if result.is_none() {
                    result = Some(operation.take().unwrap()()?);
                }
                self.finalize(entry.key(), entry.val(), Ok(result.as_ref().unwrap().clone()));
            }
        }
        Ok(())
    }

    pub async fn shunt_async(
        &self,
        id: &I,
        operation: impl futures::Future<Output = Result<R>>,
    ) -> Result<()> {
        if let Some(op_awaiters) = self.ops_awaiters.get(id) {
            let r = operation.await?;
            self.finalize(id, &op_awaiters.1, Ok(r));
        }
        Ok(())
    }

    fn finalize(&self, id: &I, op_awaiters: &OperationAwaiters<R>, value: Result<R>) -> bool {
        // A shunt and the original owner may finish concurrently. Keep the
        // first result and never remove a newer operation using the same key.
        let published = op_awaiters.tx.send_if_modified(|slot| {
            if slot.is_some() {
                false
            } else {
                *slot = Some(value);
                true
            }
        });
        self.remove_matching(id, op_awaiters);
        published
    }

    fn published_result(&self, op_awaiters: &OperationAwaiters<R>) -> Result<R> {
        match &*op_awaiters.rx.borrow() {
            Some(Ok(r)) => Ok(r.clone()),
            Some(Err(e)) => Err(clone_published_error(e)),
            None => Err(error!("{}: operation completed without a result", self.description)),
        }
    }

    fn remove_matching(&self, id: &I, op_awaiters: &OperationAwaiters<R>) {
        self.ops_awaiters
            .remove_with(id, |(_, current)| std::ptr::eq(current.as_ref(), op_awaiters));
    }

    async fn wait_operation(
        &self,
        id: &I,
        timeout_ms: Option<u64>,
        op_awaiters: &OperationAwaiters<R>,
        check_complete: impl Fn() -> Result<bool>,
    ) -> Result<Option<R>> {
        let mut rx = op_awaiters.rx.clone();
        let result = loop {
            // An externally completed idle registration has no result producer.
            // All attached readers must recheck their external state, including
            // those that subscribed before the registration left the map.
            if op_awaiters.state.load(Ordering::SeqCst) == OP_RETIRED {
                break Ok(None);
            }
            log::trace!("{}: wait_operation: waiting... {}", self.description, id);

            let result = if let Ok(result) =
                tokio::time::timeout(Duration::from_millis(1), rx.changed()).await
            {
                result
            } else if check_complete()? {
                // Operation might be done before calling `wait_operation` - check it and return
                break Ok(None);
            } else if let Some(timeout_ms) = timeout_ms {
                tokio::time::timeout(Duration::from_millis(timeout_ms), rx.changed())
                    .await
                    .map_err(|_| {
                        NodeError::Timeout(format!("{}: timeout {}", self.description, id))
                    })?
            } else {
                rx.changed().await
            };
            if result.is_err() {
                break Ok(None);
            }

            let r = match &*rx.borrow() {
                Some(Ok(r)) => Ok(Some(r.clone())),
                Some(Err(e)) => Err(clone_published_error(e)),
                None => continue,
            };
            log::trace!("{}: wait_operation: done {}", self.description, id);
            break r;
        };
        // Only retire a registration that has no operation owner. Removing an
        // active owner would allow a second writer for the same key. The CAS
        // also prevents a new owner from claiming an entry while it retires.
        if matches!(result, Ok(None))
            && op_awaiters
                .state
                .compare_exchange(OP_IDLE, OP_RETIRED, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            self.remove_matching(id, op_awaiters);
            // Wake every old subscriber without inventing a result or
            // cancelling an operation. Retired entries cannot have an owner.
            op_awaiters.tx.send_modify(|_| {});
        }
        result
    }

    async fn do_operation(
        &self,
        id: &I,
        operation: impl futures::Future<Output = Result<R>>,
        op_awaiters: &OperationAwaiters<R>,
    ) -> Result<R> {
        log::trace!("{}: do_operation: doing... {}", self.description, id);
        let mut rx = op_awaiters.rx.clone();
        let mut cleanup = OperationCleanup(Some(|| {
            self.finalize(
                id,
                op_awaiters,
                Err(error!("{}: operation cancelled {}", self.description, id)),
            );
        }));
        let result = tokio::select! {
            result = operation => {
                log::trace!("{}: do_operation: done {}", self.description, id);
                let r = match result {
                    Ok(ref r) => Ok(r.clone()),
                    Err(ref e) => Err(clone_published_error(e)),
                };
                if self.finalize(id, op_awaiters, r) {
                    result
                } else {
                    self.published_result(op_awaiters)
                }
            }
            _ = rx.changed() => {
                log::trace!("{}: do_operation: shunt {}", self.description, id);
                // Value already published to `tx` by the external `shunt`,
                // which also removed the entry — nothing to finalize here.
                self.published_result(op_awaiters)
            }
        };
        cleanup.0 = None;
        result
    }
}
