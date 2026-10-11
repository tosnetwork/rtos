/*
 * RTOS project modifications (2026-10-10): project and crate naming.
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
//! # `SessionCallbacks` entity
//!
//! Per-session callback delivery aspect. Owns the listener-notification
//! transport — the `SXCB` callback worker thread (when
//! `use_callback_thread=true`), the boxed `CallbackTaskQueuePtr`, the
//! `use_callback_thread` flag, the `stop_flag`-driven shutdown
//! suppression gate, and the four `notify_*` wrappers
//! (`notify_candidate`, `notify_candidate_observed`,
//! `notify_generate_slot`, `notify_block_finalized`). Pairs with
//! [`SessionRuntime`](crate::session_runtime::SessionRuntime), which
//! owns the cross-controller state.
//!
//! ## Boundary
//!
//! `SessionCallbacks` owns the callback-side data only. It does NOT
//! call back into `SessionProcessor` or controllers: every public
//! entry point takes the `SessionListenerPtr` weak handle plus a
//! pre-built payload and dispatches the listener method either
//! synchronously (when `use_callback_thread=false`) or via the SXCB
//! task queue.
//!
//! Callers (`SessionProcessor`, `SessionImpl`) keep an
//! `Arc<SessionCallbacks>` so the aspect outlives the main loop and
//! the worker thread can be torn down in the correct order.

use crate::{
    task_queue::{post_callback_closure, CallbackTaskQueuePtr},
    AsyncCollationRequestPtr, BlockHash, BlockPayloadPtr, BlockSourceInfo, MetricsHandle,
    PublicKeyHash, SessionId, SessionListenerPtr, ValidatorBlockCandidateCallback,
    ValidatorBlockCandidateDecisionCallback,
};
use consensus_common::{check_execution_time, CandidateObservedFlags, CollationParentHint};
use rtos_block::BlockIdExt;
#[cfg(test)]
use rtos_block::BlockSignaturesVariant;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, SystemTime},
};

/// Per-session callback delivery aspect.
///
/// Held as `Arc<SessionCallbacks>` by both `SessionImpl` (so the worker
/// thread can be spawned/joined alongside the rest of the session
/// teardown) and `SessionProcessor::callbacks` (so the `notify_*`
/// wrappers can dispatch without going through the main
/// `SessionProcessor` borrow).
pub(crate) struct SessionCallbacks {
    /// Session identifier; used purely for log records.
    session_id: SessionId,
    /// Shared shutdown flag. When set (validator-group rotation, e.g.
    /// new MC validator set), every callback invocation is silently
    /// suppressed so the listener never sees events from an old
    /// session.
    stop_flag: Arc<AtomicBool>,
    /// When `true`, callbacks are dispatched onto the `SXCB` worker via
    /// `task_queue`; when `false`, they execute synchronously on the
    /// calling (`SXMAIN`) thread.
    use_callback_thread: bool,
    /// Crossbeam-backed transport into the `SXCB` worker. Kept here as
    /// `Arc` so the worker thread (spawned by `SessionImpl::create`)
    /// holds an independent clone and the queue's `flush()` can run on
    /// shutdown.
    task_queue: CallbackTaskQueuePtr,
    /// Weak handle to the higher-layer session listener. Stored here so
    /// every `notify_*` wrapper can dispatch without the caller threading
    /// the listener through per call (mirrors how the receiver holds its
    /// own listener handle). Weak so callbacks never keep the
    /// validator-group alive past session teardown; each dispatch
    /// re-checks `upgrade()` and silently drops when the listener is gone.
    listener: SessionListenerPtr,
    delivery_sink: Option<consensus_common::finality_delivery::DurableFinalitySinkPtr>,
    source_delivery: Arc<std::sync::Mutex<Option<Arc<crate::finality_delivery::SourceFinalityDelivery>>>>,
}

/// The main worker owns the live source slot. Stopped SessionImpl/listener
/// clones share this slot and cannot prolong its file lock. Accepted node work
/// retains its own SourceFinalityDelivery Arc until completion.
pub(crate) struct SourceDeliveryLifetime(
    Arc<std::sync::Mutex<Option<Arc<crate::finality_delivery::SourceFinalityDelivery>>>>,
);
impl Drop for SourceDeliveryLifetime {
    fn drop(&mut self) { self.0.lock().unwrap().take(); }
}

// ======================================================================
// Construction & dispatch
// ======================================================================
// Build the aspect (plus the test-only listener swap), expose the
// callback-thread flag, and the private `invoke` primitive that
// suppresses-on-shutdown and routes sync vs SXCB-queue dispatch.
impl SessionCallbacks {
    /// Construct a fresh callbacks aspect.
    ///
    /// `listener` is the weak handle to the higher-layer session listener;
    /// it is stored so the `notify_*` wrappers can dispatch without the
    /// caller passing it per call.
    pub(crate) fn new(
        session_id: SessionId,
        stop_flag: Arc<AtomicBool>,
        use_callback_thread: bool,
        task_queue: CallbackTaskQueuePtr,
        listener: SessionListenerPtr,
    ) -> Self {
        Self { session_id, stop_flag, use_callback_thread, task_queue, listener, delivery_sink: None, source_delivery: Arc::new(std::sync::Mutex::new(None)) }
    }

    pub(crate) fn with_delivery_sink(mut self, sink: Option<consensus_common::finality_delivery::DurableFinalitySinkPtr>) -> Self {
        self.delivery_sink = sink;
        self
    }

    pub(crate) fn delivery_lifetime(&self) -> SourceDeliveryLifetime {
        SourceDeliveryLifetime(self.source_delivery.clone())
    }

    pub(crate) fn initialize_delivery(&self, runtime: Arc<consensus_common::session_runtime::AuthenticatedSessionRuntime>, namespace: &std::path::Path) -> rtos_block::Result<()> {
        let sink = self.delivery_sink.clone().ok_or_else(|| rtos_block::error!("Missing durable sink"))?;
        let source = crate::finality_delivery::SourceFinalityDelivery::open(runtime, namespace, sink)?;
        let mut slot = self.source_delivery.lock().unwrap();
        if slot.is_some() { return Err(rtos_block::error!("Source delivery already initialized")); }
        *slot = Some(source);
        Ok(())
    }

    fn delivery_source(&self) -> rtos_block::Result<Arc<crate::finality_delivery::SourceFinalityDelivery>> {
        self.source_delivery.lock().unwrap().clone().ok_or_else(|| rtos_block::error!("Source delivery not initialized"))
    }
    pub(crate) fn bind_delivery_start(&self, anchor: BlockIdExt) -> rtos_block::Result<()> { self.delivery_source()?.bind_start(anchor) }
    pub(crate) fn retain_finality_intent(&self, prevs: Vec<BlockIdExt>, event: &crate::simplex_state::BlockFinalizedEvent) -> rtos_block::Result<()> {
        self.delivery_source()?.retain_intent(prevs, event)
    }
    pub(crate) fn resolve_finality_intent(&self, id: &crate::block::RawCandidateId) -> rtos_block::Result<()> {
        self.delivery_source()?.resolve_intent(id)
    }
    pub(crate) fn pending_finality_intents(&self) -> rtos_block::Result<Vec<Vec<u8>>> { self.delivery_source()?.pending_intents() }

    pub(crate) fn poll_durable_finality(&self, draft: consensus_common::finality_delivery::FinalizedDeliveryDraft) -> rtos_block::Result<bool> {
        let source = self.source_delivery.lock().unwrap().clone().ok_or_else(|| rtos_block::error!("Source delivery not initialized"))?;
        if let Some((id, draft)) = source.poll(draft)? {
            let listener = self.listener.clone();
            self.invoke(move || { if let Some(listener) = listener.upgrade() { listener.on_durable_block_finalized(id, draft); } });
            Ok(true)
        } else { Ok(false) }
    }

    /// Clone this callbacks aspect with a different session listener.
    ///
    /// Test-only seam. Production sets the listener once at construction;
    /// tests build a processor with a placeholder listener and later swap
    /// in a recording listener via `SessionProcessor::set_listener_for_test`,
    /// which rebuilds the shared `Arc<SessionCallbacks>` through this
    /// method. The queue/flag handles are cheap `Arc` clones.
    #[cfg(test)]
    pub(crate) fn with_listener(&self, listener: SessionListenerPtr) -> Self {
        Self {
            session_id: self.session_id.clone(),
            stop_flag: self.stop_flag.clone(),
            use_callback_thread: self.use_callback_thread,
            task_queue: self.task_queue.clone(),
            listener,
            delivery_sink: self.delivery_sink.clone(),
            source_delivery: self.source_delivery.clone(),
        }
    }

    /// Whether callbacks are dispatched onto the `SXCB` worker.
    ///
    /// `SessionImpl::create` reads this to decide whether to spawn the
    /// callback thread.
    pub(crate) fn use_callback_thread(&self) -> bool {
        self.use_callback_thread
    }

    /// Invoke a listener-bound closure.
    ///
    /// When `use_callback_thread=true`, the closure is posted onto the
    /// `SXCB` worker via `task_queue.post_closure(...)`; when
    /// `use_callback_thread=false`, it executes synchronously on the
    /// calling (`SXMAIN`) thread.
    ///
    /// Suppresses the closure when `stop_flag` is set (session
    /// shutdown). This prevents notifying the validator-group about
    /// events from an old session after MC rotation has installed a
    /// new validator set.
    fn invoke<F>(&self, callback: F)
    where
        F: FnOnce() + Send + 'static,
    {
        if self.stop_flag.load(Ordering::Relaxed) {
            log::trace!(
                "Session {} invoke_session_callback: suppressed during shutdown",
                self.session_id.to_hex_string()
            );
            return;
        }

        if self.use_callback_thread {
            post_callback_closure(&self.task_queue, callback);
        } else {
            callback();
        }
    }
}

// ======================================================================
// Listener notifications
// ======================================================================
// The four `notify_*` wrappers (candidate, candidate-observed,
// generate-slot, block-finalized). Each clones the weak listener and
// dispatches a pre-built payload through `invoke`.
impl SessionCallbacks {
    /// Notify listener about a block candidate for validation.
    ///
    /// Called when a block broadcast is received and the candidate
    /// needs to be validated against the validator-side state.
    pub(crate) fn notify_candidate(
        &self,
        source_info: BlockSourceInfo,
        root_hash: BlockHash,
        data: BlockPayloadPtr,
        collated_data: BlockPayloadPtr,
        callback: ValidatorBlockCandidateDecisionCallback,
    ) {
        check_execution_time!(20_000);

        log::trace!(
            "Session {} notify_candidate: posting on_candidate event for root_hash={:x}",
            self.session_id.to_hex_string(),
            root_hash
        );

        let listener = self.listener.clone();
        self.invoke(move || {
            check_execution_time!(20_000);

            if let Some(listener) = listener.upgrade() {
                log::trace!("SessionCallbacks::notify_candidate: on_candidate start");

                listener.on_candidate(source_info, root_hash, data, collated_data, callback);

                log::trace!("SessionCallbacks::notify_candidate: on_candidate finish");
            }
        });
    }

    pub(crate) fn notify_authenticated_candidate(
        &self,
        evidence: consensus_common::CandidateAuthenticationEvidence,
    ) {
        let listener = self.listener.clone();
        self.invoke(move || {
            if let Some(listener) = listener.upgrade() {
                listener.on_authenticated_candidate(evidence);
            }
        });
    }

    /// Notify listener that a candidate has been observed (with
    /// parent/body/local flags) so the validator-side state resolver
    /// cache can race against `engine.wait_state()`.
    pub(crate) fn notify_candidate_observed(
        &self,
        block_id: BlockIdExt,
        data: BlockPayloadPtr,
        collated_data: BlockPayloadPtr,
        flags: CandidateObservedFlags,
    ) {
        check_execution_time!(20_000);

        log::trace!(
            "Session {} notify_candidate_observed: block_id={} parent_ready={} local_collated={} body_present={}",
            self.session_id.to_hex_string(),
            block_id,
            flags.parent_ready,
            flags.local_collated,
            flags.body_present,
        );
        log::info!(
            target: "simplex_resolver",
            "SessionCallbacks::notify_candidate_observed session_id={} block_id={} parent_ready={} local_collated={} body_present={}",
            self.session_id.to_hex_string(),
            block_id,
            flags.parent_ready,
            flags.local_collated,
            flags.body_present,
        );

        let listener = self.listener.clone();
        self.invoke(move || {
            check_execution_time!(20_000);

            if let Some(listener) = listener.upgrade() {
                listener.on_candidate_observed(block_id, data, collated_data, flags);
            }
        });
    }

    /// Notify listener that this validator should generate a block for
    /// the given slot.
    ///
    /// The caller pre-builds `parent_hint` (explicit vs. implicit)
    /// using session state; this aspect performs only the closure
    /// dispatch.
    pub(crate) fn notify_generate_slot(
        &self,
        source_info: BlockSourceInfo,
        request: AsyncCollationRequestPtr,
        parent_hint: CollationParentHint,
        callback: ValidatorBlockCandidateCallback,
    ) {
        check_execution_time!(20_000);

        log::trace!(
            "Session {} notify_generate_slot: posting on_generate_slot event",
            self.session_id.to_hex_string()
        );

        let listener = self.listener.clone();
        self.invoke(move || {
            check_execution_time!(20_000);

            if let Some(listener) = listener.upgrade() {
                log::trace!("SessionCallbacks::notify_generate_slot: on_generate_slot start");

                listener.on_generate_slot(source_info, request, parent_hint, callback);

                log::trace!("SessionCallbacks::notify_generate_slot: on_generate_slot finish");
            }
        });
    }

    /// Notify listener that a block has been finalized.
    ///
    /// The caller pre-builds `signatures_variant` (this requires
    /// session state — total-weight threshold, raw-signature parsing —
    /// that does not belong to the callback aspect); this aspect
    /// performs only the closure dispatch.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn notify_block_finalized(
        &self,
        block_id: BlockIdExt,
        source_info: BlockSourceInfo,
        root_hash: BlockHash,
        file_hash: BlockHash,
        data: BlockPayloadPtr,
        signatures_variant: consensus_common::SessionFinality,
        approve_signatures: Vec<(PublicKeyHash, BlockPayloadPtr)>,
    ) {
        check_execution_time!(20_000);

        log::trace!(
            "Session {} notify_block_finalized: posting for block_id={}",
            self.session_id.to_hex_string(),
            block_id,
        );

        let listener = self.listener.clone();
        self.invoke(move || {
            check_execution_time!(20_000);

            if let Some(listener) = listener.upgrade() {
                listener.on_block_finalized(
                    block_id,
                    source_info,
                    root_hash,
                    file_hash,
                    data,
                    signatures_variant,
                    approve_signatures,
                );
            }
        });
    }
}

// ======================================================================
// SXCB worker loop
// ======================================================================
// The callback-thread main loop: pull + execute queued listener closures
// until stopped, then flush and signal stopped. Only spawned when
// `use_callback_thread=true`.
impl SessionCallbacks {
    /// Run the `SXCB` worker loop.
    ///
    /// Pulls callback closures from `task_queue` and executes them on
    /// the caller's thread (which `SessionImpl::create` spawns as the
    /// `SXCB:{session_id}` thread). The loop exits when
    /// `should_stop_flag` is set, then flushes any remaining tasks and
    /// stores `true` into `is_stopped_flag` so the parent can join.
    ///
    /// Only called when `use_callback_thread=true`. When the flag is
    /// `false`, callbacks run inline in the calling (`SXMAIN`) thread
    /// and this loop is never spawned.
    pub(crate) fn run_worker_loop(
        &self,
        should_stop_flag: Arc<AtomicBool>,
        is_stopped_flag: Arc<AtomicBool>,
        metrics_receiver: MetricsHandle,
    ) {
        log::info!(
            "SimplexSession callbacks processing loop is started (session_id is {})",
            self.session_id.to_hex_string()
        );

        let activity_node = consensus_common::ConsensusCommonFactory::create_activity_node(
            format!("SimplexCallbacks_{}", self.session_id.to_hex_string()),
        );

        let loop_counter =
            metrics_receiver.sink().register_counter(&"simplex_callbacks_loop_iterations".into());
        let loop_overloads_counter =
            metrics_receiver.sink().register_counter(&"simplex_callbacks_loop_overloads".into());

        let mut last_warn_dump_time = SystemTime::now();

        loop {
            activity_node.tick();
            loop_counter.increment(1);

            if should_stop_flag.load(Ordering::Relaxed) {
                break;
            }

            if self.task_queue.is_overloaded() {
                loop_overloads_counter.increment(1);
            }

            const MAX_TIMEOUT: Duration = Duration::from_millis(100);

            let task = self.task_queue.pull_closure(MAX_TIMEOUT, &mut last_warn_dump_time);

            if let Some(task) = task {
                check_execution_time!(100_000);
                task();
            }
        }

        self.task_queue.flush();

        log::info!(
            "SimplexSession callbacks processing loop is finished (session_id is {})",
            self.session_id.to_hex_string()
        );

        is_stopped_flag.store(true, Ordering::Release);
    }
}

// ======================================================================
// Debug
// ======================================================================
// Non-exhaustive `Debug` exposing identity and dispatch-mode fields.
impl std::fmt::Debug for SessionCallbacks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionCallbacks")
            .field("session_id", &self.session_id.to_hex_string())
            .field("use_callback_thread", &self.use_callback_thread)
            .field("stop_flag", &self.stop_flag.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

// ======================================================================
// Tests
// ======================================================================
// Tests live in a sibling file but are included directly via `#[path]` so
// they can reach the private `invoke` helper without widening visibility.
// Mirrors `session_telemetry.rs` / `session_runtime.rs`.
#[cfg(test)]
#[path = "tests/test_session_callbacks.rs"]
mod tests;
