// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Live node acceptance, independent of propagation receipts and source ACKs.
use super::*;
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

const MAX_ACCEPTANCE_REQUESTS: usize = 1024;
const RETRY_DELAY: Duration = Duration::from_millis(250);

#[derive(Default)]
pub(super) struct AcceptanceRequests(BTreeMap<UInt256, AcceptanceState>);
enum AcceptanceState {
    Pending,
    Retry(Instant),
    Accepted,
    Notified,
}

impl SourceFinalityDelivery {
    pub(crate) fn take_acceptance_notification(
        &self,
        draft: &FinalizedDeliveryDraft,
    ) -> Result<bool> {
        let id = PendingFinalityRecord::from_draft(&self.runtime, draft)?.id()?;
        let mut requests = self.acceptance.lock().unwrap();
        if matches!(requests.0.get(&id), Some(AcceptanceState::Accepted)) {
            requests.0.insert(id, AcceptanceState::Notified);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Only a successful node completion allows the controller to resolve its
    /// persistent finality intent. This process-local cache is not a recovery
    /// receipt: after restart the retained intent drives actual acceptance again.
    pub(crate) fn poll_acceptance(self: &Arc<Self>, draft: FinalizedDeliveryDraft) -> Result<bool> {
        #[cfg(test)]
        self.poll_attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let id = PendingFinalityRecord::from_draft(&self.runtime, &draft)?.id()?;
        {
            let mut requests = self.acceptance.lock().unwrap();
            match requests.0.get(&id) {
                Some(AcceptanceState::Accepted | AcceptanceState::Notified) => return Ok(true),
                Some(AcceptanceState::Pending) => return Ok(false),
                Some(AcceptanceState::Retry(at)) if Instant::now() < *at => return Ok(false),
                _ => {}
            }
            if !requests.0.contains_key(&id) && requests.0.len() >= MAX_ACCEPTANCE_REQUESTS {
                // Evict only a finished scheduling cache entry. Re-acceptance
                // is idempotent; in-flight requests must retain their owner.
                let evict = requests.0.iter().find_map(|(key, state)| {
                    matches!(state, AcceptanceState::Accepted | AcceptanceState::Notified)
                        .then(|| key.clone())
                });
                if let Some(key) = evict {
                    requests.0.remove(&key);
                } else {
                    fail!("Too many in-flight node acceptance requests");
                }
            }
            requests.0.insert(id.clone(), AcceptanceState::Pending);
        }
        let owner = self.clone();
        let callback_id = id.clone();
        if let Err(error) = self.sink.accept_draft(
            draft,
            Box::new(move |result| {
                let state = match result {
                    Ok(()) => AcceptanceState::Accepted,
                    Err(error) => {
                        log::warn!("Node acceptance failed; finality intent retained: {error}");
                        AcceptanceState::Retry(Instant::now() + RETRY_DELAY)
                    }
                };
                owner.acceptance.lock().unwrap().0.insert(callback_id, state);
                owner.notify_ready();
            }),
        ) {
            self.acceptance
                .lock()
                .unwrap()
                .0
                .insert(id, AcceptanceState::Retry(Instant::now() + RETRY_DELAY));
            return Err(error);
        }
        Ok(matches!(self.acceptance.lock().unwrap().0.get(&id), Some(AcceptanceState::Accepted)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use consensus_common::finality_delivery::{DurableFinalitySink, FinalizedDeliveryCompletion};
    use rtos_block::ShardIdent;

    type Completion = Box<dyn FnOnce(Result<()>) + Send>;
    #[derive(Default)]
    struct AcceptanceOnlySink(Mutex<Vec<Completion>>);
    impl DurableFinalitySink for AcceptanceOnlySink {
        fn accept_draft(&self, _: FinalizedDeliveryDraft, done: Completion) -> Result<()> {
            self.0.lock().unwrap().push(done);
            Ok(())
        }
        fn stage(&self, _: FinalizedDeliveryDraft, _: FinalizedDeliveryCompletion) -> Result<()> {
            panic!("Node acceptance must not request a propagation receipt")
        }
    }

    #[test]
    fn direct_acceptance_waits_for_node_and_rechecks_after_restart_for_all_roles() {
        for (is_final, shard) in [
            (true, ShardIdent::masterchain()),
            (true, ShardIdent::with_tagged_prefix(0, 0x8000000000000000).unwrap()),
            (false, ShardIdent::with_tagged_prefix(0, 0x8000000000000000).unwrap()),
        ] {
            let temp = crate::authenticated_fixture::TestDirectory::new();
            let (runtime, draft) = super::super::tests::fixture_role(is_final, shard);
            let namespace = std::path::PathBuf::from(
                runtime.runtime_directory(temp.path().to_str().unwrap()).unwrap(),
            );
            let sink = Arc::new(AcceptanceOnlySink::default());
            let source =
                SourceFinalityDelivery::open(runtime.clone(), &namespace, sink.clone()).unwrap();
            assert!(!source.poll_acceptance(draft.clone()).unwrap());
            assert!(!source.poll_acceptance(draft.clone()).unwrap());
            assert_eq!(sink.0.lock().unwrap().len(), 1);
            let done = sink.0.lock().unwrap().pop().unwrap();
            done(Err(error!("State sync failed")));
            assert!(!source.poll_acceptance(draft.clone()).unwrap());
            let id = PendingFinalityRecord::from_draft(&runtime, &draft).unwrap().id().unwrap();
            source.acceptance.lock().unwrap().0.insert(id, AcceptanceState::Retry(Instant::now()));
            assert!(!source.poll_acceptance(draft.clone()).unwrap());
            let done = sink.0.lock().unwrap().pop().unwrap();
            done(Ok(()));
            assert!(source.poll_acceptance(draft.clone()).unwrap());
            assert!(sink.0.lock().unwrap().is_empty());
            drop(source);
            let cold = SourceFinalityDelivery::open(runtime, &namespace, sink.clone()).unwrap();
            assert!(!cold.poll_acceptance(draft).unwrap());
            let done = sink.0.lock().unwrap().pop().unwrap();
            done(Ok(()));
        }
    }
}
