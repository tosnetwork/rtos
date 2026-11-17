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
    /// Isolated fixture only: expose the authenticated request before node
    /// submission so the driver can select its real body sync. This observation
    /// is not source WAL custody and is never consumed during recovery.
    #[cfg(all(target_os = "linux", feature = "isolated-consensus-signing"))]
    fn observe_live_io_source(&self, record: &PendingFinalityRecord) -> Result<()> {
        use std::io::{Read, Write};
        let Some(control) = std::env::var_os("RTOS_TEST_PUBLICATION_IO_CONTROL") else {
            return Ok(());
        };
        if !record.is_final || !record.block_id.shard().is_masterchain() {
            return Ok(());
        }
        let control = PathBuf::from(control);
        if !control.is_absolute() || control.canonicalize()? != control {
            fail!("Live IO observation requires a canonical control directory");
        }
        let armed = control.join("live-source-arm.json");
        let file = match File::open(&armed) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let mut bytes = Vec::new();
        file.take(4097).read_to_end(&mut bytes)?;
        if bytes.len() > 4096 {
            fail!("Live IO selector exceeds bound");
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Selection {
            pid: u32,
            session_id: String,
        }
        let selected: Selection = serde_json::from_slice(&bytes)?;
        if selected.pid != std::process::id()
            || selected.session_id != record.session_id.to_hex_string()
        {
            return Ok(());
        }
        // Claim once across concurrent sessions/callbacks. No existing evidence
        // is overwritten, and only the driver resumes this owned test process.
        let claimed = control.join("live-source-claimed");
        let mut claim =
            match std::fs::OpenOptions::new().write(true).create_new(true).open(&claimed) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Ok(()),
                Err(error) => return Err(error.into()),
            };
        claim.write_all(record.id()?.to_hex_string().as_bytes())?;
        claim.sync_all()?;
        let observed = serde_json::json!({
            "schema": 1, "pid": std::process::id(),
            "namespace": self.store.directory.parent(),
            "source_id": record.id()?.to_hex_string(),
            "record": record.disk_record(),
            "is_custody_receipt": false,
        });
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(control.join("live-source.json"))?;
        file.write_all(&serde_json::to_vec(&observed)?)?;
        file.sync_all()?;
        File::open(&control)?.sync_all()?;
        unsafe extern "C" {
            fn kill(pid: i32, signal: i32) -> i32;
        }
        if unsafe { kill(std::process::id() as i32, 19) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }
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
        let record = PendingFinalityRecord::from_draft(&self.runtime, &draft)?;
        let id = record.id()?;
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
            #[cfg(all(target_os = "linux", feature = "isolated-consensus-signing"))]
            self.observe_live_io_source(&record)?;
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

    #[cfg(all(target_os = "linux", feature = "isolated-consensus-signing"))]
    #[test]
    fn live_io_observation_child() {
        let Some(root) = std::env::var_os("RTOS_LIVE_IO_CHILD") else {
            return;
        };
        let root = PathBuf::from(root);
        let (runtime, draft) = super::super::tests::fixture();
        let namespace = PathBuf::from(runtime.runtime_directory(root.to_str().unwrap()).unwrap());
        let sink = Arc::new(AcceptanceOnlySink::default());
        let source =
            SourceFinalityDelivery::open(runtime.clone(), &namespace, sink.clone()).unwrap();
        let record = PendingFinalityRecord::from_draft(&runtime, &draft).unwrap();
        let selector = root.join("live-source-arm.json");
        std::fs::write(
            &selector,
            serde_json::to_vec(&serde_json::json!({
                "pid": std::process::id(), "session_id": "wrong-session"
            }))
            .unwrap(),
        )
        .unwrap();
        source.observe_live_io_source(&record).unwrap();
        assert!(!root.join("live-source.json").exists());
        std::fs::write(
            &selector,
            serde_json::to_vec(&serde_json::json!({
                "pid": std::process::id(), "session_id": runtime.session_id().to_hex_string()
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(!source.poll_acceptance(draft.clone()).unwrap());
        // The parent resumed us; the callback is still pending, no acceptance
        // or custody was manufactured by the observation.
        assert_eq!(sink.0.lock().unwrap().len(), 1);
        assert!(!source.poll_acceptance(draft.clone()).unwrap());
        sink.0.lock().unwrap().pop().unwrap()(Ok(()));
        std::fs::remove_file(root.join("live-source-claimed")).unwrap();
        std::fs::remove_file(root.join("live-source.json")).unwrap();
        // An already accepted request must not claim a newly armed sync cut:
        // it will never reach the node durability operation again.
        assert!(source.poll_acceptance(draft).unwrap());
        assert!(!root.join("live-source.json").exists());
    }

    #[cfg(all(target_os = "linux", feature = "isolated-consensus-signing"))]
    #[test]
    fn live_io_observation_stops_owned_process_without_acceptance_or_wal() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let root = crate::authenticated_fixture::TestDirectory::new();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "finality_delivery::acceptance::tests::live_io_observation_child",
                    "--nocapture",
                ])
                .env("RTOS_LIVE_IO_CHILD", root.path())
                .env("RTOS_TEST_PUBLICATION_IO_CONTROL", root.path())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            assert!(child.0.try_wait().unwrap().is_none(), "child exited before observation stop");
            let status = std::fs::read_to_string(format!("/proc/{}/status", child.0.id())).unwrap();
            if status.lines().any(|line| {
                line.starts_with("State:") && line.split_whitespace().nth(1) == Some("T")
            }) {
                break;
            }
            assert!(Instant::now() < deadline, "child did not stop");
            std::thread::sleep(Duration::from_millis(10));
        }
        let observed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.path().join("live-source.json")).unwrap())
                .unwrap();
        assert_eq!(observed["pid"], child.0.id());
        assert_eq!(observed["is_custody_receipt"], false);
        let record = PendingFinalityRecord::from_disk(
            serde_json::from_value(observed["record"].clone()).unwrap(),
        )
        .unwrap();
        record.validate().unwrap();
        assert_eq!(observed["source_id"], record.id().unwrap().to_hex_string());
        let namespace = PathBuf::from(observed["namespace"].as_str().unwrap());
        assert!(namespace.starts_with(root.path()));
        assert!(std::fs::read_dir(namespace.join("finality-pending"))
            .unwrap()
            .all(|entry| entry.unwrap().file_name() == ".lock"));
        unsafe extern "C" {
            fn kill(pid: i32, signal: i32) -> i32;
        }
        assert_eq!(unsafe { kill(child.0.id() as i32, 18) }, 0);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(Instant::now() < deadline, "child did not resume");
            std::thread::sleep(Duration::from_millis(10));
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
