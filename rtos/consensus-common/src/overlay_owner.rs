// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use crate::*;
use std::sync::{Arc, Mutex};

/// Records every overlay created by a session so its external owner can verify
/// resource joins even if a consensus worker unwinds before normal teardown.
pub struct OverlayOwner {
    inner: ConsensusOverlayManagerPtr,
    open: Mutex<bool>,
    overlays: Mutex<Vec<(Arc<adnl::PrivateOverlayShortId>, ConsensusOverlayPtr)>>,
}
impl OverlayOwner {
    pub fn new(inner: ConsensusOverlayManagerPtr) -> Arc<Self> {
        Arc::new(Self { inner, open: Mutex::new(true), overlays: Mutex::new(Vec::new()) })
    }
    pub fn drained(&self) -> bool {
        self.overlays.lock().unwrap().iter().all(|(_, overlay)| self.inner.overlay_drained(overlay))
    }
    pub fn stop_checked(&self) -> Result<()> {
        *self.open.lock().unwrap() = false;
        let overlays = self.overlays.lock().unwrap().clone();
        let mut errors = Vec::new();
        for (id, overlay) in overlays {
            if let Err(error) = self.inner.stop_overlay_checked(&id, &overlay) {
                errors.push(error.to_string());
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(rtos_block::error!("{}", errors.join("; ")))
        }
    }
}
impl ConsensusOverlayManager for OverlayOwner {
    fn wire_profile(&self) -> rtos_api::WireProfile {
        self.inner.wire_profile()
    }
    fn start_overlay(
        &self,
        key: &PrivateKey,
        id: &Arc<adnl::PrivateOverlayShortId>,
        nodes: &[ConsensusNode],
        listener: ConsensusOverlayListenerPtr,
        replay: ConsensusOverlayLogReplayListenerPtr,
        transport: OverlayTransportType,
        sync: Option<BlockSyncOverlayParams>,
    ) -> Result<ConsensusOverlayPtr> {
        // Stop must not snapshot before an admitted construction is registered.
        let open = self.open.lock().unwrap();
        if !*open {
            return Err(rtos_block::error!("Overlay owner admission is closed"));
        }
        let overlay =
            self.inner.start_overlay(key, id, nodes, listener, replay, transport, sync)?;
        self.overlays.lock().unwrap().push((id.clone(), overlay.clone()));
        Ok(overlay)
    }
    fn stop_overlay(&self, id: &Arc<adnl::PrivateOverlayShortId>, overlay: &ConsensusOverlayPtr) {
        if let Err(error) = self.stop_overlay_checked(id, overlay) {
            log::error!("Overlay shutdown: {error}");
        }
    }
    fn stop_overlay_checked(
        &self,
        id: &Arc<adnl::PrivateOverlayShortId>,
        overlay: &ConsensusOverlayPtr,
    ) -> Result<()> {
        self.inner.stop_overlay_checked(id, overlay)
    }
    fn overlay_drained(&self, overlay: &ConsensusOverlayPtr) -> bool {
        self.inner.overlay_drained(overlay)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc,
    };
    struct Listener;
    impl ConsensusOverlayListener for Listener {
        fn on_message(&self, _: PublicKeyHash, _: &BlockPayloadPtr) {}
        fn on_broadcast(&self, _: PublicKeyHash, _: &BlockPayloadPtr, _: BroadcastSource) {}
        fn on_query(&self, _: PublicKeyHash, _: &BlockPayloadPtr, _: QueryResponseCallback) {}
    }
    impl ConsensusOverlayLogReplayListener for Listener {
        fn on_time_changed(&self, _: std::time::SystemTime) {}
    }
    struct HeldConstruction {
        entered: mpsc::Sender<()>,
        release: Mutex<mpsc::Receiver<()>>,
        stopped: AtomicUsize,
    }
    impl ConsensusOverlayManager for HeldConstruction {
        fn start_overlay(
            &self,
            _: &PrivateKey,
            _: &Arc<adnl::PrivateOverlayShortId>,
            _: &[ConsensusNode],
            _: ConsensusOverlayListenerPtr,
            _: ConsensusOverlayLogReplayListenerPtr,
            _: OverlayTransportType,
            _: Option<BlockSyncOverlayParams>,
        ) -> Result<ConsensusOverlayPtr> {
            self.entered.send(()).unwrap();
            self.release.lock().unwrap().recv_timeout(std::time::Duration::from_secs(5)).unwrap();
            Ok(Arc::new(crate::dummy_catchain_overlay::DummyConsensusOverlay))
        }
        fn stop_overlay(&self, _: &Arc<adnl::PrivateOverlayShortId>, _: &ConsensusOverlayPtr) {}
        fn stop_overlay_checked(
            &self,
            _: &Arc<adnl::PrivateOverlayShortId>,
            _: &ConsensusOverlayPtr,
        ) -> Result<()> {
            self.stopped.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    #[test]
    fn overlay_owned_admission_serializes_construction_against_stop_snapshot() {
        let (entered, arrived) = mpsc::channel();
        let (release, held) = mpsc::channel();
        let inner = Arc::new(HeldConstruction {
            entered,
            release: Mutex::new(held),
            stopped: AtomicUsize::new(0),
        });
        let owner = OverlayOwner::new(inner.clone());
        let key = rtos_block::Ed25519KeyOption::<rtos_block::ZeroizingBytes>::from_private_key(&[33; 32]).unwrap();
        let id = rtos_block::KeyId::from_data([34; 32]);
        let listener: Arc<dyn ConsensusOverlayListener + Send + Sync> = Arc::new(Listener);
        let replay: Arc<dyn ConsensusOverlayLogReplayListener + Send + Sync> = Arc::new(Listener);
        let start = {
            let owner = owner.clone();
            let key = key.clone();
            let id = id.clone();
            let listener = listener.clone();
            let replay = replay.clone();
            std::thread::spawn(move || {
                owner.start_overlay(
                    &key,
                    &id,
                    &[],
                    Arc::downgrade(&listener),
                    Arc::downgrade(&replay),
                    OverlayTransportType::Catchain,
                    None,
                )
            })
        };
        arrived.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        let (finished, completion) = mpsc::channel();
        let stopper = {
            let owner = owner.clone();
            std::thread::spawn(move || {
                let result = owner.stop_checked();
                finished.send(()).unwrap();
                result
            })
        };
        let stopped_early = completion.recv_timeout(std::time::Duration::from_millis(50)).is_ok();
        release.send(()).unwrap();
        start.join().unwrap().unwrap();
        stopper.join().unwrap().unwrap();
        assert!(!stopped_early, "stop snapshot escaped an admitted construction");
        assert_eq!(inner.stopped.load(Ordering::SeqCst), 1);
        assert!(owner
            .start_overlay(
                &key,
                &id,
                &[],
                Arc::downgrade(&listener),
                Arc::downgrade(&replay),
                OverlayTransportType::Catchain,
                None
            )
            .is_err());
    }
}
