// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Condvar,
    },
    time::Duration,
};

#[derive(Default)]
struct Gate {
    open: Mutex<bool>,
    changed: Condvar,
}
impl Gate {
    fn wait(&self) {
        let mut open = self.open.lock().unwrap();
        while !*open {
            open = self.changed.wait(open).unwrap();
        }
    }
    fn release(&self) {
        *self.open.lock().unwrap() = true;
        self.changed.notify_all();
    }
}
struct Release(Arc<Gate>);
impl Drop for Release {
    fn drop(&mut self) {
        self.0.release();
    }
}
async fn bounded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("real sender owner failed to terminate")
}
fn pool(owner: &Arc<AdnlTasks>) -> SendWorkerPool {
    let mut pool = SendWorkerPool::new(owner.clone());
    pool.workers = 1;
    pool
}

#[tokio::test]
async fn rldp_owned_queue_failure_cancels_before_receipt_poll() {
    for false_result in [true, false] {
        let owner = AdnlTasks::new();
        let pool = pool(&owner);
        let control = SendControl::new();
        let (release, wait) = oneshot::channel();
        let first = pool
            .submit(control.clone(), async move {
                let _ = wait.await;
                if false_result {
                    Ok(false)
                } else {
                    Err(error!("original first failure"))
                }
            })
            .unwrap();
        let entered = Arc::new(AtomicBool::new(false));
        let flag = entered.clone();
        let second = pool
            .submit(control.clone(), async move {
                flag.store(true, Ordering::Release);
                Ok(true)
            })
            .unwrap();
        release.send(()).unwrap();
        // Do not poll the first receipt: the worker itself must cancel the
        // next queued job rather than relying on its transfer being scheduled.
        assert!(bounded(second).await.unwrap().is_err());
        assert!(!entered.load(Ordering::Acquire));
        let result = bounded(first).await.unwrap();
        if false_result {
            assert!(matches!(result, Ok(false)));
        } else {
            assert!(result.is_err());
        }
        let first = control.take_failure().unwrap();
        if false_result {
            assert!(matches!(first, Ok(false)));
        } else {
            assert_eq!(first.unwrap_err().to_string(), "original first failure");
        }
        bounded(owner.wait()).await.unwrap();
    }
}

#[tokio::test]
async fn rldp_owned_running_fec_retains_permit_registration_and_join() {
    for reason in
        [SendCancelled::CallerDropped, SendCancelled::Deadline, SendCancelled::OwnerClosed]
    {
        let owner = AdnlTasks::new();
        let pool = pool(&owner);
        let control = SendControl::new();
        let slots = Arc::new(Semaphore::new(1));
        let permit = Arc::new(slots.clone().acquire_owned().await.unwrap());
        let transfers = Arc::new(lockfree::map::Map::new());
        transfers.insert([1; 32], super::super::RldpTransfer::Done);
        let registration = Arc::new(SendRegistration {
            peer: None,
            transfers: transfers.clone(),
            send: [1; 32],
            receive: None,
            owner: owner.clone(),
            bounded_permit: Some(permit.clone()),
        });
        let gate = Arc::new(Gate::default());
        let _release = Release(gate.clone());
        let work_gate = gate.clone();
        let (entered, entered_rx) = oneshot::channel();
        let work_control = control.clone();
        let work_owner = owner.clone();
        let mut receipt = pool
            .submit(control.clone(), async move {
                let (_state, ()) =
                    fec((permit, registration), work_control.clone(), work_owner, move |_| {
                        let _ = entered.send(());
                        work_gate.wait();
                        Ok(())
                    })
                    .await?;
                work_control.check()?;
                Ok(true)
            })
            .unwrap();
        let result = std::panic::AssertUnwindSafe(async {
            bounded(entered_rx).await.unwrap();
            match reason {
                SendCancelled::CallerDropped => drop(control.guard()),
                _ => control.cancel(reason),
            }
            owner.close();
            assert_eq!(slots.available_permits(), 0);
            assert!(transfers.get(&[1; 32]).is_some());
            assert!(matches!(receipt.try_recv(), Err(oneshot::error::TryRecvError::Empty)));
            // Dropping a shutdown observer must not drop any actual handle.
            assert!(tokio::time::timeout(Duration::from_millis(20), owner.wait()).await.is_err());
            assert!(!owner.drained());
        })
        .catch_unwind()
        .await;
        control.cancel(SendCancelled::OwnerClosed);
        owner.close();
        gate.release();
        let terminal = bounded(receipt).await.unwrap();
        bounded(owner.wait()).await.unwrap();
        assert!(terminal.is_err());
        assert_eq!(slots.available_permits(), 1);
        assert!(transfers.get(&[1; 32]).is_none());
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    }
}

#[test]
fn rldp_owned_cancelled_blocking_queue_never_enters_fec() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let owner = AdnlTasks::new();
        let pool = pool(&owner);
        let control = SendControl::new();
        let gate = Arc::new(Gate::default());
        let _release = Release(gate.clone());
        let held = gate.clone();
        let (entered, entered_rx) = oneshot::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            let _ = entered.send(());
            held.wait();
        });
        let executed = Arc::new(AtomicBool::new(false));
        let flag = executed.clone();
        let work_owner = owner.clone();
        let work_control = control.clone();
        let (queued, queued_rx) = oneshot::channel();
        let receipt = pool
            .submit(control.clone(), async move {
                let future = fec((), work_control, work_owner, move |_| {
                    flag.store(true, Ordering::Release);
                    Ok(())
                });
                tokio::pin!(future);
                futures::future::poll_fn(|cx| {
                    assert!(future.as_mut().poll(cx).is_pending());
                    std::task::Poll::Ready(())
                })
                .await;
                let _ = queued.send(());
                future.await?;
                Ok(true)
            })
            .unwrap();
        let result = std::panic::AssertUnwindSafe(async {
            bounded(entered_rx).await.unwrap();
            bounded(queued_rx).await.unwrap();
            control.cancel(SendCancelled::Deadline);
            owner.close();
            assert!(!executed.load(Ordering::Acquire));
            assert!(tokio::time::timeout(Duration::from_millis(20), owner.wait()).await.is_err());
        })
        .catch_unwind()
        .await;
        control.cancel(SendCancelled::OwnerClosed);
        owner.close();
        gate.release();
        bounded(blocker).await.unwrap();
        assert!(bounded(receipt).await.unwrap().is_err());
        bounded(owner.wait()).await.unwrap();
        assert!(!executed.load(Ordering::Acquire));
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

#[tokio::test]
async fn rldp_owned_fec_panic_is_sticky_and_has_receipt() {
    let owner = AdnlTasks::new();
    let pool = pool(&owner);
    let control = SendControl::new();
    let work_owner = owner.clone();
    let work_control = control.clone();
    let receipt = pool
        .submit(control, async move {
            fec((), work_control, work_owner, |_| -> Result<()> { panic!("controlled FEC panic") })
                .await?;
            Ok(true)
        })
        .unwrap();
    assert!(bounded(receipt).await.unwrap().is_err());
    let first = bounded(owner.wait()).await.unwrap_err().to_string();
    assert!(first.contains("panicked"));
    assert_eq!(bounded(owner.wait()).await.unwrap_err().to_string(), first);
}

#[tokio::test]
async fn rldp_owned_query_capacity_is_not_tombstone_capacity() {
    let owner = AdnlTasks::new();
    let capacity = Arc::new(Semaphore::new(32));
    let transfers = Arc::new(lockfree::map::Map::new());
    for index in 0..40u8 {
        let permit = Arc::new(capacity.clone().try_acquire_owned().unwrap());
        drop(SendRegistration {
            peer: None,
            transfers: transfers.clone(),
            send: [index; 32],
            receive: None,
            owner: owner.clone(),
            bounded_permit: Some(permit),
        });
        assert_eq!(capacity.available_permits(), 32);
        assert!(transfers.get(&[index; 32]).is_some());
    }
    bounded(owner.wait()).await.unwrap();
    for index in 0..40u8 {
        assert!(transfers.get(&[index; 32]).is_none());
    }
}

async fn node() -> Arc<crate::adnl::node::AdnlNode> {
    use crate::adnl::node::{AdnlNode, AdnlNodeConfig};
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    let (_, config) = AdnlNodeConfig::from_ip_address_and_private_keys(
        &format!("127.0.0.1:{port}"),
        vec![([83; 32], 0)],
    )
    .unwrap();
    AdnlNode::with_config(
        config,
        #[cfg(feature = "dump")]
        None,
    )
    .await
    .unwrap()
}
fn rldp(adnl: &Arc<crate::adnl::node::AdnlNode>) -> Arc<super::super::RldpNode> {
    super::super::RldpNode::with_params(
        adnl.clone(),
        Vec::new(),
        None,
        #[cfg(feature = "debug")]
        None,
        #[cfg(feature = "debug")]
        None,
    )
    .unwrap()
}

#[tokio::test]
async fn rldp_owned_query_deadline_includes_peer_admission_wait() {
    use super::super::RldpQueryTimeout;
    use crate::adnl::common::{AdnlPeers, TaggedByteSlice};
    let adnl = node().await;
    let rldp = rldp(&adnl);
    let local = adnl.key_by_tag(0).unwrap();
    let peers = AdnlPeers::with_keys(local.id().clone(), local.id().clone());
    let peer = rldp.get_peer(local.id(), local.id(), true, None).await.unwrap();
    let capacity = peer.outbound_semaphore.available_permits();
    let occupied = peer.outbound_semaphore.clone().try_acquire_many_owned(capacity as u32).unwrap();
    let outcome = std::panic::AssertUnwindSafe(async {
        let data = TaggedByteSlice {
            object: &[0; 4],
            #[cfg(feature = "telemetry")]
            tag: 0,
        };
        let started = std::time::Instant::now();
        let error = tokio::time::timeout(
            Duration::from_secs(12),
            rldp.query(&data, Some(1024), &peers, true, None),
        )
        .await
        .expect("query deadline must bound waiting for the peer slot")
        .unwrap_err();
        assert!(error.downcast_ref::<RldpQueryTimeout>().is_some(), "{error:#}");
        assert!(started.elapsed() >= Duration::from_millis(9500));
        assert_eq!(rldp.allocated.send_transfers.load(Ordering::Acquire), 0);
        assert_eq!(rldp.allocated.recv_transfers.load(Ordering::Acquire), 0);
    })
    .catch_unwind()
    .await;
    drop(occupied);
    bounded(adnl.stop_checked()).await.unwrap();
    assert_eq!(peer.outbound_semaphore.available_permits(), capacity);
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test]
async fn rldp_owned_idle_peer_does_not_retain_own_sender() {
    let adnl = node().await;
    let rldp = rldp(&adnl);
    let key = adnl.key_by_tag(0).unwrap();
    let peer = rldp.get_peer(key.id(), key.id(), true, None).await.unwrap();
    let weak = Arc::downgrade(&peer);
    let idle = peer.idle.clone();
    bounded(idle.notified()).await;
    drop(peer);
    drop(rldp);
    let result = std::panic::AssertUnwindSafe(async {
        bounded(async {
            while weak.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await;
    })
    .catch_unwind()
    .await;
    bounded(adnl.stop_checked()).await.unwrap();
    assert!(weak.upgrade().is_none());
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test]
async fn rldp_owned_public_v1_v2_cancellation_retains_real_sender() {
    use super::super::{QueryResponseLimits, RldpNode};
    use crate::adnl::common::{AdnlPeers, TaggedByteSlice};
    // All six public entrypoint/protocol combinations, with caller cancellation,
    // the actual hard-deadline branch, and ADNL shutdown respectively.
    for v2 in [false, true] {
        for api in 0..3 {
            for stop in 0..3 {
                let adnl = node().await;
                let rldp = rldp(&adnl);
                let local = adnl.key_by_tag(0).unwrap();
                let peers = AdnlPeers::with_keys(local.id().clone(), local.id().clone());
                let peer = rldp.get_peer(local.id(), local.id(), v2, None).await.unwrap();
                let control = SendControl::new();
                *rldp.test_control.lock().unwrap() = Some(control.clone());
                if stop == 1 {
                    *control.test_deadline.lock().unwrap() = Some(Duration::from_millis(40));
                }
                let gate = Arc::new(Gate::default());
                let _release = Release(gate.clone());
                let work_gate = gate.clone();
                let (entered, entered_rx) = oneshot::channel();
                let entered = Mutex::new(Some(entered));
                *control.test_after_fec.lock().unwrap() = Some(Arc::new(move || {
                    if let Some(sent) = entered.lock().unwrap().take() {
                        let _ = sent.send(());
                    }
                    work_gate.wait();
                }));
                let send_node = rldp.clone();
                let sender = tokio::spawn(async move {
                    let bytes = [5; 32];
                    let data = TaggedByteSlice {
                        object: &bytes,
                        #[cfg(feature = "telemetry")]
                        tag: 0,
                    };
                    match api {
                        0 => send_node.message(&data, &peers, v2, None).await.map(|_| ()),
                        1 => send_node.query(&data, Some(1024), &peers, v2, None).await.map(|_| ()),
                        _ => send_node
                            .query_bounded(
                                &data,
                                QueryResponseLimits { wire_bytes: 1024, decoded_bytes: 1024 },
                                &peers,
                                v2,
                                None,
                            )
                            .await
                            .map(|_| ()),
                    }
                });
                let result = std::panic::AssertUnwindSafe(async {
                    bounded(entered_rx).await.unwrap();
                    match stop {
                        0 => sender.abort(),
                        1 => {}
                        _ => adnl.tasks().close(),
                    }
                    bounded(control.cancelled()).await;
                    assert_eq!(
                        peer.outbound_semaphore.available_permits(),
                        RldpNode::MAX_OUTBOUNDS_PER_PEER as usize - 1
                    );
                    assert!(rldp.transfers.iter().next().is_some());
                    assert!(tokio::time::timeout(Duration::from_millis(20), adnl.stop_checked())
                        .await
                        .is_err());
                    assert!(!adnl.tasks().drained());
                })
                .catch_unwind()
                .await;
                control.cancel(SendCancelled::OwnerClosed);
                adnl.tasks().close();
                gate.release();
                let returned = bounded(sender).await;
                bounded(adnl.stop_checked()).await.unwrap();
                assert_eq!(
                    peer.outbound_semaphore.available_permits(),
                    RldpNode::MAX_OUTBOUNDS_PER_PEER as usize
                );
                assert!(rldp.transfers.iter().next().is_none());
                if stop == 0 {
                    assert!(returned.unwrap_err().is_cancelled());
                } else {
                    assert!(returned.unwrap().is_err());
                }
                if let Err(panic) = result {
                    std::panic::resume_unwind(panic);
                }
            }
        }
    }
}

#[tokio::test]
async fn rldp_owned_first_part_outcome_waits_for_sibling_fec() {
    use super::super::{send, RldpTransfer, SendContext, SendJob, SendTransferState};
    use crate::adnl::common::AdnlPeers;
    for outcome in 0..4 {
        let adnl = node().await;
        let rldp = rldp(&adnl);
        let local = adnl.key_by_tag(0).unwrap();
        let peer = rldp.get_peer(local.id(), local.id(), true, None).await.unwrap();
        let mut pool = SendWorkerPool::new(adnl.tasks().clone());
        pool.workers = 2; // Two real active siblings, still below production max8.
        let pool = Arc::new(pool);
        let control = SendControl::new();
        let gate = Arc::new(Gate::default());
        let _release = Release(gate.clone());
        let sibling_started = Arc::new(Gate::default());
        let _start_release = Release(sibling_started.clone());
        let work_gate = gate.clone();
        let work_started = sibling_started.clone();
        let weak_control = Arc::downgrade(&control);
        *control.test_after_start.lock().unwrap() = Some(Arc::new(move |part| {
            if part == 1 {
                work_started.release();
                if outcome == 3 {
                    weak_control.upgrade().unwrap().test_bbr_error.store(true, Ordering::Release);
                }
                work_gate.wait();
                Ok(None)
            } else {
                work_started.wait();
                match outcome {
                    0 => Ok(Some(false)),
                    1 => Err(error!("specific first part error")),
                    2 => panic!("controlled first part panic"),
                    _ => Ok(Some(true)),
                }
            }
        }));
        let (transfer, states) = send::owned_test_transfer(2).unwrap();
        let id = [7; 32];
        rldp.transfers.insert(id, RldpTransfer::Send(SendTransferState::V2(states)));
        let registration = Arc::new(SendRegistration {
            peer: None,
            transfers: rldp.transfers.clone(),
            send: id,
            receive: None,
            owner: adnl.tasks().clone(),
            bounded_permit: None,
        });
        let permit = Arc::new(peer.outbound_semaphore.clone().acquire_owned().await.unwrap());
        let (done, mut receipt) = oneshot::channel();
        let job = SendJob {
            send_id: id,
            v2: true,
            done,
            ctx: SendContext {
                admission: Some(Arc::new(
                    peer.transfer_slots.clone().acquire_owned().await.unwrap(),
                )),
                adnl: adnl.clone(),
                peers: AdnlPeers::with_keys(local.id().clone(), local.id().clone()),
                pong: tokio::sync::mpsc::unbounded_channel().1,
                send_transfer: transfer,
                transfer_id: id,
                control: control.clone(),
                registration,
                permit: Some(permit),
                #[cfg(feature = "debug")]
                timestamp: rldp.timestamp.clone(),
                #[cfg(feature = "telemetry")]
                tag: 0,
            },
        };
        let work_peer = peer.clone();
        let transfers = rldp.transfers.clone();
        adnl.tasks().spawn_admitted(
            "test real send job",
            adnl.tasks().enter().unwrap(),
            async move {
                job.run(work_peer, &transfers, &pool, 500).await;
            },
        );
        let result = std::panic::AssertUnwindSafe(async {
            bounded(control.cancelled()).await;
            assert!(matches!(receipt.try_recv(), Err(oneshot::error::TryRecvError::Empty)));
            assert_eq!(peer.outbound_semaphore.available_permits(), 2);
            assert_eq!(peer.transfer_slots.available_permits(), 255);
            assert!(rldp.transfers.get(&id).is_some());
            assert!(tokio::time::timeout(Duration::from_millis(20), adnl.stop_checked())
                .await
                .is_err());
        })
        .catch_unwind()
        .await;
        control.cancel(SendCancelled::OwnerClosed);
        adnl.tasks().close();
        sibling_started.release();
        gate.release();
        let terminal = bounded(receipt).await.unwrap();
        let stopped = bounded(adnl.stop_checked()).await;
        match outcome {
            0 => {
                assert!(matches!(terminal, Ok(false)));
                stopped.unwrap();
            }
            1 => {
                assert_eq!(terminal.unwrap_err().to_string(), "specific first part error");
                stopped.unwrap();
            }
            2 => {
                assert!(terminal.is_err());
                assert!(stopped.is_err());
            }
            _ => {
                assert_eq!(terminal.unwrap_err().to_string(), "controlled BBR step error");
                stopped.unwrap();
            }
        }
        assert_eq!(peer.outbound_semaphore.available_permits(), 3);
        assert_eq!(peer.transfer_slots.available_permits(), 256);
        assert!(rldp.transfers.get(&id).is_none());
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    }
}

#[tokio::test]
async fn rldp_owned_close_before_workers_first_poll_rejects_queue() {
    let owner = AdnlTasks::new();
    let pool = pool(&owner);
    let entered = Arc::new(AtomicBool::new(false));
    let flag = entered.clone();
    let receipt = pool
        .submit(SendControl::new(), async move {
            flag.store(true, Ordering::Release);
            Ok(true)
        })
        .unwrap();
    // current-thread runtime: no admitted worker has been polled yet.
    owner.close();
    assert!(bounded(receipt).await.unwrap().is_err());
    bounded(owner.wait()).await.unwrap();
    assert!(!entered.load(Ordering::Acquire));
    assert!(pool.submit(SendControl::new(), async { Ok(true) }).is_err());
}

#[tokio::test]
async fn rldp_owned_async_part_panic_has_sticky_completion() {
    for cooperative in [false, true] {
        let owner = AdnlTasks::new();
        let pool = pool(&owner);
        let work = async { panic!("controlled asynchronous part panic") };
        let receipt = if cooperative {
            pool.submit_v2(SendControl::new(), work)
        } else {
            pool.submit(SendControl::new(), work)
        }
        .unwrap();
        assert!(bounded(receipt).await.unwrap().is_err());
        assert!(bounded(owner.wait()).await.unwrap_err().to_string().contains("panicked"));
    }
}

#[tokio::test]
async fn rldp_owned_inbound_expiry_cannot_revive_removed_registration() {
    for cancelled in [false, true] {
        let owner = AdnlTasks::new();
        let transfers = Arc::new(lockfree::map::Map::new());
        let id = [91; 32];
        let (sender, _receiver) = tokio::sync::mpsc::unbounded_channel();
        transfers.insert(id, super::super::RldpTransfer::Recv(sender));
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let map = transfers.clone();
        let lifetime = owner.clone();
        owner.spawn("test actual inbound expiry", async move {
            super::super::expire_inbound_transfer(
                map,
                id,
                lifetime,
                async move {
                    let _ = entered_tx.send(());
                    let _ = release_rx.await;
                },
                None,
            )
            .await;
            let _ = done_tx.send(());
        });
        bounded(entered_rx).await.unwrap();
        // The real receive owner removes the registration before the delayed
        // expiry can finish. Both shutdown and the timer branch must preserve it.
        transfers.remove(&id);
        if cancelled {
            owner.close();
        }
        let _ = release_tx.send(());
        let completed = tokio::time::timeout(Duration::from_secs(5), done_rx).await;
        owner.close();
        bounded(owner.wait()).await.unwrap();
        completed.unwrap().unwrap();
        assert!(transfers.get(&id).is_none(), "late inbound expiry revived a removed ID");
    }
    // A live registration still transitions on a real timer completion.
    let owner = AdnlTasks::new();
    let transfers = Arc::new(lockfree::map::Map::new());
    let id = [92; 32];
    let (sender, _receiver) = tokio::sync::mpsc::unbounded_channel();
    transfers.insert(id, super::super::RldpTransfer::Recv(sender));
    super::super::expire_inbound_transfer(transfers.clone(), id, owner.clone(), async {}, None)
        .await;
    assert!(matches!(&*transfers.get(&id).unwrap().val(), super::super::RldpTransfer::Done));
    owner.close();
    bounded(owner.wait()).await.unwrap();
}

#[tokio::test]
async fn rldp_owned_expired_protocol_deadline_skips_queued_work() {
    let owner = AdnlTasks::new();
    let pool = pool(&owner);
    let (release, wait) = oneshot::channel();
    let (entered, started) = oneshot::channel();
    let first = pool
        .submit(SendControl::new(), async move {
            entered.send(()).unwrap();
            let _ = wait.await;
            Ok(true)
        })
        .unwrap();
    bounded(started).await.unwrap();
    let deadline = std::time::Instant::now() + Duration::from_millis(50);
    let control = SendControl::with_protocol_deadline(Some(deadline));
    let executed = Arc::new(AtomicBool::new(false));
    let flag = executed.clone();
    let second = pool
        .submit(control.clone(), async move {
            flag.store(true, Ordering::Release);
            Ok(true)
        })
        .unwrap();
    tokio::time::sleep_until(tokio::time::Instant::from_std(deadline) + Duration::from_millis(20))
        .await;
    release.send(()).unwrap();
    let result = bounded(second).await.unwrap();
    assert!(bounded(first).await.unwrap().unwrap());
    bounded(owner.wait()).await.unwrap();
    assert!(!executed.load(Ordering::Acquire), "queued work started after its absolute deadline");
    assert!(result.is_err());
    let error = control.take_failure().unwrap().unwrap_err();
    assert!(
        matches!(error.downcast_ref::<SendCancelled>(), Some(SendCancelled::Deadline)),
        "{error:#}"
    );
}

#[tokio::test]
async fn rldp_cooperative_fec_limit_survives_cancellation_until_real_join() {
    let owner = AdnlTasks::new();
    let pool = pool(&owner);
    let capacity = pool.fec_slots();
    let gate = Arc::new(Gate::default());
    let _release = Release(gate.clone());
    let (entered, started) = oneshot::channel();
    let control = SendControl::new();
    let work_control = control.clone();
    let work_owner = owner.clone();
    let slots = capacity.clone();
    let first = pool
        .submit_v2(control.clone(), async move {
            fec_limited((), work_control, work_owner, slots, move |_| {
                entered.send(()).unwrap();
                gate.wait();
                Ok(())
            })
            .await?;
            Ok(true)
        })
        .unwrap();
    bounded(started).await.unwrap();
    assert_eq!(capacity.available_permits(), 0);
    control.cancel(SendCancelled::CallerDropped);
    assert_eq!(capacity.available_permits(), 0, "cancellation cannot release a running FEC slot");
    let later = SendControl::with_protocol_deadline(Some(
        std::time::Instant::now() + Duration::from_millis(40),
    ));
    let ran = Arc::new(AtomicBool::new(false));
    let flag = ran.clone();
    let slots = capacity.clone();
    let work_owner = owner.clone();
    let work_control = later.clone();
    let second = pool
        .submit_v2(later.clone(), async move {
            fec_limited((), work_control, work_owner, slots, move |_| {
                flag.store(true, Ordering::Release);
                Ok(())
            })
            .await?;
            Ok(true)
        })
        .unwrap();
    tokio::time::sleep(Duration::from_millis(70)).await;
    _release.0.release();
    let _ = bounded(first).await.unwrap();
    let result = bounded(second).await.unwrap();
    bounded(owner.wait()).await.unwrap();
    assert!(!ran.load(Ordering::Acquire));
    assert!(result.is_err());
    assert!(matches!(
        later.take_failure().unwrap().unwrap_err().downcast_ref::<SendCancelled>(),
        Some(SendCancelled::Deadline)
    ));
    assert_eq!(capacity.available_permits(), 1);
}

#[tokio::test]
async fn rldp_connection_retirement_waits_for_actual_fec_before_reusing_capacity() {
    retirement_joins_before_reuse(true).await;
}

#[tokio::test]
async fn rldp_connection_reopen_waits_for_old_generation_cleanup() {
    retirement_joins_before_reuse(false).await;
}

async fn retirement_joins_before_reuse(fill_table: bool) {
    use crate::adnl::common::{AdnlPeers, TaggedByteSlice};
    let adnl = node().await;
    let rldp = rldp(&adnl);
    let local = adnl.key_by_tag(0).unwrap();
    let peer = rldp.get_peer(local.id(), local.id(), true, None).await.unwrap();
    let control = SendControl::new();
    *rldp.test_control.lock().unwrap() = Some(control.clone());
    let gate = Arc::new(Gate::default());
    let _release = Release(gate.clone());
    let work_gate = gate.clone();
    let (entered, started) = oneshot::channel();
    let entered = Mutex::new(Some(entered));
    *control.test_after_fec.lock().unwrap() = Some(Arc::new(move || {
        if let Some(entered) = entered.lock().unwrap().take() {
            let _ = entered.send(());
        }
        work_gate.wait();
    }));
    let sender_node = rldp.clone();
    let local_id = local.id().clone();
    let sender = tokio::spawn(async move {
        sender_node
            .message(
                &TaggedByteSlice {
                    object: b"x",
                    #[cfg(feature = "telemetry")]
                    tag: 0,
                },
                &AdnlPeers::with_keys(local_id.clone(), local_id),
                true,
                None,
            )
            .await
    });
    let mut admission = None;
    let result = std::panic::AssertUnwindSafe(async {
        bounded(started).await.unwrap();
        let deadline = Some(tokio::time::Instant::now() + Duration::from_secs(60));
        for value in 0..if fill_table { 4095u32 } else { 0 } {
            let mut id = [0; 32];
            id[..4].copy_from_slice(&value.to_le_bytes());
            rldp.get_peer(local.id(), &rtos_block::KeyId::from_data(id), true, deadline)
                .await
                .unwrap();
        }
        let other = if fill_table {
            rtos_block::KeyId::from_data([79; 32])
        } else {
            rldp.peers.expire(tokio::time::Instant::now() + Duration::from_secs(131));
            local.id().clone()
        };
        let admission_node = rldp.clone();
        let local_id = local.id().clone();
        admission = Some(tokio::spawn(async move {
            admission_node.get_peer(&local_id, &other, true, deadline).await
        }));
        bounded(peer.closed.cancelled()).await;
        bounded(control.cancelled()).await;
        if tokio::time::timeout(Duration::from_millis(20), admission.as_mut().unwrap())
            .await
            .is_ok()
        {
            // The handle was already consumed; failure cleanup must not poll it twice.
            admission = None;
            panic!("retirement must not reuse a slot while its actual FEC still runs");
        }
        assert!(rldp.transfers.iter().next().is_some(), "retain registration until real join");
        gate.release();
        let replacement = bounded(admission.as_mut().unwrap()).await.unwrap().unwrap();
        admission = None;
        assert!(!replacement.closed.is_cancelled());
        assert!(rldp.transfers.iter().next().is_none());
    })
    .catch_unwind()
    .await;
    gate.release();
    bounded(adnl.stop_checked()).await.unwrap();
    assert!(bounded(sender).await.unwrap().is_err());
    if let Some(admission) = admission {
        let _ = bounded(admission).await.unwrap();
    }
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test]
async fn rldp_connection_expiration_keeps_longest_deadline() {
    let adnl = node().await;
    let rldp = rldp(&adnl);
    let local = adnl.key_by_tag(0).unwrap();
    let now = tokio::time::Instant::now();
    let short_id = rtos_block::KeyId::from_data([11; 32]);
    let long_id = rtos_block::KeyId::from_data([12; 32]);
    let idle_id = rtos_block::KeyId::from_data([13; 32]);
    let short = rldp.get_peer(local.id(), &short_id, true, Some(now)).await.unwrap();
    let refreshed = rldp
        .get_peer(local.id(), &short_id, true, Some(now + Duration::from_secs(10)))
        .await
        .unwrap();
    assert!(Arc::ptr_eq(&short, &refreshed));
    let long = rldp
        .get_peer(local.id(), &long_id, true, Some(now + Duration::from_secs(30)))
        .await
        .unwrap();
    rldp.get_peer(local.id(), &long_id, true, Some(now)).await.unwrap();
    let idle = rldp.get_peer(local.id(), &idle_id, true, Some(now)).await.unwrap();
    rldp.peers.expire(now + Duration::from_secs(120) - Duration::from_nanos(1));
    assert!(!idle.closed.is_cancelled());
    rldp.peers.expire(now + Duration::from_secs(120));
    assert!(idle.closed.is_cancelled());
    assert!(!short.closed.is_cancelled());
    assert!(!long.closed.is_cancelled());
    rldp.peers.expire(now + Duration::from_secs(130));
    assert!(short.closed.is_cancelled());
    assert!(!long.closed.is_cancelled());
    rldp.peers.expire(now + Duration::from_secs(150));
    assert!(long.closed.is_cancelled());
    bounded(adnl.stop_checked()).await.unwrap();
}

#[tokio::test]
async fn rldp_old_inbound_expiry_preserves_reopened_registration() {
    let adnl = node().await;
    let rldp = rldp(&adnl);
    let local = adnl.key_by_tag(0).unwrap();
    let now = tokio::time::Instant::now();
    let old = rldp.get_peer(local.id(), local.id(), true, Some(now)).await.unwrap();
    let id = [94; 32];
    let (sender, _receiver) = tokio::sync::mpsc::unbounded_channel();
    old.insert_transfer(&rldp.transfers, id, super::super::RldpTransfer::Recv(sender)).unwrap();
    rldp.peers.expire(now + Duration::from_secs(120));
    let fresh = rldp.get_peer(local.id(), local.id(), true, None).await.unwrap();
    assert!(old.drained.is_cancelled());
    let (sender, _receiver) = tokio::sync::mpsc::unbounded_channel();
    fresh.insert_transfer(&rldp.transfers, id, super::super::RldpTransfer::Recv(sender)).unwrap();
    // The old timer's completion can already be in flight on another worker.
    // Its final mutation must be serialized with close and generation cleanup.
    super::super::expire_inbound_transfer(
        rldp.transfers.clone(),
        id,
        adnl.tasks().clone(),
        async {},
        Some(old),
    )
    .await;
    let preserved =
        matches!(rldp.transfers.get(&id).unwrap().val(), super::super::RldpTransfer::Recv(_));
    bounded(adnl.stop_checked()).await.unwrap();
    assert!(preserved, "old inbound expiry overwrote the reopened connection's registration");
}
