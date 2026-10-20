// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Real InternalDb before-write / after-successful-sync error injection. These
//! are application-visible storage boundary errors, not failed OS syscalls.
use super::*;
use crate::internal_db::OutboxSyncBoundary;
use crate::propagation_outbox::inspect_closure_batch;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

async fn released_write_failure(boundary: OutboxSyncBoundary) {
    let signer =
        std::env::var("RTOS_PUBLIC_FIXTURE_SIGNER").expect("public fixture signer required");
    let pair = Pair::with_source_transport("included").await;
    let run=std::panic::AssertUnwindSafe(async {
        let engine=&pair.provider;
        engine.clone().download_and_apply_block(pair.master.id(),1,false).await.unwrap();
        let zero=engine.load_state(&pair.anchor).await.unwrap();
        let config=zero.config_params().unwrap();
        let cc=pair.master.block().unwrap().read_info().unwrap().gen_catchain_seqno();
        let (committee,_)=config.validator_set().unwrap()
            .calc_subset(&config.catchain_config().unwrap(),SHARD_FULL,-1,cc).unwrap();
        let local=engine.network().context().stack.adnl.key_by_tag(NodeNetwork::TAG_OVERLAY_KEY)
            .unwrap().id().clone();
        let runtime=Arc::new(AuthenticatedSessionRuntime::from_authenticated_config(
            SessionNetworkPin{global_id:-239,zerostate:pair.anchor.clone()},config,
            rtos_api::session_identity::SessionCoordinates{shard:pair.anchor.shard(),catchain_seqno:cc,
                vertical_seqno:0,last_key_block_seqno:0,new_catchain_ids:false},committee,local,
        ).unwrap().bind_recovery_anchor(pair.anchor.clone()).unwrap());
        let namespace=PathBuf::from(runtime.runtime_directory(
            Path::new(engine.db_root_dir().unwrap()).join("catchains").to_str().unwrap()).unwrap());
        let domain=OutboxDomain{zerostate:pair.anchor.clone(),global_id:-239,wire_profile:WireProfile::T0};
        let worker=engine.ensure_publication_worker().await.unwrap();
        let real_confirm=worker.delivered_sink(runtime.clone());
        let db=engine.db().clone();
        let attempts=Arc::new(AtomicUsize::new(0));
        let injections=Arc::new(AtomicUsize::new(0));
        let result=Arc::new(Mutex::new(None::<String>));
        let expected=Arc::new(Mutex::new(None));
        let arm_attempts=attempts.clone();
        let arm_injections=injections.clone();
        let observed=result.clone();
        let offered=expected.clone();
        let hook_domain=domain.clone();
        let confirm:simplex::finality_delivery::DeliveredCompletionSink=Arc::new(move |receipt,done| {
            let offer=receipt.offer().clone();
            assert!(offered.lock().unwrap().replace(offer.clone()).is_none(),"only one real confirmation is armed");
            let attempts=arm_attempts.clone();
            let injections=arm_injections.clone();
            let domain=hook_domain.clone();
            db.set_outbox_sync_observer(Some(Arc::new(move |point,puts,_deletes| {
                // Validate the exact serialized write, not a call-number guess:
                // no reserve/offer/other event write may satisfy this fault.
                let (entries,closed)=inspect_closure_batch(puts,&domain)?;
                if !entries.is_empty() || closed.len()!=1 || !closed[0].released || closed[0].offer()!=offer {
                    rtos_block::fail!("Released fault intercepted unrelated storage transition");
                }
                if point==OutboxSyncBoundary::BeforeWrite { attempts.fetch_add(1,Ordering::SeqCst); }
                if point==boundary {
                    if injections.fetch_add(1,Ordering::SeqCst)!=0 {
                        rtos_block::fail!("poisoned outbox attempted another storage write");
                    }
                    rtos_block::fail!("Injected Released storage boundary error at {point:?}; not a syscall EIO");
                }
                Ok(())
            })));
            let observed=observed.clone();
            real_confirm(receipt,Box::new(move |reply| {
                *observed.lock().unwrap()=Some(match &reply {
                    Ok(())=>"UNEXPECTED SUCCESS".to_owned(),Err(error)=>error.to_string(),
                });
                done(reply);
            }))
        });
        let source=FinalityDeliveryTestDriver::open(runtime.clone(),&namespace,worker.sink(runtime.clone()),confirm).unwrap();
        source.prepare_intents(false).unwrap();
        let root=engine.load_state(pair.master.id()).await.unwrap().root_cell().clone();
        let creator=runtime.committee()[0].validator_id().unwrap();
        let (id,_,row)=chain::successor(&signer,pair.master.id(),&root,false,0,cc,&creator);
        let block=fixture_block(&row);
        let proof=BlockProofStuff::deserialize(&id,decode(&row["proof_boc"]),false).unwrap();
        let created=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let draft=FinalizedDeliveryDraft{block_id:id.clone(),source_info:BlockSourceInfo{
            source:ValidatorIdentity::from_descriptor(&runtime.committee()[0]).unwrap(),
            priority:BlockCandidatePriority{round:id.seq_no(),first_block_round:0,priority:0}},
            data:ConsensusCommonFactory::create_block_payload(block.data().to_vec()),
            finality:SessionFinality::Carrier(proof.drain_signatures().unwrap()),
            last_mc_finalized_seqno:0,candidate_already_sent:false,created_at_unix_secs:created};
        engine.set_test_chain_time(Some(1002+id.seq_no()));
        pair.receiver.set_test_chain_time(Some(1002+id.seq_no()));
        if let Some(observer)=&pair.observer { observer.set_test_chain_time(Some(1002+id.seq_no())); }
        engine.enable_publication_worker().await.unwrap();
        tokio::time::timeout(Duration::from_secs(60),async{
            loop{if source.poll(draft.clone()).unwrap() && source.counts().unwrap().1==1 {break;}
                tokio::time::sleep(Duration::from_millis(10)).await;}
        }).await.expect("real source handoff must become a synced canonical reference");
        tokio::time::timeout(Duration::from_secs(120),async{
            loop{source.maintain().unwrap();if result.lock().unwrap().is_some(){break;}
                tokio::time::sleep(Duration::from_millis(20)).await;}
        }).await.expect("real opaque source confirmation did not reach the Released write");
        let error=result.lock().unwrap().clone().unwrap();
        assert!(error.contains("Injected Released storage boundary error"),"{error}");
        assert_eq!(attempts.load(Ordering::SeqCst),1);
        assert_eq!(injections.load(Ordering::SeqCst),1);
        let offer=expected.lock().unwrap().clone().unwrap();
        let (active,closed)=inspect_closure_progress(engine.db(),&domain).unwrap();
        assert_eq!(closed.len(),1);
        assert_eq!(closed[0].offer(),offer);
        assert_eq!(closed[0].binding.created_at_unix_secs,created);
        let written=boundary==OutboxSyncBoundary::AfterSuccessfulSync;
        assert_eq!(closed[0].released,written);
        assert_eq!(active.len(),usize::from(!written));
        assert_eq!(source.counts().unwrap(),(0,0,1));
        let source_id=simplex::finality_delivery::close_source_id(&offer.request).unwrap();
        let path=source_directory(&namespace).join("references-v1").join(format!("{}.delivered",source_id.to_hex_string()));
        let disk:serde_json::Value=serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(disk["node_confirmed"],false,"error must not acknowledge source confirmation");
        // The actor's actual poison path closes admission. No second capability
        // is fabricated or replayed to check this refusal.
        assert!(worker.sink(runtime).lookup_terminal(offer.request,
            Box::new(|_|panic!("rejected poisoned admission must not call completion"))).is_err());
        assert!(engine.ensure_publication_worker().await.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst),1,"no same-instance retry after uncertain outcome");
        drop(source);
        (namespace,domain,closed[0].clone())
    }).catch_unwind().await;
    // Collect all three real Engine joins before asserting any error. The
    // provider must report the poisoned writer; peer shutdowns must succeed.
    let mut engines = vec![pair.provider.clone(), pair.receiver.clone()];
    engines.extend(pair.observer.iter().cloned());
    let stopped =
        futures::future::join_all(engines.into_iter().map(|engine| engine.wait_stop())).await;
    let (namespace, domain, original) =
        run.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    assert!(stopped[0].is_err(), "provider must report uncertain WAL failure");
    assert!(stopped.iter().skip(1).all(|result| result.is_ok()));
    let Pair { _dir: dir, provider, receiver, observer, .. } = pair;
    drop(provider);
    drop(receiver);
    drop(observer);
    let engine = open_engine(&dir.path().join("provider")).await;
    let mut service = None;
    let run = std::panic::AssertUnwindSafe(async {
        let (active, closed) = inspect_closure_progress(engine.db(), &domain).unwrap();
        assert_eq!(
            closed,
            vec![original.clone()],
            "cold physical state must match the actual boundary"
        );
        assert_eq!(active.len(), usize::from(!original.released));
        engine.ensure_publication_worker().await.unwrap();
        service = Some(engine.ensure_retired_session_recovery().await.unwrap());
        let final_record = tokio::time::timeout(Duration::from_secs(90), async {
            loop {
                let (active, closed) = inspect_closure_progress(engine.db(), &domain).unwrap();
                if active.is_empty() && closed.len() == 1 && closed[0].released {
                    let batch =
                        simplex::finality_delivery::scan_finality_closures_namespace_report(
                            &namespace, None, 16,
                        )
                        .unwrap();
                    if batch.next_cursor.is_some() && batch.items.is_empty() {
                        break closed[0].clone();
                    }
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("cold service must reconcile real Delivered and actual durable custody");
        assert_eq!(final_record.binding, original.binding);
        assert_eq!(final_record.lease_generation, original.lease_generation);
        assert_eq!(final_record.dependency_digest, original.dependency_digest);
    })
    .catch_unwind()
    .await;
    engine.wait_stop().await.unwrap();
    if let Some(service) = service {
        assert_eq!(service.snapshot().active, 0);
    }
    run.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real public signer/network/Source+InternalDb storage boundary failure, not syscall EIO"]
async fn persistent_closure_released_before_write_error_and_cold_service() {
    released_write_failure(OutboxSyncBoundary::BeforeWrite).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real public signer/network/Source+InternalDb storage boundary failure, not syscall EIO"]
async fn persistent_closure_released_after_sync_error_and_cold_service() {
    released_write_failure(OutboxSyncBoundary::AfterSuccessfulSync).await;
}
