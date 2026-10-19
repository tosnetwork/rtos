// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! The production validator session and its namespace-owned signing journal.
use super::{Listener, RejectFinalitySink};
use crate::{authenticated_fixture::TestDirectory, SessionListener};
use consensus_common::ConsensusCommonFactory;
use rtos_block::{Result, UInt256};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

/// The production validator session signs with its custody signer and owns its
/// namespace journal for as long as its workers live: a second writer cannot
/// take the namespace while the session runs, and can once it has shut down.
/// A restart authenticates the journal without signing. An observer runtime
/// takes no signer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_validator_production_signer_owns_its_journal_until_shutdown() {
    use adnl::{
        node::{AdnlNode, AdnlNodeConfig},
        DhtNode, NetworkStack, OverlayNode, RldpNode,
    };
    let directory = TestDirectory::new();
    let store = Arc::new(rtos_pq_consensus::ConsensusKeyStore::from_seed(&[0xdc; 32], 0).unwrap());
    let mut custody = rtos_pq_consensus::PqConsensusCustody::default();
    custody.install(UInt256::from([2; 32]), store.clone(), 0, 0).unwrap();
    let (mut nodes, keys) = crate::pq_fixture::members();
    nodes[1] = crate::SimplexSessionNode::from_descriptor(
        &crate::signing_coordinator::tests::custody_descriptor(&store),
    )
    .unwrap();
    let (runtime, key, mut options) = crate::authenticated_fixture::runtime_with_members(
        nodes.iter().map(|node| node.descriptor.clone().unwrap()).collect(),
        keys[1].clone(),
    );
    options.first_block_timeout = Duration::from_millis(30);
    options.target_rate = Duration::from_millis(30);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
        as u32;
    let signer = crate::SessionSigner::from_custody_match(
        &custody,
        &UInt256::from([2; 32]),
        &runtime.committee()[1],
        now,
    )
    .unwrap();
    let path = std::path::PathBuf::from(
        runtime.runtime_directory(directory.path().to_str().unwrap()).unwrap(),
    );
    crate::runtime_manifest::RuntimeManifest::provision_test_validator(&runtime, &path).unwrap();
    let (_, config) =
        AdnlNodeConfig::from_ip_address_and_private_keys("127.0.0.1:0", vec![([0x74; 32], 0)])
            .unwrap();
    let adnl = AdnlNode::with_config(config).await.unwrap();
    adnl.add_key(key.clone(), 1).unwrap();
    let dht = DhtNode::with_adnl_node(adnl.clone(), 0).unwrap();
    let overlay =
        OverlayNode::with_params_and_profile(adnl.clone(), &[24; 32], 0, rtos_api::WireProfile::T0)
            .unwrap();
    let rldp = RldpNode::with_params(adnl.clone(), vec![overlay.clone()], None).unwrap();
    overlay.set_rldp(rldp.clone()).unwrap();
    let stack = Arc::new(NetworkStack { adnl: adnl.clone(), dht, overlay, rldp, quic: None });
    adnl.start_over_udp(vec![stack.overlay.clone(), stack.dht.clone(), stack.rldp.clone()])
        .await
        .unwrap();
    let manager = ConsensusCommonFactory::create_adnl_overlay_manager(
        tokio::runtime::Handle::current(),
        stack,
        None,
        false,
    )
    .unwrap();
    let listener: Arc<dyn SessionListener + Send + Sync> = Arc::new(Listener::default());
    let owner_free = || -> Result<bool> {
        let owner = std::fs::File::open(path.join(crate::signing_coordinator::OWNER_FILE))?;
        Ok(owner.try_lock().is_ok())
    };
    let result = (|| -> Result<()> {
        let create = || {
            crate::SessionFactory::create_authenticated_validator_session_checked(
                &options,
                runtime.clone(),
                signer.clone(),
                &key,
                path.to_str().unwrap().to_owned(),
                manager.clone(),
                Arc::downgrade(&listener),
                None,
                Some(Arc::new(RejectFinalitySink)),
                None,
            )
            .map_err(crate::SessionCreationFailure::into_error)
        };
        let session = create()?;
        anyhow::ensure!(!owner_free()?, "a running session must own its namespace journal");
        session.start(vec![runtime.pin().zerostate.clone()], runtime.pin().zerostate.clone());
        let deadline = Instant::now() + Duration::from_secs(5);
        while store.consensus_signatures_produced() == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        anyhow::ensure!(!owner_free()?, "ownership is retained while the session runs");
        let stopped = session.stop_checked();
        let drained = session.threads_drained();
        stopped?;
        anyhow::ensure!(drained);
        let count = store.consensus_signatures_produced();
        anyhow::ensure!(count > 0, "the session never reached the production custody signer");
        anyhow::ensure!(owner_free()?, "a shut-down session must release its namespace");
        drop(session);
        let read_journal = || -> Result<_> {
            let db =
                crate::database::SimplexDb::open(&path, &runtime.session_id().to_hex_string())?;
            let rows = db
                .storage
                .get_by_prefix(crate::signing_coordinator::PREFIX.to_vec(), None)
                .wait()?;
            db.close(None)?;
            Ok(rows)
        };
        let before = read_journal()?;
        anyhow::ensure!(before.len() > 1, "the session did not journal its signed decisions");
        // Recovery authenticates the journal before exposing a receiver and
        // does not sign while the FSM is not started.
        let recovered = create()?;
        let stopped = recovered.stop_checked();
        let drained = recovered.threads_drained();
        stopped?;
        anyhow::ensure!(drained);
        drop(recovered);
        anyhow::ensure!(read_journal()? == before, "recovery changed durable signed decisions");
        anyhow::ensure!(
            store.consensus_signatures_produced() == count,
            "recovery invoked the signer"
        );
        // An observer runtime takes no signer.
        let (observer, observer_key, observer_options) =
            crate::authenticated_fixture::runtime(false);
        let refused = crate::SessionFactory::create_authenticated_validator_session_checked(
            &observer_options,
            observer,
            signer.clone(),
            &observer_key,
            directory.path().join("observer").to_string_lossy().into_owned(),
            manager.clone(),
            Arc::downgrade(&listener),
            None,
            Some(Arc::new(RejectFinalitySink)),
            None,
        );
        if let Ok(session) = refused {
            session.stop_checked()?;
            anyhow::bail!("an observer session accepted a consensus signer");
        }
        Ok(())
    })();
    drop(manager);
    let drained = adnl.stop_checked().await;
    drained.unwrap();
    result.unwrap();
}
