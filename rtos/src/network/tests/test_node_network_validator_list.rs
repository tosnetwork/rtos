/*
 * RTOS project modifications (2026-10-10): project and crate naming.
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use super::*;
use crate::validator::validator_manager::emulator_network_bootstrap::EmulatorNetworkBootstrap;
use futures::FutureExt;
use rtos_block::{Ed25519KeyOption, ZeroizingBytes};

fn make_test_key() -> Arc<dyn KeyOption> {
    Ed25519KeyOption::<ZeroizingBytes>::generate().unwrap()
}

fn make_validator_node(
    public_key: Arc<dyn KeyOption>,
    adnl_key: Arc<dyn KeyOption>,
) -> CatchainNode {
    CatchainNode { public_key: public_key.into(), adnl_id: adnl_key.id().clone() }
}

#[test]
fn test_select_local_validator_candidate_matches_pubkey_and_adnl() {
    let validator_key = make_test_key();
    let adnl_key = make_test_key();
    let validator = make_validator_node(validator_key.clone(), adnl_key.clone());
    let validator_key_ids = vec![validator_key.id().clone()];
    let validator_adnl_key_ids = vec![adnl_key.id().clone()];

    let (local_validator, adnl_missing) = select_local_validator_candidate(
        std::slice::from_ref(&validator),
        &validator_key_ids,
        &validator_adnl_key_ids,
    );

    let local_validator = local_validator.expect("local validator should be selected");
    assert_eq!(local_validator.public_key.id(), validator_key.id());
    assert_eq!(local_validator.adnl_id, adnl_key.id().clone());
    assert!(!adnl_missing);
}

#[test]
fn test_select_local_validator_candidate_matches_pubkey_when_adnl_missing() {
    let validator_key = make_test_key();
    let chain_adnl_key = make_test_key();
    let local_adnl_key = make_test_key();
    let validator = make_validator_node(validator_key.clone(), chain_adnl_key.clone());
    let validator_key_ids = vec![validator_key.id().clone()];
    let validator_adnl_key_ids = vec![local_adnl_key.id().clone()];

    let (local_validator, adnl_missing) = select_local_validator_candidate(
        std::slice::from_ref(&validator),
        &validator_key_ids,
        &validator_adnl_key_ids,
    );

    let local_validator = local_validator.expect("pubkey membership should select the validator");
    assert_eq!(local_validator.public_key.id(), validator_key.id());
    assert_eq!(local_validator.adnl_id, chain_adnl_key.id().clone());
    assert!(adnl_missing);
}

#[test]
fn test_select_local_validator_candidate_accepts_pubkey_adnl_fallback() {
    let validator_key = make_test_key();
    let chain_adnl_key = make_test_key();
    let validator = make_validator_node(validator_key.clone(), chain_adnl_key);
    let validator_key_ids = vec![validator_key.id().clone()];
    // C++ parity fallback: allow validator pubkey short-id to serve as ADNL identity.
    let validator_adnl_key_ids = vec![validator_key.id().clone()];

    let (local_validator, adnl_missing) = select_local_validator_candidate(
        std::slice::from_ref(&validator),
        &validator_key_ids,
        &validator_adnl_key_ids,
    );

    let local_validator = local_validator.expect("pubkey membership should select validator");
    assert_eq!(local_validator.public_key.id(), validator_key.id());
    assert!(!adnl_missing);
}

#[test]
fn test_select_local_validator_candidate_returns_none_without_pubkey_match() {
    let validator_key = make_test_key();
    let adnl_key = make_test_key();
    let other_validator_key = make_test_key();
    let validator = make_validator_node(validator_key, adnl_key.clone());
    let validator_key_ids = vec![other_validator_key.id().clone()];
    let validator_adnl_key_ids = vec![adnl_key.id().clone()];

    let (local_validator, adnl_missing) = select_local_validator_candidate(
        std::slice::from_ref(&validator),
        &validator_key_ids,
        &validator_adnl_key_ids,
    );

    assert!(local_validator.is_none());
    assert!(!adnl_missing);
}

/// Verifies that selection follows local-key order, not validator-list order.
///
/// This mirrors C++ `get_validator()` which iterates `temp_keys_` and returns the first
/// local key that is present in the validator set, without ADNL consideration.
#[test]
fn test_select_local_validator_candidate_uses_first_local_key_match() {
    let key_a = make_test_key();
    let key_b = make_test_key();
    let adnl_a = make_test_key();
    let adnl_b = make_test_key();
    let local_adnl = make_test_key();

    let val_a = make_validator_node(key_a.clone(), adnl_a.clone());
    let val_b = make_validator_node(key_b.clone(), adnl_b.clone());
    let validators = vec![val_a, val_b];

    // Case 1: validator list order is [A, B], but local key order is [B, A].
    // Rust must follow local key order to match C++ temp_keys_ iteration.
    let local_key_ids = vec![key_b.id().clone(), key_a.id().clone()];
    let local_adnl_ids = vec![adnl_b.id().clone(), local_adnl.id().clone()];

    let (selected, adnl_missing) =
        select_local_validator_candidate(&validators, &local_key_ids, &local_adnl_ids);

    let selected = selected.expect("should select first local-key match");
    assert_eq!(selected.public_key.id(), key_b.id(), "must follow local key order");
    assert!(!adnl_missing, "selected validator has a ready ADNL key");

    // Case 2: ADNL readiness still must not change key selection.
    let unrelated_adnl = make_test_key();
    let local_adnl_ids_none = vec![unrelated_adnl.id().clone(), adnl_a.id().clone()];

    let (selected2, adnl_missing2) =
        select_local_validator_candidate(&validators, &local_key_ids, &local_adnl_ids_none);

    let selected2 = selected2.expect("should still select first local-key match");
    assert_eq!(selected2.public_key.id(), key_b.id(), "ADNL readiness must not affect key order");
    assert!(adnl_missing2);
}

const REGISTRATION_ELECTION: i32 = 1001;

async fn registration_fixture() -> Result<(EmulatorNetworkBootstrap, Arc<NodeNetwork>)> {
    let bootstrap = EmulatorNetworkBootstrap::build(1)?;
    let mut config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&bootstrap.config_path)?)?;
    config["ip_address_quic"] = "127.0.0.1:0".into();
    for key in config["validator_keys"].as_array_mut().unwrap() {
        key["election_id"] = REGISTRATION_ELECTION.into();
    }
    std::fs::write(&bootstrap.config_path, serde_json::to_vec(&config)?)?;
    let network = NodeNetwork::new(
        bootstrap.load_node_config().await?,
        tokio_util::sync::CancellationToken::new(),
        #[cfg(feature = "telemetry")]
        crate::collator_test_bundle::create_engine_telemetry(),
        crate::collator_test_bundle::create_engine_allocated(),
    )
    .await?;
    let prepared = async {
        network.config_handler.wait_test_subscribers().await?;
        // Leave the real configuration intact but unload the transport so each
        // test can control the competing callback's next registration attempt.
        network
            .event(ConfigEvent::RemoveValidatorAdnlKey(
                bootstrap.validators[0].adnl_key.id().clone(),
                REGISTRATION_ELECTION,
            ))
            .await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if let Err(error) = prepared {
        let _ = network.stop_adnl().await;
        return Err(error);
    }
    Ok((bootstrap, network))
}

fn hold_registration(
    network: &NodeNetwork,
) -> (tokio::sync::oneshot::Receiver<()>, tokio::sync::oneshot::Sender<()>) {
    let (entered, arrived) = tokio::sync::oneshot::channel();
    let (release, held) = tokio::sync::oneshot::channel();
    *network.validator_context.adnl_registration_gate.lock().unwrap() = Some((entered, held));
    (arrived, release)
}

async fn finish_registration_test(
    network: &NodeNetwork,
    result: std::thread::Result<Result<()>>,
) -> Result<()> {
    let stopped = network.stop_adnl().await;
    match result {
        Ok(result) => {
            result?;
            stopped
        }
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn validator_registration_waits_for_config_callback_before_selecting_context() -> Result<()> {
    let (bootstrap, network) = registration_fixture().await?;
    let result = std::panic::AssertUnwindSafe(async {
        let key = bootstrap.validators[0].adnl_key.id().clone();
        let (arrived, release) = hold_registration(&network);
        let callback = {
            let network = network.clone();
            let key = key.clone();
            tokio::spawn(async move {
                network.event(ConfigEvent::AddValidatorAdnlKey(key, REGISTRATION_ELECTION)).await
            })
        };
        tokio::time::timeout(Duration::from_secs(5), arrived).await??;
        assert!(network.validator_context.adnl_key_ids.get(&REGISTRATION_ELECTION).is_none());
        assert!(network.network_context.stack.adnl.key_by_id(&key).is_err());
        let nodes = vec![make_validator_node(
            bootstrap.validators[0].validator_key.clone(),
            bootstrap.validators[0].adnl_key.clone(),
        )];
        let list_id = UInt256::from([92; 32]);
        let selected = network.set_validator_list(list_id.clone(), &nodes);
        tokio::pin!(selected);
        // Poll the real selection future while the callback is inside key load.
        // It must wait, not return membership-only with missing transport state.
        assert!(tokio::time::timeout(Duration::from_millis(30), &mut selected).await.is_err());
        release.send(()).unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(5), callback).await???);
        let outcome = tokio::time::timeout(Duration::from_secs(5), &mut selected).await??;
        assert!(matches!(outcome, ValidatorListOutcome::Selected { .. }));
        assert!(network.has_validator_list_context(&list_id));
        assert!(!network.load_and_store_validator_adnl_key(key, REGISTRATION_ELECTION).await?);
        Ok(())
    })
    .catch_unwind()
    .await;
    finish_registration_test(&network, result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn validator_registration_failed_lookup_and_transport_are_retryable() -> Result<()> {
    let (bootstrap, network) = registration_fixture().await?;
    let result = std::panic::AssertUnwindSafe(async {
        let unknown = make_test_key();
        assert!(network
            .load_and_store_validator_adnl_key(unknown.id().clone(), REGISTRATION_ELECTION)
            .await
            .is_err());
        assert!(network.validator_context.adnl_key_ids.get(&REGISTRATION_ELECTION).is_none());

        // A real transport rejection (reserved DHT tag) must not commit a
        // registration either, or alter the DHT identity it collided with.
        let key = bootstrap.validators[0].adnl_key.id().clone();
        let dht = network.network_context.stack.adnl.key_by_tag(NodeNetwork::TAG_DHT_KEY)?;
        assert!(network
            .load_and_store_validator_adnl_key(key.clone(), NodeNetwork::TAG_DHT_KEY as i32)
            .await
            .is_err());
        assert!(network
            .validator_context
            .adnl_key_ids
            .get(&(NodeNetwork::TAG_DHT_KEY as i32))
            .is_none());
        assert_eq!(
            network.network_context.stack.adnl.key_by_tag(NodeNetwork::TAG_DHT_KEY)?.id(),
            dht.id()
        );

        // The valid candidate uses the SAME election as the failed lookup. The
        // old reservation bug rejected this as a conflicting fallback key.
        assert!(
            network.load_and_store_validator_adnl_key(key.clone(), REGISTRATION_ELECTION).await?
        );
        assert_eq!(network.network_context.stack.adnl.key_by_id(&key)?.id(), &key);
        assert!(network
            .load_and_store_validator_adnl_key(unknown.id().clone(), REGISTRATION_ELECTION)
            .await
            .is_err());
        assert_eq!(
            network
                .validator_context
                .adnl_key_ids
                .get(&REGISTRATION_ELECTION)
                .unwrap()
                .val()
                .key_id,
            key
        );
        Ok(())
    })
    .catch_unwind()
    .await;
    finish_registration_test(&network, result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn validator_registration_cancelled_lookup_releases_election() -> Result<()> {
    let (bootstrap, network) = registration_fixture().await?;
    let result = std::panic::AssertUnwindSafe(async {
        let key = bootstrap.validators[0].adnl_key.id().clone();
        let (arrived, release) = hold_registration(&network);
        let loader = {
            let network = network.clone();
            let key = key.clone();
            tokio::spawn(async move {
                network.load_and_store_validator_adnl_key(key, REGISTRATION_ELECTION).await
            })
        };
        tokio::time::timeout(Duration::from_secs(5), arrived).await??;
        loader.abort();
        assert!(loader.await.unwrap_err().is_cancelled());
        drop(release);
        assert!(network.validator_context.adnl_key_ids.get(&REGISTRATION_ELECTION).is_none());
        assert!(
            tokio::time::timeout(
                Duration::from_secs(5),
                network.load_and_store_validator_adnl_key(key.clone(), REGISTRATION_ELECTION),
            )
            .await??
        );
        assert_eq!(network.network_context.stack.adnl.key_by_id(&key)?.id(), &key);
        Ok(())
    })
    .catch_unwind()
    .await;
    finish_registration_test(&network, result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn validator_registration_removal_waits_for_inflight_add() -> Result<()> {
    let (bootstrap, network) = registration_fixture().await?;
    let result = std::panic::AssertUnwindSafe(async {
        let key = bootstrap.validators[0].adnl_key.id().clone();
        let (arrived, release) = hold_registration(&network);
        let loader = {
            let network = network.clone();
            let key = key.clone();
            tokio::spawn(async move {
                network.load_and_store_validator_adnl_key(key, REGISTRATION_ELECTION).await
            })
        };
        tokio::time::timeout(Duration::from_secs(5), arrived).await??;
        let removed =
            network.event(ConfigEvent::RemoveValidatorAdnlKey(key.clone(), REGISTRATION_ELECTION));
        tokio::pin!(removed);
        assert!(tokio::time::timeout(Duration::from_millis(30), &mut removed).await.is_err());
        release.send(()).unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(5), loader).await???);
        assert!(tokio::time::timeout(Duration::from_secs(5), &mut removed).await??);
        assert!(network.validator_context.adnl_key_ids.get(&REGISTRATION_ELECTION).is_none());
        assert!(network.network_context.stack.adnl.key_by_id(&key).is_err());
        Ok(())
    })
    .catch_unwind()
    .await;
    finish_registration_test(&network, result).await
}
