// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
#[derive(Debug)]
struct ConfigLimit;
impl std::fmt::Display for ConfigLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "configuration test limit")
    }
}
impl std::error::Error for ConfigLimit {}
struct ConfigBudget(std::sync::Mutex<(usize, usize)>);
impl ConfigBudget {
    fn new(steps: usize, bytes: usize) -> Self {
        Self(std::sync::Mutex::new((steps, bytes)))
    }
}
impl rtos_block::config_read_budget::ConfigReadBudget for ConfigBudget {
    fn step(&self) -> Result<()> {
        let mut u = self.0.lock().unwrap();
        if u.0 == 0 {
            return Err(ConfigLimit.into());
        }
        u.0 -= 1;
        Ok(())
    }
    fn workspace(&self, bytes: usize) -> Result<()> {
        let mut u = self.0.lock().unwrap();
        if u.1 < bytes {
            return Err(ConfigLimit.into());
        }
        u.1 -= bytes;
        Ok(())
    }
}
#[test]
fn bounded_config_runtime_current_next_previous_and_roles_equal_ordinary() {
    let (pin, mut config, nodes) = fixture();
    let mut previous = nodes.clone();
    let mut next = nodes.clone();
    for (i, v) in previous.iter_mut().enumerate() {
        v.adnl_addr = Some(UInt256::from([40 + i as u8; 32]));
    }
    for (i, v) in next.iter_mut().enumerate() {
        v.adnl_addr = Some(UInt256::from([50 + i as u8; 32]));
    }
    config
        .set_config(ConfigParamEnum::ConfigParam32(ConfigParam32 {
            prev_validators: ValidatorSet::new(0, 1, 3, previous).unwrap(),
        }))
        .unwrap();
    config
        .set_config(ConfigParamEnum::ConfigParam36(ConfigParam36 {
            next_validators: ValidatorSet::new(100, 200, 3, next).unwrap(),
        }))
        .unwrap();
    let budget = ConfigBudget::new(1_000_000, 32 << 20);
    let decoded = config.session_config_bounded(true, &budget).unwrap();
    assert_eq!(decoded.current, config.validator_set().unwrap());
    assert_eq!(decoded.previous, config.prev_validator_set().unwrap());
    assert_eq!(decoded.next, config.next_validator_set().unwrap());
    for set in [&decoded.current, &decoded.next] {
        let shard = ShardIdent::masterchain();
        let subset = set
            .calc_subset_bounded(
                &decoded.catchain,
                shard.shard_prefix_with_tag(),
                shard.workchain_id(),
                7,
                &budget,
            )
            .unwrap()
            .0;
        for local in [KeyId::from_data([99; 32]), subset[0].adnl_addr().unwrap()] {
            let ordinary = AuthenticatedSessionRuntime::from_authenticated_config(
                pin.clone(),
                &config,
                coords(&shard),
                subset.clone(),
                local.clone(),
            )
            .unwrap();
            let bounded = AuthenticatedSessionRuntime::from_decoded_config_bounded(
                pin.clone(),
                &decoded,
                coords(&shard),
                subset.clone(),
                local,
                &budget,
            )
            .unwrap();
            assert!(ordinary.same_admission(&bounded));
            assert_eq!(
                ordinary.pq_context().unwrap().validator_info(),
                bounded.pq_context().unwrap().validator_info()
            );
        }
    }
}
#[test]
fn bounded_config_runtime_request_is_cumulative_and_rejects_duplicates() {
    let (pin, config, nodes) = fixture();
    let generous = ConfigBudget::new(1_000_000, 32 << 20);
    let before = *generous.0.lock().unwrap();
    config.session_config_bounded(true, &generous).unwrap();
    let after = *generous.0.lock().unwrap();
    let exact = ConfigBudget::new(before.0 - after.0, before.1 - after.1);
    config.session_config_bounded(true, &exact).unwrap();
    let error = config.session_config_bounded(true, &exact).err().unwrap();
    assert!(error.downcast_ref::<ConfigLimit>().is_some());
    let decoded = config.session_config_bounded(true, &generous).unwrap();
    let shard = ShardIdent::masterchain();
    assert!(AuthenticatedSessionRuntime::from_decoded_config_bounded(
        pin,
        &decoded,
        coords(&shard),
        vec![nodes[0].clone(), nodes[0].clone()],
        KeyId::from_data([99; 32]),
        &generous
    )
    .is_err());
}
#[test]
fn bounded_config_consumer_scope_preserves_unused_bad_sets() {
    let (pin, mut config, nodes) = fixture();
    // A protocol-1 live runtime never reads transport sets outside current.
    config
        .set_config(ConfigParamEnum::ConfigParam30(NewConsensusConfigAll {
            mc: Some(SimplexConfig { protocol_version: 1, ..Default::default() }),
            shard: Some(SimplexConfig { protocol_version: 1, ..Default::default() }),
        }))
        .unwrap();
    for index in [32u32, 36] {
        let mut wrapper = BuilderData::new();
        wrapper.checked_append_reference(Cell::default()).unwrap();
        config.config_params.set_builder(index.write_to_bitstring().unwrap(), &wrapper).unwrap();
    }
    let budget = ConfigBudget::new(1_000_000, 32 << 20);
    let shard = ShardIdent::masterchain();
    let ordinary = AuthenticatedSessionRuntime::from_authenticated_config(
        pin.clone(),
        &config,
        coords(&shard),
        nodes.clone(),
        nodes[0].adnl_addr().unwrap(),
    )
    .unwrap();
    let live = config.runtime_session_config_bounded(true, &budget).unwrap();
    let bounded = AuthenticatedSessionRuntime::from_decoded_config_bounded(
        pin,
        &live,
        coords(&shard),
        nodes.clone(),
        nodes[0].adnl_addr().unwrap(),
        &budget,
    )
    .unwrap();
    assert!(ordinary.same_admission(&bounded));
    assert!(config.governing_session_config_bounded(true, &budget).is_ok());
    // Retired identity needs next even at protocol1 to check requested epoch.
    assert!(config.session_config_bounded(true, &budget).is_err());
    config
        .set_config(ConfigParamEnum::ConfigParam30(NewConsensusConfigAll {
            mc: Some(SimplexConfig { protocol_version: 2, ..Default::default() }),
            shard: None,
        }))
        .unwrap();
    assert!(config.runtime_session_config_bounded(true, &budget).is_err());
    assert!(config.governing_session_config_bounded(true, &budget).is_ok());
}

#[test]
fn recovery_admission_canonicalizes_only_cached_committee_prefixes() {
    let (pin, config, nodes) = fixture();
    let shard = ShardIdent::masterchain();
    let local = nodes[2].adnl_addr().unwrap();
    // A shuffled subset may retain prefix caches from its full set; a live
    // ValidatorSet rebuild recomputes those caches in subset order.
    let mut raw = vec![nodes[2].clone(), nodes[0].clone()];
    raw[0].weight = 17;
    raw[1].weight = 29;
    raw[0].prev_weight_sum = 999;
    raw[1].prev_weight_sum = 0;
    let canonical = ValidatorSet::new(1, 100, 2, raw.clone()).unwrap();
    assert_ne!(raw, canonical.list());
    let create = |committee| AuthenticatedSessionRuntime::from_authenticated_config(
        pin.clone(), &config, coords(&shard), committee, local.clone()).unwrap();
    let live = create(canonical.list().to_vec());
    let recovered = create(raw.clone());
    assert!(live.same_admission(&recovered));
    assert_eq!(recovered.committee(), canonical.list());
    assert_eq!(recovered.committee()[0].prev_weight_sum, 0);
    assert_eq!(recovered.committee()[1].prev_weight_sum, 17);
    let identity = derive_session_from_config(pin.global_id, &config, coords(&shard), &raw).unwrap();
    assert_eq!(recovered.session_id(), &identity.session_id);
    let budget = ConfigBudget::new(1_000_000, 32 << 20);
    let decoded = config.session_config_bounded(true, &budget).unwrap();
    let bounded = AuthenticatedSessionRuntime::from_decoded_config_bounded(
        pin.clone(), &decoded, coords(&shard), raw.clone(), local.clone(), &budget).unwrap();
    assert!(live.same_admission(&bounded));
    assert_eq!(live.pq_context().unwrap().validator_info(), bounded.pq_context().unwrap().validator_info());
    let mut changed = raw.clone();
    changed[1].weight += 1;
    assert!(!live.same_admission(&create(changed)));
    let mut changed = raw;
    changed.reverse();
    assert!(!live.same_admission(&create(changed)));
    // Same session ID is insufficient: transport admission and local role also
    // have to remain identical, even though neither is the prefix cache.
    let mut changed = live.clone();
    changed.members.push(KeyId::from_data([98; 32]));
    assert_eq!(live.admission_mismatch(&changed), Some("members"));
    let mut changed = live.clone();
    changed.local_role = LocalRole::Observer;
    assert_eq!(live.admission_mismatch(&changed), Some("local_role"));
    let mut changed = live.clone();
    changed.committee[0].adnl_addr = Some(UInt256::from([97; 32]));
    assert_eq!(live.admission_mismatch(&changed), Some("committee"));
    let mut changed = live.clone();
    changed.committee[0] = nodes[1].clone();
    assert_eq!(live.admission_mismatch(&changed), Some("committee"));
}
