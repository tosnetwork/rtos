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
