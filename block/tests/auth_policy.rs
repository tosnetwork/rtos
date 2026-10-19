// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use rtos_block::*;

fn hex(cell: &Cell) -> String {
    write_boc(cell).unwrap().iter().map(|b| format!("{b:02x}")).collect()
}
fn policy(sequence: u64, retired: u16, deadline: u32, network: u8) -> AuthPolicy {
    AuthPolicy { network: UInt256::from([network; 32]), sequence, retired, deadline }
}
fn config(version: u32, policy: Option<Cell>, mandatory: bool, critical: bool) -> ConfigParams {
    let mut config = ConfigParams::default();
    config
        .set_config(ConfigParamEnum::ConfigParam8(ConfigParam8 {
            global_version: GlobalVersion { version, capabilities: 0 },
        }))
        .unwrap();
    if let Some(cell) = policy {
        config.set_config(ConfigParamEnum::ConfigParamAny(48, cell)).unwrap();
    }
    for (number, include) in [(9, mandatory), (10, critical)] {
        let mut map = HashmapE::with_bit_len(32);
        // Nonempty even when 48 is absent; checks membership rather than presence.
        map.set(8u32.write_to_bitstring().unwrap(), &SliceData::default()).unwrap();
        if include {
            map.set(48u32.write_to_bitstring().unwrap(), &SliceData::default()).unwrap();
        }
        config
            .set_config(ConfigParamEnum::ConfigParamAny(number, map.data().unwrap().clone()))
            .unwrap();
    }
    config
}
fn outcome(cell: Cell) -> String {
    match AuthPolicy::construct_from_cell(cell) {
        Ok(p) => format!("1\t{:x}\t{}\t{}\t{}", p.network, p.sequence, p.retired, p.deadline),
        Err(_) => "0".to_string(),
    }
}
fn raw_policy(
    tag: u8,
    retired: u16,
    entries: &[(u8, u32)],
    wrong_profile: bool,
    tail: bool,
    extra_ref: bool,
) -> Cell {
    let mut b = BuilderData::new();
    b.append_u8(tag).unwrap();
    UInt256::from([7; 32]).write_to(&mut b).unwrap();
    0u64.write_to(&mut b).unwrap();
    retired.write_to(&mut b).unwrap();
    let mut dict = HashmapE::with_bit_len(8);
    for (key, value) in entries {
        dict.set(key.write_to_bitstring().unwrap(), &value.write_to_bitstring().unwrap()).unwrap();
    }
    dict.write_to(&mut b).unwrap();
    let hash = if wrong_profile {
        UInt256::default()
    } else {
        UInt256::calc_file_hash(AUTH_POLICY_PROFILE.as_bytes())
    };
    hash.write_to(&mut b).unwrap();
    if tail {
        b.append_bit_one().unwrap();
    }
    if extra_ref {
        b.checked_append_reference(Cell::default()).unwrap();
    }
    b.into_cell().unwrap()
}

#[test]
fn auth_policy_reference_matrix() {
    let mut rows: Vec<(String, String, String, String, String)> = Vec::new();
    let mut policies = vec![None];
    for network in [0, 1] {
        for sequence in [0, 1, u64::MAX] {
            for retired in [0, 2] {
                for deadline in [0, 100, 200] {
                    let cell = policy(sequence, retired, deadline, network).serialize().unwrap();
                    rows.push((
                        format!("policy-{network}-{sequence}-{retired}-{deadline}"),
                        "p".into(),
                        hex(&cell),
                        "-".into(),
                        outcome(cell.clone()),
                    ));
                    policies.push(Some(cell));
                }
            }
        }
    }
    let malformed = [
        raw_policy(0xa0, 0, &[], false, false, false),
        raw_policy(0xa1, 1, &[], false, false, false),
        raw_policy(0xa1, 3, &[], false, false, false),
        raw_policy(0xa1, 0, &[], true, false, false),
        raw_policy(0xa1, 0, &[], false, true, false),
        raw_policy(0xa1, 0, &[], false, false, true),
        raw_policy(0xa1, 0, &[(1, 0)], false, false, false),
        raw_policy(0xa1, 0, &[(0, 100)], false, false, false),
        raw_policy(0xa1, 0, &[(2, 100)], false, false, false),
        raw_policy(0xa1, 0, &[(1, 100), (2, 200)], false, false, false),
        Cell::default(),
    ];
    for (i, cell) in malformed.iter().enumerate() {
        rows.push((
            format!("malformed-{i}"),
            "p".into(),
            hex(cell),
            "-".into(),
            outcome(cell.clone()),
        ));
    }
    for version in [0, 14, 15, 16, 17, 19] {
        for mandatory in [false, true] {
            for critical in [false, true] {
                for (i, cell) in
                    policies.iter().cloned().chain(malformed.iter().cloned().map(Some)).enumerate()
                {
                    let cfg = config(version, cell.clone(), mandatory, critical);
                    // Admission without a predecessor is exactly the standalone check.
                    assert_eq!(
                        validate_auth_policy_admission(Ok(&cfg), None).is_ok(),
                        cfg.validate_auth_policy_config().is_ok()
                    );
                    rows.push((
                        format!("config-{version}-{mandatory}-{critical}-{i}"),
                        "c".into(),
                        hex(cfg.root().unwrap()),
                        "-".into(),
                        u8::from(cfg.validate_auth_policy_config().is_ok()).to_string(),
                    ));
                }
            }
        }
    }
    for (i, old) in policies.iter().enumerate() {
        for (j, new) in policies.iter().enumerate() {
            let old = config(16, old.clone(), true, true);
            let new = config(16, new.clone(), true, true);
            assert_eq!(
                validate_auth_policy_admission(Ok(&new), Some(Ok(&old))).is_ok(),
                old.validate_auth_policy_transition(&new).is_ok()
            );
            rows.push((
                format!("transition-{i}-{j}"),
                "t".into(),
                hex(old.root().unwrap()),
                hex(new.root().unwrap()),
                u8::from(old.validate_auth_policy_transition(&new).is_ok()).to_string(),
            ));
        }
    }
    for (i, cell) in malformed.iter().enumerate() {
        let old = config(16, Some(cell.clone()), true, true);
        let new = config(16, policies[1].clone(), true, true);
        assert_eq!(
            validate_auth_policy_admission(Ok(&new), Some(Ok(&old))).is_ok(),
            old.validate_auth_policy_transition(&new).is_ok()
        );
        rows.push((
            format!("transition-malformed-old-{i}"),
            "t".into(),
            hex(old.root().unwrap()),
            hex(new.root().unwrap()),
            u8::from(old.validate_auth_policy_transition(&new).is_ok()).to_string(),
        ));
    }
    for number in [8, 9, 10] {
        for mutation in ["absent", "empty", "trailing"] {
            let mut cfg = config(17, policies[1].clone(), true, true);
            match mutation {
                "absent" => cfg.update_param(number, |p| *p = None).unwrap(),
                "empty" => cfg
                    .set_config(ConfigParamEnum::ConfigParamAny(number, Cell::default()))
                    .unwrap(),
                _ => {
                    let original = cfg.config_cell_slice(number).unwrap();
                    let mut b = original.as_builder().unwrap();
                    b.append_bit_one().unwrap();
                    cfg.set_config(ConfigParamEnum::ConfigParamAny(number, b.into_cell().unwrap()))
                        .unwrap();
                }
            }
            assert_eq!(
                validate_auth_policy_admission(Ok(&cfg), None).is_ok(),
                cfg.validate_auth_policy_config().is_ok()
            );
            rows.push((
                format!("config-field-{number}-{mutation}"),
                "c".into(),
                hex(cfg.root().unwrap()),
                "-".into(),
                u8::from(cfg.validate_auth_policy_config().is_ok()).to_string(),
            ));
        }
    }
    if let Some(path) = std::env::var_os("RTOS_AUTH_POLICY_EXPORT") {
        std::fs::write(
            path,
            rows.iter()
                .map(|(name, mode, a, b, result)| format!("{name}\t{mode}\t{a}\t{b}\t{result}\n"))
                .collect::<String>(),
        )
        .unwrap();
    } else {
        let expected = include_str!("data/auth-policy.tsv");
        let actual = rows
            .iter()
            .map(|(name, _, _, _, result)| format!("{name}\t{result}\n"))
            .collect::<String>();
        assert_eq!(actual, expected);
    }
}

#[test]
fn config_validation_consumes_auth_policy() {
    let root =
        read_single_root_boc(include_bytes!("../src/tests/data/config.boc").as_slice()).unwrap();
    let mut cfg = ConfigParams::with_address_and_params(AccountId::from([1; 32]), Some(root));
    assert!(cfg.valid_config_data(true, None).unwrap());
    cfg.set_config(ConfigParamEnum::ConfigParam8(ConfigParam8 {
        global_version: GlobalVersion { version: 17, capabilities: 0 },
    }))
    .unwrap();
    assert!(!cfg.valid_config_data(true, None).unwrap());
    cfg.set_config(ConfigParamEnum::ConfigParam48(policy(0, 0, 100, 7))).unwrap();
    assert!(!cfg.valid_config_data(true, None).unwrap());
    for number in [9, 10] {
        let slice = cfg.config_cell_slice(number).unwrap();
        let mut map = HashmapE::with_hashmap(32, Some(slice.into_cell().unwrap()));
        map.set(48u32.write_to_bitstring().unwrap(), &SliceData::default()).unwrap();
        cfg.set_config(ConfigParamEnum::ConfigParamAny(number, map.data().unwrap().clone()))
            .unwrap();
    }
    assert!(cfg.valid_config_data(true, None).unwrap());
    assert_eq!(cfg.auth_policy().unwrap().unwrap(), policy(0, 0, 100, 7));
    assert!(matches!(cfg.config(48).unwrap(), Some(ConfigParamEnum::ConfigParam48(_))));
    cfg.set_config(ConfigParamEnum::ConfigParamAny(
        48,
        raw_policy(0xa1, 1, &[], false, false, false),
    ))
    .unwrap();
    assert!(!cfg.valid_config_data(true, None).unwrap());
}

// Mirrors the reference test helper: network is 123 in the low 32 bits.
fn reference_policy(sequence: u64, retired: u16, deadline: u32) -> Cell {
    let mut network = [0u8; 32];
    network[28..].copy_from_slice(&123u32.to_be_bytes());
    AuthPolicy { network: UInt256::from(network), sequence, retired, deadline }.serialize().unwrap()
}

fn admit(candidate: Result<&ConfigParams>, previous: Option<Result<&ConfigParams>>) -> String {
    match validate_auth_policy_admission(candidate, previous) {
        Ok(()) => "ok".to_string(),
        Err(error) => error.to_string(),
    }
}

// One-to-one port of the reference trusted-state admission assertions, followed
// by the precedence cases the reference encodes through its branch order.
#[test]
fn trusted_state_admission_preserves_errors_and_retirement() {
    let initial = config(16, Some(reference_policy(0, 0, 0)), true, true);
    let retired = config(16, Some(reference_policy(1, 2, 0)), true, true);
    let missing = config(16, None, true, true);
    let cleared = config(16, Some(reference_policy(2, 0, 0)), true, true);
    let no_root = ConfigParams::default();
    assert!(no_root.root().is_none());
    let rollback = "AUTH retirement policy cannot roll back";
    let candidate_error = "candidate proof unavailable";
    let previous_error = "previous proof unavailable";
    let previous_root = "previous AUTH configuration root is missing";

    assert_eq!(admit(Ok(&initial), None), "ok");
    assert_eq!(admit(Ok(&retired), Some(Ok(&initial))), "ok");
    assert_eq!(admit(Ok(&retired), Some(Ok(&retired))), "ok");
    assert_ne!(admit(Ok(&missing), None), "ok");
    assert_eq!(admit(Ok(&cleared), Some(Ok(&retired))), rollback);
    assert_eq!(admit(Ok(&initial), Some(Ok(&no_root))), previous_root);
    assert_eq!(admit(Err(error!("{candidate_error}")), Some(Ok(&initial))), candidate_error);
    assert_eq!(admit(Ok(&initial), Some(Err(error!("{previous_error}")))), previous_error);

    // The candidate lookup is unwrapped first, whatever the previous holds.
    assert_eq!(
        admit(Err(error!("{candidate_error}")), Some(Err(error!("{previous_error}")))),
        candidate_error
    );
    assert_eq!(admit(Err(error!("{candidate_error}")), None), candidate_error);
    assert_eq!(admit(Err(error!("{candidate_error}")), Some(Ok(&no_root))), candidate_error);
    // A missing candidate root is refused, never read as a legacy configuration.
    assert_eq!(admit(Ok(&no_root), None), "AUTH configuration root is missing");
    assert_eq!(admit(Ok(&no_root), Some(Ok(&initial))), "AUTH configuration root is missing");
    // Without the root-missing branch this rollback would pass as a fresh policy.
    assert_eq!(admit(Ok(&retired), Some(Ok(&no_root))), previous_root);

    // Equal sequence is accepted only for an identical policy cell.
    let changed_same_sequence = config(16, Some(reference_policy(1, 2, 100)), true, true);
    assert_eq!(admit(Ok(&changed_same_sequence), Some(Ok(&retired))), rollback);
}

// Keeps only the dictionary root; every branch below it becomes a pruned cell,
// as in a configuration read through a proof that does not cover AUTH.
fn pruned_config(config: &ConfigParams) -> ConfigParams {
    let root = config.root().unwrap();
    let proof = MerkleProof::create(root, |hash| hash == root.repr_hash()).unwrap();
    let virtual_root = proof.proof.clone().virtualize(1);
    assert_eq!(virtual_root.repr_hash(), root.repr_hash());
    ConfigParams::with_address_and_params(AccountId::from([1; 32]), Some(virtual_root))
}

#[test]
fn trusted_state_admission_refuses_pruned_configuration() {
    let initial = config(16, Some(reference_policy(0, 0, 0)), true, true);
    let retired = config(16, Some(reference_policy(1, 2, 0)), true, true);
    let pruned_initial = pruned_config(&initial);
    let pruned_retired = pruned_config(&retired);
    assert_eq!(admit(Ok(&retired), Some(Ok(&initial))), "ok");
    assert_ne!(admit(Ok(&pruned_retired), None), "ok");
    assert_ne!(admit(Ok(&pruned_retired), Some(Ok(&initial))), "ok");
    assert_ne!(admit(Ok(&retired), Some(Ok(&pruned_initial))), "ok");
}
