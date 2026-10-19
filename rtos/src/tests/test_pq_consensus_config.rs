// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::os::unix::fs::PermissionsExt;

const AT: &str = "$.extraconfig.pq_consensus";

/// The reference cases state the section inside `extraconfig`; the section
/// check itself is location independent.
fn section(text: &str) -> Option<Value> {
    let root: Value = serde_json::from_str(text).expect("fixture parses");
    root.get("extraconfig").and_then(|extra| extra.get("pq_consensus")).cloned()
}

fn json_accepted(text: &str) -> bool {
    match section(text) {
        None => true,
        Some(section) => check_pq_consensus_json(&section, AT).is_none(),
    }
}

fn json_refused(text: &str, phrase: &str) -> bool {
    section(text)
        .and_then(|section| check_pq_consensus_json(&section, AT))
        .is_some_and(|refused| refused.contains(phrase))
}

#[test]
fn json_checks() {
    assert!(
        json_accepted(r#"{"extraconfig": {"state_serializer_enabled": true}}"#),
        "json_accepts_no_binding"
    );
    assert!(
        json_accepted(
            r#"{"extraconfig": {"pq_consensus": {"@type": "engine.validator.pqConsensus",
          "validator_id": "AA==", "consensus_key_file": "/k/a", "keys": []}}}"#
        ),
        "json_accepts_the_single_form"
    );
    assert!(
        json_accepted(
            r#"{"extraconfig": {"pq_consensus": {"validator_id": "AA==", "consensus_key_file": "",
          "keys": [{"@type": "engine.validator.pqConsensusKey", "consensus_key_file": "/k/a", "valid_from": 0,
          "expire_at": 0}, {"consensus_key_file": "/k/b", "valid_from": "2000000000", "expire_at": 0}]}}}"#
        ),
        "json_accepts_the_multi_form"
    );
    assert!(
        json_refused(
            r#"{"extraconfig": {"pq_consensus": {"validator_id": "AA==", "keys": [
          {"consensus_key_file": "/k/b", "validFrom": 2000000000, "valid_from": 0, "expire_at": 0}]}}}"#,
            "validFrom is not a field"
        ),
        "json_refuses_a_misspelt_window_field"
    );
    assert!(
        json_refused(
            r#"{"extraconfig": {"pq_consensus": {"validator_id": "AA==", "keys": [
          {"consensus_key_file": "/k/b", "expire_at": 0}]}}}"#,
            "valid_from is missing"
        ),
        "json_refuses_a_missing_window_field"
    );
    assert!(
        json_refused(
            r#"{"extraconfig": {"pq_consensus": {"validator_id": "AA==", "consensus_key_file": "/k/a",
          "comment": 1}}}"#,
            "comment is not a field"
        ),
        "json_refuses_an_unknown_binding_field"
    );
    assert!(
        json_refused(
            r#"{"extraconfig": {"pq_consensus": {"validator_id": "AA==", "consensus_key_file": "/k/a",
          "keys": [{"consensus_key_file": "/k/b", "valid_from": 5, "expire_at": 0}]}}}"#,
            "both a single"
        ),
        "json_refuses_both_forms_at_once"
    );
    assert!(
        json_refused(
            r#"{"extraconfig": {"pq_consensus": {"validator_id": "AA==",
          "consensus_key_file": "", "keys": []}}}"#,
            "names no consensus key"
        ),
        "json_refuses_no_key"
    );
    assert!(
        json_refused(
            r#"{"extraconfig": {"pq_consensus": {"validator_id": "AA==", "keys": [
          {"consensus_key_file": "/k/b", "valid_from": -5, "expire_at": 0}]}}}"#,
            "not a unix time"
        ),
        "json_refuses_a_negative_window"
    );
    assert!(
        json_refused(
            r#"{"extraconfig": {"pq_consensus": {"validator_id": "AA==", "keys": [
          {"consensus_key_file": "/k/b", "valid_from": 2147483648, "expire_at": 0}]}}}"#,
            "not a unix time"
        ),
        "json_refuses_a_window_beyond_int32"
    );
    assert!(
        json_refused(
            r#"{"extraconfig": {"pq_consensus": {"validator_id": "AA==", "keys": [
          {"@type": "engine.validator.pqConsensus", "consensus_key_file": "/k/b", "valid_from": 1, "expire_at": 0}]}}}"#,
            "is not a engine.validator.pqConsensusKey"
        ),
        "json_refuses_another_key_type"
    );
    assert!(
        json_refused(
            r#"{"extraconfig": {"pq_consensus": {"consensus_key_file": "/k/a"}}}"#,
            "validator_id is missing"
        ),
        "json_refuses_a_missing_validator"
    );
}

#[test]
fn json_window_forms_follow_the_signed_tl_bound() {
    let key = |window: &str| {
        serde_json::from_str::<Value>(&format!(
            r#"{{"validator_id": "AA==", "keys": [
              {{"consensus_key_file": "/k/b", "valid_from": {window}, "expire_at": 0}}]}}"#
        ))
        .unwrap()
    };
    for accepted in ["0", "2147483647", "\"2147483647\"", "\"0\"", "17"] {
        assert!(check_pq_consensus_json(&key(accepted), AT).is_none(), "{accepted}");
    }
    for refused in [
        "2147483648",
        "\"2147483648\"",
        "4294967295",
        "-0",
        "1.0",
        "1e3",
        "\"\"",
        "\"+1\"",
        "\" 1\"",
        "\"0x10\"",
        "\"00000000001\"",
        "18446744073709551616",
    ] {
        assert!(
            check_pq_consensus_json(&key(refused), AT)
                .is_some_and(|refusal| refusal.contains("not a unix time")),
            "{refused}"
        );
    }
    for not_a_number in ["null", "true", "[]", "{}"] {
        assert!(
            check_pq_consensus_json(&key(not_a_number), AT)
                .is_some_and(|refusal| refusal.contains("is not a number")),
            "{not_a_number}"
        );
    }
    // A decimal string with leading zeros within ten digits is the same integer.
    assert!(check_pq_consensus_json(&key("\"0000000017\""), AT).is_none());
}

#[test]
fn json_optional_types_are_checked_when_present() {
    for (text, phrase) in [
        (
            r#"{"@type": 5, "validator_id": "AA==", "consensus_key_file": "/k/a"}"#,
            "is not a engine.validator.pqConsensus",
        ),
        (
            r#"{"@type": "engine.validator.pqConsensusKey", "validator_id": "AA==", "consensus_key_file": "/k/a"}"#,
            "is not a engine.validator.pqConsensus",
        ),
        (
            r#"{"validator_id": "AA==", "consensus_key_file": 1}"#,
            "consensus_key_file is not a string",
        ),
        (r#"{"validator_id": "AA==", "keys": {}}"#, "keys is not a list"),
        (r#"{"validator_id": "AA==", "keys": null}"#, "keys is not a list"),
        (r#"{"validator_id": "AA==", "keys": [7]}"#, "keys[0] is not an object"),
        (
            r#"{"validator_id": "AA==", "keys": [{"consensus_key_file": "", "valid_from": 0, "expire_at": 0}]}"#,
            "keys[0].consensus_key_file is missing or empty",
        ),
    ] {
        let section: Value = serde_json::from_str(text).unwrap();
        let refused = check_pq_consensus_json(&section, AT).unwrap_or_default();
        assert!(refused.contains(phrase), "{text}: {refused}");
    }
    assert!(check_pq_consensus_json(&Value::from(3), AT)
        .is_some_and(|r| r.ends_with("is not an object")));
}

fn id_b64(byte: u8) -> String {
    base64_encode([byte; 32])
}

#[test]
fn runtime_decoding_reads_validator_id_as_base64_only() {
    let parse = |validator_id: Value| {
        PqConsensusConfig::from_json(
            &serde_json::json!({ "validator_id": validator_id, "consensus_key_file": "/k/a" }),
            AT,
        )
    };
    let decoded = parse(Value::from(id_b64(0x5a))).unwrap().unwrap();
    assert_eq!(decoded.validator_id, UInt256::from([0x5a; 32]));
    // The operator tool's input forms are not runtime configuration.
    let hex_id = hex::encode([0x5a; 32]);
    for refused in [
        Value::from(hex_id.clone()),
        Value::from(format!("-1:{hex_id}")),
        Value::from("AA=="),
        Value::from(base64_encode([0x5a; 33])),
        Value::from(7),
        Value::Null,
    ] {
        assert!(parse(refused.clone()).is_err(), "{refused}");
    }
}

#[test]
fn single_key_normalizes_to_its_implicit_window_and_writes_back_the_same_forms() {
    let single = PqConsensusConfig::from_json(
        &serde_json::json!({ "validator_id": id_b64(1), "consensus_key_file": "/k/a" }),
        AT,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        single.keys,
        vec![ConfiguredKey { key_file: "/k/a".into(), valid_from: 0, expire_at: 0 }]
    );
    let written = single.to_json();
    assert_eq!(written["consensus_key_file"], "/k/a");
    assert_eq!(written["keys"], serde_json::json!([]));
    assert_eq!(written["@type"], "engine.validator.pqConsensus");
    assert!(check_pq_consensus_json(&written, AT).is_none());
    assert_eq!(PqConsensusConfig::from_json(&written, AT).unwrap().unwrap(), single);

    // One listed key with the implicit window is written back as the single form.
    let listed = PqConsensusConfig::from_json(
        &serde_json::json!({ "validator_id": id_b64(1), "keys": [
            { "consensus_key_file": "/k/a", "valid_from": "0", "expire_at": 0 }] }),
        AT,
    )
    .unwrap()
    .unwrap();
    assert_eq!(listed, single);
    assert_eq!(listed.to_json(), written);

    // Anything else is written in keys alone with the single file empty.
    let multi = PqConsensusConfig {
        validator_id: UInt256::from([1; 32]),
        keys: vec![
            ConfiguredKey { key_file: "/k/a".into(), valid_from: 0, expire_at: 2000 },
            ConfiguredKey { key_file: "/k/b".into(), valid_from: 1000, expire_at: 0 },
        ],
    };
    let written = multi.to_json();
    assert_eq!(written["consensus_key_file"], "");
    assert_eq!(written["keys"].as_array().unwrap().len(), 2);
    assert_eq!(written["keys"][0]["@type"], "engine.validator.pqConsensusKey");
    assert!(check_pq_consensus_json(&written, AT).is_none());
    assert_eq!(PqConsensusConfig::from_json(&written, AT).unwrap().unwrap(), multi);
    // A window-bounded single key is never written as the single form.
    let bounded = PqConsensusConfig {
        validator_id: UInt256::from([1; 32]),
        keys: vec![ConfiguredKey { key_file: "/k/a".into(), valid_from: 0, expire_at: 2000 }],
    };
    assert_eq!(bounded.to_json()["consensus_key_file"], "");
    // Serde forms are the same and refuse what the check refuses.
    let text = serde_json::to_string(&multi).unwrap();
    assert_eq!(serde_json::from_str::<PqConsensusConfig>(&text).unwrap(), multi);
    let refused = serde_json::from_str::<PqConsensusConfig>(
        r#"{"validator_id": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", "keys": [
            {"consensus_key_file": "/k/b", "validFrom": 1, "valid_from": 0, "expire_at": 0}]}"#,
    )
    .unwrap_err()
    .to_string();
    assert!(refused.contains("post-quantum consensus configuration refused"), "{refused}");
    assert!(refused.contains("validFrom is not a field"), "{refused}");
}

#[test]
fn node_configuration_locates_the_section_at_its_own_field() {
    assert!(parse_pq_consensus(&serde_json::json!({})).unwrap().is_none());
    assert!(parse_pq_consensus(&serde_json::json!({ "pq_consensus": null })).unwrap().is_none());
    assert!(parse_pq_consensus(&serde_json::json!([])).is_err());
    let refused =
        parse_pq_consensus(&serde_json::json!({ "pq_consensus": { "validator_id": "AA==" } }))
            .unwrap_err()
            .to_string();
    assert!(refused.contains("$.pq_consensus names no consensus key"), "{refused}");
    let config = parse_pq_consensus(&serde_json::json!({ "pq_consensus": {
            "validator_id": id_b64(3), "consensus_key_file": "/k/a" } }))
    .unwrap()
    .unwrap();
    assert_eq!(config.validator_id, UInt256::from([3; 32]));
}

struct SeedDir(tempfile::TempDir);

impl SeedDir {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(dir)
    }
    fn seed(&self, name: &str, byte: u8) -> PathBuf {
        let path = self.0.path().join(name);
        std::fs::write(&path, [byte; 32]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }
}

fn key(path: &Path, valid_from: u32, expire_at: u32) -> ConfiguredKey {
    ConfiguredKey { key_file: path.to_path_buf(), valid_from, expire_at }
}

fn key_id_of(byte: u8) -> [u8; 32] {
    *ConsensusKeyStore::from_seed(&[byte; 32], 0).unwrap().consensus_key().key_id.as_array()
}

#[test]
fn startup_load_installs_every_unexpired_key_and_records_the_rest() {
    let dir = SeedDir::new();
    let a = dir.seed("a.seed", 0xd1);
    let b = dir.seed("b.seed", 0xd2);
    let gone = dir.seed("gone.seed", 0xd3);
    let validator = UInt256::from([0x31; 32]);
    let loaded = load_pq_consensus_config(
        PqConsensusConfig {
            validator_id: validator.clone(),
            keys: vec![key(&a, 0, 5000), key(&b, 4000, 0), key(&gone, 10, 100)],
        },
        1000,
    )
    .unwrap();
    assert_eq!(loaded.key_ids_by_file.len(), 2);
    assert_eq!(loaded.key_ids_by_file[&a], key_id_of(0xd1));
    assert_eq!(loaded.key_ids_by_file[&b], key_id_of(0xd2));
    assert!(!loaded.key_ids_by_file.contains_key(&gone), "an expired key is not loaded");
    assert_eq!(loaded.custody.validator_id(), &validator);
    let mut usable = loaded.custody.usable_key_ids(1000);
    usable.sort();
    let mut expected = vec![key_id_of(0xd1), key_id_of(0xd2)];
    expected.sort();
    assert_eq!(usable, expected);
    // The window of the unloaded key stays in the schedule: re-adding a key
    // valid from the same election is refused.
    let extra = Arc::new(ConsensusKeyStore::from_seed(&[0xd4; 32], 0).unwrap());
    assert!(loaded.custody.install(extra, 10, 0).is_err());
    // The loaded deadlines are the stores' own deadlines.
    assert!(loaded.custody.read(|custody| {
        custody.held_keys(&validator).values().all(|held| held.store.expire_at() == held.expire_at)
    }));
}

#[test]
fn startup_load_refusals_are_errors_with_the_reference_reasons() {
    let dir = SeedDir::new();
    let a = dir.seed("a.seed", 0xd5);
    let twin = dir.seed("twin.seed", 0xd5);
    let validator = UInt256::from([0x32; 32]);
    let refuse = |validator_id: UInt256, keys: Vec<ConfiguredKey>, now: u32| {
        load_pq_consensus_config(PqConsensusConfig { validator_id, keys }, now)
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default()
    };
    assert_eq!(
        refuse(UInt256::default(), vec![key(&a, 0, 0)], 1),
        "post-quantum consensus custody names no validator: validator_id is zero"
    );
    assert!(refuse(validator.clone(), vec![key(&a, 0, 0), key(&a, 5, 0)], 1)
        .contains("a consensus key file is configured twice"));
    assert!(refuse(validator.clone(), vec![key(&a, 0, 10)], 20)
        .contains("every configured consensus key has expired"));
    assert!(refuse(validator.clone(), vec![key(&a, 10, 10)], 1)
        .contains("a consensus key expires not after its window opens"));
    assert!(refuse(validator.clone(), vec![key(&a, 7, 0), key(&twin, 7, 0)], 1)
        .contains("two consensus keys are valid from the same election date"));
    // The same seed under two names is refused only once the identities are known.
    assert!(refuse(validator.clone(), vec![key(&a, 0, 0), key(&twin, 5, 0)], 1)
        .contains("a consensus key is configured twice"));
    let nine: Vec<_> =
        (0..9).map(|i| key(&dir.seed(&format!("n{i}.seed"), 0xe0 + i), u32::from(i), 0)).collect();
    assert!(refuse(validator.clone(), nine, 1).contains("at most 8 consensus keys"));
    let missing = dir.0.path().join("missing.seed");
    let refused = refuse(validator.clone(), vec![key(&missing, 0, 0)], 1);
    assert!(
        refused.starts_with(&format!("post-quantum consensus key {}:", missing.display())),
        "{refused}"
    );
    let loose = dir.seed("loose.seed", 0xd6);
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert!(
        refuse(validator, vec![key(&loose, 0, 0)], 1).contains("group or world permission bits")
    );
}

#[test]
fn startup_load_reads_the_section_from_the_configuration_file() {
    let dir = SeedDir::new();
    let a = dir.seed("a.seed", 0xd7);
    assert!(load_pq_consensus_from_dir(Path::new(""), 1).unwrap().is_none());
    assert!(load_pq_consensus_from_dir(dir.0.path(), 1).unwrap().is_none(), "no file");
    let config = dir.0.path().join(NODE_CONFIG_FILE_NAME);
    std::fs::write(&config, br#"{"log_config_name": null}"#).unwrap();
    assert!(load_pq_consensus_from_dir(dir.0.path(), 1).unwrap().is_none(), "no section");
    std::fs::write(
        &config,
        serde_json::to_vec(&serde_json::json!({ "pq_consensus": {
            "validator_id": id_b64(0x33), "consensus_key_file": a } }))
        .unwrap(),
    )
    .unwrap();
    let loaded = load_pq_consensus_from_dir(dir.0.path(), 1).unwrap().unwrap();
    assert_eq!(loaded.custody.usable_key_ids(1), vec![key_id_of(0xd7)]);
    std::fs::write(
        &config,
        br#"{"pq_consensus": {"validator_id": "AA==", "consensus_key_file": "/k", "keys": [{"consensus_key_file": "/j", "valid_from": 1, "expire_at": 0}]}}"#,
    )
    .unwrap();
    let refused = load_pq_consensus_from_dir(dir.0.path(), 1).err().unwrap().to_string();
    assert!(refused.contains("both a single"), "{refused}");
}

#[test]
fn shared_custody_reads_see_a_change_entirely_or_not_at_all() {
    use rtos_block::{PqConsensusKey, ValidatorDescr};
    let validator = UInt256::from([0x34; 32]);
    let base = Arc::new(ConsensusKeyStore::from_seed(&[0xd8; 32], 0).unwrap());
    let rotated = Arc::new(ConsensusKeyStore::from_seed(&[0xd9; 32], 0).unwrap());
    let mut custody = PqConsensusCustody::default();
    custody.install(validator.clone(), base.clone(), 0, 0).unwrap();
    let shared = Arc::new(PqCustodyShared::new(validator.clone(), custody));
    let descriptor = |key: &PqConsensusKey| {
        ValidatorDescr::with_pq_params(validator.clone(), key.clone(), 1, UInt256::from([0x35; 32]))
    };
    let listed = vec![descriptor(rotated.consensus_key())];
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reader = {
        let (shared, listed, stop) = (shared.clone(), listed.clone(), stop.clone());
        std::thread::spawn(move || {
            let mut seen = [0usize; 2];
            while !stop.load(std::sync::atomic::Ordering::Acquire) {
                // Membership and the exact signer of one decision always agree.
                let (member, signer) = shared.read(|custody| {
                    (
                        rtos_pq_consensus::local_consensus_member(
                            &listed,
                            &Default::default(),
                            &Default::default(),
                            custody,
                            1,
                        ),
                        custody.get_matching_store(&validator, &listed[0], 1),
                    )
                });
                assert_eq!(member.is_some(), signer.is_some());
                seen[usize::from(member.is_some())] += 1;
            }
            seen
        })
    };
    let rotated_id = *rotated.consensus_key().key_id.as_array();
    for _ in 0..200 {
        shared.install(rotated.clone(), 10, 0).unwrap();
        // A set that lists the key refuses its removal in the same change.
        assert_eq!(
            shared.remove_key_checked(&rotated_id, 1, &[listed.as_slice()]),
            Err("a previous, current or next validator set still lists this key")
        );
        shared.remove_key_checked(&rotated_id, 1, &[]).unwrap();
    }
    stop.store(true, std::sync::atomic::Ordering::Release);
    reader.join().unwrap();
    assert_eq!(shared.remove_key_checked(&rotated_id, 1, &[]), Err("no such held consensus key"));
    assert!(!shared.is_empty());
}
