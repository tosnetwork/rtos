// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use crate::*;

fn descriptor(format: usize, active: bool) -> WorkchainDescr {
    WorkchainDescr {
        active,
        accept_msgs: true,
        min_split: 1,
        max_split: 4,
        zerostate_root_hash: UInt256::from([1; 32]),
        zerostate_file_hash: UInt256::from([2; 32]),
        format: match format {
            0 => WorkchainFormat::Basic(WorkchainFormat1::with_params(-1, 0)),
            1 => WorkchainFormat::Basic(WorkchainFormat1::with_params(1, 0)),
            2 => WorkchainFormat::Basic(WorkchainFormat1::with_params(i32::MIN, u64::MAX)),
            _ => WorkchainFormat::Extended(WorkchainFormat0::with_params(64, 256, 32, 1).unwrap()),
        },
        ..Default::default()
    }
}
fn config(entries: &[(i32, WorkchainDescr)]) -> ConfigParams {
    let mut config = ConfigParams::default();
    config
        .set_config(ConfigParamEnum::ConfigParam0(ConfigParam0 {
            config_addr: UInt256::default().into(),
        }))
        .unwrap();
    let mut wc = ConfigParam12::default();
    for (id, d) in entries {
        wc.insert(*id, d).unwrap();
    }
    config.set_config(ConfigParamEnum::ConfigParam12(wc)).unwrap();
    config
}
fn hex(cell: &Cell) -> String {
    write_boc(cell).unwrap().iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn workchain_execution_reference_vectors() {
    let mut rows = Vec::new();
    for format in 0..4 {
        for active in [false, true] {
            for mutation in [
                "same",
                "delete",
                "add-tvm",
                "add-unknown",
                "format",
                "selector",
                "mode",
                "version",
                "root",
                "file",
                "enabled",
                "active",
                "accept",
                "split",
                "monitor",
                "timings",
                "persistent",
                "addr-min",
                "addr-max",
                "addr-step",
            ] {
                let old = descriptor(format, active);
                let mut new = old.clone();
                let mut entries = Vec::new();
                match mutation {
                    "format" => {
                        new.format = if old.basic() {
                            descriptor(3, active).format
                        } else {
                            descriptor(0, active).format
                        }
                    }
                    "selector" => {
                        new.format = match &old.format {
                            WorkchainFormat::Basic(b) => {
                                WorkchainFormat::Basic(WorkchainFormat1::with_params(
                                    b.vm_version.wrapping_add(1),
                                    b.vm_mode,
                                ))
                            }
                            WorkchainFormat::Extended(_) => WorkchainFormat::Extended(
                                WorkchainFormat0::with_params(64, 256, 32, 2).unwrap(),
                            ),
                        }
                    }
                    "mode" => {
                        if let WorkchainFormat::Basic(ref mut b) = new.format {
                            b.vm_mode ^= 1;
                        }
                    }
                    "version" => new.version = u32::MAX,
                    "root" => new.zerostate_root_hash = UInt256::from([3; 32]),
                    "file" => new.zerostate_file_hash = UInt256::from([4; 32]),
                    "enabled" => new.enabled_since = u32::MAX,
                    "active" => new.active = !active,
                    "accept" => new.accept_msgs = false,
                    "split" => {
                        new.min_split = 2;
                        new.max_split = 5;
                    }
                    "monitor" => new.monitor_min_split = 1,
                    "timings" => new.split_merge_timings = Some(WcSplitMergeTimings::default()),
                    "persistent" => {
                        new.split_merge_timings = Some(WcSplitMergeTimings::default());
                        new.persistent_state_split_depth = 63;
                    }
                    "addr-min" | "addr-max" | "addr-step" => {
                        if !old.basic() {
                            new.format = WorkchainFormat::Extended(
                                WorkchainFormat0::with_params(
                                    if mutation == "addr-min" { 96 } else { 64 },
                                    if mutation == "addr-max" { 512 } else { 256 },
                                    if mutation == "addr-step" { 64 } else { 32 },
                                    1,
                                )
                                .unwrap(),
                            );
                        }
                    }
                    _ => {}
                }
                if mutation != "delete" {
                    entries.push((0, new));
                }
                if mutation == "add-tvm" {
                    entries.push((42, descriptor(0, true)));
                }
                if mutation == "add-unknown" {
                    entries.push((42, descriptor(3, true)));
                }
                let old = config(&[(0, old)]);
                let new = config(&entries);
                for role in [-1, 0, 1, 42] {
                    let name = format!("format{format}-active{active}-{mutation}-role{role}");
                    let transition = old.validate_workchain_execution_transition(&new).is_ok();
                    let admission = new.validate_local_workchain_execution(role).is_ok();
                    if std::env::var_os("RTOS_WORKCHAIN_EXPORT").is_none() {
                        let expected = include_str!("data/workchain-execution.tsv")
                            .lines()
                            .find(|l| l.split('\t').next() == Some(name.as_str()))
                            .expect("frozen reference case");
                        assert_eq!(
                            expected,
                            format!("{name}\t{}\t{}", u8::from(transition), u8::from(admission)),
                            "{name}"
                        );
                    }
                    rows.push(format!(
                        "{name}\t{role}\t{}\t{}\t{}\t{}",
                        hex(old.config_params.data().unwrap()),
                        hex(new.config_params.data().unwrap()),
                        u8::from(transition),
                        u8::from(admission)
                    ));
                }
            }
        }
    }
    assert_eq!(rows.len(), 640);
    if let Some(path) = std::env::var_os("RTOS_WORKCHAIN_EXPORT") {
        std::fs::write(path, rows.join("\n") + "\n").unwrap();
    }
}

#[test]
fn workchain_raw_descriptor_vectors() {
    let mut rows = Vec::new();
    for line in include_str!("data/workchain-raw-input.tsv").lines() {
        let fields: Vec<_> = line.split('\t').collect();
        let bytes: Vec<u8> = fields[2]
            .as_bytes()
            .chunks(2)
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect();
        // A configuration whose dictionary cannot even be read (an empty-cell
        // node or a malformed fork on the way to parameter 0, which the
        // reference dictionary reader also refuses) is refused by every rule.
        let Ok(config) = ConfigParams::with_root(read_single_root_boc(&bytes).unwrap()) else {
            rows.push(format!("{}\t0\t0\t0", fields[0]));
            continue;
        };
        rows.push(format!(
            "{}\t{}\t{}\t{}",
            fields[0],
            u8::from(config.validate_workchain_execution_transition(&config).is_ok()),
            u8::from(config.validate_local_workchain_execution(fields[1].parse().unwrap()).is_ok()),
            u8::from(config.validate_workchain_descriptor_config().is_ok())
        ));
    }
    assert_eq!(rows.join("\n") + "\n", include_str!("data/workchain-raw-expected.tsv"));
}

#[test]
fn workchain_raw_config_consumer() {
    let base = ConfigParams::with_root(
        read_single_root_boc(include_bytes!("data/workchain-config-base.boc")).unwrap(),
    )
    .unwrap();
    assert!(base.valid_config_data(false, None).unwrap());
    for (line, expected) in include_str!("data/workchain-raw-input.tsv")
        .lines()
        .zip(include_str!("data/workchain-raw-expected.tsv").lines())
    {
        let fields: Vec<_> = line.split('\t').collect();
        let bytes: Vec<u8> = fields[2]
            .as_bytes()
            .chunks(2)
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect();
        let mut config = base.clone();
        // A fork-bit input cannot be read (the reference dictionary reader
        // refuses its malformed root fork as well); its rule is applied to the
        // base configuration below.
        if !fields[0].contains("config-fork-bit") {
            let input = ConfigParams::with_root(read_single_root_boc(&bytes).unwrap()).unwrap();
            let key = 12u32.write_to_bitstring().unwrap();
            config
                .config_params
                .set(key.clone(), &input.config_params.get(key).unwrap().unwrap())
                .unwrap();
        }
        if fields[0].contains("config-fork-bit") {
            let mut root = BuilderData::from_cell(config.root().unwrap()).unwrap();
            root.append_bit_zero().unwrap();
            config = ConfigParams::with_address_and_params(
                config.config_addr.clone(),
                Some(root.into_cell().unwrap()),
            );
        }
        assert_eq!(
            config.valid_config_data(false, None).unwrap_or(false),
            expected.ends_with("\t1"),
            "{}",
            fields[0]
        );
    }
}

#[test]
fn workchain_zero_label_vectors() {
    let mut rows = Vec::new();
    for line in include_str!("data/workchain-zero-label-input.tsv").lines() {
        let fields: Vec<_> = line.split('\t').collect();
        let bytes: Vec<u8> = fields[2]
            .as_bytes()
            .chunks(2)
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect();
        // A configuration whose dictionary cannot even be read (an empty-cell
        // node or a malformed fork on the way to parameter 0, which the
        // reference dictionary reader also refuses) is refused by every rule.
        let Ok(config) = ConfigParams::with_root(read_single_root_boc(&bytes).unwrap()) else {
            rows.push(format!("{}\t0\t0\t0", fields[0]));
            continue;
        };
        rows.push(format!(
            "{}\t{}\t{}\t{}",
            fields[0],
            u8::from(config.validate_workchain_execution_transition(&config).is_ok()),
            u8::from(config.validate_local_workchain_execution(fields[1].parse().unwrap()).is_ok()),
            u8::from(config.validate_workchain_descriptor_config().is_ok())
        ));
    }
    assert_eq!(rows.join("\n") + "\n", include_str!("data/workchain-zero-label-expected.tsv"));
}
