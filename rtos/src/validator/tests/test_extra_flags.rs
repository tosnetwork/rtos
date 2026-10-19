// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! The v12 rule on reserved `extra_flags` bits of inbound and imported
//! internal messages. `data/extra-flags-mask.tsv` holds VarUInteger 16
//! encodings (minimal and nonminimal) of each value under several configured
//! global versions with the verdict of the reference rule, compiled verbatim
//! from the reference validator (see the header line).
use super::*;
use rtos_block::{
    ConfigParam8, GlobalVersion, IBitstring, InternalMessageHeader, MsgAddressInt, Serializable,
};

const FIXTURE: &str = include_str!("data/extra-flags-mask.tsv");

fn config_with_version(version: u32) -> ConfigParams {
    let mut config = ConfigParams::default();
    config
        .set_config(ConfigParamEnum::ConfigParam8(ConfigParam8 {
            global_version: GlobalVersion { version, capabilities: 0 },
        }))
        .unwrap();
    config
}

fn header(extra_flags: u128) -> InternalMessageHeader {
    let mut header = InternalMessageHeader::with_addresses(
        MsgAddressInt::standard(0, AccountId::from([1; 32])),
        MsgAddressInt::standard(0, AccountId::from([2; 32])),
        CurrencyCollection::with_coins(1000),
    );
    header.extra_flags = coins(extra_flags);
    header
}

/// A minimal VarUInteger 16 encoding read back through the message decoder.
fn coins(value: u128) -> Coins {
    let len = (128 - value.leading_zeros() as usize).div_ceil(8);
    let mut builder = rtos_block::BuilderData::new();
    builder.append_bits(len, 4).unwrap();
    for i in (0..len).rev() {
        builder.append_u8((value >> (8 * i)) as u8).unwrap();
    }
    Coins::construct_from(&mut SliceData::load_builder(builder).unwrap()).unwrap()
}

fn envelope(message: &Message) -> MsgEnvelope {
    MsgEnvelope::with_routing(
        rtos_block::ChildCell::with_struct(message).unwrap(),
        Coins::new(1),
        Default::default(),
        Default::default(),
        0,
        None,
    )
}

fn base(governing: u32, proposed: u32) -> ValidateBase {
    let mut base =
        ValidateBase { config_params: config_with_version(governing), ..Default::default() };
    base.next_state_extra.config = config_with_version(proposed);
    base
}

fn rejected_with(result: Result<()>, text: &str) {
    let message = result.expect_err("expected a rejection").to_string();
    assert!(message.contains(text), "{message}");
}

#[test]
fn extra_flags_rule_matches_reference_verdicts() {
    let mut lines = FIXTURE.lines();
    let header_line = lines.next().unwrap();
    assert!(header_line.starts_with("# reference_commit=881240331ee48a291b96d73f8b8b93bae005ace0"));
    let mut cases = 0;
    let mut nonminimal = 0;
    for line in lines {
        let f: Vec<_> = line.split('\t').collect();
        let cell = rtos_block::read_single_root_boc(hex::decode(f[1]).unwrap()).unwrap();
        let mut slice = SliceData::load_cell(cell).unwrap();
        let version: u32 = f[2].parse().unwrap();
        let expected = f[3] == "1";
        match Coins::construct_from(&mut slice) {
            Ok(value) => {
                assert!(slice.is_empty_cell(), "{}", f[0]);
                assert_eq!(extra_flags_within_valid_mask(&value, version), expected, "{}", f[0]);
            }
            // A nonminimal encoding never decodes here, so such a message is
            // refused before the rule runs; the reference rule refuses it from
            // version 12 as well (its integer reader refuses leading zeros).
            Err(_) => {
                nonminimal += 1;
                let signed = i32::from_be_bytes(version.to_be_bytes());
                assert_eq!(expected, signed < 12, "{}", f[0]);
            }
        }
        cases += 1;
    }
    assert!(cases >= 300 && nonminimal >= 100, "{cases} {nonminimal}");
}

#[test]
fn inbound_guard_rejects_reserved_bits_from_version_12() {
    for (flags, ok) in [(0, true), (1, true), (2, true), (3, true), (4, false), (1 << 100, false)] {
        let result = ValidateQuery::check_inbound_extra_flags(
            &base(12, 12),
            &UInt256::from([5; 32]),
            &header(flags),
        );
        if ok {
            result.unwrap();
        } else {
            rejected_with(result, "inbound internal message with hash 0505");
        }
    }
    ValidateQuery::check_inbound_extra_flags(&base(11, 11), &UInt256::default(), &header(4))
        .unwrap();
}

#[test]
fn imported_guard_names_the_message_hash() {
    let message = Message::with_int_header(header(8));
    let env = envelope(&message);
    let hash = message.serialize().unwrap().repr_hash().to_hex_string();
    assert_ne!(hash, env.serialize().unwrap().repr_hash().to_hex_string());
    rejected_with(
        ValidateQuery::check_imported_extra_flags(&base(16, 16), &env),
        &format!("imported internal message with hash {hash} has invalid reserved extra_flags"),
    );
    let message = Message::with_int_header(header(3));
    let env = envelope(&message);
    ValidateQuery::check_imported_extra_flags(&base(16, 16), &env).unwrap();
}

// The governing masterchain configuration decides, not a version the
// candidate proposes in its new state.
#[test]
fn guards_use_the_governing_configuration_version() {
    let key = UInt256::default();
    rejected_with(
        ValidateQuery::check_inbound_extra_flags(&base(12, 11), &key, &header(4)),
        "invalid reserved extra_flags",
    );
    ValidateQuery::check_inbound_extra_flags(&base(11, 12), &key, &header(4)).unwrap();
    let message = Message::with_int_header(header(4));
    let env = envelope(&message);
    rejected_with(
        ValidateQuery::check_imported_extra_flags(&base(12, 11), &env),
        "invalid reserved extra_flags",
    );
    ValidateQuery::check_imported_extra_flags(&base(11, 12), &env).unwrap();
}

#[test]
#[ignore]
fn generate_extra_flags_cases() {
    let out = std::env::var("RTOS_FLAGS_CASES_OUT").expect("RTOS_FLAGS_CASES_OUT");
    let values: [u128; 16] = [
        0,
        1,
        2,
        3,
        4,
        5,
        7,
        8,
        0xff,
        0x100,
        1 << 63,
        1 << 64,
        (1 << 64) | 3,
        1 << 119,
        (1 << 120) - 1,
        (1 << 120) - 4,
    ];
    let versions: [u32; 8] = [0, 11, 12, 13, 16, 0x7fff_ffff, 0x8000_0000, u32::MAX];
    let mut tsv = String::new();
    for value in values {
        let minimal = (128 - value.leading_zeros() as usize).div_ceil(8);
        let lens: std::collections::BTreeSet<usize> =
            [minimal, minimal + 1, 15].into_iter().filter(|len| *len <= 15).collect();
        for len in lens {
            let mut builder = rtos_block::BuilderData::new();
            builder.append_bits(len, 4).unwrap();
            for i in (0..len).rev() {
                builder.append_u8((value >> (8 * i)) as u8).unwrap();
            }
            let cell = builder.into_cell().unwrap();
            let boc = hex::encode(rtos_block::write_boc(&cell).unwrap());
            for version in versions {
                tsv.push_str(&format!("v{value:x}-len{len}-gv{version}\t{boc}\t{version}\n"));
            }
        }
    }
    std::fs::write(out, tsv).unwrap();
}
