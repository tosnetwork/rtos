// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Full-node protocol behaviour against outputs of a driver built on the
//! fixed C++ baseline (data/fullnode-proto/out-*.txt). Each line there is
//! "<section> <key> <value>"; no expected value in this file is hand-written.
use super::*;
use rtos_api::WireProfile;

pub(super) fn cpp_lines(file: &'static str) -> impl Iterator<Item = (&'static str, &'static str)> {
    file.lines().filter_map(|line| {
        let mut parts = line.splitn(3, ' ');
        let _section = parts.next()?;
        let key = parts.next()?;
        Some((key, parts.next().unwrap_or("")))
    })
}

pub(super) fn cpp_value(file: &'static str, key: &str) -> &'static str {
    cpp_lines(file)
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v)
        .unwrap_or_else(|| panic!("C++ driver output has no {key}"))
}

pub(super) const CPP_TL: &str = include_str!("data/fullnode-proto/out-tl.txt");

/// Bytes of a query whose constructor `id` is followed by two block ids and,
/// for the slice query, an offset and a size: the layout the legacy
/// persistent-state queries had.
fn legacy_query(id: u32, slice: bool) -> Vec<u8> {
    let mut bytes = id.to_le_bytes().to_vec();
    for _ in 0..2 {
        bytes.extend_from_slice(&(-1i32).to_le_bytes());
        bytes.extend_from_slice(&(0x8000_0000_0000_0000u64 as i64).to_le_bytes());
        bytes.extend_from_slice(&7i32.to_le_bytes());
        bytes.extend_from_slice(&[0x11; 64]);
    }
    if slice {
        bytes.extend_from_slice(&0i64.to_le_bytes());
        bytes.extend_from_slice(&(1i64 << 21).to_le_bytes());
    }
    bytes
}

#[test]
fn legacy_persistent_state_queries_are_not_in_any_profile() {
    for (id, slice) in [(0x7f99e3b8u32, false), (0xf5e9e6e3, true), (0x4667fc2d, false)] {
        assert_eq!(cpp_value(CPP_TL, &format!("legacyParse.{id:08x}")), "error");
        let bytes = legacy_query(id, slice);
        for profile in [WireProfile::T0, WireProfile::Legacy] {
            assert!(
                profile.deserialize(&bytes).is_err(),
                "constructor {id:08x} must not decode under {profile:?}"
            );
        }
    }
}
