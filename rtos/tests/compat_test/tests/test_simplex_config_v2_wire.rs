/*
 * RTOS project modifications (2026-10-10): project and crate naming.
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
//! Cross-implementation wire-format tests for `simplex_config_v2#22`.
//!
//! The target schema uses five reserved bits, two protocol-version bits and
//! one transport bit. Both directions are checked against the C++ TL-B codec.

use base64::Engine;
use compat_test::{skip_if_no_cpp, CppTestNode};
use rtos_block::{read_single_root_boc, write_boc, Deserializable, Serializable, SimplexConfig};

const CASES: &[(u8, bool, u32)] = &[
    (0, false, 4),
    (0, true, 4),
    (1, false, 8),
    (1, true, 16),
    (2, false, 4),
    (2, true, 8),
    (3, false, 4),
    (3, true, 4),
];

fn rust_cell_to_b64(cfg: &SimplexConfig) -> String {
    let cell = cfg.write_to_new_cell().unwrap().into_cell().unwrap();
    let boc = write_boc(&cell).unwrap();
    base64::engine::general_purpose::STANDARD.encode(boc)
}

/// Rust-built simplex_config_v2 cells must unpack on the C++ side to the
/// exact same field values (i.e. our flag-byte layout matches C++'s codegen).
#[test]
fn test_rust_built_simplex_config_v2_parses_in_cpp() {
    skip_if_no_cpp!();

    let mut cpp = CppTestNode::spawn(15920).expect("spawn C++");

    for &(protocol_version, use_quic, slots) in CASES {
        let cfg = SimplexConfig {
            protocol_version,
            use_quic,
            slots_per_leader_window: slots,
            ..Default::default()
        };
        let boc_b64 = rust_cell_to_b64(&cfg);

        let (cpp_eo, cpp_uq, cpp_slots) = cpp.parse_simplex_config_v2(&boc_b64).expect("cpp parse");
        assert_eq!(
            (cpp_eo, cpp_uq, cpp_slots),
            (protocol_version, use_quic, slots),
            "Rust->C++ field mismatch (protocol_version={}, use_quic={}, slots={})",
            protocol_version,
            use_quic,
            slots
        );
    }

    cpp.shutdown().expect("shutdown");
}

/// And the inverse: C++-built cells must deserialize on the Rust side with
/// identical fields. Confirms our v2 deserializer reads the bit layout the
/// C++ codegen produces.
#[test]
fn test_cpp_built_simplex_config_v2_parses_in_rust() {
    skip_if_no_cpp!();

    let mut cpp = CppTestNode::spawn(15921).expect("spawn C++");

    for &(protocol_version, use_quic, slots) in CASES {
        let boc =
            cpp.build_simplex_config_v2(protocol_version, use_quic, slots).expect("cpp build");
        let cell = read_single_root_boc(&boc).expect("rust read_single_root_boc");
        let cfg = SimplexConfig::construct_from_cell(cell).expect("rust deser");

        assert_eq!(cfg.protocol_version, protocol_version);
        assert_eq!(cfg.use_quic, use_quic);
        assert_eq!(cfg.slots_per_leader_window, slots);
    }

    cpp.shutdown().expect("shutdown");
}
