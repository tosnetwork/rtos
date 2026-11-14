// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
use adnl::fec::{Algorithm, Decoder, Parameters};

#[test]
fn inconsistent_repairs_follow_cpp_pivot_selection() {
    // Independent review's 8-symbol minimum, actual CPP result 4d vs old Rust 6f.
    let mut decoder = Decoder::new(Algorithm::RaptorQ, Parameters::new(1, 1).unwrap()).unwrap();
    for (id, data) in [
        (1, 0x24),
        (7, 0xbe),
        (8, 0xdf),
        (9, 0x44),
        (10, 0x23),
        (13, 0xfe),
        (2097152, 0xb5),
        (16777215, 0x33),
    ] {
        decoder.add_symbol(id, vec![data]).unwrap();
    }
    assert_eq!(decoder.try_decode().unwrap(), [0x4d]);
}

#[test]
fn rank_failure_retries_only_after_a_new_symbol() {
    let mut decoder = Decoder::new(Algorithm::RaptorQ, Parameters::new(4, 2).unwrap()).unwrap();
    decoder.add_symbol(4, vec![0x7c, 0x97]).unwrap();
    decoder.add_symbol(62, vec![0x68, 0xf8]).unwrap();
    assert!(decoder.may_try_decode());
    assert_eq!(decoder.try_decode().unwrap_err().0, "unclassified");
    assert!(!decoder.may_try_decode());
    decoder.add_symbol(4, vec![0x7c, 0x97]).unwrap();
    assert!(!decoder.may_try_decode());
    assert_eq!(decoder.try_decode().unwrap_err().0, "need_more_symbols");
    decoder.add_symbol(0, vec![1, 2]).unwrap();
    assert!(decoder.may_try_decode());
    assert_eq!(decoder.try_decode().unwrap(), [1, 2, 3, 4]);
}
