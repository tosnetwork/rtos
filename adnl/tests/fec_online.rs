// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
use adnl::fec::{Algorithm, Decoder, Encoder, Parameters};

#[test]
fn online_rows_match_cpp_rng_degree_and_repeated_index_rules() {
    let mut encoder = Encoder::new(Algorithm::Online, vec![1, 2, 4], 1).unwrap();
    // TOS1181 fec_encode. These are coded rows even for IDs below K.
    let expected = [3, 1, 7, 6, 7, 6, 4, 4, 6, 2, 7, 2, 4, 3, 6, 6];
    for (id, byte) in expected.into_iter().enumerate() {
        assert_eq!(encoder.symbol(id as u32).unwrap(), (id as u32, vec![byte]));
    }
    assert_eq!(encoder.symbol(16777215).unwrap(), (16777215, vec![3]));
}

#[test]
fn online_belief_propagation_and_round_robin_regeneration() {
    let mut decoder = Decoder::new(Algorithm::Online, Parameters::new(1, 1).unwrap()).unwrap();
    decoder.add_symbol(0, vec![0]).unwrap();
    assert!(!decoder.may_try_decode());
    assert_eq!(decoder.try_decode().unwrap_err().0, "need_more_symbols");
    // First degree-one row for this RNG distribution; low IDs can have repeated edges.
    decoder.add_symbol(503, vec![0x75]).unwrap();
    assert!(decoder.may_try_decode());
    assert_eq!(decoder.try_decode().unwrap(), [0x75]);
    // Online receive IDs are full u32; only the RaptorQ profile bounds wire ESI.
    decoder.add_symbol(u32::MAX, vec![0]).unwrap();
    assert_eq!(decoder.try_decode().unwrap(), [0x75]);
    assert_eq!(decoder.add_symbol(2, vec![]).unwrap_err().0, "symbol_length");
    let mut encoder = decoder.take_encoder().unwrap();
    assert_eq!(encoder.symbol(2).unwrap(), (0, vec![0x75]));
}
