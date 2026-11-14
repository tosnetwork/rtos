// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
use adnl::fec::{Algorithm, Encoder, PeerFecType, Refusal};
use rtos_api::{
    ton::fec::{
        type_::{Online, RaptorQ},
        Type,
    },
    WireProfile,
};
fn rq(data_size: i32, symbol_size: i32, symbols_count: i32) -> Type {
    Type::Fec_RaptorQ(RaptorQ { data_size, symbol_size, symbols_count })
}
fn reason(error: anyhow::Error) -> &'static str {
    error.downcast_ref::<Refusal>().unwrap().0
}

#[test]
fn peer_policy_checks_all_fields_before_restricting_the_constructor() {
    for (data_size, symbol_size, symbols_count, expected) in [
        (0, 0, -1, "fec_negative"),
        (0, 767, 1, "fec_symbol_size_small"),
        (0, 2049, 1, "fec_symbol_size_large"),
        (0, 768, 1, "fec_symbols_count"),
        (0, 768, 0, "fec_not_raptorq"),
    ] {
        let value = Type::Fec_Online(Online { data_size, symbol_size, symbols_count });
        assert_eq!(reason(PeerFecType::from_tl(&value).unwrap_err()), expected);
    }
}

#[test]
fn peer_type_acceptance_precedes_codec_capacity() {
    let peer = PeerFecType::from_tl(&rq(56403 * 768, 768, 56403)).unwrap();
    let mut decoder = peer.create_decoder().unwrap();
    decoder.add_symbol(0, vec![7; 768]).unwrap();
    assert!(!decoder.may_try_decode());
    assert_eq!(decoder.try_decode().unwrap_err().0, "need_more_symbols");
    let peer = PeerFecType::from_tl(&rq(56404 * 768, 768, 56404)).unwrap();
    assert_eq!(peer.create_decoder().err().unwrap().0, "fec_too_many_symbols");
}

#[test]
fn zero_peer_data_constructs_a_live_empty_decoder() {
    let wire = WireProfile::T0.serialize(&rq(0, 768, 0)).unwrap();
    let peer = PeerFecType::from_wire(&wire).unwrap();
    assert_eq!(peer.to_wire().unwrap(), wire);
    let mut decoder = peer.create_decoder().unwrap();
    assert!(!decoder.may_try_decode());
    decoder.add_symbol(0, vec![0; 768]).unwrap();
    assert!(decoder.may_try_decode());
    assert!(decoder.try_decode().unwrap().is_empty());
    let mut encoder = decoder.take_encoder().unwrap();
    assert_eq!(encoder.symbol(3).unwrap(), (3, vec![0; 768]));
    // Explicit local encoder configuration is a different admission boundary.
    assert!(Encoder::new(Algorithm::RaptorQ, vec![], 768).is_err());
}

#[test]
fn peer_wire_decoder_keeps_constructor_truncation_and_suffix_errors() {
    assert_eq!(reason(PeerFecType::from_wire(&[0]).unwrap_err()), "tl_truncated");
    assert_eq!(reason(PeerFecType::from_wire(&[0; 4]).unwrap_err()), "tl_unknown_constructor");
    let mut wire = WireProfile::T0.serialize(&rq(1, 768, 1)).unwrap();
    wire.push(0);
    assert_eq!(reason(PeerFecType::from_wire(&wire).unwrap_err()), "tl_trailing_data");
}
