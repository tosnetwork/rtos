// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
use adnl::{
    fec::{Algorithm, Decoder, Encoder, Parameters},
    RaptorqEncoder,
};

#[test]
fn native_sender_retains_cpp_repair_bytes_and_external_ids() {
    // Clean TOS 1181c08e, net fec_encode, data 00..1e, symbol_size=12.
    let data = (0..31).collect::<Vec<u8>>();
    let mut sender = RaptorqEncoder::with_data(&data, Some(12));
    let mut random = Encoder::new(Algorithm::RaptorQ, data, 12).unwrap();
    let expected = [
        "000102030405060708090a0b",
        "0c0d0e0f1011121314151617",
        "18191a1b1c1d1e0000000000",
        "1c7cdcbc3c5cfce56583b452",
        "9ea0e2dcf2cc8ed6f841972e",
        "1b76c1ac4c2196f8b8ab9e8d",
    ];
    for (id, bytes) in expected.into_iter().enumerate() {
        let mut seqno = id as u32;
        assert_eq!(hex::encode(sender.encode(&mut seqno).unwrap()), bytes);
        assert_eq!(seqno, id as u32);
        let (random_id, random_bytes) = random.symbol(id as u32).unwrap();
        assert_eq!(random_id, seqno);
        assert_eq!(hex::encode(random_bytes), bytes);
    }
}

#[test]
fn round_robin_tail_and_first_duplicate_follow_native_receive_rules() {
    let mut encoder = Encoder::new(Algorithm::RoundRobin, vec![1, 2, 3], 2).unwrap();
    assert_eq!(encoder.symbol(3).unwrap(), (1, vec![3]));
    let mut decoder = Decoder::new(Algorithm::RoundRobin, encoder.parameters()).unwrap();
    assert_eq!(decoder.add_symbol(1, vec![3]).unwrap_err().0, "symbol_length");
    decoder.add_symbol(3, vec![3, 99]).unwrap();
    decoder.add_symbol(1, vec![88, 77]).unwrap();
    assert_eq!(decoder.try_decode().unwrap_err().0, "need_more_symbols");
    decoder.add_symbol(0, vec![1, 2]).unwrap();
    assert_eq!(decoder.try_decode().unwrap(), [1, 2, 3]);
}

#[test]
fn raptorq_defers_decoding_until_all_supplied_symbols_are_added() {
    let p = Parameters::new(3, 2).unwrap();
    let mut duplicate = Decoder::new(Algorithm::RaptorQ, p).unwrap();
    duplicate.add_symbol(0, vec![1, 2]).unwrap();
    duplicate.add_symbol(0, vec![9, 9]).unwrap();
    assert!(!duplicate.may_try_decode());
    assert_eq!(duplicate.try_decode().unwrap_err().0, "need_more_symbols");
    let mut decoder = Decoder::new(Algorithm::RaptorQ, p).unwrap();
    decoder.add_symbol(2, vec![55, 66]).unwrap();
    decoder.add_symbol(3, vec![77, 88]).unwrap();
    assert!(decoder.may_try_decode());
    decoder.add_symbol(0, vec![1, 2]).unwrap();
    decoder.add_symbol(0, vec![9, 9]).unwrap();
    decoder.add_symbol(1, vec![3, 0]).unwrap();
    assert_eq!(decoder.try_decode().unwrap(), [1, 2, 3]);
    assert_eq!(decoder.add_symbol(1 << 24, vec![]).unwrap_err().0, "symbol_length");
    assert_eq!(decoder.add_symbol(1 << 24, vec![0, 0]).unwrap_err().0, "symbol_id_range");
}
