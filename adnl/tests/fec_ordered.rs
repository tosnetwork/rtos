// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
use adnl::fec::{Algorithm, Decoder, Encoder, Parameters};
use raptorq::{
    decode_ordered_with_encoder, EncodingPacket, ObjectTransmissionInformation, PayloadId,
};

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

#[test]
fn receive_only_recovery_discards_the_solved_repair_encoder() {
    let p = Parameters::new(2, 3).unwrap();
    let packets =
        ["67105a", "ec4c00", "407200", "f49700", "590d00", "e94200", "1dd500", "276200", "c13200"]
            .into_iter()
            .enumerate()
            .map(|(i, bytes)| {
                EncodingPacket::new(PayloadId::new(0, i as u32 + 1), hex::decode(bytes).unwrap())
            })
            .collect::<Vec<_>>();
    let config = ObjectTransmissionInformation::new(2, 3, 1, 1, 1);
    let (without, encoder) = decode_ordered_with_encoder(&config, &packets, false).unwrap();
    assert_eq!(without, [0x67, 0x10]);
    assert!(encoder.is_none());
    let (with, encoder) = decode_ordered_with_encoder(&config, &packets, true).unwrap();
    assert_eq!(with, without);
    let encoder = encoder.unwrap();
    assert_eq!(encoder.repair_packets(0, 1)[0].data(), &[0x67, 0x10, 0x5a]);

    let mut decoder = Decoder::new(Algorithm::RaptorQ, p).unwrap();
    for packet in packets {
        decoder
            .add_symbol(packet.payload_id().encoding_symbol_id(), packet.data().to_vec())
            .unwrap();
    }
    assert_eq!(decoder.try_decode_with_encoder(false).unwrap(), without);
    assert!(!decoder.may_try_decode());
    assert_eq!(decoder.try_decode_with_encoder(true).unwrap_err().0, "need_more_symbols");
    // A later explicit encoder request can rebuild from the decoded data, but
    // cannot recover the discarded inconsistent padding/intermediate solution.
    let mut fresh = decoder.take_encoder().unwrap();
    assert_eq!(fresh.symbol(1).unwrap().1, [0x67, 0x10, 0]);
    assert_eq!(decoder.into_decoded_data().unwrap(), without);
}

#[test]
fn receive_only_source_recovery_can_move_the_cached_allocation() {
    let mut decoder = Decoder::new(Algorithm::RaptorQ, Parameters::new(3, 2).unwrap()).unwrap();
    assert_eq!(decoder.take_encoder().err().unwrap().to_string(), "decode first");
    decoder.add_symbol(0, vec![1, 2]).unwrap();
    decoder.add_symbol(1, vec![3, 99]).unwrap();
    let allocation = decoder.try_decode_with_encoder(false).unwrap().as_ptr();
    assert_eq!(decoder.try_decode_with_encoder(true).unwrap(), [1, 2, 3]);
    let decoded = decoder.into_decoded_data().unwrap();
    assert_eq!(decoded, [1, 2, 3]);
    assert_eq!(decoded.as_ptr(), allocation);
}

#[test]
fn receive_only_repair_recovery_moves_data_and_preserves_retry_rules() {
    let p = Parameters::new(4, 2).unwrap();
    let mut decoder = Decoder::new(Algorithm::RaptorQ, p).unwrap();
    decoder.add_symbol(4, vec![0x7c, 0x97]).unwrap();
    decoder.add_symbol(62, vec![0x68, 0xf8]).unwrap();
    assert_eq!(decoder.try_decode_with_encoder(false).unwrap_err().0, "unclassified");
    assert!(!decoder.may_try_decode());
    decoder.add_symbol(4, vec![0x7c, 0x97]).unwrap();
    assert_eq!(decoder.try_decode_with_encoder(false).unwrap_err().0, "need_more_symbols");
    decoder.add_symbol(0, vec![1, 2]).unwrap();
    let allocation = decoder.try_decode_with_encoder(false).unwrap().as_ptr();
    assert!(!decoder.may_try_decode());
    let decoded = decoder.into_decoded_data().unwrap();
    assert_eq!(decoded, [1, 2, 3, 4]);
    assert_eq!(decoded.as_ptr(), allocation);
}

#[test]
fn consuming_an_unready_decoder_does_not_return_partial_data() {
    let p = Parameters::new(4, 2).unwrap();
    let mut decoder = Decoder::new(Algorithm::RaptorQ, p).unwrap();
    decoder.add_symbol(0, vec![1, 2]).unwrap();
    assert_eq!(decoder.into_decoded_data().unwrap_err().0, "need_more_symbols");
    // A normal repair-only receiver also supports terminal extraction.
    let mut encoder = Encoder::new(Algorithm::RaptorQ, vec![5, 6, 7, 8], 2).unwrap();
    let mut decoder = Decoder::new(Algorithm::RaptorQ, p).unwrap();
    for id in 2..12 {
        decoder.add_symbol(id, encoder.symbol(id).unwrap().1).unwrap();
    }
    assert_eq!(decoder.try_decode_with_encoder(false).unwrap(), [5, 6, 7, 8]);
    assert_eq!(decoder.into_decoded_data().unwrap(), [5, 6, 7, 8]);
}
