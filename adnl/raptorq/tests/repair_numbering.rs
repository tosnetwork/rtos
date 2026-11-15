// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: Apache-2.0
use raptorq::{Encoder, ObjectTransmissionInformation, SourceBlockDecoder};
#[test]
fn batch_repairs_follow_source_symbols_in_external_numbering() {
    let data = (0..31).collect::<Vec<u8>>();
    let config = ObjectTransmissionInformation::new(data.len() as u64, 12, 1, 1, 1);
    let encoder = Encoder::new(&data, config);
    let packets = encoder.get_encoded_packets(3);
    assert_eq!(
        packets.iter().map(|p| p.payload_id().encoding_symbol_id()).collect::<Vec<_>>(),
        vec![0, 1, 2, 3, 4, 5]
    );
    assert!(packets.iter().all(|p| p.data().len() == 12));
}

#[test]
fn maximum_wire_esi_decodes_without_narrowing_internal_isi() {
    let data = (0..31).collect::<Vec<u8>>();
    let config = ObjectTransmissionInformation::new(data.len() as u64, 12, 1, 1, 1);
    let encoder = Encoder::new(&data, config);
    let block = &encoder.get_block_encoders()[0];
    let packets = [
        block.source_packets()[0].clone(),
        block.repair_packets(2097152 - 3, 1).pop().unwrap(),
        block.repair_packets(16777215 - 3, 1).pop().unwrap(),
    ];
    let mut decoder = SourceBlockDecoder::new2(0, &config, data.len() as u64);
    let decoded = decoder.decode(packets).unwrap();
    assert_eq!(&decoded[..data.len()], &data);
}
