// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use super::*;

fn bits(text: &str) -> SliceData {
    let mut builder = BuilderData::new();
    if text != "-" {
        for bit in text.bytes() {
            builder.append_bit_bool(bit == b'1').unwrap();
        }
    }
    SliceData::load_builder(builder).unwrap()
}

#[test]
fn dynamic_varuint_matches_cpp_reference_readers() {
    let rows = include_str!("../../tests/data/varuint-reference-verdicts.tsv");
    let mut count = 0;
    for row in rows.lines().filter(|line| !line.starts_with('#')) {
        let f: Vec<_> = row.split('\t').collect();
        let codec = VarUIntegerCodec::new(f[1].parse().unwrap()).unwrap();
        let input = bits(f[2]);
        for (encoding, validate, value) in [
            (VarUIntegerEncoding::Minimal, 3, 4),
            (VarUIntegerEncoding::Structural, 7, 8),
            (VarUIntegerEncoding::Positive, 9, 10),
        ] {
            if f[validate] == "n/a" {
                continue;
            }
            let mut slice = input.clone();
            let accepted = codec.skip(&mut slice, encoding) && slice.is_empty_cell();
            assert_eq!(accepted, f[validate] == "1", "{} {encoding:?} validate", f[0]);
            let mut slice = input.clone();
            let decoded = codec.read(&mut slice, encoding).filter(|_| slice.is_empty_cell());
            assert_eq!(
                decoded.map(|x| x.to_string()).unwrap_or_else(|| "-".into()),
                f[value],
                "{} {encoding:?} read",
                f[0]
            );
        }
        let mut slice = input.clone();
        let skipped =
            codec.skip(&mut slice, VarUIntegerEncoding::Structural) && slice.is_empty_cell();
        assert_eq!(skipped, f[5] == "1", "{} skip", f[0]);
        // The legacy TSV renders the unsigned failure sentinel as `-`.
        let expected_uint = if f[6] == "-" { u64::MAX.to_string() } else { f[6].into() };
        assert_eq!(codec.as_uint(&input).to_string(), expected_uint, "{} as_uint", f[0]);
        let mut slice = input.clone();
        let decoded = load_var_integer(&mut slice, codec.prefix_bits, false)
            .ok()
            .filter(|_| slice.is_empty_cell());
        assert_eq!(
            decoded.map(|x| x.to_string()).unwrap_or_else(|| "-".into()),
            f[11],
            "{} VM read",
            f[0]
        );
        count += 1;
    }
    assert_eq!(count, 348);
}

#[test]
fn dynamic_varuint_failure_preserves_slice() {
    for encoding in [
        VarUIntegerEncoding::Structural,
        VarUIntegerEncoding::Minimal,
        VarUIntegerEncoding::Positive,
    ] {
        let codec = VarUIntegerCodec::new(7).unwrap();
        for text in ["", "111", "11000000001"] {
            let original = bits(text);
            let mut slice = original.clone();
            assert!(codec.read(&mut slice, encoding).is_none());
            assert_eq!(slice, original);
            assert!(!codec.skip(&mut slice, encoding));
            assert_eq!(slice, original);
        }
    }
}
