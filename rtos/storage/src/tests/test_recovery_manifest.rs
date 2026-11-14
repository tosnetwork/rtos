// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use rtos_block::sha256_digest;

fn fixture(kind: Kind) -> (Vec<u8>, Sidecar) {
    let mut writer = ManifestWriter::new(Vec::new(), kind, [42; 16]).unwrap();
    let first = if kind == Kind::Selection { Record::Predicate } else { Record::SelectionDigest };
    writer.record(first, 3, &mut &b"abc"[..]).unwrap();
    writer.record(Record::Provider, 2, &mut &b"de"[..]).unwrap();
    writer.finish().unwrap()
}
fn decode(bytes: &[u8], kind: Kind, descriptor: Sidecar) -> Result<()> {
    read_manifest(bytes, kind, [42; 16], descriptor, |_, _, payload| {
        io::copy(payload, &mut io::sink())?;
        Ok(())
    })
}
#[test]
fn roundtrip_and_record_boundaries() {
    for kind in [Kind::Selection, Kind::Ready] {
        let (bytes, descriptor) = fixture(kind);
        assert_eq!(&bytes[..8], b"RTOSAMF1");
        assert_eq!(&bytes[8..12], &[1, 0, kind as u8, 0]);
        assert_eq!(&bytes[12..28], &[42; 16]);
        assert_eq!(descriptor.bytes, 92);
        assert_eq!(descriptor.records, 2);
        assert_eq!(descriptor.digest, sha256_digest(&bytes));
        let mut values = Vec::new();
        read_manifest(&bytes[..], kind, [42; 16], descriptor, |tag, len, payload| {
            let mut value = Vec::new();
            payload.read_to_end(&mut value)?;
            assert_eq!(len, value.len() as u64);
            values.push((tag, value));
            Ok(())
        })
        .unwrap();
        assert_eq!(values[0].1, b"abc");
        assert_eq!(values[1], (Record::Provider, b"de".to_vec()));
        assert!(read_manifest(&bytes[..], kind, [41; 16], descriptor, |_, _, _| Ok(())).is_err());
        assert!(read_manifest(&bytes[..], kind, [42; 16], descriptor, |_, _, _| Ok(())).is_err());
    }
}
#[test]
fn corruption_truncation_counts_and_trailing_bytes_refuse() {
    let (bytes, descriptor) = fixture(Kind::Selection);
    for end in 0..bytes.len() {
        assert!(decode(&bytes[..end], Kind::Selection, descriptor).is_err(), "prefix {end}");
    }
    for index in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[index] ^= 128;
        assert!(decode(&changed, Kind::Selection, descriptor).is_err(), "byte {index}");
    }
    let mut changed = bytes.clone();
    changed.push(0);
    assert!(decode(&changed, Kind::Selection, descriptor).is_err());
    assert!(decode(&bytes, Kind::Ready, descriptor).is_err());
    let mut changed = bytes.clone();
    changed[37] ^= 1;
    assert!(decode(
        &changed,
        Kind::Selection,
        Sidecar { digest: sha256_digest(&changed), ..descriptor }
    )
    .is_err());
    for records in [0, 1, 3, u64::MAX] {
        assert!(decode(&bytes, Kind::Selection, Sidecar { records, ..descriptor }).is_err());
    }
    for length in [u64::MAX, 47] {
        let mut changed = bytes.clone();
        changed[29..37].copy_from_slice(&length.to_le_bytes());
        let mut visited = false;
        assert!(read_manifest(&changed[..], Kind::Selection, [42; 16], descriptor, |_, _, _| {
            visited = true;
            Ok(())
        })
        .is_err());
        assert!(!visited);
    }
}
#[test]
fn invalid_order_and_input_eof() {
    let mut writer = ManifestWriter::new(Vec::new(), Kind::Selection, [42; 16]).unwrap();
    assert!(writer.record(Record::Provider, 0, &mut io::empty()).is_err());
    writer.record(Record::Predicate, 0, &mut io::empty()).unwrap();
    assert!(writer.record(Record::Predicate, 0, &mut io::empty()).is_err());
    assert!(writer.record(Record::SelectionDigest, 0, &mut io::empty()).is_err());
    writer.record(Record::Child, 0, &mut io::empty()).unwrap();
    assert!(writer.record(Record::Provider, 0, &mut io::empty()).is_err());
    assert!(writer.record(Record::Tail, u64::MAX, &mut io::empty()).is_err());
    assert!(writer.record(Record::Tail, 2, &mut &b"x"[..]).is_err());
    assert!(writer.record(Record::Tail, 0, &mut io::empty()).is_err());
    assert!(writer.finish().is_err());
}
struct ShortWriter {
    remaining: usize,
}
impl Write for ShortWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::other("injected write failure"));
        }
        let n = data.len().min(self.remaining).min(3);
        self.remaining -= n;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn partial_writes_cannot_publish_descriptor() {
    for remaining in 0..81 {
        let writer = ManifestWriter::new(ShortWriter { remaining }, Kind::Selection, [42; 16]);
        if let Ok(mut writer) = writer {
            if writer.record(Record::Predicate, 3, &mut &b"abc"[..]).is_err() {
                assert!(writer.record(Record::Provider, 0, &mut io::empty()).is_err());
            }
            assert!(writer.finish().is_err(), "failure after {remaining} bytes");
        }
    }
    let mut writer =
        ManifestWriter::new(ShortWriter { remaining: 81 }, Kind::Selection, [42; 16]).unwrap();
    writer.record(Record::Predicate, 3, &mut &b"abc"[..]).unwrap();
    assert_eq!(writer.finish().unwrap().1.bytes, 81);
}
struct BoundedInput {
    remaining: u64,
}
impl Read for BoundedInput {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        assert!(bytes.len() <= BUFFER);
        let n = (bytes.len() as u64).min(self.remaining) as usize;
        bytes[..n].fill(17);
        self.remaining -= n as u64;
        Ok(n)
    }
}
#[test]
fn large_synthetic_payload_uses_bounded_buffers() {
    use std::io::{Seek, SeekFrom};
    // Tests framing only, not provider record schema validation.
    let file = tempfile::tempfile().unwrap();
    let mut writer = ManifestWriter::new(file, Kind::Selection, [42; 16]).unwrap();
    writer.record(Record::Predicate, 0, &mut io::empty()).unwrap();
    let length = 8 * 1024 * 1024 + 17;
    let mut input = BoundedInput { remaining: length + 1 };
    writer.record(Record::Provider, length, &mut input).unwrap();
    assert_eq!(input.remaining, 1);
    let (mut file, descriptor) = writer.finish().unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut total = 0;
    read_manifest(file, Kind::Selection, [42; 16], descriptor, |_, len, payload| {
        let mut buffer = [0; 4096];
        let mut seen = 0;
        loop {
            let n = payload.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            assert!(buffer[..n].iter().all(|byte| *byte == 17));
            seen += n as u64;
        }
        assert_eq!(seen, len);
        total += seen;
        Ok(())
    })
    .unwrap();
    assert_eq!(total, length);
}

#[test]
fn typed_predicate_streams_directly_and_encoder_failures_latch() {
    use crate::archives::truncation_selection::{read_predicate, TruncationSelection};
    use rtos_block::{BlockIdExt, ShardIdent};
    let cutoff =
        BlockIdExt::with_params(ShardIdent::masterchain(), 123, [1; 32].into(), [2; 32].into());
    let selection = TruncationSelection::new(cutoff.clone(), Vec::new()).unwrap();
    let mut writer = ManifestWriter::new(Vec::new(), Kind::Selection, [42; 16]).unwrap();
    writer
        .record_with(Record::Predicate, selection.encoded_len().unwrap(), |out| {
            selection.write_predicate(out)
        })
        .unwrap();
    let (bytes, descriptor) = writer.finish().unwrap();
    read_manifest(&bytes[..], Kind::Selection, [42; 16], descriptor, |record, len, input| {
        assert_eq!(record, Record::Predicate);
        let restored = read_predicate(input, len, |_| panic!("unexpected top block"))?;
        assert_eq!(restored, cutoff);
        Ok(())
    })
    .unwrap();
    for overrun in [false, true] {
        let mut writer = ManifestWriter::new(Vec::new(), Kind::Selection, [42; 16]).unwrap();
        assert!(writer
            .record_with(Record::Predicate, 1, |out| {
                if overrun {
                    // Even a swallowed encoder error must poison publication.
                    assert!(out.write_all(b"ab").is_err());
                    let _ = out.write_all(b"a");
                }
                Ok(())
            })
            .is_err());
        assert!(writer.finish().is_err());
    }
}
