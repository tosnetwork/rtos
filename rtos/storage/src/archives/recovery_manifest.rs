// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded sidecar framing. Successful decoding is not mutation authority:
//! callers must validate record schemas, identities and complete inventories.
use super::recovery_root::Sidecar;
use rtos_block::{error, fail, Result, Sha256};
use std::io::{self, Read, Write};

const MAGIC: &[u8; 8] = b"RTOSAMF1";
const HEADER: u64 = 28;
const TRAILER: u64 = 41;
const BUFFER: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind { Selection = 1, Ready = 2 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Record {
    Predicate = 1, Provider = 2, MapInventory = 3, Child = 4,
    Tail = 5, ParentMutation = 6, SelectionDigest = 7,
}

impl Record {
    fn decode(tag: u8) -> Result<Self> {
        Ok(match tag {
            1 => Self::Predicate, 2 => Self::Provider, 3 => Self::MapInventory,
            4 => Self::Child, 5 => Self::Tail, 6 => Self::ParentMutation,
            7 => Self::SelectionDigest, _ => fail!("Unknown archive manifest record"),
        })
    }

    fn rank(self, kind: Kind) -> Result<u8> {
        Ok(match (kind, self) {
            (Kind::Selection, Self::Predicate) | (Kind::Ready, Self::SelectionDigest) => 0,
            (_, Self::Provider) => 1,
            (Kind::Selection, Self::MapInventory) => 2,
            (_, Self::Child) => 3,
            (Kind::Ready, Self::ParentMutation) => 4,
            (_, Self::Tail) => 5,
            _ => fail!("Record incompatible with archive manifest kind"),
        })
    }
}

fn next_rank(kind: Kind, record: Record, previous: Option<u8>) -> Result<u8> {
    let rank = record.rank(kind)?;
    if previous.map_or(rank != 0, |old| rank == 0 || rank < old) {
        fail!("Invalid archive manifest record order");
    }
    Ok(rank)
}

struct Hashed<T> {
    inner: T,
    bytes: u64,
    body: Option<Sha256>,
    full: Sha256,
}
impl<T> Hashed<T> {
    fn new(inner: T) -> Self {
        Self { inner, bytes: 0, body: Some(Sha256::new()), full: Sha256::new() }
    }
    fn account(&mut self, bytes: &[u8]) {
        self.bytes += bytes.len() as u64;
        if let Some(body) = &mut self.body { body.update(bytes); }
        self.full.update(bytes);
    }
    fn check_size(&self, len: usize) -> io::Result<()> {
        self.bytes.checked_add(len as u64)
            .ok_or_else(|| io::Error::other("Archive manifest length overflow"))?;
        Ok(())
    }
    fn end_body(&mut self) -> [u8; 32] {
        self.body.take().expect("body finalized once").finalize()
    }
}
impl<T: Write> Write for Hashed<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.check_size(buf.len())?;
        let n = self.inner.write(buf)?;
        self.account(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> { self.inner.flush() }
}
impl<T: Read> Read for Hashed<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.check_size(buf.len())?;
        let n = self.inner.read(buf)?;
        self.account(&buf[..n]);
        Ok(n)
    }
}

struct PayloadWriter<'a, W> { inner: &'a mut W, remaining: u64, failed: bool }
impl<W: Write> Write for PayloadWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.failed || bytes.len() as u64 > self.remaining {
            self.failed = true;
            return Err(io::Error::other("Archive payload length exceeded"));
        }
        match self.inner.write(bytes) {
            Ok(n) => {
                self.remaining -= n as u64;
                if n == 0 && !bytes.is_empty() { self.failed = true; }
                Ok(n)
            }
            Err(err) => { self.failed = true; Err(err) }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.failed { return Err(io::Error::other("Archive payload writer failed")); }
        self.inner.flush().inspect_err(|_| self.failed = true)
    }
}

pub(crate) struct ManifestWriter<W> {
    io: Hashed<W>, kind: Kind, rank: Option<u8>, records: u64, failed: bool,
}
impl<W: Write> ManifestWriter<W> {
    pub(crate) fn new(writer: W, kind: Kind, operation: [u8; 16]) -> Result<Self> {
        if operation == [0; 16] { fail!("Zero archive manifest operation"); }
        let mut io = Hashed::new(writer);
        io.write_all(MAGIC)?;
        io.write_all(&1u16.to_le_bytes())?;
        io.write_all(&[kind as u8, 0])?;
        io.write_all(&operation)?;
        Ok(Self { io, kind, rank: None, records: 0, failed: false })
    }

    /// Copies exactly length bytes, leaving subsequent input untouched.
    pub(crate) fn record(&mut self, record: Record, length: u64, input: &mut impl Read) -> Result<()> {
        self.record_with(record, length, |output| {
            let mut remaining = length;
            let mut buffer = [0; BUFFER];
            while remaining != 0 {
                let n = remaining.min(BUFFER as u64) as usize;
                input.read_exact(&mut buffer[..n])?;
                output.write_all(&buffer[..n])?;
                remaining -= n as u64;
            }
            Ok(())
        })
    }

    /// Allows typed encoders to stream directly, without an intermediate Vec.
    /// A failed or short encoder permanently prevents descriptor publication.
    pub(crate) fn record_with(
        &mut self, record: Record, length: u64,
        encode: impl FnOnce(&mut dyn Write) -> Result<()>,
    ) -> Result<()> {
        if self.failed { fail!("Archive manifest writer failed"); }
        let rank = next_rank(self.kind, record, self.rank)?;
        let count = self.records.checked_add(1).ok_or_else(|| error!("Manifest count overflow"))?;
        self.io.bytes.checked_add(9).and_then(|n| n.checked_add(length))
            .and_then(|n| n.checked_add(TRAILER)).ok_or_else(|| error!("Manifest length overflow"))?;
        self.failed = true;
        self.io.write_all(&[record as u8])?;
        self.io.write_all(&length.to_le_bytes())?;
        let mut output = PayloadWriter { inner: &mut self.io, remaining: length, failed: false };
        encode(&mut output)?;
        if output.failed || output.remaining != 0 { fail!("Incomplete archive manifest payload"); }
        self.records = count;
        self.rank = Some(rank);
        self.failed = false;
        Ok(())
    }

    /// Flush is not fsync. The owned recovery executor must make the returned
    /// file and its directory durable before publishing its descriptor.
    pub(crate) fn finish(mut self) -> Result<(W, Sidecar)> {
        if self.failed || self.records == 0 { fail!("Incomplete archive manifest"); }
        self.io.write_all(&[0])?;
        let body = self.io.end_body();
        self.io.write_all(&self.records.to_le_bytes())?;
        self.io.write_all(&body)?;
        self.io.flush()?;
        let descriptor = Sidecar {
            bytes: self.io.bytes, records: self.records, digest: self.io.full.finalize(),
        };
        Ok((self.io.inner, descriptor))
    }
}

/// Visitors only stage validation data. They must not mutate canonical state:
/// a later record or trailer can still invalidate this entire stream.
pub(crate) fn read_manifest(
    reader: impl Read, kind: Kind, operation: [u8; 16], expected: Sidecar,
    mut visit: impl FnMut(Record, u64, &mut dyn Read) -> Result<()>,
) -> Result<()> {
    if operation == [0; 16] || expected.bytes < HEADER + 9 + TRAILER || expected.records == 0 {
        fail!("Invalid archive manifest descriptor");
    }
    let mut io = Hashed::new(reader);
    let mut header = [0; HEADER as usize];
    io.read_exact(&mut header)?;
    if &header[..8] != MAGIC || header[8..12] != [1, 0, kind as u8, 0]
        || header[12..] != operation {
        fail!("Archive manifest header mismatch");
    }
    let mut count = 0u64;
    let mut rank = None;
    loop {
        let remaining = expected.bytes.checked_sub(io.bytes)
            .ok_or_else(|| error!("Archive manifest exceeded descriptor"))?;
        if remaining < TRAILER { fail!("Truncated archive manifest trailer"); }
        let mut tag = [0];
        io.read_exact(&mut tag)?;
        if tag[0] == 0 { break; }
        let record = Record::decode(tag[0])?;
        rank = Some(next_rank(kind, record, rank)?);
        if remaining < 9 + TRAILER || count >= expected.records {
            fail!("Archive manifest record count or framing mismatch");
        }
        let mut length = [0; 8];
        io.read_exact(&mut length)?;
        let length = u64::from_le_bytes(length);
        if length > remaining - 9 - TRAILER { fail!("Archive manifest payload exceeds descriptor"); }
        let mut payload = (&mut io).take(length);
        visit(record, length, &mut payload)?;
        if payload.limit() != 0 { fail!("Archive manifest payload not fully consumed"); }
        count = count.checked_add(1).ok_or_else(|| error!("Archive manifest count overflow"))?;
    }
    let body = io.end_body();
    let mut trailer = [0; 40];
    io.read_exact(&mut trailer)?;
    if count != expected.records || trailer[..8] != count.to_le_bytes()
        || trailer[8..] != body || io.bytes != expected.bytes {
        fail!("Archive manifest trailer mismatch");
    }
    if io.full.finalize() != expected.digest { fail!("Archive manifest digest mismatch"); }
    let mut extra = [0];
    if io.inner.read(&mut extra)? != 0 { fail!("Trailing archive manifest bytes"); }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/test_recovery_manifest.rs"]
mod tests;
