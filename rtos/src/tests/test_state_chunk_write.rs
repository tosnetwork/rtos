// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! The production chunk completion boundary with conforming partial writers.
use super::append_downloaded_chunk;
use std::io::{self, Cursor, Write};

struct PartialWriter {
    bytes: Vec<u8>,
    interrupted: bool,
    fail_after: Option<usize>,
    zero: bool,
}

impl Write for PartialWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.interrupted {
            self.interrupted = false;
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        let remaining = self.fail_after.map_or(usize::MAX, |limit| limit - self.bytes.len());
        if remaining == 0 {
            return if self.zero { Ok(0) } else { Err(io::Error::from_raw_os_error(5)) };
        }
        let count = bytes.len().min(2).min(remaining);
        self.bytes.extend_from_slice(&bytes[..count]);
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn writer(interrupted: bool, fail_after: Option<usize>, zero: bool) -> PartialWriter {
    PartialWriter { bytes: Vec::new(), interrupted, fail_after, zero }
}

#[test]
fn chunk_write_complete_cursor_acknowledges_exact_bytes() {
    let mut dest = Cursor::new(Vec::new());
    assert_eq!(append_downloaded_chunk(&mut dest, b"state chunk").unwrap(), 11);
    assert_eq!(dest.into_inner(), b"state chunk");
}

#[test]
fn chunk_write_short_writes_acknowledge_only_after_complete_bytes() {
    let mut dest = writer(false, None, false);
    assert_eq!(append_downloaded_chunk(&mut dest, b"state chunk").unwrap(), 11);
    assert_eq!(dest.bytes, b"state chunk");
}

#[test]
fn chunk_write_interrupted_then_short_writes_complete_before_ack() {
    let mut dest = writer(true, None, false);
    assert_eq!(append_downloaded_chunk(&mut dest, b"state chunk").unwrap(), 11);
    assert_eq!(dest.bytes, b"state chunk");
}

#[test]
fn chunk_write_zero_after_prefix_refuses_completion() {
    let mut dest = writer(false, Some(3), true);
    let error = append_downloaded_chunk(&mut dest, b"state chunk").unwrap_err();
    assert_eq!(error.downcast_ref::<io::Error>().unwrap().kind(), io::ErrorKind::WriteZero);
    assert_eq!(dest.bytes, b"sta");
}

#[test]
fn chunk_write_eio_after_prefix_refuses_completion() {
    let mut dest = writer(false, Some(3), false);
    let error = append_downloaded_chunk(&mut dest, b"state chunk").unwrap_err();
    assert_eq!(error.downcast_ref::<io::Error>().unwrap().raw_os_error(), Some(5));
    assert_eq!(dest.bytes, b"sta");
}
