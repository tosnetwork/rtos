// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//! Original Falcon-512 with the fixed 666-byte padded signature encoding.
use std::{error::Error, fmt, os::raw::c_int};

pub const PUBLIC_KEY_BYTES: usize = 897;
pub const SIGNATURE_BYTES: usize = 666;
pub const MAX_MESSAGE_BYTES: usize = 8192;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifyError {
    PublicKeyLength(usize),
    SignatureLength(usize),
    MessageLength(usize),
    Backend(c_int),
}
impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Falcon-512 verification error: {self:?}")
    }
}
impl Error for VerifyError {}

extern "C" {
    fn rtos_falcon512_padded_verify(
        message: *const u8,
        message_len: usize,
        signature: *const u8,
        signature_len: usize,
        key: *const u8,
        key_len: usize,
    ) -> c_int;
}

/// Reject unsupported lengths before native code. Invalid encodings, nonzero
/// padding and mathematically invalid signatures return `Ok(false)`.
pub fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, VerifyError> {
    if message.len() > MAX_MESSAGE_BYTES {
        return Err(VerifyError::MessageLength(message.len()));
    }
    if signature.len() != SIGNATURE_BYTES {
        return Err(VerifyError::SignatureLength(signature.len()));
    }
    if public_key.len() != PUBLIC_KEY_BYTES {
        return Err(VerifyError::PublicKeyLength(public_key.len()));
    }
    let empty = 0u8;
    let message_ptr = if message.is_empty() { &empty } else { message.as_ptr() };
    // SAFETY: all slices remain readable and immutable throughout this synchronous
    // call, exact lengths are checked above, and the backend retains no pointers.
    match unsafe {
        rtos_falcon512_padded_verify(
            message_ptr,
            message.len(),
            signature.as_ptr(),
            signature.len(),
            public_key.as_ptr(),
            public_key.len(),
        )
    } {
        1 => Ok(true),
        0 => Ok(false),
        code => Err(VerifyError::Backend(code)),
    }
}
