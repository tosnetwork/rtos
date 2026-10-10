// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//! Bounded verification using the pinned portable ML-DSA-44 C backend.
//!
//! This crate verifies a signature under a supplied public key. It does not
//! establish that the key is authorized by a network, session, or validator set.
#![deny(unsafe_op_in_unsafe_fn)]

use std::{error::Error, fmt, os::raw::c_int};

pub const PUBLIC_KEY_BYTES: usize = 1312;
pub const SIGNATURE_BYTES: usize = 2420;
pub const MAX_MESSAGE_BYTES: usize = 8192;
pub const MAX_CONTEXT_BYTES: usize = 255;
pub const SIMPLEX_CONTEXT: &[u8] = b"TOS-CONSENSUS-SIMPLEX-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifyError {
    PublicKeyLength(usize),
    SignatureLength(usize),
    MessageLength(usize),
    ContextLength(usize),
    Backend(c_int),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublicKeyLength(n) => {
                write!(f, "ML-DSA-44 public key length {n}, expected {PUBLIC_KEY_BYTES}")
            }
            Self::SignatureLength(n) => {
                write!(f, "ML-DSA-44 signature length {n}, expected {SIGNATURE_BYTES}")
            }
            Self::MessageLength(n) => {
                write!(f, "ML-DSA-44 message length {n} exceeds {MAX_MESSAGE_BYTES}")
            }
            Self::ContextLength(n) => {
                write!(f, "ML-DSA-44 context length {n} exceeds {MAX_CONTEXT_BYTES}")
            }
            Self::Backend(code) => write!(f, "ML-DSA-44 verification backend failed ({code})"),
        }
    }
}

impl Error for VerifyError {}

extern "C" {
    fn rtos_mldsa44_native_verify(
        signature: *const u8,
        message: *const u8,
        message_len: usize,
        context: *const u8,
        context_len: usize,
        public_key: *const u8,
    ) -> c_int;
}

/// Verify pure ML-DSA-44, including the FIPS 204 context string.
///
/// `Ok(false)` means a mathematical signature rejection. Malformed input or
/// a backend fault returns `Err`; neither result authorizes the message.
pub fn verify(
    message: &[u8],
    context: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool, VerifyError> {
    verify_with(message, context, signature, public_key, native_verify)
}

/// Verify a Simplex consensus preimage with the frozen consensus context.
/// The caller must independently authenticate membership and build the exact
/// protocol preimage, including its session and vote role.
pub fn verify_simplex(
    preimage: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool, VerifyError> {
    verify(preimage, SIMPLEX_CONTEXT, signature, public_key)
}

// A private callback allows boundary tests to prove malformed inputs never
// enter native code. Production always invokes the fixed native verifier.
fn verify_with(
    message: &[u8],
    context: &[u8],
    signature: &[u8],
    public_key: &[u8],
    backend: impl FnOnce(&[u8], &[u8], &[u8; SIGNATURE_BYTES], &[u8; PUBLIC_KEY_BYTES]) -> c_int,
) -> Result<bool, VerifyError> {
    if message.len() > MAX_MESSAGE_BYTES {
        return Err(VerifyError::MessageLength(message.len()));
    }
    if context.len() > MAX_CONTEXT_BYTES {
        return Err(VerifyError::ContextLength(context.len()));
    }
    let signature =
        signature.try_into().map_err(|_| VerifyError::SignatureLength(signature.len()))?;
    let public_key =
        public_key.try_into().map_err(|_| VerifyError::PublicKeyLength(public_key.len()))?;
    match backend(message, context, signature, public_key) {
        0 => Ok(true),
        -6 => Ok(false),
        code => Err(VerifyError::Backend(code)),
    }
}

fn native_verify(
    message: &[u8],
    context: &[u8],
    signature: &[u8; SIGNATURE_BYTES],
    public_key: &[u8; PUBLIC_KEY_BYTES],
) -> c_int {
    // Even an empty slice points to a real byte for C implementations that
    // perform pointer arithmetic before inspecting the zero length.
    let empty = 0u8;
    let message_ptr = if message.is_empty() { &empty } else { message.as_ptr() };
    let context_ptr = if context.is_empty() { &empty } else { context.as_ptr() };
    // SAFETY: key and signature have the C API's exact array widths. All inputs
    // remain alive and immutable for this synchronous call; C does not retain
    // or free them. Lengths refer to the corresponding readable slices. The
    // backend is compiled with a fixed parameter set and no context parameter.
    unsafe {
        rtos_mldsa44_native_verify(
            signature.as_ptr(),
            message_ptr,
            message.len(),
            context_ptr,
            context.len(),
            public_key.as_ptr(),
        )
    }
}

#[cfg(test)]
mod tests;
