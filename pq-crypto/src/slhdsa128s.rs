// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//! Pure SLH-DSA-SHA2-128s (FIPS 205), with an explicit context string.
use std::{error::Error, fmt, os::raw::c_int};

pub const PUBLIC_KEY_BYTES: usize = 32;
pub const SIGNATURE_BYTES: usize = 7856;
pub const MAX_MESSAGE_BYTES: usize = 8192;
pub const MAX_CONTEXT_BYTES: usize = 255;

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
        write!(f, "SLH-DSA-SHA2-128s verification error: {self:?}")
    }
}
impl Error for VerifyError {}

extern "C" {
    fn rtos_slhdsa128s_native_verify(
        message: *const u8,
        message_len: usize,
        context: *const u8,
        context_len: usize,
        signature: *const u8,
        signature_len: usize,
        key: *const u8,
        key_len: usize,
    ) -> c_int;
}

/// Verify the pure FIPS 205 profile, including its context/domain prefix.
/// Malformed lengths return `Err` before native code; mathematical rejection
/// returns `Ok(false)`. HashSLH-DSA and the internal no-context mode are not exposed.
pub fn verify(
    message: &[u8],
    context: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool, VerifyError> {
    verify_with(message, context, signature, public_key, native_verify)
}

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
        1 => Ok(true),
        0 => Ok(false),
        code => Err(VerifyError::Backend(code)),
    }
}

fn native_verify(
    message: &[u8],
    context: &[u8],
    signature: &[u8; SIGNATURE_BYTES],
    public_key: &[u8; PUBLIC_KEY_BYTES],
) -> c_int {
    // A real byte also backs empty slices, for zero-length C pointer arithmetic.
    let empty = 0u8;
    let message_ptr = if message.is_empty() { &empty } else { message.as_ptr() };
    let context_ptr = if context.is_empty() { &empty } else { context.as_ptr() };
    // SAFETY: all inputs are readable and immutable for this synchronous call.
    // Key/signature lengths and resource bounds are checked before entry. The
    // fixed parameter backend retains no pointers and performs no callbacks.
    unsafe {
        rtos_slhdsa128s_native_verify(
            message_ptr,
            message.len(),
            context_ptr,
            context.len(),
            signature.as_ptr(),
            signature.len(),
            public_key.as_ptr(),
            public_key.len(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_precede_native_and_backend_codes_are_exact() {
        let sig = [0; SIGNATURE_BYTES];
        let pk = [0; PUBLIC_KEY_BYTES];
        let never =
            |_: &[u8], _: &[u8], _: &[u8; SIGNATURE_BYTES], _: &[u8; PUBLIC_KEY_BYTES]| -> c_int {
                panic!("malformed input entered native code")
            };
        assert_eq!(
            verify_with(&[0; 8193], &[], &sig, &pk, never),
            Err(VerifyError::MessageLength(8193))
        );
        assert_eq!(
            verify_with(&[], &[0; 256], &sig, &pk, never),
            Err(VerifyError::ContextLength(256))
        );
        for n in [0, 1, 7855, 7857, 8192] {
            assert_eq!(
                verify_with(&[], &[], &vec![0; n], &pk, never),
                Err(VerifyError::SignatureLength(n))
            );
        }
        for n in [0, 1, 31, 33, 64] {
            assert_eq!(
                verify_with(&[], &[], &sig, &vec![0; n], never),
                Err(VerifyError::PublicKeyLength(n))
            );
        }
        for n in [0, 1, 8191, 8192] {
            for c in [0, 1, 254, 255] {
                for (code, expected) in [
                    (1, Ok(true)),
                    (0, Ok(false)),
                    (-1, Err(VerifyError::Backend(-1))),
                    (2, Err(VerifyError::Backend(2))),
                ] {
                    assert_eq!(
                        verify_with(&vec![0; n], &vec![0; c], &sig, &pk, |_, _, _, _| code),
                        expected
                    );
                }
            }
        }
    }
}
