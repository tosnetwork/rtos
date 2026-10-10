// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
use super::*;

#[test]
fn malformed_inputs_never_reach_native_code() {
    let message = vec![0; MAX_MESSAGE_BYTES];
    let context = vec![0; MAX_CONTEXT_BYTES];
    let signature = vec![0; SIGNATURE_BYTES];
    let public_key = vec![0; PUBLIC_KEY_BYTES];
    let never = |_: &[u8], _: &[u8], _: &[u8; SIGNATURE_BYTES], _: &[u8; PUBLIC_KEY_BYTES]| {
        panic!("malformed input reached backend")
    };
    for size in [0, PUBLIC_KEY_BYTES - 1, PUBLIC_KEY_BYTES + 1] {
        assert_eq!(
            verify_with(&message, &context, &signature, &vec![0; size], never),
            Err(VerifyError::PublicKeyLength(size))
        );
    }
    for size in [0, SIGNATURE_BYTES - 1, SIGNATURE_BYTES + 1] {
        assert_eq!(
            verify_with(&message, &context, &vec![0; size], &public_key, never),
            Err(VerifyError::SignatureLength(size))
        );
    }
    assert_eq!(
        verify_with(&vec![0; MAX_MESSAGE_BYTES + 1], &context, &signature, &public_key, never),
        Err(VerifyError::MessageLength(MAX_MESSAGE_BYTES + 1))
    );
    assert_eq!(
        verify_with(&message, &vec![0; MAX_CONTEXT_BYTES + 1], &signature, &public_key, never),
        Err(VerifyError::ContextLength(MAX_CONTEXT_BYTES + 1))
    );
}

#[test]
fn backend_faults_are_not_mathematical_rejections() {
    for code in [-9, -8, -7, -5, -4, -3, -2, -1, 1, i32::MAX, i32::MIN] {
        assert_eq!(
            verify_with(&[], &[], &[0; SIGNATURE_BYTES], &[0; PUBLIC_KEY_BYTES], |_, _, _, _| code),
            Err(VerifyError::Backend(code))
        );
    }
    for (code, expected) in [(0, true), (-6, false)] {
        assert_eq!(
            verify_with(&[], &[], &[0; SIGNATURE_BYTES], &[0; PUBLIC_KEY_BYTES], |_, _, _, _| code),
            Ok(expected)
        );
    }
}
