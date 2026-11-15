// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
use adnl::wire_keys::*;
use rtos_api::{ton, IntoBoxed, WireProfile};
use rtos_block::UInt256;
fn reason(error: anyhow::Error) -> &'static str {
    error.downcast_ref::<KeyRefusal>().unwrap().0
}
fn private(key: ton::PrivateKey) -> NetworkPrivateKey {
    NetworkPrivateKey::from_wire(&WireProfile::T0.serialize(&key).unwrap()).unwrap()
}

#[test]
fn key_metadata_estimate_is_distinct_from_padded_wire_size() {
    for (count, estimate, encoded) in [(253, 261, 260), (254, 262, 264)] {
        let key = ton::pub_::publickey::Unenc { data: vec![0; count] }.into_boxed();
        let wire = WireProfile::T0.serialize(&key).unwrap();
        let key = NetworkPublicKey::from_wire(&wire).unwrap();
        assert_eq!(key.serialized_size_estimate(), estimate);
        assert_eq!(key.to_wire().unwrap().len(), encoded);
    }
}
#[test]
fn wire_key_refusals_keep_truncation_constructor_and_suffix_boundaries() {
    for (wire, code) in [
        (vec![], "tl_truncated"),
        (vec![0; 4], "tl_unknown_constructor"),
        (hex::decode("0a451fb6ffffffffffffffff").unwrap(), "tl_truncated"),
        (hex::decode("0a451fb60000000000000000").unwrap(), "tl_trailing_data"),
    ] {
        assert_eq!(reason(NetworkPublicKey::from_wire(&wire).err().unwrap()), code);
    }
    // Local malformed private-key configuration remains an error to callers;
    // the conformance adapter distinguishes it from a remote key refusal.
    assert!(NetworkPrivateKey::from_wire(&[0; 4]).is_err());
}
#[test]
fn adnl_text_matches_reference_and_checks_prefix_before_crc() {
    let text = "uaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaadi2";
    assert_eq!(encode_adnl_id(&[0; 32]), text);
    assert_eq!(decode_adnl_id(&text.to_ascii_uppercase()).unwrap(), [0; 32]);
    assert_eq!(reason(decode_adnl_id("").unwrap_err()), "adnl_id_length");
    let change = |offset: usize, value: u8| {
        let mut bytes = text.as_bytes().to_vec();
        bytes[offset] = value;
        String::from_utf8(bytes).unwrap()
    };
    assert_eq!(reason(decode_adnl_id(&change(0, b'a')).unwrap_err()), "adnl_id_prefix");
    assert_eq!(reason(decode_adnl_id(&change(1, b'b')).unwrap_err()), "adnl_id_checksum");
    assert_eq!(reason(decode_adnl_id(&change(2, b'!')).unwrap_err()), "adnl_id_encoding");
}
#[test]
fn legacy_cipher_profiles_reuse_native_cipher_and_do_not_grant_signing() {
    // Public test key; expected ciphertext comes from the pinned native reference.
    let key = private(ton::pk::privatekey::Aes { key: UInt256::from([9; 32]) }.into_boxed());
    let public = key.public_key().unwrap();
    let plain = (0..17).collect::<Vec<u8>>();
    let cipher = public.encrypt_deterministic(&plain).unwrap();
    assert_eq!(hex::encode(&cipher),"3e5718fea51a8f3f5baca61c77afab473c1810f8b9db330273b4011ce92c787e90abacd9cfdbf324f360ee77918ad604da");
    assert_eq!(key.decrypt(&cipher).unwrap(), plain);
    assert_eq!(reason(key.sign(&plain).unwrap_err()), "signing_unsupported");
    assert_eq!(reason(public.verify(&plain, &[]).unwrap_err()), "signing_unsupported");
    let mut bad = cipher;
    bad[40] ^= 1;
    assert_eq!(reason(key.decrypt(&bad).unwrap_err()), "digest_mismatch");
    assert_eq!(reason(key.decrypt(&[0; 31]).unwrap_err()), "ciphertext_short");
    let plain_key = private(ton::pk::privatekey::Unenc { data: vec![255] }.into_boxed());
    assert!(plain_key.sign(&plain).unwrap().is_empty());
    assert!(plain_key.public_key().unwrap().verify(&plain, &[1, 2, 3]).is_ok());
    assert_eq!(plain_key.decrypt(&plain).unwrap(), plain);
    let overlay = private(ton::pk::privatekey::Overlay { name: vec![255] }.into_boxed());
    assert_eq!(reason(overlay.sign(&plain).unwrap_err()), "key_unusable");
    assert_eq!(
        reason(overlay.public_key().unwrap().encrypt_deterministic(&plain).unwrap_err()),
        "encryption_unsupported"
    );
}
