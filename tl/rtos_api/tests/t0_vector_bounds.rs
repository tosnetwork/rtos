// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
use rtos_api::{ton, IntoBoxed, WireProfile};
fn wire(count: i32) -> Vec<u8> {
    let list = ton::adnl::addresslist::AddressList {
        addrs: Vec::new(),
        version: 0,
        reinit_date: 0,
        priority: 0,
        expire_at: 0,
    };
    let mut b = WireProfile::T0.serialize(&list.into_boxed()).unwrap();
    b[4..8].copy_from_slice(&count.to_le_bytes());
    b
}
#[test]
fn typed_and_dynamic_slice_readers_apply_cpp_remaining_bytes_vector_guard() {
    // Actual CPP TlFetchVector uses byte multiplicity, not element-width estimates.
    // Empty AddressList has16bytes remaining after the count.
    for count in [17, i32::MAX] {
        let b = wire(count);
        let errors = [
            WireProfile::T0.deserialize_value::<ton::adnl::AddressList>(&b).err().unwrap(),
            WireProfile::T0
                .deserialize_value_bounded::<ton::adnl::AddressList>(&b, b.len())
                .err()
                .unwrap(),
            WireProfile::T0.deserialize_with_suffix(&b).err().unwrap(),
            WireProfile::T0.deserialize_bundle(&b).err().unwrap(),
        ];
        for e in errors {
            assert!(e.to_string().starts_with("Invalid TL vector length"), "{e}");
        }
    }
    let b = wire(16);
    assert!(WireProfile::T0
        .deserialize_value::<ton::adnl::AddressList>(&b)
        .err()
        .unwrap()
        .is::<rtos_api::InvalidConstructor>());
    let b = wire(17);
    assert!(WireProfile::Legacy
        .deserialize_value::<ton::adnl::AddressList>(&b)
        .err()
        .unwrap()
        .is::<rtos_api::InvalidConstructor>());
}
