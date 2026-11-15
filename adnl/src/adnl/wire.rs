// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//! Typed T0 wire decoding with caller-specific refusal types.
use rtos_api::WireProfile;

pub(crate) fn decode<T: rtos_api::BoxedDeserialize>(
    bytes: &[u8],
    refused: impl Fn(&'static str) -> anyhow::Error,
) -> anyhow::Result<T> {
    WireProfile::T0.deserialize_value_bounded(bytes, bytes.len()).map_err(|error| {
        let reason = if error.is::<rtos_api::InvalidConstructor>() {
            "tl_unknown_constructor"
        } else if error.to_string().starts_with("Invalid TL vector length ") {
            "tl_bad_length"
        } else if error.is::<rtos_api::DecodeLimitExceeded>()
            || error.to_string().starts_with("Too big string of ")
            || error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::UnexpectedEof)
        {
            "tl_truncated"
        } else if error.to_string() == "Trailing bytes after wire object" {
            "tl_trailing_data"
        } else {
            return error;
        };
        refused(reason)
    })
}
