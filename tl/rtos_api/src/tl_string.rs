// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! TL strings are byte strings. Text consumers explicitly validate UTF-8;
//! encoding always retains the original bytes, including malformed UTF-8.
use crate::{BareDeserialize, BareSerialize, Deserializer, Result, Serializer, WireProfile};
use std::{fmt, ops::Deref, str::Utf8Error};

#[repr(transparent)]
#[derive(Clone, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TlString(Vec<u8>);

impl TlString {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn as_str(&self) -> std::result::Result<&str, Utf8Error> {
        std::str::from_utf8(&self.0)
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
    pub fn into_string(self) -> std::result::Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.0)
    }
}
impl From<Vec<u8>> for TlString {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}
impl From<String> for TlString {
    fn from(value: String) -> Self {
        Self(value.into_bytes())
    }
}
impl From<&str> for TlString {
    fn from(value: &str) -> Self {
        Self(value.as_bytes().to_vec())
    }
}
impl AsRef<[u8]> for TlString {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}
impl Deref for TlString {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_bytes()
    }
}
impl fmt::Debug for TlString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_str() {
            Ok(text) => fmt::Debug::fmt(text, f),
            Err(_) => fmt::Debug::fmt(&self.0, f),
        }
    }
}
impl fmt::Display for TlString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Diagnostics only. The wire serializer never passes through Display.
        f.write_str(&String::from_utf8_lossy(&self.0))
    }
}
impl PartialEq<str> for TlString {
    fn eq(&self, other: &str) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}
impl PartialEq<&str> for TlString {
    fn eq(&self, other: &&str) -> bool {
        self == *other
    }
}
impl PartialEq<String> for TlString {
    fn eq(&self, other: &String) -> bool {
        self == other.as_str()
    }
}
impl BareDeserialize for TlString {
    fn deserialize_bare(de: &mut Deserializer) -> Result<Self> {
        let value = Self(de.read_bare()?);
        if de.profile == WireProfile::Legacy {
            value.as_str()?;
        }
        Ok(value)
    }
}
impl BareSerialize for TlString {
    fn constructor(&self) -> u32 {
        unreachable!()
    }
    fn serialize_bare(&self, ser: &mut Serializer) -> Result<()> {
        if ser.profile == WireProfile::Legacy {
            self.as_str()?;
        }
        ser.write_bare(self.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn target_strings_preserve_every_byte() {
        let value = TlString::from((0..=255).collect::<Vec<u8>>());
        let mut encoded = Vec::new();
        Serializer::with_profile(&mut encoded, WireProfile::T0).write_bare(&value).unwrap();
        let mut input = encoded.as_slice();
        let decoded: TlString = Deserializer::with_profile(&mut input, WireProfile::T0)
            .with_input_len(encoded.len())
            .read_bare()
            .unwrap();
        assert_eq!(decoded, value);
        assert!(decoded.as_str().is_err());
        assert!(input.is_empty());
    }

    #[test]
    fn legacy_strings_keep_utf8_contract() {
        for profile in [WireProfile::Legacy, WireProfile::T0] {
            let value = TlString::from("TOS 文字");
            let mut bytes = Vec::new();
            Serializer::with_profile(&mut bytes, profile).write_bare(&value).unwrap();
            let mut input = bytes.as_slice();
            let decoded: TlString =
                Deserializer::with_profile(&mut input, profile).read_bare().unwrap();
            assert_eq!(decoded.as_str().unwrap(), "TOS 文字");
        }
        let value = TlString::from(vec![0xff]);
        assert!(Serializer::new(&mut Vec::new()).write_bare(&value).is_err());
        let mut input = &[1, 0xff, 0, 0][..];
        assert!(Deserializer::new(&mut input).read_bare::<TlString>().is_err());
    }

    #[test]
    fn missing_large_payload_precedes_allocation_limit() {
        let mut input = &[255, 0, 0, 0, 0, 1, 0, 0][..];
        let mut de = Deserializer::with_profile(&mut input, WireProfile::T0)
            .with_input_len(8)
            .with_bytes_budget(0);
        let error = de.read_bare::<TlString>().unwrap_err();
        assert_eq!(error.downcast_ref::<io::Error>().unwrap().kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(de.pos, 8);
    }
}
