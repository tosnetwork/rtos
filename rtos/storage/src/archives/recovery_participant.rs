// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Participant binding against independently enumerated, trusted providers.
//! Manifest path bytes are compared, never used to choose a filesystem target.
use rtos_block::{error, fail, sha256_digest, Result, Sha256};
use std::{
    io::{Read, Write},
    path::{Component, PathBuf},
};

const PROVIDER_PREFIX: usize = 93;
const BACKLINK_SIZE: usize = 164;
const BACKLINK_CHECKSUM: usize = BACKLINK_SIZE - 32;
const MAIN: u8 = 1;
const KEY: u8 = 2;
const ARCHIVE: u8 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Identity {
    pub bytes: u64,
    pub digest: [u8; 32],
}
impl Identity {
    pub(crate) fn native(bytes: &[u8]) -> Result<Self> {
        let value = Self { bytes: u64::try_from(bytes.len())?, digest: sha256_digest(bytes) };
        value.validate()?;
        Ok(value)
    }
    fn validate(self) -> Result<()> {
        if self.bytes == 0 || self.digest == [0; 32] {
            fail!("Missing recovery database identity");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Anchor {
    Node = 1,
    ExplicitEpoch = 2,
    Discovery = 3,
}

/// Construct only from trusted startup configuration and independently inspected
/// existing providers. Anchor identity includes the configured anchor, not its
/// position in a mutable configuration vector. Physical path and native identity
/// uniqueness are separate full-enumeration obligations.
#[derive(Clone)]
pub(crate) struct Provider {
    pub roles: u8,
    pub anchor: Anchor,
    pub anchor_identity: [u8; 32],
    pub database: Identity,
    pub range: Option<(u32, u32)>,
    pub relative: PathBuf,
}
fn existing_directory(path: &std::path::Path) -> Result<PathBuf> {
    let absolute =
        if path.is_absolute() { path.to_path_buf() } else { std::env::current_dir()?.join(path) };
    let mut prefix = PathBuf::new();
    for part in absolute.components() {
        if matches!(part, Component::ParentDir) {
            fail!("Parent traversal in recovery anchor");
        }
        prefix.push(part.as_os_str());
        let metadata = std::fs::symlink_metadata(&prefix)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            fail!("Invalid recovery anchor directory");
        }
    }
    Ok(std::fs::canonicalize(absolute)?)
}
impl Provider {
    pub(crate) fn main(
        root: &std::path::Path,
        epochs: bool,
        native_identity: &[u8],
    ) -> Result<Self> {
        let root = existing_directory(root)?;
        let mut digest = Sha256::new();
        let raw = root.as_os_str().as_encoded_bytes();
        digest.update(b"RTOS archive recovery anchor v1");
        digest.update([Anchor::Node as u8]);
        digest.update(u64::try_from(raw.len())?.to_le_bytes());
        digest.update(raw);
        let value = Self {
            roles: if epochs { MAIN | KEY } else { MAIN | KEY | ARCHIVE },
            anchor: Anchor::Node,
            anchor_identity: digest.finalize(),
            database: Identity::native(native_identity)?,
            range: None,
            relative: PathBuf::new(),
        };
        value.validate()?;
        Ok(value)
    }

    /// Bind a trusted existing epoch path to its configured anchor and native
    /// identity. This inspection does not replace an owned filesystem handle.
    pub(crate) fn epoch(
        path: &std::path::Path,
        anchor_root: &std::path::Path,
        anchor: Anchor,
        range: (u32, u32),
        native_identity: &[u8],
    ) -> Result<Self> {
        if anchor == Anchor::Node {
            fail!("Epoch provider requires epoch anchor");
        }
        let path = existing_directory(path)?;
        let root = existing_directory(anchor_root)?;
        let relative = path.strip_prefix(&root)?.to_path_buf();
        if anchor == Anchor::ExplicitEpoch && !relative.as_os_str().is_empty() {
            fail!("Explicit epoch anchor must be the configured directory");
        }
        let mut digest = Sha256::new();
        let raw = root.as_os_str().as_encoded_bytes();
        digest.update(b"RTOS archive recovery anchor v1");
        digest.update([anchor as u8]);
        digest.update(u64::try_from(raw.len())?.to_le_bytes());
        digest.update(raw);
        let value = Self {
            roles: ARCHIVE,
            anchor,
            anchor_identity: digest.finalize(),
            database: Identity::native(native_identity)?,
            range: Some(range),
            relative,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<()> {
        self.database.validate()?;
        if self.anchor_identity == [0; 32] {
            fail!("Missing recovery anchor identity");
        }
        match self.anchor {
            Anchor::Node => {
                if !matches!(self.roles, 3 | 7) || self.range.is_some() {
                    fail!("Invalid main recovery provider roles or range");
                }
            }
            Anchor::ExplicitEpoch | Anchor::Discovery => {
                if self.roles != ARCHIVE || !self.range.is_some_and(|(start, end)| start <= end) {
                    fail!("Invalid epoch recovery provider roles or range");
                }
            }
        }
        if self.relative.components().any(|part| !matches!(part, Component::Normal(_))) {
            fail!("Invalid recovery relative path");
        }
        let bytes = self.relative.as_os_str().as_encoded_bytes();
        // Reject alternate spellings hidden by Path::components normalization.
        if !bytes.is_empty()
            && bytes
                .split(|byte| *byte == b'/')
                .any(|part| part.is_empty() || part == b"." || part == b".." || part.contains(&0))
        {
            fail!("Noncanonical recovery relative path");
        }
        if self.anchor == Anchor::Discovery && bytes.is_empty() {
            fail!("Discovered recovery provider requires relative directory");
        }
        Ok(())
    }
    fn prefix(&self) -> Result<[u8; PROVIDER_PREFIX]> {
        self.validate()?;
        let mut bytes = [0; PROVIDER_PREFIX];
        bytes[..2].copy_from_slice(&1u16.to_le_bytes());
        bytes[2] = self.roles;
        bytes[3] = self.anchor as u8;
        bytes[4..36].copy_from_slice(&self.anchor_identity);
        bytes[36..44].copy_from_slice(&self.database.bytes.to_le_bytes());
        bytes[44..76].copy_from_slice(&self.database.digest);
        if let Some((start, end)) = self.range {
            bytes[76] = 1;
            bytes[77..81].copy_from_slice(&start.to_le_bytes());
            bytes[81..85].copy_from_slice(&end.to_le_bytes());
        }
        bytes[85..93].copy_from_slice(
            &u64::try_from(self.relative.as_os_str().as_encoded_bytes().len())?.to_le_bytes(),
        );
        Ok(bytes)
    }
    pub(crate) fn encoded_len(&self) -> Result<u64> {
        self.validate()?;
        (PROVIDER_PREFIX as u64)
            .checked_add(u64::try_from(self.relative.as_os_str().as_encoded_bytes().len())?)
            .ok_or_else(|| error!("Recovery provider length overflow"))
    }
    pub(crate) fn write(&self, out: &mut dyn Write) -> Result<()> {
        out.write_all(&self.prefix()?)?;
        out.write_all(self.relative.as_os_str().as_encoded_bytes())?;
        Ok(())
    }
    pub(crate) fn digest(&self) -> Result<[u8; 32]> {
        let mut digest = Sha256::new();
        digest.update(self.prefix()?);
        digest.update(self.relative.as_os_str().as_encoded_bytes());
        Ok(digest.finalize())
    }
    /// Compare with a provider from the trusted enumeration, without allocating
    /// from an on-disk path length or following any manifest-supplied path.
    pub(crate) fn check_record(&self, input: &mut dyn Read, length: u64) -> Result<()> {
        if length != self.encoded_len()? {
            fail!("Recovery provider length mismatch");
        }
        let mut prefix = [0; PROVIDER_PREFIX];
        input.read_exact(&mut prefix)?;
        if prefix != self.prefix()? {
            fail!("Recovery provider identity mismatch");
        }
        let expected = self.relative.as_os_str().as_encoded_bytes();
        let mut buffer = [0; 4096];
        for chunk in expected.chunks(buffer.len()) {
            input.read_exact(&mut buffer[..chunk.len()])?;
            if &buffer[..chunk.len()] != chunk {
                fail!("Recovery provider path mismatch");
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Backlink {
    pub operation: [u8; 16],
    pub main: Identity,
    pub selection: [u8; 32],
    /// Hash of complete provider descriptor, including roles, anchor, range,
    /// native database identity and exact relative path.
    pub provider: [u8; 32],
}
impl Backlink {
    fn validate(&self) -> Result<()> {
        self.main.validate()?;
        if self.operation == [0; 16] || self.selection == [0; 32] || self.provider == [0; 32] {
            fail!("Incomplete recovery participant binding");
        }
        Ok(())
    }
    pub(crate) fn encode(&self) -> Result<[u8; BACKLINK_SIZE]> {
        self.validate()?;
        let mut bytes = [0; BACKLINK_SIZE];
        bytes[..8].copy_from_slice(b"RTOSATP1");
        bytes[8..10].copy_from_slice(&1u16.to_le_bytes());
        // Bytes10..12 are reserved flags, currently zero.
        bytes[12..28].copy_from_slice(&self.operation);
        bytes[28..36].copy_from_slice(&self.main.bytes.to_le_bytes());
        bytes[36..68].copy_from_slice(&self.main.digest);
        bytes[68..100].copy_from_slice(&self.selection);
        bytes[100..132].copy_from_slice(&self.provider);
        let checksum = sha256_digest(&bytes[..BACKLINK_CHECKSUM]);
        bytes[BACKLINK_CHECKSUM..].copy_from_slice(&checksum);
        Ok(bytes)
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != BACKLINK_SIZE {
            fail!("Recovery participant length mismatch");
        }
        if &bytes[..8] != b"RTOSATP1"
            || bytes[8..12] != [1, 0, 0, 0]
            || bytes[BACKLINK_CHECKSUM..] != sha256_digest(&bytes[..BACKLINK_CHECKSUM])
        {
            fail!("Unsupported or corrupt recovery participant");
        }
        let value = Self {
            operation: bytes[12..28].try_into()?,
            main: Identity {
                bytes: u64::from_le_bytes(bytes[28..36].try_into()?),
                digest: bytes[36..68].try_into()?,
            },
            selection: bytes[68..100].try_into()?,
            provider: bytes[100..132].try_into()?,
        };
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn check(
        &self,
        root: &super::recovery_root::RootHeader,
        provider: &Provider,
    ) -> Result<()> {
        root.validate()?;
        self.validate()?;
        if self.operation != root.operation
            || self.selection != root.selection.digest
            || self.main.bytes != root.database_identity_bytes
            || self.main.digest != root.database_identity_digest
            || self.provider != provider.digest()?
        {
            fail!("Recovery participant does not match root and provider");
        }
        // Main/key routing is one participant. Its native identity must also
        // equal the root identity, not just the descriptor's opaque digest.
        if provider.roles & (MAIN | KEY) != 0 && provider.database != self.main {
            fail!("Recovery main participant native identity mismatch");
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "../tests/test_recovery_participant.rs"]
mod tests;
