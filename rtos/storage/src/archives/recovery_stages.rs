// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Selection-owned package stages. Partial bytes are disposable only while
//! Building and only after the complete original canonical inventories match.
use super::{
    recovery_artifacts::directory,
    recovery_data::sorted_entries,
    recovery_participant::Anchor,
    recovery_providers::RecoveryProviders,
    recovery_root::{Inventory, RootHeader, State},
};
use rtos_block::{error, fail, sha256_digest, Result, Sha256, ShardIdent};
use std::{
    fs,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

pub(super) struct Stage {
    pub provider: usize,
    pub identity: [u8; 32],
}
impl Stage {
    pub(super) fn decode(
        providers: &RecoveryProviders,
        input: &mut dyn Read,
        length: u64,
    ) -> Result<Self> {
        if length != 52 {
            fail!("Unsupported Building child record length");
        }
        let mut bytes = [0; 52];
        input.read_exact(&mut bytes)?;
        // version, package-stage disposition, package kind, package ID,
        // full shard workchain/tagged-prefix, complete provider digest.
        if bytes[..3] != [1, 0, 1] || bytes[3] > 1 {
            fail!("Unsupported Building child disposition");
        }
        let key = bytes[3] == 1;
        let id = u32::from_le_bytes(bytes[4..8].try_into()?);
        let shard = ShardIdent::with_tagged_prefix(
            i32::from_le_bytes(bytes[8..12].try_into()?),
            u64::from_le_bytes(bytes[12..20].try_into()?),
        )?;
        if key && !shard.is_masterchain() {
            fail!("Key stage must have masterchain shard");
        }
        let mut selected = None;
        for (index, participant) in providers.participants.iter().enumerate() {
            if participant.descriptor.digest()?.as_slice() == &bytes[20..52] {
                selected = Some(index);
                break;
            }
        }
        let provider = selected.ok_or_else(|| error!("Unknown Building stage provider"))?;
        let descriptor = &providers.participants[provider].descriptor;
        if (key && descriptor.roles & 2 == 0)
            || (!key && descriptor.roles & 4 == 0)
            || descriptor.range.is_some_and(|(start, end)| key || id < start || id > end)
        {
            fail!("Building stage outside provider routing");
        }
        Ok(Self { provider, identity: sha256_digest(bytes) })
    }
    pub(super) fn name(&self) -> String {
        format!("stage-{}.pack", hex::encode(self.identity))
    }
    pub(super) fn path(&self, providers: &RecoveryProviders, root: &RootHeader) -> Result<PathBuf> {
        Ok(operation(providers, root, self.provider)?.join(self.name()))
    }
}
pub(super) fn operation(
    providers: &RecoveryProviders,
    root: &RootHeader,
    index: usize,
) -> Result<PathBuf> {
    Ok(providers.participants[index]
        .archive_root
        .join("archive/recovery")
        .join(hex::encode(root.operation)))
}
pub(super) fn present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() && meta.nlink() == 1 => {
            Ok(true)
        }
        Ok(_) => fail!("Building stage is not an exclusively owned regular file"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
pub(super) struct StageInventory {
    hash: Sha256,
    count: u64,
    last: Option<(usize, [u8; 32])>,
}
impl StageInventory {
    pub(super) fn new() -> Self {
        Self { hash: Sha256::new(), count: 0, last: None }
    }
    pub(super) fn record(&mut self, provider: usize, identity: [u8; 32]) -> Result<()> {
        if self.last.is_some_and(|last| last >= (provider, identity)) {
            fail!("Unordered or duplicate Building stages");
        }
        self.last = Some((provider, identity));
        self.count =
            self.count.checked_add(1).ok_or_else(|| error!("Stage inventory count overflow"))?;
        self.hash.update(u64::try_from(provider)?.to_le_bytes());
        self.hash.update(identity);
        Ok(())
    }
    pub(super) fn finish(self) -> Inventory {
        Inventory { count: self.count, digest: self.hash.finalize() }
    }
}
/// Enumerate every control directory with bounded name batches. Comparing this
/// inventory with present declared stages rejects extra files without retaining
/// a set proportional to the number of children. Missing declared stages are
/// legal before creation and after an interrupted abort.
pub(super) fn inventory(providers: &RecoveryProviders, root: &RootHeader) -> Result<Inventory> {
    if root.state != State::Building {
        fail!("Stage inspection requires Building");
    }
    let ready_intent = super::recovery_producer::has_ready_intent(providers, root)?;
    let mut inventory = StageInventory::new();
    for (index, participant) in providers.participants.iter().enumerate() {
        let operation = operation(providers, root, index)?;
        let controls = operation.parent().unwrap();
        let archive = controls.parent().unwrap();
        if !directory(archive)? || !directory(controls)? {
            continue;
        }
        for entry in fs::read_dir(controls)? {
            if entry?.file_name() != operation.file_name().unwrap() {
                fail!("Unknown Building operation directory");
            }
        }
        if !directory(&operation)? {
            continue;
        }
        sorted_entries(&operation, |path| {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| error!("Invalid stage filename"))?;
            if name == "selection.v1" && participant.descriptor.anchor == Anchor::Node {
                return Ok(());
            }
            if name == "ready.v1" && ready_intent && participant.descriptor.anchor == Anchor::Node {
                if !present(&path)? { fail!("Missing declared Ready staging file"); }
                return Ok(());
            }
            let hex = name
                .strip_prefix("stage-")
                .and_then(|n| n.strip_suffix(".pack"))
                .ok_or_else(|| error!("Unrecognized remaining recovery artifact"))?;
            if hex.len() != 64
                || !hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                fail!("Invalid Building stage identity");
            }
            let identity: [u8; 32] =
                hex::decode(hex)?.try_into().map_err(|_| error!("Invalid stage digest"))?;
            if !present(&path)? {
                fail!("Building stage disappeared during inspection");
            }
            inventory.record(index, identity)
        })?;
    }
    Ok(inventory.finish())
}
