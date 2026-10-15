// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Independent, existing-only provider enumeration for node bootstrap. This
//! retains physical owners and main protection, but does not authorize replay.
use super::{epoch::{scan_existing, ArchivalModeConfig}, recovery_participant::{Anchor, Provider},
    recovery_root::{Inventory, RootHeader}};
use crate::{db::{provider_reservation::ProviderReservation, rocksdb::RocksDb}, repair_protection::RepairProtection};
use rtos_block::{error, fail, Result, Sha256};
use std::{collections::HashSet, io::Read, sync::Arc};

pub(crate) struct Participant {
    pub descriptor: Provider,
    pub database: Arc<RocksDb>,
}
pub(crate) struct RecoveryProviders {
    pub participants: Vec<Participant>,
    /// All participant decisions use this rebuilt main protection, never the
    /// empty protection object on a newly opened epoch wrapper.
    pub protection: Arc<RepairProtection>,
}
impl RecoveryProviders {
    pub(crate) async fn inspect(
        main: Arc<RocksDb>, root: &RootHeader, config: Option<&ArchivalModeConfig>,
        protection: &Arc<RepairProtection>,
    ) -> Result<Self> {
        root.validate()?;
        if !Arc::ptr_eq(protection, main.repair_protection()) {
            fail!("Recovery providers require the main database protection");
        }
        let node_root = main.db().path().parent().ok_or_else(|| error!("Missing node root"))?;
        let descriptor = Provider::main(node_root, config.is_some(), &main.db().get_db_identity()?)?;
        if descriptor.database.bytes != root.database_identity_bytes
            || descriptor.database.digest != root.database_identity_digest {
            fail!("Recovery provider main identity mismatch");
        }
        let mut identities = HashSet::new();
        identities.insert(descriptor.database);
        let mut participants = vec![Participant { descriptor, database: main }];
        if let Some(config) = config {
            for entry in scan_existing(config, true).await? {
                let owner = ProviderReservation::open_existing(&entry.path.join("archive_db"))?;
                let database = RocksDb::open_existing_for_recovery(owner, None)?;
                let descriptor = Provider::epoch(&entry.path,
                    if entry.explicit { &entry.path } else { &config.new_epochs_path },
                    if entry.explicit { Anchor::ExplicitEpoch } else { Anchor::Discovery },
                    (entry.meta.mc_seq_no_start, entry.meta.mc_seq_no_end), &database.db().get_db_identity()?)?;
                if !identities.insert(descriptor.database) { fail!("Duplicate recovery provider native identity"); }
                participants.push(Participant { descriptor, database });
            }
        }
        // Same ordering used by Provider records: routing roles, anchor kind,
        // anchor identity and exact relative path, independent of config order.
        participants.sort_by(|a, b| {
            let a = &a.descriptor; let b = &b.descriptor;
            (a.roles, a.anchor as u8, a.anchor_identity, &a.relative)
                .cmp(&(b.roles, b.anchor as u8, b.anchor_identity, &b.relative))
        });
        Ok(Self { participants, protection: protection.clone() })
    }
    pub(crate) fn inventory(&self) -> Result<Inventory> {
        let mut digest = Sha256::new();
        for participant in &self.participants {
            digest.update(participant.descriptor.encoded_len()?.to_le_bytes());
            digest.update(participant.descriptor.digest()?);
        }
        Ok(Inventory { count: u64::try_from(self.participants.len())?, digest: digest.finalize() })
    }
    /// A selection validator streams records in order and must call finish;
    /// missing, extra and duplicate providers cannot silently disappear.
    pub(crate) fn checker(&self) -> ProviderRecords<'_> { ProviderRecords { providers: self, next: 0, failed: false } }
}

pub(crate) struct ProviderRecords<'a> { providers: &'a RecoveryProviders, next: usize, failed: bool }
impl ProviderRecords<'_> {
    pub(crate) fn record(&mut self, input: &mut dyn Read, length: u64) -> Result<()> {
        if self.failed { fail!("Recovery provider record stream failed"); }
        self.failed = true;
        let expected = self.providers.participants.get(self.next).ok_or_else(|| error!("Extra recovery provider"))?;
        expected.descriptor.check_record(input, length)?;
        self.next += 1; self.failed = false;
        Ok(())
    }
    pub(crate) fn finish(self) -> Result<()> {
        if self.failed || self.next != self.providers.participants.len() { fail!("Incomplete recovery provider set"); }
        Ok(())
    }
}

#[cfg(test)]
#[path = "../tests/test_recovery_providers.rs"]
mod tests;
