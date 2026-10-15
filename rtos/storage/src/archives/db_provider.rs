/*
 * RTOS project modifications (2026-10-10): project and crate naming.
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use super::{
    context::{ArchiveOperation, ArchiveProvider},
    epoch::EpochRouter,
};
use rtos_block::Result;
use std::{path::PathBuf, sync::Arc};

/// A resolved destination retains its actual provider and inherited epoch.
pub struct ResolvedArchive {
    pub provider: ArchiveProvider,
    pub root_path: Arc<PathBuf>,
    pub operation: ArchiveOperation,
}

#[async_trait::async_trait]
pub trait ArchiveDbProvider: Send + Sync {
    fn main_binding(&self) -> &ArchiveProvider;

    /// Existing destination only. This route must not create directories/DBs.
    async fn resolve_for_read(
        &self,
        parent: &ArchiveOperation,
        archive_id: u32,
    ) -> Result<Option<ResolvedArchive>>;

    /// Initialization/mutation route. Canonical mutation ownership migration is
    /// still separate; admission must nevertheless precede resolution effects.
    async fn db_for_archive(
        &self,
        parent: &ArchiveOperation,
        archive_id: u32,
    ) -> Result<ResolvedArchive>;

    fn memory_usage(&self) -> crate::RocksDbMemoryUsage;
}

pub struct SingleDbProvider {
    binding: ArchiveProvider,
    db_root_path: Arc<PathBuf>,
}
impl SingleDbProvider {
    pub fn new(binding: ArchiveProvider, db_root_path: Arc<PathBuf>) -> Self {
        Self { binding, db_root_path }
    }
    fn resolve(&self, parent: &ArchiveOperation) -> Result<ResolvedArchive> {
        Ok(ResolvedArchive {
            operation: parent.inherit(&self.binding)?,
            provider: self.binding.clone(),
            root_path: self.db_root_path.clone(),
        })
    }
}
#[async_trait::async_trait]
impl ArchiveDbProvider for SingleDbProvider {
    fn main_binding(&self) -> &ArchiveProvider {
        &self.binding
    }
    async fn resolve_for_read(
        &self,
        parent: &ArchiveOperation,
        _archive_id: u32,
    ) -> Result<Option<ResolvedArchive>> {
        Ok(Some(self.resolve(parent)?))
    }
    async fn db_for_archive(
        &self,
        parent: &ArchiveOperation,
        _archive_id: u32,
    ) -> Result<ResolvedArchive> {
        self.resolve(parent)
    }
    fn memory_usage(&self) -> crate::RocksDbMemoryUsage {
        Default::default()
    }
}

pub struct EpochDbProvider {
    router: Arc<EpochRouter>,
}
impl EpochDbProvider {
    pub fn new(router: Arc<EpochRouter>) -> Self {
        Self { router }
    }
    pub fn router(&self) -> &Arc<EpochRouter> {
        &self.router
    }
}
#[async_trait::async_trait]
impl ArchiveDbProvider for EpochDbProvider {
    fn main_binding(&self) -> &ArchiveProvider {
        self.router.view().binding()
    }
    async fn resolve_for_read(
        &self,
        parent: &ArchiveOperation,
        archive_id: u32,
    ) -> Result<Option<ResolvedArchive>> {
        // Check even a cache miss/hit; neither permits bypassing the captured view.
        let operation = self.router.view().inherit(parent)?;
        let Some(epoch) = self.router.resolve(archive_id) else {
            return Ok(None);
        };
        Ok(Some(ResolvedArchive {
            operation: operation.inherit(epoch.binding())?,
            provider: epoch.binding().clone(),
            root_path: epoch.path().clone(),
        }))
    }
    async fn db_for_archive(
        &self,
        parent: &ArchiveOperation,
        archive_id: u32,
    ) -> Result<ResolvedArchive> {
        let operation = self.router.view().inherit(parent)?;
        let epoch = self.router.resolve_or_create_in(&operation, archive_id).await?;
        Ok(ResolvedArchive {
            operation: operation.inherit(epoch.binding())?,
            provider: epoch.binding().clone(),
            root_path: epoch.path().clone(),
        })
    }
    fn memory_usage(&self) -> crate::RocksDbMemoryUsage {
        self.router.memory_usage()
    }
}

#[cfg(test)]
#[path = "../tests/test_archive_provider_context.rs"]
mod tests;
