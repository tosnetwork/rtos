// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Native truncation planning. Call only with admission closed, writers retired,
//! and the main repair protection held. Canonical data is read, never edited.
use super::{
    package_entry_id::PackageEntryId,
    package_entry_meta_db::{PackageEntryInfo, PackageEntryMeta},
    package_id::PackageId,
    package_offsets_db::PackageOffsetKey,
    recovery_parent::Map,
    recovery_providers::RecoveryProviders,
    truncation_selection::TruncationSelection,
};
use crate::db::DbKey;
use rtos_block::{error, fail, BlockIdExt, Result, ShardIdent};
use std::{
    fs,
    io::{self, Read, Write},
    os::{fd::IntoRawFd, unix::fs::OpenOptionsExt},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Disposition {
    Keep,
    Filter,
    Drop,
}
struct Archive {
    provider: usize,
    key: bool,
    id: u32,
    disposition: Disposition,
    sliced: bool,
    slice_size: u32,
    separated: bool,
    depth: u8,
}
struct Member {
    archive: Archive,
    index: u32,
    meta: PackageEntryMeta,
    info: PackageEntryInfo,
    path: PathBuf,
}
struct PackageDecision {
    changed: bool,
    retained: bool,
    size: u64,
}

pub(super) struct Plan<'a> {
    providers: &'a RecoveryProviders,
    selection: &'a TruncationSelection,
}
impl<'a> Plan<'a> {
    pub(super) fn new(
        providers: &'a RecoveryProviders,
        selection: &'a TruncationSelection,
    ) -> Result<Self> {
        if providers.protection.archive_range(0, None) {
            fail!("Truncation conflicts with repair custody");
        }
        Ok(Self { providers, selection })
    }
    fn main(&self) -> Result<&crate::db::rocksdb::RocksDb> {
        Ok(&self
            .providers
            .participants
            .iter()
            .find(|p| p.descriptor.anchor == super::recovery_participant::Anchor::Node)
            .ok_or_else(|| error!("Missing truncation main provider"))?
            .database)
    }
    fn boundary(&self, key: bool) -> Result<Option<u32>> {
        let db = self.main()?.db();
        let name = if key { Map::KeyFiles } else { Map::Files }.name();
        let cf = db.cf_handle(name).ok_or_else(|| error!("Missing truncation parent map"))?;
        let mut rows = db.raw_iterator_cf(&cf);
        rows.seek_to_first();
        let mut boundary = None;
        while rows.valid() {
            let bytes: [u8; 4] =
                rows.key().ok_or_else(|| error!("Missing parent key"))?.try_into()?;
            let id = u32::from_le_bytes(bytes);
            if id <= self.selection.cutoff().seq_no()
                && boundary.is_none_or(|previous| id > previous)
            {
                boundary = Some(id);
            }
            rows.next();
        }
        rows.status()?;
        Ok(boundary)
    }
    fn archive(&self, provider: usize, key: bool, id: u32) -> Result<Archive> {
        let disposition = match self.boundary(key)? {
            Some(boundary) if id > boundary => Disposition::Drop,
            Some(boundary) if id == boundary => Disposition::Filter,
            _ => Disposition::Keep,
        };
        let db = self.providers.participants[provider].database.db();
        let cf = db
            .cf_handle(&format!("status_{}db_{id}", if key { "key_" } else { "" }))
            .ok_or_else(|| error!("Missing archive status family"))?;
        let get = |key: &[u8]| -> Result<Vec<u8>> {
            db.get_cf(&cf, key)?.ok_or_else(|| error!("Missing archive status"))
        };
        let sliced = match get(b"SlicedMode")?.as_slice() {
            [0] => false,
            [1] => true,
            _ => fail!("Invalid sliced mode"),
        };
        let slice_size =
            if sliced { u32::from_le_bytes(get(b"SliceSize")?.as_slice().try_into()?) } else { 0 };
        if sliced && slice_size == 0 {
            fail!("Zero archive slice size");
        }
        let (separated, depth) = match db.get_cf(&cf, b"ShardSplitDepth")? {
            Some(bytes) if bytes.len() == 1 => (true, bytes[0]),
            None => (false, 0),
            _ => fail!("Invalid shard split depth"),
        };
        Ok(Archive { provider, key, id, disposition, sliced, slice_size, separated, depth })
    }
    fn member(&self, archive: Archive, key: &[u8], value: &[u8]) -> Result<Member> {
        let index = u32::from_le_bytes(key.try_into()?);
        let meta: PackageEntryMeta = serde_cbor::from_slice(value)?;
        let info = if !archive.sliced {
            if index != u32::MAX && index != 0 {
                fail!("Invalid nonsliced metadata index");
            }
            PackageEntryInfo { seqno: archive.id, shard: ShardIdent::masterchain() }
        } else if archive.separated {
            meta.get_info()?.ok_or_else(|| error!("Missing separated package identity"))?
        } else {
            PackageEntryInfo {
                seqno: archive
                    .id
                    .checked_add(
                        index
                            .checked_mul(archive.slice_size)
                            .ok_or_else(|| error!("Package index overflow"))?,
                    )
                    .ok_or_else(|| error!("Package ID overflow"))?,
                shard: ShardIdent::masterchain(),
            }
        };
        let base = self.providers.participants[archive.provider].archive_root.as_path();
        let package = if archive.key {
            PackageId::for_key_block(info.seqno)
        } else {
            PackageId::for_block(info.seqno)
        };
        let path = package.full_path(base, &info.shard)?;
        Ok(Member { archive, index, meta, info, path })
    }
    fn members(
        &self,
        provider: usize,
        key: bool,
        id: u32,
        mut visit: impl FnMut(Member) -> Result<()>,
    ) -> Result<()> {
        let db = self.providers.participants[provider].database.db();
        let cf = db
            .cf_handle(&format!("entry_meta_{}db_{id}", if key { "key_" } else { "" }))
            .ok_or_else(|| error!("Missing package metadata"))?;
        let archive = self.archive(provider, key, id)?;
        if archive.sliced {
            let status = db
                .cf_handle(&format!("status_{}db_{id}", if key { "key_" } else { "" }))
                .ok_or_else(|| error!("Missing archive status"))?;
            let total = db
                .get_cf(&status, b"TotalSlices")?
                .ok_or_else(|| error!("Missing package count"))?;
            let total = u32::from_le_bytes(total.as_slice().try_into()?);
            for index in 0..total {
                let key_bytes = index.to_le_bytes();
                let value = db
                    .get_pinned_cf(&cf, key_bytes)?
                    .ok_or_else(|| error!("Missing package metadata index"))?;
                visit(self.member(self.archive(provider, key, id)?, &key_bytes, &value)?)?;
            }
        } else {
            let primary = u32::MAX.to_le_bytes();
            let imported = 0u32.to_le_bytes();
            let (key_bytes, value) = match db.get_cf(&cf, primary)? {
                Some(value) => (primary, value),
                None => match db.get_cf(&cf, imported)? {
                    Some(value) => (imported, value),
                    None => {
                        let status = db
                            .cf_handle(&format!("status_{}db_{id}", if key { "key_" } else { "" }))
                            .ok_or_else(|| error!("Missing nonsliced status"))?;
                        let size = db
                            .get_cf(&status, b"NonSlicedSize")?
                            .ok_or_else(|| error!("Missing nonsliced size"))?;
                        let size = u64::from_le_bytes(size.as_slice().try_into()?);
                        (primary, serde_cbor::to_vec(&PackageEntryMeta::with_data(size, 0, None))?)
                    }
                },
            };
            visit(self.member(archive, &key_bytes, &value)?)?;
        }
        Ok(())
    }

    fn decision(&self, member: &Member) -> Result<PackageDecision> {
        let mut decision = self.content_decision(member)?;
        // Legacy package filenames are derived from their metadata ordinal.
        // Keep empty interior slots so later retained packages keep that identity.
        if !decision.retained && member.archive.disposition == Disposition::Filter
            && member.archive.sliced && !member.archive.separated
        {
            self.members(member.archive.provider, member.archive.key, member.archive.id, |later| {
                if later.index > member.index && self.content_decision(&later)?.retained {
                    decision.retained = true;
                }
                Ok(())
            })?;
        }
        Ok(decision)
    }

    fn content_decision(&self, member: &Member) -> Result<PackageDecision> {
        let mut kept = 0u64;
        let mut removed = false;
        let mut total = 0u64;
        scan_package(&member.path, |entry, header, name, body| {
            let remove = match member.archive.disposition {
                Disposition::Keep => false,
                Disposition::Filter => self.selection.should_delete(block_id(&entry)?),
                Disposition::Drop => {
                    if !self.selection.should_delete(block_id(&entry)?) {
                        fail!("Tail archive contains retained block");
                    }
                    true
                }
            };
            let size = header.len() as u64 + name.len() as u64 + body.limit();
            total = total.checked_add(size).ok_or_else(|| error!("Package size overflow"))?;
            if remove {
                removed = true;
            } else {
                kept = kept.checked_add(size).ok_or_else(|| error!("Package size overflow"))?;
            }
            io::copy(body, &mut io::sink())?;
            Ok(())
        })?;
        if total != member.meta.entry_size() {
            fail!("Canonical package differs from committed metadata size");
        }
        Ok(PackageDecision {
            changed: removed,
            retained: member.archive.disposition != Disposition::Drop
                && (!member.archive.sliced || !removed || kept != 0),
            size: kept,
        })
    }
    /// Resolve every canonical package through its real metadata, rejecting
    /// ambiguous or orphan files rather than guessing an archive owner.
    fn package_member(&self, provider: usize, path: &Path) -> Result<Member> {
        let db = self.providers.participants[provider].database.db();
        let mut found = None;
        for name in rocksdb::DB::list_cf(&rocksdb::Options::default(), db.path())? {
            if let Some((key, id)) = metadata_family(&name)? {
                self.members(provider, key, id, |member| {
                    if member.path == path {
                        if found.is_some() {
                            fail!("Package has multiple metadata owners");
                        }
                        found = Some(member);
                    }
                    Ok(())
                })?;
            }
        }
        found.ok_or_else(|| error!("Canonical package has no metadata owner"))
    }
    fn stage_identity(&self, member: &Member) -> Result<[u8; 52]> {
        let mut bytes = [0; 52];
        bytes[..3].copy_from_slice(&[1, 0, 1]);
        bytes[3] = u8::from(member.archive.key);
        bytes[4..8].copy_from_slice(&member.info.seqno.to_le_bytes());
        bytes[8..12].copy_from_slice(&member.info.shard.workchain_id().to_le_bytes());
        bytes[12..20].copy_from_slice(&member.info.shard.shard_prefix_with_tag().to_le_bytes());
        bytes[20..].copy_from_slice(
            &self.providers.participants[member.archive.provider].descriptor.digest()?,
        );
        Ok(bytes)
    }
    fn write_stage(&self, member: &Member, path: &Path) -> Result<()> {
        let mut file = fs::File::options()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        let result = (|| {
            file.write_all(&super::package::PKG_HEADER_MAGIC.to_le_bytes())?;
            scan_package(&member.path, |entry, header, name, body| {
                if self.selection.should_delete(block_id(&entry)?) {
                    io::copy(body, &mut io::sink())?;
                } else {
                    file.write_all(header)?;
                    file.write_all(name)?;
                    io::copy(body, &mut file)?;
                }
                Ok(())
            })
        })();
        let closed = super::recovery_worker::sync_close(file);
        result?;
        closed
    }
    fn relocated(
        &self,
        member: &Member,
        old: u64,
        expected_key: Option<&[u8]>,
        block_only: bool,
    ) -> Result<Option<Option<u64>>> {
        let mut source = 0u64;
        let mut target = 0u64;
        let mut found = None;
        scan_package(&member.path, |entry, header, name, body| {
            let size = header.len() as u64 + name.len() as u64 + body.limit();
            let keep = !self.selection.should_delete(block_id(&entry)?);
            if source == old
                && expected_key.is_none_or(|key| PackageOffsetKey::from(&entry).key() == key)
                && (!block_only || matches!(&entry, PackageEntryId::Block(_)))
            {
                found = Some(keep.then_some(target));
            }
            source = source.checked_add(size).ok_or_else(|| error!("Package offset overflow"))?;
            if keep {
                target =
                    target.checked_add(size).ok_or_else(|| error!("Package offset overflow"))?;
            }
            io::copy(body, &mut io::sink())?;
            Ok(())
        })?;
        Ok(found)
    }
}
fn metadata_family(name: &str) -> Result<Option<(bool, u32)>> {
    let Some(tail) = name.strip_prefix("entry_meta_") else {
        return Ok(None);
    };
    let (key, id) = if let Some(id) = tail.strip_prefix("key_db_") {
        (true, id)
    } else if let Some(id) = tail.strip_prefix("db_") {
        (false, id)
    } else {
        fail!("Unrecognized entry metadata family");
    };
    Ok(Some((key, id.parse()?)))
}
fn block_id(entry: &PackageEntryId<BlockIdExt>) -> Result<&BlockIdExt> {
    match entry {
        PackageEntryId::Block(id) | PackageEntryId::Proof(id) | PackageEntryId::ProofLink(id) => {
            Ok(id)
        }
        _ => fail!("Unsupported archive entry during truncation"),
    }
}

/// Stream bodies with a fixed-size copy buffer; even very large blocks are
/// never materialized in memory while constructing a replacement package.
fn scan_package(
    path: &Path,
    mut visit: impl FnMut(
        PackageEntryId<BlockIdExt>,
        &[u8; 8],
        &[u8],
        &mut io::Take<&mut fs::File>,
    ) -> Result<()>,
) -> Result<()> {
    let before = fs::symlink_metadata(path)?;
    if !before.is_file() || before.file_type().is_symlink() {
        fail!("Invalid package input type");
    }
    let mut file = fs::File::options().read(true).custom_flags(libc::O_NOFOLLOW).open(path)?;
    let outcome = (|| {
        let mut magic = [0; 4];
        file.read_exact(&mut magic)?;
        if u32::from_le_bytes(magic) != super::package::PKG_HEADER_MAGIC {
            fail!("Invalid package header");
        }
        loop {
            let mut header = [0; 8];
            match file.read(&mut header[..1]) {
                Ok(0) => break,
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
            file.read_exact(&mut header[1..])?;
            if u16::from_le_bytes(header[..2].try_into()?) != 0x1E8B {
                fail!("Invalid package entry header");
            }
            let mut name = vec![0; u16::from_le_bytes(header[2..4].try_into()?) as usize];
            file.read_exact(&mut name)?;
            let entry = PackageEntryId::from_filename(std::str::from_utf8(&name)?)?;
            let mut body = (&mut file).take(u64::from(u32::from_le_bytes(header[4..].try_into()?)));
            visit(entry, &header, &name, &mut body)?;
            if body.limit() != 0 {
                fail!("Truncated or unconsumed package body");
            }
        }
        use std::os::unix::fs::MetadataExt;
        let unchanged = |after: fs::Metadata| {
            after.dev() == before.dev()
                && after.ino() == before.ino()
                && after.len() == before.len()
                && after.mtime() == before.mtime()
                && after.mtime_nsec() == before.mtime_nsec()
                && after.ctime() == before.ctime()
                && after.ctime_nsec() == before.ctime_nsec()
        };
        if !unchanged(file.metadata()?) || !unchanged(fs::symlink_metadata(path)?) {
            fail!("Package changed during truncation planning");
        }
        Ok(())
    })();
    let fd = file.into_raw_fd();
    if unsafe { libc::close(fd) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    outcome
}

impl Plan<'_> {
    fn row(
        &self,
        archive: &Archive,
        kind: &str,
        key: &[u8],
        old: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        if archive.disposition == Disposition::Drop {
            return Ok(None);
        }
        if archive.disposition == Disposition::Keep {
            return Ok(Some(old.to_vec()));
        }
        match kind {
            "offsets" => {
                let offset: u64 = serde_cbor::from_slice(old)?;
                let mut answer = None;
                self.members(archive.provider, archive.key, archive.id, |member| {
                    if let Some(new) = self.relocated(&member, offset, Some(key), false)? {
                        if answer.is_some() {
                            fail!("Offset row has multiple source entries");
                        }
                        answer = Some(new.map(|offset| serde_cbor::to_vec(&offset)).transpose()?);
                    }
                    Ok(())
                })?;
                answer.ok_or_else(|| error!("Offset metadata does not identify a package entry"))
            }
            "entry_meta" => {
                if archive.sliced && archive.separated {
                    // Separated packages carry their physical identity in the
                    // value, so project retained members onto dense ordinals.
                    let target = u32::from_le_bytes(key.try_into()?);
                    let mut ordinal = 0u32;
                    let mut projected = None;
                    self.members(archive.provider, archive.key, archive.id, |member| {
                        let decision = self.decision(&member)?;
                        if decision.retained {
                            if ordinal == target {
                                projected = Some(serde_cbor::to_vec(&PackageEntryMeta::with_data(
                                    decision.size, member.meta.version(), Some(&member.info),
                                ))?);
                            }
                            ordinal = ordinal.checked_add(1)
                                .ok_or_else(|| error!("Package count overflow"))?;
                        }
                        Ok(())
                    })?;
                    return Ok(projected);
                }
                if !archive.sliced && key == 0u32.to_le_bytes() {
                    let db = self.providers.participants[archive.provider].database.db();
                    let cf = db
                        .cf_handle(&format!(
                            "entry_meta_{}db_{}",
                            if archive.key { "key_" } else { "" },
                            archive.id
                        ))
                        .ok_or_else(|| error!("Missing entry metadata"))?;
                    if db.get_pinned_cf(&cf, u32::MAX.to_le_bytes())?.is_some() {
                        return Ok(None);
                    }
                }
                let member = self.member(
                    self.archive(archive.provider, archive.key, archive.id)?,
                    key,
                    old,
                )?;
                let decision = self.decision(&member)?;
                if !decision.retained {
                    return Ok(None);
                }
                let info = member.meta.get_info()?;
                Ok(Some(serde_cbor::to_vec(&PackageEntryMeta::with_data(
                    decision.size,
                    member.meta.version(),
                    info.as_ref(),
                ))?))
            }
            "status" if key == b"TotalSlices" => {
                let mut count = 0u32;
                self.members(archive.provider, archive.key, archive.id, |member| {
                    if self.decision(&member)?.retained {
                        count =
                            count.checked_add(1).ok_or_else(|| error!("Package count overflow"))?;
                    }
                    Ok(())
                })?;
                Ok(Some(count.to_le_bytes().to_vec()))
            }
            "status" if key == b"NonSlicedSize" => {
                let mut size = None;
                self.members(archive.provider, archive.key, archive.id, |member| {
                    if size.is_some() {
                        fail!("Multiple nonsliced packages");
                    }
                    size = Some(self.decision(&member)?.size);
                    Ok(())
                })?;
                Ok(Some(
                    size.ok_or_else(|| error!("Missing nonsliced package"))?.to_le_bytes().to_vec(),
                ))
            }
            "status" => Ok(Some(old.to_vec())),
            "block_index" => {
                use super::block_index_db::BlocksIndexKey;
                if old.len() != 8 {
                    fail!("Invalid native block index row");
                }
                let offset = u32::from_le_bytes(old[..4].try_into()?);
                let mc_ref = u32::from_le_bytes(old[4..].try_into()?);
                let shard = match BlocksIndexKey::parse_bytes(key)? {
                    BlocksIndexKey::Seqno { shard, .. }
                    | BlocksIndexKey::Lt { shard, .. }
                    | BlocksIndexKey::Utime { shard, .. } => shard,
                };
                let info = if !archive.sliced || archive.key {
                    PackageEntryInfo { seqno: archive.id, shard: ShardIdent::masterchain() }
                } else {
                    let delta = mc_ref
                        .checked_sub(archive.id)
                        .ok_or_else(|| error!("Block index precedes archive"))?;
                    PackageEntryInfo {
                        seqno: mc_ref - delta % archive.slice_size,
                        shard: if !archive.separated || shard.is_masterchain() {
                            ShardIdent::masterchain()
                        } else {
                            shard.relative_with_len(archive.depth)?
                        },
                    }
                };
                let mut answer = None;
                self.members(archive.provider, archive.key, archive.id, |member| {
                    if member.info == info {
                        if answer.is_some() {
                            fail!("Block index has ambiguous package identity");
                        }
                        answer = self.relocated(&member, u64::from(offset), None, true)?;
                    }
                    Ok(())
                })?;
                answer
                    .ok_or_else(|| error!("Block index does not identify a source block"))?
                    .map(|offset| {
                        let mut value = u32::try_from(offset)?.to_le_bytes().to_vec();
                        value.extend_from_slice(&old[4..]);
                        Ok(value)
                    })
                    .transpose()
            }
            _ => fail!("Unknown archive metadata kind"),
        }
    }
    fn families(
        &self,
        provider: usize,
        mut visit: impl FnMut(&str, Archive, &str) -> Result<()>,
    ) -> Result<()> {
        let db = self.providers.participants[provider].database.db();
        let mut names = rocksdb::DB::list_cf(&rocksdb::Options::default(), db.path())?;
        names.sort();
        for name in &names {
            for kind in ["block_index", "entry_meta", "offsets", "status"] {
                if let Some(tail) = name.strip_prefix(&format!("{kind}_")) {
                    let (key, id) = if let Some(id) = tail.strip_prefix("key_db_") {
                        (true, id.parse()?)
                    } else if let Some(id) = tail.strip_prefix("db_") {
                        (false, id.parse()?)
                    } else {
                        fail!("Unknown archive family");
                    };
                    visit(name, self.archive(provider, key, id)?, kind)?;
                }
            }
        }
        Ok(())
    }
    fn rows(
        &self,
        name: &str,
        archive: &Archive,
        kind: &str,
        mut visit: impl FnMut(&[u8], &[u8], Option<&[u8]>) -> Result<()>,
    ) -> Result<()> {
        let db = self.providers.participants[archive.provider].database.db();
        let cf =
            db.cf_handle(name).ok_or_else(|| error!("Missing archive family during planning"))?;
        let mut rows = db.raw_iterator_cf(&cf);
        rows.seek_to_first();
        while rows.valid() {
            let key = rows.key().ok_or_else(|| error!("Missing archive row key"))?;
            let old = rows.value().ok_or_else(|| error!("Missing archive row value"))?;
            // Same bound as the replay decoder, checked before any allocation.
            if key.len() > 65536 || old.len() > super::recovery_parent::BATCH_LIMIT / 4 {
                fail!("Archive row exceeds recovery budget");
            }
            let new = self.row(archive, kind, key, old)?;
            visit(key, old, new.as_deref())?;
            rows.next();
        }
        rows.status()?;
        Ok(())
    }
    fn packages(
        &self,
        provider: usize,
        mut visit: impl FnMut(Member, PackageDecision) -> Result<()>,
    ) -> Result<()> {
        let base = self.providers.participants[provider].archive_root.as_path();
        let packages = base.join("archive/packages");
        if !super::recovery_artifacts::directory(&packages)? {
            return Ok(());
        }
        super::recovery_data::sorted_entries(&packages, |bucket| {
            if !super::recovery_artifacts::directory(&bucket)? {
                fail!("Missing package bucket");
            }
            super::recovery_data::sorted_entries(&bucket, |path| {
                let member = self.package_member(provider, &path)?;
                let decision = self.decision(&member)?;
                visit(member, decision)
            })
        })
    }
}

pub(super) fn has_ready_intent(
    providers: &RecoveryProviders,
    root: &super::recovery_root::RootHeader,
) -> Result<bool> {
    let main = providers
        .participants
        .iter()
        .position(|p| p.descriptor.anchor == super::recovery_participant::Anchor::Node)
        .ok_or_else(|| error!("Missing selection provider"))?;
    let path = super::recovery_stages::operation(providers, root, main)?.join("selection.v1");
    let mut found = false;
    super::recovery_artifacts::read_sidecar(
        &path,
        super::recovery_manifest::Kind::Selection,
        root,
        root.selection,
        |tag, length, input| {
            if tag == super::recovery_manifest::Record::ReadyIntent {
                let mut version = [0; 2];
                if found || length != 2 {
                    fail!("Invalid or duplicate Ready staging intent");
                }
                input.read_exact(&mut version)?;
                if version != [1, 0] {
                    fail!("Unknown Ready staging intent version");
                }
                found = true;
            } else {
                io::copy(input, &mut io::sink())?;
            }
            Ok(())
        },
    )?;
    Ok(found)
}

impl Plan<'_> {
    fn selected_stages(&self, mut visit: impl FnMut([u8; 52]) -> Result<()>) -> Result<()> {
        // The Selection schema orders by stage identity. Bounded selection of
        // the next 512 hashes avoids retaining a package-sized inventory.
        for provider in 0..self.providers.participants.len() {
            let mut last = None;
            loop {
                let mut next = std::collections::BinaryHeap::new();
                self.packages(provider, |member, decision| {
                    if decision.changed && decision.retained {
                        let identity = self.stage_identity(&member)?;
                        let hash = rtos_block::sha256_digest(identity);
                        if last.is_none_or(|last| hash > last) {
                            next.push((hash, identity));
                            if next.len() > 512 {
                                next.pop();
                            }
                        }
                    }
                    Ok(())
                })?;
                if next.is_empty() {
                    break;
                }
                for (hash, identity) in next.into_sorted_vec() {
                    visit(identity)?;
                    last = Some(hash);
                }
            }
        }
        Ok(())
    }
    fn parents(
        &self,
        mut visit: impl FnMut(super::recovery_parent::Key, &[u8], Disposition) -> Result<()>,
    ) -> Result<()> {
        let db = self.main()?.db();
        for map in [Map::Files, Map::KeyFiles] {
            let boundary = self.boundary(map == Map::KeyFiles)?;
            let cf = db.cf_handle(map.name()).ok_or_else(|| error!("Missing parent map"))?;
            let mut rows = db.raw_iterator_cf(&cf);
            rows.seek_to_first();
            while rows.valid() {
                let bytes: [u8; 4] =
                    rows.key().ok_or_else(|| error!("Missing parent key"))?.try_into()?;
                let id = u32::from_le_bytes(bytes);
                let disposition = match boundary {
                    Some(boundary) if id > boundary => Disposition::Drop,
                    Some(boundary) if id == boundary => Disposition::Filter,
                    _ => Disposition::Keep,
                };
                visit(
                    super::recovery_parent::Key { map, bytes },
                    rows.value().ok_or_else(|| error!("Missing parent value"))?,
                    disposition,
                )?;
                rows.next();
            }
            rows.status()?;
        }
        Ok(())
    }
    /// Produce durable Selection/Building and complete Ready before touching
    /// canonical packages or native archive metadata. The executor owns IO and
    /// retains the provider set across this synchronous phase.
    pub(super) fn produce(
        &self,
        policy: super::recovery_root::Policy,
    ) -> Result<super::recovery_root::RootHeader> {
        use super::{
            recovery_manifest::{Kind, ManifestWriter, Record},
            recovery_parent::{self, InventoryRole},
            recovery_participant::{Anchor, Backlink, Identity},
            recovery_root::{Inventory, RootHeader, Sidecar, State, PARTICIPANT_KEY, ROOT_KEY},
        };
        for participant in &self.providers.participants {
            let base = participant.archive_root.as_path();
            super::recovery_guard::ensure_open_provider_clear(participant.database.db(), base)?;
        }
        let original_data = super::recovery_data::inventory(self.providers)?;
        let original_maps = recovery_parent::native_inventory(self.main()?.db())?;
        let native = self.main()?.db().get_db_identity()?;
        let mut root = RootHeader {
            state: State::Preparing,
            policy,
            aborted: false,
            operation: rand::random(),
            database_identity_bytes: native.len() as u64,
            database_identity_digest: rtos_block::sha256_digest(native),
            selection: Sidecar::default(),
            ready: Sidecar::default(),
            providers: self.providers.inventory()?,
            maps: original_maps,
            data: original_data,
        };
        let main = self
            .providers
            .participants
            .iter()
            .position(|p| p.descriptor.anchor == Anchor::Node)
            .ok_or_else(|| error!("Missing main provider"))?;
        self.main()?.db().put(ROOT_KEY, root.encode()?)?;
        self.main()?.sync_wal()?; // Preparing durable before creating any artifacts.
        let preparing = root.clone();
        for index in 0..self.providers.participants.len() {
            let operation = super::recovery_stages::operation(self.providers, &root, index)?;
            fs::create_dir_all(
                operation.parent().ok_or_else(|| error!("Missing recovery parent"))?,
            )?;
            fs::create_dir(&operation)?;
        }
        let operation = super::recovery_stages::operation(self.providers, &root, main)?;
        let mut writer = ManifestWriter::new(
            create_control(&operation.join("selection.v1"))?,
            Kind::Selection,
            root.operation,
        )?;
        writer.record_with(Record::Predicate, self.selection.encoded_len()?, |out| {
            self.selection.write_predicate(out)
        })?;
        for participant in &self.providers.participants {
            writer.record_with(Record::Provider, participant.descriptor.encoded_len()?, |out| {
                participant.descriptor.write(out)
            })?;
        }
        recovery_parent::write_inventory(&mut writer, InventoryRole::Original, original_maps)?;
        writer.record_with(Record::ArchiveInventory, 43, |out| {
            out.write_all(&[1, 0, policy as u8])?;
            out.write_all(&original_data.count.to_le_bytes())?;
            out.write_all(&original_data.digest)?;
            Ok(())
        })?;
        writer.record(Record::ReadyIntent, 2, &mut &[1u8, 0][..])?;
        self.selected_stages(|identity| writer.record(Record::Child, 52, &mut &identity[..]))?;
        let (file, selection) = writer.finish()?;
        super::recovery_worker::sync_close(file)?;
        root.selection = selection;
        root.state = State::Building;
        root.providers = Inventory::default();
        root.maps = Inventory::default();
        root.data = Inventory::default();
        self.sync_operation_directories(&root)?;
        if super::recovery_data::inventory(self.providers)? != preparing.data
            || recovery_parent::native_inventory(self.main()?.db())? != preparing.maps
            || self.providers.inventory()? != preparing.providers {
            fail!("Canonical archive changed during Selection construction");
        }
        preparing.check_successor(&root)?;
        self.main()?.db().put(ROOT_KEY, root.encode()?)?;
        self.main()?.sync_wal()?;
        for participant in &self.providers.participants {
            let backlink = Backlink {
                operation: root.operation,
                main: Identity {
                    bytes: root.database_identity_bytes,
                    digest: root.database_identity_digest,
                },
                selection: root.selection.digest,
                provider: participant.descriptor.digest()?,
            };
            participant.database.db().put(PARTICIPANT_KEY, backlink.encode()?)?;
            participant.database.sync_wal()?;
        }
        for provider in 0..self.providers.participants.len() {
            self.packages(provider, |member, decision| {
                if decision.changed && decision.retained {
                    let identity = self.stage_identity(&member)?;
                    let stage = super::recovery_stages::Stage::decode(
                        self.providers,
                        &mut &identity[..],
                        52,
                    )?;
                    self.write_stage(&member, &stage.path(self.providers, &root)?)?;
                }
                Ok(())
            })?;
        }
        let reset = recovery_parent::ResetValue::capture()?;
        let reset_bytes = serde_cbor::to_vec(&super::package_index_db::PackageIndexEntry::new())?;
        let mut final_maps = recovery_parent::MapInventory::new();
        self.parents(|key, old, disposition| {
            match disposition {
                Disposition::Keep => final_maps.row(key, old)?,
                Disposition::Filter => final_maps.row(key, &reset_bytes)?,
                Disposition::Drop => {}
            }
            Ok(())
        })?;
        let mut writer = ManifestWriter::new(
            create_control(&operation.join("ready.v1"))?,
            Kind::Ready,
            root.operation,
        )?;
        writer.record(Record::SelectionDigest, 32, &mut &root.selection.digest[..])?;
        for participant in &self.providers.participants {
            writer.record_with(Record::Provider, participant.descriptor.encoded_len()?, |out| {
                participant.descriptor.write(out)
            })?;
        }
        recovery_parent::write_inventory(&mut writer, InventoryRole::Final, final_maps.finish())?;
        for provider in 0..self.providers.participants.len() {
            self.families(provider, |name, archive, kind| {
                let mut length = 50u64;
                let mut count = 0u64;
                self.rows(name, &archive, kind, |key, old, new| {
                    let size = 4
                        + key.len() as u64
                        + 1
                        + 4
                        + old.len() as u64
                        + 1
                        + new.map_or(0, |value| 4 + value.len() as u64);
                    length = length
                        .checked_add(size)
                        .ok_or_else(|| error!("Ready table size overflow"))?;
                    count =
                        count.checked_add(1).ok_or_else(|| error!("Ready row count overflow"))?;
                    Ok(())
                })?;
                writer.record_with(Record::Child, length, |out| {
                    out.write_all(&[1, 0, 1, u8::from(archive.key)])?;
                    out.write_all(&archive.id.to_le_bytes())?;
                    let tag = ["block_index", "entry_meta", "offsets", "status"]
                        .iter()
                        .position(|value| *value == kind)
                        .ok_or_else(|| error!("Unknown child table"))?;
                    out.write_all(&[tag as u8])?;
                    out.write_all(&self.providers.participants[provider].descriptor.digest()?)?;
                    out.write_all(&[u8::from(archive.disposition != Disposition::Drop)])?;
                    out.write_all(&count.to_le_bytes())?;
                    self.rows(name, &archive, kind, |key, old, new| {
                        write_blob(out, key)?;
                        out.write_all(&[1])?;
                        write_blob(out, old)?;
                        out.write_all(&[u8::from(new.is_some())])?;
                        if let Some(new) = new {
                            write_blob(out, new)?;
                        }
                        Ok(())
                    })
                })
            })?;
            self.packages(provider, |member, decision| {
                let identity = self.stage_identity(&member)?;
                let old = super::recovery_data::file_digest(&member.path)?;
                let new = if !decision.retained {
                    None
                } else if decision.changed {
                    let stage = super::recovery_stages::Stage::decode(
                        self.providers,
                        &mut &identity[..],
                        52,
                    )?;
                    Some(super::recovery_data::file_digest(&stage.path(self.providers, &root)?)?)
                } else {
                    Some(old)
                };
                writer.record_with(Record::Child, 96 + if new.is_some() { 40 } else { 0 }, |out| {
                    out.write_all(&[1, 0, 2])?;
                    out.write_all(&identity)?;
                    out.write_all(&old.0.to_le_bytes())?;
                    out.write_all(&old.1)?;
                    out.write_all(&[u8::from(new.is_some())])?;
                    if let Some((size, hash)) = new {
                        out.write_all(&size.to_le_bytes())?;
                        out.write_all(&hash)?;
                    }
                    Ok(())
                })
            })?;
        }
        self.parents(|key, old, disposition| match disposition {
            Disposition::Keep => Ok(()),
            Disposition::Filter => {
                recovery_parent::write_command(&mut writer, key, old, Some(&reset))
            }
            Disposition::Drop => recovery_parent::write_command(&mut writer, key, old, None),
        })?;
        let (file, ready) = writer.finish()?;
        super::recovery_worker::sync_close(file)?;
        self.sync_operation_directories(&root)?;
        if super::recovery_data::inventory(self.providers)? != original_data
            || recovery_parent::native_inventory(self.main()?.db())? != original_maps
        {
            fail!("Canonical archive changed while constructing recovery manifests");
        }
        let mut next = root.clone();
        next.state = State::Ready;
        next.ready = ready;
        root.check_successor(&next)?;
        self.main()?.db().put(ROOT_KEY, next.encode()?)?;
        self.main()?.sync_wal()?;
        super::recovery_forward::validate(self.providers, &next)?;
        Ok(next)
    }
    fn sync_operation_directories(&self, root: &super::recovery_root::RootHeader) -> Result<()> {
        for provider in 0..self.providers.participants.len() {
            super::recovery_forward::sync_directory_path(&super::recovery_stages::operation(
                self.providers,
                root,
                provider,
            )?)?;
        }
        Ok(())
    }
}
fn create_control(path: &Path) -> Result<fs::File> {
    Ok(fs::File::options()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?)
}
fn write_blob(out: &mut dyn Write, bytes: &[u8]) -> Result<()> {
    out.write_all(&u32::try_from(bytes.len())?.to_le_bytes())?;
    out.write_all(bytes)?;
    Ok(())
}

#[cfg(test)]
#[path = "../tests/test_recovery_producer_indices.rs"]
mod index_tests;
