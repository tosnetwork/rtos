/*
 * RTOS project modifications (2026-10-10): project and crate naming.
 * Copyright (C) 2019-2024 EverX. All Rights Reserved.
 * Modifications Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This file has been modified from its original version.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::{db::DbKey, error::StorageError};
use rtos_block::{error, Error, Result};
use std::{
    io::{ErrorKind, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

static FILE_WRITE_ATTEMPT: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub struct FileDb {
    path: PathBuf,
}

static PATH_CHUNK_MAX_LEN: usize = 4;
static PATH_MAX_DEPTH: usize = 2;

impl FileDb {
    pub fn with_path<P: AsRef<Path>>(path: P) -> Self {
        Self { path: path.as_ref().to_path_buf() }
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    pub async fn destroy(&mut self) -> Result<bool> {
        match tokio::fs::metadata(&self.path).await {
            Ok(meta) if meta.is_dir() => tokio::fs::remove_dir_all(&self.path).await?,
            _ => (),
        }
        Ok(true)
    }

    pub fn get_write_object(&self, key: &(dyn DbKey + Send + Sync)) -> Result<impl Write + Seek> {
        let path = self.make_path(key.key(), true);
        let dir = path.parent().ok_or_else(|| error!("Unable to get parent path"))?;
        std::fs::create_dir_all(dir)?;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(false)
            .truncate(true)
            .open(path)?;
        Ok(file)
    }

    pub fn finalize_write_object(&self, key: &(dyn DbKey + Send + Sync)) -> Result<()> {
        let tmp_path = self.make_path(key.key(), true);
        let final_path = self.make_path(key.key(), false);
        // A successful publication must survive loss of the filesystem cache.
        // Keep the old final path intact until the new contents are durable.
        std::fs::OpenOptions::new().read(true).write(true).open(&tmp_path)?.sync_all()?;
        std::fs::rename(&tmp_path, &final_path)?;
        crate::archives::package::sync_file_and_parents_native(&final_path, None)
    }

    pub fn cleanup_tmp(&self) -> Result<()> {
        Self::cleanup_worker(&self.path)
    }

    pub fn get_read_object(&self, key: &(dyn DbKey + Send + Sync)) -> Result<impl Read + Seek> {
        let path = self.make_path(key.key(), false);
        let file = std::fs::File::open(path)?;
        Ok(file)
    }

    pub async fn write_whole_file(
        &self,
        key: &(dyn DbKey + Send + Sync),
        data: &[u8],
    ) -> Result<()> {
        let path = self.make_path(key.key(), false);
        let dir = path.parent().ok_or_else(|| error!("Unable to get parent path"))?;
        tokio::fs::create_dir_all(dir).await?;
        // Unique, same-directory temporary files keep failed or concurrent
        // writes from truncating an acknowledged final file.
        let mut selected = None;
        for _ in 0..16 {
            let attempt = FILE_WRITE_ATTEMPT
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_add(1))
                .map_err(|_| error!("File write attempt counter exhausted"))?;
            let mut temporary = path.clone();
            temporary.set_extension(format!("{}.{attempt}.tmp", std::process::id()));
            match tokio::fs::OpenOptions::new().write(true).create_new(true).open(&temporary).await
            {
                Ok(file) => {
                    selected = Some((temporary, file));
                    break;
                }
                Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        let (temporary, mut file) =
            selected.ok_or_else(|| error!("File temporary collision limit reached"))?;
        let result: Result<()> = async {
            file.write_all(data).await?;
            // Drain Tokio buffered IO and propagate the actual write error
            // before syncing or publishing the file.
            file.flush().await?;
            file.sync_all().await?;
            tokio::fs::rename(&temporary, &path).await?;
            crate::archives::package::sync_file_and_parents(&path).await?;
            Ok(())
        }
        .await;
        drop(file);
        if result.is_err() {
            // A rename may have completed. Only our temporary is disposable;
            // never remove or roll back the final path on an uncertain sync.
            let _ = tokio::fs::remove_file(&temporary).await;
        }
        result
    }

    pub async fn read_whole_file(&self, key: &(dyn DbKey + Send + Sync)) -> Result<Vec<u8>> {
        self.read_file_part(key, 0, self.get_file_size(key).await?).await
    }

    pub async fn read_whole_file_to(
        &self,
        key: &(dyn DbKey + Send + Sync),
        buf: &mut Vec<u8>,
    ) -> Result<()> {
        let path = self.make_path(key.key(), false);
        let mut file = tokio::fs::File::open(path)
            .await
            .map_err(|err| Self::transform_io_error(err, key.key()))?;
        file.read_to_end(buf).await.map_err(|err| Self::transform_io_error(err, key.key()))?;
        Ok(())
    }

    pub async fn read_file_part(
        &self,
        key: &(dyn DbKey + Send + Sync),
        offset: u64,
        size: u64,
    ) -> Result<Vec<u8>> {
        let path = self.make_path(key.key(), false);
        let mut file = tokio::fs::File::open(path)
            .await
            .map_err(|err| Self::transform_io_error(err, key.key()))?;
        file.seek(SeekFrom::Start(offset)).await?;
        let mut result = vec![0; size as usize];
        file.read_exact(&mut result)
            .await
            .map_err(|err| Self::transform_io_error(err, key.key()))?;

        Ok(result)
    }

    pub async fn get_file_size(&self, key: &(dyn DbKey + Send + Sync)) -> Result<u64> {
        let path = self.make_path(key.key(), false);
        let metadata = tokio::fs::metadata(path)
            .await
            .map_err(|err| Self::transform_io_error(err, key.key()))?;

        Ok(metadata.len())
    }

    pub async fn contains(&self, key: &(dyn DbKey + Send + Sync)) -> Result<bool> {
        let path = self.make_path(key.key(), false);
        Ok(path.is_file() && path.exists())
    }

    pub fn for_each_key(&self, predicate: &mut dyn FnMut(&[u8]) -> Result<bool>) -> Result<bool> {
        Self::for_each_key_worker(&self.path, &[], 1, predicate)
    }

    pub async fn delete_file(&self, key: &(dyn DbKey + Send + Sync)) -> Result<()> {
        let path = self.make_path(key.key(), false);
        if let Err(err) = tokio::fs::remove_file(&path).await {
            if err.kind() != ErrorKind::NotFound {
                return Err(err.into());
            }
        }

        // Cleanup upper-level empty directories
        let mut dir = path.as_path();
        loop {
            dir = dir.parent().ok_or_else(|| error!("Unable to get parent path"))?;
            if self.path().starts_with(dir) || !Self::is_dir_empty(&dir).await {
                break;
            } else {
                let _ = tokio::fs::remove_dir(&dir).await; // If can't remove empty dir, do nothing.
            }
        }

        Ok(())
    }

    pub(crate) fn make_path(&self, key: &[u8], tmp: bool) -> PathBuf {
        let mut key_str = hex::encode(key);
        let mut result = self.path.clone();
        let mut depth = 1;
        while depth < PATH_MAX_DEPTH && !key_str.is_empty() {
            let remaining = key_str.split_off(std::cmp::min(key_str.len(), PATH_CHUNK_MAX_LEN));
            result = result.join(key_str);
            key_str = remaining;
            depth += 1;
        }
        if !key_str.is_empty() {
            result = result.join(key_str);
        }
        if tmp {
            result.set_extension("tmp");
        }
        result
    }

    fn transform_io_error(err: std::io::Error, key: &[u8]) -> Error {
        match err.kind() {
            ErrorKind::NotFound => StorageError::KeyNotFound("&[u8]", hex::encode(key)).into(),
            ErrorKind::UnexpectedEof => StorageError::OutOfRange.into(),
            _ => err.into(),
        }
    }

    async fn is_dir_empty<P: AsRef<Path>>(path: P) -> bool {
        if let Ok(mut read_dir) = tokio::fs::read_dir(path).await {
            if let Ok(val) = read_dir.next_entry().await {
                return val.is_none();
            }
        }
        false
    }

    fn for_each_key_worker<P: AsRef<Path>>(
        path: P,
        key: &[u8],
        depth: usize,
        predicate: &mut dyn FnMut(&[u8]) -> Result<bool>,
    ) -> Result<bool> {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let file_name = entry.file_name();
            let file_name = file_name.to_str().ok_or_else(|| error!("Can't decode filename"))?;
            let mut key = key.to_vec();
            if !file_name.contains(".tmp") {
                key.append(&mut hex::decode(file_name)?);
                let result = if depth == PATH_MAX_DEPTH {
                    predicate(&key)?
                } else {
                    Self::for_each_key_worker(entry.path(), &key, depth + 1, predicate)?
                };
                if !result {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    fn cleanup_worker<P: AsRef<Path>>(path: P) -> Result<()> {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let file_name = entry.file_name();
            let file_name = file_name.to_str().ok_or_else(|| error!("Can't decode filename"))?;
            if file_name.contains(".tmp") {
                std::fs::remove_file(entry.path())?;
            } else if entry.path().is_dir() {
                Self::cleanup_worker(entry.path())?;
            }
        }
        Ok(())
    }
}
