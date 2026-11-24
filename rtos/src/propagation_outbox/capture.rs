// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Optional isolated-test capture after successful live acceptance.
//! Schema-5 is an export envelope, not a persisted outbox row or queue receipt.
//! Consumers independently authenticate carriers and the complete original frontier.
#[cfg(feature = "interop-publication-capture")]
use std::sync::{Mutex, OnceLock};
use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::Path,
};

const MAX_FILES: usize = 128;
const MAX_TOTAL: usize = 64 << 20;
const MAX_ROW: usize = 16 << 20;

#[derive(Default)]
struct Budget {
    seen: HashSet<String>,
    bytes: usize,
}

// Explicit test feature only; no error propagates into acceptance or persistence.
#[cfg(feature = "interop-publication-capture")]
pub(crate) fn observe_live(
    record: std::sync::Arc<super::PublicationRecord>,
    limits: &super::Limits,
) {
    static BUDGET: OnceLock<Mutex<Budget>> = OnceLock::new();
    let Some(directory) = std::env::var_os("RTOS_TEST_PUBLICATION_CAPTURE") else { return };
    let directory = Path::new(&directory);
    if directory.join("failed").exists() || !directory.join("selector").exists() {
        return;
    }
    let result = (|| {
        let mut budget = BUDGET
            .get_or_init(Default::default)
            .lock()
            .map_err(|_| io::Error::other("publication capture lock poisoned"))?;
        // ID 1 is only a schema envelope field; no outbox record is created.
        let entry = super::UnverifiedRecord {
            id: super::RecordId(1),
            stage: super::PublicationStage::DraftDurable,
            record,
            pending: Vec::new(),
        };
        let digest = super::domain_digest(&entry.record.domain).map_err(io::Error::other)?;
        let row = super::encode_body(&digest, &entry, limits).map_err(io::Error::other)?;
        capture(
            directory,
            std::process::id(),
            &[("LiveAcceptance/b/0000000000000001".into(), row)],
            &mut budget,
        )
    })();
    if let Err(error) = result {
        if let Ok(mut file) =
            OpenOptions::new().write(true).create_new(true).open(directory.join("failed"))
        {
            let _ = writeln!(file, "{error}");
        }
    }
}

fn read_selector(
    directory: &Path,
    open: impl FnOnce(&Path) -> io::Result<fs::File>,
) -> io::Result<Option<String>> {
    let selector = directory.join("selector");
    if fs::symlink_metadata(directory)?.file_type().is_symlink() {
        return Err(io::Error::other("capture requires an owned directory"));
    }
    let metadata = match fs::symlink_metadata(&selector) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() {
        return Err(io::Error::other("capture requires an owned selector"));
    }
    // The controller may disarm after metadata inspection. An already opened
    // selector can finish this bounded observation; an absent selector is idle.
    let file = match open(&selector) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut raw = String::new();
    file.take(129).read_to_string(&mut raw)?;
    Ok(Some(raw))
}

fn capture(
    directory: &Path,
    pid: u32,
    puts: &[(String, Vec<u8>)],
    budget: &mut Budget,
) -> io::Result<()> {
    let Some(raw) = read_selector(directory, |path| fs::File::open(path))? else {
        return Ok(());
    };
    if raw.len() > 128 {
        return Err(io::Error::other("capture selector exceeds bound"));
    }
    let fields: Vec<_> = raw.lines().collect();
    if fields.len() != 2 || fields[0].parse::<u32>().ok() != Some(pid) {
        return Ok(());
    }
    let session = hex::decode(fields[1]).map_err(io::Error::other)?;
    if session.len() != 32 {
        return Err(io::Error::other("capture requires an exact WC session"));
    }
    for (key, row) in puts {
        if !key.starts_with("LiveAcceptance/b/") {
            continue;
        }
        // Schema 5: magic(8), schema(2), domain(32), id(8), protocol(1),
        // profile(32), session(32), workchain(4), remainder and checksum.
        if row.len() < 119 || &row[..8] != b"RTOSPBXB" || row[8..10] != 5u16.to_le_bytes() {
            return Err(io::Error::other("unsupported publication body schema"));
        }
        if row[83..115] != session || row[115..119] != 0i32.to_le_bytes() {
            continue;
        }
        let digest = rtos_block::UInt256::calc_file_hash(row).to_hex_string();
        if budget.seen.contains(&digest) {
            continue;
        }
        if budget.seen.len() >= MAX_FILES
            || row.len() > MAX_ROW
            || row.len() > MAX_TOTAL - budget.bytes
        {
            return Err(io::Error::other("publication capture budget exhausted"));
        }
        let temporary = directory.join(format!("{digest}.tmp"));
        let destination = directory.join(format!("{digest}.bin"));
        if destination.exists() {
            return Err(io::Error::other("capture destination already exists"));
        }
        let mut file = OpenOptions::new().write(true).create_new(true).open(&temporary)?;
        file.write_all(row)?;
        file.sync_all()?;
        fs::rename(&temporary, destination)?;
        let receipt = serde_json::json!({
            "pid":pid, "session":fields[1], "key":key, "sha256":digest,
            "bytes":row.len(), "after_live_acceptance":true,
            "scope":"Live WC acceptance export; synthetic envelope ID, not an outbox receipt or independent finality proof"
        });
        let receipt_path = directory.join(format!("{digest}.json"));
        let mut file = OpenOptions::new().write(true).create_new(true).open(receipt_path)?;
        file.write_all(serde_json::to_string_pretty(&receipt)?.as_bytes())?;
        file.sync_all()?;
        fs::File::open(directory)?.sync_all()?;
        budget.bytes += row.len();
        budget.seen.insert(digest);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> (String, Vec<u8>) {
        let mut row = vec![0; 151];
        row[..8].copy_from_slice(b"RTOSPBXB");
        row[8..10].copy_from_slice(&5u16.to_le_bytes());
        row[83..115].fill(7);
        ("LiveAcceptance/b/1".into(), row)
    }

    #[test]
    fn selector_removed_after_metadata_is_normal_disarm() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("selector"), "42\nsession\n").unwrap();
        let result = read_selector(directory.path(), |path| {
            fs::remove_file(path)?;
            fs::File::open(path)
        });
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn disarm_does_not_hide_other_open_errors() {
        let directory = tempfile::tempdir().unwrap();
        assert!(read_selector(directory.path(), |_| panic!("absent selector opened"))
            .unwrap()
            .is_none());
        fs::write(directory.path().join("selector"), "42\nsession\n").unwrap();
        let error = read_selector(directory.path(), |_| {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied"))
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn exact_pid_session_and_wc_only_preserve_raw_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let (key, value) = row();
        let mut budget = Budget::default();
        let selector = directory.path().join("selector");
        fs::write(&selector, format!("42\n{}\n", hex::encode([7; 32]))).unwrap();
        capture(directory.path(), 43, &[(key.clone(), value.clone())], &mut budget).unwrap();
        assert_eq!(budget.bytes, 0);
        let mut other_session = value.clone();
        other_session[83] ^= 1;
        capture(directory.path(), 42, &[(key.clone(), other_session)], &mut budget).unwrap();
        assert_eq!(budget.bytes, 0);
        let mut mc = value.clone();
        mc[115..119].copy_from_slice(&(-1i32).to_le_bytes());
        capture(directory.path(), 42, &[(key.clone(), mc)], &mut budget).unwrap();
        assert_eq!(budget.bytes, 0);
        capture(directory.path(), 42, &[(key.clone(), value.clone())], &mut budget).unwrap();
        let digest = rtos_block::UInt256::calc_file_hash(&value).to_hex_string();
        assert_eq!(fs::read(directory.path().join(format!("{digest}.bin"))).unwrap(), value);
        capture(directory.path(), 42, &[(key, value.clone())], &mut budget).unwrap();
        assert_eq!(budget.seen.len(), 1);
        assert_eq!(budget.bytes, value.len());
    }

    #[test]
    fn byte_quota_refuses_before_creating_files() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("selector"), format!("42\n{}\n", hex::encode([7; 32])))
            .unwrap();
        let mut budget = Budget { bytes: MAX_TOTAL, ..Default::default() };
        assert!(capture(directory.path(), 42, &[row()], &mut budget).is_err());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }
}
