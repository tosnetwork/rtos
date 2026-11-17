// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Isolated Linux fixture: bind a native sync cut to one authenticated acceptance.
//! Observations never replace the actual synchronization or its error handling.
use crate::{
    propagation_outbox::{delivery_id, PropagationOutbox, UnverifiedRecord},
    validator::accept_block::AcceptedSessionBlock,
};
use rtos_block::{fail, Result, UInt256};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use storage::{
    archives::package_entry_id::GetFileName,
    durability::{SyncObservation, SyncPoint},
};
const CONTROL: &str = "RTOS_TEST_PUBLICATION_IO_CONTROL";
const MAX_SELECTOR: u64 = 4096;

#[derive(Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Selector {
    schema: u32,
    pid: u32,
    session_id: String,
    block_id: String,
    block_sha256: String,
    source_id: String,
    node_receipt: String,
}
#[derive(Deserialize, Serialize)]
struct Witness {
    schema: u32,
    selector_sha256: String,
    selector: Selector,
    proof_sha256: String,
    publication: PublicationContext,
    artifact: String,
    pid: u32,
    tid: u32,
    device: u64,
    inode: u64,
    path: PathBuf,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
struct PublicationContext {
    record_id: Option<u64>,
    node_receipt: Option<String>,
    delivery_id: String,
    stage: String,
}
impl PublicationContext {
    fn from_entry(entry: &UnverifiedRecord, queued: bool) -> Result<Self> {
        let delivery_id = delivery_id(&entry.record)?.to_hex_string();
        Ok(Self {
            record_id: queued.then_some(entry.id.0),
            node_receipt: queued.then(|| delivery_id.clone()),
            delivery_id,
            stage: if queued { format!("{:?}", entry.stage) } else { "LiveAcceptance".into() },
        })
    }
}
tokio::task_local! { static PUBLICATION: PublicationContext; }

pub(crate) async fn acceptance_scope<T>(
    entry: &UnverifiedRecord,
    queued: bool,
    work: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    if std::env::var_os(CONTROL).is_none() {
        return work.await;
    }
    PUBLICATION.scope(PublicationContext::from_entry(entry, queued)?, work).await
}
fn matches_publication(selector: &Selector, publication: &PublicationContext) -> bool {
    publication.delivery_id == selector.node_receipt
        && match publication.stage.as_str() {
            "LiveAcceptance" => {
                publication.record_id.is_none() && publication.node_receipt.is_none()
            }
            "DraftDurable" => {
                publication.record_id.is_some()
                    && publication.node_receipt.as_ref() == Some(&selector.node_receipt)
            }
            _ => false,
        }
}

fn digest(bytes: &[u8]) -> String {
    UInt256::calc_file_hash(bytes).to_hex_string()
}
fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn load(control: &Path) -> Result<Option<(Selector, String)>> {
    if !control.is_absolute() || control.canonicalize()? != control {
        fail!("Publication IO control requires a canonical directory");
    }
    let path = control.join("selector.json");
    let info = match std::fs::symlink_metadata(&path) {
        Ok(info) => info,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !info.file_type().is_file() || info.len() > MAX_SELECTOR {
        fail!("Invalid publication IO selector type/size");
    }
    let mut bytes = Vec::new();
    File::open(path)?.take(MAX_SELECTOR + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_SELECTOR {
        fail!("Publication IO selector grew beyond bound");
    }
    let selector: Selector = serde_json::from_slice(&bytes)?;
    if selector.schema != 1
        || selector.pid == 0
        || !is_digest(&selector.session_id)
        || !is_digest(&selector.block_sha256)
        || !is_digest(&selector.source_id)
        || !is_digest(&selector.node_receipt)
    {
        fail!("Invalid publication IO selector identity");
    }
    Ok(Some((selector, digest(&bytes))))
}
fn matches(
    selector: &Selector,
    pid: u32,
    session: &str,
    block: &str,
    body: &[u8],
    is_final: bool,
) -> bool {
    is_final
        && selector.pid == pid
        && selector.session_id == session
        && selector.block_id == block
        && selector.block_sha256 == digest(body)
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn arm(
    control: &Path,
    selector: &Selector,
    selector_sha256: &str,
    proof_sha256: &str,
    publication: &PublicationContext,
    path: &Path,
) -> Result<()> {
    let path = path.canonicalize()?;
    if path.to_str().is_none_or(|text| text.contains(['\n', '\r'])) {
        fail!("Native publication IO target must be a single UTF-8 path");
    }
    let info = std::fs::metadata(&path)?;
    if !info.is_file() || info.len() == 0 {
        fail!("Publication body sync requires a nonempty regular artifact");
    }
    let thread = std::fs::read_link("/proc/thread-self")?;
    let tid: u32 = thread
        .file_name()
        .and_then(|part| part.to_str())
        .ok_or_else(|| rtos_block::error!("Missing publication sync thread"))?
        .parse()?;
    let pid = std::process::id();
    let witness = Witness {
        schema: 1,
        selector_sha256: selector_sha256.to_owned(),
        selector: selector.clone(),
        proof_sha256: proof_sha256.to_owned(),
        publication: publication.clone(),
        artifact: "loose_block_body".into(),
        pid,
        tid,
        device: info.dev(),
        inode: info.ino(),
        path: path.clone(),
    };
    // The JSON is evidence. Only the final atomic rename arms the native cut.
    write_new(&control.join("target.json"), &serde_json::to_vec(&witness)?)?;
    let native = format!("{pid} {tid} {} {}\n{}\n", info.dev(), info.ino(), path.display());
    write_new(&control.join("target.native.tmp"), native.as_bytes())?;
    std::fs::rename(control.join("target.native.tmp"), control.join("target.native"))?;
    File::open(control)?.sync_all()?;
    Ok(())
}

pub(crate) fn for_acceptance(accepted: &AcceptedSessionBlock) -> Result<SyncObservation> {
    let Some(control) = std::env::var_os(CONTROL) else { return Ok(None) };
    let control = PathBuf::from(control);
    let Some((selector, selector_sha256)) = load(&control)? else { return Ok(None) };
    if !matches(
        &selector,
        std::process::id(),
        &accepted.authenticated_session_id().to_hex_string(),
        &accepted.block().id().to_string(),
        accepted.block().data(),
        accepted.is_final(),
    ) {
        return Ok(None);
    }
    let Ok(publication) = PUBLICATION.try_with(Clone::clone) else { return Ok(None) };
    if !matches_publication(&selector, &publication) {
        return Ok(None);
    }
    let name = storage::archives::package_entry_id::PackageEntryId::Block(accepted.block().id())
        .filename_short();
    let proof_sha256 = digest(accepted.proof().data());
    let armed = AtomicBool::new(false);
    Ok(Some(Arc::new(move |point, path| {
        if point == SyncPoint::File
            && path.file_name().and_then(|part| part.to_str()) == Some(name.as_str())
            && !armed.swap(true, Ordering::SeqCst)
        {
            arm(&control, &selector, &selector_sha256, &proof_sha256, &publication, path)?;
        }
        Ok(())
    })))
}

/// Called synchronously after the publication worker marks the real typed
/// durability failure fatal, before it returns an unsuccessful acceptance.
pub(crate) fn after_fatal(
    entry: &UnverifiedRecord,
    store: Option<&PropagationOutbox>,
    accepted: &AcceptedSessionBlock,
    error: &anyhow::Error,
) -> Result<()> {
    let Some(control) = std::env::var_os(CONTROL) else { return Ok(()) };
    let control = PathBuf::from(control);
    let Some((selector, selector_sha256)) = load(&control)? else { return Ok(()) };
    if !matches(
        &selector,
        std::process::id(),
        &accepted.authenticated_session_id().to_hex_string(),
        &accepted.block().id().to_string(),
        accepted.block().data(),
        accepted.is_final(),
    ) {
        return Ok(());
    }
    let publication = PublicationContext::from_entry(entry, store.is_some())?;
    if !matches_publication(&selector, &publication) {
        return Ok(());
    }
    if let Some(store) = store {
        let (_, retained) = store
            .delivery(&delivery_id(&entry.record)?)?
            .ok_or_else(|| rtos_block::error!("Failed publication lost its full WAL draft"))?;
        if PublicationContext::from_entry(&retained, true)? != publication
            || retained.record != entry.record
        {
            fail!("Failed publication advanced or changed its durable draft");
        }
    }
    let target_bytes = std::fs::read(control.join("target.json"))?;
    let target: Witness = serde_json::from_slice(&target_bytes)?;
    let marker = std::fs::read(control.join("native-error.marker"))?;
    let marker_text = std::str::from_utf8(&marker)?;
    let expected = |operation: &str| {
        format!(
            "publication sync-eio pid={} tid={} syscall={operation} errno=5: {}\n",
            target.pid,
            target.tid,
            target.path.display()
        )
    };
    if target.schema != 1
        || target.selector != selector
        || target.publication != publication
        || target.selector_sha256 != selector_sha256
        || target.pid != std::process::id()
        || target.artifact != "loose_block_body"
        || target.proof_sha256 != digest(accepted.proof().data())
        || (marker_text != expected("fsync") && marker_text != expected("fdatasync"))
        || error.downcast_ref::<crate::internal_db::PublicationDurabilityFailure>().is_none()
        || !error.to_string().contains("Input/output error (os error 5)")
    {
        fail!("Fatal publication IO observation differs from selected native EIO");
    }
    let failed = serde_json::json!({
        "schema":1, "pid":std::process::id(), "selector_sha256":selector_sha256,
        "target_sha256":digest(&target_bytes), "native_marker_sha256":digest(&marker),
        "error":error.to_string(), "typed_durability_failure":true,
        "publication_owner_marked_fatal":true, "accepted_callback_returned":false,
        "retained_draft_verified":store.is_some(), "publication":publication,
    });
    write_new(&control.join("failed.json"), &serde_json::to_vec(&failed)?)?;
    File::open(&control)?.sync_all()?;
    unsafe extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;
    }
    // Linux SIGSTOP stops the owned process only after the actual fatal path.
    if unsafe { kill(std::process::id() as i32, 19) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn publication_io_arm_records_actual_worker_and_never_changes_body() {
        let directory =
            std::env::temp_dir().join(format!("rtos-io-control-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let body = directory.join("body");
        std::fs::write(&body, b"actual body").unwrap();
        let selector = Selector {
            schema: 1,
            pid: std::process::id(),
            session_id: "a".repeat(64),
            block_id: "block".into(),
            block_sha256: digest(b"actual body"),
            source_id: "b".repeat(64),
            node_receipt: "e".repeat(64),
        };
        let publication = PublicationContext {
            record_id: Some(7),
            node_receipt: Some(selector.node_receipt.clone()),
            delivery_id: selector.node_receipt.clone(),
            stage: "DraftDurable".into(),
        };
        arm(&directory, &selector, &"c".repeat(64), &"d".repeat(64), &publication, &body).unwrap();
        let witness: serde_json::Value =
            serde_json::from_slice(&std::fs::read(directory.join("target.json")).unwrap()).unwrap();
        let native = std::fs::read_to_string(directory.join("target.native")).unwrap();
        let info = body.metadata().unwrap();
        assert_eq!(witness["device"], info.dev());
        assert_eq!(witness["inode"], info.ino());
        assert_eq!(witness["artifact"], "loose_block_body");
        assert_eq!(witness["pid"], std::process::id());
        assert!(native.ends_with(&format!("\n{}\n", body.display())));
        assert_eq!(std::fs::read(&body).unwrap(), b"actual body");
        assert!(arm(&directory, &selector, "c", "d", &publication, &body).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn publication_io_requires_the_exact_unaccepted_wal_delivery() {
        let selector = Selector {
            schema: 1,
            pid: 7,
            session_id: "a".repeat(64),
            block_id: "block".into(),
            block_sha256: digest(b"body"),
            source_id: "b".repeat(64),
            node_receipt: "c".repeat(64),
        };
        let mut publication = PublicationContext {
            record_id: Some(9),
            node_receipt: Some(selector.node_receipt.clone()),
            delivery_id: selector.node_receipt.clone(),
            stage: "DraftDurable".into(),
        };
        assert!(matches_publication(&selector, &publication));
        publication.node_receipt = Some("d".repeat(64));
        assert!(!matches_publication(&selector, &publication));
        publication.node_receipt = Some(selector.node_receipt.clone());
        for stage in ["Prepared", "Ready", "AcceptedDraft", "Completed"] {
            publication.stage = stage.into();
            assert!(!matches_publication(&selector, &publication));
        }
        publication.stage = "LiveAcceptance".into();
        assert!(!matches_publication(&selector, &publication));
        publication.record_id = None;
        publication.node_receipt = None;
        assert!(matches_publication(&selector, &publication));
        publication.delivery_id = "f".repeat(64);
        assert!(!matches_publication(&selector, &publication));
    }

    #[test]
    fn publication_io_selector_requires_exact_final_acceptance() {
        let selector = Selector {
            schema: 1,
            pid: 7,
            session_id: "a".repeat(64),
            block_id: "full block identity".into(),
            block_sha256: digest(b"body"),
            source_id: "b".repeat(64),
            node_receipt: "e".repeat(64),
        };
        assert!(matches(&selector, 7, &selector.session_id, &selector.block_id, b"body", true));
        assert!(!matches(&selector, 8, &selector.session_id, &selector.block_id, b"body", true));
        assert!(!matches(&selector, 7, &"c".repeat(64), &selector.block_id, b"body", true));
        assert!(!matches(&selector, 7, &selector.session_id, "other block", b"body", true));
        assert!(!matches(
            &selector,
            7,
            &selector.session_id,
            &selector.block_id,
            b"metadata",
            true
        ));
        assert!(!matches(&selector, 7, &selector.session_id, &selector.block_id, b"body", false));
    }
}
