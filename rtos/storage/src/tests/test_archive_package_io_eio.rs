// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Exact private package IO and owned-close EIO; no hardware/power-loss claim.
use super::{metadata_eio_tests as base, *};
use crate::{archives::package::PKG_HEADER_SIZE, tests::late_index_eio_support as late};
use std::time::Duration;

fn arm() -> PathBuf {
    std::env::var_os("RTOS_PKG_IO_ARM").unwrap().into()
}
fn no_arm() -> bool {
    std::env::var("RTOS_PKG_IO_NO_ARM").as_deref() == Ok("1")
}
fn arm_value(value: String) {
    if no_arm() {
        eprintln!("PKG-IO ARM_SKIPPED");
    } else {
        std::fs::write(arm(), value).unwrap();
        eprintln!("PKG-IO ARMED");
    }
}
fn disarm() {
    if !no_arm() {
        std::fs::remove_file(arm()).unwrap();
    }
}

async fn shutdown(
    db: Arc<RocksDb>,
    handles_db: Arc<RocksDb>,
    slice: Option<ArchiveSlice>,
    handles: Vec<Arc<BlockHandle>>,
    arm_close: bool,
) -> Result<()> {
    let result = if let Some(slice) = slice {
        let info = base::package(&slice, &handles[0]).await;
        if arm_close {
            let fd = info.package().writer_fd_for_io_test().await?;
            eprintln!("PKG-IO OWNED_WRITER_FD fd={fd} path={}", info.package().path().display());
            arm_value(fd.to_string());
        }
        drop(slice);
        drop(handles);
        tokio::time::timeout(late::TIMEOUT, async {
            while Arc::strong_count(&info) != 1 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("package IO owners remain; cold forbidden");
        let result = tokio::time::timeout(late::TIMEOUT, info.package().close_for_sst_test())
            .await
            .expect("native package close owner timed out; cold forbidden");
        eprintln!("PKG-IO CLOSE_RESULT result={result:?}");
        drop(info);
        result
    } else {
        drop(handles);
        Ok(())
    };
    if arm_close {
        disarm();
    }
    late::close_db(db).await;
    late::close_db(handles_db).await;
    eprintln!("PKG-IO ALL_OWNERS_CLOSED");
    result
}
async fn exercise(key: bool) {
    let path = late::root();
    let cut = std::env::var("RTOS_PKG_IO_CUT").unwrap();
    assert!(matches!(
        cut.as_str(),
        "write-first"
            | "write-last"
            | "data-sync"
            | "file-sync"
            | "dir-sync"
            | "wal-sync"
            | "close"
    ));
    let control = late::control();
    let protected = std::env::var("RTOS_PKG_IO_PROTECTED").as_deref() == Ok("1");
    let early = cut.starts_with("write-") || cut == "data-sync";
    let (db, handles_db, handles) = base::native(&path, key).await;
    let slice = base::open(&db, &path, key, None).await.unwrap();
    for handle in &handles[..2] {
        assert_eq!(base::produce(&slice, handle).await.unwrap(), base::payload(handle));
    }
    base::reads(&slice, &handles[..2]).await;
    let info = base::package(&slice, &handles[0]).await;
    let pack = info.package().path().to_path_buf();
    let prefix = std::fs::read(&pack).unwrap();
    let seed = base::snapshot(&db, key, &pack);
    let old = [
        base::rows(&db, &base::cf("offsets", key)),
        base::rows(&db, &base::cf("block_index", key)),
    ];
    let target = PackageEntryId::Block(handles[2].id());
    let payload_offset = prefix.len()
        + crate::archives::package_entry::PKG_ENTRY_HEADER_SIZE
        + target.filename().len();
    let threshold = if cut == "write-last" { payload_offset } else { prefix.len() };
    std::fs::write(std::env::var_os("RTOS_PKG_IO_OFFSET_FILE").unwrap(), threshold.to_string())
        .unwrap();
    if protected {
        base::protect(&db, handles[0].id());
    }
    eprintln!("PKG-IO SEEDS_SYNCED pack={} old_len={} payload_offset={payload_offset} filename_len={} cut={cut}", pack.display(), prefix.len(), target.filename().len());
    drop(info);
    if cut != "close" {
        arm_value("target-append".into());
    } else {
        eprintln!("PKG-IO CLOSE_ARM_DEFERRED");
    }
    let result = base::produce(&slice, &handles[2]).await;
    eprintln!("PKG-IO TARGET_RESULT cut={cut} result={result:?}");
    let acknowledged = control || cut == "close";
    assert_eq!(result.is_ok(), acknowledged, "package IO producer acknowledgement differs");
    if let Err(error) = result {
        late::check_eio(&error.to_string());
    }
    base::old_rows(&db, key, &old);
    base::reads(&slice, &handles[..2]).await;
    if !acknowledged {
        let before = std::fs::read(&pack).unwrap().len();
        let retry = base::produce(&slice, &handles[2]).await;
        eprintln!(
            "PKG-IO LIVE_RETRY cut={cut} before={before} after={} result={retry:?}",
            std::fs::read(&pack).unwrap().len()
        );
        assert!(retry.is_err(), "held package IO fault returned retry success");
        if early {
            assert!(retry.unwrap_err().to_string().contains("uncertain"));
            assert_eq!(
                base::snapshot(&db, key, &pack).0,
                seed.0,
                "pre-metadata fault changed provider tables"
            );
        }
    }
    let present = acknowledged || !early;
    base::target_rows(&db, key, &handles[2], present, present);
    if present {
        base::reads(&slice, &handles).await;
    }
    base::old_rows(&db, key, &old);
    let before_close = base::snapshot(&db, key, &pack);
    assert!(before_close.1.starts_with(&prefix));
    let end = slice
        .entry_db
        .get_value(&if key { u32::MAX.into() } else { 0u32.into() })
        .unwrap()
        .entry_size();
    let status = if key {
        slice.package_status_db.get_value::<u64>(&PackageStatusKey::NonSlicedSize).unwrap()
    } else {
        end
    };
    eprintln!(
        "PKG-IO LIVE_PREFIX end={end} status={status} physical_len={} target_present={present}",
        before_close.1.len()
    );
    if cut != "close" {
        disarm();
    }
    let closed = shutdown(db, handles_db, Some(slice), handles, cut == "close").await;
    if cut == "close" && !control {
        let error = closed.expect_err("package close EIO reported successful shutdown");
        late::check_eio(&error.to_string());
        assert_eq!(std::fs::read(&pack).unwrap(), before_close.1);
        eprintln!("PKG-IO COMPLETE outcome=shutdown-refusal cut={cut} key={key}");
        return;
    }
    closed.expect("unexpected shutdown error; cold forbidden");
    let (db, handles_db, handles) = base::native(&path, key).await;
    let raw_cold = base::snapshot(&db, key, &pack);
    assert_eq!(raw_cold, before_close, "native close changed recorded successful prefix");
    let opened = base::open(&db, &path, key, protected.then(|| handles[0].id())).await;
    let refused =
        protected && (end != status || end + PKG_HEADER_SIZE as u64 != raw_cold.1.len() as u64);
    if refused {
        let error = match opened {
            Err(error) => error,
            Ok(_) => panic!("protected uncertain prefix accepted"),
        };
        assert!(error.to_string().contains(if end != status {
            "ambiguous durable length metadata"
        } else {
            "physical length differs from durable metadata"
        }));
        assert_eq!(std::fs::read(&pack).unwrap(), raw_cold.1);
        base::old_rows(&db, key, &old);
        shutdown(db, handles_db, None, handles, false).await.unwrap();
        eprintln!("PKG-IO COMPLETE outcome=protected-refusal cut={cut} key={key}");
        return;
    }
    let slice = opened.expect("coherent cold consumer failed");
    base::old_rows(&db, key, &old);
    base::reads(&slice, &handles[..2]).await;
    base::target_rows(&db, key, &handles[2], present, present);
    if present {
        base::reads(&slice, &handles).await;
    }
    let bytes = std::fs::read(&pack).unwrap();
    assert!(bytes.starts_with(&prefix));
    assert_eq!(
        bytes.len() as u64,
        end + PKG_HEADER_SIZE as u64,
        "actual committed boundary not recovered"
    );
    assert_eq!(base::produce(&slice, &handles[2]).await.unwrap(), base::payload(&handles[2]));
    base::reads(&slice, &handles).await;
    let final_data = base::snapshot(&db, key, &pack);
    shutdown(db, handles_db, Some(slice), handles, false).await.unwrap();
    let (db, handles_db, handles) = base::native(&path, key).await;
    let slice = base::open(&db, &path, key, protected.then(|| handles[0].id())).await.unwrap();
    base::reads(&slice, &handles).await;
    base::old_rows(&db, key, &old);
    assert_eq!(base::snapshot(&db, key, &pack), final_data);
    shutdown(db, handles_db, Some(slice), handles, false).await.unwrap();
    eprintln!("PKG-IO COMPLETE outcome=recovered cut={cut} key={key} protected={protected} control={control}");
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires private native package IO EIO harness"]
async fn blocks_package_io_eio() {
    exercise(false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires private native package IO EIO harness"]
async fn keyblocks_package_io_eio() {
    exercise(true).await;
}
