// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Test-only coordination of process creation with exact socket lifecycle checks.
//! CLOEXEC closes descriptors at exec, not when the child is first created.
use std::process::{Child, Command, Output, Stdio};

static PROCESS_CREATION: tokio::sync::RwLock<()> = tokio::sync::RwLock::const_new(());

/// Multiple socket fixtures remain concurrent. Acquire before reserving a port,
/// and retain through the last exact rebind/owner assertion. Do not spawn a
/// process while holding this lease, or recursively acquire it.
pub(crate) async fn socket_lifecycle() -> tokio::sync::RwLockReadGuard<'static, ()> {
    PROCESS_CREATION.read().await
}

/// Wait only for spawn/exec, never for the child's test execution, under the
/// exclusive lease. These callers run on independent test-harness threads.
pub(crate) fn spawn(command: &mut Command) -> std::io::Result<Child> {
    let _creation = futures::executor::block_on(PROCESS_CREATION.write());
    command.spawn()
}

pub(crate) fn output(command: &mut Command) -> std::io::Result<Output> {
    // Match Command::output: wait_with_output closes the unused stdin pipe.
    spawn(command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()))?
        .wait_with_output()
}

#[cfg(unix)]
#[test]
fn child_creation_waits_until_socket_lifecycle_finishes() {
    use std::{
        io::{Read, Write},
        net::UdpSocket,
        os::{
            fd::AsRawFd,
            unix::{net::UnixStream, process::CommandExt},
        },
        sync::mpsc,
        time::Duration,
    };
    let mut lease = Some(futures::executor::block_on(socket_lifecycle()));
    let mut socket = Some(UdpSocket::bind("127.0.0.1:0").unwrap());
    let address = socket.as_ref().unwrap().local_addr().unwrap();
    let (mut parent, child) = UnixStream::pair().unwrap();
    parent.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
    child.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let fd = child.as_raw_fd();
    let (attempted, attempt) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", "test_process::nonexistent_child_case"]);
        // SAFETY: the fork child uses only async-signal-safe read/write calls on
        // a live socket. No allocation, Rust locks or runtime access before exec.
        unsafe {
            command.pre_exec(move || {
                let mut byte = 1u8;
                if libc::write(fd, (&byte as *const u8).cast(), 1) != 1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::read(fd, (&mut byte as *mut u8).cast(), 1) != 1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        attempted.send(()).unwrap();
        let result = spawn(&mut command);
        drop(child);
        result.and_then(|mut child| child.wait())
    });
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        attempt.recv_timeout(Duration::from_secs(5)).unwrap();
        let mut byte = [0];
        let ready = parent.read(&mut byte);
        if matches!(ready, Ok(1)) {
            drop(socket.take());
            let error = UdpSocket::bind(address).unwrap_err();
            panic!(
                "child entered pre-exec during socket lifecycle; actual rebind refused: {error}"
            );
        }
        assert!(
            matches!(ready, Err(ref e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)),
            "child entered pre-exec during socket lifecycle: {ready:?}"
        );
        drop(socket.take());
        let rebound = UdpSocket::bind(address).expect("socket must rebind before child creation");
        drop(rebound);
        drop(lease.take());
        parent.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        parent.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [1]);
    }));
    // Release the child and join even if the negative control fails assertions.
    drop(socket);
    drop(lease);
    let release = parent.write_all(&[1]);
    let child_status = worker.join().unwrap();
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
    release.unwrap();
    assert!(child_status.unwrap().success());
}
