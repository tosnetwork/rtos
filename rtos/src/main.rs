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
mod auth_admission;
mod block;
mod block_proof;
mod boot;
pub(crate) mod retired_history;
pub(crate) mod historical_recovery;
mod collator_test_bundle;
mod config;
mod confirmed_blocks;
mod engine;
mod engine_operations;
mod engine_traits;
mod served_masterchain;
mod error;
mod full_node;
mod internal_db;
mod macros;
mod network;
mod network_db;
mod pq_consensus_config;
mod propagation_outbox;
pub(crate) mod propagation_outbox_auth;
pub(crate) mod publication_worker;
pub(crate) mod publication_repair;
#[cfg(all(target_os = "linux", feature = "isolated-consensus-signing"))]
pub(crate) mod publication_io_test_control;
mod rng;
mod rpc_server;
mod shard_state;
mod shard_states_keeper;
mod sync;
mod types;
mod validating_utils;
mod validator;

mod ext_messages;

// Shared archive fixtures also build in this binary's test crate.
#[cfg(test)]
use rtos::archive_import;

#[cfg(not(feature = "xp25"))]
mod shard_blocks;
#[cfg(feature = "xp25")]
mod shard_blocks_intershard;
#[cfg(feature = "xp25")]
mod shard_blocks {
    pub use crate::shard_blocks_intershard::*;
}

use crate::{
    config::{SecretsVaultConfig, TonNodeConfig},
    engine::{Engine, EngineFlags, Stopper},
    internal_db::restore::set_graceful_termination,
    network::shard_overlay_certificates::ShardOverlayCertificatePolicy,
    validating_utils::supported_version,
};
use rtos_block::Result;
#[cfg(feature = "mirrornet")]
use rtos_block::UnixTime;
use std::sync::{
    atomic::{AtomicBool, AtomicI32, Ordering},
    Arc, OnceLock,
};
#[cfg(feature = "trace_alloc")]
use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::AtomicU64,
    thread,
    time::Duration,
};
#[cfg(feature = "trace_alloc_detail")]
use std::{
    fs::File,
    io::Write,
    mem::{self, MaybeUninit},
    sync::atomic::{AtomicIsize, AtomicUsize},
};

#[cfg(test)]
#[path = "tests/test_helper.rs"]
pub mod test_helper;

#[cfg(all(feature = "jemalloc", not(feature = "trace_alloc"), not(windows)))]
#[global_allocator]
static GLOBAL_JEMALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(feature = "jemalloc")]
#[allow(non_upper_case_globals)]
#[export_name = "malloc_conf"]
// muzzy_decay_ms:0 forces MADV_DONTNEED immediately after MADV_FREE so that
// kernel anon-rss matches what jemalloc considers freed — critical under cgroup
// memory.max limits where phantom muzzy pages would trigger memcg OOM.
pub static malloc_conf: &[u8] = b"background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:0\0";

#[cfg(feature = "trace_alloc")]
struct TracingAllocator {
    count: AtomicU64,
    allocated: AtomicU64,
    overhead: AtomicU64,
}

#[cfg(feature = "trace_alloc_detail")]
struct AllocDetail {
    start: AtomicUsize,
    size: AtomicIsize,
}

#[cfg(feature = "trace_alloc_detail")]
const SIZE_TRACEBUF: usize = 20000000;

#[cfg(feature = "trace_alloc_detail")]
lazy_static::lazy_static! {
    static ref TRACEBUF: [AllocDetail; SIZE_TRACEBUF] = {
        let mut data: [MaybeUninit<AllocDetail>; SIZE_TRACEBUF] = unsafe {
            MaybeUninit::uninit().assume_init()
        };
        for elem in &mut data[..] {
            elem.write(
                AllocDetail {
                    start: AtomicUsize::new(0),
                    size: AtomicIsize::new(0)
                }
            );
        }
        unsafe { mem::transmute::<_, [AllocDetail; SIZE_TRACEBUF]>(data) }
    };
    static ref TRACEBUF_HEAD: AtomicUsize = AtomicUsize::new(0);
    static ref TRACEBUF_TAIL: AtomicUsize = AtomicUsize::new(0);
}

#[cfg(feature = "trace_alloc")]
thread_local!(
    static NOCALC: AtomicBool = AtomicBool::new(false)
);

#[cfg(feature = "trace_alloc")]
unsafe impl GlobalAlloc for TracingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ret = System.alloc(layout);
        self.check_alloc(ret, layout.size());
        ret
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ret = System.alloc_zeroed(layout);
        self.check_alloc(ret, layout.size());
        ret
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        self.check_dealloc(ptr, layout.size());
        let ret = System.realloc(ptr, layout, new_size);
        self.check_alloc(ret, new_size);
        ret
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.check_dealloc(ptr, layout.size());
        System.dealloc(ptr, layout);
    }
}

#[cfg(feature = "trace_alloc")]
impl TracingAllocator {
    fn check_alloc(&self, _ptr: *mut u8, size: usize) {
        if NOCALC
            .with(|f| f.compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed).is_ok())
        {
            self.allocated.fetch_add(size as u64, Ordering::Relaxed);
            #[cfg(feature = "trace_alloc_detail")]
            Self::post_trace(_ptr as usize, size as isize);
            self.count.fetch_add(1, Ordering::Relaxed);
            NOCALC.with(|f| f.store(false, Ordering::Relaxed));
        } else {
            self.overhead.fetch_add(size as u64, Ordering::Relaxed);
        }
    }

    fn check_dealloc(&self, _ptr: *mut u8, size: usize) {
        if NOCALC
            .with(|f| f.compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed).is_ok())
        {
            self.allocated.fetch_sub(size as u64, Ordering::Relaxed);
            #[cfg(feature = "trace_alloc_detail")]
            Self::post_trace(_ptr as usize, -(size as isize));
            self.count.fetch_sub(1, Ordering::Relaxed);
            NOCALC.with(|f| f.store(false, Ordering::Relaxed));
        } else {
            self.overhead.fetch_sub(size as u64, Ordering::Relaxed);
        }
    }

    #[cfg(feature = "trace_alloc_detail")]
    fn post_trace(start: usize, size: isize) {
        loop {
            let this = TRACEBUF_HEAD.load(Ordering::Relaxed);
            let next = if this == SIZE_TRACEBUF - 1 { 0 } else { this + 1 };
            if next == TRACEBUF_TAIL.load(Ordering::Acquire) {
                thread::yield_now();
                continue;
            }
            if TRACEBUF_HEAD
                .compare_exchange(this, next, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
            {
                thread::yield_now();
                continue;
            }
            if start == 0 {
                panic!("ZEROADDR_WRITE")
            }
            TRACEBUF[this].start.store(start, Ordering::Relaxed);
            TRACEBUF[this].size.store(size, Ordering::Release);
            break;
        }
    }
}

#[cfg(feature = "trace_alloc")]
#[global_allocator]
static GLOBAL: TracingAllocator = TracingAllocator {
    count: AtomicU64::new(0),
    allocated: AtomicU64::new(0),
    overhead: AtomicU64::new(0),
};

/// The log configuration of a node without a log configuration file: the
/// standard output at `level`.
fn default_log_config(level: log::LevelFilter) -> std::result::Result<log4rs::Config, String> {
    let stdout = log4rs::append::console::ConsoleAppender::builder()
        .target(log4rs::append::console::Target::Stdout)
        .build();
    log4rs::config::Config::builder()
        .appender(
            log4rs::config::Appender::builder()
                .filter(Box::new(log4rs::filter::threshold::ThresholdFilter::new(level)))
                .build("stdout", Box::new(stdout)),
        )
        .build(log4rs::config::Root::builder().appender("stdout").build(level))
        .map_err(|error| format!("bad default log configuration: {error}"))
}

/// Changes the log level of the running node, as the reference engine's
/// verbosity changes: the root level of the log configuration the node
/// started with. Levels a log configuration file sets for named loggers
/// stay as the file sets them.
struct Log4rsVerbosity {
    handle: log4rs::Handle,
    source: Option<std::path::PathBuf>,
}

impl network::control::VerbosityControl for Log4rsVerbosity {
    fn set_level(&self, level: log::LevelFilter) -> Result<()> {
        let mut config = match &self.source {
            Some(path) => {
                log4rs::config::load_config_file(path, Default::default()).map_err(|error| {
                    rtos_block::error!(
                        "cannot reload the log configuration {}: {error}",
                        path.display()
                    )
                })?
            }
            None => default_log_config(level).map_err(|error| rtos_block::error!("{error}"))?,
        };
        config.root_mut().set_level(level);
        self.handle.set_config(config);
        Ok(())
    }
}

/// Sets up logging from the log configuration file, or the default one, and
/// installs the control that changes its level at run time.
fn init_logging(path: Option<&std::path::Path>) -> std::result::Result<(), String> {
    let config = match path {
        Some(path) => {
            log4rs::config::load_config_file(path, Default::default()).map_err(|error| {
                format!("cannot initialize logging from {}: {error}", path.display())
            })?
        }
        None => default_log_config(log::LevelFilter::Info)?,
    };
    let handle = log4rs::init_config(config).map_err(|error| format!("Error init log: {error}"))?;
    network::control::install_verbosity_control(Box::new(Log4rsVerbosity {
        handle,
        source: path.map(std::path::Path::to_path_buf),
    }))
    .map_err(|error| error.to_string())
}

static NOT_SET_LABEL: &str = "Not set";

fn get_version() -> String {
    format!(
        "Execute {:?}\n\
        BLOCK_VERSION: {:?}\n\
        COMMIT_ID: {:?}\n\
        BUILD_DATE: {:?}\n\
        COMMIT_DATE: {:?}\n\
        GIT_BRANCH: {:?}\n\
        RUST_VERSION:{}\n",
        std::option_env!("CARGO_PKG_VERSION").unwrap_or(NOT_SET_LABEL),
        supported_version(),
        std::option_env!("BUILD_GIT_COMMIT").unwrap_or(NOT_SET_LABEL),
        std::option_env!("BUILD_TIME").unwrap_or(NOT_SET_LABEL),
        std::option_env!("BUILD_GIT_DATE").unwrap_or(NOT_SET_LABEL),
        std::option_env!("BUILD_GIT_BRANCH").unwrap_or(NOT_SET_LABEL),
        std::option_env!("BUILD_RUST_VERSION").unwrap_or(NOT_SET_LABEL),
    )
}

fn get_build_info() -> String {
    let mut info = String::new();
    info += &format!(
        "RTOS, version {}\n\
        Rust: {}\n\
        NODE git commit:         {}",
        std::option_env!("CARGO_PKG_VERSION").unwrap_or(NOT_SET_LABEL),
        std::option_env!("BUILD_RUST_VERSION").unwrap_or(NOT_SET_LABEL),
        std::option_env!("BUILD_GIT_COMMIT").unwrap_or(NOT_SET_LABEL),
    );
    info
}

async fn start_engine(
    config: TonNodeConfig,
    zerostate_path: Option<&str>,
    validator_runtime: tokio::runtime::Handle,
    liteserver_runtime: tokio::runtime::Handle,
    flags: EngineFlags,
    stopper: Arc<Stopper>,
    metrics: Option<(std::net::SocketAddr, metrics_exporter_prometheus::PrometheusHandle)>,
) -> Result<(Arc<Engine>, tokio::task::JoinHandle<()>)> {
    crate::engine::run(
        config,
        zerostate_path,
        validator_runtime,
        liteserver_runtime,
        flags,
        stopper,
        metrics,
    )
    .await
}

const CONFIG_NAME: &str = "config.json";
const DEFAULT_CONFIG_NAME: &str = "default_config.json";

fn check_debug_build() {
    // check that node built with --release
    if cfg!(debug_assertions) {
        println!("!!! WARN: Node was built without --release\n");
    }
}

/// Exit status for a refused option, configuration or configuration lock.
const EXIT_CONFIG: i32 = 2;
/// Exit status for a failure after the configuration was accepted.
const EXIT_RUNTIME: i32 = 1;
/// Name of the lock held over the configuration directory while the node runs.
const CONFIG_LOCK_NAME: &str = "config.json.lock";

/// Set by the panic hook on any thread; a run that panicked never exits 0.
static PANICKED: AtomicBool = AtomicBool::new(false);
/// The stop signal received, 0 if none. The process ends by that signal.
static RECEIVED_SIGNAL: AtomicI32 = AtomicI32::new(0);
/// Lets the panic hook request a failed stop once the engine stopper exists.
static PANIC_STOPPER: OnceLock<Arc<Stopper>> = OnceLock::new();
/// The configuration lock; never released before the process exits.
static CONFIG_LOCK: OnceLock<std::fs::File> = OnceLock::new();

/// How the node run ended, before the process status is chosen.
#[derive(Debug, PartialEq, Eq)]
enum RunEnd {
    Exit(i32),
    Panicked,
}

/// The process status: an exit code, or termination by a signal.
#[derive(Debug, PartialEq, Eq)]
enum Disposition {
    Exit(i32),
    Signal(i32),
}

/// A received stop signal decides the status even when cleanup failed or a
/// thread panicked. Otherwise any panic seen anywhere turns success into a
/// runtime failure.
fn final_disposition(end: RunEnd, signal: i32, panicked: bool) -> Disposition {
    if signal != 0 {
        return Disposition::Signal(signal);
    }
    match end {
        RunEnd::Exit(0) if panicked => Disposition::Exit(EXIT_RUNTIME),
        RunEnd::Exit(code) => Disposition::Exit(code),
        RunEnd::Panicked => Disposition::Exit(EXIT_RUNTIME),
    }
}

/// Ends the process by `signal` with its default action, so the parent sees
/// a signal termination.
fn terminate_by_signal(signal: i32) -> ! {
    // SAFETY: plain libc calls on a valid signal number; the sigset is
    // initialised by sigemptyset before use.
    unsafe {
        libc::signal(signal, libc::SIG_DFL);
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, signal);
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
        libc::raise(signal);
    }
    // Not reached for a terminating signal; keep the shell convention.
    std::process::exit(128 + signal)
}

/// Takes the configuration lock: a whole-file write record lock (fcntl), held
/// for the process lifetime. A second node, or a tool editing the
/// configuration under the same lock, cannot run beside this one.
fn acquire_config_lock(configs_dir: &str) -> std::result::Result<std::fs::File, String> {
    use std::os::unix::{fs::OpenOptionsExt, io::AsRawFd};
    let path = std::path::Path::new(configs_dir).join(CONFIG_LOCK_NAME);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|e| format!("cannot open the configuration lock {}: {e}", path.display()))?;
    // SAFETY: flock is a plain C structure; zeroed is a valid initial value.
    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
    lock.l_type = libc::F_WRLCK as _;
    lock.l_whence = libc::SEEK_SET as _;
    lock.l_start = 0;
    lock.l_len = 0;
    // SAFETY: the descriptor is open and the structure outlives the call.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLK, &lock) } == -1 {
        let error = std::io::Error::last_os_error();
        return Err(match error.raw_os_error() {
            Some(libc::EAGAIN) | Some(libc::EACCES) => format!(
                "the configuration lock {} is held by another process: a node already \
                running with this configuration, or a tool editing it: {error}",
                path.display()
            ),
            _ => format!("cannot lock the configuration lock {}: {error}", path.display()),
        });
    }
    Ok(file)
}

fn build_command() -> clap::Command {
    let app = clap::Command::new("rtos")
        .disable_version_flag(true)
        .arg(
            clap::Arg::new("version")
                .short('V')
                .long("version")
                .action(clap::ArgAction::SetTrue)
                .help("show build information and exit"),
        )
        .arg(
            clap::Arg::new("zerostate")
                .short('z')
                .long("zerostate")
                .value_name("zerostate")
                .num_args(1),
        )
        .arg(
            clap::Arg::new("config")
                .short('c')
                .long("configs")
                .value_name("config")
                .num_args(1)
                .default_value("./"),
        )
        .arg(
            clap::Arg::new("console_key")
                .short('k')
                .long("ckey")
                .value_name("console_key")
                .num_args(1)
                .help("use console key in json format"),
        )
        .arg(
            clap::Arg::new("initial_sync_disabled")
                .short('i')
                .long("initial-sync-disabled")
                .action(clap::ArgAction::SetTrue)
                .help("use this flag to sync from zero_state"),
        )
        .arg(
            clap::Arg::new("force_check_db")
                .short('f')
                .long("force-check-db")
                .action(clap::ArgAction::SetTrue)
                .help("start check & restore db process forcedly with refilling cells database"),
        )
        .arg(
            clap::Arg::new("process_conf_and_exit")
                .long("process-conf-and-exit")
                .action(clap::ArgAction::SetTrue)
                .help("finish node after config file processing (reading or generating)."),
        )
        .arg(
            clap::Arg::new("truncate_db")
                .short('T')
                .long("truncate-db")
                .value_name("truncate_db")
                .help("truncate db (with specified seqno as new top masterchain block seqno)"),
        )
        .arg(
            clap::Arg::new("state_ttl")
                .short('s')
                .long("state-ttl")
                .value_name("seconds")
                .allow_hyphen_values(true)
                .help("state will be gc'd after this time (in seconds) default=86400"),
        )
        .arg(
            clap::Arg::new("auto_sign")
                .long("auto-sign")
                .value_name("adnl")
                .action(clap::ArgAction::Append)
                .help("ADNL id (hex) to receive automatically issued shard overlay certificates"),
        )
        .arg(
            clap::Arg::new("accept_certs_from")
                .long("accept-certs-from")
                .value_name("adnl")
                .action(clap::ArgAction::Append)
                .help(
                    "accept shard overlay certificates from sender ADNL id (hex), or \"*\" for \
                     any validator issuer",
                ),
        )
        .arg(
            clap::Arg::new("shutdown_at")
                .long("shutdown-at")
                .value_name("unixtime")
                .action(clap::ArgAction::Append)
                .help("stop the node at the given time (unix timestamp)"),
        );

    #[cfg(feature = "mirrornet")]
    let app = app.arg(
        clap::Arg::new("timeshift")
            .long("timeshift")
            .value_name("timeshift")
            .help("shift the node's time by the specified number of seconds (can be negative) for testing purposes"),
    );
    app
}

/// Reads a number the way the reference reads its time options: leading
/// whitespace is skipped, the longest prefix of the form
/// `[+-]digits[.digits][(e|E)[+-]digits]` is taken and the rest ignored; a
/// prefix that is not a complete number reads as zero, and a magnitude too
/// large reads as the largest finite value.
fn reference_to_double(text: &str) -> f64 {
    let bytes = text.as_bytes();
    let mut start = 0;
    while start < bytes.len() && matches!(bytes[start], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
    {
        start += 1;
    }
    let mut end = start;
    let digits = |from: usize| {
        let mut at = from;
        while at < bytes.len() && bytes[at].is_ascii_digit() {
            at += 1;
        }
        at
    };
    if end < bytes.len() && matches!(bytes[end], b'+' | b'-') {
        end += 1;
    }
    let mantissa_start = end;
    end = digits(end);
    let mut mantissa_digits = end > mantissa_start;
    if end < bytes.len() && bytes[end] == b'.' {
        let fraction = digits(end + 1);
        mantissa_digits |= fraction > end + 1;
        end = fraction;
    }
    if mantissa_digits && end < bytes.len() && matches!(bytes[end], b'e' | b'E') {
        end += 1;
        if end < bytes.len() && matches!(bytes[end], b'+' | b'-') {
            end += 1;
        }
        end = digits(end);
    }
    let Some(prefix) = text.get(start..end) else {
        return 0.0;
    };
    match prefix.parse::<f64>() {
        Ok(value) if value.is_infinite() => {
            if value > 0.0 {
                f64::MAX
            } else {
                -f64::MAX
            }
        }
        Ok(value) => value,
        Err(_) => 0.0,
    }
}

/// A time option's value in seconds; `None` when the reference refuses it
/// (not greater than zero).
fn positive_seconds(text: &str) -> Option<f64> {
    let value = reference_to_double(text);
    (value > 0.0).then_some(value)
}

/// The shard overlay certificate options of this run, in the order given:
/// repeated values accumulate, and `*` accepts from any sender for good.
fn shard_overlay_certificate_policy(
    matches: &clap::ArgMatches,
) -> std::result::Result<ShardOverlayCertificatePolicy, String> {
    let mut policy = ShardOverlayCertificatePolicy::default();
    for value in matches.get_many::<String>("auto_sign").into_iter().flatten() {
        policy.add_auto_sign(value).map_err(|e| format!("--auto-sign {value}: {e}"))?;
    }
    for value in matches.get_many::<String>("accept_certs_from").into_iter().flatten() {
        policy
            .add_accept_certs_from(value)
            .map_err(|e| format!("--accept-certs-from {value}: {e}"))?;
    }
    for target in policy.auto_sign() {
        println!(
            "configured auto-sign shard overlay certificates for adnl={}",
            hex::encode(target.data())
        );
    }
    if policy.accepts_from_any() {
        println!("configured accepting shard overlay certificates from any validator");
    }
    let mut senders: Vec<_> = policy.accepted_senders().iter().collect();
    senders.sort_by(|left, right| left.data().cmp(right.data()));
    for sender in senders {
        println!(
            "configured accepting shard overlay certificates from adnl={}",
            hex::encode(sender.data())
        );
    }
    Ok(policy)
}

fn build_runtime(name: &str) -> std::result::Result<tokio::runtime::Runtime, i32> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(8 * 1024 * 1024)
        .build()
        .map_err(|e| {
            eprintln!("Can't create {name} tokio runtime: {e}");
            EXIT_RUNTIME
        })
}

/// Parses every configuration section the engine parses again at start, so a
/// malformed section is refused as a configuration error.
fn preflight_config(config: &TonNodeConfig) -> Result<()> {
    config.load_global_config()?;
    config.adnl_node()?;
    config.control_server()?;
    config.lite_server()?;
    config.json_rpc_server()?;
    Ok(())
}

/// Waits for SIGINT, SIGTERM or SIGHUP, records it and requests the stop. A
/// second signal ends the process at once, by that signal.
fn install_stop_signals(
    runtime: &tokio::runtime::Runtime,
    stopper: Arc<Stopper>,
) -> std::result::Result<(), String> {
    use tokio::signal::unix::{signal, SignalKind};
    let (mut interrupt, mut terminate, mut hangup) = runtime
        .block_on(async {
            Ok::<_, std::io::Error>((
                signal(SignalKind::interrupt())?,
                signal(SignalKind::terminate())?,
                signal(SignalKind::hangup())?,
            ))
        })
        .map_err(|e| format!("Error setting termination signals handler: {e}"))?;
    runtime.spawn(async move {
        let mut first = true;
        loop {
            let received = tokio::select! {
                _ = interrupt.recv() => libc::SIGINT,
                _ = terminate.recv() => libc::SIGTERM,
                _ = hangup.recv() => libc::SIGHUP,
            };
            if !first {
                terminate_by_signal(received);
            }
            first = false;
            RECEIVED_SIGNAL.store(received, Ordering::SeqCst);
            log::warn!("Got signal {received}, starting node's safe stopping...");
            stopper.set_stop();
        }
    });
    Ok(())
}

fn main() {
    // Installed first: a panic on any thread at any time is recorded.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        PANICKED.store(true, Ordering::SeqCst);
        log::error!("FATAL PANIC: {info}");
        if let Some(stopper) = PANIC_STOPPER.get() {
            // A panic requests shutdown but can never authorize a clean-shutdown marker.
            stopper.report_service_failure(0, format!("panic: {info}"));
        }
        default_hook(info);
    }));
    let end = match std::panic::catch_unwind(run_node) {
        Ok(code) => RunEnd::Exit(code),
        Err(_) => RunEnd::Panicked,
    };
    match final_disposition(
        end,
        RECEIVED_SIGNAL.load(Ordering::SeqCst),
        PANICKED.load(Ordering::SeqCst),
    ) {
        Disposition::Signal(signal) => terminate_by_signal(signal),
        Disposition::Exit(code) => std::process::exit(code),
    }
}

fn run_node() -> i32 {
    check_debug_build();

    let matches = match build_command().try_get_matches() {
        Ok(matches) => matches,
        Err(error) => {
            // Help is printed and ends like a refused option.
            let _ = error.print();
            return EXIT_CONFIG;
        }
    };

    println!("{}", get_build_info());
    let version = get_version();
    println!("{}", version);
    if matches.get_flag("version") {
        return 0;
    }

    let truncate_db = match matches.get_one::<String>("truncate_db").map(|s| s.parse::<u32>()) {
        None => None,
        Some(Ok(seqno)) => Some(seqno),
        Some(Err(e)) => {
            eprintln!("truncate_db value must be a valid u32: {}", e);
            return EXIT_CONFIG;
        }
    };

    let state_ttl = match matches.get_one::<String>("state_ttl") {
        None => None,
        Some(text) => match positive_seconds(text) {
            Some(seconds) => Some(seconds),
            None => {
                eprintln!("state-ttl should be positive");
                return EXIT_CONFIG;
            }
        },
    };

    let certificate_policy = match shard_overlay_certificate_policy(&matches) {
        Ok(policy) => policy,
        Err(error) => {
            eprintln!("{error}");
            return EXIT_CONFIG;
        }
    };

    // Scheduled before the configuration is read, as the reference engine
    // schedules it; the lines are logged once logging is set up.
    let shutdown_lines = match scheduled_shutdown::parse_all(&matches)
        .and_then(|times| scheduled_shutdown::schedule_all(&times))
    {
        Ok(lines) => lines,
        Err(error) => {
            eprintln!("failed to parse options: [Error : 0 : {error}]");
            return EXIT_CONFIG;
        }
    };

    let flags = EngineFlags {
        initial_sync_disabled: matches.get_flag("initial_sync_disabled"),
        force_check_db: matches.get_flag("force_check_db"),
        truncate_db,
    };
    let process_conf_and_exit = matches.get_flag("process_conf_and_exit");

    let config_dir_path = match matches.get_one::<String>("config") {
        Some(config) => config.as_str(),
        None => {
            eprintln!("Can't load config: config dir is not set!");
            return EXIT_CONFIG;
        }
    };

    let console_key =
        matches.get_one::<String>("console_key").map(|console_key| console_key.to_string());

    let zerostate_path = matches.get_one::<String>("zerostate").map(String::as_str);

    // The lock is taken before the configuration is read or generated.
    match acquire_config_lock(config_dir_path) {
        Ok(file) => {
            let _ = CONFIG_LOCK.set(file);
        }
        Err(error) => {
            eprintln!("{error}");
            return EXIT_CONFIG;
        }
    }

    let runtime = match build_runtime("Engine") {
        Ok(runtime) => runtime,
        Err(code) => return code,
    };
    let validator_runtime = match build_runtime("Validator") {
        Ok(runtime) => runtime,
        Err(code) => return code,
    };
    let liteserver_runtime = match build_runtime("Liteserver") {
        Ok(runtime) => runtime,
        Err(code) => return code,
    };

    let (mut config, created) = match runtime.block_on(async {
        TonNodeConfig::load_or_create(
            config_dir_path,
            CONFIG_NAME,
            None,
            DEFAULT_CONFIG_NAME,
            console_key,
        )
        .await
    }) {
        Ok(loaded) => loaded,
        Err(e) => {
            eprintln!("Can't load config: {e:?}");
            return EXIT_CONFIG;
        }
    };

    config.set_shard_overlay_certificate_policy(certificate_policy);
    if let Some(seconds) = state_ttl {
        config.set_state_ttl(seconds);
    }

    if created {
        let path = std::path::Path::new(config_dir_path).join(CONFIG_NAME);
        eprintln!("created config file '{}'", path.display());
        eprintln!("check it manually before continue");
        return 0;
    }

    if process_conf_and_exit {
        println!("Finish node because of --process-conf-and-exit flag is set");
        return 0;
    }

    if let Err(error) = init_logging(config.log_config_path().as_deref()) {
        eprintln!("{error}");
        return EXIT_CONFIG;
    }
    log::info!("{}", version);
    scheduled_shutdown::log_lines(&shutdown_lines);

    #[cfg(feature = "mirrornet")]
    if let Some(timeshift) = matches.get_one::<String>("timeshift") {
        let timeshift = match timeshift.parse::<i64>() {
            Ok(timeshift) => timeshift,
            Err(e) => {
                log::error!("Invalid timeshift value {timeshift}: {e}");
                return EXIT_CONFIG;
            }
        };
        if let Err(e) = UnixTime::set_timeshift(timeshift) {
            log::error!("Failed to set timeshift: {e}");
            return EXIT_CONFIG;
        }
        log::warn!("Node time is shifted by {} seconds", timeshift);
    }

    let metrics_handle = match config.metrics() {
        Ok(metrics) => metrics.map(|mc| (mc.address, engine::init_prometheus_recorder(&mc))),
        Err(e) => {
            log::error!("Bad metrics config: {e:?}");
            eprintln!("Bad metrics config: {e:?}");
            return EXIT_CONFIG;
        }
    };

    // Load secrets from vault to config
    if let Err(e) = runtime.block_on(SecretsVaultConfig::on_load(&mut config)) {
        log::error!("Can't load secrets from the vault: {e:?}");
        eprintln!("Can't load secrets from the vault: {e:?}");
        return EXIT_CONFIG;
    }

    if let Err(e) = preflight_config(&config) {
        log::error!("Configuration refused: {e:?}");
        eprintln!("Configuration refused: {e:?}");
        return EXIT_CONFIG;
    }

    #[cfg(feature = "trace_alloc_detail")]
    thread::spawn(|| {
        let mut file = File::create("trace.bin").unwrap();
        loop {
            let this = TRACEBUF_TAIL.load(Ordering::Relaxed);
            let next = if this == SIZE_TRACEBUF - 1 { 0 } else { this + 1 };
            if this == TRACEBUF_HEAD.load(Ordering::Relaxed) {
                thread::yield_now();
                continue;
            }
            let size = TRACEBUF[this].size.load(Ordering::Acquire);
            if size == 0 {
                thread::yield_now();
                continue;
            }
            let start = TRACEBUF[this].start.load(Ordering::Relaxed);
            if start == 0 {
                panic!("ZEROADDR_READ")
            }
            file.write_all(&start.to_le_bytes()).ok();
            file.write_all(&size.to_le_bytes()).ok();
            TRACEBUF[this].size.store(0, Ordering::Release);
            TRACEBUF_TAIL.store(next, Ordering::Release);
        }
    });

    #[cfg(feature = "trace_alloc")]
    thread::spawn(|| loop {
        thread::sleep(Duration::from_millis(30000));
        let count = GLOBAL.count.load(Ordering::Relaxed);
        let allocated = GLOBAL.allocated.load(Ordering::Relaxed);
        let overhead = GLOBAL.overhead.load(Ordering::Relaxed);
        log::info!(
            "Allocated {} + {} = {} bytes, {} objects",
            allocated,
            overhead,
            allocated + overhead,
            count
        );
    });

    let stopper = Arc::new(Stopper::new());
    let _ = PANIC_STOPPER.set(stopper.clone());
    if PANICKED.load(Ordering::SeqCst) {
        stopper.report_service_failure(0, "panic before the engine started".to_owned());
    }
    if let Err(error) = install_stop_signals(&runtime, stopper.clone()) {
        log::error!("{error}");
        eprintln!("{error}");
        return EXIT_RUNTIME;
    }

    let validator_rt_handle = validator_runtime.handle().clone();
    let liteserver_rt_handle = liteserver_runtime.handle().clone();
    let db_dir = config.internal_db_path().to_string();
    let clean_shutdown = runtime.block_on(async move {
        match start_engine(
            config,
            zerostate_path,
            validator_rt_handle,
            liteserver_rt_handle,
            flags,
            stopper.clone(),
            metrics_handle,
        )
        .await
        {
            Err(e) => {
                log::error!("Can't start node's Engine: {e:?}");
                eprintln!("Can't start node's Engine: {e:?}");
                false
            }
            Ok((engine, join_handle)) => {
                log::info!("Node services started.");
                if let Err(error) = join_handle.await {
                    stopper.report_service_failure(
                        0,
                        format!("Engine supervisor join failed: {error}"),
                    );
                }
                log::warn!("Still stopping node...");
                finish_node_shutdown(engine.wait_stop().await, &db_dir)
            }
        }
    });

    // Shut down all tokio runtimes with a 5sec timeout
    let shutdown_timeout = std::time::Duration::from_secs(5);
    runtime.shutdown_timeout(shutdown_timeout);
    validator_runtime.shutdown_timeout(shutdown_timeout);
    liteserver_runtime.shutdown_timeout(shutdown_timeout);
    if clean_shutdown {
        0
    } else {
        EXIT_RUNTIME
    }
}

// Keep clean-shutdown bookkeeping tied to the actual terminal result.
fn finish_node_shutdown(result: Result<()>, db_dir: &str) -> bool {
    match result {
        Ok(()) => {
            log::warn!("Node stopped");
            set_graceful_termination(db_dir);
            true
        }
        Err(error) => {
            log::error!("Node shutdown failed: {error}");
            eprintln!("Node shutdown failed: {error}");
            false
        }
    }
}

/// `--shutdown-at <unix time>`: at that time the process ends with status 0
/// at once, without an orderly stop, as the reference engine ends. The next
/// start recovers the database as after any unclean end. There is no
/// equivalent here of the reference engine's index flush before it ends.
mod scheduled_shutdown {
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    /// A line to log once logging is set up, with its level.
    pub(super) type Line = (log::Level, String);

    /// The values as the reference option parser reads an unsigned 32-bit
    /// integer: decimal digits only, without sign or spaces, within range.
    pub(super) fn parse(value: &str) -> std::result::Result<u32, String> {
        let refused = || format!("Can't parse \"{value}\" as number");
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(refused());
        }
        value.parse::<u32>().map_err(|_| refused())
    }

    pub(super) fn parse_all(matches: &clap::ArgMatches) -> std::result::Result<Vec<u32>, String> {
        matches.get_many::<String>("shutdown_at").into_iter().flatten().map(|v| parse(v)).collect()
    }

    fn unix_now() -> f64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs_f64())
            .unwrap_or(0.0)
    }

    /// Arms one timer per value; each is a monotonic deadline taken from the
    /// Unix time now, and the earliest ends the process.
    pub(super) fn schedule_all(times: &[u32]) -> std::result::Result<Vec<Line>, String> {
        let mut lines = Vec::new();
        for &at in times {
            let delay = f64::from(at) - unix_now();
            if delay < 0.0 {
                lines.push((
                    log::Level::Debug,
                    format!("Scheduled shutdown is in past ({at}.000000)"),
                ));
                continue;
            }
            lines.push((
                log::Level::Info,
                format!("Schedule shutdown for {at}.000000 (in {delay:.6}s)"),
            ));
            let deadline = Instant::now() + Duration::from_secs_f64(delay);
            std::thread::Builder::new()
                .name("scheduled shutdown".to_string())
                .spawn(move || end_at(deadline))
                .map_err(|error| format!("cannot schedule the shutdown: {error}"))?;
        }
        Ok(lines)
    }

    pub(super) fn log_lines(lines: &[Line]) {
        for (level, line) in lines {
            log::log!(*level, "{line}");
        }
    }

    fn end_at(deadline: Instant) {
        loop {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            std::thread::sleep(deadline - now);
        }
        log::warn!("Shutting down as scheduled");
        log::logger().flush();
        // SAFETY: `_exit` ends the process at once with status 0 and runs no
        // exit handlers, as the reference engine ends at this point.
        unsafe { libc::_exit(0) }
    }
}

#[cfg(test)]
#[path = "tests/test_scheduled_shutdown.rs"]
mod scheduled_shutdown_tests;

#[cfg(test)]
#[path = "tests/test_verbosity_logging.rs"]
mod verbosity_logging_tests;

#[cfg(test)]
mod shutdown_tests {
    use super::*;

    #[tokio::test]
    async fn failed_shutdown_keeps_database_recovery_beacon() {
        let directory = tempfile::tempdir().unwrap();
        let beacon = directory.path().join("ton_node.running");
        std::fs::write(&beacon, b"running").unwrap();
        let stopper = Arc::new(Stopper::new());
        stopper.acquire_stop(Engine::MASK_SERVICE_VALIDATOR_MANAGER);
        stopper.report_service_failure(
            Engine::MASK_SERVICE_VALIDATOR_MANAGER,
            "controlled validator teardown failure".to_owned(),
        );
        assert!(!finish_node_shutdown(
            stopper.wait_stop().await,
            directory.path().to_str().unwrap()
        ));
        assert!(beacon.exists(), "failed stop must require database recovery");
    }

    /// Every input of the reference table reads to the same value, and the
    /// time options accept exactly the inputs the reference accepts.
    #[test]
    fn time_options_read_numbers_like_the_reference() {
        let table = include_str!("tests/data/storage-gc-cli-options.tsv");
        let mut checked = 0;
        for line in table.lines() {
            let fields: Vec<&str> = line.split('\t').collect();
            if fields.first() != Some(&"to_double") {
                continue;
            }
            let input = if fields[1] == "-" {
                String::new()
            } else {
                let bytes: Vec<u8> = (0..fields[1].len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&fields[1][i..i + 2], 16).unwrap())
                    .collect();
                String::from_utf8(bytes).unwrap()
            };
            let expected: f64 = fields[2].parse().unwrap();
            let value = reference_to_double(&input);
            assert!(
                value == expected || (value == 0.0 && expected == 0.0),
                "{input:?}: {value} != {expected}"
            );
            assert_eq!(positive_seconds(&input).is_some(), fields[3] == "1", "{input:?}");
            checked += 1;
        }
        assert!(checked >= 50, "reference table not read");
        let default =
            table.lines().find_map(|line| line.strip_prefix("default\tstate_ttl\t")).unwrap();
        assert_eq!(default.parse::<f64>().unwrap(), crate::config::DEFAULT_STATE_TTL_SEC);
    }

    #[test]
    fn state_ttl_option_is_parsed_and_short_flags_exist() {
        let matches =
            build_command().try_get_matches_from(["rtos", "-s", "30.5", "-T", "7"]).unwrap();
        assert_eq!(matches.get_one::<String>("state_ttl").map(String::as_str), Some("30.5"));
        assert_eq!(matches.get_one::<String>("truncate_db").map(String::as_str), Some("7"));
        let matches = build_command().try_get_matches_from(["rtos", "--state-ttl", "-1"]).unwrap();
        assert_eq!(positive_seconds(matches.get_one::<String>("state_ttl").unwrap()), None);
    }

    #[test]
    fn exit_status_classes() {
        assert_eq!(final_disposition(RunEnd::Exit(0), 0, false), Disposition::Exit(0));
        assert_eq!(
            final_disposition(RunEnd::Exit(EXIT_CONFIG), 0, false),
            Disposition::Exit(EXIT_CONFIG)
        );
        assert_eq!(
            final_disposition(RunEnd::Exit(EXIT_RUNTIME), 0, false),
            Disposition::Exit(EXIT_RUNTIME)
        );
        // A panic on any thread turns a clean stop into a runtime failure.
        assert_eq!(final_disposition(RunEnd::Exit(0), 0, true), Disposition::Exit(EXIT_RUNTIME));
        assert_eq!(final_disposition(RunEnd::Panicked, 0, true), Disposition::Exit(EXIT_RUNTIME));
        // A stop signal decides the status whatever the cleanup did.
        for end in [RunEnd::Exit(0), RunEnd::Exit(EXIT_RUNTIME), RunEnd::Panicked] {
            assert_eq!(
                final_disposition(end, libc::SIGTERM, true),
                Disposition::Signal(libc::SIGTERM)
            );
        }
        assert_eq!(
            final_disposition(RunEnd::Exit(EXIT_RUNTIME), libc::SIGINT, false),
            Disposition::Signal(libc::SIGINT)
        );
    }

    #[test]
    fn config_lock_excludes_a_second_holder_in_another_process() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().to_str().unwrap();
        let held = acquire_config_lock(path).unwrap();
        // fcntl record locks are per process: probe from a child process.
        let probe = std::process::Command::new("python3")
            .arg("-c")
            .arg(
                "import fcntl,sys\n\
                 f=open(sys.argv[1],'r+')\n\
                 try:\n fcntl.lockf(f,fcntl.LOCK_EX|fcntl.LOCK_NB)\nexcept OSError:\n sys.exit(3)\n",
            )
            .arg(directory.path().join(CONFIG_LOCK_NAME))
            .status()
            .unwrap();
        assert_eq!(probe.code(), Some(3), "a held configuration lock must refuse a second holder");
        drop(held);
        assert!(acquire_config_lock(path).is_ok());
    }

    #[tokio::test]
    async fn successful_shutdown_clears_database_recovery_beacon() {
        let directory = tempfile::tempdir().unwrap();
        let beacon = directory.path().join("ton_node.running");
        std::fs::write(&beacon, b"running").unwrap();
        let stopper = Arc::new(Stopper::new());
        stopper.set_stop();
        assert!(finish_node_shutdown(
            stopper.wait_stop().await,
            directory.path().to_str().unwrap()
        ));
        assert!(!beacon.exists());
    }
}

pub(crate) mod history_read_budget;

mod repair_lease_binding;

mod repair_provenance;

mod publication_dependency_leases;

pub(crate) mod bounded_session_derivation;
