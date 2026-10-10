// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use crate::Error;
use rtos_block::{derive_consensus_key_id, PqConsensusKey, MLDSA44_ALGORITHM_ID};
use rtos_pq_crypto::{MAX_MESSAGE_BYTES, PUBLIC_KEY_BYTES, SIGNATURE_BYTES, SIMPLEX_CONTEXT};
use std::{
    collections::BTreeSet,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex, OnceLock,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

pub const SEED_BYTES: usize = 32;
const SECRET_BYTES: usize = 2560;
pub const CONFIG_VOTE_CONTEXT: &[u8] = b"TOS-VALIDATOR-CONFIG-VOTE-v1";
pub const ELECTION_CONTEXT: &[u8] = b"TOS-VALIDATOR-ELECTION-v1";

extern "C" {
    fn rtos_pq_consensus_native_keypair_internal(pk: *mut u8, sk: *mut u8, seed: *const u8) -> i32;
    fn rtos_pq_consensus_native_signature_internal(
        sig: *mut u8,
        message: *const u8,
        message_len: usize,
        prefix: *const u8,
        prefix_len: usize,
        randomness: *const u8,
        secret: *const u8,
        external_mu: i32,
    ) -> i32;
}

fn retired_keys() -> &'static Mutex<BTreeSet<[u8; 32]>> {
    static KEYS: OnceLock<Mutex<BTreeSet<[u8; 32]>>> = OnceLock::new();
    KEYS.get_or_init(Mutex::default)
}
fn registry() -> std::sync::MutexGuard<'static, BTreeSet<[u8; 32]>> {
    // Losing retirement records must never turn a failed registry into a fresh
    // one. Allocation failure also aborts through Rust's allocation handler.
    retired_keys().lock().unwrap_or_else(|_| std::process::abort())
}
pub fn consensus_key_retired(key_id: &[u8; 32]) -> bool {
    registry().contains(key_id)
}
fn retire(key_id: [u8; 32]) {
    registry().insert(key_id);
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsensusSignature {
    pub algorithm_id: u16,
    pub bytes: [u8; SIGNATURE_BYTES],
}

/// Secret material cannot be cloned, formatted, serialized or exported. Share
/// an immutable Arc instead. The deadline is fixed before a store can be shared.
pub struct ConsensusKeyStore {
    key: PqConsensusKey,
    secret: Box<Zeroizing<[u8; SECRET_BYTES]>>,
    expire_at: u32,
    signatures_produced: AtomicU64,
    refused_after_expiry: AtomicU64,
}

impl ConsensusKeyStore {
    /// The caller retains responsibility for wiping its own seed buffer.
    pub fn from_seed(seed: &[u8], expire_at: u32) -> Result<Self, Error> {
        if seed.len() != SEED_BYTES {
            return Err(Error::SeedLength(seed.len()));
        }
        let mut public = [0; PUBLIC_KEY_BYTES];
        let mut secret = Box::new(Zeroizing::new([0; SECRET_BYTES]));
        // SAFETY: all buffers have the pinned ABI widths, remain live for the
        // synchronous call, and do not alias. Native code retains no pointers.
        let code = unsafe {
            rtos_pq_consensus_native_keypair_internal(
                public.as_mut_ptr(),
                secret.as_mut_ptr(),
                seed.as_ptr(),
            )
        };
        if code != 0 {
            return Err(Error::Backend(code));
        }
        let key = PqConsensusKey {
            algorithm_id: MLDSA44_ALGORITHM_ID,
            key_id: derive_consensus_key_id(MLDSA44_ALGORITHM_ID, &public),
            public_key: public.to_vec(),
        };
        if consensus_key_retired(key.key_id.as_array()) {
            return Err(Error::Retired);
        }
        Ok(Self {
            key,
            secret,
            expire_at,
            signatures_produced: AtomicU64::new(0),
            refused_after_expiry: AtomicU64::new(0),
        })
    }
    pub fn generate(expire_at: u32) -> Result<Self, Error> {
        let mut seed = Zeroizing::new([0; SEED_BYTES]);
        getrandom::getrandom(seed.as_mut()).map_err(|_| Error::Randomness)?;
        Self::from_seed(seed.as_ref(), expire_at)
    }
    pub fn consensus_key(&self) -> &PqConsensusKey {
        &self.key
    }
    pub fn expire_at(&self) -> u32 {
        self.expire_at
    }
    pub fn retired(&self) -> bool {
        consensus_key_retired(self.key.key_id.as_array())
    }
    /// A custody observation past the deadline also permanently retires this
    /// identity in this process. valid_from is a stake-election rule only.
    pub fn expired_at(&self, now: u64) -> bool {
        if self.retired() {
            return true;
        }
        if self.expire_at != 0 && now >= u64::from(self.expire_at) {
            retire(*self.key.key_id.as_array());
            return true;
        }
        false
    }
    pub fn expired_now(&self) -> bool {
        self.expired_with_clock(system_clock)
    }
    fn expired_with_clock(&self, clock: impl FnOnce() -> Option<u64>) -> bool {
        if self.retired() {
            return true;
        }
        if self.expire_at == 0 {
            return false;
        }
        match clock() {
            Some(now) => self.expired_at(now),
            None => {
                retire(*self.key.key_id.as_array());
                true
            }
        }
    }
    pub fn consensus_signatures_produced(&self) -> u64 {
        self.signatures_produced.load(Ordering::Relaxed)
    }
    pub fn signatures_refused_after_expiry(&self) -> u64 {
        self.refused_after_expiry.load(Ordering::Relaxed)
    }
    pub fn sign_consensus(&self, message: &[u8]) -> Result<ConsensusSignature, Error> {
        let signature =
            self.sign_within_deadline(message, SIMPLEX_CONTEXT, system_clock, native_sign)?;
        self.signatures_produced.fetch_add(1, Ordering::Relaxed);
        Ok(signature)
    }
    pub fn sign_config_vote(&self, message: &[u8]) -> Result<ConsensusSignature, Error> {
        self.sign_within_deadline(message, CONFIG_VOTE_CONTEXT, system_clock, native_sign)
    }
    pub fn sign_election(&self, message: &[u8]) -> Result<ConsensusSignature, Error> {
        self.sign_within_deadline(message, ELECTION_CONTEXT, system_clock, native_sign)
    }
    // No public arbitrary-context API or replaceable clock/backend. Test-only
    // callers in this crate exercise deadline crossing through this same path.
    pub(crate) fn sign_within_deadline(
        &self,
        message: &[u8],
        context: &[u8],
        clock: impl Fn() -> Option<u64>,
        backend: impl FnOnce(&[u8], &[u8], &[u8; SECRET_BYTES]) -> Result<[u8; SIGNATURE_BYTES], Error>,
    ) -> Result<ConsensusSignature, Error> {
        let refuse = || {
            if self.expired_with_clock(&clock) {
                self.refused_after_expiry.fetch_add(1, Ordering::Relaxed);
                Err(Error::Expired)
            } else {
                Ok(())
            }
        };
        refuse()?;
        if message.len() > MAX_MESSAGE_BYTES {
            return Err(Error::MessageTooLong);
        }
        let signature = backend(message, context, &self.secret)?;
        refuse()?;
        Ok(ConsensusSignature { algorithm_id: MLDSA44_ALGORITHM_ID, bytes: signature })
    }
}
fn system_clock() -> Option<u64> {
    SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|time| time.as_secs())
}

pub(crate) fn native_sign(
    message: &[u8],
    context: &[u8],
    secret: &[u8; SECRET_BYTES],
) -> Result<[u8; SIGNATURE_BYTES], Error> {
    // Only the three frozen public entry points reach this private routine.
    assert!(matches!(context, SIMPLEX_CONTEXT | CONFIG_VOTE_CONTEXT | ELECTION_CONTEXT));
    let mut prefix = Vec::with_capacity(2 + context.len());
    prefix.extend_from_slice(&[0, context.len() as u8]);
    prefix.extend_from_slice(context);
    let mut random = Zeroizing::new([0; 32]);
    getrandom::getrandom(random.as_mut()).map_err(|_| Error::Randomness)?;
    let mut signature = [0; SIGNATURE_BYTES];
    let empty = 0;
    let message_ptr = if message.is_empty() { &empty } else { message.as_ptr() };
    // SAFETY: fixed-size output, secret and randomness match the C ABI; input
    // slice lengths are exact, no buffers alias, and no pointer escapes the call.
    let code = unsafe {
        rtos_pq_consensus_native_signature_internal(
            signature.as_mut_ptr(),
            message_ptr,
            message.len(),
            prefix.as_ptr(),
            prefix.len(),
            random.as_ptr(),
            secret.as_ptr(),
            0,
        )
    };
    if code != 0 {
        return Err(Error::Backend(code));
    }
    Ok(signature)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn poisoned_registry_aborts() {
        use std::os::unix::process::ExitStatusExt;
        if std::env::var_os("RTOS_PQ_REGISTRY_POISON_CHILD").is_some() {
            // A controlled subprocess must not leave a core file containing
            // other tests' memory or consume disk space when it aborts.
            let limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) }, 0);
            let _ = std::panic::catch_unwind(|| {
                let _guard = retired_keys().lock().unwrap();
                panic!("controlled registry poisoning");
            });
            consensus_key_retired(&[0; 32]);
            panic!("a poisoned retirement registry was silently reused");
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "store::tests::poisoned_registry_aborts", "--nocapture"])
            .env("RTOS_PQ_REGISTRY_POISON_CHILD", "1")
            .output()
            .unwrap();
        assert_eq!(
            output.status.signal(),
            Some(libc::SIGABRT),
            "child output: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
