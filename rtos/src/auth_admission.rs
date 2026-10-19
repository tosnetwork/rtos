// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! AUTH policy admission of every masterchain state the node adopts.
//!
//! A state becomes trusted (published head, restored head, initial state) only
//! after its configuration passes ConfigParam48 admission: standalone when no
//! trusted state precedes it, otherwise as a transition from the trusted
//! predecessor. Any configuration lookup failure, including a pruned proof
//! cell, refuses the state; it is never read as an absent configuration.

use crate::{error::AuthPolicyRefused, shard_state::ShardStateStuff};
use rtos_block::{validate_auth_policy_admission, ConfigParams, Result};

#[cfg(test)]
pub(crate) mod test_override {
    use rtos_block::{BlockIdExt, ConfigParams};
    use std::sync::Mutex;

    // Tests replace the configuration a given state reports, on whichever side
    // of admission that state appears. Keyed by full block identity, so
    // concurrently running networks never see each other's entries.
    static CONFIGS: Mutex<Vec<(BlockIdExt, ConfigParams)>> = Mutex::new(Vec::new());

    pub(crate) fn set(id: &BlockIdExt, config: ConfigParams) {
        let mut configs = CONFIGS.lock().unwrap_or_else(|e| e.into_inner());
        configs.retain(|(known, _)| known != id);
        configs.push((id.clone(), config));
    }

    pub(crate) fn clear(id: &BlockIdExt) {
        CONFIGS.lock().unwrap_or_else(|e| e.into_inner()).retain(|(known, _)| known != id);
    }

    pub(super) fn get(id: &BlockIdExt) -> Option<ConfigParams> {
        CONFIGS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|(known, _)| known == id)
            .map(|(_, config)| config.clone())
    }
}

fn with_config<T>(
    state: &ShardStateStuff,
    f: impl FnOnce(Result<&ConfigParams>) -> Result<T>,
) -> Result<T> {
    #[cfg(test)]
    if let Some(config) = test_override::get(state.block_id()) {
        return f(Ok(&config));
    }
    f(state.config_params())
}

fn refusal(
    context: &str,
    id: &rtos_block::BlockIdExt,
    error: rtos_block::Error,
) -> rtos_block::Error {
    AuthPolicyRefused(format!("{context} {id}: {error}")).into()
}

/// Admit `candidate` after `previous` (the trusted predecessor), or on its own
/// when no trusted state precedes it. A refusal is `AuthPolicyRefused`
/// with `context` prefixed to the reason.
pub(crate) fn admit_auth_policy_state(
    context: &str,
    candidate: &ShardStateStuff,
    previous: Option<&ShardStateStuff>,
) -> Result<()> {
    let result = with_config(candidate, |candidate_config| match previous {
        None => validate_auth_policy_admission(candidate_config, None),
        Some(previous) => with_config(previous, |previous_config| {
            validate_auth_policy_admission(candidate_config, Some(previous_config))
        }),
    });
    result.map_err(|error| refusal(context, candidate.block_id(), error))
}
