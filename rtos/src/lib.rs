/*
 * Copyright (C) 2019-2024 EverX. All Rights Reserved.
 * Modifications Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This file has been modified from its original version.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
pub mod archive_import;
pub mod block;
pub mod block_proof;
pub mod boot;
pub(crate) mod retired_history;
pub(crate) mod historical_recovery;
pub mod collator_test_bundle;
pub mod config;
pub mod confirmed_blocks;
pub mod engine;
pub mod engine_operations;
pub mod engine_traits;
pub mod served_masterchain;
pub mod error;
pub mod ext_messages;
pub mod full_node;
pub mod internal_db;
pub mod macros;
pub mod network;
mod network_db;
#[cfg(feature = "isolated-consensus-signing")]
pub use network_db::DbNetworkBinding;
pub mod propagation_outbox;
pub(crate) mod propagation_outbox_auth;
pub(crate) mod publication_worker;
pub(crate) mod publication_repair;
pub mod rng;
pub mod rpc_server;
pub mod shard_state;
pub mod shard_states_keeper;
pub mod sync;
pub mod types;
pub mod validating_utils;
pub mod validator;

#[cfg(not(feature = "xp25"))]
mod shard_blocks;
#[cfg(feature = "xp25")]
mod shard_blocks_intershard;
#[cfg(feature = "xp25")]
mod shard_blocks {
    pub use crate::shard_blocks_intershard::*;
}

include!("../../common/src/info.rs");

#[cfg(test)]
#[path = "tests/test_helper.rs"]
pub mod test_helper;

#[cfg(test)]
#[path = "tests/test_disk_full_validator_state.rs"]
mod disk_full_validator_state_tests;

#[cfg(test)]
#[path = "tests/test_sst_validator_lease.rs"]
mod sst_validator_lease_tests;

#[cfg(test)]
#[path = "tests/test_disk_full_persistent_files.rs"]
mod disk_full_persistent_files_tests;

pub(crate) mod history_read_budget;

mod repair_lease_binding;

mod repair_provenance;

mod publication_dependency_leases;

pub(crate) mod bounded_session_derivation;
