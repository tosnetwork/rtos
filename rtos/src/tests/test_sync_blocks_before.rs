/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
use super::{EngineOperations, DEFAULT_SYNC_BLOCKS_BEFORE};

struct BareEngine;

#[async_trait::async_trait]
impl EngineOperations for BareEngine {}

#[test]
fn initial_sync_window_defaults_to_one_hour() {
    assert_eq!(DEFAULT_SYNC_BLOCKS_BEFORE, 3600);
    assert_eq!(BareEngine.sync_blocks_before(), 3600);
}
