// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
/// Raw Simplex version predicates. Feature flags do not admit an unsupported
/// version; session admission must additionally check `supported`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimplexProtocolVersion(pub u32);

impl SimplexProtocolVersion {
    pub const MAX_SUPPORTED: u32 = 2;
    pub const fn supported(self) -> bool {
        self.0 <= Self::MAX_SUPPORTED
    }
    pub const fn enable_block_sync(self) -> bool {
        self.0 == 1
    }
    pub const fn use_new_db_names(self) -> bool {
        self.0 >= 2
    }
    pub const fn observers_in_private_overlay(self) -> bool {
        self.0 >= 2
    }
    pub const fn enable_plumtree_broadcast(self) -> bool {
        self.0 >= 2
    }
}
