/*
 * RTOS project modifications (2026-10-10): project and crate naming.
 * Copyright (C) 2019-2023 EverX. All Rights Reserved.
 * Modifications Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This file has been modified from its original version.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use rtos_block::ComputeSkipReason;
use rtos_vm::stack::StackItem;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ExecutorError {
    #[error("Invalid external message")]
    InvalidExtMessage,
    #[error("Transaction executor internal error: {0}")]
    TrExecutorError(String),
    #[error("Contract did not accept message, exit code: {0}")]
    NoAcceptError(i32, Option<StackItem>),
    #[error("Cannot pay for importing this external message")]
    NoFundsToImportMsg,
    #[error("Compute phase skipped while processing external inbound message with reason {:?}", .0)]
    ExtMsgComputeSkipped(ComputeSkipReason),
}

impl ExecutorError {
    pub fn external_rejection_code(&self) -> Option<i32> {
        match self {
            Self::NoAcceptError(code, _) => Some(*code),
            Self::ExtMsgComputeSkipped(_) => Some(0),
            _ => None,
        }
    }
}
