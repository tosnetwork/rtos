/* Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RTOS_CONSENSUS_SIGNER_CONFIG_H
#define RTOS_CONSENSUS_SIGNER_CONFIG_H
#define MLD_CONFIG_PARAMETER_SET 44
#define MLD_CONFIG_NAMESPACE_PREFIX rtos_pq_consensus_native
#define MLD_CONFIG_NO_RANDOMIZED_API
/* Portable pinned backend. Randomness is supplied by the Rust OS CSPRNG. */
#endif
