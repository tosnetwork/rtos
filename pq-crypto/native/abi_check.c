/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include "mldsa_native.h"

/* Keep the Rust ABI constants checked against the pinned C header at build time. */
typedef char rtos_mldsa44_public_key_size[(MLDSA44_PUBLICKEYBYTES == 1312) ? 1 : -1];
typedef char rtos_mldsa44_signature_size[(MLDSA44_BYTES == 2420) ? 1 : -1];
typedef char rtos_mldsa44_invalid_signature[(MLD_ERR_INVALID_SIGNATURE == -6) ? 1 : -1];

