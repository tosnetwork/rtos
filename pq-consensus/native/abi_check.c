/* Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later */
#include "mldsa_native.h"
typedef char seed_size[(MLDSA_SEEDBYTES == 32) ? 1 : -1];
typedef char random_size[(MLDSA_RNDBYTES == 32) ? 1 : -1];
typedef char secret_size[(MLDSA44_SECRETKEYBYTES == 2560) ? 1 : -1];
typedef char public_size[(MLDSA44_PUBLICKEYBYTES == 1312) ? 1 : -1];
typedef char signature_size[(MLDSA44_BYTES == 2420) ? 1 : -1];
