/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
/* Fixed Pure SLH-DSA-SHA2-128s verification; no signing, RNG, or other suites. */
#define slh_verify rtos_slhdsa128s_verify_internal
#define slh_sig_sz rtos_slhdsa128s_sig_sz
#define slh_dsa_sha2_128s rtos_slhdsa128s_parameters
#define sha2_256_compress rtos_slhdsa_sha256_compress
#define sha2_256_init rtos_slhdsa_sha256_init
#define sha2_224_init rtos_slhdsa_sha224_init
#define sha2_256_copy rtos_slhdsa_sha256_copy
#define sha2_256_update rtos_slhdsa_sha256_update
#define sha2_256_final_pad rtos_slhdsa_sha256_final_pad
#define sha2_256_final_len rtos_slhdsa_sha256_final_len
#define sha2_256 rtos_slhdsa_sha256
#define sha2_224 rtos_slhdsa_sha224
#include "slhdsa-c/sha2_256.c"
#include "slhdsa-c/slh_sha2.c"
#include "slhdsa-c/slh_dsa.c"

int rtos_slhdsa128s_native_verify(const uint8_t *message, size_t message_len,
                                const uint8_t *context, size_t context_len,
                                const uint8_t *signature, size_t signature_len,
                                const uint8_t *key, size_t key_len)
{
    if (key_len != 32 || signature_len != 7856 || message_len > 8192 || context_len > 255)
        return -1;
    return slh_verify(message, message_len, signature, signature_len, context,
                      context_len, key, &slh_dsa_sha2_128s);
}
