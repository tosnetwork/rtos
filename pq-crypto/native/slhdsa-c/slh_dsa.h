/*
 * Copyright (c) The slhdsa-c project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* === FIPS 205 Stateless Hash-Based Digital Signature Standard. */
/* API fo internal and "pure" variants. */

#ifndef _SLH_DSA_H_
#define _SLH_DSA_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <stdint.h>

#ifndef _SLH_PARAM_H_
  typedef struct slh_param_s slh_param_t;
#endif

  extern const slh_param_t slh_dsa_sha2_128s;
  size_t slh_sig_sz(const slh_param_t *prm);
  int slh_verify(const uint8_t *m, size_t m_sz, const uint8_t *sig,
                 size_t sig_sz, const uint8_t *ctx, size_t ctx_sz,
                 const uint8_t *pk, const slh_param_t *prm);

#ifdef __cplusplus
}
#endif

/* _SLH_DSA_H_ */
#endif
