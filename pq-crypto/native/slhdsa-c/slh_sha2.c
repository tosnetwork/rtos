/*
 * Copyright (c) The slhdsa-c project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* === Portable C code: Functions for instantiation of SLH-DSA with SHA2 */

#include <string.h>
#include "plat_local.h"
#include "sha2_api.h"
#include "slh_adrs.h"
#include "slh_var.h"

/* Cat 1: Hmsg(R, PK.seed, PK.root, M) = */
/* MGF1-SHA-256(R || PK.seed || SHA-256(R ||PK.seed || PK.root || */
/* M), m) */

static void sha2_256_h_msg(slh_var_t *var, uint8_t *h, const uint8_t *r,
                           const uint8_t *m, size_t m_sz, const uint8_t *ctx,
                           size_t ctx_sz)
{
  sha2_256_t sha2;
  size_t i;
  size_t n = var->prm->n;
  uint8_t buf[16 + 16 + 32 + 4];
  size_t mgf_sz;
  uint8_t *ctr;

  /* SHA-256(R || PK.seed || PK.root || M) */
  sha2_256_init(&sha2);
  sha2_256_update(&sha2, r, n);
  sha2_256_update(&sha2, var->pk_seed, n);
  sha2_256_update(&sha2, var->pk_root, n);

  /* add "pure" domain separator and context, if supplied */
  if (ctx_sz != SLH_CTX_SZ_NO_CONTEXT)
  {
    buf[0] = 0;
    buf[1] = ctx_sz & 0xFF;
    sha2_256_update(&sha2, buf, 2);
    sha2_256_update(&sha2, ctx, ctx_sz);
  }
  /* message */
  sha2_256_update(&sha2, m, m_sz);
  sha2_256_final(&sha2, buf + 2 * n);

  /* MGF1-SHA-256(R || PK.seed || .. */
  memcpy(buf, r, n);
  memcpy(buf + n, var->pk_seed, n);

  mgf_sz = 2 * n + 32 + 4;
  ctr = buf + mgf_sz - 4;

  /* MGF1 counter mode */
  for (i = 0; i < var->prm->m; i += 32)
  {
    uint32_t c = i / 32;
    ctr[0] = c >> 24;
    ctr[1] = (c >> 16) & 0xFF;
    ctr[2] = (c >> 8) & 0xFF;
    ctr[3] = c & 0xFF;

    sha2_256_init(&sha2);
    sha2_256_update(&sha2, buf, mgf_sz);
    if ((var->prm->m - i) >= 32)
    {
      sha2_256_final(&sha2, h + i);
    }
    else
    {
      sha2_256_final(&sha2, buf);
      memcpy(h + i, buf, var->prm->m - i);
    }
  }
}

/* Cat 3, 5: Hmsg(R, PK.seed, PK.root, M) = */
/* MGF1-SHA-512(R || PK.seed || SHA-512(R || PK.seed || PK.root || */
/* M), m) */



/* insert ARDSc. */

static void sha2_256_adrsc(sha2_256_t *sha2, const slh_var_t *var)
{
  uint8_t buf[22];
  adrsc_22(var, buf);
  sha2_256_update(sha2, buf, 22);
}



/* Cat 1, 3, 5: PRF(PK.seed, SK.seed, ADRS) = */
/* Trunc_n(SHA-256(PK.seed || toByte(0, 64 − n) || ADRSc || */
/* SK.seed)) */



/* Cat 1: PRFmsg(SK.prf, opt_rand, M) = */
/* Trunc_n(HMAC-SHA-256(SK.prf, opt_rand || M)) */



/* Cat 3, 5: PRFmsg(SK.prf, opt_rand, M) = */
/* Trunc_n(HMAC-SHA-512(SK.prf, opt_rand || M)) */



/* Cat 1: T_l(PK.seed, ADRS, M1 ) = */
/* Trunc_n(SHA-256(PK.seed || toByte(0, 64 − n) || ADRSc || Ml )) */

static void sha2_256_tl(slh_var_t *var, uint8_t *h, const uint8_t *m,
                        size_t m_sz)
{
  sha2_256_t sha2;
  size_t n = var->prm->n;

  sha2_256_copy(&sha2, &var->sha2_256_pk_seed);
  sha2_256_adrsc(&sha2, var);
  sha2_256_update(&sha2, m, m_sz);
  sha2_256_final_len(&sha2, h, n);
}

/* Cat 1: F(PK.seed, ADRS, M1 ) = */
/* Trunc_n(SHA-256(PK.seed || toByte(0, 64 − n) || ADRSc || M1 )) */

static void sha2_256_f(slh_var_t *var, uint8_t *h, const uint8_t *m1)
{
  sha2_256_tl(var, h, m1, var->prm->n);
}

/* Cat 1: H(PK.seed, ADRS, M2 ) = */
/* Trunc_n(SHA-256(PK.seed || toByte(0, 64 − n) || ADRSc || M2 )) */

static void sha2_256_h(slh_var_t *var, uint8_t *h, const uint8_t *m1,
                       const uint8_t *m2)
{
  sha2_256_t sha2;
  size_t n = var->prm->n;

  sha2_256_copy(&sha2, &var->sha2_256_pk_seed);
  sha2_256_adrsc(&sha2, var);
  sha2_256_update(&sha2, m1, n);
  sha2_256_update(&sha2, m2, n);
  sha2_256_final_len(&sha2, h, n);
}

/* Cat 3, 5: Tl(PK.seed, ADRS, Ml ) = */
/* Trunc_n(SHA-512(PK.seed || toByte(0, 128 − n) || ADRSc || Ml )) */



/* Cat 3, 5: H(PK.seed, ADRS, M2 ) = */
/* Trunc_n(SHA-512(PK.seed || toByte(0, 128 − n) || ADRSc || M2 )) */



/* create a context */

static void sha2_mk_var(slh_var_t *var, const uint8_t *pk, const uint8_t *sk,
                        const slh_param_t *prm)
{
  uint8_t buf[128 - 24];
  size_t n = prm->n;
  var->prm = prm;

  var->prm = prm; /* store fixed parameters */
  (void)sk; /* Verification-only profile; no private key path. */
  memcpy(var->pk_seed, pk, n);
  memcpy(var->pk_root, pk + n, n);

  /* eliminate the first compression function */
  memset(buf, 0x00, sizeof(buf));
  sha2_256_init(&var->sha2_256_pk_seed);
  sha2_256_update(&var->sha2_256_pk_seed, var->pk_seed, n);
  sha2_256_update(&var->sha2_256_pk_seed, buf, 64 - n);

  /* local ADRS buffer */
  var->adrs = &var->t_adrs;
}

/* === Chaining function used in WOTS+ */
/* Algorithm 5: chain(X, i, s, PK.seed, ADRS) */

static void sha2_256_chain(slh_var_t *var, uint8_t *tmp, const uint8_t *x,
                           uint32_t i, uint32_t s)
{
  uint32_t j;
  size_t n = var->prm->n;
  sha2_256_t sha2;
  uint32_t sp[8 + 24];
  uint8_t *mp = (uint8_t *)&sp[8];
  uint8_t *op = (uint8_t *)&sha2.s[8];

  /* these cases exist */
  if (s == 0)
  {
    memcpy(tmp, x, n);
    return;
  }

  /* set initial address */
  adrs_set_hash_address(var, i);

  /* initial set-up */
  sha2_256_copy(&sha2, &var->sha2_256_pk_seed);
  sha2_256_adrsc(&sha2, var);
  sha2_256_update(&sha2, x, n);
  if (s == 1)
  {
    /* just one hash */
    sha2_256_final_len(&sha2, tmp, n);
    return;
  }
  sha2_256_final_pad(&sha2);
  memcpy(sp, sha2.s, sizeof(sp));
  sha2_256_compress(sp);

  /* iteration */
  for (j = 1; j < s; j++)
  {
    memcpy(mp + 22, sp, n);        /* copy result back to input */
    slh_tobyte(mp + 18, i + j, 4); /* hash address, last part of ADSc */
    memcpy(sp, sha2.s, 32 + 18);   /* PK.seed compressed, start of ADRSc */
    memcpy(mp + 22 + n, op + 22 + n, 64 - 22 - n); /* padding */
    sha2_256_compress(sp);
  }

  /* final output */
  memcpy(tmp, sp, n);
}

/* Combination WOTS PRF + Chain */



/* Combination FORS PRF + F (if s == 1) */



/* 10.2.   SLH-DSA Using SHA2 for Security Category 1 */

const slh_param_t slh_dsa_sha2_128s = {/* .alg_id = */ "SLH-DSA-SHA2-128s",
                                       /* .n = */ 16,
                                       /* .h = */ 63,
                                       /* .d = */ 7,
                                       /* .hp = */ 9,
                                       /* .a = */ 12,
                                       /* .k = */ 14,
                                       /* .lg_w = */ 4,
                                       /* .m = */ 30,
                                       /* .mk_var = */ sha2_mk_var,
                                       /* .chain = */ sha2_256_chain,
                                       /* .wots_chain = */ NULL,
                                       /* .fors_hash = */ NULL,
                                       /* .h_msg = */ sha2_256_h_msg,
                                       /* .prf = */ NULL,
                                       /* .prf_msg = */ NULL,
                                       /* .h_f = */ sha2_256_f,
                                       /* .h_h = */ sha2_256_h,
                                       /* .h_t = */ sha2_256_tl};

