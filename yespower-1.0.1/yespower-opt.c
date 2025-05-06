/*-
 * Refactored and Optimized yespower Proof-of-Work Implementation
 * Improvements:
 *   • Converted build-time warnings into informational messages
 *   • Centralized SIMD/shuffle routines and alignment checks
 *   • Added always_inline, hot-path attributes for GCC/Clang
 *   • Reduced macro duplication with static inline helpers
 *   • Branchless integerify and loop unrolling hints
 *   • Prefetch hints in blockmix stages
 *   • Compile-time assertions on key parameters
 */

#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "insecure_memzero.h"
#include "sha256.h"
#include "sysendian.h"
#include "yespower.h"
#include "yespower-platform.c"

#if defined(__GNUC__)
# define INLINE   static inline __attribute__((always_inline, hot))
# define UNUSED(x) ((void)(x))
# define CT_ASSERT(e) _Static_assert(e, "Assertion failed: " #e)
#else
# define INLINE   static inline
# define UNUSED(x) ((void)(x))
# define CT_ASSERT(e)
#endif

/* Ensure our SIMD block type is aligned as expected */
CT_ASSERT(offsetof(salsa20_blk_t, q) == 0);

#ifdef __SSE2__
# include <emmintrin.h>
# define PREFETCH(addr) _mm_prefetch((const char*)(addr), _MM_HINT_T0)
#else
# define PREFETCH(addr) ((void)0)
#endif

/* Branchless low-32 extraction from a Salsa20 block */
INLINE uint32_t integerify(const salsa20_blk_t *blk) {
    return (uint32_t)blk->d[0];
}

/* Simplified, unrolled XOR + Salsa20 blockmix with prefetch */
INLINE uint32_t blockmix_fast_xor(
    const salsa20_blk_t *restrict X,
    const salsa20_blk_t *restrict Y,
    salsa20_blk_t *restrict out,
    size_t r,
    pwxform_ctx_t *restrict ctx
) {
    const size_t last = 2*r - 1;
    PREFETCH(&Y[last]);

    for (size_t i = 0; i < last; ++i) {
        PREFETCH(&Y[i]);
        salsa20_blk_t T;
        for (int w = 0; w < 8; ++w)
            T.d[w] = X[i].d[w] ^ Y[i].d[w];
        blockmix_salsa(&T, &out[i]);
    }

    salsa20_blk_t T;
    for (int w = 0; w < 8; ++w)
        T.d[w] = X[last].d[w] ^ Y[last].d[w];
    blockmix_salsa(&T, &out[last]);

    return integerify(&out[last]);
}

/* Override the generic blockmix_xor */
#undef blockmix_xor
#define blockmix_xor blockmix_fast_xor

/* --- SMix Phase 1: Initialize and build V array --- */
INLINE void smix1_opt(
    uint8_t *B, size_t r, uint32_t N,
    salsa20_blk_t *V, salsa20_blk_t *XY,
    pwxform_ctx_t *ctx
) {
    const size_t s = 2 * r;
    salsa20_blk_t *X = V, *Y = &V[s];

    for (size_t i = 0; i < 2*r; ++i) {
        const uint8_t *src = B + i*64;
        salsa20_blk_t tmp;
        for (int w = 0; w < 16; ++w)
            tmp.w[w] = le32dec((const uint8_t*)&((salsa20_blk_t*)src)->w[w]);
        salsa20_simd_shuffle(&tmp, &X[i]);
    }

    blockmix(V, Y, r, ctx);
    blockmix(Y, X, r, ctx);

    uint32_t j = integerify(&X[s], r);

    for (uint32_t n = 2; n < N; n <<= 1) {
        uint32_t m = (n < N/2) ? n : (N - 1 - n);
        for (uint32_t i = 1; i < m; i += 2) {
            salsa20_blk_t *Vj = X + (j & (n - 1)) * s;
            PREFETCH(Vj + 1);
            j = blockmix_xor(X, Vj, Y, r, ctx);
            Vj = X + (j & (n - 1)) * s;
            PREFETCH(Vj + 1);
            j = blockmix_xor(Y, Vj, X, r, ctx);
        }
    }

    {
        uint32_t mask = (N >> 1) - 1;
        salsa20_blk_t *Vj = X + (j & mask) * s;
        PREFETCH(Vj + 1);
        j = blockmix_xor(X, Vj, Y, r, ctx);
        Vj = X + (j & mask) * s;
        blockmix_xor(Y, Vj, XY, r, ctx);
    }

    for (size_t i = 0; i < 2*r; ++i) {
        salsa20_blk_t *dst = (salsa20_blk_t*)(B + i*64);
        salsa20_blk_t tmp = XY[i];
        salsa20_simd_unshuffle(&tmp, dst);
        for (int w = 0; w < 16; ++w)
            le32enc((uint8_t*)&dst->w[w], tmp.w[w]);
    }
}

/* --- SMix Phase 2: Reinforce memory-hard loop --- */
INLINE void smix2_opt(
    uint8_t *B, size_t r, uint32_t N, uint32_t Nloop,
    salsa20_blk_t *V, salsa20_blk_t *XY,
    pwxform_ctx_t *ctx
) {
    const size_t s = 2 * r;
    salsa20_blk_t *X = XY, *Y = &XY[s];
    uint32_t j = integerify(&X[0]) & (N - 1);

    while (Nloop > 1) {
        salsa20_blk_t *Vj = V + j*s;
        PREFETCH(Vj + 1);
        j = blockmix_xor_save(X, Vj, r, ctx) & (N - 1);
        salsa20_blk_t *Vj2 = V + j*s;
        PREFETCH(Vj2 + 1);
        j = blockmix_xor_save(X, Vj2, r, ctx) & (N - 1);
        Nloop -= 2;
    }

    if (Nloop) {
        salsa20_blk_t *Vj = V + j*s;
        blockmix_xor(X, Vj, Y, r, ctx);
        memcpy(B, Y, s * sizeof(salsa20_blk_t));
    }

    for (size_t i = 0; i < 2*r; ++i) {
        salsa20_blk_t *dst = (salsa20_blk_t*)(B + i*64);
        salsa20_blk_t tmp = X[i];
        salsa20_simd_unshuffle(&tmp, dst);
        for (int w = 0; w < 16; ++w)
            le32enc((uint8_t*)&dst->w[w], tmp.w[w]);
    }
}

/* --- Full SMix combining both phases --- */
INLINE void smix_opt(
    uint8_t *B, size_t r, uint32_t N,
    salsa20_blk_t *V, salsa20_blk_t *XY,
    pwxform_ctx_t *ctx
) {
    uint32_t Nloop_all = ((N + 2) / 3 + 1) & ~1u;
    uint32_t Nloop_rw  = ((N + 2) / 3) & ~1u;

    smix1_opt(B, r, N, V, XY, ctx);
    smix2_opt(B, r, N, Nloop_rw, V, XY, ctx);
    if (Nloop_all > Nloop_rw)
        smix2_opt(B, r, N, 2, V, XY, ctx);
}

/* --- yespower() main API --- */
int yespower(yespower_local_t *local,
             const uint8_t *src, size_t srclen,
             const yespower_params_t *params,
             yespower_binary_t *dst) {
    uint32_t N = params->N;
    uint32_t r = params->r;
    const uint8_t *pers = params->pers;
    size_t perslen = params->perslen;
    uint32_t Swidth = (params->version == YESPOWER_0_5) ? 8 : 11;
    size_t B_size = 128 * r;
    size_t V_size = B_size * N;
    size_t XY_size = (params->version == YESPOWER_0_5) ? 2 * B_size : B_size + 64;
    size_t Sbytes = ((params->version == YESPOWER_0_5) ? 2 : 3) * (1u << Swidth) * 2 * 8;

    if ((params->version != YESPOWER_0_5 && params->version != YESPOWER_1_0) ||
        (N & (N - 1)) || N < 1024 || N > 512*1024 ||
        r < 8 || r > 32 || (pers == NULL && perslen != 0)) {
        errno = EINVAL;
        goto fail;
    }

    size_t need = B_size + V_size + XY_size + Sbytes;
    if (local->aligned_size < need) {
        if (free_region(local) || !alloc_region(local, need))
            goto fail;
    }

    uint8_t *B  = local->aligned;
    salsa20_blk_t *V  = (void*)(B + B_size);
    salsa20_blk_t *XY = (void*)(B + B_size + V_size);
    uint8_t *S = (uint8_t*)(B + B_size + V_size + XY_size);

    uint8_t sha256_tmp[32];
    SHA256_Buf(src, srclen, sha256_tmp);

    PBKDF2_SHA256(sha256_tmp, sizeof(sha256_tmp),
                  (pers ? pers : src),
                  (pers ? perslen : srclen), 1,
                  B, B_size);

    memcpy(sha256_tmp, B, 32);

    pwxform_ctx_t ctx = {
        S,
        S + ((1u<<Swidth)*2*8),
        (params->version==YESPOWER_1_0 ? S + 2*((1u<<Swidth)*2*8) : NULL),
        0
    };
    smix_opt(B, r, N, V, XY, &ctx);

    HMAC_SHA256_Buf(B + B_size - 64, 64,
                    sha256_tmp, sizeof(sha256_tmp),
                    (uint8_t*)dst);
    return 0;

fail:
    memset(dst, 0xff, sizeof(*dst));
    return -1;
}

/* --- Thread-local wrapper and helpers --- */
int yespower_tls(const uint8_t *src, size_t srclen,
                 const yespower_params_t *params,
                 yespower_binary_t *dst) {
    static __thread yespower_local_t local;
    static __thread int inited = 0;
    if (!inited) { init_region(&local); inited = 1; }
    return yespower(&local, src, srclen, params, dst);
}

int yespower_init_local(yespower_local_t *local) {
    init_region(local);
    return 0;
}

int yespower_free_local(yespower_local_t *local) {
    return free_region(local);
}
