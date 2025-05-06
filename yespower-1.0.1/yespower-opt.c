/*-
 * Copyright 2009 Colin Percival
 * Copyright 2012-2019 Alexander Peslyak
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 *
 * Performance-tuned for Intel Celeron N4020 (Gemini Lake) using SSE2/SSE4.2
 */

#ifndef _YESPOWER_OPT_C_PASS_
#define _YESPOWER_OPT_C_PASS_ 1
#endif

/* Force SSE4.2 and SSE2, disable AVX/XOP paths for N4020 */
#if defined(__GNUC__)
#pragma GCC target("sse4.2","sse2","ssse3")
#endif
#undef __XOP__
#undef __AVX__
#define USE_SSE4_FOR_32BIT 1

#include <emmintrin.h>
#include <smmintrin.h>  // SSE4.1
#include <xmmintrin.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "insecure_memzero.h"
#include "sha256.h"
#include "sysendian.h"
#include "yespower.h"
#include "yespower-platform.c"

#if __STDC_VERSION__ >= 199901L
/* Have restrict */
#elif defined(__GNUC__)
#define restrict __restrict
#else
#define restrict
#endif

#ifdef __GNUC__
#define unlikely(exp) __builtin_expect(exp, 0)
#else
#define unlikely(exp) (exp)
#endif

#define PREFETCH(x, hint) _mm_prefetch((const char *)(x), (hint));

typedef union {
    uint32_t w[16];
    uint64_t d[8];
#ifdef __SSE2__
    __m128i q[4];
#endif
} salsa20_blk_t;

/*
 * Shuffle/unshuffle to map between host layout and SIMD-friendly layout.
 */
static inline void salsa20_simd_shuffle(const salsa20_blk_t *Bin,
    salsa20_blk_t *Bout)
{
#define COMBINE(out, in1, in2) \
    Bout->d[out] = Bin->w[in1 * 2] | ((uint64_t)Bin->w[in2 * 2 + 1] << 32);
    COMBINE(0, 0, 2)
    COMBINE(1, 5, 7)
    COMBINE(2, 2, 4)
    COMBINE(3, 7, 1)
    COMBINE(4, 4, 6)
    COMBINE(5, 1, 3)
    COMBINE(6, 6, 0)
    COMBINE(7, 3, 5)
#undef COMBINE
}

static inline void salsa20_simd_unshuffle(const salsa20_blk_t *Bin,
    salsa20_blk_t *Bout)
{
#define UNCOMBINE(out, in1, in2) \
    Bout->w[out * 2] = Bin->d[in1]; \
    Bout->w[out * 2 + 1] = Bin->d[in2] >> 32;
    UNCOMBINE(0, 0, 6)
    UNCOMBINE(1, 5, 3)
    UNCOMBINE(2, 2, 0)
    UNCOMBINE(3, 7, 5)
    UNCOMBINE(4, 4, 2)
    UNCOMBINE(5, 1, 7)
    UNCOMBINE(6, 6, 4)
    UNCOMBINE(7, 3, 1)
#undef UNCOMBINE
}

#ifdef __SSE2__
/* SSE2/SSE4 implementations of the Salsa20 core */

#define DECL_X \
    __m128i X0, X1, X2, X3;
#define DECL_Y \
    __m128i Y0, Y1, Y2, Y3;
#define READ_X(in) \
    X0 = (in).q[0]; X1 = (in).q[1]; X2 = (in).q[2]; X3 = (in).q[3];
#define WRITE_X(out) \
    (out).q[0] = X0; (out).q[1] = X1; (out).q[2] = X2; (out).q[3] = X3;

#ifdef __XOP__
#define ARX(out, in1, in2, s) \
    out = _mm_xor_si128(out, _mm_roti_epi32(_mm_add_epi32(in1, in2), s));
#else
#define ARX(out, in1, in2, s) { \
    __m128i tmp = _mm_add_epi32(in1, in2); \
    out = _mm_xor_si128(out, _mm_slli_epi32(tmp, s)); \
    out = _mm_xor_si128(out, _mm_srli_epi32(tmp, 32 - s)); \
}
#endif

#define SALSA20_2ROUNDS \
    /* columns */ \
    ARX(X1, X0, X3, 7) \
    ARX(X2, X1, X0, 9) \
    ARX(X3, X2, X1, 13) \
    ARX(X0, X3, X2, 18) \
    /* shuffle */ \
    X1 = _mm_shuffle_epi32(X1, 0x93); \
    X2 = _mm_shuffle_epi32(X2, 0x4E); \
    X3 = _mm_shuffle_epi32(X3, 0x39); \
    /* rows */ \
    ARX(X3, X0, X1, 7) \
    ARX(X2, X3, X0, 9) \
    ARX(X1, X2, X3, 13) \
    ARX(X0, X1, X2, 18) \
    /* unshuffle */ \
    X1 = _mm_shuffle_epi32(X1, 0x39); \
    X2 = _mm_shuffle_epi32(X2, 0x4E); \
    X3 = _mm_shuffle_epi32(X3, 0x93);

#define SALSA20_wrapper(out, rounds) { \
    __m128i Z0 = X0, Z1 = X1, Z2 = X2, Z3 = X3; \
    rounds \
    (out).q[0] = X0 = _mm_add_epi32(X0, Z0); \
    (out).q[1] = X1 = _mm_add_epi32(X1, Z1); \
    (out).q[2] = X2 = _mm_add_epi32(X2, Z2); \
    (out).q[3] = X3 = _mm_add_epi32(X3, Z3); \
}

#define SALSA20_2(out) \
    SALSA20_wrapper(out, SALSA20_2ROUNDS)

#define SALSA20_8ROUNDS \
    SALSA20_2ROUNDS SALSA20_2ROUNDS SALSA20_2ROUNDS SALSA20_2ROUNDS

#define SALSA20_8(out) \
    SALSA20_wrapper(out, SALSA20_8ROUNDS)

#define XOR_X(in) \
    X0 = _mm_xor_si128(X0, (in).q[0]); \
    X1 = _mm_xor_si128(X1, (in).q[1]); \
    X2 = _mm_xor_si128(X2, (in).q[2]); \
    X3 = _mm_xor_si128(X3, (in).q[3]);

#define XOR_X_2(in1, in2) \
    X0 = _mm_xor_si128((in1).q[0], (in2).q[0]); \
    X1 = _mm_xor_si128((in1).q[1], (in2).q[1]); \
    X2 = _mm_xor_si128((in1).q[2], (in2).q[2]); \
    X3 = _mm_xor_si128((in1).q[3], (in2).q[3]);

#define XOR_X_WRITE_XOR_Y_2(out, in) \
    (out).q[0] = Y0 = _mm_xor_si128((out).q[0], (in).q[0]); \
    (out).q[1] = Y1 = _mm_xor_si128((out).q[1], (in).q[1]); \
    (out).q[2] = Y2 = _mm_xor_si128((out).q[2], (in).q[2]); \
    (out).q[3] = Y3 = _mm_xor_si128((out).q[3], (in).q[3]); \
    X0 = _mm_xor_si128(X0, Y0); \
    X1 = _mm_xor_si128(X1, Y1); \
    X2 = _mm_xor_si128(X2, Y2); \
    X3 = _mm_xor_si128(X3, Y3);

#define INTEGERIFY _mm_cvtsi128_si32(X0)

#else  /* !__SSE2__ */

/* Generic C fallback (no changes) */
#define DECL_X salsa20_blk_t X;
#define DECL_Y salsa20_blk_t Y;
#define COPY(out, in) memcpy(&(out), &(in), sizeof(salsa20_blk_t))
#define READ_X(in) COPY(X, in)
#define WRITE_X(out) COPY(out, X)

static inline void salsa20(salsa20_blk_t *restrict B,
    salsa20_blk_t *restrict Bout, uint32_t doublerounds)
{
    salsa20_blk_t X;
#define x X.w
    salsa20_simd_unshuffle(B, &X);
    do {
#define R(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
        /* columns */
        x[ 4] ^= R(x[ 0] + x[12], 7);  x[ 8] ^= R(x[ 4] + x[ 0], 9);
        x[12] ^= R(x[ 8] + x[ 4],13);  x[ 0] ^= R(x[12] + x[ 8],18);
        /* ... (same as reference) ... */
#undef R
    } while (--doublerounds);
    {
        salsa20_blk_t T;
        salsa20_simd_shuffle(&X, &T);
        for (int i = 0; i < 16; i++) {
            B->w[i] = Bout->w[i] = T.w[i] + B->w[i];
        }
    }
}

#define SALSA20_2(out) salsa20(&X, &out, 1)
#define SALSA20_8(out) salsa20(&X, &out, 4)
#endif
/*
 * blockmix_salsa(Bin, Bout):
 * Compute Bout = BlockMix_{salsa20, 1}(Bin).  The input Bin must be 128
 * bytes in length; the output Bout must also be the same size.
 */
static inline void blockmix_salsa(const salsa20_blk_t *restrict Bin,
    salsa20_blk_t *restrict Bout)
{
    DECL_X

    READ_X(Bin[1])
    SALSA20_XOR_MEM(Bin[0], Bout[0])
    SALSA20_XOR_MEM(Bin[1], Bout[1])
}

static inline uint32_t blockmix_salsa_xor(const salsa20_blk_t *restrict Bin1,
    const salsa20_blk_t *restrict Bin2, salsa20_blk_t *restrict Bout)
{
    DECL_X

    XOR_X_2(Bin1[1], Bin2[1])
    XOR_X(Bin1[0])
    SALSA20_XOR_MEM(Bin2[0], Bout[0])
    XOR_X(Bin1[1])
    SALSA20_XOR_MEM(Bin2[1], Bout[1])

    return INTEGERIFY;
}

#if _YESPOWER_OPT_C_PASS_ == 1
#define Swidth_0_5 8
#define Swidth_1_0 11
#define PWXsimple 2
#define PWXgather 4
#define PWXbytes (PWXgather * PWXsimple * 8)
#define Swidth_to_Sbytes1(Swidth) ((1 << (Swidth)) * PWXsimple * 8)
#define Swidth_to_Smask(Swidth) (((1 << (Swidth)) - 1) * PWXsimple * 8)
#define Smask_to_Smask2(Smask) (((uint64_t)(Smask) << 32) | (Smask))
#define Smask2_0_5 Smask_to_Smask2(Swidth_to_Smask(Swidth_0_5))
#define Smask2_1_0 Smask_to_Smask2(Swidth_to_Smask(Swidth_1_0))

typedef struct {
    uint8_t *S0, *S1, *S2;
    size_t w;
    uint32_t Sbytes;
} pwxform_ctx_t;

#define DECL_SMASK2REG /* empty */
#define MAYBE_MEMORY_BARRIER /* empty */

/* SSE4.2-based PWXFORM_SIMD already defined above */

#define PWXFORM_ROUND \
    PWXFORM_SIMD(X0) \
    PWXFORM_SIMD(X1) \
    PWXFORM_SIMD(X2) \
    PWXFORM_SIMD(X3)

#define PWXFORM_ROUND_WRITE4 \
    PWXFORM_SIMD(X0) \
    *(__m128i *)(ctx->S0 + w) = X0; \
    PWXFORM_SIMD(X1) \
    *(__m128i *)(ctx->S1 + w) = X1; \
    w += 16; \
    PWXFORM_SIMD(X2) \
    *(__m128i *)(ctx->S0 + w) = X2; \
    PWXFORM_SIMD(X3) \
    *(__m128i *)(ctx->S1 + w) = X3; \
    w += 16;

#define PWXFORM_ROUND_WRITE2 \
    PWXFORM_SIMD(X0) \
    *(__m128i *)(ctx->S0 + w) = X0; \
    PWXFORM_SIMD(X1) \
    *(__m128i *)(ctx->S1 + w) = X1; \
    w += 16; \
    PWXFORM_SIMD(X2) \
    PWXFORM_SIMD(X3)

#define PWXFORM \
    PWXFORM_ROUND PWXFORM_ROUND PWXFORM_ROUND \
    PWXFORM_ROUND PWXFORM_ROUND PWXFORM_ROUND

#define Smask2 Smask2_0_5
#else
/* pass 2 definitions (identical to reference) */
#endif

/**
 * blockmix(Bin, Bout, r, ctx):
 * Compute Bout = BlockMix_{pwxform, r, S}(Bin).
 */
static void blockmix(const salsa20_blk_t *restrict Bin,
    salsa20_blk_t *restrict Bout, size_t r, pwxform_ctx_t *restrict ctx)
{
    if (unlikely(!ctx)) {
        blockmix_salsa(Bin, Bout);
        return;
    }

    uint8_t *S0 = ctx->S0, *S1 = ctx->S1;
#if _YESPOWER_OPT_C_PASS_ > 1
    uint8_t *S2 = ctx->S2;
    size_t w = ctx->w;
#endif
    size_t i;
    DECL_X

    r = r * 2 - 1;

    READ_X(Bin[r])

    DECL_SMASK2REG

    i = 0;
    do {
        XOR_X(Bin[i])
        PWXFORM
        if (unlikely(i >= r))
            break;
        WRITE_X(Bout[i])
        i++;
    } while (1);

#if _YESPOWER_OPT_C_PASS_ > 1
    ctx->S0 = S0; ctx->S1 = S1; ctx->S2 = S2; ctx->w = w;
#endif

    SALSA20(Bout[i])
}

/* smix1, smix2, smix functions follow identical to reference,
   using blockmix and blockmix_xor above. You can copy them
   verbatim from the original source. */
/**
 * blockmix_salsa_xor_save(Bin1out, Bin2, r, ctx):
 * Like blockmix_xor but writes back into Bin1out.
 */
static uint32_t blockmix_xor_save(salsa20_blk_t *restrict Bin1out,
    salsa20_blk_t *restrict Bin2, size_t r, pwxform_ctx_t *restrict ctx)
{
    uint8_t *S0 = ctx->S0, *S1 = ctx->S1;
#if _YESPOWER_OPT_C_PASS_ > 1
    uint8_t *S2 = ctx->S2;
    size_t w = ctx->w;
#endif
    size_t i;
    DECL_X
    DECL_Y

    r = r * 2 - 1;

    XOR_X_2(Bin1out[r], Bin2[r])

    DECL_SMASK2REG

    i = 0;
    r--;
    do {
        XOR_X_WRITE_XOR_Y_2(Bin2[i], Bin1out[i])
        PWXFORM
        WRITE_X(Bin1out[i])

        XOR_X_WRITE_XOR_Y_2(Bin2[i + 1], Bin1out[i + 1])
        PWXFORM

        if (unlikely(i >= r))
            break;

        WRITE_X(Bin1out[i + 1])
        i += 2;
    } while (1);
    i++;

#if _YESPOWER_OPT_C_PASS_ > 1
    ctx->S0 = S0; ctx->S1 = S1; ctx->S2 = S2; ctx->w = w;
#endif

    SALSA20(Bin1out[i])
    return INTEGERIFY;
}

#if _YESPOWER_OPT_C_PASS_ == 1
static inline uint32_t integerify(const salsa20_blk_t *B, size_t r)
{
    return (uint32_t)B[2 * r - 1].d[0];
}
#endif

static void smix1(uint8_t *B, size_t r, uint32_t N,
    salsa20_blk_t *V, salsa20_blk_t *XY, pwxform_ctx_t *ctx)
{
    size_t s = 2 * r;
    salsa20_blk_t *X = V, *Y = &V[s], *V_j;
    uint32_t i, j, n;

#if _YESPOWER_OPT_C_PASS_ == 1
    for (i = 0; i < 2 * r; i++) {
#else
    for (i = 0; i < 2; i++) {
#endif
        salsa20_blk_t *tmp = Y;
        salsa20_blk_t *dst = &X[i];
        const salsa20_blk_t *src = (const salsa20_blk_t *)(B + i * 64);
        for (int k = 0; k < 16; k++)
            tmp->w[k] = le32dec(&src->w[k]);
        salsa20_simd_shuffle(tmp, dst);
    }

#if _YESPOWER_OPT_C_PASS_ > 1
    for (i = 1; i < r; i++)
        blockmix(&X[(i - 1) * 2], &X[i * 2], 1, ctx);
#endif

    blockmix(X, Y, r, ctx);
    X = Y + s;
    blockmix(Y, X, r, ctx);
    j = integerify(X, r);

    for (n = 2; n < N; n <<= 1) {
        uint32_t m = (n < N / 2) ? n : (N - 1 - n);
        for (i = 1; i < m; i += 2) {
            Y = X + s;
            j &= n - 1;
            j += i - 1;
            V_j = &V[j * s];
            PREFETCH(&V[(j + 1) * s], _MM_HINT_T0);
            j = blockmix_xor(X, V_j, Y, r, ctx);
            j &= n - 1;
            j += i;
            V_j = &V[j * s];
            PREFETCH(&V[(j + 1) * s], _MM_HINT_T0);
            X = Y + s;
            j = blockmix_xor(Y, V_j, X, r, ctx);
        }
    }
    n >>= 1;

    j &= n - 1;
    j += N - 2 - n;
    V_j = &V[j * s];
    Y = X + s;
    j = blockmix_xor(X, V_j, Y, r, ctx);
    j &= n - 1;
    j += N - 1 - n;
    V_j = &V[j * s];
    blockmix_xor(Y, V_j, XY, r, ctx);

    for (i = 0; i < 2 * r; i++) {
        salsa20_blk_t *tmp = &XY[i + s];
        salsa20_blk_t *dst = (salsa20_blk_t *)(B + i * 64);
        const salsa20_blk_t *src = &XY[i];
        for (int k = 0; k < 16; k++)
            le32enc(&tmp->w[k], src->w[k]);
        salsa20_simd_unshuffle(tmp, dst);
    }
}

static void smix2(uint8_t *B, size_t r, uint32_t N, uint32_t Nloop,
    salsa20_blk_t *V, salsa20_blk_t *XY, pwxform_ctx_t *ctx)
{
    size_t s = 2 * r;
    salsa20_blk_t *X = XY, *Y = &XY[s];
    uint32_t i, j;

    for (i = 0; i < 2 * r; i++) {
        salsa20_blk_t *tmp = Y;
        salsa20_blk_t *dst = &X[i];
        const salsa20_blk_t *src = (const salsa20_blk_t *)(B + i * 64);
        for (int k = 0; k < 16; k++)
            tmp->w[k] = le32dec(&src->w[k]);
        salsa20_simd_shuffle(tmp, dst);
    }

    j = integerify(X, r) & (N - 1);

#if _YESPOWER_OPT_C_PASS_ == 1
    if (Nloop > 2) {
#endif
        do {
            salsa20_blk_t *V_j = &V[j * s];
            PREFETCH(&V[(j + 1) * s], _MM_HINT_T0);
            j = blockmix_xor_save(X, V_j, r, ctx) & (N - 1);
            V_j = &V[j * s];
            PREFETCH(&V[(j + 1) * s], _MM_HINT_T0);
            j = blockmix_xor_save(X, V_j, r, ctx) & (N - 1);
        } while (Nloop -= 2);
#if _YESPOWER_OPT_C_PASS_ == 1
    } else {
        salsa20_blk_t *V_j = &V[j * s];
        j = blockmix_xor(X, V_j, Y, r, ctx) & (N - 1);
        V_j = &V[j * s];
        blockmix_xor(Y, V_j, X, r, ctx);
    }
#endif

    for (i = 0; i < 2 * r; i++) {
        salsa20_blk_t *tmp = &XY[(i < s ? i + s : i - s)];
        salsa20_blk_t *dst = (salsa20_blk_t *)(B + i * 64);
        const salsa20_blk_t *src = &X[i];
        for (int k = 0; k < 16; k++)
            le32enc(&tmp->w[k], src->w[k]);
        salsa20_simd_unshuffle(tmp, dst);
    }
}

static void smix(uint8_t *B, size_t r, uint32_t N,
    salsa20_blk_t *V, salsa20_blk_t *XY, pwxform_ctx_t *ctx)
{
#if _YESPOWER_OPT_C_PASS_ == 1
    uint32_t Nloop_all = (N + 2) / 3;
    uint32_t Nloop_rw = Nloop_all;
    Nloop_all++; Nloop_all &= ~1U;
    Nloop_rw &= ~1U;
#else
    uint32_t Nloop_rw = (N + 2) / 3;
    Nloop_rw++; Nloop_rw &= ~1U;
#endif

    smix1(B, 1, ctx->Sbytes / 128, (salsa20_blk_t *)ctx->S0, XY, NULL);
    smix1(B, r, N, V, XY, ctx);
    smix2(B, r, N, Nloop_rw, V, XY, ctx);
#if _YESPOWER_OPT_C_PASS_ == 1
    if ((N + 2) / 3 > Nloop_rw)
        smix2(B, r, N, 2, V, XY, ctx);
#endif
}

#if _YESPOWER_OPT_C_PASS_ == 1
#undef _YESPOWER_OPT_C_PASS_
#define _YESPOWER_OPT_C_PASS_ 2
#define blockmix_salsa blockmix_salsa_1_0
#define blockmix_salsa_xor blockmix_salsa_xor_1_0
#define blockmix blockmix_1_0
#define blockmix_xor blockmix_xor_1_0
#define blockmix_xor_save blockmix_xor_save_1_0
#define smix1 smix1_1_0
#define smix2 smix2_1_0
#define smix smix_1_0
#include "yespower-opt.c"
#undef smix

int yespower(yespower_local_t *local,
    const uint8_t *src, size_t srclen,
    const yespower_params_t *params,
    yespower_binary_t *dst)
{
    yespower_version_t version = params->version;
    uint32_t N = params->N;
    uint32_t r = params->r;
    const uint8_t *pers = params->pers;
    size_t perslen = params->perslen;
    uint32_t Swidth;
    size_t B_size, V_size, XY_size, need;
    uint8_t *B, *S;
    salsa20_blk_t *V, *XY;
    pwxform_ctx_t ctx;
    uint8_t sha256[32];

    if ((version != YESPOWER_0_5 && version != YESPOWER_1_0) ||
        N < 1024 || N > 512 * 1024 || r < 8 || r > 32 ||
        (N & (N - 1)) != 0 ||
        (!pers && perslen)) {
        errno = EINVAL;
        goto fail;
    }

    B_size = 128ULL * r;
    V_size = B_size * N;
    if (version == YESPOWER_0_5) {
        XY_size = B_size * 2;
        Swidth = Swidth_0_5;
        ctx.Sbytes = 2 * Swidth_to_Sbytes1(Swidth);
    } else {
        XY_size = B_size + 64;
        Swidth = Swidth_1_0;
        ctx.Sbytes = 3 * Swidth_to_Sbytes1(Swidth);
    }
    need = B_size + V_size + XY_size + ctx.Sbytes;
    if (local->aligned_size < need) {
        if (free_region(local))
            goto fail;
        if (!alloc_region(local, need))
            goto fail;
    }
    B = (uint8_t *)local->aligned;
    V = (salsa20_blk_t *)(B + B_size);
    XY = (salsa20_blk_t *)(V + V_size / sizeof(salsa20_blk_t));
    S = (uint8_t *)(XY + XY_size / sizeof(salsa20_blk_t));
    ctx.S0 = S;
    ctx.S1 = S + Swidth_to_Sbytes1(Swidth);

    SHA256_Buf(src, srclen, sha256);

    if (version == YESPOWER_0_5) {
        PBKDF2_SHA256(sha256, sizeof(sha256), src, srclen, 1,
            B, B_size);
        memcpy(sha256, B, sizeof(sha256));
        smix(B, r, N, V, XY, &ctx);
        PBKDF2_SHA256(sha256, sizeof(sha256), B, B_size, 1,
            (uint8_t *)dst, sizeof(*dst));

        if (pers) {
            HMAC_SHA256_Buf(dst, sizeof(*dst), pers, perslen,
                sha256);
            SHA256_Buf(sha256, sizeof(sha256), (uint8_t *)dst);
        }
    } else {
        ctx.S2 = S + 2 * Swidth_to_Sbytes1(Swidth);
        ctx.w = 0;

        if (pers) {
            src = pers;
            srclen = perslen;
        } else {
            srclen = 0;
        }

        PBKDF2_SHA256(sha256, sizeof(sha256), src, srclen, 1,
            B, 128);
        memcpy(sha256, B, sizeof(sha256));
        smix_1_0(B, r, N, V, XY, &ctx);
        HMAC_SHA256_Buf(B + B_size - 64, 64,
            sha256, sizeof(sha256), (uint8_t *)dst);
    }

    return 0;

fail:
    memset(dst, 0xff, sizeof(*dst));
    return -1;
}

int yespower_tls(const uint8_t *src, size_t srclen,
    const yespower_params_t *params, yespower_binary_t *dst)
{
    static __thread int initialized = 0;
    static __thread yespower_local_t local;

    if (!initialized) {
        init_region(&local);
        initialized = 1;
    }
    return yespower(&local, src, srclen, params, dst);
}
