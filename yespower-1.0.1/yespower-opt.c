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
 * Performance-tuned for Intel Celeron N4020 (Gemini Lake) using SSE2/SSE4.2
 */

#ifndef _YESPOWER_OPT_C_PASS_
#define _YESPOWER_OPT_C_PASS_ 1
#endif

#if defined(__GNUC__)
#pragma GCC target("sse4.2","sse2","ssse3")
#endif
#undef __XOP__
#undef __AVX__
#define USE_SSE4_FOR_32BIT 1

#include <emmintrin.h>
#include <smmintrin.h>
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
#define restrict __restrict
#endif

#ifdef __GNUC__
#define unlikely(x) __builtin_expect((x),0)
#else
#define unlikely(x) (x)
#endif

#define PREFETCH(p,h) _mm_prefetch((const char*)(p),(h))

/* Salsa20 block union */
typedef union {
    uint32_t w[16];
    uint64_t d[8];
#ifdef __SSE2__
    __m128i q[4];
#endif
} salsa20_blk_t;

/* Forward declarations for macros used below */
#ifdef __SSE2__
#define SALSA20_XOR_MEM(in,out) do { XOR_X(in); SALSA20_8(out); } while(0)
#else
#define SALSA20_XOR_MEM(in,out) do { XOR_X(in); SALSA20(out); } while(0)
#endif

/* shuffle/unshuffle routines (unchanged) */
static inline void salsa20_simd_shuffle(const salsa20_blk_t *Bin,
    salsa20_blk_t *Bout) { /* … original code … */ }
static inline void salsa20_simd_unshuffle(const salsa20_blk_t *Bin,
    salsa20_blk_t *Bout) { /* … original code … */ }

/* SSE2-based SALSA20 core */
#ifdef __SSE2__
#define DECL_X __m128i X0,X1,X2,X3;
#define DECL_Y __m128i Y0,Y1,Y2,Y3;
#define READ_X(in)  X0=(in).q[0];X1=(in).q[1];X2=(in).q[2];X3=(in).q[3];
#define WRITE_X(o)  (o).q[0]=X0;(o).q[1]=X1;(o).q[2]=X2;(o).q[3]=X3;
#define ARX(o,a,b,s) do{ __m128i t=_mm_add_epi32(a,b); \
    o=_mm_xor_si128(o,_mm_slli_epi32(t,s)); \
    o=_mm_xor_si128(o,_mm_srli_epi32(t,32-s)); }while(0)
#define SALSA20_2ROUNDS \
    ARX(X1,X0,X3,7) ARX(X2,X1,X0,9) ARX(X3,X2,X1,13) ARX(X0,X3,X2,18) \
    X1=_mm_shuffle_epi32(X1,0x93);X2=_mm_shuffle_epi32(X2,0x4E);X3=_mm_shuffle_epi32(X3,0x39); \
    ARX(X3,X0,X1,7) ARX(X2,X3,X0,9) ARX(X1,X2,X3,13) ARX(X0,X1,X2,18) \
    X1=_mm_shuffle_epi32(X1,0x39);X2=_mm_shuffle_epi32(X2,0x4E);X3=_mm_shuffle_epi32(X3,0x93);
#define SALSA20_WRAPPER(out,rounds) do{ \
    __m128i Z0=X0,Z1=X1,Z2=X2,Z3=X3; rounds \
    (out).q[0]=X0=_mm_add_epi32(X0,Z0); \
    (out).q[1]=X1=_mm_add_epi32(X1,Z1); \
    (out).q[2]=X2=_mm_add_epi32(X2,Z2); \
    (out).q[3]=X3=_mm_add_epi32(X3,Z3); }while(0)
#define SALSA20_2(out) SALSA20_WRAPPER(out,SALSA20_2ROUNDS)
#define SALSA20_8(out) SALSA20_WRAPPER(out, \
    SALSA20_2ROUNDS SALSA20_2ROUNDS SALSA20_2ROUNDS SALSA20_2ROUNDS)
#define XOR_X(in) do{ X0=_mm_xor_si128(X0,(in).q[0]); \
    X1=_mm_xor_si128(X1,(in).q[1]); \
    X2=_mm_xor_si128(X2,(in).q[2]); \
    X3=_mm_xor_si128(X3,(in).q[3]); }while(0)
#define XOR_X_2(a,b) do{ X0=_mm_xor_si128((a).q[0],(b).q[0]); \
    X1=_mm_xor_si128((a).q[1],(b).q[1]); \
    X2=_mm_xor_si128((a).q[2],(b).q[2]); \
    X3=_mm_xor_si128((a).q[3],(b).q[3]); }while(0)
#define INTEGERIFY _mm_cvtsi128_si32(X0)
#else
/* Generic SALSA20 (unchanged) */
#define DECL_X salsa20_blk_t X;
#define DECL_Y salsa20_blk_t Y;
/* … original generic implementation … */
#endif

/* blockmix_salsa: */
static inline void blockmix_salsa(const salsa20_blk_t *restrict Bin,
    salsa20_blk_t *restrict Bout)
{
    DECL_X;
    READ_X(Bin[1]);
    SALSA20_XOR_MEM(Bin[0], Bout[0]);
    SALSA20_XOR_MEM(Bin[1], Bout[1]);
}

/* blockmix_salsa_xor: */
static inline uint32_t blockmix_salsa_xor(const salsa20_blk_t *restrict B1,
    const salsa20_blk_t *restrict B2, salsa20_blk_t *restrict Bout)
{
    DECL_X;
    XOR_X_2(B1[1], B2[1]);
    XOR_X(B1[0]);
    SALSA20_XOR_MEM(B2[0], Bout[0]);
    XOR_X(B1[1]);
    SALSA20_XOR_MEM(B2[1], Bout[1]);
    return INTEGERIFY;
}
/* ------------------------------------------------------------------------ */
/* Context and PWX transform definitions (SSE4.2 path) */

#if _YESPOWER_OPT_C_PASS_ == 1

#define Swidth_0_5 8
#define Swidth_1_0 11
#define PWXsimple 2
#define PWXgather 4

/* Number of bytes per S-width block */
#define Swidth_to_Sbytes1(S)  ((1u << (S)) * PWXsimple * 8)
#define Swidth_to_Smask(S)    (((1u << (S)) - 1u) * PWXsimple * 8)
#define Smask_to_Smask2(M)    (((uint64_t)(M) << 32) | (M))

/* Precomputed masks */
#define Smask2_0_5  Smask_to_Smask2(Swidth_to_Smask(Swidth_0_5))
#define Smask2_1_0  Smask_to_Smask2(Swidth_to_Smask(Swidth_1_0))

typedef struct {
    uint8_t *S0, *S1, *S2;
    size_t w;        /* write offset */
    uint32_t Sbytes; /* total S-array bytes */
} pwxform_ctx_t;

/* SSE4.2-based PWXFORM */
#define HI32(X)           _mm_shuffle_epi32((X), _MM_SHUFFLE(2,3,0,1))
#define EXTRACT64(X)      _mm_cvtsi128_si64((X))

#define PWXFORM_SIMD(X) do { \
    __m128i v = (X); \
    uint64_t idx = (uint64_t)EXTRACT64(v) & Smask2; \
    uint32_t lo = (uint32_t)idx, hi = (uint32_t)(idx >> 32); \
    __m128i s0 = *(__m128i*)(ctx->S0 + lo); \
    __m128i s1 = *(__m128i*)(ctx->S1 + hi); \
    v = _mm_mul_epu32(HI32(v), v); \
    v = _mm_add_epi64(v, s0); \
    v = _mm_xor_si128(v, s1); \
    (X) = v; \
} while(0)

#define PWXFORM_ROUND       PWXFORM_SIMD(X0); PWXFORM_SIMD(X1); \
                            PWXFORM_SIMD(X2); PWXFORM_SIMD(X3)

#define PWXFORM_ROUND_WRITE4  \
    PWXFORM_SIMD(X0); *(__m128i*)(ctx->S0 + w) = X0; \
    PWXFORM_SIMD(X1); *(__m128i*)(ctx->S1 + w) = X1; \
    w += 16; \
    PWXFORM_SIMD(X2); *(__m128i*)(ctx->S0 + w) = X2; \
    PWXFORM_SIMD(X3); *(__m128i*)(ctx->S1 + w) = X3; \
    w += 16

#define PWXFORM_ROUND_WRITE2  \
    PWXFORM_SIMD(X0); *(__m128i*)(ctx->S0 + w) = X0; \
    PWXFORM_SIMD(X1); *(__m128i*)(ctx->S1 + w) = X1; \
    w += 16; \
    PWXFORM_SIMD(X2); PWXFORM_SIMD(X3)

#define PWXFORM             PWXFORM_ROUND PWXFORM_ROUND PWXFORM_ROUND \
                            PWXFORM_ROUND PWXFORM_ROUND PWXFORM_ROUND

#define Smask2              Smask2_0_5

#else
/* pass 2 definitions (identical to reference code) */
#endif

/* ------------------------------------------------------------------------ */
/* blockmix with pwxform */

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

    /* index of last 64-byte block in Bin */
    r = 2 * r - 1;

    /* read last block into X */
    READ_X(Bin[r]);

    DECL_SMASK2REG

    i = 0;
    do {
        XOR_X(Bin[i]);
        PWXFORM;
        if (unlikely(i >= r))
            break;
        WRITE_X(Bout[i]);
        i++;
    } while (1);

#if _YESPOWER_OPT_C_PASS_ > 1
    ctx->S0 = S0; ctx->S1 = S1; ctx->S2 = S2; ctx->w = w;
#endif

    /* final salsa20 on Bout[i] */
    SALSA20_8(Bout[i]);
}
/* ------------------------------------------------------------------------ */
/* blockmix_xor_save and smix routines */

static uint32_t blockmix_xor_save(salsa20_blk_t *restrict Bin1out,
    salsa20_blk_t *restrict Bin2, size_t r, pwxform_ctx_t *restrict ctx)
{
    uint8_t *S0 = ctx->S0, *S1 = ctx->S1;
#if _YESPOWER_OPT_C_PASS_ > 1
    uint8_t *S2 = ctx->S2;
    size_t w = ctx->w;
#endif
    size_t i;
    DECL_X; DECL_Y

    r = 2 * r - 1;
    XOR_X_2(Bin1out[r], Bin2[r]);
    DECL_SMASK2REG

    i = 0;
    r--;
    do {
        XOR_X_WRITE_XOR_Y_2(Bin2[i], Bin1out[i]);
        PWXFORM;
        WRITE_X(Bin1out[i]);

        XOR_X_WRITE_XOR_Y_2(Bin2[i+1], Bin1out[i+1]);
        PWXFORM;
        if (unlikely(i >= r)) break;
        WRITE_X(Bin1out[i+1]);
        i += 2;
    } while (1);
    i++;

#if _YESPOWER_OPT_C_PASS_ > 1
    ctx->S0 = S0; ctx->S1 = S1; ctx->S2 = S2; ctx->w = w;
#endif

    SALSA20_8(Bin1out[i]);
    return INTEGERIFY;
}

static inline uint32_t integerify(const salsa20_blk_t *B, size_t r)
{
    return (uint32_t)B[2*r - 1].d[0];
}

static void smix1(uint8_t *B, size_t r, uint32_t N,
    salsa20_blk_t *V, salsa20_blk_t *XY, pwxform_ctx_t *ctx)
{
    size_t s = 2*r;
    salsa20_blk_t *X = V, *Y = &V[s], *Vj;
    uint32_t i, j, n;

    for (i = 0; i < 2*r; i++) {
        salsa20_blk_t *tmp = &XY[i];
        salsa20_blk_t *dst = &X[i];
        const salsa20_blk_t *src = (const salsa20_blk_t*)(B + 64*i);
        for (int k = 0; k < 16; k++)
            tmp->w[k] = le32dec(&src->w[k]);
        salsa20_simd_shuffle(tmp, dst);
    }

    blockmix(X, Y, r, ctx);
    blockmix(Y, X, r, ctx);
    j = integerify(X, r);

    for (n = 2; n < N; n <<= 1) {
        uint32_t m = (n < N/2) ? n : (N - 1 - n);
        for (i = 1; i < m; i += 2) {
            Y = X + s;
            j = (j & (n-1)) + i - 1;
            Vj = &V[j * s];
            PREFETCH(&V[(j+1)*s], _MM_HINT_T0);
            j = blockmix_xor(X, Vj, Y) & (n-1);
            Vj = &V[j * s];
            PREFETCH(&V[(j+1)*s], _MM_HINT_T0);
            j = blockmix_xor(Y, Vj, X) & (n-1);
        }
    }

    j = (j & (n-1)) + N - 2 - n;
    Vj = &V[j * s];
    j = blockmix_xor(X, Vj, Y) & (n-1);
    Vj = &V[j * s];
    blockmix_xor(Y, Vj, XY);

    for (i = 0; i < 2*r; i++) {
        salsa20_blk_t *tmp = &XY[i + s];
        salsa20_blk_t *dst = (salsa20_blk_t*)(B + 64*i);
        const salsa20_blk_t *src = &XY[i];
        for (int k = 0; k < 16; k++)
            le32enc(&tmp->w[k], src->w[k]);
        salsa20_simd_unshuffle(tmp, dst);
    }
}

static void smix2(uint8_t *B, size_t r, uint32_t N, uint32_t Nloop,
    salsa20_blk_t *V, salsa20_blk_t *XY, pwxform_ctx_t *ctx)
{
    size_t s = 2*r;
    salsa20_blk_t *X = XY, *Y = &XY[s];
    uint32_t i, j;

    for (i = 0; i < 2*r; i++) {
        salsa20_blk_t *tmp = &Y[i];
        salsa20_blk_t *dst = &X[i];
        const salsa20_blk_t *src = (const salsa20_blk_t*)(B + 64*i);
        for (int k = 0; k < 16; k++)
            tmp->w[k] = le32dec(&src->w[k]);
        salsa20_simd_shuffle(tmp, dst);
    }

    j = integerify(X, r) & (N-1);

    do {
        salsa20_blk_t *Vj = &V[j * s];
        PREFETCH(&V[(j+1)*s], _MM_HINT_T0);
        j = blockmix_xor_save(X, Vj, r, ctx) & (N-1);
    } while (Nloop-- > 2);

    for (i = 0; i < 2*r; i++) {
        salsa20_blk_t *tmp = &Y[(i < s ? i+s : i-s)];
        salsa20_blk_t *dst = (salsa20_blk_t*)(B + 64*i);
        const salsa20_blk_t *src = &X[i];
        for (int k = 0; k < 16; k++)
            le32enc(&tmp->w[k], src->w[k]);
        salsa20_simd_unshuffle(tmp, dst);
    }
}

static void smix(uint8_t *B, size_t r, uint32_t N,
    salsa20_blk_t *V, salsa20_blk_t *XY, pwxform_ctx_t *ctx)
{
    uint32_t Nloop = ((N+2)/3) & ~1U;
    smix1(B, r, N, V, XY, ctx);
    smix2(B, r, N, Nloop, V, XY, ctx);
}

int yespower(yespower_local_t *local,
    const uint8_t *src, size_t srclen,
    const yespower_params_t *params,
    yespower_binary_t *dst)
{
    yespower_version_t version = params->version;
    uint32_t N = params->N, r = params->r;
    const uint8_t *pers = params->pers;
    size_t perslen = params->perslen;
    uint32_t Swidth;
    size_t Bsz = 128*r, Vsz, XYsz, need;
    uint8_t *B, *S;
    salsa20_blk_t *V, *XY;
    pwxform_ctx_t ctx;
    uint8_t sha256[32];

    if ((version != YESPOWER_0_5 && version != YESPOWER_1_0) ||
        (N & (N-1)) || r<8 || r>32 ||
        (!pers && perslen)) {
        errno = EINVAL;
        goto fail;
    }

    Vsz = Bsz * N;
    if (version == YESPOWER_0_5) {
        XYsz = Bsz*2;
        Swidth = Swidth_0_5;
        ctx.Sbytes = 2 * Swidth_to_Sbytes1(Swidth);
    } else {
        XYsz = Bsz+64;
        Swidth = Swidth_1_0;
        ctx.Sbytes = 3 * Swidth_to_Sbytes1(Swidth);
    }
    need = Bsz + Vsz + XYsz + ctx.Sbytes;
    if (local->aligned_size < need) {
        if (free_region(local)) goto fail;
        if (!alloc_region(local, need)) goto fail;
    }
    B = local->aligned;
    V = (salsa20_blk_t*)(B + Bsz);
    XY = (salsa20_blk_t*)( (uint8_t*)V + Vsz );
    S = (uint8_t*)( (uint8_t*)XY + XYsz );
    ctx.S0 = S;
    ctx.S1 = S + Swidth_to_Sbytes1(Swidth);

    SHA256_Buf(src, srclen, sha256);

    if (version == YESPOWER_0_5) {
        PBKDF2_SHA256(sha256,32,src,srclen,1,B,Bsz);
        memcpy(sha256,B,32);
        smix(B,r,N,V,XY,&ctx);
        PBKDF2_SHA256(sha256,32,B,Bsz,1,(uint8_t*)dst,sizeof(*dst));
        if (pers) {
            HMAC_SHA256_Buf(dst,sizeof(*dst),pers,perslen,sha256);
            SHA256_Buf(sha256,32,(uint8_t*)dst);
        }
    } else {
        ctx.S2 = S + 2*Swidth_to_Sbytes1(Swidth);
        ctx.w = 0;
        if (pers) { src=pers; srclen=perslen; } else srclen=0;
        PBKDF2_SHA256(sha256,32,src,srclen,1,B,128);
        memcpy(sha256,B,32);
        smix(B,r,N,V,XY,&ctx);
        HMAC_SHA256_Buf(B+Bsz-64,64,sha256,32,(uint8_t*)dst);
    }
    return 0;
fail:
    memset(dst,0xff,sizeof(*dst));
    return -1;
}

int yespower_tls(const uint8_t *src, size_t srclen,
    const yespower_params_t *params, yespower_binary_t *dst)
{
    static __thread yespower_local_t local;
    static __thread int init;
    if (!init) { init_region(&local); init=1; }
    return yespower(&local, src, srclen, params, dst);
}
