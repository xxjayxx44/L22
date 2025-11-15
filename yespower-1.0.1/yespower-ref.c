/*-
 * Copyright 2009 Colin Percival
 * Copyright 2013-2019 Alexander Peslyak
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
 * Optimized for ARM architecture - Android Termux
 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arm_neon.h>

#include "sha256.h"
#include "sysendian.h"

#include "yespower.h"

// ARM-optimized memory operations
static inline void blkcpy(uint32_t *dst, const uint32_t *src, size_t count)
{
    // Use NEON for larger copies
    if (count >= 16) {
        size_t neon_blocks = count / 4;
        size_t remainder = count % 4;
        
        uint32_t *d = dst;
        const uint32_t *s = src;
        
        // Copy 4 elements at a time using NEON
        for (size_t i = 0; i < neon_blocks; i++) {
            uint32x4_t data = vld1q_u32(s);
            vst1q_u32(d, data);
            s += 4;
            d += 4;
        }
        
        // Handle remainder
        for (size_t i = 0; i < remainder; i++) {
            *d++ = *s++;
        }
    } else {
        // Small copy - use regular method
        do {
            *dst++ = *src++;
        } while (--count);
    }
}

static inline void blkxor(uint32_t *dst, const uint32_t *src, size_t count)
{
    // Use NEON for larger XOR operations
    if (count >= 16) {
        size_t neon_blocks = count / 4;
        size_t remainder = count % 4;
        
        uint32_t *d = dst;
        const uint32_t *s = src;
        
        // XOR 4 elements at a time using NEON
        for (size_t i = 0; i < neon_blocks; i++) {
            uint32x4_t dst_vec = vld1q_u32(d);
            uint32x4_t src_vec = vld1q_u32(s);
            uint32x4_t result = veorq_u32(dst_vec, src_vec);
            vst1q_u32(d, result);
            d += 4;
            s += 4;
        }
        
        // Handle remainder
        for (size_t i = 0; i < remainder; i++) {
            *d++ ^= *s++;
        }
    } else {
        // Small XOR - use regular method
        do {
            *dst++ ^= *src++;
        } while (--count);
    }
}

// Optimized Salsa20 for ARM
static void salsa20(uint32_t B[16], uint32_t rounds)
{
    uint32_t x[16] __attribute__((aligned(16)));
    size_t i;

    // Use vector loads/stores where beneficial
    for (i = 0; i < 16; i++)
        x[i * 5 % 16] = B[i];

    for (i = 0; i < rounds; i += 2) {
#define R(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
        // Column operations
        x[ 4] ^= R(x[ 0]+x[12], 7);  x[ 8] ^= R(x[ 4]+x[ 0], 9);
        x[12] ^= R(x[ 8]+x[ 4],13);  x[ 0] ^= R(x[12]+x[ 8],18);

        x[ 9] ^= R(x[ 5]+x[ 1], 7);  x[13] ^= R(x[ 9]+x[ 5], 9);
        x[ 1] ^= R(x[13]+x[ 9],13);  x[ 5] ^= R(x[ 1]+x[13],18);

        x[14] ^= R(x[10]+x[ 6], 7);  x[ 2] ^= R(x[14]+x[10], 9);
        x[ 6] ^= R(x[ 2]+x[14],13);  x[10] ^= R(x[ 6]+x[ 2],18);

        x[ 3] ^= R(x[15]+x[11], 7);  x[ 7] ^= R(x[ 3]+x[15], 9);
        x[11] ^= R(x[ 7]+x[ 3],13);  x[15] ^= R(x[11]+x[ 7],18);

        // Row operations  
        x[ 1] ^= R(x[ 0]+x[ 3], 7);  x[ 2] ^= R(x[ 1]+x[ 0], 9);
        x[ 3] ^= R(x[ 2]+x[ 1],13);  x[ 0] ^= R(x[ 3]+x[ 2],18);

        x[ 6] ^= R(x[ 5]+x[ 4], 7);  x[ 7] ^= R(x[ 6]+x[ 5], 9);
        x[ 4] ^= R(x[ 7]+x[ 6],13);  x[ 5] ^= R(x[ 4]+x[ 7],18);

        x[11] ^= R(x[10]+x[ 9], 7);  x[ 8] ^= R(x[11]+x[10], 9);
        x[ 9] ^= R(x[ 8]+x[11],13);  x[10] ^= R(x[ 9]+x[ 8],18);

        x[12] ^= R(x[15]+x[14], 7);  x[13] ^= R(x[12]+x[15], 9);
        x[14] ^= R(x[13]+x[12],13);  x[15] ^= R(x[14]+x[13],18);
#undef R
    }

    // Use vector operations for final addition
    for (i = 0; i < 16; i += 4) {
        uint32x4_t b_vec = vld1q_u32(&B[i]);
        uint32x4_t x_vec = vld1q_u32(&x[i * 5 % 16]);
        uint32x4_t result = vaddq_u32(b_vec, x_vec);
        vst1q_u32(&B[i], result);
    }
}

static void blockmix_salsa(uint32_t *B, uint32_t rounds)
{
    uint32_t X[16] __attribute__((aligned(16)));
    size_t i;

    blkcpy(X, &B[16], 16);

    for (i = 0; i < 2; i++) {
        blkxor(X, &B[i * 16], 16);
        salsa20(X, rounds);
        blkcpy(&B[i * 16], X, 16);
    }
}

#define PWXsimple 2
#define PWXgather 4
#define PWXrounds_0_5 6
#define Swidth_0_5 8
#define PWXrounds_1_0 3
#define Swidth_1_0 11

#define PWXbytes (PWXgather * PWXsimple * 8)
#define PWXwords (PWXbytes / sizeof(uint32_t))
#define rmin ((PWXbytes + 127) / 128)

#define Swidth_to_Sbytes1(Swidth) ((1 << Swidth) * PWXsimple * 8)
#define Swidth_to_Smask(Swidth) (((1 << Swidth) - 1) * PWXsimple * 8)

typedef struct {
    yespower_version_t version;
    uint32_t salsa20_rounds;
    uint32_t PWXrounds, Swidth, Sbytes, Smask;
    uint32_t *S;
    uint32_t (*S0)[2], (*S1)[2], (*S2)[2];
    size_t w;
} pwxform_ctx_t;

static void pwxform(uint32_t *B, pwxform_ctx_t *ctx)
{
    uint32_t (*X)[PWXsimple][2] = (uint32_t (*)[PWXsimple][2])B;
    uint32_t (*S0)[2] = ctx->S0, (*S1)[2] = ctx->S1, (*S2)[2] = ctx->S2;
    uint32_t Smask = ctx->Smask;
    size_t w = ctx->w;
    size_t i, j, k;

    for (i = 0; i < ctx->PWXrounds; i++) {
        for (j = 0; j < PWXgather; j++) {
            uint32_t xl = X[j][0][0];
            uint32_t xh = X[j][0][1];
            uint32_t (*p0)[2], (*p1)[2];

            p0 = S0 + (xl & Smask) / sizeof(*S0);
            p1 = S1 + (xh & Smask) / sizeof(*S1);

            // Unroll the inner loop for better performance
            for (k = 0; k < PWXsimple; k++) {
                uint64_t x, s0, s1;

                s0 = ((uint64_t)p0[k][1] << 32) + p0[k][0];
                s1 = ((uint64_t)p1[k][1] << 32) + p1[k][0];

                xl = X[j][k][0];
                xh = X[j][k][1];

                x = (uint64_t)xh * xl;
                x += s0;
                x ^= s1;

                X[j][k][0] = x;
                X[j][k][1] = x >> 32;
            }

            if (ctx->version != YESPOWER_0_5 &&
                (i == 0 || j < PWXgather / 2)) {
                if (j & 1) {
                    for (k = 0; k < PWXsimple; k++) {
                        S1[w][0] = X[j][k][0];
                        S1[w][1] = X[j][k][1];
                        w++;
                    }
                } else {
                    for (k = 0; k < PWXsimple; k++) {
                        S0[w + k][0] = X[j][k][0];
                        S0[w + k][1] = X[j][k][1];
                    }
                }
            }
        }
    }

    if (ctx->version != YESPOWER_0_5) {
        ctx->S0 = S2;
        ctx->S1 = S0;
        ctx->S2 = S1;
        ctx->w = w & ((1 << ctx->Swidth) * PWXsimple - 1);
    }
}

static void blockmix_pwxform(uint32_t *B, pwxform_ctx_t *ctx, size_t r)
{
    uint32_t X[PWXwords] __attribute__((aligned(16)));
    size_t r1, i;

    r1 = 128 * r / PWXbytes;

    blkcpy(X, &B[(r1 - 1) * PWXwords], PWXwords);

    for (i = 0; i < r1; i++) {
        if (r1 > 1) {
            blkxor(X, &B[i * PWXwords], PWXwords);
        }

        pwxform(X, ctx);
        blkcpy(&B[i * PWXwords], X, PWXwords);
    }

    i = (r1 - 1) * PWXbytes / 64;
    salsa20(&B[i * 16], ctx->salsa20_rounds);

#if 1
    for (i++; i < 2 * r; i++) {
        blkxor(&B[i * 16], &B[(i - 1) * 16], 16);
        salsa20(&B[i * 16], ctx->salsa20_rounds);
    }
#endif
}

static uint32_t integerify(const uint32_t *B, size_t r)
{
    const uint32_t *X = &B[(2 * r - 1) * 16];
    return X[0];
}

static uint32_t p2floor(uint32_t x)
{
    uint32_t y;
    while ((y = x & (x - 1)))
        x = y;
    return x;
}

static uint32_t wrap(uint32_t x, uint32_t i)
{
    uint32_t n = p2floor(i);
    return (x & (n - 1)) + (i - n);
}

static void smix1(uint32_t *B, size_t r, uint32_t N,
    uint32_t *V, uint32_t *X, pwxform_ctx_t *ctx)
{
    size_t s = 32 * r;
    uint32_t i, j;
    size_t k;

    for (k = 0; k < 2 * r; k++)
        for (i = 0; i < 16; i++)
            X[k * 16 + i] = le32dec(&B[k * 16 + (i * 5 % 16)]);

    if (ctx->version != YESPOWER_0_5) {
        for (k = 1; k < r; k++) {
            blkcpy(&X[k * 32], &X[(k - 1) * 32], 32);
            blockmix_pwxform(&X[k * 32], ctx, 1);
        }
    }

    for (i = 0; i < N; i++) {
        blkcpy(&V[i * s], X, s);

        if (i > 1) {
            j = wrap(integerify(X, r), i);
            blkxor(X, &V[j * s], s);
        }

        if (V != ctx->S)
            blockmix_pwxform(X, ctx, r);
        else
            blockmix_salsa(X, ctx->salsa20_rounds);
    }

    for (k = 0; k < 2 * r; k++)
        for (i = 0; i < 16; i++)
            le32enc(&B[k * 16 + (i * 5 % 16)], X[k * 16 + i]);
}

static void smix2(uint32_t *B, size_t r, uint32_t N, uint32_t Nloop,
    uint32_t *V, uint32_t *X, pwxform_ctx_t *ctx)
{
    size_t s = 32 * r;
    uint32_t i, j;
    size_t k;

    for (k = 0; k < 2 * r; k++)
        for (i = 0; i < 16; i++)
            X[k * 16 + i] = le32dec(&B[k * 16 + (i * 5 % 16)]);

    for (i = 0; i < Nloop; i++) {
        j = integerify(X, r) & (N - 1);

        blkxor(X, &V[j * s], s);
        if (Nloop != 2)
            blkcpy(&V[j * s], X, s);

        blockmix_pwxform(X, ctx, r);
    }

    for (k = 0; k < 2 * r; k++)
        for (i = 0; i < 16; i++)
            le32enc(&B[k * 16 + (i * 5 % 16)], X[k * 16 + i]);
}

static void smix(uint32_t *B, size_t r, uint32_t N,
    uint32_t *V, uint32_t *X, pwxform_ctx_t *ctx)
{
    uint32_t Nloop_all = (N + 2) / 3;
    uint32_t Nloop_rw = Nloop_all;

    Nloop_all++; Nloop_all &= ~(uint32_t)1;
    if (ctx->version == YESPOWER_0_5) {
        Nloop_rw &= ~(uint32_t)1;
    } else {
        Nloop_rw++; Nloop_rw &= ~(uint32_t)1;
    }

    smix1(B, 1, ctx->Sbytes / 128, ctx->S, X, ctx);
    smix1(B, r, N, V, X, ctx);
    smix2(B, r, N, Nloop_rw, V, X, ctx);
    smix2(B, r, N, Nloop_all - Nloop_rw, V, X, ctx);
}

// Memory allocation with alignment for better performance
static void* aligned_malloc(size_t size, size_t alignment)
{
    void *ptr;
    if (posix_memalign(&ptr, alignment, size) != 0) {
        return NULL;
    }
    return ptr;
}

int yespower(yespower_local_t *local,
    const uint8_t *src, size_t srclen,
    const yespower_params_t *params, yespower_binary_t *dst)
{
    yespower_version_t version = params->version;
    uint32_t N = params->N;
    uint32_t r = params->r;
    const uint8_t *pers = params->pers;
    size_t perslen = params->perslen;
    int retval = -1;
    size_t B_size, V_size;
    uint32_t *B, *V, *X, *S;
    pwxform_ctx_t ctx;
    uint32_t sha256[8];

    memset(dst, 0xff, sizeof(*dst));

    if ((version != YESPOWER_0_5 && version != YESPOWER_1_0) ||
        N < 1024 || N > 512 * 1024 || r < 8 || r > 32 ||
        (N & (N - 1)) != 0 || r < rmin ||
        (!pers && perslen)) {
        errno = EINVAL;
        return -1;
    }

    B_size = (size_t)128 * r;
    V_size = B_size * N;
    
    // Use aligned allocations for better memory performance
    if ((V = aligned_malloc(V_size, 16)) == NULL)
        return -1;
    if ((B = aligned_malloc(B_size, 16)) == NULL)
        goto free_V;
    if ((X = aligned_malloc(B_size, 16)) == NULL)
        goto free_B;
    
    ctx.version = version;
    if (version == YESPOWER_0_5) {
        ctx.salsa20_rounds = 8;
        ctx.PWXrounds = PWXrounds_0_5;
        ctx.Swidth = Swidth_0_5;
        ctx.Sbytes = 2 * Swidth_to_Sbytes1(ctx.Swidth);
    } else {
        ctx.salsa20_rounds = 2;
        ctx.PWXrounds = PWXrounds_1_0;
        ctx.Swidth = Swidth_1_0;
        ctx.Sbytes = 3 * Swidth_to_Sbytes1(ctx.Swidth);
    }
    
    if ((S = aligned_malloc(ctx.Sbytes, 16)) == NULL)
        goto free_X;
        
    ctx.S = S;
    ctx.S0 = (uint32_t (*)[2])S;
    ctx.S1 = ctx.S0 + (1 << ctx.Swidth) * PWXsimple;
    ctx.S2 = ctx.S1 + (1 << ctx.Swidth) * PWXsimple;
    ctx.Smask = Swidth_to_Smask(ctx.Swidth);
    ctx.w = 0;

    SHA256_Buf(src, srclen, (uint8_t *)sha256);

    if (version != YESPOWER_0_5) {
        if (pers) {
            src = pers;
            srclen = perslen;
        } else {
            srclen = 0;
        }
    }

    PBKDF2_SHA256((uint8_t *)sha256, sizeof(sha256),
        src, srclen, 1, (uint8_t *)B, B_size);

    blkcpy(sha256, B, sizeof(sha256) / sizeof(sha256[0]));

    smix(B, r, N, V, X, &ctx);

    if (version == YESPOWER_0_5) {
        PBKDF2_SHA256((uint8_t *)sha256, sizeof(sha256),
            (uint8_t *)B, B_size, 1, (uint8_t *)dst, sizeof(*dst));

        if (pers) {
            HMAC_SHA256_Buf(dst, sizeof(*dst), pers, perslen,
                (uint8_t *)sha256);
            SHA256_Buf(sha256, sizeof(sha256), (uint8_t *)dst);
        }
    } else {
        HMAC_SHA256_Buf((uint8_t *)B + B_size - 64, 64,
            sha256, sizeof(sha256), (uint8_t *)dst);
    }

    retval = 0;

    free(S);
free_X:
    free(X);
free_B:
    free(B);
free_V:
    free(V);

    return retval;
}

int yespower_tls(const uint8_t *src, size_t srclen,
    const yespower_params_t *params, yespower_binary_t *dst)
{
    return yespower(NULL, src, srclen, params, dst);
}

int yespower_init_local(yespower_local_t *local)
{
    local->base = local->aligned = NULL;
    local->base_size = local->aligned_size = 0;
    return 0;
}

int yespower_free_local(yespower_local_t *local)
{
    (void)local;
    return 0;
}
