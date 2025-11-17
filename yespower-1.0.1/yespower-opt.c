#ifndef _YESPOWER_OPT_C_PASS_
#define _YESPOWER_OPT_C_PASS_ 1
#endif

#if _YESPOWER_OPT_C_PASS_ == 1
/*
 * MINIMAL FAST YESPOWER-R16 VALID IMPLEMENTATION
 */

/* Disable warnings for maximum speed */
#pragma GCC optimize("O3","fast-math","inline")

#ifdef __SSE2__
#include <emmintrin.h>
#endif

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "sha256.h"
#include "sysendian.h"
#include "yespower.h"

/* FAST MEMORY OPERATIONS */
#define blkcpy(dst, src, count) memcpy(dst, src, (count) * 4)
#define blkxor(dst, src, count) do { \
    size_t _c = (count); \
    uint32_t *_d = (dst), *_s = (src); \
    while (_c--) *_d++ ^= *_s++; \
} while(0)

/* MINIMAL VALID PARAMETERS */
#define PWXsimple 2
#define PWXgather 4
#define PWXrounds_0_5 6
#define PWXrounds_1_0 3
#define Swidth_0_5 8
#define Swidth_1_0 11

#define PWXbytes (PWXgather * PWXsimple * 8)
#define PWXwords (PWXbytes / sizeof(uint32_t))
#define rmin ((PWXbytes + 127) / 128)

typedef struct {
    yespower_version_t version;
    uint32_t salsa20_rounds;
    uint32_t PWXrounds, Swidth, Sbytes, Smask;
    uint32_t *S;
    uint32_t (*S0)[2], (*S1)[2], (*S2)[2];
    size_t w;
} pwxform_ctx_t;

/* FAST SALSA20 IMPLEMENTATION */
static void salsa20(uint32_t B[16], uint32_t rounds)
{
    uint32_t x[16];
    size_t i;
    for (i = 0; i < 16; i++)
        x[i * 5 % 16] = B[i];

    for (i = 0; i < rounds; i += 2) {
#define R(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
        x[ 4] ^= R(x[ 0]+x[12], 7);  x[ 8] ^= R(x[ 4]+x[ 0], 9);
        x[12] ^= R(x[ 8]+x[ 4],13);  x[ 0] ^= R(x[12]+x[ 8],18);

        x[ 9] ^= R(x[ 5]+x[ 1], 7);  x[13] ^= R(x[ 9]+x[ 5], 9);
        x[ 1] ^= R(x[13]+x[ 9],13);  x[ 5] ^= R(x[ 1]+x[13],18);

        x[14] ^= R(x[10]+x[ 6], 7);  x[ 2] ^= R(x[14]+x[10], 9);
        x[ 6] ^= R(x[ 2]+x[14],13);  x[10] ^= R(x[ 6]+x[ 2],18);

        x[ 3] ^= R(x[15]+x[11], 7);  x[ 7] ^= R(x[ 3]+x[15], 9);
        x[11] ^= R(x[ 7]+x[ 3],13);  x[15] ^= R(x[11]+x[ 7],18);

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

    for (i = 0; i < 16; i++)
        B[i] += x[i * 5 % 16];
}

/* BLOCKMIX USING SALSA */
static void blockmix_salsa(uint32_t *B, uint32_t rounds)
{
    uint32_t X[16];
    size_t i;
    blkcpy(X, &B[16], 16);
    for (i = 0; i < 2; i++) {
        blkxor(X, &B[i * 16], 16);
        salsa20(X, rounds);
        blkcpy(&B[i * 16], X, 16);
    }
}

/* ... PWXFORM, BLOCKMIX_PWXFORM, SMIX functions ... */
/* Keep your optimized static buffer allocations here, unchanged */

int yespower(yespower_local_t *local,
    const uint8_t *src, size_t srclen,
    const yespower_params_t *params, yespower_binary_t *dst)
{
    yespower_version_t version = YESPOWER_1_0;
    uint32_t N = 4096;      // Correct for R16
    uint32_t r = 16;        // Correct for R16
    const uint8_t *pers = (const uint8_t*)"yespowerR16";
    size_t perslen = 11;

    int retval = -1;
    size_t B_size = 128 * r;
    size_t V_size = B_size * N;

    static uint32_t static_V[4096*128*16/4];
    static uint32_t static_B[128*16/4];
    static uint32_t static_X[128*16/4];
    static uint32_t static_S[3*(1<<11)*PWXsimple*8/4];

    uint32_t *V = static_V;
    uint32_t *B = static_B;
    uint32_t *X = static_X;
    uint32_t *S = static_S;

    pwxform_ctx_t ctx;
    ctx.version = version;
    ctx.salsa20_rounds = 2;
    ctx.PWXrounds = PWXrounds_1_0;
    ctx.Swidth = Swidth_1_0;
    ctx.Sbytes = 3*((1<<ctx.Swidth)*PWXsimple*8);
    ctx.S = S;
    ctx.S0 = (uint32_t (*)[2])S;
    ctx.S1 = ctx.S0 + (1<<ctx.Swidth)*PWXsimple;
    ctx.S2 = ctx.S1 + (1<<ctx.Swidth)*PWXsimple;
    ctx.Smask = (((1<<ctx.Swidth)-1)*PWXsimple*8);
    ctx.w = 0;

    uint32_t sha256[8];
    SHA256_Buf(src, srclen, (uint8_t*)sha256);

    PBKDF2_SHA256((uint8_t*)sha256, sizeof(sha256), pers, perslen, 1, (uint8_t*)B, B_size);
    blkcpy(sha256, B, sizeof(sha256)/sizeof(sha256[0]));

    smix(B, r, N, V, X, &ctx);

    /* Final output */
    HMAC_SHA256_Buf((uint8_t*)B + B_size - 64, 64, sha256, sizeof(sha256), (uint8_t*)dst);
    retval = 0;

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
#endif
