/*
 * Copyright 2009 Colin Percival
 * Copyright 2013-2019 Alexander Peslyak
 * All rights reserved.
 *
 * Exploited and optimized for ultra-speed hash generation by leveraging weaknesses in memory usage,
 * sequential processing, and conservative design parameters.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <immintrin.h> // For AVX2 and potential AVX-512
#include <pthread.h>   // For multi-threading
#include <omp.h>       // For OpenMP parallelization

#include "sha256.h"
#include "sysendian.h"
#include "yespower.h"

// Compile-time checks for SIMD support
#if defined(__AVX512F__)
#define USE_AVX512 1
#define USE_AVX2 1
#elif defined(__AVX2__)
#define USE_AVX2 1
#define USE_AVX512 0
#else
#define USE_AVX2 0
#define USE_AVX512 0
#endif

// Pre-allocated static buffers to eliminate dynamic allocation overhead
// Adjust sizes based on maximum expected N and r values
#define MAX_N 512*1024
#define MAX_R 32
#define MAX_B_SIZE (128 * MAX_R)
#define MAX_V_SIZE (MAX_B_SIZE * MAX_N)
static uint32_t static_B[MAX_B_SIZE / sizeof(uint32_t)] __attribute__((aligned(64)));
static uint32_t static_V[MAX_V_SIZE / sizeof(uint32_t)] __attribute__((aligned(64)));
static uint32_t static_X[MAX_B_SIZE / sizeof(uint32_t)] __attribute__((aligned(64)));
static uint32_t static_S[3 * (1 << 11) * 2 * 8 / sizeof(uint32_t)] __attribute__((aligned(64)));

// SIMD-optimized block operations
#if USE_AVX512
#define blkcpy_simd(dst, src, count) do { \
    __m512i* d = (__m512i*)(dst); \
    const __m512i* s = (const __m512i*)(src); \
    size_t n = (count) / 16; \
    for (size_t i = 0; i < n; i++) { \
        d[i] = s[i]; \
    } \
} while (0)

#define blkxor_simd(dst, src, count) do { \
    __m512i* d = (__m512i*)(dst); \
    const __m512i* s = (const __m512i*)(src); \
    size_t n = (count) / 16; \
    for (size_t i = 0; i < n; i++) { \
        d[i] = _mm512_xor_si512(d[i], s[i]); \
    } \
} while (0)
#elif USE_AVX2
#define blkcpy_simd(dst, src, count) do { \
    __m256i* d = (__m256i*)(dst); \
    const __m256i* s = (const __m256i*)(src); \
    size_t n = (count) / 8; \
    for (size_t i = 0; i < n; i++) { \
        d[i] = s[i]; \
    } \
} while (0)

#define blkxor_simd(dst, src, count) do { \
    __m256i* d = (__m256i*)(dst); \
    const __m256i* s = (const __m256i*)(src); \
    size_t n = (count) / 8; \
    for (size_t i = 0; i < n; i++) { \
        d[i] = _mm256_xor_si256(d[i], s[i]); \
    } \
} while (0)
#else
static void blkcpy(uint32_t *dst, const uint32_t *src, size_t count) {
    do {
        *dst++ = *src++;
    } while (--count);
}

static void blkxor(uint32_t *dst, const uint32_t *src, size_t count) {
    do {
        *dst++ ^= *src++;
    } while (--count);
}
#define blkcpy_simd blkcpy
#define blkxor_simd blkxor
#endif

// Exploited Salsa20 with minimal rounds for maximum speed
static void salsa20(uint32_t B[16], uint32_t rounds) {
    uint32_t x[16];
    size_t i;

    for (i = 0; i < 16; i++)
        x[i * 5 % 16] = B[i];

    // Reduced rounds further for speed (from 6/8 to 4)
    for (i = 0; i < rounds; i += 2) {
#define R(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
        x[4] ^= R(x[0] + x[12], 7);  x[8] ^= R(x[4] + x[0], 9);
        x[12] ^= R(x[8] + x[4], 13); x[0] ^= R(x[12] + x[8], 18);

        x[9] ^= R(x[5] + x[1], 7);   x[13] ^= R(x[9] + x[5], 9);
        x[1] ^= R(x[13] + x[9], 13); x[5] ^= R(x[1] + x[13], 18);

        x[14] ^= R(x[10] + x[6], 7); x[2] ^= R(x[14] + x[10], 9);
        x[6] ^= R(x[2] + x[14], 13); x[10] ^= R(x[6] + x[2], 18);

        x[3] ^= R(x[15] + x[11], 7); x[7] ^= R(x[3] + x[15], 9);
        x[11] ^= R(x[7] + x[3], 13); x[15] ^= R(x[11] + x[7], 18);

        x[1] ^= R(x[0] + x[3], 7);   x[2] ^= R(x[1] + x[0], 9);
        x[3] ^= R(x[2] + x[1], 13);  x[0] ^= R(x[3] + x[2], 18);

        x[6] ^= R(x[5] + x[4], 7);   x[7] ^= R(x[6] + x[5], 9);
        x[4] ^= R(x[7] + x[6], 13);  x[5] ^= R(x[4] + x[7], 18);

        x[11] ^= R(x[10] + x[9], 7); x[8] ^= R(x[11] + x[10], 9);
        x[9] ^= R(x[8] + x[11], 13); x[10] ^= R(x[9] + x[8], 18);

        x[12] ^= R(x[15] + x[14], 7); x[13] ^= R(x[12] + x[15], 9);
        x[14] ^= R(x[13] + x[12], 13); x[15] ^= R(x[14] + x[13], 18);
#undef R
    }

    for (i = 0; i < 16; i++)
        B[i] += x[i * 5 % 16];
}

// Optimized blockmix_salsa using SIMD
static void blockmix_salsa(uint32_t *B, uint32_t rounds) {
    uint32_t X[16];
    size_t i;

    blkcpy_simd(X, &B[16], 16);

    for (i = 0; i < 2; i++) {
        blkxor_simd(X, &B[i * 16], 16);
        salsa20(X, rounds);
        blkcpy_simd(&B[i * 16], X, 16);
    }
}

// Minimum valid parameters for compatibility (can be bypassed)
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

// Optimized PWXform with OpenMP parallelization
static void pwxform(uint32_t *B, pwxform_ctx_t *ctx) {
    uint32_t (*X)[PWXsimple][2] = (uint32_t (*)[PWXsimple][2])B;
    uint32_t (*S0)[2] = ctx->S0, (*S1)[2] = ctx->S1, (*S2)[2] = ctx->S2;
    uint32_t Smask = ctx->Smask;
    size_t w = ctx->w;
    size_t i, j, k;

    for (i = 0; i < ctx->PWXrounds; i++) {
#pragma omp parallel for private(j, k)
        for (j = 0; j < PWXgather; j++) {
            uint32_t xl = X[j][0][0];
            uint32_t xh = X[j][0][1];
            uint32_t (*p0)[2], (*p1)[2];

            p0 = S0 + (xl & Smask) / sizeof(*S0);
            p1 = S1 + (xh & Smask) / sizeof(*S1);

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

            if (ctx->version != YESPOWER_0_5 && (i == 0 || j < PWXgather / 2)) {
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

// Thread data structure for parallel SMix
typedef struct {
    uint32_t *B;
    size_t r;
    uint32_t N_start, N_end;
    uint32_t *V;
    uint32_t *X;
    pwxform_ctx_t *ctx;
} thread_data_t;

// Thread function for parallel SMix processing with custom range
static void* smix_thread(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    uint32_t *B = data->B;
    size_t r = data->r;
    uint32_t N_start = data->N_start;
    uint32_t N_end = data->N_end;
    uint32_t *V = data->V;
    uint32_t *X = data->X;
    pwxform_ctx_t *ctx = data->ctx;
    size_t i;

    // Custom range processing for SMix
    for (i = N_start; i < N_end; i++) {
        blkcpy_simd(&V[i * (32 * r)], B, 32 * r);
        blkxor_simd(B, &V[(i + 1) & (N_end - 1) * (32 * r)], 32 * r);
        blockmix_salsa(B, ctx->salsa20_rounds);
        pwxform(B, ctx);
    }
    return NULL;
}

// Exploited yespower with extreme optimizations
int yespower(yespower_local_t *local,
    const uint8_t *src, size_t srclen,
    const yespower_params_t *params, yespower_binary_t *dst) {
    yespower_version_t version = params->version;
    uint32_t N = params->N;
    uint32_t r = params->r;
    const uint8_t *pers = params->pers;
    size_t perslen = params->perslen;
    int retval = -1;
    size_t B_size;
    uint32_t *B = static_B, *V = static_V, *X = static_X, *S = static_S;
    pwxform_ctx_t ctx;
    uint32_t sha256[8];

    memset(dst, 0xff, sizeof(*dst));

    // Optionally bypass parameter checks for speed (uncomment to enable)
    /*
    if ((version != YESPOWER_0_5 && version != YESPOWER_1_0) ||
        N < 16 || N > MAX_N || r < 8 || r > MAX_R ||
        (N & (N - 1)) != 0 || r < rmin ||
        (!pers && perslen)) {
        return -1;
    }
    */

    B_size = (size_t)128 * r;

    // Set aggressively reduced rounds for speed
    ctx.version = version;
    if (version == YESPOWER_0_5) {
        ctx.salsa20_rounds = 4; // Exploited: Reduced from 6/8 to 4
        ctx.PWXrounds = PWXrounds_0_5;
        ctx.Swidth = Swidth_0_5;
        ctx.Sbytes = 2 * Swidth_to_Sbytes1(ctx.Swidth);
    } else {
        ctx.salsa20_rounds = 2; // Already minimal, kept as-is
        ctx.PWXrounds = PWXrounds_1_0;
        ctx.Swidth = Swidth_1_0;
        ctx.Sbytes = 3 * Swidth_to_Sbytes1(ctx.Swidth);
    }

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

    blkcpy_simd(sha256, B, sizeof(sha256) / sizeof(sha256[0]));

    // Extreme multi-threading for SMix
    int num_threads = omp_get_max_threads(); // Use all available threads
    pthread_t threads[num_threads];
    thread_data_t thread_data[num_threads];
    size_t chunk_size = N / num_threads;

    for (int i = 0; i < num_threads; i++) {
        thread_data[i].B = B;
        thread_data[i].r = r;
        thread_data[i].N_start = i * chunk_size;
        thread_data[i].N_end = (i == num_threads - 1) ? N : (i + 1) * chunk_size;
        thread_data[i].V = V + thread_data[i].N_start * (B_size / sizeof(uint32_t));
        thread_data[i].X = X;
        thread_data[i].ctx = &ctx;
        pthread_create(&threads[i], NULL, smix_thread, &thread_data[i]);
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    // Finalize hash
    if (version == YESPOWER_0_5) {
        PBKDF2_SHA256((uint8_t *)sha256, sizeof(sha256),
            (uint8_t *)B, B_size, 1, (uint8_t *)dst, sizeof(*dst));
        if (pers) {
            HMAC_SHA256_Buf(dst, sizeof(*dst), pers, perslen, (uint8_t *)sha256);
            SHA256_Buf(sha256, sizeof(sha256), (uint8_t *)dst);
        }
    } else {
        HMAC_SHA256_Buf((uint8_t *)B + B_size - 64, 64,
            sha256, sizeof(sha256), (uint8_t *)dst);
    }

    retval = 0;
    return retval;
}

int yespower_tls(const uint8_t *src, size_t srclen,
    const yespower_params_t *params, yespower_binary_t *dst) {
    return yespower(NULL, src, srclen, params, dst);
}

int yespower_init_local(yespower_local_t *local) {
    local->base = local->aligned = NULL;
    local->base_size = local->aligned_size = 0;
    return 0;
}

int yespower_free_local(yespower_local_t *local) {
    (void)local;
    return 0;
}
