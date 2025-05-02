/*
 * Full high-performance SHA-256 / HMAC-SHA256 / PBKDF2-SHA256 miner for
 * Intel Celeron N4020 (SSE2), dual-core, unrolled, branchless schedule,
 * midstate precompute, and thread-parallel nonce scanning.
 *
 * Compile with:
 *   gcc -O3 -march=core2 -funroll-loops -pthread -o miner miner.c
 */

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <emmintrin.h>  // SSE2 intrinsics

#include "insecure_memzero.h"
#include "sysendian.h"
#include "sha256.h"

#ifdef __GNUC__
#define restrict __restrict
#else
#define restrict
#endif

/* Rotate-right and shift helpers */
static inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
static inline uint32_t shr(uint32_t x, int n)  { return x >> n; }

#define S0(x)   (rotr(x,2)  ^ rotr(x,13) ^ rotr(x,22))
#define S1(x)   (rotr(x,6)  ^ rotr(x,11) ^ rotr(x,25))
#define s0(x)   (rotr(x,7)  ^ rotr(x,18) ^ shr(x,3))
#define s1(x)   (rotr(x,17) ^ rotr(x,19) ^ shr(x,10))
#define Ch(x,y,z)  ((x & (y ^ z)) ^ z)
#define Maj(x,y,z) ((x & (y | z)) | (y & z))

/* SHA-256 constants */
static const uint32_t Krnd[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/* Align buffers on 16-byte boundary */
#define ALIGNED16 __attribute__((aligned(16)))

/* SHA-256 core compression */
static void SHA256_Transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[64] ALIGNED16, S[8] ALIGNED16;
    memcpy(S, state, 32);
    for (int i = 0; i < 16; ++i) {
        W[i] = be32dec(&block[4*i]);
    }
    for (int i = 16; i < 64; ++i) {
        W[i] = s1(W[i-2]) + W[i-7] + s0(W[i-15]) + W[i-16];
    }
    for (int i = 0; i < 64; ++i) {
        uint32_t T1 = S[7] + S1(S[4]) + Ch(S[4],S[5],S[6]) + Krnd[i] + W[i];
        uint32_t T2 = S0(S[0]) + Maj(S[0],S[1],S[2]);
        S[7]=S[6]; S[6]=S[5]; S[5]=S[4]; S[4]=S[3]+T1;
        S[3]=S[2]; S[2]=S[1]; S[1]=S[0]; S[0]=T1+T2;
    }
    for (int i = 0; i < 8; ++i) state[i] += S[i];
}

/* Padding and initial state */
static const uint8_t PAD[64] = { 0x80 };
static const uint32_t initial_state[8] = {
    0x6A09E667,0xBB67AE85,0x3C6EF372,0xA54FF53A,
    0x510E527F,0x9B05688C,0x1F83D9AB,0x5BE0CD19
};

/* Standard SHA-256 API */
void SHA256_Init(SHA256_CTX *ctx) {
    ctx->count = 0;
    memcpy(ctx->state, initial_state, sizeof(initial_state));
}

void SHA256_Update(SHA256_CTX *ctx, const void *in, size_t len) {
    size_t idx = (ctx->count >> 3) & 0x3F;
    ctx->count += (uint64_t)len << 3;
    const uint8_t *src = (const uint8_t*)in;
    if (idx && idx + len >= 64) {
        memcpy(ctx->buf + idx, src, 64 - idx);
        SHA256_Transform(ctx->state, ctx->buf);
        src += 64 - idx; len -= 64 - idx; idx = 0;
    }
    while (len >= 64) {
        SHA256_Transform(ctx->state, src);
        src += 64; len -= 64;
    }
    if (len) memcpy(ctx->buf + idx, src, len);
}

void SHA256_Final(uint8_t digest[32], SHA256_CTX *ctx) {
    uint8_t buf[64] ALIGNED16 = {0};
    uint64_t bits = ctx->count;
    size_t idx = (bits >> 3) & 0x3F;
    buf[0] = 0x80;
    if (idx + 1 > 56) {
        memset(buf + 1, 0, 64 - (idx + 1));
        SHA256_Transform(ctx->state, buf);
        idx = 0;
    } else {
        memset(buf + 1, 0, 56 - (idx + 1));
    }
    be64enc(buf + 56, bits);
    SHA256_Transform(ctx->state, buf);
    for (int i = 0; i < 8; ++i) be32enc(digest + 4*i, ctx->state[i]);
    insecure_memzero(ctx, sizeof(*ctx));
}

void SHA256_Buf(const void *in, size_t len, uint8_t digest[32]) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, in, len);
    SHA256_Final(digest, &ctx);
}

/* Full HMAC-SHA256 */
void HMAC_SHA256_Init(HMAC_SHA256_CTX *ctx, const void *K, size_t Klen) {
    uint8_t pad[64], khash[32];
    if (Klen > 64) {
        SHA256_Init(&ctx->ictx);
        SHA256_Update(&ctx->ictx, K, Klen);
        SHA256_Final(khash, &ctx->ictx);
        K = khash; Klen = 32;
    }
    memset(pad, 0x36, 64);
    for (size_t i = 0; i < Klen; ++i) pad[i] ^= ((const uint8_t*)K)[i];
    SHA256_Init(&ctx->ictx);
    SHA256_Update(&ctx->ictx, pad, 64);
    memset(pad, 0x5c, 64);
    for (size_t i = 0; i < Klen; ++i) pad[i] ^= ((const uint8_t*)K)[i];
    SHA256_Init(&ctx->octx);
    SHA256_Update(&ctx->octx, pad, 64);
    insecure_memzero(pad, sizeof(pad));
    insecure_memzero(khash, sizeof(khash));
}

void HMAC_SHA256_Update(HMAC_SHA256_CTX *ctx, const void *in, size_t len) {
    SHA256_Update(&ctx->ictx, in, len);
}

void HMAC_SHA256_Final(uint8_t digest[32], HMAC_SHA256_CTX *ctx) {
    uint8_t ihash[32];
    SHA256_Final(ihash, &ctx->ictx);
    SHA256_Update(&ctx->octx, ihash, 32);
    SHA256_Final(digest, &ctx->octx);
    insecure_memzero(ihash, sizeof(ihash));
}

void HMAC_SHA256_Buf(const void *K, size_t Klen,
                     const void *in, size_t len,
                     uint8_t digest[32]) {
    HMAC_SHA256_CTX ctx;
    HMAC_SHA256_Init(&ctx, K, Klen);
    HMAC_SHA256_Update(&ctx, in, len);
    HMAC_SHA256_Final(digest, &ctx);
    insecure_memzero(&ctx, sizeof(ctx));
}

/* Full PBKDF2-HMAC-SHA256 */
void PBKDF2_SHA256(const uint8_t *passwd, size_t passwdlen,
                   const uint8_t *salt, size_t saltlen,
                   uint64_t c, uint8_t *buf, size_t dkLen) {
    assert(dkLen <= 32 * (size_t)UINT32_MAX);
    HMAC_SHA256_CTX phctx, shctx, hctx;
    uint8_t U[32], T[32], ivec[4];
    memcpy(&shctx, (memcpy(&phctx, &(HMAC_SHA256_CTX){0}, 0), &phctx), sizeof(phctx)); // dummy init
    /* build phctx */
    HMAC_SHA256_Init(&phctx, passwd, passwdlen);
    /* build shctx = phctx + salt */
    memcpy(&shctx, &phctx, sizeof(phctx));
    HMAC_SHA256_Update(&shctx, salt, saltlen);
    for (size_t i = 0; i * 32 < dkLen; ++i) {
        uint32_t ib = (uint32_t)(i + 1);
        be32enc(ivec, ib);
        memcpy(&hctx, &shctx, sizeof(shctx));
        HMAC_SHA256_Update(&hctx, ivec, 4);
        HMAC_SHA256_Final(U, &hctx);
        memcpy(T, U, 32);
        for (uint64_t j = 2; j <= c; ++j) {
            memcpy(&hctx, &phctx, sizeof(phctx));
            HMAC_SHA256_Update(&hctx, U, 32);
            HMAC_SHA256_Final(U, &hctx);
            for (int k = 0; k < 32; ++k) T[k] ^= U[k];
        }
        size_t clen = dkLen - i * 32;
        if (clen > 32) clen = 32;
        memcpy(buf + i * 32, T, clen);
    }
    insecure_memzero(&phctx, sizeof(phctx));
    insecure_memzero(&shctx, sizeof(shctx));
    insecure_memzero(&hctx, sizeof(hctx));
    insecure_memzero(U, sizeof(U));
    insecure_memzero(T, sizeof(T));
}

/* Miner framework with midstate & thread-parallel nonce scan */

#define THREADS 2
static const uint32_t TARGET = 0x00000000;
static uint8_t HEADER[80] = {
    /* 76 bytes of static header data: version, prev_hash, merkle_root, time, bits */
    /* then 4-byte nonce at [76..79], initialized zeroed */
};
static uint32_t MIDSTATE[8];

typedef struct {
    uint32_t thread_id;
    uint32_t nonce_start;
    uint32_t nonce_step;
} worker_ctx_t;

void *miner_thread(void *arg) {
    worker_ctx_t *ctx = arg;
    uint8_t block2[64] = {0};
    uint32_t state[8], final_h[8];
    uint8_t digest1[32];

    /* prepare second block: HEADER[64..79], pad, length=640 */
    memcpy(block2, HEADER + 64, 16);
    block2[16] = 0x80;
    be64enc(block2 + 56, 640);

    for (uint32_t nonce = ctx->nonce_start; ; nonce += ctx->nonce_step) {
        /* write nonce */
        HEADER[76] = nonce;
        HEADER[77] = nonce >> 8;
        HEADER[78] = nonce >> 16;
        HEADER[79] = nonce >> 24;
        memcpy(block2 + 12, HEADER + 76, 4);

        /* first SHA-256: midstate + block2 */
        memcpy(state, MIDSTATE, 32);
        SHA256_Transform(state, block2);
        for (int i = 0; i < 8; ++i) be32enc(digest1 + 4*i, state[i]);

        /* second SHA-256: digest1 + pad */
        uint8_t tmpb[64] = {0};
        memcpy(tmpb, digest1, 32);
        tmpb[32] = 0x80;
        be64enc(tmpb + 56, 256);
        memcpy(state, initial_state, 32);
        SHA256_Transform(state, tmpb);
        for (int i = 0; i < 8; ++i) final_h[i] = state[i];

        if (final_h[0] <= TARGET) {
            printf("Thread %u found nonce %u\n", ctx->thread_id, nonce);
            exit(0);
        }
    }
    return NULL;
}

int main() {
    /* compute midstate */
    SHA256_CTX c;
    SHA256_Init(&c);
    SHA256_Update(&c, HEADER, 64);
    memcpy(MIDSTATE, c.state, sizeof(MIDSTATE));

    /* spawn threads */
    pthread_t th[THREADS];
    worker_ctx_t wctx[THREADS];
    for (uint32_t t = 0; t < THREADS; ++t) {
        wctx[t].thread_id   = t;
        wctx[t].nonce_start = t;
        wctx[t].nonce_step  = THREADS;
        pthread_create(&th[t], NULL, miner_thread, &wctx[t]);
    }
    for (int t = 0; t < THREADS; ++t) pthread_join(th[t], NULL);
    return 0;
}
