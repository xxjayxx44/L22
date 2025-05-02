/*-
 * Copyright 2005-2016 Colin Percival
 * Copyright 2016-2018 Alexander Peslyak
 * All rights reserved.
 *
 * [License text identical to original]
 */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "insecure_memzero.h"
#include "sysendian.h"
#include "sha256.h"

/* Compiler-specific restrict qualifier handling */
#if defined(__ICC)
#define restrict
#elif defined(__GNUC__) || defined(__clang__)
#define restrict __restrict__
#else
#define restrict
#endif

/* Byte manipulation functions */
static void be32enc_vect(uint8_t *restrict dst, const uint32_t *restrict src, size_t len) {
    while (len--) {
        be32enc(dst, src[0]);
        be32enc(dst + 4, src[1]);
        src += 2;
        dst += 8;
    }
}

static void be32dec_vect(uint32_t *restrict dst, const uint8_t *restrict src, size_t len) {
    while (len--) {
        dst[0] = be32dec(src);
        dst[1] = be32dec(src + 4);
        src += 8;
        dst += 2;
    }
}

/* SHA-256 constants and macros */
static const uint32_t Krnd[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define Ch(x, y, z)     (((x) & ((y) ^ (z))) ^ (z))
#define Maj(x, y, z)    (((x) & ((y) | (z))) | ((y) & (z)))
#define ROTR(x, n)      (((x) >> (n)) | ((x) << (32 - (n))))
#define S0(x)           (ROTR(x, 2)  ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S1(x)           (ROTR(x, 6)  ^ ROTR(x, 11) ^ ROTR(x, 25))
#define s0(x)           (ROTR(x, 7)  ^ ROTR(x, 18) ^ ((x) >> 3))
#define s1(x)           (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

#define RND(a, b, c, d, e, f, g, h, k, w) \
    do { \
        uint32_t t0 = h + S1(e) + Ch(e, f, g) + k + w; \
        uint32_t t1 = S0(a) + Maj(a, b, c); \
        d += t0; \
        h = t0 + t1; \
    } while (0)

/* SHA-256 core transformation */
static void SHA256_Transform(uint32_t state[static restrict 8],
                             const uint8_t block[static restrict 64],
                             uint32_t W[static restrict 64],
                             uint32_t S[static restrict 8]) {
    /* Prepare message schedule */
    be32dec_vect(W, block, 8);
    for (int i = 16; i < 64; ++i)
        W[i] = s1(W[i-2]) + W[i-7] + s0(W[i-15]) + W[i-16];

    /* Load state */
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h_val = state[7];

    /* 64 rounds of SHA-256 */
    for (int i = 0; i < 64; ++i) {
        RND(a, b, c, d, e, f, g, h_val, Krnd[i], W[i]);
        /* Rotate state registers */
        uint32_t t = h_val; 
        h_val = g; 
        g = f; 
        f = e; 
        e = d; 
        d = c; 
        c = b; 
        b = a; 
        a = t;
    }

    /* Update state */
    state[0] += a; 
    state[1] += b; 
    state[2] += c; 
    state[3] += d;
    state[4] += e; 
    state[5] += f; 
    state[6] += g; 
    state[7] += h_val;
}

/* Padding and finalization */
static const uint8_t PAD[64] = {0x80};
static const uint32_t INITIAL_STATE[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

void SHA256_Init(SHA256_CTX *ctx) {
    memcpy(ctx->state, INITIAL_STATE, sizeof(ctx->state));
    ctx->count = 0;
}

static void SHA256_ProcessBlock(SHA256_CTX *ctx, const uint8_t *block,
                               uint32_t tmp32[static restrict 72]) {
    SHA256_Transform(ctx->state, block, &tmp32[0], &tmp32[64]);
}

void SHA256_Update(SHA256_CTX *ctx, const void *in, size_t len) {
    const uint8_t *src = in;
    size_t r = (ctx->count >> 3) & 0x3F;
    uint32_t tmp32[72];
    
    ctx->count += (uint64_t)len << 3;
    
    /* Process initial partial block */
    if (r) {
        size_t rem = 64 - r;
        if (len < rem) {
            memcpy(ctx->buf + r, src, len);
            return;
        }
        memcpy(ctx->buf + r, src, rem);
        SHA256_ProcessBlock(ctx, ctx->buf, tmp32);
        src += rem;
        len -= rem;
    }
    
    /* Process full blocks */
    while (len >= 64) {
        SHA256_ProcessBlock(ctx, src, tmp32);
        src += 64;
        len -= 64;
    }
    
    /* Store remaining data */
    memcpy(ctx->buf, src, len);
    insecure_memzero(tmp32, sizeof(tmp32));
}

void SHA256_Final(uint8_t digest[32], SHA256_CTX *ctx) {
    uint32_t tmp32[72];
    uint8_t len[8];
    size_t r = (ctx->count >> 3) & 0x3F;
    size_t padlen = (r < 56) ? (56 - r) : (120 - r);
    
    be64enc(len, ctx->count);
    SHA256_Update(ctx, PAD, padlen);
    SHA256_Update(ctx, len, 8);
    
    be32enc_vect(digest, ctx->state, 8);
    insecure_memzero(ctx, sizeof(SHA256_CTX));
    insecure_memzero(tmp32, sizeof(tmp32));
}

/* HMAC-SHA256 implementation */
typedef struct HMAC_SHA256_CTX {
    SHA256_CTX ictx;
    SHA256_CTX octx;
} HMAC_SHA256_CTX;

void HMAC_SHA256_Init(HMAC_SHA256_CTX *ctx, const void *K, size_t Klen) {
    uint8_t pad[64] = {0};
    uint8_t khash[32];
    uint32_t tmp32[72];
    
    if (Klen > 64) {
        SHA256_Buf(K, Klen, khash);
        K = khash;
        Klen = 32;
    }
    
    /* Inner key */
    for (size_t i = 0; i < Klen; ++i) pad[i] = 0x36 ^ ((const uint8_t *)K)[i];
    SHA256_Init(&ctx->ictx);
    SHA256_Update(&ctx->ictx, pad, 64);
    
    /* Outer key */
    memset(pad, 0x5c, 64);
    for (size_t i = 0; i < Klen; ++i) pad[i] ^= ((const uint8_t *)K)[i];
    SHA256_Init(&ctx->octx);
    SHA256_Update(&ctx->octx, pad, 64);
    
    insecure_memzero(khash, sizeof(khash));
    insecure_memzero(pad, sizeof(pad));
    insecure_memzero(tmp32, sizeof(tmp32));
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

/* PBKDF2-HMAC-SHA256 implementation */
void PBKDF2_SHA256(const uint8_t *passwd, size_t passwdlen,
                   const uint8_t *salt, size_t saltlen, uint64_t c,
                   uint8_t *buf, size_t dkLen) {
    HMAC_SHA256_CTX ctx, hctx;
    uint8_t ivec[4], U[32], T[32];
    
    assert(dkLen <= 32 * (size_t)UINT32_MAX);
    
    for (uint32_t i = 1; dkLen > 0; ++i) {
        be32enc(ivec, i);
        
        /* Compute U_1 */
        HMAC_SHA256_Init(&ctx, passwd, passwdlen);
        HMAC_SHA256_Update(&ctx, salt, saltlen);
        HMAC_SHA256_Update(&ctx, ivec, 4);
        HMAC_SHA256_Final(U, &ctx);
        memcpy(T, U, 32);
        
        /* Compute subsequent U values */
        for (uint64_t j = 1; j < c; ++j) {
            HMAC_SHA256_Init(&hctx, passwd, passwdlen);
            HMAC_SHA256_Update(&hctx, U, 32);
            HMAC_SHA256_Final(U, &hctx);
            for (int k = 0; k < 32; ++k)
                T[k] ^= U[k];
        }
        
        /* Copy output */
        size_t clen = dkLen < 32 ? dkLen : 32;
        memcpy(buf, T, clen);
        buf += clen;
        dkLen -= clen;
    }
    
    insecure_memzero(&ctx, sizeof(ctx));
    insecure_memzero(U, sizeof(U));
    insecure_memzero(T, sizeof(T));
}
