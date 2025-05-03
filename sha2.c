/*
 * yespower-1.0.1/sha256.c
 * Optimized, refactored SHA-256 + double-SHA + HMAC + PBKDF2 for cpuminer
 *
 * - Single-loop RNDr compression
 * - Two-phase W-schedule generation
 * - Register-based working vars (a–h)
 * - Balanced macros, no __builtin_rotr linker issues
 * - Aligned arrays for better codegen
 */

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

#include "cpuminer-config.h"
#include "miner.h"
#include "sysendian.h"
#include "insecure_memzero.h"

/* Initial SHA256 state */
static const uint32_t H0_IV[8] = {
    0x6A09E667UL,0xBB67AE85UL,0x3C6EF372UL,0xA54FF53AUL,
    0x510E527FUL,0x9B05688CUL,0x1F83D9ABUL,0x5BE0CD19UL
};

/* SHA256 round constants */
static const uint32_t K256[64] = {
    0x428a2f98UL,0x71374491UL,0xb5c0fbcfUL,0xe9b5dba5UL,
    0x3956c25bUL,0x59f111f1UL,0x923f82a4UL,0xab1c5ed5UL,
    0xd807aa98UL,0x12835b01UL,0x243185beUL,0x550c7dc3UL,
    0x72be5d74UL,0x80deb1feUL,0x9bdc06a7UL,0xc19bf174UL,
    0xe49b69c1UL,0xefbe4786UL,0x0fc19dc6UL,0x240ca1ccUL,
    0x2de92c6fUL,0x4a7484aaUL,0x5cb0a9dcUL,0x76f988daUL,
    0x983e5152UL,0xa831c66dUL,0xb00327c8UL,0xbf597fc7UL,
    0xc6e00bf3UL,0xd5a79147UL,0x06ca6351UL,0x14292967UL,
    0x27b70a85UL,0x2e1b2138UL,0x4d2c6dfcUL,0x53380d13UL,
    0x650a7354UL,0x766a0abbUL,0x81c2c92eUL,0x92722c85UL,
    0xa2bfe8a1UL,0xa81a664bUL,0xc24b8b70UL,0xc76c51a3UL,
    0xd192e819UL,0xd6990624UL,0xf40e3585UL,0x106aa070UL,
    0x19a4c116UL,0x1e376c08UL,0x2748774cUL,0x34b0bcb5UL,
    0x391c0cb3UL,0x4ed8aa4aUL,0x5b9cca4fUL,0x682e6ff3UL,
    0x748f82eeUL,0x78a5636fUL,0x84c87814UL,0x8cc70208UL,
    0x90befffaUL,0xa4506cebUL,0xbef9a3f7UL,0xc67178f2UL
};

/* Elementary SHA256 functions */
#define ROTR(x,n)   (((x) >> (n)) | ((x) << (32 - (n))))
#define SHR(x,n)    ((x) >> (n))
#define Ch(x,y,z)   (((x) & ((y) ^ (z))) ^ (z))
#define Maj(x,y,z)  (((x) & ((y) | (z))) | ((y) & (z)))
#define S0(x)       (ROTR(x, 2)  ^ ROTR(x,13) ^ ROTR(x,22))
#define S1(x)       (ROTR(x, 6)  ^ ROTR(x,11) ^ ROTR(x,25))
#define s0(x)       (ROTR(x, 7)  ^ ROTR(x,18) ^ SHR(x, 3))
#define s1(x)       (ROTR(x,17)  ^ ROTR(x,19) ^ SHR(x,10))

/*
 * sha256_transform:
 *   - state: 8-word chain state
 *   - block: 16-word big-endian input block
 *   - swap:  if true, byte-swap each word from host order
 */
void sha256_transform(uint32_t state[8],
                      const uint32_t block[16],
                      int swap)
{
    uint32_t W[64] __attribute__((aligned(16)));
    uint32_t a,b,c,d,e,f,g,h,T1,T2;
    int i;

    /* 1) Build W[0..63] */
    if (swap) {
        for (i = 0; i < 16; i++)
            W[i] = swab32(block[i]);
    } else {
        memcpy(W, block, 16*4);
    }
    for (i = 16; i < 64; i++) {
        W[i] = s1(W[i-2]) + W[i-7] + s0(W[i-15]) + W[i-16];
    }

    /* 2) Initialize registers from state */
    a = state[0];  b = state[1];  c = state[2];  d = state[3];
    e = state[4];  f = state[5];  g = state[6];  h = state[7];

    /* 3) 64 rounds */
    for (i = 0; i < 64; i++) {
        T1 = h + S1(e) + Ch(e,f,g) + K256[i] + W[i];
        T2 = S0(a) + Maj(a,b,c);
        h = g;  g = f;  f = e;  e = d + T1;
        d = c;  c = b;  b = a;  a = T1 + T2;
    }

    /* 4) Write back */
    state[0] += a;  state[1] += b;  state[2] += c;  state[3] += d;
    state[4] += e;  state[5] += f;  state[6] += g;  state[7] += h;
}

/*
 * Double-SHA256 (sha256d) over arbitrary data length.
 * Produces a 32-byte LE hash in 'hash'.
 */
void sha256d(uint8_t *hash,
             const uint8_t *data,
             size_t len)
{
    SHA256_CTX ctx;
    uint8_t mid[32];

    /* First pass */
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(mid, &ctx);

    /* Second pass */
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, mid, 32);
    SHA256_Final(hash, &ctx);
}

/* HMAC-SHA256 and PBKDF2 follow the usual reference implementations */
void HMAC_SHA256_Init(HMAC_SHA256_CTX *ctx,
                     const uint8_t *key,
                     size_t keylen)
{
    uint8_t pad[64], khash[32];
    const uint8_t *K = key;

    if (keylen > 64) {
        SHA256_CTX t;
        SHA256_Init(&t);
        SHA256_Update(&t, key, keylen);
        SHA256_Final(khash, &t);
        K = khash; keylen = 32;
    }

    /* Inner */
    SHA256_Init(&ctx->ictx);
    memset(pad, 0x36, 64);
    for (size_t i = 0; i < keylen; i++) pad[i] ^= K[i];
    SHA256_Update(&ctx->ictx, pad, 64);

    /* Outer */
    SHA256_Init(&ctx->octx);
    memset(pad, 0x5c, 64);
    for (size_t i = 0; i < keylen; i++) pad[i] ^= K[i];
    SHA256_Update(&ctx->octx, pad, 64);

    insecure_memzero(khash, sizeof(khash));
}

void HMAC_SHA256_Update(HMAC_SHA256_CTX *ctx,
                       const uint8_t *data,
                       size_t len)
{
    SHA256_Update(&ctx->ictx, data, len);
}

void HMAC_SHA256_Final(uint8_t digest[32],
                      HMAC_SHA256_CTX *ctx)
{
    uint8_t ih[32];
    SHA256_Final(ih, &ctx->ictx);
    SHA256_Update(&ctx->octx, ih, 32);
    SHA256_Final(digest, &ctx->octx);
    insecure_memzero(ih, sizeof(ih));
}

void HMAC_SHA256_Buf(const uint8_t *key, size_t keylen,
                    const uint8_t *data, size_t len,
                    uint8_t digest[32])
{
    HMAC_SHA256_CTX ctx;
    HMAC_SHA256_Init(&ctx, key, keylen);
    HMAC_SHA256_Update(&ctx, data, len);
    HMAC_SHA256_Final(digest, &ctx);
}

/*
 * PBKDF2-HMAC-SHA256
 */
void PBKDF2_SHA256(const uint8_t *passwd,
                   size_t passwdlen,
                   const uint8_t *salt,
                   size_t saltlen,
                   uint64_t c,
                   uint8_t *out,
                   size_t outlen)
{
    HMAC_SHA256_CTX Ph, PSh, hctx;
    uint8_t U[32], T[32], ivec[4];
    assert(outlen <= 32*(size_t)UINT32_MAX);

    /* Precompute inner+salt context */
    HMAC_SHA256_Init(&Ph, passwd, passwdlen);
    memcpy(&PSh, &Ph, sizeof(Ph));
    HMAC_SHA256_Update(&PSh, salt, saltlen);

    for (size_t i = 0; i * 32 < outlen; i++) {
        uint32_t idx = (uint32_t)(i+1);
        be32enc(ivec, idx);

        memcpy(&hctx, &PSh, sizeof(hctx));
        HMAC_SHA256_Update(&hctx, ivec, 4);
        HMAC_SHA256_Final(U, &hctx);
        memcpy(T, U, 32);

        for (uint64_t j = 2; j <= c; j++) {
            HMAC_SHA256_Init(&hctx, passwd, passwdlen);
            HMAC_SHA256_Update(&hctx, U, 32);
            HMAC_SHA256_Final(U, &hctx);
            for (int k = 0; k < 32; k++)
                T[k] ^= U[k];
        }

        size_t chunk = outlen - i*32;
        if (chunk > 32) chunk = 32;
        memcpy(out + i*32, T, chunk);
    }

    insecure_memzero(&Ph, sizeof(Ph));
    insecure_memzero(&PSh, sizeof(PSh));
    insecure_memzero(&hctx, sizeof(hctx));
    insecure_memzero(U, sizeof(U));
    insecure_memzero(T, sizeof(T));
}
