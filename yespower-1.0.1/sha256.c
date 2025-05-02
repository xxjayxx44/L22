/*
 * yespower-1.0.1/sha256.c
 * Optimized SHA-256, HMAC-SHA256, and PBKDF2-SHA256
 */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "insecure_memzero.h"
#include "sysendian.h"
#include "sha256.h"

#ifdef __ICC
# define restrict
#elif __STDC_VERSION__ >= 199901L
/* restrict supported */
#elif defined(__GNUC__)
# define restrict __restrict
#else
# define restrict
#endif

/* SHA-256 constants */
static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define SHR(x,n)  ((x)>>(n))
#define S0(x)     (ROTR(x, 2) ^ ROTR(x,13) ^ ROTR(x,22))
#define S1(x)     (ROTR(x, 6) ^ ROTR(x,11) ^ ROTR(x,25))
#define s0(x)     (ROTR(x, 7) ^ ROTR(x,18) ^ SHR(x, 3))
#define s1(x)     (ROTR(x,17) ^ ROTR(x,19) ^ SHR(x,10))
#define Ch(x,y,z) (((x)&(y)) ^ (~(x)&(z)))
#define Maj(x,y,z) ((((x)&(y)) ^ ((x)&(z))) ^ ((y)&(z)))

/* Core compression: fully unrolled inner loop */
static void SHA256_Transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[64], S[8];
    int i;

    /* Message schedule W[0..63] */
    for (i = 0; i < 16; i++) {
        W[i] = ((uint32_t)block[4*i] << 24)
             | ((uint32_t)block[4*i+1] << 16)
             | ((uint32_t)block[4*i+2] << 8)
             |  (uint32_t)block[4*i+3];
    }
    for (i = 16; i < 64; i++) {
        W[i] = s1(W[i-2]) + W[i-7] + s0(W[i-15]) + W[i-16];
    }

    /* Initialize working vars */
    for (i = 0; i < 8; i++) S[i] = state[i];

    /* 64 rounds */
    for (i = 0; i < 64; i++) {
        uint32_t T1 = S[7] + S1(S[4]) + Ch(S[4],S[5],S[6]) + K[i] + W[i];
        uint32_t T2 = S0(S[0]) + Maj(S[0],S[1],S[2]);
        S[7] = S[6]; S[6] = S[5]; S[5] = S[4];
        S[4] = S[3] + T1;
        S[3] = S[2]; S[2] = S[1]; S[1] = S[0];
        S[0] = T1 + T2;
    }

    /* Update state */
    for (i = 0; i < 8; i++) state[i] += S[i];
}

/* Pad and append length (in bits), then transform final block(s) */
static void SHA256_Pad(SHA256_CTX *ctx, uint8_t buf[64]) {
    size_t r = (ctx->count >> 3) & 0x3f;
    size_t padlen = (r < 56) ? (56 - r) : (120 - r);
    static const uint8_t PADDING[64] = { 0x80 };

    memcpy(&ctx->buf[r], PADDING, 1);
    if (padlen > 1) memset(&ctx->buf[r+1], 0, padlen-1);

    /* Append length in bits */
    be64enc(&ctx->buf[56], ctx->count);

    /* Process final block(s) */
    SHA256_Transform(ctx->state, ctx->buf);
    if (padlen > 56) {
        /* one extra block needed */
        memset(ctx->buf, 0, 56);
        SHA256_Transform(ctx->state, ctx->buf);
    }
}

void SHA256_Init(SHA256_CTX *ctx) {
    ctx->count = 0;
    static const uint32_t IV[8] = {
        0x6A09E667,0xBB67AE85,0x3C6EF372,0xA54FF53A,
        0x510E527F,0x9B05688C,0x1F83D9AB,0x5BE0CD19
    };
    memcpy(ctx->state, IV, sizeof(IV));
}

void SHA256_Update(SHA256_CTX *ctx, const void *in, size_t len) {
    const uint8_t *data = in;
    size_t r = (ctx->count >> 3) & 0x3f;
    ctx->count += (uint64_t)len << 3;

    if (r && len >= 64 - r) {
        memcpy(&ctx->buf[r], data, 64 - r);
        SHA256_Transform(ctx->state, ctx->buf);
        data += 64 - r;
        len  -= 64 - r;
        r = 0;
    }
    while (len >= 64) {
        SHA256_Transform(ctx->state, data);
        data += 64;
        len  -= 64;
    }
    if (len) memcpy(ctx->buf, data, len);
}

void SHA256_Final(uint8_t digest[32], SHA256_CTX *ctx) {
    SHA256_Pad(ctx, ctx->buf);
    for (int i = 0; i < 8; i++) {
        be32enc(&digest[4*i], ctx->state[i]);
    }
    insecure_memzero(ctx, sizeof(*ctx));
}

void SHA256_Buf(const void *in, size_t len, uint8_t digest[32]) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, in, len);
    SHA256_Final(digest, &ctx);
}

/* HMAC-SHA256 */

static void _HMAC_SHA256_Init(HMAC_SHA256_CTX *ctx,
    const void *K, size_t Klen, uint8_t pad[64], uint32_t tmp32[72], uint8_t khash[32])
{
    if (Klen > 64) {
        SHA256_Init(&ctx->ictx);
        SHA256_Update(&ctx->ictx, K, Klen);
        SHA256_Final(khash, &ctx->ictx);
        K = khash;
        Klen = 32;
    }
    memset(pad, 0x36, 64);
    for (size_t i = 0; i < Klen; i++) pad[i] ^= ((uint8_t*)K)[i];
    SHA256_Init(&ctx->ictx);
    SHA256_Update(&ctx->ictx, pad, 64);

    memset(pad, 0x5c, 64);
    for (size_t i = 0; i < Klen; i++) pad[i] ^= ((uint8_t*)K)[i];
    SHA256_Init(&ctx->octx);
    SHA256_Update(&ctx->octx, pad, 64);
}

void HMAC_SHA256_Init(HMAC_SHA256_CTX *ctx, const void *K, size_t Klen) {
    uint8_t  pad[64], khash[32];
    uint32_t tmp32[72];
    _HMAC_SHA256_Init(ctx, K, Klen, pad, tmp32, khash);
    insecure_memzero(pad, 64);
    insecure_memzero(khash, 32);
    insecure_memzero(tmp32, 288);
}

void HMAC_SHA256_Update(HMAC_SHA256_CTX *ctx, const void *in, size_t len) {
    SHA256_Update(&ctx->ictx, in, len);
}

void HMAC_SHA256_Final(uint8_t digest[32], HMAC_SHA256_CTX *ctx) {
    uint8_t  ihash[32];
    uint32_t tmp32[72];

    SHA256_Final(ihash, &ctx->ictx);
    SHA256_Update(&ctx->octx, ihash, 32);
    SHA256_Final(digest, &ctx->octx);

    insecure_memzero(ihash, 32);
    insecure_memzero(tmp32, 288);
}

/* PBKDF2 with HMAC-SHA256 */

void PBKDF2_SHA256(const uint8_t *passwd, size_t passwdlen,
                   const uint8_t *salt,   size_t saltlen,
                   uint64_t c, uint8_t *buf, size_t dkLen)
{
    HMAC_SHA256_CTX Phctx, PShctx, hctx;
    uint32_t tmp32[72];
    uint8_t  u[32], T[32];
    uint8_t  iv[4];
    size_t   i, j, k, clen;

    assert(dkLen <= 32*(size_t)UINT32_MAX);

    /* Initial HMAC state with password */
    HMAC_SHA256_Init(&Phctx, passwd, passwdlen);
    /* HMAC after password+salt */
    memcpy(&PShctx, &Phctx, sizeof(Phctx));
    HMAC_SHA256_Update(&PShctx, salt, saltlen);

    for (i = 0; i*32 < dkLen; i++) {
        /* INT(i+1) */
        be32enc(iv, (uint32_t)(i+1));

        /* U1 = PRF(P, S||INT) */
        memcpy(&hctx, &PShctx, sizeof(hctx));
        HMAC_SHA256_Update(&hctx, iv, 4);
        HMAC_SHA256_Final(T, &hctx);

        memcpy(u, T, 32);

        for (j = 2; j <= c; j++) {
            HMAC_SHA256_Init(&hctx, passwd, passwdlen);
            HMAC_SHA256_Update(&hctx, u, 32);
            HMAC_SHA256_Final(u, &hctx);
            for (k = 0; k < 32; k++)
                T[k] ^= u[k];
        }

        clen = (dkLen - i*32 > 32) ? 32 : dkLen - i*32;
        memcpy(buf + i*32, T, clen);
    }
    insecure_memzero(tmp32, 288);
}
