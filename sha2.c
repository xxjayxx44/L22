/*
 * yespower-1.0.1/sha256.c
 * Optimized SHA-256 + double-SHA256 + HMAC-SHA256 + PBKDF2-HMAC-SHA256
 * No dependency on sysendian.h — all BE helpers inlined
 */

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

#include "cpuminer-config.h"
#include "miner.h"


/* --- Big-endian encode/decode helpers --- */
static inline uint32_t be32dec(const uint8_t *p) {
    return ((uint32_t)p[0] << 24)
         | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] <<  8)
         | ((uint32_t)p[3]      );
}

static inline void be32enc(uint8_t *p, uint32_t x) {
    p[0] = (uint8_t)(x >> 24);
    p[1] = (uint8_t)(x >> 16);
    p[2] = (uint8_t)(x >>  8);
    p[3] = (uint8_t) x;
}

static inline void be64enc(uint8_t *p, uint64_t x) {
    p[0] = (uint8_t)(x >> 56);
    p[1] = (uint8_t)(x >> 48);
    p[2] = (uint8_t)(x >> 40);
    p[3] = (uint8_t)(x >> 32);
    p[4] = (uint8_t)(x >> 24);
    p[5] = (uint8_t)(x >> 16);
    p[6] = (uint8_t)(x >>  8);
    p[7] = (uint8_t) x;
}

/* Byte-swap 32-bit word */
static inline uint32_t swab32(uint32_t x) {
    return ((x << 24) & 0xff000000u)
         | ((x <<  8) & 0x00ff0000u)
         | ((x >>  8) & 0x0000ff00u)
         | ((x >> 24) & 0x000000ffu);
}

/* --- SHA-256 constants & macros --- */
static const uint32_t H0_IV[8] = {
    0x6A09E667UL,0xBB67AE85UL,0x3C6EF372UL,0xA54FF53AUL,
    0x510E527FUL,0x9B05688CUL,0x1F83D9ABUL,0x5BE0CD19UL
};

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

#define ROTR(x,n)   (((x) >> (n)) | ((x) << (32 - (n))))
#define SHR(x,n)    ((x) >> (n))
#define Ch(x,y,z)   (((x) & ((y) ^ (z))) ^ (z))
#define Maj(x,y,z)  (((x) & ((y) | (z))) | ((y) & (z)))
#define S0(x)       (ROTR(x, 2)  ^ ROTR(x,13) ^ ROTR(x,22))
#define S1(x)       (ROTR(x, 6)  ^ ROTR(x,11) ^ ROTR(x,25))
#define s0(x)       (ROTR(x, 7)  ^ ROTR(x,18) ^ SHR(x, 3))
#define s1(x)       (ROTR(x,17)  ^ ROTR(x,19) ^ SHR(x,10))

/* --- Core block transform --- */
void sha256_transform(uint32_t state[8],
                      const uint32_t block[16],
                      int swap)
{
    uint32_t W[64] __attribute__((aligned(16)));
    uint32_t a,b,c,d,e,f,g,h,T1,T2;
    int i;

    /* 1) Build message schedule */
    if (swap) {
        for (i = 0; i < 16; i++)
            W[i] = swab32(block[i]);
    } else {
        memcpy(W, block, 16 * 4);
    }
    for (i = 16; i < 64; i++)
        W[i] = s1(W[i-2]) + W[i-7] + s0(W[i-15]) + W[i-16];

    /* 2) Initialize working vars */
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    /* 3) 64 rounds */
    for (i = 0; i < 64; i++) {
        T1 = h + S1(e) + Ch(e,f,g) + K256[i] + W[i];
        T2 = S0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    /* 4) Update state */
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

/* --- SHA-256 API wrappers --- */
void SHA256_Init(SHA256_CTX *ctx) {
    ctx->count = 0;
    memcpy(ctx->state, H0_IV, sizeof(H0_IV));
}

void SHA256_Update(SHA256_CTX *ctx, const uint8_t *data, size_t len) {
    size_t r = (ctx->count >> 3) & 0x3F;
    ctx->count += (uint64_t)len << 3;

    if (r && len) {
        size_t tofill = 64 - r;
        if (len < tofill) {
            memcpy(&ctx->buf[r], data, len);
            return;
        }
        memcpy(&ctx->buf[r], data, tofill);
        sha256_transform(ctx->state, (const uint32_t*)ctx->buf, 1);
        data += tofill; len -= tofill;
    }
    while (len >= 64) {
        sha256_transform(ctx->state, (const uint32_t*)data, 1);
        data += 64; len -= 64;
    }
    if (len) {
        memcpy(ctx->buf, data, len);
    }
}

void SHA256_Final(uint8_t digest[32], SHA256_CTX *ctx) {
    uint8_t tmp[8];
    size_t r = (ctx->count >> 3) & 0x3F;

    /* Pad */
    ctx->buf[r++] = 0x80;
    if (r > 56) {
        memset(&ctx->buf[r], 0, 64 - r);
        sha256_transform(ctx->state, (const uint32_t*)ctx->buf, 1);
        r = 0;
    }
    memset(&ctx->buf[r], 0, 56 - r);
    be64enc(tmp, ctx->count);
    memcpy(&ctx->buf[56], tmp, 8);
    sha256_transform(ctx->state, (const uint32_t*)ctx->buf, 1);

    /* Output */
    for (int i = 0; i < 8; i++)
        be32enc(&digest[i*4], ctx->state[i]);
    insecure_memzero(ctx, sizeof(*ctx));
}

/* --- Double-SHA256 --- */
void sha256d(uint8_t *hash, const uint8_t *data, size_t len) {
    SHA256_CTX ctx;
    uint8_t mid[32];

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(mid, &ctx);

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, mid, 32);
    SHA256_Final(hash, &ctx);
}

/* --- HMAC-SHA256 --- */
void HMAC_SHA256_Init(HMAC_SHA256_CTX *ctx, const uint8_t *key, size_t keylen) {
    uint8_t pad[64], kh[32];
    const uint8_t *K = key;

    if (keylen > 64) {
        SHA256_CTX t;
        SHA256_Init(&t);
        SHA256_Update(&t, key, keylen);
        SHA256_Final(kh, &t);
        K = kh; keylen = 32;
    }
    memset(pad, 0x36, 64);
    for (size_t i = 0; i < keylen; i++) pad[i] ^= K[i];
    SHA256_Init(&ctx->ictx);
    SHA256_Update(&ctx->ictx, pad, 64);

    memset(pad, 0x5c, 64);
    for (size_t i = 0; i < keylen; i++) pad[i] ^= K[i];
    SHA256_Init(&ctx->octx);
    SHA256_Update(&ctx->octx, pad, 64);

    insecure_memzero(kh, sizeof(kh));
}

void HMAC_SHA256_Update(HMAC_SHA256_CTX *ctx, const uint8_t *d, size_t l) {
    SHA256_Update(&ctx->ictx, d, l);
}

void HMAC_SHA256_Final(uint8_t dgst[32], HMAC_SHA256_CTX *ctx) {
    uint8_t ih[32];
    SHA256_Final(ih, &ctx->ictx);
    SHA256_Update(&ctx->octx, ih, 32);
    SHA256_Final(dgst, &ctx->octx);
    insecure_memzero(ih, sizeof(ih));
}

void HMAC_SHA256_Buf(const uint8_t *k, size_t kl,
                    const uint8_t *d, size_t l,
                    uint8_t dgst[32]) {
    HMAC_SHA256_CTX ctx;
    HMAC_SHA256_Init(&ctx, k, kl);
    HMAC_SHA256_Update(&ctx, d, l);
    HMAC_SHA256_Final(dgst, &ctx);
}

/* --- PBKDF2-HMAC-SHA256 --- */
void PBKDF2_SHA256(const uint8_t *pw, size_t pwl,
                   const uint8_t *salt, size_t saltl,
                   uint64_t c, uint8_t *out, size_t outl) {
    HMAC_SHA256_CTX Ph, PSh, hctx;
    uint8_t U[32], T[32], ivec[4];
    assert(outl <= 32 * (size_t)UINT32_MAX);

    HMAC_SHA256_Init(&Ph, pw, pwl);
    memcpy(&PSh, &Ph, sizeof(Ph));
    HMAC_SHA256_Update(&PSh, salt, saltl);

    for (size_t i = 0; i * 32 < outl; i++) {
        uint32_t idx = (uint32_t)(i + 1);
        be32enc(ivec, idx);

        memcpy(&hctx, &PSh, sizeof(hctx));
        HMAC_SHA256_Update(&hctx, ivec, 4);
        HMAC_SHA256_Final(U, &hctx);
        memcpy(T, U, 32);

        for (uint64_t j = 2; j <= c; j++) {
            HMAC_SHA256_Init(&hctx, pw, pwl);
            HMAC_SHA256_Update(&hctx, U, 32);
            HMAC_SHA256_Final(U, &hctx);
            for (int k = 0; k < 32; k++) T[k] ^= U[k];
        }

        size_t chunk = outl - i * 32;
        if (chunk > 32) chunk = 32;
        memcpy(out + i * 32, T, chunk);
    }

    insecure_memzero(&Ph, sizeof(Ph));
    insecure_memzero(&PSh, sizeof(PSh));
    insecure_memzero(&hctx, sizeof(hctx));
    insecure_memzero(U, sizeof(U));
    insecure_memzero(T, sizeof(T));
}
