/*
 * optimized_sha256_full.c
 *
 * A single-file, optimized SHA-256 implementation (Intel Celeron N4020/SSE2),
 * including HMAC-SHA256 and PBKDF2-HMAC-SHA256, all in one compilation unit.
 */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "insecure_memzero.h"
#include "sysendian.h"

/* User-visible API header (you can extract these prototypes to sha256.h) */

typedef struct {
    uint64_t count;
    uint32_t state[8];
    uint8_t  buf[64];
} SHA256_CTX;

typedef struct {
    SHA256_CTX ictx;
    SHA256_CTX octx;
} HMAC_SHA256_CTX;

void SHA256_Init(SHA256_CTX *ctx);
void SHA256_Update(SHA256_CTX *ctx, const void *data, size_t len);
void SHA256_Final(uint8_t digest[32], SHA256_CTX *ctx);
void SHA256_Buf(const void *data, size_t len, uint8_t digest[32]);

void HMAC_SHA256_Init(HMAC_SHA256_CTX *ctx, const void *key, size_t keylen);
void HMAC_SHA256_Update(HMAC_SHA256_CTX *ctx, const void *data, size_t len);
void HMAC_SHA256_Final(uint8_t digest[32], HMAC_SHA256_CTX *ctx);
void HMAC_SHA256_Buf(const void *key, size_t keylen,
                     const void *data, size_t len,
                     uint8_t digest[32]);

void PBKDF2_SHA256(const uint8_t *passwd, size_t passwdlen,
                   const uint8_t *salt,   size_t saltlen,
                   uint64_t c, uint8_t *buf, size_t dkLen);


/* --- internal macros and constants --- */

/* Rotate and shift */
#define ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHR(x,n)  ((x) >> (n))

/* SHA-256 functions */
#define S0(x) (ROTR(x, 2)  ^ ROTR(x,13) ^ ROTR(x,22))
#define S1(x) (ROTR(x, 6)  ^ ROTR(x,11) ^ ROTR(x,25))
#define s0(x) (ROTR(x, 7)  ^ ROTR(x,18) ^ SHR(x, 3))
#define s1(x) (ROTR(x,17)  ^ ROTR(x,19) ^ SHR(x,10))
#define Ch(x,y,z) (((x) & ((y) ^ (z))) ^ (z))
#define Maj(x,y,z) (((x) & ((y)|(z))) | ((y) & (z))

/* SHA-256 round constants */
static const uint32_t K256[64] = {
    0x428a2f98ul,0x71374491ul,0xb5c0fbcful,0xe9b5dba5ul,
    0x3956c25bul,0x59f111f1ul,0x923f82a4ul,0xab1c5ed5ul,
    0xd807aa98ul,0x12835b01ul,0x243185beul,0x550c7dc3ul,
    0x72be5d74ul,0x80deb1feul,0x9bdc06a7ul,0xc19bf174ul,
    0xe49b69c1ul,0xefbe4786ul,0x0fc19dc6ul,0x240ca1ccul,
    0x2de92c6ful,0x4a7484aaul,0x5cb0a9dcul,0x76f988daul,
    0x983e5152ul,0xa831c66dul,0xb00327c8ul,0xbf597fc7ul,
    0xc6e00bf3ul,0xd5a79147ul,0x06ca6351ul,0x14292967ul,
    0x27b70a85ul,0x2e1b2138ul,0x4d2c6dfcul,0x53380d13ul,
    0x650a7354ul,0x766a0abbul,0x81c2c92eul,0x92722c85ul,
    0xa2bfe8a1ul,0xa81a664bul,0xc24b8b70ul,0xc76c51a3ul,
    0xd192e819ul,0xd6990624ul,0xf40e3585ul,0x106aa070ul,
    0x19a4c116ul,0x1e376c08ul,0x2748774cul,0x34b0bcb5ul,
    0x391c0cb3ul,0x4ed8aa4aul,0x5b9cca4ful,0x682e6ff3ul,
    0x748f82eeul,0x78a5636ful,0x84c87814ul,0x8cc70208ul,
    0x90befffaul,0xa4506cebul,0xbef9a3f7ul,0xc67178f2ul
};

/* Initial hash state */
static const uint32_t sha256_iv[8] = {
    0x6A09E667ul,0xBB67AE85ul,0x3C6EF372ul,0xA54FF53Aul,
    0x510E527Ful,0x9B05688Cul,0x1F83D9ABul,0x5BE0CD19ul
};

/* Padding byte 0x80 then zeros */
static const uint8_t sha256_pad[64] = { 0x80 };

/* --- core transform --- */
static inline void sha256_transform(uint32_t state[8], const uint8_t block[64])
__attribute__((always_inline));
static inline void sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[64] __attribute__((aligned(16)));
    uint32_t a,b,c,d,e,f,g,h,T1,T2;
    int i;

    /* Prepare W[0..63] */
    for (i = 0; i < 16; i++) {
        W[i] = __builtin_bswap32(((uint32_t*)block)[i]);
    }
    for (i = 16; i < 64; i++) {
        W[i] = s1(W[i-2]) + W[i-7] + s0(W[i-15]) + W[i-16];
    }

    /* Init working vars */
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    /* 64 rounds */
    #pragma GCC unroll 4
    for (i = 0; i < 64; i++) {
        T1 = h + S1(e) + Ch(e,f,g) + K256[i] + W[i];
        T2 = S0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    /* Update state */
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

/* --- SHA-256 public functions --- */

void SHA256_Init(SHA256_CTX *ctx) {
    ctx->count = 0;
    memcpy(ctx->state, sha256_iv, sizeof(sha256_iv));
}

static void SHA256_Pad(SHA256_CTX *ctx, uint8_t tmpbuf[8]) {
    size_t r = (ctx->count >> 3) & 0x3F;
    uint64_t bits = ctx->count;
    if (r < 56) {
        memcpy(&ctx->buf[r], sha256_pad, 56 - r);
    } else {
        memcpy(&ctx->buf[r], sha256_pad, 64 - r);
        sha256_transform(ctx->state, ctx->buf);
        memset(ctx->buf, 0, 56);
    }
    ((uint64_t*)tmpbuf)[0] = __builtin_bswap64(bits);
    memcpy(&ctx->buf[56], tmpbuf, 8);
    sha256_transform(ctx->state, ctx->buf);
}

void SHA256_Update(SHA256_CTX *ctx, const void *data, size_t len) {
    const uint8_t *ptr = data;
    uint8_t tmpbuf[8];
    size_t used = (ctx->count >> 3) & 0x3F;
    ctx->count += (uint64_t)len << 3;

    if (used && len) {
        size_t want = 64 - used;
        if (len < want) {
            memcpy(&ctx->buf[used], ptr, len);
            return;
        }
        memcpy(&ctx->buf[used], ptr, want);
        sha256_transform(ctx->state, ctx->buf);
        ptr  += want;
        len  -= want;
    }
    while (len >= 64) {
        sha256_transform(ctx->state, ptr);
        ptr  += 64;
        len  -= 64;
    }
    if (len) {
        memcpy(ctx->buf, ptr, len);
    }
}

void SHA256_Final(uint8_t digest[32], SHA256_CTX *ctx) {
    uint8_t tmpbuf[64] = {0};
    SHA256_Pad(ctx, tmpbuf);
    for (int i = 0; i < 8; i++) {
        ((uint32_t*)digest)[i] = __builtin_bswap32(ctx->state[i]);
    }
    insecure_memzero(ctx, sizeof(*ctx));
}

void SHA256_Buf(const void *data, size_t len, uint8_t digest[32]) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(digest, &ctx);
}

/* --- HMAC-SHA256 --- */

void HMAC_SHA256_Init(HMAC_SHA256_CTX *ctx, const void *key, size_t keylen) {
    uint8_t pad[64], khash[32];
    const uint8_t *K = key;

    if (keylen > 64) {
        SHA256_CTX tctx;
        SHA256_Init(&tctx);
        SHA256_Update(&tctx, key, keylen);
        SHA256_Final(khash, &tctx);
        K = khash;
        keylen = 32;
    }

    /* inner */
    SHA256_Init(&ctx->ictx);
    memset(pad, 0x36, 64);
    for (size_t i = 0; i < keylen; i++) pad[i] ^= K[i];
    SHA256_Update(&ctx->ictx, pad, 64);

    /* outer */
    SHA256_Init(&ctx->octx);
    memset(pad, 0x5c, 64);
    for (size_t i = 0; i < keylen; i++) pad[i] ^= K[i];
    SHA256_Update(&ctx->octx, pad, 64);

    insecure_memzero(khash, sizeof(khash));
}

void HMAC_SHA256_Update(HMAC_SHA256_CTX *ctx, const void *data, size_t len) {
    SHA256_Update(&ctx->ictx, data, len);
}

void HMAC_SHA256_Final(uint8_t digest[32], HMAC_SHA256_CTX *ctx) {
    uint8_t ihash[32];
    SHA256_Final(ihash, &ctx->ictx);
    SHA256_Update(&ctx->octx, ihash, 32);
    SHA256_Final(digest, &ctx->octx);
    insecure_memzero(ihash, sizeof(ihash));
}

void HMAC_SHA256_Buf(const void *key, size_t keylen,
                     const void *data, size_t len,
                     uint8_t digest[32]) {
    HMAC_SHA256_CTX ctx;
    HMAC_SHA256_Init(&ctx, key, keylen);
    HMAC_SHA256_Update(&ctx, data, len);
    HMAC_SHA256_Final(digest, &ctx);
}

/* --- PBKDF2-HMAC-SHA256 --- */

void PBKDF2_SHA256(const uint8_t *passwd, size_t passwdlen,
                   const uint8_t *salt,   size_t saltlen,
                   uint64_t c, uint8_t *buf, size_t dkLen)
{
    HMAC_SHA256_CTX Phctx, PShctx, hctx;
    uint8_t U[32], T[32], ivec[4];
    size_t i, j, k, clen;

    assert(dkLen <= 32 * (size_t)UINT32_MAX);

    /* Precompute inner and inner+salt contexts */
    HMAC_SHA256_Init(&Phctx, passwd, passwdlen);
    memcpy(&PShctx, &Phctx, sizeof(Phctx));
    HMAC_SHA256_Update(&PShctx, salt, saltlen);

    for (i = 0; i * 32 < dkLen; i++) {
        uint32_t block = (uint32_t)(i + 1);
        be32enc(ivec, block);

        /* U1 = PRF(P, S || INT(i+1)) */
        memcpy(&hctx, &PShctx, sizeof(hctx));
        HMAC_SHA256_Update(&hctx, ivec, 4);
        HMAC_SHA256_Final(U, &hctx);
        memcpy(T, U, 32);

        /* U2..Uc */
        for (j = 2; j <= c; j++) {
            HMAC_SHA256_Init(&hctx, passwd, passwdlen);
            HMAC_SHA256_Update(&hctx, U, 32);
            HMAC_SHA256_Final(U, &hctx);
            for (k = 0; k < 32; k++) T[k] ^= U[k];
        }

        /* Write block to output */
        clen = dkLen - i * 32;
        if (clen > 32) clen = 32;
        memcpy(buf + i * 32, T, clen);
    }

    insecure_memzero(&Phctx, sizeof(Phctx));
    insecure_memzero(&PShctx, sizeof(PShctx));
    insecure_memzero(&hctx, sizeof(hctx));
    insecure_memzero(U, sizeof(U));
    insecure_memzero(T, sizeof(T));
}
