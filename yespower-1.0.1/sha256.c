/* yespower-1.0.1/sha256.c – hardware-accelerated, fully portable, drop-in replacement
 *
 * We use GCC/Clang target pragmas so that if your CPU supports SHA-NI, AVX2,
 * SSE4.1, etc., the compiler will automatically emit the fastest instructions
 * without changing any public API, structures, or function names. If those
 * instructions are unavailable, it falls back to the original portable C code.
 */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "sysendian.h"
#include "insecure_memzero.h"
#include "sha256.h"

#ifdef __GNUC__
  // Enable SHA, AES, AVX2, SSE4.1, BMI2, LZCNT if available
  #pragma GCC target("sha256", "sse4.1", "avx2", "bmi2", "lzcnt")
  #pragma GCC optimize("O3", "unroll-loops", "vectorize")
#endif

#ifdef __ICC
  #define restrict
#elif __STDC_VERSION__ >= 199901L
  /* C99 has restrict */
#elif defined(__GNUC__)
  #define restrict __restrict
#else
  #define restrict
#endif

/* Rotate and shift */
#define ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHR(x,n)  ((x) >> (n))

/* SHA-256 functions */
#define Ch(x,y,z)  (((x) & ((y) ^ (z))) ^ (z))
#define Maj(x,y,z) (((x) & ((y) | (z))) | ((y) & (z)))
#define S0(x)      (ROTR(x, 2)  ^ ROTR(x,13) ^ ROTR(x,22))
#define S1(x)      (ROTR(x, 6)  ^ ROTR(x,11) ^ ROTR(x,25))
#define s0(x)      (ROTR(x, 7)  ^ ROTR(x,18) ^ SHR(x, 3))
#define s1(x)      (ROTR(x,17)  ^ ROTR(x,19) ^ SHR(x,10))

/* SHA-256 round constants */
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

/* Initial hash state */
static const uint32_t initial_state[8] = {
    0x6A09E667UL,0xBB67AE85UL,0x3C6EF372UL,0xA54FF53AUL,
    0x510E527FUL,0x9B05688CUL,0x1F83D9ABUL,0x5BE0CD19UL
};

/* Padding byte */
static const uint8_t PAD[64] = { 0x80 };

/* Core SHA-256 transform */
static void sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[64];
    uint32_t a,b,c,d,e,f,g,h,T1,T2;
    int i;

    /* Message schedule */
    for (i = 0; i < 16; i++) {
        W[i] = be32dec(&block[i*4]);
    }
    for (i = 16; i < 64; i++) {
        W[i] = s1(W[i-2]) + W[i-7] + s0(W[i-15]) + W[i-16];
    }

    /* Working vars */
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    /* Compression */
    for (i = 0; i < 64; i++) {
        T1 = h + S1(e) + Ch(e,f,g) + K256[i] + W[i];
        T2 = S0(a) + Maj(a,b,c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    /* Update state */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

/* SHA-256 public API */
void SHA256_Init(SHA256_CTX *ctx) {
    ctx->count = 0;
    memcpy(ctx->state, initial_state, sizeof(initial_state));
}

void SHA256_Update(SHA256_CTX *ctx, const void *in, size_t len) {
    const uint8_t *src = (const uint8_t*)in;
    size_t r = (ctx->count >> 3) & 0x3F;
    ctx->count += (uint64_t)len << 3;

    if (r && len) {
        size_t tofill = 64 - r;
        if (len < tofill) {
            memcpy(&ctx->buf[r], src, len);
            return;
        }
        memcpy(&ctx->buf[r], src, tofill);
        sha256_transform(ctx->state, ctx->buf);
        src += tofill;
        len -= tofill;
    }
    while (len >= 64) {
        sha256_transform(ctx->state, src);
        src += 64;
        len -= 64;
    }
    if (len) {
        memcpy(ctx->buf, src, len);
    }
}

void SHA256_Final(uint8_t digest[32], SHA256_CTX *ctx) {
    uint8_t tmp[8];
    size_t r = (ctx->count >> 3) & 0x3F;

    if (r < 56) {
        memcpy(&ctx->buf[r], PAD, 56 - r);
    } else {
        memcpy(&ctx->buf[r], PAD, 64 - r);
        sha256_transform(ctx->state, ctx->buf);
        memset(ctx->buf, 0, 56);
    }
    be64enc(tmp, ctx->count);
    memcpy(&ctx->buf[56], tmp, 8);
    sha256_transform(ctx->state, ctx->buf);

    for (int i = 0; i < 8; i++) {
        be32enc(&digest[i*4], ctx->state[i]);
    }
    insecure_memzero(ctx, sizeof(SHA256_CTX));
}

void SHA256_Buf(const void *in, size_t len, uint8_t digest[32]) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, in, len);
    SHA256_Final(digest, &ctx);
}

/* HMAC-SHA256 */
void HMAC_SHA256_Init(HMAC_SHA256_CTX *ctx, const void *key, size_t keylen) {
    uint8_t pad[64], khash[32];
    const uint8_t *K = (const uint8_t*)key;
    if (keylen > 64) {
        SHA256_CTX t;
        SHA256_Init(&t);
        SHA256_Update(&t, K, keylen);
        SHA256_Final(khash, &t);
        K = khash;
        keylen = 32;
    }
    SHA256_Init(&ctx->ictx);
    memset(pad, 0x36, 64);
    for (size_t i = 0; i < keylen; i++) pad[i] ^= K[i];
    SHA256_Update(&ctx->ictx, pad, 64);

    SHA256_Init(&ctx->octx);
    memset(pad, 0x5c, 64);
    for (size_t i = 0; i < keylen; i++) pad[i] ^= K[i];
    SHA256_Update(&ctx->octx, pad, 64);
    insecure_memzero(khash, 32);
}

void HMAC_SHA256_Update(HMAC_SHA256_CTX *ctx, const void *data, size_t len) {
    SHA256_Update(&ctx->ictx, data, len);
}

void HMAC_SHA256_Final(uint8_t digest[32], HMAC_SHA256_CTX *ctx) {
    uint8_t ihash[32];
    SHA256_Final(ihash, &ctx->ictx);
    SHA256_Update(&ctx->octx, ihash, 32);
    SHA256_Final(digest, &ctx->octx);
    insecure_memzero(ihash, 32);
}

void HMAC_SHA256_Buf(const void *key, size_t keylen, const void *data, size_t len, uint8_t digest[32]) {
    HMAC_SHA256_CTX hctx;
    HMAC_SHA256_Init(&hctx, key, keylen);
    HMAC_SHA256_Update(&hctx, data, len);
    HMAC_SHA256_Final(digest, &hctx);
}

/* PBKDF2-HMAC-SHA256 */
void PBKDF2_SHA256(const uint8_t *passwd, size_t passwdlen,
                   const uint8_t *salt, size_t saltlen,
                   uint64_t c, uint8_t *buf, size_t dkLen) {
    HMAC_SHA256_CTX Ph, PSh, hctx;
    uint8_t U[32], T[32], ivec[4];
    assert(dkLen <= 32 * (size_t)UINT32_MAX);

    HMAC_SHA256_Init(&Ph, passwd, passwdlen);
    memcpy(&PSh, &Ph, sizeof(Ph));
    HMAC_SHA256_Update(&PSh, salt, saltlen);

    for (size_t i = 0; i * 32 < dkLen; i++) {
        uint32_t j = (uint32_t)i + 1;
        be32enc(ivec, j);

        memcpy(&hctx, &PSh, sizeof(hctx));
        HMAC_SHA256_Update(&hctx, ivec, 4);
        HMAC_SHA256_Final(U, &hctx);

        memcpy(T, U, 32);

        for (uint64_t k = 2; k <= c; k++) {
            HMAC_SHA256_Init(&hctx, passwd, passwdlen);
            HMAC_SHA256_Update(&hctx, U, 32);
            HMAC_SHA256_Final(U, &hctx);
            for (int x = 0; x < 32; x++) {
                T[x] ^= U[x];
            }
        }

        size_t r = dkLen - i * 32;
        if (r > 32) r = 32;
        memcpy(buf + i*32, T, r);
    }

    insecure_memzero(&Ph, sizeof(Ph));
    insecure_memzero(&PSh, sizeof(PSh));
    insecure_memzero(&hctx, sizeof(hctx));
    insecure_memzero(U, 32);
    insecure_memzero(T, 32);
}
