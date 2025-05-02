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

static void SHA256_Transform(uint32_t state[static restrict 8],
                             const uint8_t block[static restrict 64],
                             uint32_t W[static restrict 64],
                             uint32_t S[static restrict 8]) {
    /* ... (identical transform implementation) ... */
}

/* Padding and finalization */
static const uint8_t PAD[64] = {0x80};
static const uint32_t INITIAL_STATE[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

void libcperciva_SHA256_Init(libcperciva_SHA256_CTX *ctx) {
    memcpy(ctx->state, INITIAL_STATE, sizeof(ctx->state));
    ctx->count = 0;
}

void libcperciva_SHA256_Update(libcperciva_SHA256_CTX *ctx, const void *in, size_t len) {
    /* ... (identical update implementation) ... */
}

void libcperciva_SHA256_Final(uint8_t digest[32], libcperciva_SHA256_CTX *ctx) {
    /* ... (identical final implementation) ... */
}

void libcperciva_SHA256_Buf(const void *in, size_t len, uint8_t digest[32]) {
    libcperciva_SHA256_CTX ctx;
    libcperciva_SHA256_Init(&ctx);
    libcperciva_SHA256_Update(&ctx, in, len);
    libcperciva_SHA256_Final(digest, &ctx);
    insecure_memzero(&ctx, sizeof(ctx));
}

/* HMAC-SHA256 implementation */
void libcperciva_HMAC_SHA256_Init(libcperciva_HMAC_SHA256_CTX *ctx, const void *K, size_t Klen) {
    /* ... (identical HMAC init implementation) ... */
}

void libcperciva_HMAC_SHA256_Update(libcperciva_HMAC_SHA256_CTX *ctx, const void *in, size_t len) {
    libcperciva_SHA256_Update(&ctx->ictx, in, len);
}

void libcperciva_HMAC_SHA256_Final(uint8_t digest[32], libcperciva_HMAC_SHA256_CTX *ctx) {
    /* ... (identical HMAC final implementation) ... */
}

void libcperciva_HMAC_SHA256_Buf(const void *K, size_t Klen, const void *in, size_t len, uint8_t digest[32]) {
    libcperciva_HMAC_SHA256_CTX ctx;
    libcperciva_HMAC_SHA256_Init(&ctx, K, Klen);
    libcperciva_HMAC_SHA256_Update(&ctx, in, len);
    libcperciva_HMAC_SHA256_Final(digest, &ctx);
    insecure_memzero(&ctx, sizeof(ctx));
}

/* PBKDF2-HMAC-SHA256 implementation */
void PBKDF2_SHA256(const uint8_t *passwd, size_t passwdlen,
                   const uint8_t *salt, size_t saltlen, uint64_t c,
                   uint8_t *buf, size_t dkLen) {
    libcperciva_HMAC_SHA256_CTX ctx, hctx;
    uint8_t ivec[4], U[32], T[32];
    
    assert(dkLen <= 32 * (size_t)UINT32_MAX);
    
    for (uint32_t i = 1; dkLen > 0; ++i) {
        be32enc(ivec, i);
        
        /* Compute U_1 */
        libcperciva_HMAC_SHA256_Init(&ctx, passwd, passwdlen);
        libcperciva_HMAC_SHA256_Update(&ctx, salt, saltlen);
        libcperciva_HMAC_SHA256_Update(&ctx, ivec, 4);
        libcperciva_HMAC_SHA256_Final(U, &ctx);
        memcpy(T, U, 32);
        
        /* Compute subsequent U values */
        for (uint64_t j = 1; j < c; ++j) {
            libcperciva_HMAC_SHA256_Init(&hctx, passwd, passwdlen);
            libcperciva_HMAC_SHA256_Update(&hctx, U, 32);
            libcperciva_HMAC_SHA256_Final(U, &hctx);
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
