#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "insecure_memzero.h"
#include "sysendian.h"

#include "sha256.h"

#ifdef __ICC
#define restrict
#elif __STDC_VERSION__ >= 199901L
#elif defined(__GNUC__)
#define restrict __restrict__
#else
#define restrict
#endif

/* Encode a length len/4 vector of (uint32_t) into a length len vector of (uint8_t) in big-endian form. */
static void
be32enc_vect(uint8_t *dst, const uint32_t *src, size_t len) {
    for (size_t i = 0; i < len; i += 4) {
        be32enc(dst + i, src[i/4]);
    }
}

/* Decode a big-endian length len vector of (uint8_t) into a length len/4 vector of (uint32_t). */
static void
be32dec_vect(uint32_t *dst, const uint8_t *src, size_t len) {
    for (size_t i = 0; i < len; i += 4) {
        dst[i/4] = be32dec(src + i);
    }
}

/* SHA256 round constants. */
static const uint32_t Krnd[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* Elementary functions */
#define Ch(x, y, z)     ((z) ^ ((x) & ((y) ^ (z))))
#define Maj(x, y, z)    (((x) & (y)) | ((z) & ((x) | (y))))
#define SHR(x, n)       ((x) >> (n))
#define ROTR(x, n)      (((x) >> (n)) | ((x) << (32 - (n))))
#define S0(x)           (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S1(x)           (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define s0(x)           (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define s1(x)           (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

/* SHA256 block compression function. */
static void
SHA256_Transform(uint32_t state[static restrict 8],
                 const uint8_t block[static restrict 64],
                 uint32_t W[static restrict 64]) {
    uint32_t a, b, c, d, e, f, g, h;
    int i;

    /* Prepare message schedule */
    be32dec_vect(W, block, 64);

    for (i = 16; i < 64; ++i) {
        W[i] = s1(W[i-2]) + W[i-7] + s0(W[i-15]) + W[i-16];
    }

    /* Initialize working variables */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    /* Compress */
    for (i = 0; i < 64; ++i) {
        uint32_t t1 = h + S1(e) + Ch(e, f, g) + Krnd[i] + W[i];
        uint32_t t2 = S0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
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

static const uint8_t PAD[64] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static void
SHA256_Pad(SHA256_CTX *ctx) {
    uint8_t len[8];
    size_t r = (ctx->count >> 3) & 0x3f;

    be64enc(len, ctx->count);
    SHA256_Update(ctx, PAD, ((r < 56) ? 56 - r : 120 - r));
    SHA256_Update(ctx, len, 8);
}

static const uint32_t initial_state[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

void
SHA256_Init(SHA256_CTX *ctx) {
    ctx->count = 0;
    memcpy(ctx->state, initial_state, 32);
}

void
SHA256_Update(SHA256_CTX *ctx, const void *in, size_t len) {
    uint32_t W[64];
    const uint8_t *src = in;
    size_t r = (ctx->count >> 3) & 0x3f;

    ctx->count += len << 3;

    if (len < 64 - r) {
        memcpy(ctx->buf + r, src, len);
        return;
    }

    memcpy(ctx->buf + r, src, 64 - r);
    SHA256_Transform(ctx->state, ctx->buf, W);
    src += 64 - r;
    len -= 64 - r;

    while (len >= 64) {
        SHA256_Transform(ctx->state, src, W);
        src += 64;
        len -= 64;
    }

    memcpy(ctx->buf, src, len);
    insecure_memzero(W, 256);
}

void
SHA256_Final(uint8_t digest[32], SHA256_CTX *ctx) {
    SHA256_Pad(ctx);
    be32enc_vect(digest, ctx->state, 32);
    insecure_memzero(ctx, sizeof(SHA256_CTX));
}

void
SHA256_Buf(const void *in, size_t len, uint8_t digest[32]) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, in, len);
    SHA256_Final(digest, &ctx);
    insecure_memzero(&ctx, sizeof(ctx));
}

/* HMAC-SHA256 functions */
typedef struct {
    SHA256_CTX ictx;
    SHA256_CTX octx;
} HMAC_SHA256_CTX;

void
HMAC_SHA256_Init(HMAC_SHA256_CTX *ctx, const void *K, size_t Klen) {
    uint8_t pad[64];
    uint8_t khash[32];
    SHA256_CTX *ictx = &ctx->ictx;
    SHA256_CTX *octx = &ctx->octx;

    if (Klen > 64) {
        SHA256_Buf(K, Klen, khash);
        K = khash;
        Klen = 32;
    }

    memset(pad, 0x36, 64);
    for (size_t i = 0; i < Klen; ++i)
        pad[i] ^= ((const uint8_t *)K)[i];
    SHA256_Init(ictx);
    SHA256_Update(ictx, pad, 64);

    memset(pad, 0x5c, 64);
    for (size_t i = 0; i < Klen; ++i)
        pad[i] ^= ((const uint8_t *)K)[i];
    SHA256_Init(octx);
    SHA256_Update(octx, pad, 64);

    insecure_memzero(khash, 32);
    insecure_memzero(pad, 64);
}

void
HMAC_SHA256_Update(HMAC_SHA256_CTX *ctx, const void *in, size_t len) {
    SHA256_Update(&ctx->ictx, in, len);
}

void
HMAC_SHA256_Final(uint8_t digest[32], HMAC_SHA256_CTX *ctx) {
    uint8_t ihash[32];
    SHA256_Final(ihash, &ctx->ictx);
    SHA256_Update(&ctx->octx, ihash, 32);
    SHA256_Final(digest, &ctx->octx);
    insecure_memzero(ihash, 32);
}

void
HMAC_SHA256_Buf(const void *K, size_t Klen, const void *in, size_t len, uint8_t digest[32]) {
    HMAC_SHA256_CTX ctx;
    HMAC_SHA256_Init(&ctx, K, Klen);
    HMAC_SHA256_Update(&ctx, in, len);
    HMAC_SHA256_Final(digest, &ctx);
    insecure_memzero(&ctx, sizeof(ctx));
}

/* PBKDF2-SHA256 */
void
PBKDF2_SHA256(const uint8_t *passwd, size_t passwdlen,
              const uint8_t *salt, size_t saltlen, uint64_t c,
              uint8_t *buf, size_t dkLen) {
    HMAC_SHA256_CTX Phctx, hctx;
    uint8_t ivec[4];
    uint8_t U[32];
    uint8_t T[32];
    size_t i, k;
    size_t clen;

    assert(dkLen <= 32 * (size_t)UINT32_MAX);

    HMAC_SHA256_Init(&Phctx, passwd, passwdlen);

    for (i = 1; dkLen > 0; i++) {
        be32enc(ivec, (uint32_t)i);
        hctx = Phctx;
        HMAC_SHA256_Update(&hctx, salt, saltlen);
        HMAC_SHA256_Update(&hctx, ivec, 4);
        HMAC_SHA256_Final(U, &hctx);

        memcpy(T, U, 32);

        for (uint64_t j = 2; j <= c; j++) {
            HMAC_SHA256_Buf(passwd, passwdlen, U, 32, U);
            for (k = 0; k < 32; k++)
                T[k] ^= U[k];
        }

        clen = dkLen < 32 ? dkLen : 32;
        memcpy(buf, T, clen);
        buf += clen;
        dkLen -= clen;
    }

    insecure_memzero(&Phctx, sizeof(Phctx));
    insecure_memzero(U, 32);
    insecure_memzero(T, 32);
}
