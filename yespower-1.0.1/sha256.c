#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "insecure_memzero.h"
#include "sysendian.h"
#include "sha256.h"

#ifdef __ICC
#define restrict
#elif __STDC_VERSION__ >= 199901L
/* Have restrict */
#elif defined(__GNUC__)
#define restrict __restrict
#else
#define restrict
#endif

/* Encode two 32-bit words (8 bytes) in big-endian order */
static inline void be32enc_vect(uint8_t *restrict dst, const uint32_t *restrict src, size_t len) {
    while (len--) {
        be32enc(dst, src[0]);
        be32enc(dst + 4, src[1]);
        src += 2;
        dst += 8;
    }
}

/* Decode two 32-bit words (8 bytes) from big-endian order */
static inline void be32dec_vect(uint32_t *restrict dst, const uint8_t *restrict src, size_t len) {
    while (len--) {
        dst[0] = be32dec(src);
        dst[1] = be32dec(src + 4);
        dst += 2;
        src += 8;
    }
}

/* SHA256 round constants */
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

/* Elementary functions used by SHA256 */
#define Ch(x, y, z)   (((x) & ((y) ^ (z))) ^ (z))
#define Maj(x, y, z)  (((x) & ((y) | (z))) | ((y) & (z)))
#define SHR(x, n)     ((x) >> (n))
#define ROTR(x, n)    (((x) >> (n)) | ((x) << (32 - (n))))
#define S0(x)         (ROTR((x), 2) ^ ROTR((x), 13) ^ ROTR((x), 22))
#define S1(x)         (ROTR((x), 6) ^ ROTR((x), 11) ^ ROTR((x), 25))
#define s0(x)         (ROTR((x), 7) ^ ROTR((x), 18) ^ SHR((x), 3))
#define s1(x)         (ROTR((x), 17) ^ ROTR((x), 19) ^ SHR((x), 10))

#define RND(a, b, c, d, e, f, g, h, k)  do { \
    (h) += S1(e) + Ch(e, f, g) + (k);       \
    (d) += (h);                           \
    (h) += S0(a) + Maj(a, b, c);            \
} while(0)

#define RNDr(S, W, i, ii)  RND(S[(64 - (i)) % 8], S[(65 - (i)) % 8], \
                               S[(66 - (i)) % 8], S[(67 - (i)) % 8], \
                               S[(68 - (i)) % 8], S[(69 - (i)) % 8], \
                               S[(70 - (i)) % 8], S[(71 - (i)) % 8], \
                               (W)[(i) + (ii)] + Krnd[(i) + (ii)])

#define MSCH(W, ii, i)  ((W)[(i) + (ii) + 16] = s1((W)[(i) + (ii) + 14]) + \
                         (W)[(i) + (ii) + 9] + s0((W)[(i) + (ii) + 1]) + (W)[(i) + (ii)])

/*
 * SHA256_Transform:
 * Compress a 512-bit block into the current state.
 */
static void SHA256_Transform(uint32_t state[static restrict 8],
    const uint8_t block[static restrict 64],
    uint32_t W[static restrict 64],
    uint32_t S[static restrict 8])
{
    int i;
    be32dec_vect(W, block, 8);
    memcpy(S, state, 32);
    for (i = 0; i < 64; i += 16) {
        RNDr(S, W,  0, i); RNDr(S, W,  1, i);
        RNDr(S, W,  2, i); RNDr(S, W,  3, i);
        RNDr(S, W,  4, i); RNDr(S, W,  5, i);
        RNDr(S, W,  6, i); RNDr(S, W,  7, i);
        RNDr(S, W,  8, i); RNDr(S, W,  9, i);
        RNDr(S, W, 10, i); RNDr(S, W, 11, i);
        RNDr(S, W, 12, i); RNDr(S, W, 13, i);
        RNDr(S, W, 14, i); RNDr(S, W, 15, i);
        if (i == 48)
            break;
        MSCH(W, 0, i);  MSCH(W, 1, i);  MSCH(W, 2, i);  MSCH(W, 3, i);
        MSCH(W, 4, i);  MSCH(W, 5, i);  MSCH(W, 6, i);  MSCH(W, 7, i);
        MSCH(W, 8, i);  MSCH(W, 9, i);  MSCH(W, 10, i); MSCH(W, 11, i);
        MSCH(W, 12, i); MSCH(W, 13, i); MSCH(W, 14, i); MSCH(W, 15, i);
    }
    state[0] += S[0]; state[1] += S[1]; state[2] += S[2]; state[3] += S[3];
    state[4] += S[4]; state[5] += S[5]; state[6] += S[6]; state[7] += S[7];
}

/* Padding block, identical to original */
static const uint8_t PAD[64] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static void SHA256_Pad(SHA256_CTX *restrict ctx, uint32_t tmp32[static restrict 72]) {
    size_t r = ((size_t)ctx->count >> 3) & 0x3f;
    if (r < 56) {
        memcpy(&ctx->buf[r], PAD, 56 - r);
    } else {
        memcpy(&ctx->buf[r], PAD, 64 - r);
        SHA256_Transform(ctx->state, ctx->buf, tmp32, &tmp32[64]);
        memset(ctx->buf, 0, 56);
    }
    be64enc(&ctx->buf[56], ctx->count);
    SHA256_Transform(ctx->state, ctx->buf, tmp32, &tmp32[64]);
}

static const uint32_t initial_state[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

void SHA256_Init(SHA256_CTX *restrict ctx) {
    ctx->count = 0;
    memcpy(ctx->state, initial_state, sizeof(initial_state));
}

static void _SHA256_Update(SHA256_CTX *restrict ctx, const void *restrict in, size_t len,
    uint32_t tmp32[static restrict 72])
{
    const uint8_t *restrict src = in;
    if (len == 0)
        return;
    uint32_t r = ((uint32_t)ctx->count >> 3) & 0x3f;
    ctx->count += ((uint64_t)len << 3);
    if (len < 64 - r) {
        memcpy(&ctx->buf[r], src, len);
        return;
    }
    memcpy(&ctx->buf[r], src, 64 - r);
    SHA256_Transform(ctx->state, ctx->buf, tmp32, &tmp32[64]);
    src += 64 - r; len -= 64 - r;
    while (len >= 64) {
        SHA256_Transform(ctx->state, src, tmp32, &tmp32[64]);
        src += 64; len -= 64;
    }
    memcpy(ctx->buf, src, len);
}

void SHA256_Update(SHA256_CTX *restrict ctx, const void *restrict in, size_t len) {
    uint32_t tmp32[72];
    _SHA256_Update(ctx, in, len, tmp32);
    insecure_memzero(tmp32, sizeof(tmp32));
}

static void _SHA256_Final(uint8_t digest[32], SHA256_CTX *restrict ctx,
    uint32_t tmp32[static restrict 72])
{
    SHA256_Pad(ctx, tmp32);
    be32enc_vect(digest, ctx->state, 4);
}

void SHA256_Final(uint8_t digest[32], SHA256_CTX *restrict ctx) {
    uint32_t tmp32[72];
    _SHA256_Final(digest, ctx, tmp32);
    insecure_memzero(ctx, sizeof(SHA256_CTX));
    insecure_memzero(tmp32, sizeof(tmp32));
}

void SHA256_Buf(const void *restrict in, size_t len, uint8_t digest[32]) {
    SHA256_CTX ctx;
    uint32_t tmp32[72];
    SHA256_Init(&ctx);
    _SHA256_Update(&ctx, in, len, tmp32);
    _SHA256_Final(digest, &ctx, tmp32);
    insecure_memzero(&ctx, sizeof(ctx));
    insecure_memzero(tmp32, sizeof(tmp32));
}

static void _HMAC_SHA256_Init(HMAC_SHA256_CTX *restrict ctx, const void *restrict _K, size_t Klen,
    uint32_t tmp32[static restrict 72], uint8_t pad[static restrict 64],
    uint8_t khash[static restrict 32])
{
    const uint8_t *restrict K = _K;
    size_t i;
    if (Klen > 64) {
        SHA256_Init(&ctx->ictx);
        _SHA256_Update(&ctx->ictx, K, Klen, tmp32);
        _SHA256_Final(khash, &ctx->ictx, tmp32);
        K = khash; Klen = 32;
    }
    SHA256_Init(&ctx->ictx);
    memset(pad, 0x36, 64);
    for (i = 0; i < Klen; i++)
        pad[i] ^= K[i];
    _SHA256_Update(&ctx->ictx, pad, 64, tmp32);
    SHA256_Init(&ctx->octx);
    memset(pad, 0x5c, 64);
    for (i = 0; i < Klen; i++)
        pad[i] ^= K[i];
    _SHA256_Update(&ctx->octx, pad, 64, tmp32);
}

void HMAC_SHA256_Init(HMAC_SHA256_CTX *restrict ctx, const void *restrict _K, size_t Klen) {
    uint32_t tmp32[72];
    uint8_t pad[64], khash[32];
    _HMAC_SHA256_Init(ctx, _K, Klen, tmp32, pad, khash);
    insecure_memzero(tmp32, sizeof(tmp32));
    insecure_memzero(pad, sizeof(pad));
    insecure_memzero(khash, sizeof(khash));
}

static void _HMAC_SHA256_Update(HMAC_SHA256_CTX *restrict ctx, const void *restrict in, size_t len,
    uint32_t tmp32[static restrict 72])
{
    _SHA256_Update(&ctx->ictx, in, len, tmp32);
}

void HMAC_SHA256_Update(HMAC_SHA256_CTX *restrict ctx, const void *restrict in, size_t len) {
    uint32_t tmp32[72];
    _HMAC_SHA256_Update(ctx, in, len, tmp32);
    insecure_memzero(tmp32, sizeof(tmp32));
}

static void _HMAC_SHA256_Final(uint8_t digest[32], HMAC_SHA256_CTX *restrict ctx,
    uint32_t tmp32[static restrict 72], uint8_t ihash[static restrict 32])
{
    _SHA256_Final(ihash, &ctx->ictx, tmp32);
    _SHA256_Update(&ctx->octx, ihash, 32, tmp32);
    _SHA256_Final(digest, &ctx->octx, tmp32);
}

void HMAC_SHA256_Final(uint8_t digest[32], HMAC_SHA256_CTX *restrict ctx) {
    uint32_t tmp32[72];
    uint8_t ihash[32];
    _HMAC_SHA256_Final(digest, ctx, tmp32, ihash);
    insecure_memzero(tmp32, sizeof(tmp32));
    insecure_memzero(ihash, sizeof(ihash));
}

void HMAC_SHA256_Buf(const void *restrict K, size_t Klen,
    const void *restrict in, size_t len, uint8_t digest[32])
{
    HMAC_SHA256_CTX ctx;
    uint32_t tmp32[72];
    uint8_t tmp8[96];
    _HMAC_SHA256_Init(&ctx, K, Klen, tmp32, tmp8, &tmp8[64]);
    _HMAC_SHA256_Update(&ctx, in, len, tmp32);
    _HMAC_SHA256_Final(digest, &ctx, tmp32, tmp8);
    insecure_memzero(&ctx, sizeof(ctx));
    insecure_memzero(tmp32, sizeof(tmp32));
    insecure_memzero(tmp8, sizeof(tmp8));
}

static int SHA256_Pad_Almost(SHA256_CTX *restrict ctx, uint8_t len[static restrict 8],
    uint32_t tmp32[static restrict 72])
{
    uint32_t r = ((uint32_t)ctx->count >> 3) & 0x3f;
    if (r >= 56)
        return -1;
    be64enc(len, ctx->count);
    _SHA256_Update(ctx, PAD, 56 - r, tmp32);
    ctx->buf[63] = len[7];
    _SHA256_Update(ctx, len, 7, tmp32);
    return 0;
}

void PBKDF2_SHA256(const uint8_t *restrict passwd, size_t passwdlen,
    const uint8_t *restrict salt, size_t saltlen, uint64_t c,
    uint8_t *restrict buf, size_t dkLen)
{
    HMAC_SHA256_CTX Phctx, PShctx, hctx;
    uint32_t tmp32[72];
    union {
        uint8_t tmp8[96];
        uint32_t state[8];
    } u;
    size_t i, clen;
    uint8_t ivec[4];
    uint8_t U[32];
    uint8_t T[32];
    uint64_t j;
    assert(dkLen <= 32 * (size_t)(UINT32_MAX));

    if (c == 1 && (dkLen & 31) == 0 && (saltlen & 63) <= 51) {
        uint32_t oldcount;
        uint8_t *ivecp;
        _HMAC_SHA256_Init(&hctx, passwd, passwdlen, tmp32, u.tmp8, &u.tmp8[64]);
        _HMAC_SHA256_Update(&hctx, salt, saltlen, tmp32);
        oldcount = hctx.ictx.count & (0x3f << 3);
        _HMAC_SHA256_Update(&hctx, "\0\0\0", 4, tmp32);
        if ((hctx.ictx.count & (0x3f << 3)) < oldcount ||
            SHA256_Pad_Almost(&hctx.ictx, u.tmp8, tmp32))
            goto generic;
        ivecp = hctx.ictx.buf + (oldcount >> 3);
        hctx.octx.count += 32 << 3;
        SHA256_Pad_Almost(&hctx.octx, u.tmp8, tmp32);
        for (i = 0; i * 32 < dkLen; i++) {
            be32enc(ivecp, (uint32_t)(i + 1));
            memcpy(u.state, hctx.ictx.state, sizeof(u.state));
            SHA256_Transform(u.state, hctx.ictx.buf, tmp32, &tmp32[64]);
            be32enc_vect(hctx.octx.buf, u.state, 4);
            memcpy(u.state, hctx.octx.state, sizeof(u.state));
            SHA256_Transform(u.state, hctx.octx.buf, tmp32, &tmp32[64]);
            be32enc_vect(&buf[i * 32], u.state, 4);
        }
        goto cleanup;
    }
generic:
    _HMAC_SHA256_Init(&Phctx, passwd, passwdlen, tmp32, u.tmp8, &u.tmp8[64]);
    memcpy(&PShctx, &Phctx, sizeof(HMAC_SHA256_CTX));
    _HMAC_SHA256_Update(&PShctx, salt, saltlen, tmp32);
    for (i = 0; i * 32 < dkLen; i++) {
        uint8_t ivec[4];
        be32enc(ivec, (uint32_t)(i + 1));
        memcpy(&hctx, &PShctx, sizeof(HMAC_SHA256_CTX));
        _HMAC_SHA256_Update(&hctx, ivec, 4, tmp32);
        _HMAC_SHA256_Final(T, &hctx, tmp32, u.tmp8);
        if (c > 1) {
            memcpy(U, T, 32);
            for (j = 2; j <= c; j++) {
                memcpy(&hctx, &Phctx, sizeof(HMAC_SHA256_CTX));
                _HMAC_SHA256_Update(&hctx, U, 32, tmp32);
                _HMAC_SHA256_Final(U, &hctx, tmp32, u.tmp8);
                for (int k = 0; k < 32; k++)
                    T[k] ^= U[k];
            }
        }
        clen = dkLen - i * 32; if (clen > 32) clen = 32;
        memcpy(&buf[i * 32], T, clen);
    }
    insecure_memzero(&Phctx, sizeof(HMAC_SHA256_CTX));
    insecure_memzero(&PShctx, sizeof(HMAC_SHA256_CTX));
    insecure_memzero(U, sizeof(U));
    insecure_memzero(T, sizeof(T));
cleanup:
    insecure_memzero(&hctx, sizeof(HMAC_SHA256_CTX));
    insecure_memzero(tmp32, sizeof(tmp32));
    insecure_memzero(&u, sizeof(u));
}
