/*
 * Optimized SHA-256, HMAC-SHA256, and PBKDF2-HMAC-SHA256 implementation
 * Adapted for use in yespower-opt.c (provides SHA256_Buf and HMAC_SHA256_Buf).
 */

#include <stdint.h>
#include <string.h>

/* SHA-256 context structure */
typedef struct {
    uint32_t state[8];
    uint64_t count;       /* number of bits processed */
    uint8_t buffer[64];   /* 512-bit block buffer */
} SHA256_CTX;

/* Rotate right (32-bit) */
#define ROTR(x,n)    (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x,y,z)    (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z)   (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)       (ROTR(x,  2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x)       (ROTR(x,  6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x)      (ROTR(x,  7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIG1(x)      (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

/* SHA-256 constants (first 32 bits of cube roots of first 64 primes) */
static const uint32_t K256[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

/*
 * SHA256_Transform:
 *   Perform the SHA-256 compression on a single 512-bit block.
 *   This version unrolls rounds in 8-round blocks for improved instruction-level parallelism.
 */
static void SHA256_Transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h, T1, T2;

    /* Prepare message schedule (big-endian) */
    for (int i = 0; i < 16; i++) {
        W[i]  = ((uint32_t)block[4*i]   << 24)
              | ((uint32_t)block[4*i+1] << 16)
              | ((uint32_t)block[4*i+2] <<  8)
              | ((uint32_t)block[4*i+3]);
    }
    for (int i = 16; i < 64; i++) {
        W[i] = SIG1(W[i-2]) + W[i-7] + SIG0(W[i-15]) + W[i-16];
    }

    /* Initialize working variables */
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    /* Unrolled main loop: process in chunks of 8 rounds */
    for (int i = 0; i < 64; i += 8) {
        /* Round i */
        T1 = h + EP1(e) + CH(e,f,g) + K256[i]   + W[i];
        T2 = EP0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;

        /* Round i+1 */
        T1 = h + EP1(e) + CH(e,f,g) + K256[i+1] + W[i+1];
        T2 = EP0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;

        /* Round i+2 */
        T1 = h + EP1(e) + CH(e,f,g) + K256[i+2] + W[i+2];
        T2 = EP0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;

        /* Round i+3 */
        T1 = h + EP1(e) + CH(e,f,g) + K256[i+3] + W[i+3];
        T2 = EP0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;

        /* Round i+4 */
        T1 = h + EP1(e) + CH(e,f,g) + K256[i+4] + W[i+4];
        T2 = EP0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;

        /* Round i+5 */
        T1 = h + EP1(e) + CH(e,f,g) + K256[i+5] + W[i+5];
        T2 = EP0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;

        /* Round i+6 */
        T1 = h + EP1(e) + CH(e,f,g) + K256[i+6] + W[i+6];
        T2 = EP0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;

        /* Round i+7 */
        T1 = h + EP1(e) + CH(e,f,g) + K256[i+7] + W[i+7];
        T2 = EP0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    /* Add back into state */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

/*
 * SHA256_Init:
 *   Initialize the SHA-256 context (set initial hash values).
 */
void SHA256_Init(SHA256_CTX *ctx) {
    /* These are the first 32 bits of the fractional parts of the square roots of the first 8 primes */
    ctx->state[0] = 0x6a09e667UL;
    ctx->state[1] = 0xbb67ae85UL;
    ctx->state[2] = 0x3c6ef372UL;
    ctx->state[3] = 0xa54ff53aUL;
    ctx->state[4] = 0x510e527fUL;
    ctx->state[5] = 0x9b05688cUL;
    ctx->state[6] = 0x1f83d9abUL;
    ctx->state[7] = 0x5be0cd19UL;
    ctx->count = 0;
    memset(ctx->buffer, 0, 64);
}

/*
 * SHA256_Update:
 *   Process input data in chunks, updating the SHA-256 state.
 */
void SHA256_Update(SHA256_CTX *ctx, const uint8_t *data, size_t len) {
    size_t idx = (ctx->count >> 3) & 0x3F; /* bytes used in buffer */
    ctx->count += (uint64_t)len << 3;      /* update bit count */

    size_t part = 64 - idx;
    size_t i = 0;

    /* If buffer has leftover data and we can fill to 64 bytes, fill and transform */
    if (len >= part) {
        memcpy(&ctx->buffer[idx], data, part);
        SHA256_Transform(ctx->state, ctx->buffer);
        i = part;
        /* Process full blocks directly from input */
        for (; i + 63 < len; i += 64) {
            SHA256_Transform(ctx->state, data + i);
        }
        idx = 0;
    }

    /* Copy remaining bytes into buffer */
    if (i < len) {
        memcpy(&ctx->buffer[idx], data + i, len - i);
    }
}

/*
 * SHA256_Final:
 *   Finalize the hash and produce the 32-byte output (big-endian).
 */
void SHA256_Final(uint8_t hash[32], SHA256_CTX *ctx) {
    static const uint8_t PADDING[64] = { 0x80 };
    uint8_t bits[8];
    uint64_t cnt = ctx->count;

    /* Convert bit count to big-endian byte array */
    for (int i = 0; i < 8; i++) {
        bits[7 - i] = (uint8_t)(cnt >> (i * 8));
    }

    size_t idx = (ctx->count >> 3) & 0x3F;
    size_t padLen = (idx < 56) ? (56 - idx) : (120 - idx);

    /* Pad with a single 1 bit then zeros */
    SHA256_Update(ctx, PADDING, padLen);
    /* Append length */
    SHA256_Update(ctx, bits, 8);

    /* Convert state to big-endian output */
    for (int i = 0; i < 8; i++) {
        hash[4*i    ] = (uint8_t)(ctx->state[i] >> 24);
        hash[4*i + 1] = (uint8_t)(ctx->state[i] >> 16);
        hash[4*i + 2] = (uint8_t)(ctx->state[i] >>  8);
        hash[4*i + 3] = (uint8_t)(ctx->state[i]      );
    }
}

/*
 * SHA256_Buf:
 *   Convenience wrapper: compute SHA-256 digest of a single buffer.
 *   Equivalent to: Init, Update with entire buffer, Final.
 */
void SHA256_Buf(const uint8_t *data, size_t len, uint8_t hash[32]) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(hash, &ctx);
}

/*
 * HMAC-SHA256:
 *   Computes HMAC using SHA-256:
 *     HMAC(K, D) = SHA256((K^opad) || SHA256((K^ipad) || D))
 *   key: pointer to key bytes
 *   keylen: length of key in bytes
 *   data: pointer to message bytes
 *   datalen: length of message in bytes
 *   mac: output buffer (must be at least 32 bytes)
 */
void HMAC_SHA256(const uint8_t *key, size_t keylen,
                 const uint8_t *data, size_t datalen,
                 uint8_t *mac) {
    uint8_t k_ipad[64], k_opad[64], tk[32];
    SHA256_CTX ctx;

    /* If key is longer than block size (64), shorten it */
    if (keylen > 64) {
        SHA256_CTX tctx;
        SHA256_Init(&tctx);
        SHA256_Update(&tctx, key, keylen);
        SHA256_Final(tk, &tctx);
        key = tk;
        keylen = 32;
    }

    /* Prepare inner and outer padded keys */
    memset(k_ipad, 0, 64);
    memset(k_opad, 0, 64);
    memcpy(k_ipad, key, keylen);
    memcpy(k_opad, key, keylen);
    for (int i = 0; i < 64; i++) {
        k_ipad[i] ^= 0x36U;
        k_opad[i] ^= 0x5cU;
    }

    /* Inner hash */
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, k_ipad, 64);
    SHA256_Update(&ctx, data, datalen);
    SHA256_Final(tk, &ctx);

    /* Outer hash */
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, k_opad, 64);
    SHA256_Update(&ctx, tk, 32);
    SHA256_Final(mac, &ctx);
}

/*
 * HMAC_SHA256_Buf:
 *   Alias for HMAC_SHA256 to match yespower-opt.c usage.
 *   Signature: (key, keylen, data, datalen, mac)
 */
void HMAC_SHA256_Buf(const uint8_t *key, size_t keylen,
                     const uint8_t *data, size_t datalen,
                     uint8_t *mac) {
    HMAC_SHA256(key, keylen, data, datalen, mac);
}

/*
 * PBKDF2-HMAC-SHA256:
 *   Derive a key of dkLen bytes from password and salt using HMAC-SHA256, iterated 'iterations' times.
 *   password: pointer to password bytes
 *   plen: length of password in bytes
 *   salt: pointer to salt bytes
 *   slen: length of salt in bytes
 *   iterations: iteration count (e.g. >= 1)
 *   dk: output buffer (must be at least dkLen bytes)
 *   dkLen: desired derived key length in bytes
 */
void PBKDF2_SHA256(const uint8_t *password, size_t plen,
                   const uint8_t *salt, size_t slen,
                   uint64_t iterations,
                   uint8_t *dk, size_t dkLen) {
    uint32_t blockCount = (uint32_t)((dkLen + 31) / 32);
    uint8_t U[32], T[32];
    uint8_t salt_block[slen + 4];

    memcpy(salt_block, salt, slen);

    for (uint32_t i = 1; i <= blockCount; i++) {
        /* salt||INT_32_BE(i) */
        salt_block[slen  ] = (uint8_t)(i >> 24);
        salt_block[slen+1] = (uint8_t)(i >> 16);
        salt_block[slen+2] = (uint8_t)(i >>  8);
        salt_block[slen+3] = (uint8_t)(i      );

        /* U_1 = HMAC(password, salt_block) */
        HMAC_SHA256(password, plen, salt_block, slen + 4, U);
        memcpy(T, U, 32);

        /* U_j = HMAC(password, U_{j-1}); T ^= U_j */
        for (uint64_t j = 2; j <= iterations; j++) {
            HMAC_SHA256(password, plen, U, 32, U);
            for (int k = 0; k < 32; k++) {
                T[k] ^= U[k];
            }
        }

        size_t offset = (i - 1) * 32;
        size_t clen = (dkLen - offset >= 32) ? 32 : (dkLen - offset);
        memcpy(dk + offset, T, clen);
    }
}
