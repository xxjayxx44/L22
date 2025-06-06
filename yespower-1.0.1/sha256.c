#include <stdint.h>
#include <string.h>

// -- SHA-256 implementation --

typedef struct {
    uint32_t state[8];
    uint64_t count;    // number of bits, mod 2^64
    uint8_t buffer[64];
} SHA256_CTX;

// Rotate right (32-bit)
#define ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z) (((x)&(y))^((~(x))&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define EP0(x) (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define EP1(x) (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
#define SIG0(x) (ROTR(x,7) ^ ROTR(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTR(x,17) ^ ROTR(x,19) ^ ((x) >> 10))

// SHA-256 constants (first 32 bits of cube roots of first 64 primes)
static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void SHA256_Transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[64];
    uint32_t a,b,c,d,e,f,g,h;
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    // Message schedule (big-endian input)
    for(int i = 0; i < 16; ++i) {
        W[i] = ((uint32_t)block[4*i] << 24) | ((uint32_t)block[4*i+1] << 16) |
               ((uint32_t)block[4*i+2] <<  8) | ((uint32_t)block[4*i+3]);
    }
    for(int i = 16; i < 64; ++i) {
        W[i] = SIG1(W[i-2]) + W[i-7] + SIG0(W[i-15]) + W[i-16];
    }

    // Compression function: 64 rounds unrolled in 8-round blocks for ILP
    for(int i = 0; i < 64; i += 8) {
        uint32_t T1, T2;
        T1 = h + EP1(e) + CH(e,f,g) + K256[i]   + W[i];
        T2 = EP0(a) + MAJ(a,b,c); h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;

        T1 = h + EP1(e) + CH(e,f,g) + K256[i+1] + W[i+1];
        T2 = EP0(a) + MAJ(a,b,c); h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;

        T1 = h + EP1(e) + CH(e,f,g) + K256[i+2] + W[i+2];
        T2 = EP0(a) + MAJ(a,b,c); h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;

        T1 = h + EP1(e) + CH(e,f,g) + K256[i+3] + W[i+3];
        T2 = EP0(a) + MAJ(a,b,c); h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;

        T1 = h + EP1(e) + CH(e,f,g) + K256[i+4] + W[i+4];
        T2 = EP0(a) + MAJ(a,b,c); h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;

        T1 = h + EP1(e) + CH(e,f,g) + K256[i+5] + W[i+5];
        T2 = EP0(a) + MAJ(a,b,c); h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;

        T1 = h + EP1(e) + CH(e,f,g) + K256[i+6] + W[i+6];
        T2 = EP0(a) + MAJ(a,b,c); h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;

        T1 = h + EP1(e) + CH(e,f,g) + K256[i+7] + W[i+7];
        T2 = EP0(a) + MAJ(a,b,c); h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

// Initialize SHA-256 context
void SHA256_Init(SHA256_CTX *ctx) {
    // Initial hash values (first 32 bits of sqrt primes)
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
    memset(ctx->buffer, 0, 64);
}

// Update SHA-256 with data
void SHA256_Update(SHA256_CTX *ctx, const uint8_t *data, size_t len) {
    size_t idx = (ctx->count >> 3) & 0x3F;
    ctx->count += (uint64_t)len << 3;
    size_t part = 64 - idx;
    size_t i = 0;
    if (len >= part) {
        memcpy(&ctx->buffer[idx], data, part);
        SHA256_Transform(ctx->state, ctx->buffer);
        for (i = part; i + 63 < len; i += 64) {
            SHA256_Transform(ctx->state, data + i);
        }
        idx = 0;
    }
    memcpy(&ctx->buffer[idx], data + i, len - i);
}

// Finalize SHA-256 and output 32-byte hash (big-endian)
void SHA256_Final(uint8_t hash[32], SHA256_CTX *ctx) {
    static const uint8_t PADDING[64] = { 0x80 };
    uint8_t bits[8];
    uint64_t cnt = ctx->count;
    for(int i = 0; i < 8; i++) {
        bits[7-i] = (uint8_t)(cnt >> (i * 8));
    }
    size_t idx = (ctx->count >> 3) & 0x3F;
    size_t padLen = (idx < 56) ? (56 - idx) : (120 - idx);
    SHA256_Update(ctx, PADDING, padLen);
    SHA256_Update(ctx, bits, 8);
    for(int i = 0; i < 8; i++) {
        hash[i*4    ] = (uint8_t)(ctx->state[i] >> 24);
        hash[i*4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        hash[i*4 + 2] = (uint8_t)(ctx->state[i] >>  8);
        hash[i*4 + 3] = (uint8_t)(ctx->state[i]      );
    }
}

// -- HMAC-SHA256 implementation --

// Compute HMAC-SHA256: MAC = SHA256(K_opad || SHA256(K_ipad || data))
void HMAC_SHA256(const uint8_t *key, size_t keylen,
                 const uint8_t *data, size_t datalen,
                 uint8_t *mac) {
    uint8_t k_ipad[64], k_opad[64], tk[32];
    // If key > block size, shorten it
    if (keylen > 64) {
        SHA256_CTX tctx;
        SHA256_Init(&tctx);
        SHA256_Update(&tctx, key, keylen);
        SHA256_Final(tk, &tctx);
        key = tk;
        keylen = 32;
    }
    memset(k_ipad, 0, 64);
    memset(k_opad, 0, 64);
    memcpy(k_ipad, key, keylen);
    memcpy(k_opad, key, keylen);
    for(int i = 0; i < 64; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }
    // Inner hash
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, k_ipad, 64);
    SHA256_Update(&ctx, data, datalen);
    SHA256_Final(tk, &ctx);
    // Outer hash
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, k_opad, 64);
    SHA256_Update(&ctx, tk, 32);
    SHA256_Final(mac, &ctx);
}

// -- PBKDF2-HMAC-SHA256 implementation --
// Derives key of length dkLen bytes using iteration count c.
void PBKDF2_SHA256(const uint8_t *password, size_t plen,
                   const uint8_t *salt, size_t slen,
                   uint64_t iterations, uint8_t *dk, size_t dkLen) {
    uint32_t blockCount = (dkLen + 31) / 32;
    uint8_t U[32], T[32];
    uint8_t salt_block[slen + 4];
    memcpy(salt_block, salt, slen);
    for(uint32_t i = 1; i <= blockCount; i++) {
        // salt || block index (big-endian)
        salt_block[slen  ] = (uint8_t)(i >> 24);
        salt_block[slen+1] = (uint8_t)(i >> 16);
        salt_block[slen+2] = (uint8_t)(i >> 8);
        salt_block[slen+3] = (uint8_t)(i);
        // U_1 = HMAC(password, salt||i)
        HMAC_SHA256(password, plen, salt_block, slen+4, U);
        memcpy(T, U, 32);
        // U_2 through U_c
        for(uint64_t j = 2; j <= iterations; j++) {
            HMAC_SHA256(password, plen, U, 32, U);
            for(int k = 0; k < 32; k++) {
                T[k] ^= U[k];
            }
        }
        size_t offset = (i-1)*32;
        size_t clen = (dkLen - offset >= 32) ? 32 : (dkLen - offset);
        memcpy(dk + offset, T, clen);
    }
}
