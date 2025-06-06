/* Optimized SHA-256 implementation for L22 mining (public domain) */
#include <stdint.h>
#include <string.h>

// Right-rotate a 32-bit value
#define ROTR32(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

/* SHA-256 context structure */
typedef struct {
    uint32_t state[8];
    uint64_t count;    // number of bytes processed so far
    uint8_t buf[64];
} SHA256_CTX;

/* SHA-256 round constants */
static const uint32_t K[64] = {
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

/* SHA-256 compression function (handles one 512-bit block) */
static void SHA256_Transform(SHA256_CTX *ctx) {
    uint32_t W[64];
    const uint8_t *p = ctx->buf;
    // Prepare message schedule (big-endian)
    for(int t = 0; t < 16; ++t) {
        W[t] = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
        p += 4;
    }
    for(int t = 16; t < 64; ++t) {
        uint32_t s0 = ROTR32(W[t-15], 7) ^ ROTR32(W[t-15], 18) ^ (W[t-15] >> 3);
        uint32_t s1 = ROTR32(W[t-2], 17) ^ ROTR32(W[t-2], 19) ^ (W[t-2] >> 10);
        W[t] = W[t-16] + s0 + W[t-7] + s1;
    }
    // Initialize working variables to current hash state
    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];
    uint32_t e = ctx->state[4];
    uint32_t f = ctx->state[5];
    uint32_t g = ctx->state[6];
    uint32_t h = ctx->state[7];
    // Unrolled main loop (64 rounds)
    for(int t = 0; t < 64; ++t) {
        uint32_t S0 = ROTR32(a,2) ^ ROTR32(a,13) ^ ROTR32(a,22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t S1 = ROTR32(e,6) ^ ROTR32(e,11) ^ ROTR32(e,25);
        uint32_t ch  = (e & f) ^ ((~e) & g);
        uint32_t T1 = h + S1 + ch + K[t] + W[t];
        uint32_t T2 = S0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }
    // Add the compressed chunk to the current hash value
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

/* Initialize SHA-256 context */
void SHA256_Init(SHA256_CTX *ctx) {
    // Initial hash values (first 32 bits of square roots of primes 2..19)
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

/* Process input data in chunks */
void SHA256_Update(SHA256_CTX *ctx, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t*)data;
    uint64_t idx = ctx->count & 63;
    ctx->count += len;
    // Fill buffer and transform as necessary
    while(len--) {
        ctx->buf[idx++] = *p++;
        if(idx == 64) {
            SHA256_Transform(ctx);
            idx = 0;
        }
    }
}

/* Finalize and output the SHA-256 hash */
void SHA256_Final(uint8_t hash[32], SHA256_CTX *ctx) {
    uint64_t bitlen = ctx->count * 8;
    // Append the '1' bit (0x80), then pad with zeros
    uint8_t pad = 0x80;
    SHA256_Update(ctx, &pad, 1);
    while((ctx->count & 63) != 56) {
        uint8_t zero = 0x00;
        SHA256_Update(ctx, &zero, 1);
    }
    // Append original message length in bits (big-endian)
    uint8_t lenbuf[8];
    for(int i = 0; i < 8; ++i) {
        lenbuf[7-i] = (uint8_t)(bitlen >> (i * 8));
    }
    SHA256_Update(ctx, lenbuf, 8);
    // Output hash state in big-endian
    for(int i = 0; i < 8; ++i) {
        hash[i*4 + 0] = (uint8_t)(ctx->state[i] >> 24);
        hash[i*4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        hash[i*4 + 2] = (uint8_t)(ctx->state[i] >>  8);
        hash[i*4 + 3] = (uint8_t)(ctx->state[i] >>  0);
    }
}
