#include <stdio.h>
#include <string.h>
#include <stdint.h>

// --- SHA-256 context and functions ---

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t data[64];
    size_t datalen;
} SHA256_CTX;

// SHA-256 constants (first 32 bits of sqrt of primes)
static const uint32_t sha256_k[64] = {
    0x428a2f98ul,0x71374491ul,0xb5c0fbcful,0xe9b5dba5ul,0x3956c25bul,0x59f111f1ul,0x923f82a4ul,0xab1c5ed5ul,
    0xd807aa98ul,0x12835b01ul,0x243185beul,0x550c7dc3ul,0x72be5d74ul,0x80deb1feul,0x9bdc06a7ul,0xc19bf174ul,
    0xe49b69c1ul,0xefbe4786ul,0x0fc19dc6ul,0x240ca1ccul,0x2de92c6ful,0x4a7484aaul,0x5cb0a9dcul,0x76f988daul,
    0x983e5152ul,0xa831c66dul,0xb00327c8ul,0xbf597fc7ul,0xc6e00bf3ul,0xd5a79147ul,0x06ca6351ul,0x14292967ul,
    0x27b70a85ul,0x2e1b2138ul,0x4d2c6dfcul,0x53380d13ul,0x650a7354ul,0x766a0abbul,0x81c2c92eul,0x92722c85ul,
    0xa2bfe8a1ul,0xa81a664bul,0xc24b8b70ul,0xc76c51a3ul,0xd192e819ul,0xd6990624ul,0xf40e3585ul,0x106aa070ul,
    0x19a4c116ul,0x1e376c08ul,0x2748774cul,0x34b0bcb5ul,0x391c0cb3ul,0x4ed8aa4aul,0x5b9cca4ful,0x682e6ff3ul,
    0x748f82eeul,0x78a5636ful,0x84c87814ul,0x8cc70208ul,0x90befffaul,0xa4506cebul,0xbef9a3f7ul,0xc67178f2ul
};

// Bitwise functions for SHA-256
#define ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x,y,z) (((x) & (y)) ^ ((~(x)) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIG0(x) (ROTR((x), 2) ^ ROTR((x),13) ^ ROTR((x),22))
#define SIG1(x) (ROTR((x), 6) ^ ROTR((x),11) ^ ROTR((x),25))
#define sig0(x) (ROTR((x), 7) ^ ROTR((x),18) ^ ((x) >> 3))
#define sig1(x) (ROTR((x),17) ^ ROTR((x),19) ^ ((x) >> 10))

// SHA-256 block transform (unrolled loop for speed)
static void sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[64];
    // Prepare message schedule (big-endian)
    for (int i = 0; i < 16; ++i) {
        W[i] = (uint32_t)block[i*4] << 24 |
               (uint32_t)block[i*4 + 1] << 16 |
               (uint32_t)block[i*4 + 2] << 8 |
               (uint32_t)block[i*4 + 3];
    }
    // Expand the message schedule
    for (int i = 16; i < 64; ++i) {
        W[i] = sig1(W[i-2]) + W[i-7] + sig0(W[i-15]) + W[i-16];
    }
    // Initialize working variables from current state
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    // Main SHA-256 loop (64 rounds)
    for (int i = 0; i < 64; ++i) {
        uint32_t T1 = h + SIG1(e) + CH(e, f, g) + sha256_k[i] + W[i];
        uint32_t T2 = SIG0(a) + MAJ(a, b, c);
        h = g; g = f; f = e;
        e = d + T1;
        d = c; c = b; b = a;
        a = T1 + T2;
    }
    // Add the working vars back into state
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void SHA256_Init(SHA256_CTX *ctx) {
    // Initial hash values (first 32 bits of sqrt of 2..19)
    ctx->state[0] = 0x6a09e667ul;
    ctx->state[1] = 0xbb67ae85ul;
    ctx->state[2] = 0x3c6ef372ul;
    ctx->state[3] = 0xa54ff53aul;
    ctx->state[4] = 0x510e527ful;
    ctx->state[5] = 0x9b05688cul;
    ctx->state[6] = 0x1f83d9abul;
    ctx->state[7] = 0x5be0cd19ul;
    ctx->bitlen = 0;
    ctx->datalen = 0;
}

void SHA256_Update(SHA256_CTX *ctx, const uint8_t *data, size_t len) {
    // Absorb input bytes
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            sha256_transform(ctx->state, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

void SHA256_Final(uint8_t *hash, SHA256_CTX *ctx) {
    // Pad with a 1 bit and then zeros, up to 56 bytes
    size_t i = ctx->datalen;
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0;
        sha256_transform(ctx->state, ctx->data);
        memset(ctx->data, 0, 56);
    }
    // Append length (big-endian)
    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = (uint8_t)(ctx->bitlen);
    ctx->data[62] = (uint8_t)(ctx->bitlen >> 8);
    ctx->data[61] = (uint8_t)(ctx->bitlen >> 16);
    ctx->data[60] = (uint8_t)(ctx->bitlen >> 24);
    ctx->data[59] = (uint8_t)(ctx->bitlen >> 32);
    ctx->data[58] = (uint8_t)(ctx->bitlen >> 40);
    ctx->data[57] = (uint8_t)(ctx->bitlen >> 48);
    ctx->data[56] = (uint8_t)(ctx->bitlen >> 56);
    sha256_transform(ctx->state, ctx->data);
    // Output the final hash (big-endian)
    for (int j = 0; j < 8; ++j) {
        hash[j*4]     = (uint8_t)(ctx->state[j] >> 24);
        hash[j*4 + 1] = (uint8_t)(ctx->state[j] >> 16);
        hash[j*4 + 2] = (uint8_t)(ctx->state[j] >> 8);
        hash[j*4 + 3] = (uint8_t)(ctx->state[j]);
    }
}

// HMAC-SHA256 (for PBKDF2 support, preserves SHA256 API)
void HMAC_SHA256(const uint8_t *key, size_t keylen, const uint8_t *data, size_t datalen, uint8_t *hmac) {
    uint8_t k_ipad[64], k_opad[64], tk[32];
    // If key is longer than 64 bytes, shorten it
    if (keylen > 64) {
        SHA256_CTX tctx;
        SHA256_Init(&tctx);
        SHA256_Update(&tctx, key, keylen);
        SHA256_Final(tk, &tctx);
        key = tk; keylen = 32;
    }
    // XOR key with ipad/opad values
    memset(k_ipad, 0, 64);
    memset(k_opad, 0, 64);
    memcpy(k_ipad, key, keylen);
    memcpy(k_opad, key, keylen);
    for (int i = 0; i < 64; i++) {
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
    SHA256_Final(hmac, &ctx);
}

// PBKDF2-HMAC-SHA256 (standard implementation)
void PBKDF2_SHA256(const uint8_t *password, size_t plen, const uint8_t *salt, size_t slen,
                   uint64_t iterations, uint8_t *out, size_t outlen) {
    uint8_t key_ipad[64], key_opad[64], tk[32];
    // If password is longer than 64 bytes, hash it first
    if (plen > 64) {
        SHA256_CTX tctx;
        SHA256_Init(&tctx);
        SHA256_Update(&tctx, password, plen);
        SHA256_Final(tk, &tctx);
        password = tk; plen = 32;
    }
    // Prepare HMAC key pads
    memset(key_ipad, 0, 64);
    memset(key_opad, 0, 64);
    memcpy(key_ipad, password, plen);
    memcpy(key_opad, password, plen);
    for (int i = 0; i < 64; i++) {
        key_ipad[i] ^= 0x36;
        key_opad[i] ^= 0x5c;
    }
    SHA256_CTX ctx;
    uint32_t block = 1;
    uint8_t U[32], T[32];
    size_t done = 0;
    while (done < outlen) {
        // U_1 = HMAC(password, salt || block)
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, key_ipad, 64);
        SHA256_Update(&ctx, salt, slen);
        uint8_t be[4] = {(uint8_t)(block>>24), (uint8_t)(block>>16), (uint8_t)(block>>8), (uint8_t)block};
        SHA256_Update(&ctx, be, 4);
        SHA256_Final(U, &ctx);
        memcpy(T, U, 32);
        // Iterate U_i
        for (uint64_t i = 1; i < iterations; i++) {
            SHA256_Init(&ctx);
            SHA256_Update(&ctx, key_opad, 64);
            SHA256_Update(&ctx, U, 32);
            SHA256_Final(U, &ctx);
            for (int j = 0; j < 32; j++) T[j] ^= U[j];
        }
        // Copy to output
        size_t chunk = (outlen - done < 32) ? (outlen - done) : 32;
        memcpy(out + done, T, chunk);
        done += chunk;
        block++;
    }
}

// --- Tight mining loop example ---
int main() {
    // Example 64-byte block (fill with header data as needed)
    uint8_t block[64] = {0};
    // Nonce occupies the last 4 bytes (offset 60..63)
    uint32_t nonce = 0;
    uint8_t hash1[32], finalhash[32];

    // Example difficulty: require 20 leading zero bits
    while (1) {
        // Efficient in-place nonce update (big-endian)
        block[60] = (nonce >> 24) & 0xFF;
        block[61] = (nonce >> 16) & 0xFF;
        block[62] = (nonce >> 8) & 0xFF;
        block[63] = nonce & 0xFF;

        // Compute double SHA-256: first hash
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, block, 64);
        SHA256_Final(hash1, &ctx);
        // Second hash (final result)
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, hash1, 32);
        SHA256_Final(finalhash, &ctx);

        // Check leading-zero threshold (20 bits)
        if (finalhash[0] == 0 && finalhash[1] == 0 && (finalhash[2] & 0xF0) == 0) {
            printf("Valid hash found! Nonce = %u\n", nonce);
            printf("Hash: ");
            for (int i = 0; i < 32; i++) printf("%02x", finalhash[i]);
            printf("\n");
            break;
        }
        nonce++;
        // (Loop runs until a valid nonce is found)
    }
    return 0;
}
