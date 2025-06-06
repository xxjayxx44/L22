#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// Basic SHA-256 operations (rotate right, choice, majority, etc.)
#define ROTR(x,n)   (((x) >> (n)) | ((x) << (32-(n))))
#define Ch(x,y,z)   ((z) ^ ((x) & ((y) ^ (z))))
#define Maj(x,y,z)  (((x) & (y)) | ((z) & ((x) | (y))))
#define EP0(x)      (ROTR(x, 2) ^ ROTR(x,13) ^ ROTR(x,22))
#define EP1(x)      (ROTR(x, 6) ^ ROTR(x,11) ^ ROTR(x,25))
#define SIG0(x)     (ROTR(x, 7) ^ ROTR(x,18) ^ ((x) >> 3))
#define SIG1(x)     (ROTR(x,17) ^ ROTR(x,19) ^ ((x) >> 10))

// SHA-256 context
typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t data[64];
    uint32_t datalen;
} SHA256_CTX;

// SHA-256 round constants (first 64 of the fractional parts of cube roots of primes):contentReference[oaicite:12]{index=12}
static const uint32_t K[64] = {
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

// SHA-256 transform: process one 512-bit block
static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[])
{
    uint32_t W[64], a,b,c,d,e,f,g,h,t1,t2;
    int i;
    // Prepare message schedule W
    for (i = 0; i < 16; i++) {
        W[i]  = (uint32_t)data[i*4] << 24;
        W[i] |= (uint32_t)data[i*4+1] << 16;
        W[i] |= (uint32_t)data[i*4+2] << 8;
        W[i] |= (uint32_t)data[i*4+3];
    }
    for (i = 16; i < 64; i++) {
        W[i] = SIG1(W[i-2]) + W[i-7] + SIG0(W[i-15]) + W[i-16];
    }
    // Initialize working variables with current hash state
    a = ctx->state[0];  b = ctx->state[1];
    c = ctx->state[2];  d = ctx->state[3];
    e = ctx->state[4];  f = ctx->state[5];
    g = ctx->state[6];  h = ctx->state[7];
    // Main loop (64 rounds)
    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + Ch(e,f,g) + K[i] + W[i];
        t2 = EP0(a) + Maj(a,b,c);
        h = g; g = f; f = e;
        e = d + t1;
        d = c; c = b; b = a;
        a = t1 + t2;
    }
    // Add the working vars back into state
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

// Initialize SHA-256 context
void SHA256_Init(SHA256_CTX *ctx)
{
    ctx->datalen = 0;
    ctx->bitlen = 0;
    // Initial hash values (first 32 bits of sqrt of first 8 primes):contentReference[oaicite:13]{index=13} 
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

// Update SHA-256 with data bytes
void SHA256_Update(SHA256_CTX *ctx, const uint8_t data[], size_t len)
{
    size_t i = 0;
    // Update bit length (in bits)
    ctx->bitlen += (uint64_t)len << 3;
    // Fill existing buffer if needed
    if (ctx->datalen && ctx->datalen + len >= 64) {
        size_t fill = 64 - ctx->datalen;
        memcpy(ctx->data + ctx->datalen, data, fill);
        sha256_transform(ctx, ctx->data);
        ctx->datalen = 0;
        i += fill;
    }
    // Process full 64-byte chunks directly from input
    for (; i + 63 < len; i += 64) {
        sha256_transform(ctx, data + i);
    }
    // Copy remaining bytes to buffer
    if (i < len) {
        ctx->datalen = len - i;
        memcpy(ctx->data, data + i, ctx->datalen);
    }
}

// Finalize SHA-256 and produce the digest (32 bytes)
void SHA256_Final(uint8_t hash[], SHA256_CTX *ctx)
{
    uint32_t i = ctx->datalen;
    // Append the bit '1' (0x80) and pad with zeros
    if (i < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }
    // Append 64-bit big-endian bit length
    for (i = 0; i < 8; i++) {
        ctx->data[63 - i] = (uint8_t)(ctx->bitlen >> (i * 8));
    }
    sha256_transform(ctx, ctx->data);
    // Convert state to big-endian byte array
    for (i = 0; i < 8; i++) {
        hash[i*4]     = (ctx->state[i] >> 24) & 0xFF;
        hash[i*4 + 1] = (ctx->state[i] >> 16) & 0xFF;
        hash[i*4 + 2] = (ctx->state[i] >>  8) & 0xFF;
        hash[i*4 + 3] =  ctx->state[i]        & 0xFF;
    }
}

// Compute HMAC-SHA256: out must be 32 bytes
void HMAC_SHA256(const uint8_t *key, size_t keylen,
                 const uint8_t *data, size_t datalen,
                 uint8_t out[32])
{
    uint8_t key_pad[64];
    uint8_t inner_hash[32];
    SHA256_CTX ctx;
    // Prepare key (hash if longer than block, else pad with zeros)
    if (keylen > 64) {
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, key, keylen);
        SHA256_Final(key_pad, &ctx);
        memset(key_pad + 32, 0, 32);
    } else {
        memcpy(key_pad, key, keylen);
        memset(key_pad + keylen, 0, 64 - keylen);
    }
    // Inner hash: ipad = 0x36
    for (int i = 0; i < 64; i++) key_pad[i] ^= 0x36;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, key_pad, 64);
    SHA256_Update(&ctx, data, datalen);
    SHA256_Final(inner_hash, &ctx);
    // Outer hash: opad = 0x5c
    for (int i = 0; i < 64; i++) key_pad[i] ^= (0x36 ^ 0x5c);  // undo ipad and apply opad
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, key_pad, 64);
    SHA256_Update(&ctx, inner_hash, 32);
    SHA256_Final(out, &ctx);
}

// PBKDF2-HMAC-SHA256: derive key of length outlen bytes from password and salt
// Iteration count c (typically thousands).  out and salt can overlap safely.
void PBKDF2_HMAC_SHA256(const char *password, const uint8_t *salt, size_t salt_len,
                       uint32_t iterations, uint8_t *out, size_t outlen)
{
    uint32_t pass_len = strlen(password);
    uint8_t U[32], T[32];
    uint8_t be_i[4];
    SHA256_CTX ctx;
    uint8_t *salt_block;
    // Allocate salt||block buffer
    salt_block = (uint8_t*)malloc(salt_len + 4);
    if (!salt_block) return;
    memcpy(salt_block, salt, salt_len);
    size_t derived = 0;
    uint32_t block = 1, i, j;
    while (derived < outlen) {
        // Compute U_1 = HMAC(pass, salt || INT_32_BE(block))
        be_i[0] = (block >> 24) & 0xFF;
        be_i[1] = (block >> 16) & 0xFF;
        be_i[2] = (block >>  8) & 0xFF;
        be_i[3] =  block        & 0xFF;
        memcpy(salt_block + salt_len, be_i, 4);
        HMAC_SHA256((const uint8_t*)password, pass_len,
                    salt_block, salt_len + 4, U);
        memcpy(T, U, 32);
        // U_j = HMAC(pass, U_{j-1}), T = XOR of all U_j
        for (j = 2; j <= iterations; j++) {
            HMAC_SHA256((const uint8_t*)password, pass_len, U, 32, U);
            for (i = 0; i < 32; i++) {
                T[i] ^= U[i];
            }
        }
        // Copy T to output (may be partial on last block)
        size_t to_copy = (derived + 32 > outlen) ? (outlen - derived) : 32;
        memcpy(out + derived, T, to_copy);
        derived += to_copy;
        block++;
    }
    free(salt_block);
}
