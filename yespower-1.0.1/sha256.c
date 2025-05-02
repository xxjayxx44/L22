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
#define restrict __restrict
#else
#define restrict
#endif

#define Ch(x,y,z)    ((x & (y ^ z)) ^ z)
#define Maj(x,y,z)   ((x & (y | z)) | (y & z))
#define SHR(x,n)     (x >> n)
#define ROTR(x,n)    ((x >> n) | (x << (32 - n)))
#define S0(x)        (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define S1(x)        (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
#define s0(x)        (ROTR(x,7) ^ ROTR(x,18) ^ SHR(x,3))
#define s1(x)        (ROTR(x,17) ^ ROTR(x,19) ^ SHR(x,10))

#define RND(a,b,c,d,e,f,g,h,k)  \
    h += S1(e) + Ch(e,f,g) + k; \
    d += h;                     \
    h += S0(a) + Maj(a,b,c);

#define RNDr(S,W,i) \
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],W[i]+Krnd[i]); \
    uint32_t tmp = S[7]; \
    S[7] = S[6]; S[6] = S[5]; S[5] = S[4]; S[4] = S[3] + tmp; \
    S[3] = S[2]; S[2] = S[1]; S[1] = S[0]; S[0] = tmp;

static const uint32_t Krnd[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static inline void SHA256_Transform(uint32_t state[restrict 8],
                                    const uint8_t block[restrict 64],
                                    uint32_t W[restrict 64],
                                    uint32_t S[restrict 8])
{
    int i;
    for (i = 0; i < 16; i++) {
        W[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }

    for (i = 16; i < 64; i++) {
        W[i] = s1(W[i - 2]) + W[i - 7] + s0(W[i - 15]) + W[i - 16];
    }

    memcpy(S, state, 32);

#define R(i) RNDr(S,W,i)
    R(0); R(1); R(2); R(3); R(4); R(5); R(6); R(7);
    R(8); R(9); R(10); R(11); R(12); R(13); R(14); R(15);
    R(16); R(17); R(18); R(19); R(20); R(21); R(22); R(23);
    R(24); R(25); R(26); R(27); R(28); R(29); R(30); R(31);
    R(32); R(33); R(34); R(35); R(36); R(37); R(38); R(39);
    R(40); R(41); R(42); R(43); R(44); R(45); R(46); R(47);
    R(48); R(49); R(50); R(51); R(52); R(53); R(54); R(55);
    R(56); R(57); R(58); R(59); R(60); R(61); R(62); R(63);
#undef R

    for (i = 0; i < 8; i++)
        state[i] += S[i];
}

static const uint8_t PAD[64] = { 0x80 };

static void SHA256_Pad(SHA256_CTX *ctx, uint32_t W[restrict 64], uint32_t S[restrict 8]) {
    size_t r = (ctx->count >> 3) & 0x3f;
    size_t padlen = (r < 56) ? 56 - r : 120 - r;

    SHA256_Update(ctx, PAD, padlen);

    uint8_t lenblock[8];
    be64enc(lenblock, ctx->count);
    SHA256_Update(ctx, lenblock, 8);
}

static const uint32_t initial_state[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

void SHA256_Init(SHA256_CTX *ctx) {
    ctx->count = 0;
    memcpy(ctx->state, initial_state, sizeof(initial_state));
}

static void _SHA256_Update(SHA256_CTX *ctx, const void *in, size_t len,
                           uint32_t W[restrict 64], uint32_t S[restrict 8]) {
    uint32_t r = (ctx->count >> 3) & 0x3f;
    ctx->count += (uint64_t)len << 3;

    const uint8_t *src = in;
    if (r) {
        uint32_t rem = 64 - r;
        if (len < rem) {
            memcpy(&ctx->buf[r], src, len);
            return;
        }
        memcpy(&ctx->buf[r], src, rem);
        SHA256_Transform(ctx->state, ctx->buf, W, S);
        src += rem;
        len -= rem;
    }

    while (len >= 64) {
        SHA256_Transform(ctx->state, src, W, S);
        src += 64;
        len -= 64;
    }

    memcpy(ctx->buf, src, len);
}

void SHA256_Update(SHA256_CTX *ctx, const void *in, size_t len) {
    uint32_t W[64], S[8];
    _SHA256_Update(ctx, in, len, W, S);
}

void SHA256_Final(uint8_t digest[32], SHA256_CTX *ctx) {
    uint32_t W[64], S[8];
    SHA256_Pad(ctx, W, S);

    for (size_t i = 0; i < 8; i++)
        be32enc(&digest[i * 4], ctx->state[i]);

    insecure_memzero(ctx, sizeof(*ctx));
    insecure_memzero(W, sizeof(W));
    insecure_memzero(S, sizeof(S));
}
