/* ULTRA-OPTIMIZED SHA256 FOR MINING - MAXIMUM SPEED */

#include <stdint.h>
#include <string.h>

#include "sysendian.h"
#include "sha256.h"

/* COMPILER OPTIMIZATIONS */
#ifdef __GNUC__
#define ALWAYS_INLINE __attribute__((always_inline))
#define HOT __attribute__((hot))
#define PACKED __attribute__((packed))
#else
#define ALWAYS_INLINE
#define HOT
#define PACKED
#endif

/* ULTRA-FAST ROTATE AND SHIFT - NO FUNCTION CALLS */
#define ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHR(x,n)  ((x) >> (n))

/* OPTIMIZED SHA-256 FUNCTIONS - PRE-COMPUTED WHERE POSSIBLE */
#define Ch(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define S0(x)      (ROTR(x, 2)  ^ ROTR(x,13) ^ ROTR(x,22))
#define S1(x)      (ROTR(x, 6)  ^ ROTR(x,11) ^ ROTR(x,25))
#define s0(x)      (ROTR(x, 7)  ^ ROTR(x,18) ^ SHR(x, 3))
#define s1(x)      (ROTR(x,17)  ^ ROTR(x,19) ^ SHR(x,10))

/* PRE-COMPUTED ROUND CONSTANTS - CACHE LINE ALIGNED */
static const uint32_t K256[64] __attribute__((aligned(64))) = {
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

/* INITIAL STATE - CACHE ALIGNED */
static const uint32_t initial_state[8] __attribute__((aligned(32))) = {
    0x6A09E667,0xBB67AE85,0x3C6EF372,0xA54FF53A,
    0x510E527F,0x9B05688C,0x1F83D9AB,0x5BE0CD19
};

/* PADDING - PRE-COMPUTED */
static const uint8_t PAD[64] __attribute__((aligned(64))) = {
    0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

/* ULTRA-FAST SHA256 TRANSFORM - UNROLLED AND OPTIMIZED */
static ALWAYS_INLINE HOT void 
sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[64] __attribute__((aligned(32)));
    uint32_t a, b, c, d, e, f, g, h;
    
    /* UNROLLED MESSAGE SCHEDULE - 16 WORDS */
    W[0]  = be32dec(block +  0); W[1]  = be32dec(block +  4);
    W[2]  = be32dec(block +  8); W[3]  = be32dec(block + 12);
    W[4]  = be32dec(block + 16); W[5]  = be32dec(block + 20);
    W[6]  = be32dec(block + 24); W[7]  = be32dec(block + 28);
    W[8]  = be32dec(block + 32); W[9]  = be32dec(block + 36);
    W[10] = be32dec(block + 40); W[11] = be32dec(block + 44);
    W[12] = be32dec(block + 48); W[13] = be32dec(block + 52);
    W[14] = be32dec(block + 56); W[15] = be32dec(block + 60);
    
    /* UNROLLED MESSAGE EXPANSION */
    W[16] = s1(W[14]) + W[9]  + s0(W[1]) + W[0];
    W[17] = s1(W[15]) + W[10] + s0(W[2]) + W[1];
    W[18] = s1(W[16]) + W[11] + s0(W[3]) + W[2];
    W[19] = s1(W[17]) + W[12] + s0(W[4]) + W[3];
    W[20] = s1(W[18]) + W[13] + s0(W[5]) + W[4];
    W[21] = s1(W[19]) + W[14] + s0(W[6]) + W[5];
    W[22] = s1(W[20]) + W[15] + s0(W[7]) + W[6];
    W[23] = s1(W[21]) + W[16] + s0(W[8]) + W[7];
    W[24] = s1(W[22]) + W[17] + s0(W[9]) + W[8];
    W[25] = s1(W[23]) + W[18] + s0(W[10]) + W[9];
    W[26] = s1(W[24]) + W[19] + s0(W[11]) + W[10];
    W[27] = s1(W[25]) + W[20] + s0(W[12]) + W[11];
    W[28] = s1(W[26]) + W[21] + s0(W[13]) + W[12];
    W[29] = s1(W[27]) + W[22] + s0(W[14]) + W[13];
    W[30] = s1(W[28]) + W[23] + s0(W[15]) + W[14];
    W[31] = s1(W[29]) + W[24] + s0(W[16]) + W[15];
    W[32] = s1(W[30]) + W[25] + s0(W[17]) + W[16];
    W[33] = s1(W[31]) + W[26] + s0(W[18]) + W[17];
    W[34] = s1(W[32]) + W[27] + s0(W[19]) + W[18];
    W[35] = s1(W[33]) + W[28] + s0(W[20]) + W[19];
    W[36] = s1(W[34]) + W[29] + s0(W[21]) + W[20];
    W[37] = s1(W[35]) + W[30] + s0(W[22]) + W[21];
    W[38] = s1(W[36]) + W[31] + s0(W[23]) + W[22];
    W[39] = s1(W[37]) + W[32] + s0(W[24]) + W[23];
    W[40] = s1(W[38]) + W[33] + s0(W[25]) + W[24];
    W[41] = s1(W[39]) + W[34] + s0(W[26]) + W[25];
    W[42] = s1(W[40]) + W[35] + s0(W[27]) + W[26];
    W[43] = s1(W[41]) + W[36] + s0(W[28]) + W[27];
    W[44] = s1(W[42]) + W[37] + s0(W[29]) + W[28];
    W[45] = s1(W[43]) + W[38] + s0(W[30]) + W[29];
    W[46] = s1(W[44]) + W[39] + s0(W[31]) + W[30];
    W[47] = s1(W[45]) + W[40] + s0(W[32]) + W[31];
    W[48] = s1(W[46]) + W[41] + s0(W[33]) + W[32];
    W[49] = s1(W[47]) + W[42] + s0(W[34]) + W[33];
    W[50] = s1(W[48]) + W[43] + s0(W[35]) + W[34];
    W[51] = s1(W[49]) + W[44] + s0(W[36]) + W[35];
    W[52] = s1(W[50]) + W[45] + s0(W[37]) + W[36];
    W[53] = s1(W[51]) + W[46] + s0(W[38]) + W[37];
    W[54] = s1(W[52]) + W[47] + s0(W[39]) + W[38];
    W[55] = s1(W[53]) + W[48] + s0(W[40]) + W[39];
    W[56] = s1(W[54]) + W[49] + s0(W[41]) + W[40];
    W[57] = s1(W[55]) + W[50] + s0(W[42]) + W[41];
    W[58] = s1(W[56]) + W[51] + s0(W[43]) + W[42];
    W[59] = s1(W[57]) + W[52] + s0(W[44]) + W[43];
    W[60] = s1(W[58]) + W[53] + s0(W[45]) + W[44];
    W[61] = s1(W[59]) + W[54] + s0(W[46]) + W[45];
    W[62] = s1(W[60]) + W[55] + s0(W[47]) + W[46];
    W[63] = s1(W[61]) + W[56] + s0(W[48]) + W[47];
    
    /* INITIALIZE WORKING VARIABLES */
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];
    
    /* UNROLLED COMPRESSION FUNCTION - 64 ROUNDS */
    #define ROUND(i) \
        h += S1(e) + Ch(e, f, g) + K256[i] + W[i]; \
        d += h; \
        h += S0(a) + Maj(a, b, c); \
        { uint32_t t = a; a = h; h = g; g = f; f = e; e = d; d = c; c = b; b = t; }
    
    ROUND(0);  ROUND(1);  ROUND(2);  ROUND(3);  ROUND(4);  ROUND(5);  ROUND(6);  ROUND(7);
    ROUND(8);  ROUND(9);  ROUND(10); ROUND(11); ROUND(12); ROUND(13); ROUND(14); ROUND(15);
    ROUND(16); ROUND(17); ROUND(18); ROUND(19); ROUND(20); ROUND(21); ROUND(22); ROUND(23);
    ROUND(24); ROUND(25); ROUND(26); ROUND(27); ROUND(28); ROUND(29); ROUND(30); ROUND(31);
    ROUND(32); ROUND(33); ROUND(34); ROUND(35); ROUND(36); ROUND(37); ROUND(38); ROUND(39);
    ROUND(40); ROUND(41); ROUND(42); ROUND(43); ROUND(44); ROUND(45); ROUND(46); ROUND(47);
    ROUND(48); ROUND(49); ROUND(50); ROUND(51); ROUND(52); ROUND(53); ROUND(54); ROUND(55);
    ROUND(56); ROUND(57); ROUND(58); ROUND(59); ROUND(60); ROUND(61); ROUND(62); ROUND(63);
    
    #undef ROUND
    
    /* UPDATE STATE */
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

/* ULTRA-FAST SHA256 INIT */
void ALWAYS_INLINE HOT SHA256_Init(SHA256_CTX *ctx) {
    ctx->count = 0;
    /* DIRECT COPY - NO FUNCTION CALL */
    ctx->state[0] = 0x6A09E667; ctx->state[1] = 0xBB67AE85;
    ctx->state[2] = 0x3C6EF372; ctx->state[3] = 0xA54FF53A;
    ctx->state[4] = 0x510E527F; ctx->state[5] = 0x9B05688C;
    ctx->state[6] = 0x1F83D9AB; ctx->state[7] = 0x5BE0CD19;
}

/* OPTIMIZED UPDATE - MINIMAL BRANCHING */
void ALWAYS_INLINE HOT SHA256_Update(SHA256_CTX *ctx, const void *in, size_t len) {
    const uint8_t *src = (const uint8_t *)in;
    size_t r = (ctx->count >> 3) & 0x3F;
    ctx->count += (uint64_t)len << 3;
    
    /* FAST PATH FOR FULL BLOCKS */
    if (r == 0 && len >= 64) {
        while (len >= 64) {
            sha256_transform(ctx->state, src);
            src += 64;
            len -= 64;
        }
        if (len == 0) return;
    }
    
    /* BUFFER REMAINING DATA */
    if (len < 64 - r) {
        memcpy(ctx->buf + r, src, len);
        return;
    }
    
    memcpy(ctx->buf + r, src, 64 - r);
    sha256_transform(ctx->state, ctx->buf);
    src += 64 - r;
    len -= 64 - r;
    
    while (len >= 64) {
        sha256_transform(ctx->state, src);
        src += 64;
        len -= 64;
    }
    
    if (len > 0) {
        memcpy(ctx->buf, src, len);
    }
}

/* ULTRA-FAST FINAL */
void ALWAYS_INLINE HOT SHA256_Final(uint8_t digest[32], SHA256_CTX *ctx) {
    uint8_t tmp[8];
    size_t r = (ctx->count >> 3) & 0x3F;
    
    /* OPTIMIZED PADDING */
    if (r < 56) {
        memcpy(ctx->buf + r, PAD, 56 - r);
    } else {
        memcpy(ctx->buf + r, PAD, 64 - r);
        sha256_transform(ctx->state, ctx->buf);
        memset(ctx->buf, 0, 56);
    }
    
    be64enc(tmp, ctx->count);
    memcpy(ctx->buf + 56, tmp, 8);
    sha256_transform(ctx->state, ctx->buf);
    
    /* DIRECT OUTPUT - NO LOOP */
    be32enc(digest +  0, ctx->state[0]);
    be32enc(digest +  4, ctx->state[1]);
    be32enc(digest +  8, ctx->state[2]);
    be32enc(digest + 12, ctx->state[3]);
    be32enc(digest + 16, ctx->state[4]);
    be32enc(digest + 20, ctx->state[5]);
    be32enc(digest + 24, ctx->state[6]);
    be32enc(digest + 28, ctx->state[7]);
    
    /* FAST MEMORY CLEAR */
    memset(ctx, 0, sizeof(SHA256_CTX));
}

/* SINGLE-SHOT HASHING */
void ALWAYS_INLINE HOT SHA256_Buf(const void *in, size_t len, uint8_t digest[32]) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, in, len);
    SHA256_Final(digest, &ctx);
}

/* ULTRA-FAST HMAC-SHA256 */
void ALWAYS_INLINE HOT HMAC_SHA256_Init(HMAC_SHA256_CTX *ctx, const void *key, size_t keylen) {
    uint8_t pad[64], khash[32];
    const uint8_t *K = (const uint8_t *)key;
    
    /* KEY PROCESSING */
    if (keylen > 64) {
        SHA256_Buf(K, keylen, khash);
        K = khash;
        keylen = 32;
    }
    
    /* INNER CONTEXT */
    SHA256_Init(&ctx->ictx);
    memset(pad, 0x36, 64);
    for (size_t i = 0; i < keylen; i++) pad[i] ^= K[i];
    SHA256_Update(&ctx->ictx, pad, 64);
    
    /* OUTER CONTEXT */
    SHA256_Init(&ctx->octx);
    memset(pad, 0x5c, 64);
    for (size_t i = 0; i < keylen; i++) pad[i] ^= K[i];
    SHA256_Update(&ctx->octx, pad, 64);
    
    /* CLEANUP */
    memset(khash, 0, 32);
    memset(pad, 0, 64);
}

void ALWAYS_INLINE HOT HMAC_SHA256_Update(HMAC_SHA256_CTX *ctx, const void *data, size_t len) {
    SHA256_Update(&ctx->ictx, data, len);
}

void ALWAYS_INLINE HOT HMAC_SHA256_Final(uint8_t digest[32], HMAC_SHA256_CTX *ctx) {
    uint8_t ihash[32];
    SHA256_Final(ihash, &ctx->ictx);
    SHA256_Update(&ctx->octx, ihash, 32);
    SHA256_Final(digest, &ctx->octx);
    memset(ihash, 0, 32);
}

void ALWAYS_INLINE HOT HMAC_SHA256_Buf(const void *key, size_t keylen, const void *data, size_t len, uint8_t digest[32]) {
    HMAC_SHA256_CTX ctx;
    HMAC_SHA256_Init(&ctx, key, keylen);
    HMAC_SHA256_Update(&ctx, data, len);
    HMAC_SHA256_Final(digest, &ctx);
}

/* OPTIMIZED PBKDF2 - MINIMAL ITERATIONS FOR MINING */
void ALWAYS_INLINE HOT PBKDF2_SHA256(const uint8_t *passwd, size_t passwdlen, 
                                   const uint8_t *salt, size_t saltlen, 
                                   uint64_t c, uint8_t *buf, size_t dkLen) {
    HMAC_SHA256_CTX Ph, PSh, hctx;
    uint8_t U[32], T[32], ivec[4];
    
    /* INITIALIZE CONTEXTS */
    HMAC_SHA256_Init(&Ph, passwd, passwdlen);
    memcpy(&PSh, &Ph, sizeof(Ph));
    HMAC_SHA256_Update(&PSh, salt, saltlen);
    
    /* DERIVE EACH BLOCK */
    for (size_t i = 0; i * 32 < dkLen; i++) {
        uint32_t j = i + 1;
        be32enc(ivec, j);
        
        /* FIRST ITERATION */
        memcpy(&hctx, &PSh, sizeof(hctx));
        HMAC_SHA256_Update(&hctx, ivec, 4);
        HMAC_SHA256_Final(U, &hctx);
        memcpy(T, U, 32);
        
        /* SUBSEQUENT ITERATIONS */
        for (uint64_t k = 2; k <= c; k++) {
            HMAC_SHA256_Init(&hctx, passwd, passwdlen);
            HMAC_SHA256_Update(&hctx, U, 32);
            HMAC_SHA256_Final(U, &hctx);
            for (int x = 0; x < 32; x++) T[x] ^= U[x];
        }
        
        /* OUTPUT */
        size_t r = dkLen - i * 32;
        if (r > 32) r = 32;
        memcpy(buf + i * 32, T, r);
    }
    
    /* FAST CLEANUP */
    memset(&Ph, 0, sizeof(Ph));
    memset(&PSh, 0, sizeof(PSh));
    memset(&hctx, 0, sizeof(hctx));
    memset(U, 0, 32);
    memset(T, 0, 32);
    memset(ivec, 0, 4);
}
