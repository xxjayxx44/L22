/*
 * ULTRA-OPTIMIZED SHA256 FOR MAXIMUM MINING PERFORMANCE
 * HEAVILY OPTIMIZED FOR YESPOWER MINING WORKLOADS
 */

#include "cpuminer-config.h"
#include "miner.h"

#include <string.h>
#include <inttypes.h>

/* COMPILER OPTIMIZATIONS */
#ifdef __GNUC__
#define ALWAYS_INLINE __attribute__((always_inline))
#define HOT __attribute__((hot))
#define COLD __attribute__((cold))
#define PACKED __attribute__((packed))
#else
#define ALWAYS_INLINE
#define HOT
#define COLD
#define PACKED
#endif

/* ULTRA-FAST CONSTANTS - CACHE ALIGNED */
static const uint32_t SHA256_H0[8] __attribute__((aligned(32))) = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

static const uint32_t SHA256_K[64] __attribute__((aligned(64))) = {
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

/* ULTRA-FAST ROTATE - NO FUNCTION CALL OVERHEAD */
#define ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

/* OPTIMIZED SHA-256 FUNCTIONS - PRE-COMPUTED FORMS */
#define CH(x,y,z)   (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIG0(x)     (ROTR(x, 2)  ^ ROTR(x,13) ^ ROTR(x,22))
#define SIG1(x)     (ROTR(x, 6)  ^ ROTR(x,11) ^ ROTR(x,25))
#define sig0(x)     (ROTR(x, 7)  ^ ROTR(x,18) ^ ((x) >> 3))
#define sig1(x)     (ROTR(x,17)  ^ ROTR(x,19) ^ ((x) >> 10))

/* ULTRA-FAST SHA256 COMPRESSION - FULLY UNROLLED */
static ALWAYS_INLINE HOT void 
sha256_compress(uint32_t state[8], const uint32_t M[16]) {
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h;
    
    /* UNROLLED MESSAGE SCHEDULE - 16 WORDS */
    W[0]  = M[0];  W[1]  = M[1];  W[2]  = M[2];  W[3]  = M[3];
    W[4]  = M[4];  W[5]  = M[5];  W[6]  = M[6];  W[7]  = M[7];
    W[8]  = M[8];  W[9]  = M[9];  W[10] = M[10]; W[11] = M[11];
    W[12] = M[12]; W[13] = M[13]; W[14] = M[14]; W[15] = M[15];
    
    /* UNROLLED MESSAGE EXPANSION - 48 WORDS */
    W[16] = sig1(W[14]) + W[9]  + sig0(W[1]) + W[0];
    W[17] = sig1(W[15]) + W[10] + sig0(W[2]) + W[1];
    W[18] = sig1(W[16]) + W[11] + sig0(W[3]) + W[2];
    W[19] = sig1(W[17]) + W[12] + sig0(W[4]) + W[3];
    W[20] = sig1(W[18]) + W[13] + sig0(W[5]) + W[4];
    W[21] = sig1(W[19]) + W[14] + sig0(W[6]) + W[5];
    W[22] = sig1(W[20]) + W[15] + sig0(W[7]) + W[6];
    W[23] = sig1(W[21]) + W[16] + sig0(W[8]) + W[7];
    W[24] = sig1(W[22]) + W[17] + sig0(W[9]) + W[8];
    W[25] = sig1(W[23]) + W[18] + sig0(W[10]) + W[9];
    W[26] = sig1(W[24]) + W[19] + sig0(W[11]) + W[10];
    W[27] = sig1(W[25]) + W[20] + sig0(W[12]) + W[11];
    W[28] = sig1(W[26]) + W[21] + sig0(W[13]) + W[12];
    W[29] = sig1(W[27]) + W[22] + sig0(W[14]) + W[13];
    W[30] = sig1(W[28]) + W[23] + sig0(W[15]) + W[14];
    W[31] = sig1(W[29]) + W[24] + sig0(W[16]) + W[15];
    W[32] = sig1(W[30]) + W[25] + sig0(W[17]) + W[16];
    W[33] = sig1(W[31]) + W[26] + sig0(W[18]) + W[17];
    W[34] = sig1(W[32]) + W[27] + sig0(W[19]) + W[18];
    W[35] = sig1(W[33]) + W[28] + sig0(W[20]) + W[19];
    W[36] = sig1(W[34]) + W[29] + sig0(W[21]) + W[20];
    W[37] = sig1(W[35]) + W[30] + sig0(W[22]) + W[21];
    W[38] = sig1(W[36]) + W[31] + sig0(W[23]) + W[22];
    W[39] = sig1(W[37]) + W[32] + sig0(W[24]) + W[23];
    W[40] = sig1(W[38]) + W[33] + sig0(W[25]) + W[24];
    W[41] = sig1(W[39]) + W[34] + sig0(W[26]) + W[25];
    W[42] = sig1(W[40]) + W[35] + sig0(W[27]) + W[26];
    W[43] = sig1(W[41]) + W[36] + sig0(W[28]) + W[27];
    W[44] = sig1(W[42]) + W[37] + sig0(W[29]) + W[28];
    W[45] = sig1(W[43]) + W[38] + sig0(W[30]) + W[29];
    W[46] = sig1(W[44]) + W[39] + sig0(W[31]) + W[30];
    W[47] = sig1(W[45]) + W[40] + sig0(W[32]) + W[31];
    W[48] = sig1(W[46]) + W[41] + sig0(W[33]) + W[32];
    W[49] = sig1(W[47]) + W[42] + sig0(W[34]) + W[33];
    W[50] = sig1(W[48]) + W[43] + sig0(W[35]) + W[34];
    W[51] = sig1(W[49]) + W[44] + sig0(W[36]) + W[35];
    W[52] = sig1(W[50]) + W[45] + sig0(W[37]) + W[36];
    W[53] = sig1(W[51]) + W[46] + sig0(W[38]) + W[37];
    W[54] = sig1(W[52]) + W[47] + sig0(W[39]) + W[38];
    W[55] = sig1(W[53]) + W[48] + sig0(W[40]) + W[39];
    W[56] = sig1(W[54]) + W[49] + sig0(W[41]) + W[40];
    W[57] = sig1(W[55]) + W[50] + sig0(W[42]) + W[41];
    W[58] = sig1(W[56]) + W[51] + sig0(W[43]) + W[42];
    W[59] = sig1(W[57]) + W[52] + sig0(W[44]) + W[43];
    W[60] = sig1(W[58]) + W[53] + sig0(W[45]) + W[44];
    W[61] = sig1(W[59]) + W[54] + sig0(W[46]) + W[45];
    W[62] = sig1(W[60]) + W[55] + sig0(W[47]) + W[46];
    W[63] = sig1(W[61]) + W[56] + sig0(W[48]) + W[47];
    
    /* INITIALIZE WORKING VARIABLES */
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];
    
    /* FULLY UNROLLED COMPRESSION - 64 ROUNDS */
    #define ROUND(i, a, b, c, d, e, f, g, h) \
        uint32_t t1 = h + SIG1(e) + CH(e, f, g) + SHA256_K[i] + W[i]; \
        uint32_t t2 = SIG0(a) + MAJ(a, b, c); \
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    
    ROUND(0, a, b, c, d, e, f, g, h); ROUND(1, a, b, c, d, e, f, g, h);
    ROUND(2, a, b, c, d, e, f, g, h); ROUND(3, a, b, c, d, e, f, g, h);
    ROUND(4, a, b, c, d, e, f, g, h); ROUND(5, a, b, c, d, e, f, g, h);
    ROUND(6, a, b, c, d, e, f, g, h); ROUND(7, a, b, c, d, e, f, g, h);
    ROUND(8, a, b, c, d, e, f, g, h); ROUND(9, a, b, c, d, e, f, g, h);
    ROUND(10, a, b, c, d, e, f, g, h); ROUND(11, a, b, c, d, e, f, g, h);
    ROUND(12, a, b, c, d, e, f, g, h); ROUND(13, a, b, c, d, e, f, g, h);
    ROUND(14, a, b, c, d, e, f, g, h); ROUND(15, a, b, c, d, e, f, g, h);
    ROUND(16, a, b, c, d, e, f, g, h); ROUND(17, a, b, c, d, e, f, g, h);
    ROUND(18, a, b, c, d, e, f, g, h); ROUND(19, a, b, c, d, e, f, g, h);
    ROUND(20, a, b, c, d, e, f, g, h); ROUND(21, a, b, c, d, e, f, g, h);
    ROUND(22, a, b, c, d, e, f, g, h); ROUND(23, a, b, c, d, e, f, g, h);
    ROUND(24, a, b, c, d, e, f, g, h); ROUND(25, a, b, c, d, e, f, g, h);
    ROUND(26, a, b, c, d, e, f, g, h); ROUND(27, a, b, c, d, e, f, g, h);
    ROUND(28, a, b, c, d, e, f, g, h); ROUND(29, a, b, c, d, e, f, g, h);
    ROUND(30, a, b, c, d, e, f, g, h); ROUND(31, a, b, c, d, e, f, g, h);
    ROUND(32, a, b, c, d, e, f, g, h); ROUND(33, a, b, c, d, e, f, g, h);
    ROUND(34, a, b, c, d, e, f, g, h); ROUND(35, a, b, c, d, e, f, g, h);
    ROUND(36, a, b, c, d, e, f, g, h); ROUND(37, a, b, c, d, e, f, g, h);
    ROUND(38, a, b, c, d, e, f, g, h); ROUND(39, a, b, c, d, e, f, g, h);
    ROUND(40, a, b, c, d, e, f, g, h); ROUND(41, a, b, c, d, e, f, g, h);
    ROUND(42, a, b, c, d, e, f, g, h); ROUND(43, a, b, c, d, e, f, g, h);
    ROUND(44, a, b, c, d, e, f, g, h); ROUND(45, a, b, c, d, e, f, g, h);
    ROUND(46, a, b, c, d, e, f, g, h); ROUND(47, a, b, c, d, e, f, g, h);
    ROUND(48, a, b, c, d, e, f, g, h); ROUND(49, a, b, c, d, e, f, g, h);
    ROUND(50, a, b, c, d, e, f, g, h); ROUND(51, a, b, c, d, e, f, g, h);
    ROUND(52, a, b, c, d, e, f, g, h); ROUND(53, a, b, c, d, e, f, g, h);
    ROUND(54, a, b, c, d, e, f, g, h); ROUND(55, a, b, c, d, e, f, g, h);
    ROUND(56, a, b, c, d, e, f, g, h); ROUND(57, a, b, c, d, e, f, g, h);
    ROUND(58, a, b, c, d, e, f, g, h); ROUND(59, a, b, c, d, e, f, g, h);
    ROUND(60, a, b, c, d, e, f, g, h); ROUND(61, a, b, c, d, e, f, g, h);
    ROUND(62, a, b, c, d, e, f, g, h); ROUND(63, a, b, c, d, e, f, g, h);
    
    #undef ROUND
    
    /* UPDATE STATE */
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

/* ULTRA-FAST SHA256 INIT - DIRECT ASSIGNMENT */
static ALWAYS_INLINE HOT void 
sha256_init(uint32_t state[8]) {
    state[0] = SHA256_H0[0]; state[1] = SHA256_H0[1];
    state[2] = SHA256_H0[2]; state[3] = SHA256_H0[3];
    state[4] = SHA256_H0[4]; state[5] = SHA256_H0[5];
    state[6] = SHA256_H0[6]; state[7] = SHA256_H0[7];
}

/* OPTIMIZED TRANSFORM - MINIMAL BRANCHING */
static ALWAYS_INLINE HOT void 
sha256_transform(uint32_t state[8], const uint32_t block[16], int swap) {
    uint32_t M[16];
    
    if (swap) {
        /* UNROLLED BYTE SWAP */
        M[0]  = __builtin_bswap32(block[0]);  M[1]  = __builtin_bswap32(block[1]);
        M[2]  = __builtin_bswap32(block[2]);  M[3]  = __builtin_bswap32(block[3]);
        M[4]  = __builtin_bswap32(block[4]);  M[5]  = __builtin_bswap32(block[5]);
        M[6]  = __builtin_bswap32(block[6]);  M[7]  = __builtin_bswap32(block[7]);
        M[8]  = __builtin_bswap32(block[8]);  M[9]  = __builtin_bswap32(block[9]);
        M[10] = __builtin_bswap32(block[10]); M[11] = __builtin_bswap32(block[11]);
        M[12] = __builtin_bswap32(block[12]); M[13] = __builtin_bswap32(block[13]);
        M[14] = __builtin_bswap32(block[14]); M[15] = __builtin_bswap32(block[15]);
    } else {
        /* DIRECT COPY */
        M[0] = block[0];  M[1] = block[1];  M[2] = block[2];  M[3] = block[3];
        M[4] = block[4];  M[5] = block[5];  M[6] = block[6];  M[7] = block[7];
        M[8] = block[8];  M[9] = block[9];  M[10] = block[10]; M[11] = block[11];
        M[12] = block[12]; M[13] = block[13]; M[14] = block[14]; M[15] = block[15];
    }
    
    sha256_compress(state, M);
}

/* ULTRA-FAST ONE-SHOT SHA256 - OPTIMIZED FOR MINING */
void ALWAYS_INLINE HOT 
sha256(const unsigned char *data, size_t len, unsigned char out32[32]) {
    uint32_t state[8];
    size_t full_blocks = len / 64;
    const unsigned char *ptr = data;
    
    sha256_init(state);
    
    /* PROCESS FULL BLOCKS */
    while (full_blocks--) {
        uint32_t M[16];
        /* UNROLLED BIG-ENDIAN DECODE */
        M[0]  = be32dec(ptr +  0); M[1]  = be32dec(ptr +  4);
        M[2]  = be32dec(ptr +  8); M[3]  = be32dec(ptr + 12);
        M[4]  = be32dec(ptr + 16); M[5]  = be32dec(ptr + 20);
        M[6]  = be32dec(ptr + 24); M[7]  = be32dec(ptr + 28);
        M[8]  = be32dec(ptr + 32); M[9]  = be32dec(ptr + 36);
        M[10] = be32dec(ptr + 40); M[11] = be32dec(ptr + 44);
        M[12] = be32dec(ptr + 48); M[13] = be32dec(ptr + 52);
        M[14] = be32dec(ptr + 56); M[15] = be32dec(ptr + 60);
        
        sha256_compress(state, M);
        ptr += 64;
    }
    
    /* FINAL BLOCK */
    size_t remaining = len - (ptr - data);
    unsigned char block[64] = {0};
    
    if (remaining > 0) {
        memcpy(block, ptr, remaining);
    }
    block[remaining] = 0x80;
    
    /* HANDLE LENGTH */
    if (remaining >= 56) {
        uint32_t M[16];
        for (int i = 0; i < 16; i++) M[i] = be32dec(block + i * 4);
        sha256_compress(state, M);
        memset(block, 0, 56);
    }
    
    /* APPEND BIT LENGTH */
    uint64_t bitlen = (uint64_t)len << 3;
    for (int i = 0; i < 8; i++) {
        block[63 - i] = (unsigned char)(bitlen >> (i * 8));
    }
    
    /* FINAL COMPRESSION */
    uint32_t M[16];
    for (int i = 0; i < 16; i++) M[i] = be32dec(block + i * 4);
    sha256_compress(state, M);
    
    /* OUTPUT - UNROLLED */
    be32enc(out32 +  0, state[0]); be32enc(out32 +  4, state[1]);
    be32enc(out32 +  8, state[2]); be32enc(out32 + 12, state[3]);
    be32enc(out32 + 16, state[4]); be32enc(out32 + 20, state[5]);
    be32enc(out32 + 24, state[6]); be32enc(out32 + 28, state[7]);
}

/* ULTRA-FAST DOUBLE SHA256 - OPTIMIZED FOR MINING */
void ALWAYS_INLINE HOT 
sha256d(unsigned char *hash, const unsigned char *data, int len) {
    unsigned char tmp[32];
    sha256(data, (size_t)len, tmp);
    sha256(tmp, 32, hash);
}

/* MINING-SPECIFIC OPTIMIZATIONS */

/* FAST SHA256 FOR 80-BYTE MINING BLOCKS */
void ALWAYS_INLINE HOT 
sha256_80(const unsigned char data[80], unsigned char out32[32]) {
    uint32_t state[8];
    uint32_t M[16];
    
    sha256_init(state);
    
    /* FIRST BLOCK - 64 BYTES */
    M[0]  = be32dec(data +  0); M[1]  = be32dec(data +  4);
    M[2]  = be32dec(data +  8); M[3]  = be32dec(data + 12);
    M[4]  = be32dec(data + 16); M[5]  = be32dec(data + 20);
    M[6]  = be32dec(data + 24); M[7]  = be32dec(data + 28);
    M[8]  = be32dec(data + 32); M[9]  = be32dec(data + 36);
    M[10] = be32dec(data + 40); M[11] = be32dec(data + 44);
    M[12] = be32dec(data + 48); M[13] = be32dec(data + 52);
    M[14] = be32dec(data + 56); M[15] = be32dec(data + 60);
    sha256_compress(state, M);
    
    /* SECOND BLOCK - 16 BYTES + PADDING */
    M[0]  = be32dec(data + 64); M[1]  = be32dec(data + 68);
    M[2]  = be32dec(data + 72); M[3]  = be32dec(data + 76);
    M[4]  = 0x80000000;        M[5]  = 0; M[6]  = 0; M[7]  = 0;
    M[8]  = 0; M[9]  = 0; M[10] = 0; M[11] = 0;
    M[12] = 0; M[13] = 0; M[14] = 0; M[15] = 640; /* 80*8 = 640 bits */
    sha256_compress(state, M);
    
    /* OUTPUT */
    be32enc(out32 +  0, state[0]); be32enc(out32 +  4, state[1]);
    be32enc(out32 +  8, state[2]); be32enc(out32 + 12, state[3]);
    be32enc(out32 + 16, state[4]); be32enc(out32 + 20, state[5]);
    be32enc(out32 + 24, state[6]); be32enc(out32 + 28, state[7]);
}

/* BATCH PROCESSING FOR MULTIPLE NONCES */
void ALWAYS_INLINE HOT 
sha256d_batch4(unsigned char hashes[4][32], const unsigned char *base_data, 
               const uint32_t nonces[4], int data_len) {
    unsigned char blocks[4][128]; /* Enough for 80-byte data + nonce */
    
    /* PREPARE BLOCKS */
    for (int i = 0; i < 4; i++) {
        memcpy(blocks[i], base_data, data_len - 4);
        be32enc(blocks[i] + data_len - 4, nonces[i]);
    }
    
    /* PROCESS IN BATCH */
    for (int i = 0; i < 4; i++) {
        sha256d(hashes[i], blocks[i], data_len);
    }
}
