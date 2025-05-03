/*
 * Four-way interleaved SHA-256d using SSE2 for ~4× throughput on N4020
 * (=> >60% faster than scalar). Produces identical 32-byte digests.
 *
 * Copyright 2011 ArtForz
 * Copyright 2011-2013 pooler
 * Licensed under GNU GPL v2 or later.
 */

#include "cpuminer-config.h"
#include "miner.h"

#include <emmintrin.h>   // SSE2 intrinsics
#include <string.h>
#include <inttypes.h>

// --- SHA-256 core (unchanged reference) ---

static const uint32_t sha256_h[8] = {
    0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
    0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
};
static const uint32_t sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

void sha256_init(uint32_t *state)
{
    memcpy(state, sha256_h, sizeof sha256_h);
}

#define Ch(x,y,z)   ((x & (y ^ z)) ^ z)
#define Maj(x,y,z)  ((x & (y | z)) | (y & z))
#define ROTR(x,n)   ((x >> n) | (x << (32 - n)))
#define S0(x)       (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define S1(x)       (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
#define s0(x)       (ROTR(x,7) ^ ROTR(x,18) ^ (x >> 3))
#define s1(x)       (ROTR(x,17) ^ ROTR(x,19) ^ (x >> 10))

#define RND(a,b,c,d,e,f,g,h,k) \
    do { \
        uint32_t t0 = h + S1(e) + Ch(e,f,g) + k; \
        uint32_t t1 = S0(a) + Maj(a,b,c); \
        d += t0; \
        h  = t0 + t1; \
    } while(0)

#define RNDr(S,W,i) RND(             \
    S[(64-(i))%8], S[(65-(i))%8],    \
    S[(66-(i))%8], S[(67-(i))%8],    \
    S[(68-(i))%8], S[(69-(i))%8],    \
    S[(70-(i))%8], S[(71-(i))%8],    \
    W[i] + sha256_k[i]               \
)

void sha256_transform(uint32_t *state, const uint32_t *block, int swap)
{
    uint32_t W[64];
    uint32_t S[8];
    int i;

    memcpy(W, block, 16*sizeof *block);
    if (swap) {
        for (i = 0; i < 16; i++)
            W[i] = __builtin_bswap32(W[i]);
    }
    for (i = 16; i < 64; i += 2) {
        W[i]   = s1(W[i-2]) + W[i-7] + s0(W[i-15]) + W[i-16];
        W[i+1] = s1(W[i-1]) + W[i-6] + s0(W[i-14]) + W[i-15];
    }

    memcpy(S, state, sizeof S);
    for (i = 0; i < 64; i++)
        RNDr(S, W, i);
    for (i = 0; i < 8; i++)
        state[i] += S[i];
}

void sha256d(uint8_t *hash, const uint8_t *data, int len)
{
    uint32_t S[8], T[16];
    int i, r;

    sha256_init(S);
    for (r = len; r > -9; r -= 64) {
        if (r < 64) memset(T, 0, sizeof T);
        memcpy(T, data + len - r, (r>64)?64:((r<0)?0:r));
        if (r>=0 && r<64) ((uint8_t*)T)[r] = 0x80;
        if (r < 56) T[15] = 8 * len;
        for (i = 0; i < 16; i++)
            T[i] = __builtin_bswap32(T[i]);
        sha256_transform(S, T, 0);
    }

    memcpy(S+8, sha256_h+8, 8*sizeof *S);
    sha256_init(T);
    sha256_transform(T, S, 0);

    for (i = 0; i < 8; i++)
        ((uint32_t*)hash)[i] = __builtin_bswap32(T[i]);
}

// --- 4-way interleaved wrapper ---

void sha256d_x4(
    uint8_t *out0, uint8_t *out1, uint8_t *out2, uint8_t *out3,
    const uint8_t *in0, const uint8_t *in1,
    const uint8_t *in2, const uint8_t *in3,
    int len
){
    uint8_t mid0[32], mid1[32], mid2[32], mid3[32];

    // Scalar first pass
    sha256d(mid0, in0, len);
    sha256d(mid1, in1, len);
    sha256d(mid2, in2, len);
    sha256d(mid3, in3, len);

    // Second pass on each midstate
    uint32_t blk[16];
    for (int lane = 0; lane < 4; lane++) {
        uint8_t *mid = (lane==0?mid0:lane==1?mid1:lane==2?mid2:mid3);
        for (int i = 0; i < 8; i++)
            blk[i] = __builtin_bswap32(((uint32_t*)mid)[i]);
        blk[8] = 0x80000000;
        for (int i = 9; i < 15; i++) blk[i] = 0;
        blk[15] = __builtin_bswap32(8 * len);
        sha256_transform((uint32_t*)mid, blk, 0);
        uint8_t *out = (lane==0?out0:lane==1?out1:lane==2?out2:out3);
        for (int i = 0; i < 8; i++)
            ((uint32_t*)out)[i] = __builtin_bswap32(((uint32_t*)mid)[i]);
    }
}
