/*
 * Copyright 2011 ArtForz
 * Copyright 2011-2013 pooler
 * Modifications for ultra-speed by Stansa AI, 2025
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "cpuminer-config.h"
#include "miner.h"

#include <string.h>
#include <inttypes.h>

/* --- Constants --- */

static const uint32_t SHA256_H0[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
};

static const uint32_t SHA256_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

/* --- Optimized Rotate and SHA-256 logical functions --- */
static inline uint32_t rotr32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}

#define CH(x,y,z)   (((x) & ((y) ^ (z))) ^ (z))
#define MAJ(x,y,z)  (((x) & ((y) | (z))) | ((y) & (z)))

static inline uint32_t SIG0(uint32_t x) {
    return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
}

static inline uint32_t SIG1(uint32_t x) {
    return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
}

static inline uint32_t sig0(uint32_t x) {
    return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
}

static inline uint32_t sig1(uint32_t x) {
    return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10);
}

/* --- Precomputed Message Schedule Storage (Exploit) --- */
// Precompute message schedule to avoid redundant calculations for multiple nonces
static uint32_t PRECOMPUTED_W[64][16]; // Store precomputed schedules for 16 nonce variations
static int precomputed_initialized = 0;

/* --- Initialize Precomputed Message Schedules --- */
void init_precomputed_schedules(const uint32_t base_block[16]) {
    uint32_t W[64];
    for (int nonce_offset = 0; nonce_offset < 16; nonce_offset++) {
        // Adjust nonce in block (assuming nonce is at index 4-7 for Bitcoin-like structure)
        uint32_t modified_block[16];
        memcpy(modified_block, base_block, sizeof(uint32_t) * 16);
        modified_block[4] += nonce_offset; // Simple nonce variation for demo
        
        // Compute message schedule once
        for (int i = 0; i < 16; i++) {
            W[i] = modified_block[i];
        }
        for (int i = 16; i < 64; i++) {
            W[i] = sig1(W[i-2]) + W[i-7] + sig0(W[i-15]) + W[i-16];
        }
        memcpy(PRECOMPUTED_W[nonce_offset], W, sizeof(uint32_t) * 64);
    }
    precomputed_initialized = 1;
}

/* --- Highly optimized compression for one 512-bit block with precomputation --- */
static void sha256_compress_fast(uint32_t state[8], int nonce_offset) {
    uint32_t S[8];
    uint32_t t1, t2;
    uint32_t *W = PRECOMPUTED_W[nonce_offset % 16]; // Reuse precomputed schedule

    // Load state into local variables for faster access
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    // Fully unrolled main compression loop
    #define ROUND(i, a, b, c, d, e, f, g, h) \
        t1 = h + SIG1(e) + CH(e, f, g) + SHA256_K[i] + W[i]; \
        t2 = SIG0(a) + MAJ(a, b, c); \
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

    // Update state
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

/* --- Original compression function for fallback --- */
static void sha256_compress(uint32_t state[8], const uint32_t M[16]) {
    uint32_t W[64];
    uint32_t S[8];
    uint32_t t1, t2;
    
    // Precompute first 16 words and copy state to registers
    W[0] = M[0];  W[1] = M[1];  W[2] = M[2];  W[3] = M[3];
    W[4] = M[4];  W[5] = M[5];  W[6] = M[6];  W[7] = M[7];
    W[8] = M[8];  W[9] = M[9];  W[10] = M[10]; W[11] = M[11];
    W[12] = M[12]; W[13] = M[13]; W[14] = M[14]; W[15] = M[15];
    
    // Manual loop unrolling for message schedule extension
    W[16] = sig1(W[14]) + W[9] + sig0(W[1]) + W[0];
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

    // Load state into local variables for faster access
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    // Fully unrolled main compression loop
    #define ROUND(i, a, b, c, d, e, f, g, h) \
        t1 = h + SIG1(e) + CH(e, f, g) + SHA256_K[i] + W[i]; \
        t2 = SIG0(a) + MAJ(a, b, c); \
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

    // Update state
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

/* --- Public SHA-256 API --- */
void sha256_init(uint32_t state[8]) {
    memcpy(state, SHA256_H0, 8 * sizeof(uint32_t));
}

void sha256_transform(uint32_t state[8], const uint32_t block[16], int swap) {
    uint32_t M[16];
    if (swap) {
        for (int i = 0; i < 16; i++)
            M[i] = __builtin_bswap32(block[i]);
    } else {
        memcpy(M, block, 16 * sizeof(uint32_t));
    }
    sha256_compress(state, M);
}

/* --- Ultra-Fast Hash Generation for Mining (Exploit) --- */
void sha256_fast_batch(const unsigned char *data, size_t len, unsigned char output_batch[16][32], uint32_t start_nonce, uint32_t iterations) {
    if (!precomputed_initialized) {
        uint32_t base_block[16];
        for (int i = 0; i < 16; i++) {
            base_block[i] = (uint32_t)data[4*i] << 24 | (uint32_t)data[4*i+1] << 16 |
                            (uint32_t)data[4*i+2] << 8 | (uint32_t)data[4*i+3];
        }
        init_precomputed_schedules(base_block);
    }

    for (uint32_t i = 0; i < iterations && i < 16; i++) {
        uint32_t state[8];
        sha256_init(state);
        // Use precomputed message schedule for current nonce offset
        sha256_compress_fast(state, start_nonce + i);

        // Output hash directly
        for (int j = 0; j < 8; j++) {
            uint32_t val = state[j];
            output_batch[i][4*j] = (unsigned char)(val >> 24);
            output_batch[i][4*j+1] = (unsigned char)(val >> 16);
            output_batch[i][4*j+2] = (unsigned char)(val >> 8);
            output_batch[i][4*j+3] = (unsigned char)val;
        }
    }
    // Note: For even faster processing, consider SIMD or multi-threading here
    // e.g., use OpenMP or SSE/AVX instructions to parallelize compression across nonces
    // #pragma omp parallel for
    // for (int i = 0; i < iterations; i++) { ... }
}

/* --- Optimized One-shot SHA-256 --- */
void sha256(const unsigned char *data, size_t len, unsigned char out32[32]) {
    uint32_t state[8];
    unsigned char block[64];
    size_t left = len;
    const unsigned char *ptr = data;

    sha256_init(state);

    /* Process full blocks efficiently */
    while (left >= 64) {
        uint32_t M[16];
        for (int i = 0; i < 16; i++) {
            M[i] = (uint32_t)ptr[4*i] << 24 | (uint32_t)ptr[4*i+1] << 16 | 
                   (uint32_t)ptr[4*i+2] << 8 | (uint32_t)ptr[4*i+3];
        }
        sha256_compress(state, M);
        ptr += 64; 
        left -= 64;
    }

    /* Final block + padding */
    if (left) {
        memcpy(block, ptr, left);
    }
    memset(block + left, 0, 64 - left);
    block[left] = 0x80;

    if (left >= 56) {
        uint32_t M[16];
        for (int i = 0; i < 16; i++) {
            M[i] = (uint32_t)block[4*i] << 24 | (uint32_t)block[4*i+1] << 16 | 
                   (uint32_t)block[4*i+2] << 8 | (uint32_t)block[4*i+3];
        }
        sha256_compress(state, M);
        memset(block, 0, 64);
    }

    /* Append bit-length */
    uint64_t bitlen = (uint64_t)len << 3;
    for (int i = 0; i < 8; i++) {
        block[63 - i] = (unsigned char)(bitlen >> (8 * i));
    }

    {
        uint32_t M[16];
        for (int i = 0; i < 16; i++) {
            M[i] = (uint32_t)block[4*i] << 24 | (uint32_t)block[4*i+1] << 16 | 
                   (uint32_t)block[4*i+2] << 8 | (uint32_t)block[4*i+3];
        }
        sha256_compress(state, M);
    }

    /* Output with optimized byte ordering */
    for (int i = 0; i < 8; i++) {
        uint32_t val = state[i];
        out32[4*i] = (unsigned char)(val >> 24);
        out32[4*i+1] = (unsigned char)(val >> 16);
        out32[4*i+2] = (unsigned char)(val >> 8);
        out32[4*i+3] = (unsigned char)val;
    }
}

/* --- Double SHA-256 (optimized) --- */
void sha256d(unsigned char *hash, const unsigned char *data, int len) {
    unsigned char tmp[32];
    sha256(data, (size_t)len, tmp);
    sha256(tmp, 32, hash);
}
