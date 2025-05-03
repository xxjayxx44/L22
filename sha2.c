/*
 * Copyright 2011 ArtForz
 * Copyright 2011-2013 pooler
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

/* Initial vector for second round of double-SHA256 */
static const uint32_t SHA256D_IV2[8] = {
    0x00000000u, 0x00000000u, 0x80000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000100u
};

/* --- Endianness helpers --- */
static inline uint32_t rotr32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}

static inline uint32_t be32dec(const uint8_t *p) {
    return ((uint32_t)p[0] << 24)
         | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)
         |  (uint32_t)p[3];
}

static inline void be32enc(uint8_t *p, uint32_t x) {
    p[0] = (uint8_t)(x >> 24);
    p[1] = (uint8_t)(x >> 16);
    p[2] = (uint8_t)(x >> 8);
    p[3] = (uint8_t)(x);
}

/* --- SHA-256 logical functions --- */
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

/* --- Core compression for one 512-bit block --- */
static void sha256_compress(uint32_t state[8], const uint32_t M[16]) {
    uint32_t W[64], S[8], t1, t2;
    int i;

    /* 1. Prepare message schedule */
    for (i = 0; i < 16; i++)
        W[i] = M[i];
    for (i = 16; i < 64; i++)
        W[i] = sig1(W[i - 2]) + W[i - 7]
             + sig0(W[i - 15]) + W[i - 16];

    /* 2. Init working vars */
    for (i = 0; i < 8; i++)
        S[i] = state[i];

    /* 3. 64 rounds */
    for (i = 0; i < 64; i++) {
        t1 = S[7] + SIG1(S[4]) + CH(S[4], S[5], S[6])
           + SHA256_K[i] + W[i];
        t2 = SIG0(S[0]) + MAJ(S[0], S[1], S[2]);
        S[7] = S[6];
        S[6] = S[5];
        S[5] = S[4];
        S[4] = S[3] + t1;
        S[3] = S[2];
        S[2] = S[1];
        S[1] = S[0];
        S[0] = t1 + t2;
    }

    /* 4. Fold back into state */
    for (i = 0; i < 8; i++)
        state[i] += S[i];
}

/* --- Public SHA-256 API --- */
void sha256_init(uint32_t state[8]) {
    memcpy(state, SHA256_H0, 8 * sizeof(uint32_t));
}

/**
 * Transform one 512-bit block.
 * @param state   current hash state (8 words)
 * @param block   16 big-endian 32-bit words (if swap==1, bytes are swapped)
 * @param swap    if non-zero, bytes of each word in block[] are swapped
 */
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

/* --- Single-pass SHA-256 for arbitrary data --- */
void sha256(const uint8_t *data, size_t len, uint8_t out32[32]) {
    uint32_t state[8];
    uint8_t block[64];
    size_t left = len;
    const uint8_t *ptr = data;

    sha256_init(state);

    while (left >= 64) {
        uint32_t M[16];
        for (int i = 0; i < 16; i++)
            M[i] = be32dec(ptr + 4*i);
        sha256_compress(state, M);
        ptr += 64;
        left -= 64;
    }

    /* Copy remainder and append 0x80 */
    memset(block, 0, 64);
    if (left > 0) memcpy(block, ptr, left);
    block[left] = 0x80;

    /* If not enough room for length, process this block and clear it */
    if (left >= 56) {
        uint32_t M[16];
        for (int i = 0; i < 16; i++)
            M[i] = be32dec(block + 4*i);
        sha256_compress(state, M);
        memset(block, 0, 64);
    }

    /* Append length in bits */
    uint64_t bitlen = (uint64_t)len << 3;
    for (int i = 0; i < 8; i++)
        block[63 - i] = (uint8_t)(bitlen >> (8 * i));

    {
        uint32_t M[16];
        for (int i = 0; i < 16; i++)
            M[i] = be32dec(block + 4*i);
        sha256_compress(state, M);
    }

    /* Output hash */
    for (int i = 0; i < 8; i++)
        be32enc(out32 + 4*i, state[i]);
}

/* --- Double SHA-256 (SHA-256d) --- */
void sha256d(const uint8_t *msg, size_t len, uint8_t out32[32]) {
    uint8_t inner[32];
    /* 1. Single SHA-256 */
    sha256(msg, len, inner);
    /* 2. Second SHA-256 */
    sha256(inner, 32, out32);
}
