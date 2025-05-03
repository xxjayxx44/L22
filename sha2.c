/*
 * Optimized SHA-256 implementation with SSE2-friendly data layout
 * and reduced function-call overhead.
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

static const uint32_t sha256_h0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
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

static inline uint32_t ROTR(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}
static inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}
static inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}
static inline uint32_t S0(uint32_t x) { return ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22); }
static inline uint32_t S1(uint32_t x) { return ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25); }
static inline uint32_t s0(uint32_t x) { return ROTR(x,7) ^ ROTR(x,18) ^ (x >> 3); }
static inline uint32_t s1(uint32_t x) { return ROTR(x,17) ^ ROTR(x,19) ^ (x >> 10); }

void sha256_init(uint32_t state[8]) {
    memcpy(state, sha256_h0, sizeof(sha256_h0));
}

void sha256_transform(uint32_t state[8], const uint32_t block[16], int swap) {
    uint32_t W[64];
    uint32_t a,b,c,d,e,f,g,h;
    int t;

    // Prepare message schedule
    if (swap) {
        for (t = 0; t < 16; t++) {
            uint32_t w = block[t];
            W[t] = ((w>>24)&0xff) | ((w>>8)&0xff00) | ((w<<8)&0xff0000) | ((w<<24)&0xff000000);
        }
    } else {
        memcpy(W, block, 16 * sizeof(uint32_t));
    }
    for (t = 16; t < 64; ++t) {
        W[t] = s1(W[t-2]) + W[t-7] + s0(W[t-15]) + W[t-16];
    }

    // Initialize working variables
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    // Compression loop
    for (t = 0; t < 64; ++t) {
        uint32_t T1 = h + S1(e) + Ch(e,f,g) + sha256_k[t] + W[t];
        uint32_t T2 = S0(a) + Maj(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    // Update state
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void sha256d(unsigned char hash[32], const unsigned char *data, int len) {
    uint32_t mid[8], state[8];
    uint32_t block[16];
    int i;

    // First pass
    sha256_init(state);
    // process full blocks
    for (i = 0; i + 64 <= len; i += 64) {
        memcpy(block, (const uint32_t*)(data + i), 64);
        sha256_transform(state, block, 1);
    }
    // padding
    unsigned char buf[64] = {0};
    int rem = len - i;
    memcpy(buf, data + i, rem);
    buf[rem] = 0x80;
    if (rem >= 56) {
        sha256_transform(state, (uint32_t*)buf, 0);
        memset(buf, 0, 64);
    }
    // append length
    uint64_t bits = (uint64_t)len * 8;
    *(uint64_t*)(buf + 56) = __builtin_bswap64(bits);
    sha256_transform(state, (uint32_t*)buf, 0);

    // store midstate
    memcpy(mid, state, 32);

    // Second pass
    sha256_init(state);
    sha256_transform(state, mid, 0);

    // output
    for (i = 0; i < 8; ++i) {
        uint32_t s = state[i];
        hash[i*4 + 0] = (s >> 24) & 0xff;
        hash[i*4 + 1] = (s >> 16) & 0xff;
        hash[i*4 + 2] = (s >>  8) & 0xff;
        hash[i*4 + 3] = (s >>  0) & 0xff;
    }
}
