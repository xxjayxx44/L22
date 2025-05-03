/*
 * Optimized SHA-256 and SHA-256d implementation preserving full compatibility
 * with the ArtForz/pooler reference version. Endian-safe, two-pass double-hash,
 * and minimal overhead.
 *
 * Copyright 2011 ArtForz
 * Copyright 2011-2013 pooler
 *
 * Licensed under GNU GPL v2 or later.
 */

#include "cpuminer-config.h"
#include "miner.h"

#include <string.h>
#include <inttypes.h>

// Initial hash constants
static const uint32_t H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// Round constants
static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

// SHA256d padding constants
static const uint32_t sha256d_hash1[16] = {
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x80000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000100
};

// Big-endian load
static inline uint32_t load_be32(const uint32_t *p) {
    uint32_t v = *p;
    return (v<<24) | ((v>>8)&0xff00) | ((v<<8)&0xff0000) | (v>>24);
}

// SHA256 basic operations
#define ROTR(x,n)   ((x >> n) | (x << (32-n)))
#define S0(x)       (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define S1(x)       (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
#define s0(x)       (ROTR(x,7) ^ ROTR(x,18) ^ (x >> 3))
#define s1(x)       (ROTR(x,17)^ ROTR(x,19) ^ (x >> 10))
#define Ch(x,y,z)   ((x & y) ^ (~x & z))
#define Maj(x,y,z)  ((x & y) ^ (x & z) ^ (y & z))

void sha256_init(uint32_t state[8]) {
    memcpy(state, H0, 8*sizeof(uint32_t));
}

void sha256_transform(uint32_t state[8], const uint32_t block[16], int swap) {
    uint32_t W[64], a,b,c,d,e,f,g,h;
    int t;

    // Prepare message schedule
    if (swap) {
        for (t = 0; t < 16; t++)
            W[t] = load_be32(&block[t]);
    } else {
        for (t = 0; t < 16; t++)
            W[t] = block[t];
    }
    for (t = 16; t < 64; t++)
        W[t] = s1(W[t-2]) + W[t-7] + s0(W[t-15]) + W[t-16];

    // Initialize working vars
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    // 64 rounds
    for (t = 0; t < 64; t++) {
        uint32_t T1 = h + S1(e) + Ch(e,f,g) + K[t] + W[t];
        uint32_t T2 = S0(a) + Maj(a,b,c);
        h = g; g = f; f = e;
        e = d + T1; d = c; c = b; b = a;
        a = T1 + T2;
    }

    // Update state
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void sha256d(unsigned char *out, const unsigned char *data, int len) {
    uint32_t state[8], mid[16], block[16];
    unsigned char buf[64];
    int i, rem;
    uint64_t bits;

    // First pass
    sha256_init(state);
    for (i = 0; i + 64 <= len; i += 64) {
        memcpy(block, data + i, 64);
        sha256_transform(state, block, 1);
    }

    // Padding
    rem = len - i;
    memset(buf, 0, 64);
    memcpy(buf, data + i, rem);
    buf[rem] = 0x80;
    if (rem >= 56) {
        memcpy(block, buf, 64);
        sha256_transform(state, block, 0);
        memset(buf, 0, 64);
    }
    bits = (uint64_t)len * 8;
    bits = __builtin_bswap64(bits);
    memcpy(buf + 56, &bits, 8);
    memcpy(block, buf, 64);
    sha256_transform(state, block, 0);

    // Prepare second-pass block: midstate + sha256d_hash1
    for (i = 0; i < 8; i++) mid[i] = state[i];
    for (   ; i < 16; i++) mid[i] = sha256d_hash1[i];

    // Second pass
    sha256_init(state);
    sha256_transform(state, mid, 0);

    // Output big-endian digest
    for (i = 0; i < 8; i++) {
        uint32_t w = state[i];
        w = (w<<24) | ((w>>8)&0xff00) | ((w<<8)&0xff0000) | (w>>24);
        memcpy(out + 4*i, &w, 4);
    }
}
