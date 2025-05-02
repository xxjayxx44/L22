/*
 * sha256.c - SHA-256 hash function
 * Part of the yespower project.
 */

#include <stdint.h>
#include <string.h>

#include "sha256.h"

#define Ch(x,y,z)    ((x & y) ^ (~x & z))
#define Maj(x,y,z)   ((x & y) ^ (x & z) ^ (y & z))
#define ROTR(x,n)    ((x >> n) | (x << (32 - n)))
#define SHR(x,n)     (x >> n)
#define S0(x)        (ROTR(x,7) ^ ROTR(x,18) ^ SHR(x,3))
#define S1(x)        (ROTR(x,17) ^ ROTR(x,19) ^ SHR(x,10))
#define S2(x)        (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define S3(x)        (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))

static const uint32_t K[64] = {
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

#define RNDr(S,W,i) do { \
    uint32_t t1 = S[7] + S3(S[4]) + Ch(S[4], S[5], S[6]) + K[i] + W[i]; \
    uint32_t t2 = S2(S[0]) + Maj(S[0], S[1], S[2]); \
    S[7] = S[6]; \
    S[6] = S[5]; \
    S[5] = S[4]; \
    S[4] = S[3] + t1; \
    S[3] = S[2]; \
    S[2] = S[1]; \
    S[1] = S[0]; \
    S[0] = t1 + t2; \
} while (0)

void SHA256_Transform(uint32_t *state, const uint8_t block[64]) {
    uint32_t W[64], S[8];
    int i;

    for (i = 0; i < 16; i++) {
        W[i] = (block[i * 4 + 0] << 24) |
               (block[i * 4 + 1] << 16) |
               (block[i * 4 + 2] <<  8) |
               (block[i * 4 + 3] <<  0);
    }

    for (i = 16; i < 64; i++) {
        W[i] = S1(W[i - 2]) + W[i - 7] + S0(W[i - 15]) + W[i - 16];
    }

    for (i = 0; i < 8; i++)
        S[i] = state[i];

    for (i = 0; i < 64; i++)
        RNDr(S, W, i);

    for (i = 0; i < 8; i++)
        state[i] += S[i];
}
