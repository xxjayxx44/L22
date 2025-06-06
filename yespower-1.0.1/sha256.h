/* yespower-1.0.1/sha256.c – Optimized for high-throughput mining
 * Complete FIXED Implementation with HMAC and PBKDF2
 *
 * This file replaces the original sha256.c in L22. All public functions
 * retain their original signatures and are defined exactly once. No
 * duplicate or conflicting definitions are present.
 */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "sysendian.h"
#include "insecure_memzero.h"
#include "sha256.h"

#ifdef __ICC
  #define restrict
#elif __STDC_VERSION__ >= 199901L
  /* C99 has restrict */
#elif defined(__GNUC__)
  #define restrict __restrict
#else
  #define restrict
#endif

/* Rotate and shift */
#define ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHR(x,n)  ((x) >> (n))

/* SHA-256 functions */
#define Ch(x,y,z)  (((x) & ((y) ^ (z))) ^ (z))
#define Maj(x,y,z) (((x) & ((y) | (z))) | ((y) & (z)))
#define S0(x)      (ROTR(x, 2)  ^ ROTR(x,13) ^ ROTR(x,22))
#define S1(x)      (ROTR(x, 6)  ^ ROTR(x,11) ^ ROTR(x,25))
#define s0(x)      (ROTR(x, 7)  ^ ROTR(x,18) ^ SHR(x, 3))
#define s1(x)      (ROTR(x,17)  ^ ROTR(x,19) ^ SHR(x,10))

/* SHA-256 round constants */
static const uint32_t K256[64] = {
    0x428a2f98UL,0x71374491UL,0xb5c0fbcfUL,0xe9b5dba5UL,
    0x3956c25bUL,0x59f111f1UL,0x923f82a4UL,0xab1c5ed5UL,
    0xd807aa98UL,0x12835b01UL,0x243185beUL,0x550c7dc3UL,
    0x72be5d74UL,0x80deb1feUL,0x9bdc06a7UL,0xc19bf174UL,
    0xe49b69c1UL,0xefbe4786UL,0x0fc19dc6UL,0x240ca1ccUL,
    0x2de92c6fUL,0x4a7484aaUL,0x5cb0a9dcUL,0x76f988daUL,
    0x983e5152UL,0xa831c66dUL,0xb00327c8UL,0xbf597fc7UL,
    0xc6e00bf3UL,0xd5a79147UL,0x06ca6351UL,0x14292967UL,
    0x27b70a85UL,0x2e1b2138UL,0x4d2c6dfcUL,0x53380d13UL,
    0x650a7354UL,0x766a0abbUL,0x81c2c92eUL,0x92722c85UL,
    0xa2bfe8a1UL,0xa81a664bUL,0xc24b8b70UL,0xc76c51a3UL,
    0xd192e819UL,0xd6990624UL,0xf40e3585UL,0x106aa070UL,
    0x19a4c116UL,0x1e376c08UL,0x2748774cUL,0x34b0bcb5UL,
    0x391c0cb3UL,0x4ed8aa4aUL,0x5b9cca4fUL,0x682e6ff3UL,
    0x748f82eeUL,0x78a5636fUL,0x84c87814UL,0x8cc70208UL,
    0x90befffaUL,0xa4506cebUL,0xbef9a3f7UL,0xc67178f2UL
};

/* Initial hash state */
static const uint32_t initial_state[8] = {
    0x6A09E667UL,0xBB67AE85UL,0x3C6EF372UL,0xA54FF53AUL,
    0x510E527FUL,0x9B05688CUL,0x1F83D9ABUL,0x5BE0CD19UL
};

/* Padding byte */
static const uint8_t PAD[64] = { 0x80 };

/* Core SHA-256 transform: fully unrolled for 64 rounds */
static void sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[64];
    uint32_t a,b,c,d,e,f,g,h,T1,T2;

    /* Message schedule: big-endian decode */
    for (int i = 0; i < 16; i++) {
        W[i] = be32dec(&block[i*4]);
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = s0(W[i-15]);
        uint32_t s1 = s1(W[i-2]);
        W[i] = W[i-16] + s0 + W[i-7] + s1;
    }

    /* Working variables */
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    /* Round  0 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[0]  + W[0];   T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round  1 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[1]  + W[1];   T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round  2 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[2]  + W[2];   T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round  3 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[3]  + W[3];   T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round  4 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[4]  + W[4];   T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round  5 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[5]  + W[5];   T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round  6 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[6]  + W[6];   T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round  7 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[7]  + W[7];   T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round  8 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[8]  + W[8];   T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round  9 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[9]  + W[9];   T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 10 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[10] + W[10];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 11 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[11] + W[11];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 12 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[12] + W[12];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 13 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[13] + W[13];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 14 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[14] + W[14];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 15 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[15] + W[15];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 16 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[16] + W[16];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 17 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[17] + W[17];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 18 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[18] + W[18];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 19 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[19] + W[19];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 20 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[20] + W[20];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 21 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[21] + W[21];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 22 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[22] + W[22];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 23 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[23] + W[23];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 24 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[24] + W[24];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 25 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[25] + W[25];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 26 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[26] + W[26];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 27 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[27] + W[27];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 28 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[28] + W[28];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 29 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[29] + W[29];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 30 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[30] + W[30];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 31 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[31] + W[31];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 32 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[32] + W[32];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 33 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[33] + W[33];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 34 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[34] + W[34];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 35 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[35] + W[35];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 36 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[36] + W[36];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 37 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[37] + W[37];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 38 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[38] + W[38];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 39 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[39] + W[39];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 40 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[40] + W[40];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 41 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[41] + W[41];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 42 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[42] + W[42];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 43 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[43] + W[43];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 44 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[44] + W[44];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 45 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[45] + W[45];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 46 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[46] + W[46];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 47 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[47] + W[47];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 48 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[48] + W[48];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 49 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[49] + W[49];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 50 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[50] + W[50];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 51 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[51] + W[51];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 52 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[52] + W[52];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 53 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[53] + W[53];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 54 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[54] + W[54];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 55 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[55] + W[55];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 56 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[56] + W[56];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 57 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[57] + W[57];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 58 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[58] + W[58];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 59 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[59] + W[59];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 60 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[60] + W[60];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 61 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[61] + W[61];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 62 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[62] + W[62];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Round 63 */
    T1 = h + S1(e) + Ch(e,f,g) + K256[63] + W[63];  T2 = S0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    /* Update state */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

/* SHA-256 public API */
void SHA256_Init(SHA256_CTX *ctx) {
    ctx->count = 0;
    memcpy(ctx->state, initial_state, sizeof(initial_state));
}

void SHA256_Update(SHA256_CTX *ctx, const void *in, size_t len) {
    const uint8_t *src = (const uint8_t *)in;
    size_t r = (ctx->count >> 3) & 0x3F;
    ctx->count += ((uint64_t)len << 3);

    if (r && len) {
        size_t tofill = 64 - r;
        if (len < tofill) {
            memcpy(&ctx->buf[r], src, len);
            return;
        }
        memcpy(&ctx->buf[r], src, tofill);
        sha256_transform(ctx->state, ctx->buf);
        src += tofill;
        len -= tofill;
    }
    while (len >= 64) {
        sha256_transform(ctx->state, src);
        src += 64;
        len -= 64;
    }
    if (len) {
        memcpy(ctx->buf, src, len);
    }
}

void SHA256_Final(uint8_t digest[32], SHA256_CTX *ctx) {
    uint8_t tmp[8];
    size_t r = (ctx->count >> 3) & 0x3F;

    if (r < 56) {
        memcpy(&ctx->buf[r], PAD, 56 - r);
    } else {
        memcpy(&ctx->buf[r], PAD, 64 - r);
        sha256_transform(ctx->state, ctx->buf);
        memset(ctx->buf, 0, 56);
    }
    be64enc(tmp, ctx->count);
    memcpy(&ctx->buf[56], tmp, 8);
    sha256_transform(ctx->state, ctx->buf);

    for (int i = 0; i < 8; i++) {
        be32enc(&digest[i*4], ctx->state[i]);
    }
    insecure_memzero(ctx, sizeof(SHA256_CTX));
}

void SHA256_Buf(const void *in, size_t len, uint8_t digest[32]) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, in, len);
    SHA256_Final(digest, &ctx);
}

/* HMAC-SHA256 */
void HMAC_SHA256_Init(HMAC_SHA256_CTX *ctx, const void *key, size_t keylen) {
    uint8_t pad[64], khash[32];
    const uint8_t *K = (const uint8_t *)key;
    if (keylen > 64) {
        SHA256_CTX t;
        SHA256_Init(&t);
        SHA256_Update(&t, K, keylen);
        SHA256_Final(khash, &t);
        K = khash;
        keylen = 32;
    }
    SHA256_Init(&ctx->ictx);
    memset(pad, 0x36, 64);
    for (size_t i = 0; i < keylen; i++) pad[i] ^= K[i];
    SHA256_Update(&ctx->ictx, pad, 64);

    SHA256_Init(&ctx->octx);
    memset(pad, 0x5c, 64);
    for (size_t i = 0; i < keylen; i++) pad[i] ^= K[i];
    SHA256_Update(&ctx->octx, pad, 64);
    insecure_memzero(khash, 32);
}

void HMAC_SHA256_Update(HMAC_SHA256_CTX *ctx, const void *data, size_t len) {
    SHA256_Update(&ctx->ictx, data, len);
}

void HMAC_SHA256_Final(uint8_t digest[32], HMAC_SHA256_CTX *ctx) {
    uint8_t ihash[32];
    SHA256_Final(ihash, &ctx->ictx);
    SHA256_Update(&ctx->octx, ihash, 32);
    SHA256_Final(digest, &ctx->octx);
    insecure_memzero(ihash, 32);
}

void HMAC_SHA256_Buf(const void *key, size_t keylen, const void *data, size_t len, uint8_t digest[32]) {
    HMAC_SHA256_CTX ctx;
    HMAC_SHA256_Init(&ctx, key, keylen);
    HMAC_SHA256_Update(&ctx, data, len);
    HMAC_SHA256_Final(digest, &ctx);
}

/* PBKDF2-HMAC-SHA256 */
void PBKDF2_SHA256(const uint8_t *passwd, size_t passwdlen,
                   const uint8_t *salt, size_t saltlen,
                   uint64_t c, uint8_t *buf, size_t dkLen) {
    HMAC_SHA256_CTX Ph, PSh, hctx;
    uint8_t U[32], T[32], ivec[4];
    assert(dkLen <= 32 * (size_t)UINT32_MAX);

    HMAC_SHA256_Init(&Ph, passwd, passwdlen);
    memcpy(&PSh, &Ph, sizeof(Ph));
    HMAC_SHA256_Update(&PSh, salt, saltlen);

    for (size_t i = 0; i * 32 < dkLen; i++) {
        uint32_t j = (uint32_t)i + 1;
        be32enc(ivec, j);

        memcpy(&hctx, &PSh, sizeof(hctx));
        HMAC_SHA256_Update(&hctx, ivec, 4);
        HMAC_SHA256_Final(U, &hctx);

        memcpy(T, U, 32);

        for (uint64_t k = 2; k <= c; k++) {
            HMAC_SHA256_Init(&hctx, passwd, passwdlen);
            HMAC_SHA256_Update(&hctx, U, 32);
            HMAC_SHA256_Final(U, &hctx);
            for (int x = 0; x < 32; x++) {
                T[x] ^= U[x];
            }
        }

        size_t r = dkLen - i * 32;
        if (r > 32) r = 32;
        memcpy(buf + i * 32, T, r);
    }

    insecure_memzero(&Ph, sizeof(Ph));
    insecure_memzero(&PSh, sizeof(PSh));
    insecure_memzero(&hctx, sizeof(hctx));
    insecure_memzero(U, 32);
    insecure_memzero(T, 32);
}
