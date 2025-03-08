/* Include necessary headers and define macros */
#include <emmintrin.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "sha256.h"
#include "sysendian.h"
#include "yespower.h"

/* Define macros for SIMD operations */
#ifdef __SSE2__
#define SIMD_ALIGN __attribute__((aligned(16)))
#else
#define SIMD_ALIGN
#endif

/* Optimized Salsa20 core */
static inline void salsa20_optimized(uint32_t out[16], const uint32_t in[16]) {
    uint32_t x[16];
    int i;

    for (i = 0; i &lt; 16; ++i)
        x[i] = in[i];

    for (i = 0; i &lt; 10; ++i) {
        #define ROTL(a, b) (((a) &lt;&lt; (b)) | ((a) &gt;&gt; (32 - (b))))
        x[ 4] ^= ROTL(x[ 0] + x[12],  7);  x[ 8] ^= ROTL(x[ 4] + x[ 0],  9);
        x[12] ^= ROTL(x[ 8] + x[ 4], 13);  x[ 0] ^= ROTL(x[12] + x[ 8], 18);
        x[ 9] ^= ROTL(x[ 5] + x[ 1],  7);  x[13] ^= ROTL(x[ 9] + x[ 5],  9);
        x[ 1] ^= ROTL(x[13] + x[ 9], 13);  x[ 5] ^= ROTL(x[ 1] + x[13], 18);
        x[14] ^= ROTL(x[10] + x[ 6],  7);  x[ 2] ^= ROTL(x[14] + x[10],  9);
        x[ 6] ^= ROTL(x[ 2] + x[14], 13);  x[10] ^= ROTL(x[ 6] + x[ 2], 18);
        x[ 3] ^= ROTL(x[15] + x[11],  7);  x[ 7] ^= ROTL(x[ 3] + x[15],  9);
        x[11] ^= ROTL(x[ 7] + x[ 3], 13);  x[15] ^= ROTL(x[11] + x[ 7], 18);
        x[ 1] ^= ROTL(x[ 0] + x[ 3],  7);  x[ 2] ^= ROTL(x[ 1] + x[ 0],  9);
        x[ 3] ^= ROTL(x[ 2] + x[ 1], 13);  x[ 0] ^= ROTL(x[ 3] + x[ 2], 18);
        x[ 6] ^= ROTL(x[ 5] + x[ 4],  7);  x[ 7] ^= ROTL(x[ 6] + x[ 5],  9);
        x[ 4] ^= ROTL(x[ 7] + x[ 6], 13);  x[ 5] ^= ROTL(x[ 4] + x[ 7], 18);
        x[11] ^= ROTL(x[10] + x[ 9],  7);  x[ 8] ^= ROTL(x[11] + x[10],  9);
        x[ 9] ^= ROTL(x[ 8] + x[11], 13);  x[10] ^= ROTL(x[ 9] + x[ 8], 18);
        x[12] ^= ROTL(x[15] + x[14],  7);  x[13] ^= ROTL(x[12] + x[15],  9);
        x[14] ^= ROTL(x[13] + x[12], 13);  x[15] ^= ROTL(x[14] + x[13], 18);
    }

    for (i = 0; i &lt; 16; ++i)
        out[i] = x[i] + in[i];
}

/* Optimized BlockMix function */
static inline void blockmix_optimized(const uint32_t *Bin, uint32_t *Bout, size_t r) {
    uint32_t X[16], Y[16];
    size_t i;

    memcpy(X, &amp;Bin[(2 * r - 1) * 16], 64);

    for (i = 0; i &lt; 2 * r; i++) {
        salsa20_optimized(Y, X);
        memcpy(&amp;Bout[i * 16], Y, 64);
        if (i &lt; 2 * r - 1)
            memcpy(X, &amp;Bin[i * 16], 64);
    }
}

/* Main SMix function */
static void smix_optimized(uint8_t *B, size_t r, uint32_t N, uint32_t *V, uint32_t *XY) {
    size_t s = 2 * r;
    uint32_t *X = V, *Y = &amp;V[s];
    uint32_t i, j, n;

    blockmix_optimized((uint32_t *)B, X, r);

    for (n = 1; n &lt; N; n++) {
        blockmix_optimized(X, &amp;V[n * s], r);
    }

    for (n = 0; n &lt; N; n++) {
        j = X[(2 * r - 1) * 16] &amp; (N - 1);
        for (i = 0; i &lt; s; i++)
            X[i] ^= V[j * s + i];
        blockmix_optimized(X, Y, r);
        memcpy(X, Y, s * 4);
    }

    memcpy(B, X, 128 * r);
}

/* Yespower function */
int yespower_optimized(const uint8_t *src, size_t srclen, const yespower_params_t *params, yespower_binary_t *dst) {
    uint32_t N = params-&gt;N;
    uint32_t r = params-&gt;r;
    size_t B_size = 128 * r;
    size_t V_size = B_size * N;
    size_t XY_size = 256 * r;
    uint8_t *B = malloc(B_size + V_size + XY_size);
    uint32_t *V = (uint32_t *)(B + B_size);
    uint32_t *XY = (uint32_t *)(B + B_size + V_size);

    if (!B) return -1;

    PBKDF2_SHA256(src, srclen, src, srclen, 1, B, B_size);
    smix_optimized(B, r, N, V, XY);
    PBKDF2_SHA256(B, B_size, B, B_size, 1, (uint8_t *)dst, sizeof(*dst));

    free(B);
    return 0;
}
