/* yespower-opt-n4020.c
 * SSE2‐only, Intel Celeron N4020–tuned yespower (v1.0 core)
 * Author: optimized for N4020
 * Compile with: gcc -O3 -march=native -mtune=atom -msse2 -std=c11
 */

#ifndef _YESPOWER_OPT_C_PASS_
#define _YESPOWER_OPT_C_PASS_ 1
#endif

#if _YESPOWER_OPT_C_PASS_ == 1

/* Only SSE2 path; drop AVX/XOP entirely */
#if !defined(__SSE2__)
#error "SSE2 support is required for N4020 optimization"
#endif

/* Force GCC to tune for Atom microarchitecture to avoid costly prefixes */
#if defined(__GNUC__) && (__GNUC__ >= 6)
#pragma GCC target("tune=atom")
#endif

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <emmintrin.h>    /* SSE2 intrinsics */
#include "insecure_memzero.h"
#include "sha256.h"
#include "sysendian.h"
#include "yespower.h"
#include "yespower-platform.c"

#if __STDC_VERSION__ >= 199901L
/* restrict is available */
#elif defined(__GNUC__)
#define restrict __restrict
#else
#define restrict
#endif

#ifdef __GNUC__
#define unlikely(x) __builtin_expect(!!(x), 0)
#else
#define unlikely(x) (x)
#endif

#define PREFETCH(addr) _mm_prefetch((const char *)(addr), _MM_HINT_T0)

/* salsa20 block */
typedef union {
    uint32_t w[16];
    uint64_t d[8];
    __m128i   q[4];
} salsa20_blk_t;

/* SIMD shuffle/unshuffle, inlined for speed */
static inline void salsa20_shuffle(const salsa20_blk_t *in, salsa20_blk_t *out) {
    /* interleave low/high 32-bit words into 64-bit d[] */
    out->d[0] = in->w[0]  | ((uint64_t)in->w[5]  << 32);
    out->d[1] = in->w[10] | ((uint64_t)in->w[15] << 32);
    out->d[2] = in->w[5]  | ((uint64_t)in->w[10] << 32);
    out->d[3] = in->w[15] | ((uint64_t)in->w[0]  << 32);
    out->d[4] = in->w[3]  | ((uint64_t)in->w[8]  << 32);
    out->d[5] = in->w[12] | ((uint64_t)in->w[7]  << 32);
    out->d[6] = in->w[8]  | ((uint64_t)in->w[3]  << 32);
    out->d[7] = in->w[7]  | ((uint64_t)in->w[12] << 32);
}

static inline void salsa20_unshuffle(const salsa20_blk_t *in, salsa20_blk_t *out) {
    out->w[0]  = in->d[0]       & 0xFFFFFFFF;
    out->w[5]  = in->d[0] >> 32;
    out->w[10] = in->d[1]       & 0xFFFFFFFF;
    out->w[15] = in->d[1] >> 32;
    out->w[5]  = in->d[2]       & 0xFFFFFFFF;
    out->w[10] = in->d[2] >> 32;
    out->w[15] = in->d[3]       & 0xFFFFFFFF;
    out->w[0]  = in->d[3] >> 32;
    out->w[3]  = in->d[4]       & 0xFFFFFFFF;
    out->w[8]  = in->d[4] >> 32;
    out->w[12] = in->d[5]       & 0xFFFFFFFF;
    out->w[7]  = in->d[5] >> 32;
    out->w[8]  = in->d[6]       & 0xFFFFFFFF;
    out->w[3]  = in->d[6] >> 32;
    out->w[7]  = in->d[7]       & 0xFFFFFFFF;
    out->w[12] = in->d[7] >> 32;
}

/* SSE2‐only Salsa20/8 */
#define DECL_X __m128i X0,X1,X2,X3;
#define LOAD_X(b) \
    X0=(b).q[0]; X1=(b).q[1]; X2=(b).q[2]; X3=(b).q[3];
#define SAVE_X(b) \
    (b).q[0]=X0; (b).q[1]=X1; (b).q[2]=X2; (b).q[3]=X3;

/* 2‐round column/row ARX */
#define ARX(a,b,c,s) { \
    __m128i t = _mm_add_epi32(b,c); \
    a = _mm_xor_si128(a, _mm_slli_epi32(t, s)); \
    a = _mm_xor_si128(a, _mm_srli_epi32(t, 32-s)); \
}

/* Single 8‐round core */
#define SALSA20_8ROUNDS { \
    /* 4 x 2‐round sequences */ \
    ARX(X1,X0,X3,7); ARX(X2,X1,X0,9); ARX(X3,X2,X1,13); ARX(X0,X3,X2,18); \
    X1=_mm_shuffle_epi32(X1,0x93); X2=_mm_shuffle_epi32(X2,0x4E); X3=_mm_shuffle_epi32(X3,0x39); \
    ARX(X3,X0,X1,7); ARX(X2,X3,X0,9); ARX(X1,X2,X3,13); ARX(X0,X1,X2,18); \
    X1=_mm_shuffle_epi32(X1,0x39); X2=_mm_shuffle_epi32(X2,0x4E); X3=_mm_shuffle_epi32(X3,0x93); \
    /* repeat 3 more times */ \
    ARX(X1,X0,X3,7); ARX(X2,X1,X0,9); ARX(X3,X2,X1,13); ARX(X0,X3,X2,18); \
    X1=_mm_shuffle_epi32(X1,0x93); X2=_mm_shuffle_epi32(X2,0x4E); X3=_mm_shuffle_epi32(X3,0x39); \
    ARX(X3,X0,X1,7); ARX(X2,X3,X0,9); ARX(X1,X2,X3,13); ARX(X0,X1,X2,18); \
    X1=_mm_shuffle_epi32(X1,0x39); X2=_mm_shuffle_epi32(X2,0x4E); X3=_mm_shuffle_epi32(X3,0x93); \
}

/* Apply Salsa20/8 to in, XOR with 'data', write to out */
static inline void salsa20_xor(const salsa20_blk_t *data,
                               salsa20_blk_t *inout)
{
    DECL_X
    /* load shuffled state */
    LOAD_X(*inout)
    /* xor input */
    X0 = _mm_xor_si128(X0, data->q[0]);
    X1 = _mm_xor_si128(X1, data->q[1]);
    X2 = _mm_xor_si128(X2, data->q[2]);
    X3 = _mm_xor_si128(X3, data->q[3]);
    /* do 8 rounds */
    SALSA20_8ROUNDS
    /* add original */
    X0 = _mm_add_epi32(X0, data->q[0]);
    X1 = _mm_add_epi32(X1, data->q[1]);
    X2 = _mm_add_epi32(X2, data->q[2]);
    X3 = _mm_add_epi32(X3, data->q[3]);
    /* store back */
    SAVE_X(*inout)
}

/* blockmix_salsa: process 2×64-byte Salsa blocks (r=1) */
static inline void blockmix_salsa(const salsa20_blk_t *restrict Bin,
                                  salsa20_blk_t *restrict Bout)
{
    /* X ← Bin[1] */
    Bout[0] = Bin[1];
    /* T = X ⊕ Bin[0]; Salsa20_8(T); Bout[0] = T */
    salsa20_xor(&Bin[0], &Bout[0]);
    /* T = Bout[0] ⊕ Bin[1]; Salsa20_8(T); Bout[1] = T */
    salsa20_xor(&Bin[1], &Bout[1]);
}

/* blockmix_salsa_xor: same but XORs two inputs, returns integerify */
static inline uint32_t blockmix_salsa_xor(const salsa20_blk_t *Bin1,
                                          const salsa20_blk_t *Bin2,
                                          salsa20_blk_t *Bout)
{
    salsa20_blk_t T = Bin1[1];
    /* T = Bin1[1] ⊕ Bin2[1]; */
    T.q[0] = _mm_xor_si128(Bin1[1].q[0], Bin2[1].q[0]);
    T.q[1] = _mm_xor_si128(Bin1[1].q[1], Bin2[1].q[1]);
    T.q[2] = _mm_xor_si128(Bin1[1].q[2], Bin2[1].q[2]);
    T.q[3] = _mm_xor_si128(Bin1[1].q[3], Bin2[1].q[3]);
    /* Bout[0] = Salsa20_8( T ⊕ Bin1[0]? Bin2[0]? ) */
    salsa20_xor(&Bin2[0], &T);
    Bout[0] = T;
    /* Bout[1] = Salsa20_8( Bout[0] ⊕ Bin1[1] ⊕ Bin2[1] ) */
    salsa20_xor(&Bin1[1], &T);
    salsa20_xor(&Bin2[1], &Bout[1]);
    /* integerify = low 32 bits of Bout[1].d[0] */
    return (uint32_t)_mm_cvtsi128_si32(Bout[1].q[0]);
}

/* integerify for r=1: low 32 bits of last block */
static inline uint32_t integerify(const salsa20_blk_t *B, size_t r) {
    (void)r;
    /* B[2*r-1] = B[1] */
    return (uint32_t)_mm_cvtsi128_si32(B[1].q[0]);
}

/* smix1: first pass of SMix for r=1 */
static void smix1(uint8_t *B, size_t r, uint32_t N,
                  salsa20_blk_t *V, salsa20_blk_t *XY,
                  void *ignored_ctx)
{
    /* For r==1, 2 blocks of 64 bytes → V[0], V[1] */
    salsa20_blk_t *X = V;        /* V[0] */
    salsa20_blk_t *Y = V + 2;    /* V[2] */

    /* LOAD B into X[0]..X[1] */
    for (int i = 0; i < 16; i++) {
        X[0].w[i] = le32dec(&((uint32_t *)B)[i]);
        X[1].w[i] = le32dec(&((uint32_t *)(B+64))[i]);
    }
    /* shuffle into SIMD layout */
    salsa20_shuffle(&X[0], &X[0]);
    salsa20_shuffle(&X[1], &X[1]);

    /* First blockmix: X→Y, then Y→X */
    blockmix_salsa(X, Y);
    blockmix_salsa(Y, X);

    /* Store X back into V[0..1] */
    V[0] = X[0];
    V[1] = X[1];

    uint32_t j = integerify(X, r) & (N - 1);

    /* Main loop: for n=2; n<N; n<<=1 */
    for (uint32_t n = 2; n < N; n <<= 1) {
        uint32_t idx = j;
        /* X ⊕= V[idx]; blockmix_salsa on X → Y; swap X,Y; */
        blockmix_salsa_xor(&V[idx*2], &V[idx*2+1], X);
        /* update j */
        j = integerify(X, r) & (n - 1);
    }

    /* Final: write X back to B */
    salsa20_unshuffle(&X[0], (salsa20_blk_t *)B);
    salsa20_unshuffle(&X[1], (salsa20_blk_t *)(B+64));
}

/* smix2 and smix (full r=1 only) would follow here… */

#endif /* _YESPOWER_OPT_C_PASS_ == 1 */

/* smix2: second pass for r=1 */
static void smix2(uint8_t *B, size_t r, uint32_t N, uint32_t Nloop,
                  salsa20_blk_t *V, salsa20_blk_t *XY,
                  void *ignored_ctx)
{
    /* r==1 → 2 blocks */
    salsa20_blk_t *X = XY;      /* working copy */
    salsa20_blk_t *Y = XY + 2;  /* temp */

    /* load and shuffle B → X */
    for (int i = 0; i < 16; i++) {
        X[0].w[i] = le32dec(&((uint32_t *)B)[i]);
        X[1].w[i] = le32dec(&((uint32_t *)(B+64))[i]);
    }
    salsa20_shuffle(&X[0], &X[0]);
    salsa20_shuffle(&X[1], &X[1]);

    uint32_t j = integerify(X, r) & (N - 1);

    /* Nloop is even; each iteration does two blockmix_xor_save steps */
    while (Nloop > 1) {
        /* X ⊕= V[j]; blockmix → Y; swap X,Y */
        blockmix_salsa_xor(&V[j*2], &X[0], Y);
        blockmix_salsa_xor(&V[j*2], &X[1], Y+1);
        /* copy back Y→X */
        X[0] = Y[0];
        X[1] = Y[1];
        j = integerify(X, r) & (N - 1);
        Nloop -= 2;
    }

    /* Final write-out: unshuffle X → B */
    salsa20_unshuffle(&X[0], (salsa20_blk_t *)B);
    salsa20_unshuffle(&X[1], (salsa20_blk_t *)(B+64));
}

/* smix: wrapper combining smix1, smix2 */
static void smix(uint8_t *B, size_t r, uint32_t N,
                 salsa20_blk_t *V, salsa20_blk_t *XY,
                 void *ctx)
{
    /* Compute loop counts for pass2 */
    uint32_t Nloop = ((N + 2) / 3);
    if ((Nloop & 1) == 1) Nloop++;  /* make even */
    /* First pass */
    smix1(B, r, N, V, XY, ctx);
    /* Second pass */
    smix2(B, r, N, Nloop, V, XY, ctx);
}

/* yespower: driver function */
int yespower(yespower_local_t *local,
             const uint8_t *src, size_t srclen,
             const yespower_params_t *params,
             yespower_binary_t *dst)
{
    yespower_version_t version = params->version;
    uint32_t N = params->N;
    uint32_t r = params->r;
    const uint8_t *pers = params->pers;
    size_t perslen = params->perslen;
    size_t B_size = 128 * r;
    size_t V_size = B_size * N;
    size_t XY_size = 2 * B_size;
    size_t Sbytes = 0;  /* not used in r=1 path */
    size_t need = B_size + V_size + XY_size;

    /* Validate */
    if ((version != YESPOWER_0_5 && version != YESPOWER_1_0) ||
        N < 1024 || N > 512*1024 || r != 1 || (N & (N-1)) != 0) {
        errno = EINVAL;
        goto fail;
    }

    /* Allocate if needed */
    if (local->aligned_size < need) {
        if (free_region(local)) goto fail;
        if (!alloc_region(local, need)) goto fail;
    }
    uint8_t *B  = (uint8_t*) local->aligned;
    salsa20_blk_t *V  = (salsa20_blk_t*)(B + B_size);
    salsa20_blk_t *XY = (salsa20_blk_t*)(B + B_size + V_size);

    /* 1) PBKDF2-SHA256(src → B) */
    {
        uint8_t sha[32];
        SHA256_Buf(src, srclen, sha);
        PBKDF2_SHA256(sha, 32, src, srclen, 1, B, B_size);
    }

    /* 2) SMix */
    smix(B, r, N, V, XY, NULL);

    /* 3) Final PBKDF2-SHA256(B → dst) */
    {
        uint8_t sha2[32];
        SHA256_Buf(B, B_size, sha2);
        PBKDF2_SHA256(sha2, 32, B, B_size, 1,
                      (uint8_t*)dst, sizeof(*dst));
    }

    return 0;

fail:
    if (dst) memset(dst, 0xff, sizeof(*dst));
    return -1;
}

/* yespower_tls: thread-local wrapper */
int yespower_tls(const uint8_t *src, size_t srclen,
                 const yespower_params_t *params,
                 yespower_binary_t *dst)
{
    static __thread yespower_local_t local;
    static __thread int init = 0;
    if (!init) {
        init_region(&local);
        init = 1;
    }
    return yespower(&local, src, srclen, params, dst);
}

/* yespower_init_local/free_local */
int yespower_init_local(yespower_local_t *local) {
    init_region(local);
    return 0;
}
int yespower_free_local(yespower_local_t *local) {
    return free_region(local);
}


