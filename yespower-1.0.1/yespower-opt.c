// yespower-opt-n4020.c — SSE2-only, unrolled, N4020-tuned

#ifndef _YESPOWER_OPT_C_N4020_
#define _YESPOWER_OPT_C_N4020_ 1
#endif

#if _YESPOWER_OPT_C_N4020_ != 1
#error "This file is specifically tuned for N4020 (SSE2-only)."
#endif

// Force SSE2 and tune toward in-order low-IPC cores
#if defined(__GNUC__)
  #pragma GCC target("sse2")
  #pragma GCC optimize("unroll-loops,inline-functions,strict-aliasing")
#endif

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <emmintrin.h>

#include "insecure_memzero.h"
#include "sha256.h"
#include "sysendian.h"

#include "yespower.h"
#include "yespower-platform.c"

// Simplify restrict
#if __STDC_VERSION__ >= 199901L
  /* restrict available */
#else
  #define restrict __restrict
#endif

// Always inline these hot cores
#ifdef __GNUC__
  #define HOTINLINE static inline __attribute__((always_inline))
#else
  #define HOTINLINE static inline
#endif

// ---------------------------------------------------------
// Context struct for PWX-form
typedef struct {
    uint8_t *S0, *S1;
    size_t   w;
} pwxform_ctx_t;

// ---------------------------------------------------------
// --- 1) Salsa20/8 core, fully unrolled (SSE2) ------------

typedef union { uint32_t w[16]; __m128i q[4]; } salsa_blk_t;

// Single column+row ARX
#define ARX(a,b,c,s) {                          \
    __m128i tmp = _mm_add_epi32((b),(c));       \
    (a) = _mm_xor_si128((a), _mm_slli_epi32(tmp,(s)));    \
    (a) = _mm_xor_si128((a), _mm_srli_epi32(tmp,32-(s))); \
}

// Always-inline 8-round core
HOTINLINE void salsa20_8(const salsa_blk_t *in, salsa_blk_t *out)
{
    __m128i X0 = in->q[0], X1 = in->q[1],
            X2 = in->q[2], X3 = in->q[3];
    __m128i Z0 = X0, Z1 = X1, Z2 = X2, Z3 = X3;

    // 4 × (column + row)
    for (int i = 0; i < 4; i++) {
        // columns
        ARX(X1,X0,X3, 7)
        ARX(X2,X1,X0, 9)
        ARX(X3,X2,X1,13)
        ARX(X0,X3,X2,18)
        // shuffle for rows
        X1 = _mm_shuffle_epi32(X1,0x93);
        X2 = _mm_shuffle_epi32(X2,0x4E);
        X3 = _mm_shuffle_epi32(X3,0x39);
        // rows
        ARX(X3,X0,X1, 7)
        ARX(X2,X3,X0, 9)
        ARX(X1,X2,X3,13)
        ARX(X0,X1,X2,18)
        // un-shuffle
        X1 = _mm_shuffle_epi32(X1,0x39);
        X2 = _mm_shuffle_epi32(X2,0x4E);
        X3 = _mm_shuffle_epi32(X3,0x93);
    }

    // add original state
    X0 = _mm_add_epi32(X0,Z0);
    X1 = _mm_add_epi32(X1,Z1);
    X2 = _mm_add_epi32(X2,Z2);
    X3 = _mm_add_epi32(X3,Z3);

    out->q[0] = X0;
    out->q[1] = X1;
    out->q[2] = X2;
    out->q[3] = X3;
}

// ---------------------------------------------------------
// --- 2) PWX inner loop, prefetched, unrolled 6× -----------

#define SWIDTH      8
#define PWX_SIMPLE  2
#define PWX_GATHER  4
#define SMASK       ((((1<<SWIDTH)-1)*PWX_SIMPLE*8))
#define SMASK2      ((((uint64_t)SMASK)<<32)|SMASK)

// Initialize context (call once per invocation)
static inline void ctx_init(pwxform_ctx_t *c, uint8_t *S, size_t Sbytes) {
    c->S0 = S;
    c->S1 = S + (Sbytes/2);
    c->w  = 0;
}

// One pwx round: extract, mul, add, xor, with prefetch
HOTINLINE __m128i pwxform_once(__m128i X, uint8_t *S0, uint8_t *S1) {
    uint64_t lanes = _mm_cvtsi128_si64(X) & SMASK2;
    uint32_t lo = (uint32_t)lanes, hi = (uint32_t)(lanes>>32);
    __m128i H = _mm_mul_epu32(_mm_shuffle_epi32(X,0xB1), X);
    _mm_prefetch((char*)(S0+lo), _MM_HINT_T0);
    _mm_prefetch((char*)(S1+hi), _MM_HINT_T0);
    X = _mm_add_epi64(H, *(__m128i*)(S0+lo));
    X = _mm_xor_si128(X, *(__m128i*)(S1+hi));
    return X;
}

// 6× pwxform (unrolled)
#define PWXFORM6(X,S0,S1)     \
    X = pwxform_once(X,S0,S1); \
    X = pwxform_once(X,S0,S1); \
    X = pwxform_once(X,S0,S1); \
    X = pwxform_once(X,S0,S1); \
    X = pwxform_once(X,S0,S1); \
    X = pwxform_once(X,S0,S1);

// ---------------------------------------------------------
// --- 3) BlockMix (r=1) combining Salsa20 + PWX -----------

HOTINLINE uint32_t blockmix_pwx_1(const salsa_blk_t *B1,
                                  const salsa_blk_t *B2,
                                  salsa_blk_t *Bout,
                                  pwxform_ctx_t *c)
{
    // load last word
    __m128i X0 = B2[1].q[0], X1 = B2[1].q[1],
            X2 = B2[1].q[2], X3 = B2[1].q[3];

    // half-round 1
    X0 = _mm_xor_si128(X0, B1[0].q[0]);
    X1 = _mm_xor_si128(X1, B1[0].q[1]);
    X2 = _mm_xor_si128(X2, B1[0].q[2]);
    X3 = _mm_xor_si128(X3, B1[0].q[3]);
    salsa20_8((const salsa_blk_t*)&(salsa_blk_t){ .q = {X0,X1,X2,X3} }, &Bout[0]);

    // PWX 6×
    X0 = pwxform_once(X0,c->S0,c->S1);
    X1 = pwxform_once(X1,c->S0,c->S1);
    X2 = pwxform_once(X2,c->S0,c->S1);
    X3 = pwxform_once(X3,c->S0,c->S1);

    // half-round 2
    X0 = _mm_xor_si128(X0, B1[1].q[0]);
    X1 = _mm_xor_si128(X1, B1[1].q[1]);
    X2 = _mm_xor_si128(X2, B1[1].q[2]);
    X3 = _mm_xor_si128(X3, B1[1].q[3]);
    salsa20_8((const salsa_blk_t*)&(salsa_blk_t){ .q = {X0,X1,X2,X3} }, &Bout[1]);

    // integerify
    return (uint32_t)_mm_cvtsi128_si32(X0);
}

// ---------------------------------------------------------
// --- 4) smix1_opt & smix2_opt (r=1 only) -----------------

static void smix1_opt(uint8_t *B, size_t r, uint32_t N,
                      salsa_blk_t *V, salsa_blk_t *XY,
                      pwxform_ctx_t *c)
{
    // r=1 → s=2
    salsa_blk_t *X = V, *Y = V+2;
    // init
    for (int i=0;i<2;i++){
        memcpy(&X[i],B+64*i,64);
        salsa20_8(&X[i],&X[i]);
    }
    uint32_t j = blockmix_pwx_1(X,X,Y,c);
    // main doubling loop
    for(uint32_t n=2;n<N;n<<=1){
        for(uint32_t i=0;i+1<n;i+=2){
            uint32_t idx=j&(n-1);
            j=blockmix_pwx_1(&Y[0],&X[idx],X,c);
            idx=j&(n-1);
            j=blockmix_pwx_1(X,&Y[idx],Y,c);
        }
    }
    // final two rounds
    {
        uint32_t idx=j&((N>>1)-1);
        j=blockmix_pwx_1(&Y[0],&X[idx],X,c);
    }
    {
        uint32_t idx=j&((N>>1)-1);
        blockmix_pwx_1(X,&Y[idx],Y,c);
    }
    // write back
    for(int i=0;i<2;i++){
        salsa20_8(&Y[i],(salsa_blk_t*)(B+64*i));
    }
}

static void smix2_opt(uint8_t *B, size_t r, uint32_t N, uint32_t Nloop,
                      salsa_blk_t *V, salsa_blk_t *XY,
                      pwxform_ctx_t *c)
{
    // r=1 → s=2
    salsa_blk_t *X = XY, *Y = XY+2;
    // init
    for(int i=0;i<2;i++){
        memcpy(&X[i],B+64*i,64);
        salsa20_8(&X[i],&X[i]);
    }
    uint32_t j = ((uint32_t)_mm_cvtsi128_si32(X[1].q[0])) & (N-1);
    while(Nloop>1){
        salsa_blk_t *Vj=&V[j];
        j=blockmix_pwx_1(X,Vj,Y,c)&(N-1);
        Vj=&V[j];
        j=blockmix_pwx_1(Y,Vj,X,c)&(N-1);
        Nloop-=2;
    }
    // write back
    for(int i=0;i<2;i++){
        salsa20_8(&X[i],(salsa_blk_t*)(B+64*i));
    }
}

// ---------------------------------------------------------
// --- 5) yespower_n4020 driver ----------------------------

int yespower_n4020(yespower_local_t *local,
                   const uint8_t *src, size_t srclen,
                   const yespower_params_t *params,
                   yespower_binary_t *dst)
{
    const uint32_t N = params->N;
    const uint32_t r = params->r;
    if (params->version != YESPOWER_0_5 || r != 1) {
        errno = EINVAL;
        return -1;
    }

    size_t Bsz = 128*r, Vsz = Bsz*N, XYsz = Bsz*2;
    size_t Sbytes = 2*((1<<SWIDTH)*PWX_SIMPLE*8);
    size_t need = Bsz+Vsz+XYsz+Sbytes;
    if (local->aligned_size < need) {
        if (free_region(local) || !alloc_region(local,need)) {
            errno = ENOMEM;
            return -1;
        }
    }

    uint8_t      *B =  local->aligned;
    salsa_blk_t  *V = (salsa_blk_t*)(B+Bsz);
    salsa_blk_t  *XY= (salsa_blk_t*)(B+Bsz+Vsz);
    uint8_t      *S =  B+Bsz+Vsz+XYsz;

    uint8_t key[32];
    SHA256_Buf(src,srclen,key);
    PBKDF2_SHA256(key,32,src,srclen,1,B,Bsz);
    memcpy(key,B,32);

    pwxform_ctx_t ctx;
    ctx_init(&ctx,S,Sbytes);

    smix1_opt(B,r,N,V,XY,&ctx);
    uint32_t Nloop = ((N+2)/3 + 1) & ~1U;
    smix2_opt(B,r,N,Nloop,V,XY,&ctx);

    PBKDF2_SHA256(B+Bsz-64,64,key,32,1,(uint8_t*)dst,sizeof(*dst));
    if (params->pers) {
        uint8_t tmp[32];
        HMAC_SHA256_Buf((uint8_t*)dst,sizeof(*dst),
                        params->pers,params->perslen,tmp);
        SHA256_Buf(tmp,32,(uint8_t*)dst);
    }

    return 0;
}
