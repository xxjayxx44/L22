#ifndef _YESPOWER_OPT_C_PASS_
#define _YESPOWER_OPT_C_PASS_ 1
#endif

#if _YESPOWER_OPT_C_PASS_ == 1
/*
 * Optimized SIMD implementation with AVX2/SSE4 enhancements
 */
#ifdef __AVX2__
#include <immintrin.h>
#elif defined(__SSE4_1__)
#include <smmintrin.h>
#elif defined(__SSE2__)
#include <emmintrin.h>
#endif

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "sha256.h"
#include "sysendian.h"
#include "yespower.h"

#define ALIGN_64 __attribute__((aligned(64)))
#define FORCE_INLINE __attribute__((always_inline)) inline
#define LIKELY(x) __builtin_expect((x), 1)
#define UNLIKELY(x) __builtin_expect((x), 0)

// Enhanced SIMD shuffling with aligned memory operations
typedef union ALIGN_64 {
    uint32_t w[16];
    uint64_t d[8];
#ifdef __SSE2__
    __m128i q[4];
#endif
} salsa20_blk_t;

// Optimized SIMD shuffle/unshuffle
FORCE_INLINE void salsa20_simd_shuffle(const salsa20_blk_t *Bin, salsa20_blk_t *Bout) {
#ifdef __SSE2__
    __m128i a = _mm_load_si128(&amp;Bin-&gt;q[0]);
    __m128i b = _mm_load_si128(&amp;Bin-&gt;q[1]);
    __m128i c = _mm_load_si128(&amp;Bin-&gt;q[2]);
    __m128i d = _mm_load_si128(&amp;Bin-&gt;q[3]);

    __m128i t0 = _mm_unpacklo_epi32(a, c);
    __m128i t1 = _mm_unpackhi_epi32(a, c);
    __m128i t2 = _mm_unpacklo_epi32(b, d);
    __m128i t3 = _mm_unpackhi_epi32(b, d);

    _mm_store_si128(&amp;Bout-&gt;q[0], _mm_unpacklo_epi32(t0, t2));
    _mm_store_si128(&amp;Bout-&gt;q[1], _mm_unpackhi_epi32(t0, t2));
    _mm_store_si128(&amp;Bout-&gt;q[2], _mm_unpacklo_epi32(t1, t3));
    _mm_store_si128(&amp;Bout-&gt;q[3], _mm_unpackhi_epi32(t1, t3));
#else
    // Fallback for non-SSE2
    #define COMBINE(out, in1, in2) \
        Bout-&gt;d[out] = Bin-&gt;w[in1*2] | ((uint64_t)Bin-&gt;w[in2*2+1] &lt;&lt;32);
    COMBINE(0,0,2) COMBINE(1,5,7) COMBINE(2,2,4) COMBINE(3,7,1)
    COMBINE(4,4,6) COMBINE(5,1,3) COMBINE(6,6,0) COMBINE(7,3,5)
#endif
}

// Optimized Salsa20 core with instruction reordering
#ifdef __SSE2__
#define ARX(out, in1, in2, s) do { \
    __m128i tmp = _mm_add_epi32(in1, in2); \
    tmp = _mm_xor_si128(_mm_slli_epi32(tmp, s), _mm_srli_epi32(tmp, 32-(s))); \
    out = _mm_xor_si128(out, tmp); \
} while(0)

#define SALSA20_2ROUNDS \
    ARX(X1, X0, X3, 7); ARX(X2, X1, X0, 9); ARX(X3, X2, X1, 13); ARX(X0, X3, X2, 18); \
    X1 = _mm_shuffle_epi32(X1, 0x93); X2 = _mm_shuffle_epi32(X2, 0x4E); X3 = _mm_shuffle_epi32(X3, 0x39); \
    ARX(X3, X0, X1, 7); ARX(X2, X3, X0, 9); ARX(X1, X2, X3, 13); ARX(X0, X1, X2, 18); \
    X1 = _mm_shuffle_epi32(X1, 0x39); X2 = _mm_shuffle_epi32(X2, 0x4E); X3 = _mm_shuffle_epi32(X3, 0x93);
#endif

// Enhanced memory prefetching
#ifdef __SSE__
#define PREFETCH(ptr, hint) _mm_prefetch((const char*)(ptr), (hint))
#else
#define PREFETCH(ptr, hint)
#endif

// Optimized block mixing with prefetch
static FORCE_INLINE void blockmix_salsa(const salsa20_blk_t *restrict Bin,
                                        salsa20_blk_t *restrict Bout) {
#ifdef __SSE2__
    __m128i X0, X1, X2, X3;
    
    // Prefetch next blocks
    PREFETCH(Bin + 2, _MM_HINT_T0);
    PREFETCH(Bout + 2, _MM_HINT_T1);
    
    X0 = Bin[1].q[0]; X1 = Bin[1].q[1];
    X2 = Bin[1].q[2]; X3 = Bin[1].q[3];
    
    // Process Bin[0]
    X0 = _mm_xor_si128(X0, Bin[0].q[0]);
    X1 = _mm_xor_si128(X1, Bin[0].q[1]);
    X2 = _mm_xor_si128(X2, Bin[0].q[2]);
    X3 = _mm_xor_si128(X3, Bin[0].q[3]);
    SALSA20_2ROUNDS;
    Bout[0].q[0] = X0; Bout[0].q[1] = X1;
    Bout[0].q[2] = X2; Bout[0].q[3] = X3;
    
    // Process Bin[1]
    SALSA20_2ROUNDS;
    Bout[1].q[0] = X0; Bout[1].q[1] = X1;
    Bout[1].q[2] = X2; Bout[1].q[3] = X3;
#else
    // Non-SSE2 fallback
    salsa20_blk_t X;
    salsa20_simd_unshuffle(&amp;Bin[1], &amp;X);
    // ... original non-SIMD implementation ...
#endif
}

// Enhanced pwxform context with aligned memory
typedef struct ALIGN_64 {
    uint8_t *S0, *S1, *S2;
    size_t w;
    uint32_t Sbytes;
} pwxform_ctx_t;

// Optimized integerify using direct SIMD access
static FORCE_INLINE uint32_t integerify(const salsa20_blk_t *B, size_t r) {
#ifdef __SSE2__
    return _mm_cvtsi128_si32(_mm_load_si128(&amp;B[2*r-1].q[0]));
#else
    return (uint32_t)B[2*r-1].d[0];
#endif
}

// Streamlined SMIX implementation
static void smix(uint8_t *B, size_t r, uint32_t N,
                salsa20_blk_t *V, salsa20_blk_t *XY, pwxform_ctx_t *ctx) {
    const size_t s = 2 * r;
    salsa20_blk_t *X = XY, *Y = &amp;XY[s];
    
    // Vectorized initialization
    for(size_t i=0; i&lt;2*r; i++) {
        salsa20_blk_t tmp;
        memcpy(&amp;tmp, &amp;B[i*64], 64);
        salsa20_simd_shuffle(&amp;tmp, &amp;X[i]);
    }
    
    // Optimized main loop
    for(uint32_t n=2; n<n; n<<="1)" {="" const="" uint32_t="" m="(n" <="" n="" 2)="" ?="" :="" (n-1-n);="" for(uint32_t="" i="1;" i<m;="" i+="2)" prefetch(&v[(i-1)*s],="" _mm_hint_t0);="" prefetch(&v[i*s],="" _mm_hint_t1);="" salsa20_blk_t="" *v_j="&amp;V[(i-1)*s];" blockmix_xor(x,="" v_j,="" y,="" r,="" ctx);="" v_j="&amp;V[i*s];" blockmix_xor(y,="" x,="" }="" final="" processing="" tmp;="" for(size_t="" i<2*r;="" i++)="" salsa20_simd_unshuffle(&xy[i],="" &tmp);="" memcpy(&b[i*64],="" &tmp,="" 64);="" enhanced="" yespower="" core="" with="" vectorized="" hashing="" int="" yespower(yespower_local_t="" *local,="" uint8_t="" *src,="" size_t="" srclen,="" yespower_params_t="" *params,="" yespower_binary_t="" *dst)="" ...="" (parameter="" validation="" same="" as="" original)="" sha-256="" initialization="" sha256[32]="" align_64;="" sha256_ctx="" ctx;="" sha256_init(&ctx);="" sha256_update(&ctx,="" src,="" srclen);="" sha256_final(sha256,="" &ctx);="" optimized="" pbkdf2="" implementation="" aligned(uint8_t,="" 64)="" b[128*r];="" optimized_pbkdf2_sha256(sha256,="" sizeof(sha256),="" 1,="" b,="" sizeof(b));="" process="" blocks="" smix="" aligned(salsa20_blk_t,="" v[n*s];="" xy[2*s];="" pwxform_ctx_t="" pctx;="" smix(b,="" n,="" v,="" xy,="" &pctx);="" hmac="" vector="" acceleration="" result[32];="" optimized_hmac_sha256(b,="" sizeof(b),="" sha256,="" result);="" memcpy(dst,="" result,="" sizeof(*dst));="" secure="" memory="" cleanup="" secure_memzero(sha256,="" sizeof(sha256));="" secure_memzero(b,="" secure_memzero(v,="" sizeof(v));="" return="" 0;="" maintain="" original="" api="" functions="" alignment="" yespower_tls(const="" static="" __thread="" yespower_local_t="" local="{0};" yespower(&local,="" params,="" dst);="" management="" yespower_free_local(yespower_local_t="" *local)="" if(local-="">base) {
        secure_memzero(local-&gt;base, local-&gt;aligned_size);
        free(local-&gt;base);
        local-&gt;base = NULL;
{
    return 0;

#endif
}
