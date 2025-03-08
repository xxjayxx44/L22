/*
 * Modified Salsa20 implementation with optimizations
 * Including AVX-512, memory improvements, and performance monitoring
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>

#ifdef __AVX512F__
#include <immintrin.h>
#endif

#ifndef _YESPOWER_OPT_C_PASS_
#define _YESPOWER_OPT_C_PASS_ 1
#endif

#if _YESPOWER_OPT_C_PASS_ == 1

#ifdef __AVX512F__
#define SIMD_SHUFFLE(out, in1, in2) \
    out = _mm512_permutexvar_epi32(_mm512_set_epi32(15,11,7,3,14,10,6,2,13,9,5,1,12,8,4,0), in1)
#else
#define SIMD_SHUFFLE(out, in1, in2) \
    out = _mm_shuffle_epi32(in1, 0x93)
#endif

#ifdef __AVX512F__
#define ARX(out, in1, in2, s) { \
    __m512i tmp = _mm512_add_epi32(in1, in2); \
    out = _mm512_xor_si512(out, _mm512_slli_epi32(tmp, s)); \
    out = _mm512_xor_si512(out, _mm512_srli_epi32(tmp, 32 - s)); \
}
#else
#define ARX(out, in1, in2, s) { \
    __m128i tmp = _mm_add_epi32(in1, in2); \
    out = _mm_xor_si128(out, _mm_slli_epi32(tmp, s)); \
    out = _mm_xor_si128(out, _mm_srli_epi32(tmp, 32 - s)); \
}
#endif

typedef struct {
    uint64_t aligned_size;
    uint64_t base_size;
    void *base, *aligned;
} yespower_region_t;

#define YESPOWER_WINDOWS_LARGEPAGES 0x4

static inline void start_timer(struct timespec *start) {
    clock_gettime(CLOCK_MONOTONIC, start);
}

static inline void stop_timer(struct timespec *start, struct timespec *end, const char *label) {
    clock_gettime(CLOCK_MONOTONIC, end);
    double elapsed = (end->tv_sec - start->tv_sec) + (end->tv_nsec - start->tv_nsec) / 1e9;
    printf("%s: %f seconds\n", label, elapsed);
}

static int free_region(yespower_region_t *region)
{
    if (region->base) {
#if YESPOWER_WINDOWS_LARGEPAGES
        if (!VirtualFree(region->base, 0, MEM_RELEASE)) {
            fprintf(stderr, "Error freeing memory: %lu\n", GetLastError());
            return -1;
        }
#else
        free(region->base);
#endif
    }
    region->base = region->aligned = NULL;
    region->base_size = region->aligned_size = 0;
    return 0;
}

static int alloc_region(yespower_region_t *region, size_t size, size_t alignment)
{
    size_t base_size = ((size + alignment - 1) / alignment) * alignment;
    uint8_t *base, *aligned;

#if YESPOWER_WINDOWS_LARGEPAGES
    if ((base = VirtualAlloc(NULL, base_size, MEM_COMMIT | MEM_RESERVE | MEM_LARGE_PAGES, PAGE_READWRITE)) == NULL) {
        fprintf(stderr, "Error allocating large pages: %lu\n", GetLastError());
        base = VirtualAlloc(NULL, base_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }
#else
    base = aligned_alloc(alignment, base_size);
#endif
    if (!base) {
        fprintf(stderr, "Error allocating memory\n");
        return 0;
    }

    aligned = base + (alignment - (uintptr_t)base) % alignment;

    region->base = base;
    region->aligned = aligned;
    region->base_size = base_size;
    region->aligned_size = base_size - (aligned - base);

    return 1;
}

#ifdef __AVX512F__
static void salsa20_simd_shuffle(__m512i *X)
{
    __m512i Y[16];
    for (int i = 0; i < 16; i++) {
        Y[i] = _mm512_permutexvar_epi32(_mm512_set_epi32(15,11,7,3,14,10,6,2,13,9,5,1,12,8,4,0), X[i]);
    }
    memcpy(X, Y, sizeof(Y));
}
#else
static void salsa20_simd_shuffle(__m128i *X)
{
    __m128i Y[16];
    for (int i = 0; i < 16; i++) {
        Y[i] = _mm_shuffle_epi32(X[i], 0x93);
    }
    memcpy(X, Y, sizeof(Y));
}
#endif

static void smix(uint8_t *B, size_t r, uint32_t N, void *V, void *XY, void *S)
{
    struct timespec start, end;

    start_timer(&start);
    smix1(B, r, N, V, XY, S);
    stop_timer(&start, &end, "smix1");

    start_timer(&start);
    smix2(B, r, N, V, XY, S);
    stop_timer(&start, &end, "smix2");
}

int yespower(const uint8_t *passwd, size_t passwdlen,
    const uint8_t *salt, size_t saltlen, uint64_t N, uint32_t r, uint32_t p,
    uint8_t *buf, size_t buflen)
{
    yespower_local_t local;
    int retval;

    if ((N < 1024 || N > 512 * 1024 || r < 8 || r > 32 || p < 1 || p > 512) ||
        (!salt && saltlen)) {
        fprintf(stderr, "Invalid parameters: N=%lu, r=%u, p=%u, saltlen=%zu\n",
                (unsigned long)N, r, p, saltlen);
        errno = EINVAL;
        return -1;
    }

    if (buflen < sizeof(yespower_params_t)) {
        fprintf(stderr, "Invalid buffer length: %zu\n", buflen);
        errno = ERANGE;
        return -1;
    }

    if (yespower_init_local(&local)) {
        fprintf(stderr, "Failed to initialize yespower_local\n");
        return -1;
    }

    struct timespec start, end;
    start_timer(&start);
    retval = yespower_tls((yespower_local_t *)&local,
        passwd, passwdlen, salt, saltlen, N, r, p, buf, buflen);
    stop_timer(&start, &end, "yespower_tls");

    if (yespower_free_local(&local)) {
        fprintf(stderr, "Failed to free yespower_local\n");
        return -1;
    }

    return retval;
}

#endif /* _YESPOWER_OPT_C_PASS_ */

#if _YESPOWER_OPT_C_PASS_ == 2

#undef blockmix_salsa
#undef blockmix_salsa_xor
#undef blockmix
#undef blockmix_xor
#undef blockmix_xor_save
#undef smix1
#undef smix2
#undef smix

#define blockmix_salsa blockmix_salsa_1_0
#define blockmix_salsa_xor blockmix_salsa_xor_1_0
#define blockmix blockmix_1_0
#define blockmix_xor blockmix_xor_1_0
#define blockmix_xor_save blockmix_xor_save_1_0
#define smix1 smix1_1_0
#define smix2 smix2_1_0
#define smix smix_1_0

static inline void blockmix_salsa_1_0(const salsa20_blk_t *restrict Bin,
    salsa20_blk_t *restrict Bout, size_t r)
{
    size_t i;
    DECL_X

    READ_X(Bin[2 * r - 1])
    for (i = 0; i < 2 * r; i += 2) {
        XOR_X(Bin[i])
        SALSA20_8(Bout[i])
        XOR_X(Bin[i + 1])
        SALSA20_8(Bout[i + 1])
    }
}

static inline uint32_t blockmix_salsa_xor_1_0(const salsa20_blk_t *restrict Bin1,
    const salsa20_blk_t *restrict Bin2, salsa20_blk_t *restrict Bout, size_t r)
{
    size_t i;
    DECL_X

    READ_X(Bin2[2 * r - 1])
    XOR_X(Bin1[2 * r - 1])
    for (i = 0; i < 2 * r; i += 2) {
        XOR_X(Bin1[i])
        XOR_X(Bin2[i])
        SALSA20_8(Bout[i])
        XOR_X(Bin1[i + 1])
        XOR_X(Bin2[i + 1])
        SALSA20_8(Bout[i + 1])
    }

    return INTEGERIFY;
}

static inline void blockmix_1_0(const salsa20_blk_t *restrict Bin,
    salsa20_blk_t *restrict Bout, size_t r, pwxform_ctx_t *restrict ctx)
{
    size_t i;
    DECL_X

    READ_X(Bin[2 * r - 1])
    for (i = 0; i < 2 * r; i += 2) {
        XOR_X(Bin[i])
        PWXFORM
        SALSA20_8(Bout[i])
        XOR_X(Bin[i + 1])
        PWXFORM
        SALSA20_8(Bout[i + 1])
    }
}

static inline uint32_t blockmix_xor_1_0(const salsa20_blk_t *restrict Bin1,
    const salsa20_blk_t *restrict Bin2, salsa20_blk_t *restrict Bout,
    size_t r, pwxform_ctx_t *restrict ctx)
{
    size_t i;
    DECL_X

    READ_X(Bin2[2 * r - 1])
    XOR_X(Bin1[2 * r - 1])
    for (i = 0; i < 2 * r; i += 2) {
        XOR_X(Bin1[i])
        XOR_X(Bin2[i])
        PWXFORM
        SALSA20_8(Bout[i])
        XOR_X(Bin1[i + 1])
        XOR_X(Bin2[i + 1])
        PWXFORM
        SALSA20_8(Bout[i + 1])
    }

    return INTEGERIFY;
}

static inline uint32_t blockmix_xor_save_1_0(salsa20_blk_t *restrict Bin1out,
    salsa20_blk_t *restrict Bin2, size_t r, pwxform_ctx_t *restrict ctx)
{
    size_t i;
    DECL_X
    DECL_Y

    READ_X(Bin2[2 * r - 1])
    XOR_X_WRITE_XOR_Y_2(Bin2[2 * r - 1], Bin1out[2 * r - 1])
    for (i = 0; i < 2 * r; i += 2) {
        XOR_X_WRITE_XOR_Y_2(Bin2[i], Bin1out[i])
        PWXFORM
        SALSA20_8(Bin1out[i])
        XOR_X_WRITE_XOR_Y_2(Bin2[i + 1], Bin1out[i + 1])
        PWXFORM
        SALSA20_8(Bin1out[i + 1])
    }

    return INTEGERIFY;
}

static void smix1_1_0(uint8_t *B, size_t r, uint32_t N,
    salsa20_blk_t *V, salsa20_blk_t *XY, pwxform_ctx_t *ctx)
{
    size_t s = 2 * r;
    salsa20_blk_t *X = V, *Y = &V[s], *V_j;
    uint32_t i, j, n;

    for (i = 0; i < 2; i++) {
        const salsa20_blk_t *src = (salsa20_blk_t *)&B[i * 64];
        salsa20_blk_t *tmp = Y;
        salsa20_blk_t *dst = &X[i];
        size_t k;
        for (k = 0; k < 16; k++)
            tmp->w[k] = le32dec(&src->w[k]);
        salsa20_simd_shuffle(tmp, dst);
    }

    for (i = 1; i < r; i++)
        blockmix(&X[(i - 1) * 2], &X[i * 2], 1, ctx);

    blockmix(X, Y, r, ctx);
    X = Y + s;
    blockmix(Y, X, r, ctx);
    j = integerify(X, r);

    for (n = 2; n < N; n <<= 1) {
        uint32_t m = (n < N / 2) ? n : (N - 1 - n);
        for (i = 1; i < m; i += 2) {
            Y = X + s;
            j &= n - 1;
            j += i - 1;
            V_j = &V[j * s];
            j = blockmix_xor(X, V_j, Y, r, ctx);
            j &= n - 1;
            j += i;
            V_j = &V[j * s];
            X = Y + s;
            j = blockmix_xor(Y, V_j, X, r, ctx);
        }
    }
    n >>= 1;

    j &= n - 1;
    j += N - 2 - n;
    V_j = &V[j * s];
    Y = X + s;
    j = blockmix_xor(X, V_j, Y, r, ctx);
    j &= n - 1;
    j += N - 1 - n;
    V_j = &V[j * s];
    blockmix_xor(Y, V_j, XY, r, ctx);

    for (i = 0; i < 2 * r; i++) {
        const salsa20_blk_t *src = &XY[i];
        salsa20_blk_t *tmp = &XY[s];
        salsa20_blk_t *dst = (salsa20_blk_t *)&B[i * 64];
        size_t k;
        for (k = 0; k < 16; k++)
            le32enc(&tmp->w[k], src->w[k]);
        salsa20_simd_unshuffle(tmp, dst);
    }
}

static void smix2_1_0(uint8_t *B, size_t r, uint32_t N, uint32_t Nloop,
    salsa20_blk_t *V, salsa20_blk_t *XY, pwxform_ctx_t *ctx)
{
    size_t s = 2 * r;
    salsa20_blk_t *X = XY, *Y = &XY[s];
    uint32_t i, j;

    for (i = 0; i < 2 * r; i++) {
        const salsa20_blk_t *src = (salsa20_blk_t *)&B[i * 64];
        salsa20_blk_t *tmp = Y;
        salsa20_blk_t *dst = &X[i];
        size_t k;
        for (k = 0; k < 16; k++)
            tmp->w[k] = le32dec(&src->w[k]);
        salsa20_simd_shuffle(tmp, dst);
    }

    j = integerify(X, r) & (N - 1);

    do {
        salsa20_blk_t *V_j = &V[j * s];
        j = blockmix_xor_save(X, V_j, r, ctx) & (N - 1);
        V_j = &V[j * s];
        j = blockmix_xor_save(X, V_j, r, ctx) & (N - 1);
    } while (Nloop -= 2);

    for (i = 0; i < 2 * r; i++) {
        const salsa20_blk_t *src = &X[i];
        salsa20_blk_t *tmp = Y;
        salsa20_blk_t *dst = (salsa20_blk_t *)&B[i * 64];
        size_t k;
        for (k = 0; k < 16; k++)
            le32enc(&tmp->w[k], src->w[k]);
        salsa20_simd_unshuffle(tmp, dst);
    }
}

static void smix_1_0(uint8_t *B, size_t r, uint32_t N,
    salsa20_blk_t *V, salsa20_blk_t *XY, pwxform_ctx_t *ctx)
{
    uint32_t Nloop_rw = (N + 2) / 3;
    Nloop_rw++; Nloop_rw &= ~(uint32_t)1;

    smix1_1_0(B, 1, ctx->Sbytes / 128, (salsa20_blk_t *)ctx->S0, XY, NULL);
    smix1_1_0(B, r, N, V, XY, ctx);
    smix2_1_0(B, r, N, Nloop_rw, V, XY, ctx);
}

#endif
