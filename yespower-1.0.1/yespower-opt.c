#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <stdlib.h>
#include <emmintrin.h>  // For __m128i

#ifdef _WIN32
#include <windows.h>
#endif

#ifdef __AVX512F__
#include <immintrin.h>
#endif

#ifndef _YESPOWER_OPT_C_PASS_
#define _YESPOWER_OPT_C_PASS_ 1
#endif

// Forward declarations
typedef struct yespower_local_t yespower_local_t;
typedef struct yespower_params_t yespower_params_t;
typedef struct salsa20_blk_t salsa20_blk_t;
typedef struct pwxform_ctx_t pwxform_ctx_t;

// Function prototypes
extern int yespower_tls(yespower_local_t *local,
    const uint8_t *passwd, size_t passwdlen,
    const uint8_t *salt, size_t saltlen,
    uint64_t N, uint32_t r, uint32_t p,
    uint8_t *buf, size_t buflen);
extern int yespower_init_local(yespower_local_t *local);
extern int yespower_free_local(yespower_local_t *local);

#if _YESPOWER_OPT_C_PASS_ == 1

// Windows constants if not defined
#ifndef MEM_COMMIT
#define MEM_COMMIT 0x1000
#endif
#ifndef MEM_RESERVE
#define MEM_RESERVE 0x2000
#endif
#ifndef MEM_RELEASE
#define MEM_RELEASE 0x8000
#endif
#ifndef PAGE_READWRITE
#define PAGE_READWRITE 0x04
#endif

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
    double elapsed = (end-&gt;tv_sec - start-&gt;tv_sec) + (end-&gt;tv_nsec - start-&gt;tv_nsec) / 1e9;
    printf("%s: %f seconds\n", label, elapsed);
}

static int free_region(yespower_region_t *region) {
    if (region-&gt;base) {
#if YESPOWER_WINDOWS_LARGEPAGES
        if (!VirtualFree(region-&gt;base, 0, MEM_RELEASE)) {
            fprintf(stderr, "Error freeing memory: %lu\n", (unsigned long)GetLastError());
            return -1;
        }
#else
        free(region-&gt;base);
#endif
    }
    region-&gt;base = region-&gt;aligned = NULL;
    region-&gt;base_size = region-&gt;aligned_size = 0;
    return 0;
}

static int alloc_region(yespower_region_t *region, size_t size, size_t alignment) {
    size_t base_size = ((size + alignment - 1) / alignment) * alignment;
    uint8_t *base, *aligned;

#if YESPOWER_WINDOWS_LARGEPAGES
    if ((base = VirtualAlloc(NULL, base_size, MEM_COMMIT | MEM_RESERVE | MEM_LARGE_PAGES, PAGE_READWRITE)) == NULL) {
        fprintf(stderr, "Error allocating large pages: %lu\n", (unsigned long)GetLastError());
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

    region-&gt;base = base;
    region-&gt;aligned = aligned;
    region-&gt;base_size = base_size;
    region-&gt;aligned_size = base_size - (aligned - base);

    return 1;
}

#ifdef __AVX512F__
static void salsa20_simd_shuffle(__m512i *X) {
    __m512i Y[16];
    for (int i = 0; i &lt; 16; i++) {
        Y[i] = _mm512_permutexvar_epi32(_mm512_set_epi32(15,11,7,3,14,10,6,2,13,9,5,1,12,8,4,0), X[i]);
    }
    memcpy(X, Y, sizeof(Y));
}
#else
static void salsa20_simd_shuffle(__m128i *X) {
    __m128i Y[16];
    for (int i = 0; i &lt; 16; i++) {
        Y[i] = _mm_shuffle_epi32(X[i], 0x93);
    }
    memcpy(X, Y, sizeof(Y));
}
#endif

int yespower(const uint8_t *passwd, size_t passwdlen,
    const uint8_t *salt, size_t saltlen, uint64_t N, uint32_t r, uint32_t p,
    uint8_t *buf, size_t buflen)
{
    yespower_local_t local;
    int retval;

    if ((N &lt; 1024 || N &gt; 512 * 1024 || r &lt; 8 || r &gt; 32 || p &lt; 1 || p &gt; 512) ||
        (!salt &amp;&amp; saltlen)) {
        fprintf(stderr, "Invalid parameters: N=%lu, r=%u, p=%u, saltlen=%zu\n",
                (unsigned long)N, r, p, saltlen);
        errno = EINVAL;
        return -1;
    }

    if (buflen &lt; sizeof(yespower_params_t)) {
        fprintf(stderr, "Invalid buffer length: %zu\n", buflen);
        errno = ERANGE;
        return -1;
    }

    if (yespower_init_local(&amp;local)) {
        fprintf(stderr, "Failed to initialize yespower_local\n");
        return -1;
    }

    struct timespec start, end;
    start_timer(&amp;start);
    retval = yespower_tls((yespower_local_t *)&amp;local,
        passwd, passwdlen, salt, saltlen, N, r, p, buf, buflen);
    stop_timer(&amp;start, &amp;end, "yespower_tls");

    if (yespower_free_local(&amp;local)) {
        fprintf(stderr, "Failed to free yespower_local\n");
        return -1;
    }

    return retval;
}

#endif /* _YESPOWER_OPT_C_PASS_ */

#if _YESPOWER_OPT_C_PASS_ == 2
// [Existing implementation for pass 2 remains unchanged]
#endif
