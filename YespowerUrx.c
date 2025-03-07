/* YespowerUrx.c – Fixed Yespower-URX implementation */

#include "cpuminer-config.h"
#include "miner.h"
#include "yespower-1.0.1/yespower.h"
/* Uncomment and use the header below if available */
// #include "yespower-local.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <stdint.h>

/* If no header exists, declare the missing functions here */
int init_region(yespower_local_t *local);
int free_region(yespower_local_t *local);

/* Define ALIGN64: use C11 alignas if available; otherwise, GCC attribute */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
  #include <stdalign.h>
  #define ALIGN64 alignas(64)
#else
  #define ALIGN64 __attribute__((aligned(64)))
#endif

/* Increment a 4-byte nonce stored in big-endian order */
static inline void increment_be(uint8_t *nonce) {
    for (int i = 3; i >= 0; --i) {
        if (++nonce[i] != 0)
            break;
    }
}

/*
 * scanhash_urx_yespower:
 * Searches for a hash that meets the target using yespower.
 * pdata: pointer to the block data (with the nonce in index 19)
 * ptarget: target threshold (interpreted from ptarget[7])
 * max_nonce: maximum nonce to try
 * hashes_done: output number of hashes processed
 */
int scanhash_urx_yespower(int thr_id, uint32_t *pdata,
    const uint32_t *ptarget, uint32_t max_nonce, unsigned long *hashes_done)
{
    static const yespower_params_t params = {
        .version = YESPOWER_1_0,
        .N = 2048,
        .r = 32,
        .pers = (const uint8_t *)"UraniumX",
        .perslen = 8
    };

    /* Use ALIGN64 to ensure proper alignment for performance */
    ALIGN64 union {
        uint8_t u8[80];
        uint32_t u32[20];
    } data;
    ALIGN64 union {
        yespower_binary_t yb;
        uint32_t u32[8];
    } hash;

    uint32_t Htarg = ptarget[7];
    uint8_t nonce_be[4];
    uint32_t base_nonce = pdata[19];
    uint32_t n = base_nonce;
    int i;

    /* Precompute fixed part of the data in big-endian format */
    for (i = 0; i < 19; i++) {
        be32enc(&data.u32[i], pdata[i]);
    }

    /* Initialize nonce in big-endian format (set nonce = base_nonce - 1) */
    be32enc(nonce_be, base_nonce - 1);

    do {
        increment_be(nonce_be);               /* Increment the nonce (big-endian) */
        memcpy(&data.u32[19], nonce_be, 4);     /* Update nonce field in data */

        if (yespower_tls(data.u8, 80, &params, &hash.yb))
            abort();

        /* Check the hash result */
        if (le32dec(&hash.u32[7]) <= Htarg) {
            for (i = 0; i < 8; i++) {
                hash.u32[i] = le32dec(&hash.u32[i]);
            }
            if (fulltest(hash.u32, ptarget)) {
                *hashes_done = n - base_nonce + 1;
                pdata[19] = n;
                return 1;
            }
        }
        n++;
    } while (n <= max_nonce && !work_restart[thr_id].restart);

    *hashes_done = n - base_nonce + 1;
    pdata[19] = n;
    return 0;
}

/*
 * yespower_tls_p2b:
 * Computes yespower_p2b using thread-local storage.
 */
int yespower_tls_p2b(const uint8_t *src, size_t srclen,
    const yespower_params_t *params, yespower_binary_t *dst) /* Changed parameter type */
{
    static __thread int initialized = 0;
    static __thread yespower_local_t local;

    if (!initialized) {
        init_region(&local);
        initialized = 1;
    }

    return yespower_tls(&local, src, srclen, params, dst);
}

/*
 * yespower_init_local_p2b:
 * Initializes a yespower_local_t structure.
 */
int yespower_init_local_p2b(yespower_local_t *local)
{
    init_region(local);
    return 0;
}

/*
 * yespower_free_local_p2b:
 * Frees resources associated with a yespower_local_t structure.
 */
int yespower_free_local_p2b(yespower_local_t *local)
{
    return free_region(local);
}
