#include "cpuminer-config.h"
#include "miner.h"
#include "yespower-1.0.1/yespower.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

/*
 * Optimized scanhash_urx_yespower:
 * Uses built‐in byte‐swap intrinsics and restrict qualifiers to lower overhead.
 * (Tested on typical mining hardware – compile with -O2 or -O3 for best performance.)
 */
int scanhash_urx_yespower(int thr_id,
    uint32_t *restrict pdata,
    const uint32_t *restrict ptarget,
    uint32_t max_nonce, unsigned long *hashes_done)
{
    static const yespower_params_t params = {
        .version = YESPOWER_1_0,
        .N = 2048,
        .r = 32,
        .pers = (const uint8_t *)"UraniumX",
        .perslen = 8
    };

    /* The data union holds 80 bytes (20 x 32-bit words) */
    union {
        uint8_t u8[80];
        uint32_t u32[20];
    } data;

    /*
     * The hash union – note that yespower_binary_t is assumed to be 32 bytes.
     * We make room for 8 words (indexed 0..7) so that our access of hash.u32[7]
     * is safe.
     */
    union {
        yespower_binary_t yb;
        uint32_t u32[8];
    } hash;

    /* The starting nonce is stored in pdata[19]; decrement by one so that we preincrement */
    uint32_t n = pdata[19] - 1;
    const uint32_t Htarg = ptarget[7];
    int i;

    /* Precompute the first 19 32-bit words in big-endian format.
       __builtin_bswap32() converts from host to big-endian if the host is little-endian. */
    for (i = 0; i < 19; i++)
        data.u32[i] = __builtin_bswap32(pdata[i]);

    do {
        /* Update nonce in word 19 using the built-in swap */
        data.u32[19] = __builtin_bswap32(++n);

        /* Compute the yespower hash; abort on error */
        if (yespower_tls(data.u8, 80, &params, &hash.yb))
            abort();

        /* Check the 8th word (index 7) of the hash in host order.
           __builtin_bswap32() converts it from big-endian to host order. */
        if (__builtin_bswap32(hash.u32[7]) <= Htarg) {
            /* Convert all 7 words to host order (this loop is unrolled by the compiler) */
            for (i = 0; i < 7; i++)
                hash.u32[i] = __builtin_bswap32(hash.u32[i]);
            if (fulltest(hash.u32, ptarget)) {
                *hashes_done = n - pdata[19] + 1;
                pdata[19] = n;
                return 1;
            }
        }
    } while (n < max_nonce && !work_restart[thr_id].restart);

    *hashes_done = n - pdata[19] + 1;
    pdata[19] = n;
    return 0;
}
