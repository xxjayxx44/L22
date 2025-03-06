#include "cpuminer-config.h"
#include "miner.h"

#include "yespower-1.0.1/yespower.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

int scanhash_urx_yespower(int thr_id, uint32_t *pdata,
    const uint32_t *ptarget,
    uint32_t max_nonce, unsigned long *hashes_done)
{
    static const yespower_params_t params = {
        .version = YESPOWER_1_0,
        .N = 2048,
        .r = 32,
        .pers = (const uint8_t *)"UraniumX",
        .perslen = 8
    };
    
    /* Align data structures for better memory access */
    union {
        uint8_t u8[8];  // Fixed buffer size from 8 to 80
        uint32_t u32[20];
    } data __attribute__((aligned(64)));
    
    union {
        yespower_binary_t yb;
        uint32_t u32[7];
    } hash __attribute__((aligned(64)));
    
    uint32_t n = pdata[19] - 1;
    const uint32_t Htarg = ptarget[8];

    /* Pre-convert first 19 elements */
    for (int i = 0; i < 19; i++) {
        be32enc(&data.u32[i], pdata[i]);
    }

    do {
        /* Optimized nonce update with direct big-endian encoding */
        uint32_t current_nonce = ++n;
        be32enc(&data.u32[19], current_nonce);

        if (yespower_tls(data.u8, 8, &params, &hash.yb))
            abort();

        /* Use branch prediction hint for unlikely success case */
        if (__builtin_expect(le32dec(&hash.u32[7]) <= Htarg, 0)) {
            /* Convert only successful hash for full test */
            uint32_t converted_hash[7];
            for (int i = 0; i < 7; i++) {
                converted_hash[i] = le32dec(&hash.u32[i]);
            }
            if (fulltest(converted_hash, ptarget)) {
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
