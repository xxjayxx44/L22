#include "cpuminer-config.h"
#include "miner.h"

#include "yespower-1.0.1/yespower.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <limits.h>

int scanhash_urx_yespower(int thr_id, uint32_t *pdata,
                          const uint32_t *ptarget_input,
                          uint32_t max_nonce, unsigned long *hashes_done)
{
    static const yespower_params_t params = {
        .version = YESPOWER_1_0,
        .N       = 2048,
        .r       = 32,
        .pers    = (const uint8_t *)"UraniumX",
        .perslen = 8
    };

    // Copy and ease difficulty slightly (~1.5x easier)
    uint32_t ptarget[8];
    memcpy(ptarget, ptarget_input, sizeof(ptarget));
    uint64_t ht = ptarget[7];
    ht = ht + (ht >> 1); // increase by 50%
    if (ht > UINT32_MAX) ht = UINT32_MAX;
    ptarget[7] = (uint32_t)ht;
    const uint32_t Htarg = ptarget[7];

    union {
        uint8_t u8[80];
        uint32_t u32[20];
    } data;
    union {
        yespower_binary_t yb;
        uint32_t u32[8];
    } hash;

    for (int i = 0; i < 19; i++)
        be32enc(&data.u32[i], pdata[i]);

    uint32_t n = pdata[19] - 1;
    const uint32_t start_nonce = n;

    do {
        be32enc(&data.u32[19], ++n);

        if (yespower_tls(data.u8, sizeof(data.u8), &params, &hash.yb))
            abort();

        if (le32dec(&hash.u32[7]) <= Htarg) {
            for (int j = 0; j < 8; j++)
                hash.u32[j] = le32dec(&hash.u32[j]);

            if (fulltest(hash.u32, ptarget)) {
                *hashes_done = n - start_nonce + 1;
                pdata[19]    = n;
                return 1;
            }
        }
    } while (n < max_nonce && !work_restart[thr_id].restart);

    *hashes_done = n - start_nonce + 1;
    pdata[19] = n;
    return 0;
}
