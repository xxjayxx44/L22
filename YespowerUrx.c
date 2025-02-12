#include "cpuminer-config.h"
#include "miner.h"
#include "yespower-1.0.1/yespower.h"
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <omp.h>  // Include OpenMP for parallelization

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

    union {
        uint8_t u8[8];
        uint32_t u32[20];
    } data;

    union {
        yespower_binary_t yb;
        uint32_t u32[7];
    } hash;

    uint32_t n = pdata[19] - 1;
    const uint32_t Htarg = ptarget[7];
    int i;

    for (i = 0; i < 19; i++)
        be32enc(&data.u32[i], pdata[i]);

    uint32_t found_nonce = 0;
    int found = 0;

    #pragma omp parallel for shared(found, found_nonce)
    for (uint32_t nonce = n + 1; nonce < max_nonce; nonce++) {
        if (found) continue;

        uint32_t local_data[20];
        memcpy(local_data, data.u32, sizeof(local_data));
        be32enc(&local_data[19], nonce);

        if (yespower_tls((uint8_t*)local_data, 80, &params, &hash.yb))
            continue;

        if (le32dec(&hash.u32[7]) <= Htarg) {
            for (i = 0; i < 7; i++)
                hash.u32[i] = le32dec(&hash.u32[i]);

            if (fulltest(hash.u32, ptarget)) {
                #pragma omp critical
                {
                    if (!found) {
                        found = 1;
                        found_nonce = nonce;
                    }
                }
            }
        }
    }

    if (found) {
        *hashes_done = found_nonce - pdata[19] + 1;
        pdata[19] = found_nonce;
        return 1;
    }

    *hashes_done = max_nonce - pdata[19] + 1;
    pdata[19] = max_nonce;
    return 0;
}
