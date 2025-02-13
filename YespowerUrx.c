#include "cpuminer-config.h"
#include "miner.h"
#include "yespower-1.0.1/yespower.h"
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <omp.h> // OpenMP for parallel computing

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

    int found = 0;  // Flag to indicate a valid hash is found

    // Shared hash buffer so threads work together on the same computation
    #pragma omp parallel shared(found)
    {
        int thread_id = omp_get_thread_num();
        int num_threads = omp_get_num_threads();

        // Each thread works on part of the hash computation
        #pragma omp for schedule(static)
        for (i = 0; i < 19; i++) {
            be32enc(&data.u32[i], pdata[i]);  // Each thread encodes part of the data
        }

        // Compute hash in parallel
        #pragma omp single
        {
            be32enc(&data.u32[19], n + 1);
            if (yespower_tls(data.u8, 80, &params, &hash.yb))
                abort();
        }

        // Each thread contributes to checking the result
        #pragma omp for reduction(|:found)
        for (i = 0; i < 7; i++) {
            hash.u32[i] = le32dec(&hash.u32[i]);
        }

        // Only one thread checks the final condition
        #pragma omp single
        {
            if (le32dec(&hash.u32[7]) <= Htarg && fulltest(hash.u32, ptarget)) {
                found = 1;
                *hashes_done = n - pdata[19] + 1;
                pdata[19] = n;
            }
        }
    }

    return found;
}
