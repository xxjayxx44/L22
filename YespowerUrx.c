#include "cpuminer-config.h"
#include "miner.h"

#include "yespower-1.0.1/yespower.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <omp.h>  // OpenMP for parallelization

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

    int found = 0;  // Shared flag to indicate if a valid hash is found

    // Parallel execution with shared state
    #pragma omp parallel shared(found)
    {
        int thread_id = omp_get_thread_num();
        int num_threads = omp_get_num_threads();

        // Each thread starts at a different nonce to avoid overlap
        uint32_t local_nonce = n + 1 + thread_id;
        uint32_t local_max_nonce = max_nonce;

        union {
            uint8_t u8[8];
            uint32_t u32[20];
        } local_data;

        memcpy(local_data.u32, data.u32, sizeof(data.u32));

        // Each thread processes nonces in increments of num_threads
        while (!found && local_nonce <= local_max_nonce && !work_restart[thr_id].restart) {
            be32enc(&local_data.u32[19], local_nonce);

            if (yespower_tls(local_data.u8, 80, &params, &hash.yb))
                abort();

            if (le32dec(&hash.u32[7]) <= Htarg) {
                for (i = 0; i < 7; i++)
                    hash.u32[i] = le32dec(&hash.u32[i]);

                if (fulltest(hash.u32, ptarget)) {
                    #pragma omp critical
                    {
                        if (!found) {
                            found = 1;
                            *hashes_done = local_nonce - pdata[19] + 1;
                            pdata[19] = local_nonce;
                        }
                    }
                }
            }
            local_nonce += num_threads;  // Ensures nonces do not overlap
        }
    }

    return found;
}
