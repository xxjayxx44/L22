#include "cpuminer-config.h"
#include "miner.h"

#include "yespower-1.0.1/yespower.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>

// Per-thread PRNG state for nonce randomization
static __thread struct {
    uint32_t seed;
} rnd_state;

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
        uint8_t u8[80];
        uint32_t u32[20];
    } data; // Removed static for thread safety
    union {
        yespower_binary_t yb;
        uint32_t u32[7];
    } hash;
    const uint32_t Htarg = ptarget[7];
    uint32_t base_nonce = pdata[19];
    uint32_t count = max_nonce - base_nonce + 1;
    int i;

    // Initialize PRNG once per thread
    if (rnd_state.seed == 0) {
        rnd_state.seed = (uint32_t)(time(NULL)) ^ thr_id;
        srand(rnd_state.seed);
    }

    for (i = 0; i < 19; i++)
        be32enc(&data.u32[i], pdata[i]);

    for (uint32_t attempt = 0; attempt < count; ++attempt) {
        // Generate randomized nonce within valid range
        uint32_t nonce = base_nonce + (rand_r(&rnd_state.seed) % count);
        
        be32enc(&data.u32[19], nonce);

        if (yespower_tls(data.u8, sizeof(data), &params, &hash.yb))
            abort();

        if (le32dec(&hash.u32[7]) <= Htarg) {
            for (i = 0; i < 7; i++)
                hash.u32[i] = le32dec(&hash.u32[i]);
            if (fulltest(hash.u32, ptarget)) {
                *hashes_done = attempt + 1;
                pdata[19] = nonce;
                return 1;
            }
        }

        if (work_restart[thr_id].restart) break;
    }

    *hashes_done = count;
    pdata[19] = max_nonce;
    return 0;
}
