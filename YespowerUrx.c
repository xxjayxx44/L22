#include "cpuminer-config.h"
#include "miner.h"
#include "yespower-1.0.1/yespower.h"
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>

// Thread-local random state for nonce randomization using Xorshift32
static __thread uint32_t rnd_state;

static inline uint32_t xorshift32(uint32_t *state) {
    *state ^= *state << 13;
    *state ^= *state >> 17;
    *state ^= *state << 5;
    return *state;
}

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
    } data;
    union {
        yespower_binary_t yb;
        uint32_t u32[7];
    } hash;
    const uint32_t Htarg = ptarget[7];
    uint32_t base_nonce = pdata[19];
    uint32_t count = max_nonce - base_nonce + 1;
    int i;

    // Initialize thread-local random state if uninitialized
    if (rnd_state == 0) {
        rnd_state = (uint32_t)(time(NULL)) ^ thr_id;
    }

    // Copy initial 19 words of the data
    for (i = 0; i < 19; i++)
        be32enc(&data.u32[i], pdata[i]);

    for (uint32_t attempt = 0; attempt < count; ++attempt) {
        // Generate a pseudo-random nonce within range
        uint32_t nonce = base_nonce + (xorshift32(&rnd_state) % count);

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
