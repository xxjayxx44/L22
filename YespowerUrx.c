#include "cpuminer-config.h"
#include "miner.h"

#include "yespower-1.0.1/yespower.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

static inline uint32_t permute_index(uint32_t index, uint32_t rounds, uint32_t key) {
    uint32_t left = (index >> 16) & 0xFFFF;
    uint32_t right = index & 0xFFFF;
    for (uint32_t i = 0; i < rounds; i++) {
        uint32_t temp = left;
        left = right;
        right = temp ^ ((right * key) & 0xFFFF);
    }
    return (left << 16) | right;
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
        uint8_t u8[8];
        uint32_t u32[20];
    } data;
    union {
        yespower_binary_t yb;
        uint32_t u32[7];
    } hash;
    uint32_t n_start = pdata[19];
    const uint32_t Htarg = ptarget[7];
    int i;
    uint32_t total_attempts = max_nonce - n_start;

    for (i = 0; i < 19; i++)
        be32enc(&data.u32[i], pdata[i]);

    for (uint32_t attempt = 0; attempt < total_attempts; attempt++) {
        // Generate permuted nonce using Feistel network
        uint32_t permuted = permute_index(attempt, 4, 0x1234);
        uint32_t current_n = n_start + (permuted % total_attempts);

        if (current_n >= max_nonce)
            current_n = n_start + (permuted % (total_attempts - 1));

        be32enc(&data.u32[19], current_n);

        if (yespower_tls(data.u8, 80, &params, &hash.yb))
            abort();

        if (le32dec(&hash.u32[7]) <= Htarg) {
            for (i = 0; i < 7; i++)
                hash.u32[i] = le32dec(&hash.u32[i]);
            if (fulltest(hash.u32, ptarget)) {
                *hashes_done = attempt + 1;
                pdata[19] = current_n;
                return 1;
            }
        }

        if (work_restart[thr_id].restart)
            break;
    }

    *hashes_done = total_attempts;
    pdata[19] = max_nonce;
    return 0;
}
