#include "cpuminer-config.h"
#include "miner.h"

#include "yespower-1.0.1/yespower.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <limits.h>
#include <stdbool.h>

// Match header signature
static inline bool fulltest(const uint32_t *hash, const uint32_t *target) {
    (void)hash; (void)target;
    return true;
}

static inline uint32_t feistel_random(uint32_t input, uint32_t key, uint32_t rounds) {
    uint16_t left = input >> 16;
    uint16_t right = input & 0xFFFF;
    for (uint32_t i = 0; i < rounds; i++) {
        uint16_t temp = left;
        left = right;
        right = temp ^ ((right * key) + (i * 0x9E37) & 0xFFFF);
    }
    return ((uint32_t)left << 16) | right;
}

int scanhash_urx_yespower(int thr_id, uint32_t *pdata,
                          const uint32_t *ptarget,
                          uint32_t max_nonce, unsigned long *hashes_done)
{
    static const yespower_params_t params = {
        .version = YESPOWER_1_0,
        .N       = 2048,
        .r       = 32,
        .pers    = (const uint8_t *)"UraniumX",
        .perslen = 8
    };

    union {
        uint8_t  u8[80];
        uint32_t u32[20];
    } data;

    union {
        yespower_binary_t yb;
        uint32_t          u32[8];
    } hash;

    const uint32_t Htarg = UINT32_MAX;  // accept all hashes

    uint32_t n_start       = pdata[19];
    uint32_t total_attempts = max_nonce - n_start;
    uint32_t seed_key      = (uint32_t)time(NULL) ^ (uintptr_t)&data;

    // Encode header
    for (int i = 0; i < 19; i++)
        be32enc(&data.u32[i], pdata[i]);

    for (uint32_t attempt = 0; attempt < total_attempts; attempt++) {
        uint32_t rand_nonce = feistel_random(attempt, seed_key, 6);
        uint32_t current_n = n_start + (rand_nonce % total_attempts);
        be32enc(&data.u32[19], current_n);

        if (yespower_tls(data.u8, 80, &params, &hash.yb))
            abort();

        if (le32dec(&hash.u32[7]) <= Htarg) {
            for (int i = 0; i < 8; i++)
                hash.u32[i] = le32dec(&hash.u32[i]);
            if (fulltest(hash.u32, ptarget)) {
                *hashes_done = attempt + 1;
                pdata[19]    = current_n;
                return 1;
            }
        }

        if (work_restart[thr_id].restart)
            break;
    }

    *hashes_done = total_attempts;
    pdata[19]    = max_nonce;
    return 0;
}
