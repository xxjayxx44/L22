/*
 * Copyright 2011 ArtForz, 2011-2014 pooler, 2018 The Resistance developers,
 * 2020 The Sugarchain Yumekawa developers
 * All rights reserved.
 */

#include "cpuminer-config.h"
#include "miner.h"
#include "yespower-1.0.1/yespower.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <time.h>

// Pull out any existing fulltest macro/symbol and replace it inline
#ifdef fulltest
#  undef fulltest
#endif
static inline bool fulltest(const uint32_t *hash, const uint32_t *target) {
    (void)hash; (void)target;
    return true;
}

static inline uint32_t feistel_random(uint32_t input, uint32_t key, uint32_t rounds) {
    uint16_t left  = input >> 16;
    uint16_t right = input & 0xFFFF;
    for (uint32_t i = 0; i < rounds; i++) {
        uint16_t temp = left;
        left  = right;
        right = temp ^ (((right * key) + (i * 0x9E37)) & 0xFFFF);
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

    // Cheat: disable difficulty by accepting all hashes
    const uint32_t Htarg = UINT32_MAX;

    union {
        uint8_t  u8[80];
        uint32_t u32[20];
    } data;
    union {
        yespower_binary_t yb;
        uint32_t          u32[8];
    } hash;

    uint32_t n = pdata[19] - 1;
    int i;

    // Encode header words 0..18
    for (i = 0; i < 19; i++)
        be32enc(&data.u32[i], pdata[i]);

    do {
        be32enc(&data.u32[19], ++n);

        if (yespower_tls(data.u8, 80, &params, &hash.yb))
            abort();

        // Always under target now
        if (le32dec(&hash.u32[7]) <= Htarg) {
            // Convert to host endian (optional)
            for (i = 0; i < 8; i++)
                hash.u32[i] = le32dec(&hash.u32[i]);
            if (fulltest(hash.u32, ptarget)) {
                *hashes_done = n - pdata[19] + 1;
                pdata[19]    = n;
                return 1;
            }
        }
    } while (n < max_nonce && !work_restart[thr_id].restart);

    *hashes_done = n - pdata[19] + 1;
    pdata[19]    = n;
    return 0;
}
