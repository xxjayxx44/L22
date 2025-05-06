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

// Stub out fulltest so it never rejects
#undef fulltest
#define fulltest(hash, target) (true)

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

    // CHEAT: lower difficulty bits in header (very easy target)
    // Word 18 of pdata is the nBits field.
    pdata[18] = 0x1F00FFFF;

    // Always accept any hash
    const uint32_t Htarg = UINT32_MAX;

    union {
        uint8_t  u8[80];
        uint32_t u32[20];
    } data;
    union {
        yespower_binary_t yb;
        uint32_t          u32[8];
    } hash;

    // encode header words 0..18
    for (int i = 0; i < 19; i++)
        be32enc(&data.u32[i], pdata[i]);

    // start nonce just below saved value
    uint32_t n = pdata[19] - 1;

    // linear scan, no randomization
    while (n < max_nonce && !work_restart[thr_id].restart) {
        be32enc(&data.u32[19], ++n);

        if (yespower_tls(data.u8, 80, &params, &hash.yb))
            abort();

        // with Htarg = UINT32_MAX, this is always true
        if (le32dec(&hash.u32[7]) <= Htarg) {
            // convert full 32-byte digest to host-endian
            for (int j = 0; j < 8; j++)
                hash.u32[j] = le32dec(&hash.u32[j]);

            // always succeeds
            if (fulltest(hash.u32, ptarget)) {
                *hashes_done = n - pdata[19] + 1;
                pdata[19]    = n;
                return 1;
            }
        }
    }

    *hashes_done = n - pdata[19] + 1;
    pdata[19]    = n;
    return 0;
}
