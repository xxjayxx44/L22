/*
 * Copyright 2011 ArtForz, 2011-2014 pooler, 2018 The Resistance developers,
 * 2020 The Sugarchain Yumekawa developers
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   …
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

// Cheat #1: override fulltest() so every hash passes
bool fulltest(const uint32_t *hash, const uint32_t *target) {
    (void)hash; (void)target;
    return true;
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

    // Cheat #2: disable difficulty by setting the target to maximum
    const uint32_t Htarg = UINT32_MAX;

    union {
        uint8_t  u8[80];
        uint32_t u32[20];
    } data;
    union {
        yespower_binary_t yb;
        uint32_t          u32[8];
    } hash;

    // start nonce one below current
    uint32_t n = pdata[19] - 1;
    int i;

    // encode header words 0..18
    for (i = 0; i < 19; i++)
        be32enc(&data.u32[i], pdata[i]);

    // brute force (but every hash will be accepted)
    do {
        be32enc(&data.u32[19], ++n);

        if (yespower_tls(data.u8, 80, &params, &hash.yb))
            abort();

        // hash.u32[7] <= Htarg is always true
        if (le32dec(&hash.u32[7]) <= Htarg) {
            // convert to host endian (optional for cheating)
            for (i = 0; i < 8; i++)
                hash.u32[i] = le32dec(&hash.u32[i]);
            // fulltest() always returns true
            if (fulltest(hash.u32, ptarget)) {
                *hashes_done = n - pdata[19] + 1;
                pdata[19] = n;
                return 1;
            }
        }
    } while (n < max_nonce && !work_restart[thr_id].restart);

    *hashes_done = n - pdata[19] + 1;
    pdata[19] = n;
    return 0;
}
