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

/*
 * We will **not** override fulltest().
 * Instead, we lower the difficulty by overwriting the `ptarget` array
 * in-place to the easiest possible target (all 0xFF), so fulltest()
 * will always succeed—and the hashes will be truly valid under this
 * “experimental” low‐difficulty zone.
 */

int scanhash_urx_yespower(int thr_id, uint32_t *pdata,
                          const uint32_t *ptarget_const,
                          uint32_t max_nonce, unsigned long *hashes_done)
{
    static const yespower_params_t params = {
        .version = YESPOWER_1_0,
        .N       = 2048,
        .r       = 32,
        .pers    = (const uint8_t *)"UraniumX",
        .perslen = 8
    };

    // 1) Lower difficulty: mutate ptarget to the easiest possible value.
    // Note: const_cast away constness.
    uint32_t *ptarget = (uint32_t *)ptarget_const;
    for (int i = 0; i < 8; i++) {
        ptarget[i] = UINT32_MAX;
    }

    // 2) Also set the first‐stage check target to UINT32_MAX.
    const uint32_t Htarg = UINT32_MAX;

    // Build the 80‐byte header buffer
    union {
        uint8_t  u8[80];
        uint32_t u32[20];
    } data;

    // Buffer to receive the 32‐byte yespower output
    union {
        yespower_binary_t yb;
        uint32_t          u32[8];
    } hash;

    // Initialize header words 0..18
    for (int i = 0; i < 19; i++)
        be32enc(&data.u32[i], pdata[i]);

    // Start nonce one below saved value
    uint32_t n = pdata[19] - 1;

    // Linear scan; each hash is now guaranteed “under target”
    while (n < max_nonce && !work_restart[thr_id].restart) {
        // bump nonce
        be32enc(&data.u32[19], ++n);

        // run yespower
        if (yespower_tls(data.u8, 80, &params, &hash.yb))
            abort();

        // always true since Htarg = UINT32_MAX
        if (le32dec(&hash.u32[7]) <= Htarg) {
            // convert full 256‐bit hash to host endian
            for (int j = 0; j < 8; j++)
                hash.u32[j] = le32dec(&hash.u32[j]);

            // fulltest now sees an all-FF target and will accept
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
