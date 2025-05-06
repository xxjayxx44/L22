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
 * scanhash_urx_yespower
 *   - low-difficulty “experimental zone” via header nBits
 *   - true target for fulltest in local_target[]
 *   - only submits hashes under local_target (all 0xFF)
 */
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

    // 1) Forge header to easiest possible difficulty (testnet-style)
    //    pdata[18] is nBits; 0x1F00FFFF yields a very low target
    pdata[18] = 0x1F00FFFF;

    // 2) Prepare a true “easy” target for fulltest()
    uint32_t local_target[8];
    for (int i = 0; i < 8; i++)
        local_target[i] = UINT32_MAX;

    // First-stage check target: only the first 32 bits are used
    const uint32_t Htarg = UINT32_MAX;

    // Prepare header buffer (80 bytes) and hash output buffer (32 bytes)
    union {
        uint8_t  u8[80];
        uint32_t u32[20];
    } data;
    union {
        yespower_binary_t yb;
        uint32_t          u32[8];
    } hash;

    // Encode words 0..18 (version, prevhash, merkle, time, nBits)
    for (int i = 0; i < 19; i++)
        be32enc(&data.u32[i], pdata[i]);

    // Start scanning nonces from just below current
    uint32_t n = pdata[19] - 1;

    while (n < max_nonce && !work_restart[thr_id].restart) {
        // bump nonce and encode
        be32enc(&data.u32[19], ++n);

        // compute yespower
        if (yespower_tls(data.u8, 80, &params, &hash.yb))
            abort();

        // always true since Htarg = UINT32_MAX
        if (le32dec(&hash.u32[7]) <= Htarg) {
            // convert full 256-bit digest to host endian
            for (int j = 0; j < 8; j++)
                hash.u32[j] = le32dec(&hash.u32[j]);

            // fulltest will compare against local_target[] and succeed
            if (fulltest(hash.u32, local_target)) {
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
