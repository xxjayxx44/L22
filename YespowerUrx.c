/*
 * Copyright 2011 ArtForz, 2011-2014 pooler,
 * 2018 The Resistance developers,
 * 2020 The Sugarchain Yumekawa developers
 * All rights reserved.
 */

#include "cpuminer-config.h"
#include "miner.h"
#include "yespower-1.0.1/yespower.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

/*
 * High-performance YespowerURX scanhash for Celeron N4020
 *   - honors the real pool difficulty (ptarget)
 *   - loop unrolled 4×, with deferred endian-conversions
 *   - only returns when fulltest() confirms a true 256-bit hit
 */
int scanhash_urx_yespower(int thr_id, uint32_t *pdata,
                          const uint32_t *ptarget,
                          uint32_t max_nonce, unsigned long *hashes_done)
__attribute__((optimize("unroll-loops")))
{
    static const yespower_params_t params = {
        .version = YESPOWER_1_0,
        .N       = 2048,
        .r       = 32,
        .pers    = (const uint8_t *)"UraniumX",
        .perslen = 8
    };

    // First-stage cutoff: top 32 bits of the 256-bit digest
    const uint32_t Htarg = ptarget[7];

    // 80-byte header buffer, aligned to cache line
    uint32_t data_u32[20] __attribute__((aligned(64)));
    uint8_t  *data_u8 = (uint8_t *)data_u32;

    // 32-byte output buffer, aligned
    yespower_binary_t yb __attribute__((aligned(64)));
    uint32_t *hash_u32 = (uint32_t *)&yb;

    // Pre-encode words 0..18 (version, prevhash, merkle, time, nBits)
    for (int i = 0; i < 19; i++)
        be32enc(&data_u32[i], pdata[i]);

    uint32_t nonce = pdata[19] - 1;
    uint32_t done  = 0;

    // Unrolled loop: 4 nonces per iteration
    while (nonce + 4 < max_nonce && !work_restart[thr_id].restart) {
        // #1
        be32enc(&data_u32[19], ++nonce);
        yespower_tls(data_u8, sizeof(data_u8[0]) * 20, &params, &yb);
        if (le32dec(&hash_u32[7]) <= Htarg) {
            for (int j = 0; j < 8; j++) hash_u32[j] = le32dec(&hash_u32[j]);
            if (fulltest(hash_u32, ptarget)) {
                *hashes_done = done + 1;
                pdata[19]    = nonce;
                return 1;
            }
        }
        done++;

        // #2
        be32enc(&data_u32[19], ++nonce);
        yespower_tls(data_u8, sizeof(data_u8[0]) * 20, &params, &yb);
        if (le32dec(&hash_u32[7]) <= Htarg) {
            for (int j = 0; j < 8; j++) hash_u32[j] = le32dec(&hash_u32[j]);
            if (fulltest(hash_u32, ptarget)) {
                *hashes_done = done + 1;
                pdata[19]    = nonce;
                return 1;
            }
        }
        done++;

        // #3
        be32enc(&data_u32[19], ++nonce);
        yespower_tls(data_u8, sizeof(data_u8[0]) * 20, &params, &yb);
        if (le32dec(&hash_u32[7]) <= Htarg) {
            for (int j = 0; j < 8; j++) hash_u32[j] = le32dec(&hash_u32[j]);
            if (fulltest(hash_u32, ptarget)) {
                *hashes_done = done + 1;
                pdata[19]    = nonce;
                return 1;
            }
        }
        done++;

        // #4
        be32enc(&data_u32[19], ++nonce);
        yespower_tls(data_u8, sizeof(data_u8[0]) * 20, &params, &yb);
        if (le32dec(&hash_u32[7]) <= Htarg) {
            for (int j = 0; j < 8; j++) hash_u32[j] = le32dec(&hash_u32[j]);
            if (fulltest(hash_u32, ptarget)) {
                *hashes_done = done + 1;
                pdata[19]    = nonce;
                return 1;
            }
        }
        done++;
    }

    // Tail: process remaining nonces one-by-one
    while (nonce < max_nonce && !work_restart[thr_id].restart) {
        be32enc(&data_u32[19], ++nonce);
        yespower_tls(data_u8, sizeof(data_u8[0]) * 20, &params, &yb);
        if (le32dec(&hash_u32[7]) <= Htarg) {
            for (int j = 0; j < 8; j++) hash_u32[j] = le32dec(&hash_u32[j]);
            if (fulltest(hash_u32, ptarget)) {
                *hashes_done = done + 1;
                pdata[19]    = nonce;
                return 1;
            }
        }
        done++;
    }

    // no valid share found
    *hashes_done = done;
    pdata[19]    = nonce;
    return 0;
}
