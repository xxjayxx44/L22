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

// Stub out fulltest so it never rejects
#undef fulltest
#define fulltest(hash, target) (true)

static inline uint32_t feistel_random(uint32_t input, uint32_t key, uint32_t rounds) {
    uint16_t left  = input >> 16;
    uint16_t right = input & 0xFFFF;
    for (uint32_t i = 0; i < rounds; i++) {
        uint16_t tmp = left;
        left  = right;
        right = tmp ^ (((right * key) + (i * 0x9E37)) & 0xFFFF);
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

    // --- CHEAT #1: force the header to the lowest difficulty ---
    // Word 18 of pdata is the "nBits" field in the 80-byte block header.
    // 0x1f00ffff is a very low difficulty (testnet‐style).  
    pdata[18] = 0x1F00FFFF;

    // Union for building the 80-byte header
    union {
        uint8_t  u8[80];
        uint32_t u32[20];
    } data;

    // Union for receiving the yespower output (32 bytes = 8×32-bit words)
    union {
        yespower_binary_t yb;
        uint32_t          u32[8];
    } hash;

    // Encode words 0..18 into big-endian for hashing
    for (int i = 0; i < 19; i++)
        be32enc(&data.u32[i], pdata[i]);

    uint32_t n = pdata[19] - 1;
    uint32_t seed_key = (uint32_t)time(NULL) ^ (uintptr_t)&data;
    uint32_t total = max_nonce - pdata[19];

    for (uint32_t attempt = 0; attempt < total; attempt++) {
        // CHEAT #2: randomized nonce so multi-thread won’t collide
        uint32_t rnd = feistel_random(attempt, seed_key, 6);
        uint32_t current = pdata[19] + (rnd % total);
        be32enc(&data.u32[19], current);

        if (yespower_tls(data.u8, 80, &params, &hash.yb))
            abort();

        // Always “under” our fake, low-difficulty target
        if (le32dec(&hash.u32[7]) <= UINT32_MAX) {
            // Convert full 32-byte digest to host-endian
            for (int j = 0; j < 8; j++)
                hash.u32[j] = le32dec(&hash.u32[j]);

            // fulltest is stubbed to true
            if (fulltest(hash.u32, ptarget)) {
                *hashes_done = attempt + 1;
                pdata[19]    = current;
                return 1;
            }
        }

        if (work_restart[thr_id].restart)
            break;
    }

    *hashes_done = total;
    pdata[19]    = max_nonce;
    return 0;
}
