// YespowerUrx.c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <stdbool.h>
#include "yespower-1.0.1/yespower.h"
#include "miner.h"           // for work_restart declaration
#include "util.h"            // for fulltest prototype

// Big-endian encoder for 32-bit words
#define be32enc(p, x) do { \
    ((uint8_t *)(p))[0] = (uint8_t)((x) >> 24); \
    ((uint8_t *)(p))[1] = (uint8_t)((x) >> 16); \
    ((uint8_t *)(p))[2] = (uint8_t)((x) >>  8); \
    ((uint8_t *)(p))[3] = (uint8_t)((x)      ); \
} while (0)

// Little-endian decoder for 32-bit words
#define le32dec(p) ( \
    ((uint32_t)(((const uint8_t *)(p))[0])      ) | \
    ((uint32_t)(((const uint8_t *)(p))[1]) <<  8) | \
    ((uint32_t)(((const uint8_t *)(p))[2]) << 16) | \
    ((uint32_t)(((const uint8_t *)(p))[3]) << 24) )

// Use the existing fulltest from util.c
extern bool fulltest(const uint32_t *hash, const uint32_t *target);

// Reference the global work_restart array from miner.c
extern struct work_restart *work_restart;

// A simple Feistel‐style permutation for nonce randomization
static inline uint32_t permute_index(uint32_t index, uint32_t rounds, uint32_t key) {
    uint32_t left  = (index >> 16) & 0xFFFF;
    uint32_t right = index & 0xFFFF;
    for (uint32_t i = 0; i < rounds; i++) {
        uint32_t temp = left;
        left  = right;
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

    uint32_t n_start        = pdata[19];
    const uint32_t Htarg    = ptarget[7];
    uint32_t total_attempts = (max_nonce > n_start)
                             ? max_nonce - n_start
                             : 1;

    // Pre-encode the first 19 words of the block header
    for (int i = 0; i < 19; i++)
        be32enc(&data.u32[i], pdata[i]);

    for (uint32_t attempt = 0; attempt < total_attempts; attempt++) {
        uint32_t permuted = permute_index(attempt, 4, 0x9E37);
        uint32_t current_n = n_start + (permuted % total_attempts);

        if (current_n >= max_nonce)
            current_n = n_start + (permuted % (total_attempts - 1));

        be32enc(&data.u32[19], current_n);

        if (yespower_tls(data.u8, 80, &params, &hash.yb))
            abort();

        if (le32dec(&hash.u32[7]) <= Htarg) {
            // full 256-bit decode
            for (int i = 0; i < 8; i++)
                hash.u32[i] = le32dec(&hash.u32[i]);

            if (fulltest(hash.u32, ptarget)) {
                *hashes_done = attempt + 1;
                pdata[19]     = current_n;
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

int main(int argc, char *argv[])
{
    uint32_t pdata[20];
    uint32_t ptarget[8];
    unsigned long hashes_done = 0;

    // Fill header words with pseudo-random data
    srand((unsigned)time(NULL));
    for (int i = 0; i < 19; i++)
        pdata[i] = (uint32_t)rand();
    pdata[19] = 0; // start nonce

    // Set an extremely low difficulty: almost any hash succeeds
    for (int i = 0; i < 8; i++)
        ptarget[i] = 0xFFFFFFFFu;
    ptarget[7] = 0xFFFFFFFFu;

    int result = scanhash_urx_yespower(0, pdata, ptarget, 0x100000u, &hashes_done);

    if (result) {
        printf("✅ Solved! Nonce = %u, Attempts = %lu\n",
               pdata[19], hashes_done);
    } else {
        printf("❌ No solution found after %lu attempts\n", hashes_done);
    }

    return result ? EXIT_SUCCESS : EXIT_FAILURE;
}
