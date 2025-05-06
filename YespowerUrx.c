#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include "yespower-1.0.1/yespower.h"

// Mock for big-endian encoding/decoding
#define be32enc(p, x) do { \
    ((uint8_t *)(p))[0] = ((x) >> 24) & 0xff; \
    ((uint8_t *)(p))[1] = ((x) >> 16) & 0xff; \
    ((uint8_t *)(p))[2] = ((x) >> 8) & 0xff; \
    ((uint8_t *)(p))[3] = (x) & 0xff; \
} while(0)

#define le32dec(p) ( \
    ((uint32_t)(((const uint8_t *)(p))[0])      ) | \
    ((uint32_t)(((const uint8_t *)(p))[1]) <<  8) | \
    ((uint32_t)(((const uint8_t *)(p))[2]) << 16) | \
    ((uint32_t)(((const uint8_t *)(p))[3]) << 24))

// Simple always-true test for demonstration
int fulltest(const uint32_t *hash, const uint32_t *target) {
    return 1; // Always return true for simplicity
}

// Feistel-like permutation for nonce randomization
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

// Dummy restart flag (not multithreaded here)
struct {
    int restart;
} work_restart[1];

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
        uint8_t u8[80];
        uint32_t u32[20];
    } data;

    union {
        yespower_binary_t yb;
        uint32_t u32[8];
    } hash;

    uint32_t n_start = pdata[19];
    const uint32_t Htarg = ptarget[7];
    uint32_t total_attempts = max_nonce - n_start;

    for (int i = 0; i < 19; i++)
        be32enc(&data.u32[i], pdata[i]);

    for (uint32_t attempt = 0; attempt < total_attempts; attempt++) {
        uint32_t permuted = permute_index(attempt, 4, 0x1234);
        uint32_t current_n = n_start + (permuted % total_attempts);

        if (current_n >= max_nonce)
            current_n = n_start + (permuted % (total_attempts - 1));

        be32enc(&data.u32[19], current_n);

        if (yespower_tls(data.u8, 80, &params, &hash.yb))
            abort();

        if (le32dec(&hash.u32[7]) <= Htarg) {
            for (int i = 0; i < 7; i++)
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

int main() {
    uint32_t pdata[20] = {0};
    uint32_t ptarget[8];
    unsigned long hashes_done = 0;

    // Fill block header with pseudo-random data
    srand(time(NULL));
    for (int i = 0; i < 19; i++)
        pdata[i] = rand();

    pdata[19] = 0; // Start nonce

    // Very low difficulty target (almost always succeeds)
    for (int i = 0; i < 8; i++)
        ptarget[i] = 0xFFFFFFFF;
    ptarget[7] = 0xFFFFFFFF; // Very easy threshold

    int found = scanhash_urx_yespower(0, pdata, ptarget, 0x100000, &hashes_done);

    if (found) {
        printf("✅ Block solved!\nNonce: %u\nHash attempts: %lu\n", pdata[19], hashes_done);
    } else {
        printf("❌ No solution found within range.\n");
    }

    return 0;
}
