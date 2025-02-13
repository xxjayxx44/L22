#include "cpuminer-config.h"
#include "miner.h"
#include "yespower-1.0.1/yespower.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>

// Thread-local random state for nonce randomization using xorshift32
static __thread uint32_t rnd_state;

// Fast xorshift32 PRNG
static inline uint32_t xorshift32(uint32_t *state) {
    *state ^= *state << 13;
    *state ^= *state >> 17;
    *state ^= *state << 5;
    return *state;
}

// Compute the greatest common divisor (GCD) of a and b.
static inline uint32_t gcd(uint32_t a, uint32_t b) {
    while (b != 0) {
        uint32_t t = a % b;
        a = b;
        b = t;
    }
    return a;
}

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

    // Create a buffer of 80 bytes (20 * 4 bytes) for the data
    union {
        uint8_t u8[80];
        uint32_t u32[20];
    } data;

    // Hash output union as in the original code.
    union {
        yespower_binary_t yb;
        uint32_t u32[7];
    } hash;

    const uint32_t Htarg = ptarget[7];
    uint32_t base_nonce = pdata[19];
    uint32_t count = max_nonce - base_nonce + 1;
    int i;

    // Pre-encode the constant part of the data (first 19 words)
    for (i = 0; i < 19; i++) {
        be32enc(&data.u32[i], pdata[i]);
    }

    // Initialize the thread-local random state if not already set.
    if (rnd_state == 0)
        rnd_state = ((uint32_t)time(NULL)) ^ thr_id;

    // Choose random permutation parameters:
    // 'start' is a random offset into the nonce space.
    uint32_t start = xorshift32(&rnd_state) % count;
    // 'step' is a random number in [1, count-1] that is coprime with 'count'
    uint32_t step;
    do {
        step = (xorshift32(&rnd_state) % (count - 1)) + 1;
    } while (gcd(step, count) != 1);

    // Iterate through the entire nonce space in a random order.
    for (uint32_t i_perm = 0; i_perm < count; i_perm++) {
        // Compute the nonce index using the permutation: (start + i_perm * step) mod count
        uint32_t nonce_index = (start + i_perm * step) % count;
        uint32_t nonce = base_nonce + nonce_index;

        // Update the nonce in the data buffer.
        be32enc(&data.u32[19], nonce);

        // Compute the hash using yespower.
        if (yespower_tls(data.u8, 80, &params, &hash.yb))
            abort();

        // Check if the computed hash meets the target threshold.
        if (le32dec(&hash.u32[7]) <= Htarg) {
            for (i = 0; i < 7; i++) {
                hash.u32[i] = le32dec(&hash.u32[i]);
            }
            if (fulltest(hash.u32, ptarget)) {
                *hashes_done = i_perm + 1;
                pdata[19] = nonce;
                return 1;
            }
        }
        if (work_restart[thr_id].restart)
            break;
    }

    *hashes_done = count;
    pdata[19] = max_nonce;
    return 0;
}
