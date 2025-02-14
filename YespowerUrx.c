#include "cpuminer-config.h"
#include "miner.h"
#include "yespower-1.0.1/yespower.h" // Keep header (assume yescryptR32 support)

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>

// Thread-local random state
static __thread uint32_t rnd_state;

static inline uint32_t xorshift32(uint32_t *state) {
    *state ^= *state << 13;
    *state ^= *state >> 17;
    *state ^= *state << 5;
    return *state;
}

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
    const yespower_params_t params = {
        .version = YESPOWER_1_0, // Assume yescryptR32 compatibility
        .N = 2048,
        .r = 32,                 // 32 rounds (R32)
        .pers = NULL,            // Remove URX personalization
        .perslen = 0
    };

    union {
        uint8_t u8[80];
        uint32_t u32[20];
    } data;

    union {
        yespower_binary_t yb;    // Adjust if yespower_binary_t is smaller
        uint32_t u32[8];         // 32 bytes = 8 x uint32_t
    } hash;

    const uint32_t Htarg = ptarget[7]; // Target's 8th 32-bit word (index 7)
    uint32_t base_nonce = pdata[19];
    uint32_t count = max_nonce - base_nonce + 1;
    int i;

    for (i = 0; i < 19; i++) {
        be32enc(&data.u32[i], pdata[i]);
    }

    if (rnd_state == 0)
        rnd_state = ((uint32_t)time(NULL)) ^ thr_id;

    uint32_t start = xorshift32(&rnd_state) % count;
    uint32_t step;
    do {
        step = (xorshift32(&rnd_state) % (count - 1)) + 1;
    } while (gcd(step, count) != 1);

    for (uint32_t i_perm = 0; i_perm < count; i_perm++) {
        uint32_t nonce_index = (start + i_perm * step) % count;
        uint32_t nonce = base_nonce + nonce_index;

        be32enc(&data.u32[19], nonce);

        if (yespower_tls(data.u8, 80, &params, &hash.yb))
            abort();

        // Check hash.u32[7] (last 4 bytes of 32-byte hash)
        if (le32dec(&hash.u32[7]) <= Htarg) { 
            // Validate entire 32-byte hash (8 words)
            for (i = 0; i < 8; i++) {
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
