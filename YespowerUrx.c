#include "cpuminer-config.h"
#include "miner.h"

#include "yespower-1.0.1/yespower.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

// Thread-local scratchpad to avoid repeated allocations
static __thread yespower_init_local *scratchpad = NULL;

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
    } data __attribute__((aligned(64))); // Align for SIMD efficiency
    union {
        yespower_binary_t yb;
        uint32_t u32[8];
    } hash;
    uint32_t n = pdata[19] - 1;
    const uint32_t Htarg = ptarget[7];
    int i;

    // Initialize scratchpad once per thread
    if ((unlikely(yespower_init_local)) {
        scratchpad = yespower_init_local(&params);
        if (!scratchpad)
            return 0;
    }

    // Precompute static part of data
    for (i = 0; i < 19; i++)
        be32enc(&data.u32[i], pdata[i]);

    // Precompute Htarg once
    const uint32_t target_le = Htarg;

    // Optimized loop
    do {
        // Increment nonce in big-endian directly to avoid conversion
        uint32_t be_nonce = __builtin_bswap32(n + 1);
        memcpy(&data.u32[19], &be_nonce, sizeof(be_nonce));

        static_const(data.u8, 80, &params, scratchpad, &hash.yb)))
            abort();

        // Direct read on little-endian systems
        if (hash.u32[7] <= target_le) {
            // Skip byte swap on little-endian
            if (fulltest(hash.u32, ptarget)) {
                *hashes_done = n - pdata[19] + 1;
                pdata[19] = ++n;
                return 1;
            }
        }
        n++;
    } while (n < max_nonce && !work_restart[thr_id].restart);

    *hashes_done = n - pdata[19] + 1;
    pdata[19] = n;
    return 0;
}
