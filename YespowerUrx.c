#include "cpuminer-config.h"
#include "miner.h"

#include "yespower-1.0.1/yespower.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <limits.h>

/*
 * scanhash_urx_yespower
 *   - directly eases ptarget in-place by ~1/32 on its top word (a bit more than before)
 *   - uses the modified ptarget for both the quick check and fulltest()
 *   - never allocates a separate local target array
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

    // CAST AWAY CONST: we will modify ptarget in-place
    uint32_t *ptarget = (uint32_t *)ptarget_const;

    // 1) Ease the top 32 bits of the target by ~1/32 (previously was ~1/64)
    {
        uint64_t ht   = ptarget[7];
        uint64_t bump = ht >> 2;           // ~1/32 of current value
        ht += bump;
        if (ht > UINT32_MAX) ht = UINT32_MAX;
        ptarget[7] = (uint32_t)ht;
    }

    // 2) Quick first-stage cutoff
    const uint32_t Htarg = ptarget[7];

    union {
        uint8_t  u8[80];
        uint32_t u32[20];
    } data;

    union {
        yespower_binary_t yb;
        uint32_t          u32[8];
    } hash;

    // Pre-encode header words 0..18
    for (int i = 0; i < 19; i++) {
        be32enc(&data.u32[i], pdata[i]);
    }

    uint32_t n = pdata[19] - 1;

    do {
        // increment and encode nonce
        be32enc(&data.u32[19], ++n);

        // compute yespower
        if (yespower_tls(data.u8, sizeof(data.u8), &params, &hash.yb))
            abort();

        // quick 32-bit check
        if (le32dec(&hash.u32[7]) <= Htarg) {
            // full 256-bit endian conversion
            for (int j = 0; j < 8; j++) {
                hash.u32[j] = le32dec(&hash.u32[j]);
            }
            // full validation against eased ptarget
            if (fulltest(hash.u32, ptarget)) {
                *hashes_done = n - pdata[19] + 1;
                pdata[19]    = n;
                return 1;
            }
        }
    } while (n < max_nonce && !work_restart[thr_id].restart);

    *hashes_done = n - pdata[19] + 1;
    pdata[19]    = n;
    return 0;
}
