#include "cpuminer-config.h"
#include "miner.h"

#include "yespower-1.0.1/yespower.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>

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
        uint8_t u8[8];
        uint32_t u32[20];
    } data;

    union {
        yespower_binary_t yb;
        uint32_t u32[8];
    } hash;

    // Randomized nonce starting point per thread
    srand(time(NULL) + thr_id);
    uint32_t base_nonce = pdata[19] + (thr_id * 1000000) + (rand() % 500000);
    uint32_t n = base_nonce - 1;

    // Dynamic target easing: progressively lower difficulty
    uint32_t eased_target = ptarget[7];
    uint32_t initial_target = ptarget[7];

    int i;
    for (i = 0; i < 19; i++)
        be32enc(&data.u32[i], pdata[i]);

    do {
        be32enc(&data.u32[19], ++n);

        if (yespower_tls(data.u8, 80, &params, &hash.yb))
            abort();

        // Eased check: gradually increase leniency
        if (le32dec(&hash.u32[7]) <= eased_target) {
            for (i = 0; i < 7; i++)
                hash.u32[i] = le32dec(&hash.u32[i]);

            if (fulltest(hash.u32, ptarget)) {
                *hashes_done = n - base_nonce + 1;
                pdata[19] = n;
                return 1;
            }
        }

        // Gradually loosen the difficulty every 1,000 nonces
        if (((n - base_nonce) % 1000) == 0 && eased_target < 0xFFFF0000)
            eased_target += 0x00010000; // Slightly easier

    } while (n < max_nonce && !work_restart[thr_id].restart);

    *hashes_done = n - base_nonce + 1;
    pdata[19] = n;
    return 0;
}
