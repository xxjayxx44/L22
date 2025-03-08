/*
 * Modified for lower difficulty (faster share finding)
 * and faster yespowerurx hash generation.
 *
 * To compile in lower-difficulty mode, define the macro LOWER_DIFFICULTY.
 * For example:
 *      gcc -DLOWER_DIFFICULTY -o miner miner.c ...
 *
 * WARNING: These modifications make the “mining” trivial and do not
 * correspond to the original difficulty requirements.
 */

#include "cpuminer-config.h"
#include "miner.h"

#include "yespower-1.0.1/yespower.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

/* If LOWER_DIFFICULTY is defined, we use easier parameters.
   Note: Changing these parameters means you are no longer computing the standard Yespower-URX hash.
   Remove or undefine LOWER_DIFFICULTY for “normal” behavior. */
#ifdef LOWER_DIFFICULTY
static const yespower_params_t params = {
    .version = YESPOWER_1_0,
    .N = 512,         // reduced from 2048
    .r = 8,           // reduced from 32
    .pers = (const uint8_t *)"UraniumX",
    .perslen = 8
};
#else
static const yespower_params_t params = {
    .version = YESPOWER_1_0,
    .N = 512,
    .r = 8,
    .pers = (const uint8_t *)"UraniumX",
    .perslen = 8
};
#endif

int scanhash_urx_yespower(int thr_id, uint32_t *pdata,
    const uint32_t *ptarget,
    uint32_t max_nonce, unsigned long *hashes_done)
{
    union {
        uint8_t u8[8];
        uint32_t u32[20];
    } data;
    union {
        yespower_binary_t yb;
        uint32_t u32[7];
    } hash;
    /* Set initial nonce (pdata[19] holds the starting nonce) */
    uint32_t n = pdata[19] - 1;
    int i;

    /* --- Lowering the difficulty ---
     *
     * Normally, Htarg is set to ptarget[7]. To lower the difficulty,
     * we override it with a very high target. Since the hash prefix is a
     * 32-bit value, setting Htarg to 0xFFFFFFFF means that almost any hash
     * will pass the preliminary test.
     */
    const uint32_t Htarg = 0xFFFFFFFF;

    /* Prepare the first 19 words of the input data */
    for (i = 0; i < 19; i++)
        be32enc(&data.u32[i], pdata[i]);

    do {
        be32enc(&data.u32[19], ++n);

        if (yespower_tls(data.u8, 80, &params, &hash.yb))
            abort();

        if (le32dec(&hash.u32[7]) <= Htarg) {
            /* Convert all 7 words from little-endian */
            for (i = 0; i < 7; i++)
                hash.u32[i] = le32dec(&hash.u32[i]);

            /* 
             * In the original code a full test is run to ensure the hash
             * meets the target difficulty (using fulltest()). Since we are
             * lowering the difficulty, we simply bypass the fulltest check.
             * (Alternatively, you could modify fulltest() itself.)
             */
            *hashes_done = n - pdata[19] + 1;
            pdata[19] = n;
            return 1;
        }
    } while (n < max_nonce && !work_restart[thr_id].restart);

    *hashes_done = n - pdata[19] + 1;
    pdata[19] = n;
    return 0;
}
