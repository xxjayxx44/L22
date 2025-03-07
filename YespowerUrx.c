#include "cpuminer-config.h"
#include "miner.h"
#include "yespower-1.0.1/yespower.h"
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

static inline void increment_be(uint8_t *nonce) {
    for (int i = 3; i >= 0; --i) {
        if (++nonce[i] != 0) break;
    }
}

int scanhash_urx_yespower(int thr_id, uint32_t *pdata,
    const uint32_t *ptarget, uint32_t max_nonce, unsigned long *hashes_done)
{
    static const yespower_params_t params = {
        .version = YESPOWER_1_0,
        .N = 2048,
        .r = 32,
        .pers = (const uint8_t *)"UraniumX",
        .perslen = 8
    };
    alignas(64) union {
        uint8_t u8[80];
        uint32_t u32[20];
    } data;
    alignas(64) union {
        yespower_binary_t yb;
        uint32_t u32[8];
    } hash;
    uint32_t Htarg = ptarget[7];
    uint8_t nonce_be[4];
    uint32_t base_nonce = pdata[19];
    uint32_t n = base_nonce;
    int i;

    // Precompute fixed part of the data in big-endian
    for (i = 0; i < 19; i++) {
        be32enc(&data.u32[i], pdata[i]);
    }

    // Initialize nonce in big-endian format
    be32enc(nonce_be, base_nonce - 1);

    do {
        increment_be(nonce_be); // Efficient big-endian increment
        memcpy(&data.u32[19], nonce_be, 4); // Update nonce in data

        if (yespower_tls(data.u8, 80, &params, &hash.yb))
            abort();

        // Check hash result with minimal byte operations
        if (le32dec(&hash.u32[7]) <= Htarg) {
            for (i = 0; i < 8; i++)
                hash.u32[i] = le32dec(&hash.u32[i]);
            if (fulltest(hash.u32, ptarget)) {
                *hashes_done = n - base_nonce + 1;
                pdata[19] = n;
                return 1;
            }
        }
        n++;
    } while (n <= max_nonce && !work_restart[thr_id].restart);

    *hashes_done = n - base_nonce + 1;
    pdata[19] = n;
    return 0;
}
