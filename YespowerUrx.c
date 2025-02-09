#include "cpuminer-config.h"
#include "miner.h"
#include "yespower-1.0.1/yespower.h"
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <tbb/parallel_for.h>
#include <tbb/blocked_range.h>

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
        uint8_t u8[8];    // 80 bytes for block header
        uint32_t u32[20];  // 20 32-bit words
    } data;

    union {
        yespower_binary_t yb;
        uint32_t u32[7];
    } hash;

    const uint32_t Htarg = ptarget[7];
    int i;
    uint32_t n = pdata[19] - 1;

    // Encode the first 19 32-bit words of the block header into the data buffer
    for (i = 0; i < 19; i++)
        be32enc(&data.u32[i], pdata[i]);

    // Create a range for parallel processing using TBB
    tbb::blocked_range<uint32_t> range(0, max_nonce);

    // Parallelize the nonce scanning with TBB
    tbb::parallel_for(range, [&](const tbb::blocked_range<uint32_t>& r) {
        uint32_t local_nonce = n;
        for (uint32_t i = r.begin(); i != r.end(); ++i) {
            local_nonce = i;
            be32enc(&data.u32[19], ++local_nonce);

            if (yespower_tls(data.u8, 80, &params, &hash.yb))
                abort();

            if (le32dec(&hash.u32[7]) <= Htarg) {
                for (i = 0; i < 7; i++)
                    hash.u32[i] = le32dec(&hash.u32[i]);
                if (fulltest(hash.u32, ptarget)) {
                    *hashes_done = local_nonce - pdata[19] + 1;
                    pdata[19] = local_nonce;
                    return;  // Exit once a valid hash is found
                }
            }
        }
    });

    // Store the number of hashes done
    *hashes_done = range.end() - pdata[19] + 1;
    pdata[19] = n;
    return 0;
}
