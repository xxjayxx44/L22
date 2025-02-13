#include "cpuminer-config.h"
#include "miner.h"
#include "yespower-1.0.1/yespower.h"
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>

#ifdef __ARM_NEON
#include <arm_neon.h>

// --------------------------------------------------------------------------
// neon_be32enc()
//   Uses NEON intrinsics to encode an array of 32-bit integers into big-endian
//   format. It processes four values at a time. Any remaining words are handled
//   by the scalar be32enc() function.
// 'dest'  : destination array to hold the big-endian words.
// 'src'   : source array of host-order 32-bit values.
// 'count' : number of 32-bit words to process.
// --------------------------------------------------------------------------
static inline void neon_be32enc(uint32_t *dest, const uint32_t *src, size_t count)
{
    size_t i = 0;
    for (; i + 4 <= count; i += 4) {
        // Load 4 words from source.
        uint32x4_t v = vld1q_u32(src + i);
        // Reinterpret as 16 bytes and reverse the byte order in each 32-bit element.
        uint8x16_t v8 = vreinterpretq_u8_u32(v);
        v8 = vrev32q_u8(v8);
        // Reinterpret back to 32-bit words.
        v = vreinterpretq_u32_u8(v8);
        // Store the result.
        vst1q_u32(dest + i, v);
    }
    // Process any remaining values using the scalar function.
    for (; i < count; i++) {
        be32enc(&dest[i], src[i]);
    }
}
#endif

// Thread-local random state for nonce randomization
static __thread uint32_t rnd_state;

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
        uint32_t u32[7];
    } hash;
    const uint32_t Htarg = ptarget[7];
    uint32_t base_nonce = pdata[19];
    uint32_t count = max_nonce - base_nonce + 1;
    int i;

    // Initialize random state for this thread
    if (rnd_state == 0) {
        rnd_state = (uint32_t)(time(NULL)) ^ thr_id;
    }

#ifdef __ARM_NEON
    // Use NEON to convert the first 19 words from pdata into big-endian form.
    neon_be32enc(data.u32, pdata, 19);
#else
    for (i = 0; i < 19; i++)
        be32enc(&data.u32[i], pdata[i]);
#endif

    for (uint32_t attempt = 0; attempt < count; ++attempt) {
        // Randomize nonce within valid range.
        uint32_t nonce = base_nonce + (rand_r(&rnd_state) % count);
        
        be32enc(&data.u32[19], nonce);

        if (yespower_tls(data.u8, sizeof(data), &params, &hash.yb))
            abort();

        if (le32dec(&hash.u32[7]) <= Htarg) {
            // Convert the first 7 words of the hash from little-endian to host order.
            for (i = 0; i < 7; i++)
                hash.u32[i] = le32dec(&hash.u32[i]);
            if (fulltest(hash.u32, ptarget)) {
                *hashes_done = attempt + 1;
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
