/* YespowerUrx.c – Fixed Yespower-URX implementation */

#include "cpuminer-config.h"
#include "miner.h"
#include "yespower-1.0.1/yespower.h"
#include "yespower-local.h"  // Ensure correct header inclusion

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <stdint.h>

/* Define missing functions */
int init_region(yespower_local_t *local) {
    return yespower_init_local(local);  // Properly initialize yespower region
}

int free_region(yespower_local_t *local) {
    return yespower_free_local(local);  // Properly free yespower resources
}

int yespower_p2b(yespower_local_t *local, const uint8_t *src, size_t srclen,
                 const yespower_params_t *params, yespower_binary_t *dst) {
    return yespower(local, src, srclen, params, dst);  // Ensure correct yespower call
}

/* Define ALIGN64: use C11 alignas if available; otherwise, GCC attribute */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
  #include <stdalign.h>
  #define ALIGN64 alignas(64)
#else
  #define ALIGN64 __attribute__((aligned(64)))
#endif

/* Increment a 4-byte nonce stored in big-endian order */
static inline void increment_be(uint8_t *nonce) {
    for (int i = 3; i >= 0; --i) {
        if (++nonce[i] != 0)
            break;
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

    ALIGN64 union {
        uint8_t u8[80];
        uint32_t u32[20];
    } data;
    ALIGN64 union {
        yespower_binary_t yb;
        uint32_t u32[7];  // Ensure same structure as second script
    } hash;

    uint32_t Htarg = ptarget[7];
    uint8_t nonce_be[4];
    uint32_t base_nonce = pdata[19];
    uint32_t n = base_nonce;
    int i;

    for (i = 0; i < 19; i++) {
        be32enc(&data.u32[i], pdata[i]);
    }

    be32enc(nonce_be, base_nonce - 1);

    do {
        increment_be(nonce_be);
        memcpy(&data.u32[19], nonce_be, 4);

        if (yespower_tls(data.u8, 80, &params, &hash.yb))
            abort();

        if (le32dec(&hash.u32[6]) <= Htarg) {  // Ensure same target comparison as second script
            for (i = 0; i < 7; i++) {  // Match second script's 7 uint32_t values
                hash.u32[i] = le32dec(&hash.u32[i]);
            }
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

int yespower_tls_p2b(const uint8_t *src, size_t srclen,
    const yespower_params_t *params, yespower_binary_t *dst)
{
    static __thread int initialized = 0;
    static __thread yespower_local_t local;

    if (!initialized) {
        if (init_region(&local) != 0)
            return -1;
        initialized = 1;
    }

    return yespower_p2b(&local, src, srclen, params, dst);
}

int yespower_init_local_p2b(yespower_local_t *local)
{
    return init_region(local);
}

int yespower_free_local_p2b(yespower_local_t *local)
{
    return free_region(local);
}
