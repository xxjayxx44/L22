#include "cpuminer-config.h"
#include "miner.h"

#include "yespower-1.0.1/yespower.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>

/* Inline helpers for big/little endian encode/decode (small and fast) */
static inline void be32enc_bytes(uint8_t *out, uint32_t v)
{
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);
    out[3] = (uint8_t)(v);
}

static inline uint32_t le32dec_from_u32(const uint32_t *p)
{
    uint32_t x = *p;
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return ((x & 0xFF) << 24) | ((x & 0xFF00) << 8) | ((x & 0xFF0000) >> 8) | ((x & 0xFF000000) >> 24);
#else
    return x;
#endif
}

/* Keep yespower params static and const (as before) */
static const yespower_params_t yparams = {
    .version = YESPOWER_1_0,
    .N = 4096,
    .r = 16,
    .pers = NULL,
    .perslen = 0
};

/*
 * Optimized scanhash for Yespower YTN/R16.
 *
 * Hot-loop optimizations:
 *  - Pre-encode first 19 words into a single 80-byte buffer; update only
 *    the last 4 bytes (nonce) each iteration.
 *  - Do the cheap 32-bit target comparison before fulltest().
 *  - Avoid abort() on yespower_tls error; return 0 and let caller handle it.
 */
int scanhash_ytn_yespower(int thr_id, uint32_t *pdata,
    const uint32_t *ptarget,
    uint32_t max_nonce, unsigned long *hashes_done)
{
    /* input buffer for yespower: 80 bytes (20 * 4) */
    uint8_t input[80];
    uint8_t *nonce_bytes = &input[19 * 4]; /* last 4 bytes */

    /* temporary yespower hash output */
    yespower_binary_t yb;
    uint32_t n = pdata[19] - 1;
    const uint32_t Htarg = ptarget[7];
    int i;

    /* Pre-encode the first 19 words (indices 0..18) once */
    for (i = 0; i < 19; i++) {
        be32enc_bytes(&input[i * 4], pdata[i]);
    }

    /* Main loop: only update the 20th word (nonce) each iteration */
    do {
        uint32_t next_n = ++n;
        be32enc_bytes(nonce_bytes, next_n);

        /* Call yespower: compute hash from input(80) to yb */
        if (yespower_tls(input, sizeof(input), &yparams, &yb)) {
            /* Don't abort the whole process in production; return 0 so caller can manage restart */
            *hashes_done = n - pdata[19] + 1;
            pdata[19] = n;
            return 0;
        }

        /* Fast preliminary 32-bit check (little-endian decode of 8th u32 in yb) */
        /* The binary layout: yespower_binary_t is byte array; reinterpret safely */
        /* We interpret the 8th 32-bit word starting at byte offset (7 * 4) */
        uint32_t word7;
        memcpy(&word7, ((uint8_t *)&yb) + 7 * 4, 4);
        /* Convert little-endian word to CPU order if necessary */
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        word7 = ((word7 & 0xFF) << 24) | ((word7 & 0xFF00) << 8) | ((word7 & 0xFF0000) >> 8) | ((word7 & 0xFF000000) >> 24);
#endif
        if (word7 <= Htarg) {
            /* Full verify: convert full hash words to host-endian and call fulltest */
            uint32_t fullhash[7];
            for (i = 0; i < 7; i++) {
                uint32_t w;
                memcpy(&w, ((uint8_t *)&yb) + i * 4, 4);
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
                w = ((w & 0xFF) << 24) | ((w & 0xFF00) << 8) | ((w & 0xFF0000) >> 8) | ((w & 0xFF000000) >> 24);
#endif
                fullhash[i] = w;
            }
            if (fulltest(fullhash, ptarget)) {
                *hashes_done = n - pdata[19] + 1;
                pdata[19] = n;
                return 1;
            }
        }
    } while (n < max_nonce && !work_restart[thr_id].restart);

    *hashes_done = n - pdata[19] + 1;
    pdata[19] = n;
    return 0;
}
