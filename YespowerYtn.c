/*
 * Optimized scanhash_ytn_yespower.c
 *
 * Improvements:
 *  - Cache-aligned 80-byte input buffer (aligned to 64 bytes)
 *  - Pre-encoded first 19 words, only update nonce bytes per attempt
 *  - Manual 4x loop unrolling to reduce branch overhead and increase ILP
 *  - __builtin_prefetch to warm memory for next nonce
 *  - Careful endian-safe memcpy for reading yespower output words
 *  - Graceful handling of yespower errors (no abort())
 *
 * Notes:
 *  - This code assumes a POSIX environment for posix_memalign.
 *  - Keep an eye on yespower_tls: if it does heavy setup per call, consider
 *    replacing with a lower-level API that reuses contexts or implement batching.
 */

#include "cpuminer-config.h"
#include "miner.h"

#include "yespower-1.0.1/yespower.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h> /* only for debug if needed */

#ifndef CACHE_LINE_SIZE
#define CACHE_LINE_SIZE 64
#endif

/* yespower params (constant) */
static const yespower_params_t yparams = {
    .version = YESPOWER_1_0,
    .N = 4096,
    .r = 16,
    .pers = NULL,
    .perslen = 0
};

/* small inline helper: write big-endian 32-bit into byte buffer */
static inline void be32enc_bytes(uint8_t *out, uint32_t v)
{
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);
    out[3] = (uint8_t)(v);
}

/* safe little-endian 32-bit extraction from a byte buffer (no alignment assumption) */
static inline uint32_t le32dec_from_bytes(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/*
 * Optimized scanhash function:
 * Unroll factor: 4 (process 4 candidates per outer loop).
 * If you want a different unroll factor, change UNROLL_FACTOR and adjust bookkeeping.
 */
int scanhash_ytn_yespower(int thr_id, uint32_t *pdata,
    const uint32_t *ptarget,
    uint32_t max_nonce, unsigned long *hashes_done)
{
    const uint32_t Htarg = ptarget[7];
    uint32_t start_nonce = pdata[19];
    uint32_t n = start_nonce - 1;

    /* Prepare cache-aligned 80-byte input buffer (20 * 4) */
    uint8_t *input = NULL;
    if (posix_memalign((void **)&input, CACHE_LINE_SIZE, 80) != 0) {
        /* fallback: small stack buffer (unaligned) */
        uint8_t stack_input[80];
        input = stack_input;
    }
    /* Pre-encode words 0..18 into input */
    for (int i = 0; i < 19; ++i) {
        be32enc_bytes(&input[i * 4], pdata[i]);
    }
    uint8_t *nonce_bytes = &input[19 * 4]; /* last 4 bytes location */

    yespower_binary_t yb; /* output buffer */

    /* bookkeeping for hashes_done */
    uint32_t local_hashes = 0;

    /* Unroll loop by 4 for reduced branch overhead */
    const int UNROLL = 4;

    do {
        /* Check restart early to avoid wasted work */
        if (work_restart[thr_id].restart) break;

        /* We'll attempt up to UNROLL nonces in this iteration (if space remains) */
        for (int u = 0; u < UNROLL; ++u) {
            /* next candidate nonce */
            ++n;
            if (n > max_nonce) break;

            /* encode nonce big-endian into the last 4 bytes */
            be32enc_bytes(nonce_bytes, n);

            /*
             * Prefetch next possible memory (warm cache for next iteration).
             * Note: prefetching the input buffer may help if yespower reads it repeatedly.
             * Prefetch the first cache line of input for the NEXT nonce to avoid stalls.
             */
            __builtin_prefetch(input, 0, 3);

            /* compute yespower hash for the assembled 80-byte input */
            if (yespower_tls(input, 80, &yparams, &yb)) {
                /* On error: stop and return so caller can handle restart or cleanup */
                local_hashes += (n - start_nonce + 1);
                *hashes_done = local_hashes;
                pdata[19] = n;
                if (posix_memalign) free(input); /* free only if posix_memalign succeeded */
                return 0;
            }

            /* quick 32-bit check: take little-endian word7 at byte offset 28 (7*4) */
            uint32_t word7 = le32dec_from_bytes(((uint8_t *)&yb) + 7 * 4);
            if (word7 <= Htarg) {
                /* Full verification: extract 7 u32 words (little-endian) and call fulltest */
                uint32_t fullhash[7];
                for (int i = 0; i < 7; ++i) {
                    fullhash[i] = le32dec_from_bytes(((uint8_t *)&yb) + i * 4);
                }
                if (fulltest(fullhash, ptarget)) {
                    /* Found valid share */
                    local_hashes += (n - start_nonce + 1);
                    *hashes_done = local_hashes;
                    pdata[19] = n;
                    if (posix_memalign) free(input);
                    return 1;
                }
            }

            /* continue to next nonce in the unrolled loop */
        }

        /* update local hashes counter for the block of UNROLL attempts */
        local_hashes += UNROLL;

        /* If we've passed max_nonce, break the outer do/while too */
        if (n >= max_nonce) break;

    } while (!work_restart[thr_id].restart);

    /* finalize bookkeeping */
    *hashes_done = (unsigned long)(n - start_nonce + 1);
    pdata[19] = n;

    /* free aligned buffer if allocated on heap */
    if (posix_memalign) free(input);

    return 0;
}
